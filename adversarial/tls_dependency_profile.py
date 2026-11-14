#!/usr/bin/env python3
"""Profile request-reachable rustls/webpki TLS and mTLS resource shapes.

The harness is entirely loopback-local. It creates a root, server identity and
same-subject client intermediates. A leaf is signed by the final intermediate,
while preceding certificates are valid CA certificates with the same subject
but different keys. Presenting the real signer last makes webpki explore the
issuer candidates without relying on malformed DER or an untrusted chain. It
also generates structurally bounded hostile ClientHellos at the rustls message
ceiling to exercise cipher, extension, signature, group, key-share and PSK
cardinality plus record fragmentation independently of certificate work.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import grp
import os
import pwd
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
HTTPD = Path(os.environ.get("TLS_PROFILE_HTTPD_RS", REPO / "target/release/httpd-rs"))


def run(*args: str) -> None:
    subprocess.run(
        args,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def key_and_csr(key: Path, csr: Path, subject: str, algorithm: str) -> None:
    if algorithm in {"p256", "p384"}:
        curve = "P-256" if algorithm == "p256" else "P-384"
        key_args = ["-newkey", "ec", "-pkeyopt", f"ec_paramgen_curve:{curve}"]
    elif algorithm == "ed25519":
        key_args = ["-newkey", "ed25519"]
    elif algorithm in {"rsa2048", "rsa4096", "rsa8192"}:
        key_args = ["-newkey", f"rsa:{algorithm.removeprefix('rsa')}"]
    else:
        raise ValueError(f"unsupported key algorithm {algorithm}")
    run(
        "openssl",
        "req",
        "-new",
        *key_args,
        "-nodes",
        "-subj",
        subject,
        "-keyout",
        os.fspath(key),
        "-out",
        os.fspath(csr),
    )


def sign(csr: Path, cert: Path, ca: Path, ca_key: Path, serial: int, ext: Path) -> None:
    run(
        "openssl",
        "x509",
        "-req",
        "-days",
        "2",
        "-in",
        os.fspath(csr),
        "-CA",
        os.fspath(ca),
        "-CAkey",
        os.fspath(ca_key),
        "-set_serial",
        str(serial),
        "-extfile",
        os.fspath(ext),
        "-out",
        os.fspath(cert),
    )


@dataclass
class Fixture:
    root: Path
    root_cert: Path
    server_cert: Path
    server_key: Path
    client_key: Path
    client_leaf: Path
    intermediates: list[Path]

    def chain(self, count: int) -> Path:
        if count < 1 or count > len(self.intermediates):
            raise ValueError(f"chain count must be 1..{len(self.intermediates)}")
        # The leaf was signed by the final generated intermediate. Select
        # wrong same-subject candidates first and the correct issuer last.
        chosen = self.intermediates[: count - 1] + [self.intermediates[-1]]
        path = self.root / f"client-chain-{count}.pem"
        path.write_bytes(
            self.client_leaf.read_bytes()
            + b"".join(certificate.read_bytes() for certificate in chosen)
        )
        return path


@dataclass
class ClientHelloTemplate:
    record_version: bytes
    legacy_version: bytes
    random: bytes
    session_id: bytes
    cipher_suites: bytes
    compression_methods: bytes
    extensions: list[tuple[int, bytes]]


TLS_RECORD_PLAINTEXT_MAX = 16 * 1024
TLS_HANDSHAKE_MESSAGE_MAX = 65_535


def generated_client_hello() -> bytes:
    """Return CPython/OpenSSL's initial TLS 1.3 ClientHello records."""

    ctx = context(None, None)
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    client = ctx.wrap_bio(incoming, outgoing, server_side=False, server_hostname="localhost")
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        pass
    chunks = []
    while outgoing.pending:
        chunks.append(outgoing.read())
    return b"".join(chunks)


def parse_client_hello(records: bytes) -> ClientHelloTemplate:
    pos = 0
    handshake = bytearray()
    record_version = b"\x03\x01"
    while pos < len(records):
        if pos + 5 > len(records):
            raise ValueError("truncated TLS record")
        kind = records[pos]
        record_version = records[pos + 1 : pos + 3]
        length = int.from_bytes(records[pos + 3 : pos + 5], "big")
        pos += 5
        if pos + length > len(records) or kind != 22:
            raise ValueError("unexpected initial TLS record")
        handshake.extend(records[pos : pos + length])
        pos += length
    if len(handshake) < 4 or handshake[0] != 1:
        raise ValueError("initial handshake is not ClientHello")
    declared = int.from_bytes(handshake[1:4], "big")
    if declared != len(handshake) - 4:
        raise ValueError("ClientHello length mismatch")
    body = bytes(handshake[4:])
    cursor = 0
    legacy_version = body[cursor : cursor + 2]
    cursor += 2
    random = body[cursor : cursor + 32]
    cursor += 32
    session_len = body[cursor]
    cursor += 1
    session_id = body[cursor : cursor + session_len]
    cursor += session_len
    cipher_len = int.from_bytes(body[cursor : cursor + 2], "big")
    cursor += 2
    cipher_suites = body[cursor : cursor + cipher_len]
    cursor += cipher_len
    compression_len = body[cursor]
    cursor += 1
    compression_methods = body[cursor : cursor + compression_len]
    cursor += compression_len
    extensions_len = int.from_bytes(body[cursor : cursor + 2], "big")
    cursor += 2
    extensions_end = cursor + extensions_len
    if extensions_end != len(body):
        raise ValueError("ClientHello extension length mismatch")
    extensions = []
    while cursor < extensions_end:
        if cursor + 4 > extensions_end:
            raise ValueError("truncated ClientHello extension")
        kind = int.from_bytes(body[cursor : cursor + 2], "big")
        length = int.from_bytes(body[cursor + 2 : cursor + 4], "big")
        cursor += 4
        if cursor + length > extensions_end:
            raise ValueError("truncated ClientHello extension value")
        extensions.append((kind, body[cursor : cursor + length]))
        cursor += length
    return ClientHelloTemplate(
        record_version=record_version,
        legacy_version=legacy_version,
        random=random,
        session_id=session_id,
        cipher_suites=cipher_suites,
        compression_methods=compression_methods,
        extensions=extensions,
    )


def client_hello_body(
    template: ClientHelloTemplate,
    *,
    cipher_suites: bytes,
    extensions: list[tuple[int, bytes]],
) -> bytes:
    encoded_extensions = b"".join(
        kind.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value
        for kind, value in extensions
    )
    return (
        template.legacy_version
        + template.random
        + bytes([len(template.session_id)])
        + template.session_id
        + len(cipher_suites).to_bytes(2, "big")
        + cipher_suites
        + bytes([len(template.compression_methods)])
        + template.compression_methods
        + len(encoded_extensions).to_bytes(2, "big")
        + encoded_extensions
    )


def encode_client_hello(
    template: ClientHelloTemplate,
    *,
    cipher_suites: bytes,
    extensions: list[tuple[int, bytes]],
    fragment: int = TLS_RECORD_PLAINTEXT_MAX,
) -> bytes:
    body = client_hello_body(template, cipher_suites=cipher_suites, extensions=extensions)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    if len(handshake) > TLS_HANDSHAKE_MESSAGE_MAX:
        raise ValueError(f"ClientHello exceeds {TLS_HANDSHAKE_MESSAGE_MAX} bytes")
    records = []
    for start in range(0, len(handshake), fragment):
        part = handshake[start : start + fragment]
        records.append(
            b"\x16"
            + template.record_version
            + len(part).to_bytes(2, "big")
            + part
        )
    return b"".join(records)


def replace_extension(
    extensions: list[tuple[int, bytes]], kind: int, value: bytes
) -> list[tuple[int, bytes]]:
    return [(current, data) for current, data in extensions if current != kind] + [
        (kind, value)
    ]


def unknown_u16_values(count: int, *, start: int = 0x4000) -> bytes:
    values = []
    candidate = start
    while len(values) < count:
        value = candidate & 0xFFFF
        candidate += 1
        if value not in {0x1301, 0x1302, 0x1303}:
            values.append(value.to_bytes(2, "big"))
    return b"".join(values)


def maximal_vector_extension(
    template: ClientHelloTemplate, kind: int
) -> list[tuple[int, bytes]]:
    base = replace_extension(template.extensions, kind, b"\x00\x00")
    fixed = len(
        client_hello_body(template, cipher_suites=b"\x0a\x0a", extensions=base)
    )
    count = max(1, (TLS_HANDSHAKE_MESSAGE_MAX - 4 - fixed) // 2)
    values = unknown_u16_values(count)
    return replace_extension(template.extensions, kind, len(values).to_bytes(2, "big") + values)


def client_hello_shapes() -> dict[str, bytes]:
    template = parse_client_hello(generated_client_hello())
    unknown_cipher = b"\x0a\x0a"
    max_body = TLS_HANDSHAKE_MESSAGE_MAX - 4

    fixed_cipher_body = len(
        client_hello_body(
            template,
            cipher_suites=b"",
            extensions=template.extensions,
        )
    )
    cipher_bytes = max(2, ((max_body - fixed_cipher_body) // 2) * 2)
    cipher_values = unknown_u16_values(cipher_bytes // 2)

    base_unknown_extensions = list(template.extensions)
    fixed_extension_body = len(
        client_hello_body(
            template,
            cipher_suites=unknown_cipher,
            extensions=base_unknown_extensions,
        )
    )
    extension_count = max(1, (max_body - fixed_extension_body) // 4)
    used_kinds = {kind for kind, _ in base_unknown_extensions}
    unknown_extensions = []
    candidate = 0x4000
    while len(unknown_extensions) < extension_count:
        kind = candidate & 0xFFFF
        candidate += 1
        if kind not in used_kinds:
            unknown_extensions.append((kind, b""))

    key_share_base = replace_extension(template.extensions, 51, b"\x00\x00")
    key_share_fixed = len(
        client_hello_body(
            template,
            cipher_suites=unknown_cipher,
            extensions=key_share_base,
        )
    )
    key_share_count = max(1, (max_body - key_share_fixed) // 5)
    key_shares = b"".join(
        ((0x4000 + index) & 0xFFFF).to_bytes(2, "big") + b"\x00\x01\x00"
        for index in range(key_share_count)
    )
    key_share_extensions = replace_extension(
        template.extensions, 51, len(key_shares).to_bytes(2, "big") + key_shares
    )

    psk_base = replace_extension(template.extensions, 41, b"\x00\x00\x00\x00")
    psk_fixed = len(
        client_hello_body(
            template,
            cipher_suites=unknown_cipher,
            extensions=psk_base,
        )
    )
    psk_count = max(1, (max_body - psk_fixed) // 9)
    identities = b"\x00\x01x\x00\x00\x00\x00" * psk_count
    binders = b"\x01x" * psk_count
    psk_value = (
        len(identities).to_bytes(2, "big")
        + identities
        + len(binders).to_bytes(2, "big")
        + binders
    )
    # pre_shared_key must be the final extension in a conforming ClientHello.
    psk_extensions = [(kind, value) for kind, value in template.extensions if kind != 41]
    psk_extensions.append((41, psk_value))

    shapes = {
        "minimal-reject": encode_client_hello(
            template, cipher_suites=unknown_cipher, extensions=template.extensions
        ),
        "cipher-suite-cardinality": encode_client_hello(
            template, cipher_suites=cipher_values, extensions=template.extensions
        ),
        "unknown-extension-cardinality": encode_client_hello(
            template,
            cipher_suites=unknown_cipher,
            extensions=base_unknown_extensions + unknown_extensions,
        ),
        "signature-algorithm-cardinality": encode_client_hello(
            template,
            cipher_suites=unknown_cipher,
            extensions=maximal_vector_extension(template, 13),
        ),
        "supported-group-cardinality": encode_client_hello(
            template,
            cipher_suites=unknown_cipher,
            extensions=maximal_vector_extension(template, 10),
        ),
        "key-share-cardinality": encode_client_hello(
            template,
            cipher_suites=unknown_cipher,
            extensions=key_share_extensions,
        ),
        "psk-cardinality": encode_client_hello(
            template,
            cipher_suites=unknown_cipher,
            extensions=psk_extensions,
        ),
    }
    shapes["fragmented-unknown-extensions"] = encode_client_hello(
        template,
        cipher_suites=unknown_cipher,
        extensions=base_unknown_extensions + unknown_extensions,
        fragment=16,
    )
    return shapes


def make_fixture(root: Path, intermediates: int, names: int, algorithm: str) -> Fixture:
    root_key = root / "root.key"
    root_cert = root / "root.pem"
    if algorithm in {"p256", "p384"}:
        curve = "P-256" if algorithm == "p256" else "P-384"
        root_key_args = ["-newkey", "ec", "-pkeyopt", f"ec_paramgen_curve:{curve}"]
    elif algorithm == "ed25519":
        root_key_args = ["-newkey", "ed25519"]
    else:
        root_key_args = ["-newkey", f"rsa:{algorithm.removeprefix('rsa')}"]
    run(
        "openssl",
        "req",
        "-x509",
        *root_key_args,
        "-nodes",
        "-days",
        "2",
        "-subj",
        "/CN=httpd-rs TLS profile root",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout",
        os.fspath(root_key),
        "-out",
        os.fspath(root_cert),
    )

    ca_ext = root / "intermediate.ext"
    constraints = ""
    if names:
        permitted = ",".join(f"permitted;DNS:.zone{i}.example" for i in range(names))
        constraints = f"nameConstraints=critical,{permitted}\n"
    ca_ext.write_text(
        "basicConstraints=critical,CA:TRUE,pathlen:0\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        + constraints
    )
    intermediate_certs = []
    intermediate_keys = []
    for index in range(intermediates):
        key = root / f"intermediate-{index}.key"
        csr = root / f"intermediate-{index}.csr"
        cert = root / f"intermediate-{index}.pem"
        key_and_csr(key, csr, "/CN=httpd-rs ambiguous client issuer", algorithm)
        sign(csr, cert, root_cert, root_key, 1000 + index, ca_ext)
        intermediate_keys.append(key)
        intermediate_certs.append(cert)

    server_key = root / "server.key"
    server_csr = root / "server.csr"
    server_cert = root / "server.pem"
    server_ext = root / "server.ext"
    server_ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
    )
    # ring verifies RSA public keys through 8192 bits, but does not accept an
    # 8192-bit private key for the server signing role. Keep the server's
    # CertificateVerify key at P-256 for that verifier-only extremum.
    server_algorithm = "p256" if algorithm == "rsa8192" else algorithm
    key_and_csr(server_key, server_csr, "/CN=localhost", server_algorithm)
    sign(server_csr, server_cert, root_cert, root_key, 2000, server_ext)

    client_key = root / "client.key"
    client_csr = root / "client.csr"
    client_leaf = root / "client.pem"
    client_ext = root / "client.ext"
    sans = ",".join(f"DNS:client.zone{i}.example" for i in range(names))
    client_ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=clientAuth\n"
        + (f"subjectAltName={sans}\n" if sans else "")
    )
    key_and_csr(client_key, client_csr, "/CN=httpd-rs profile client", algorithm)
    sign(
        client_csr,
        client_leaf,
        intermediate_certs[-1],
        intermediate_keys[-1],
        3000,
        client_ext,
    )
    return Fixture(
        root=root,
        root_cert=root_cert,
        server_cert=server_cert,
        server_key=server_key,
        client_key=client_key,
        client_leaf=client_leaf,
        intermediates=intermediate_certs,
    )


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def proc_value(pid: int, name: str) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith(name + ":"):
                return int(line.split()[1])
    except (FileNotFoundError, ProcessLookupError):
        pass
    return 0


def cpu_seconds(pid: int) -> float:
    try:
        values = Path(f"/proc/{pid}/stat").read_text().split()
        return (int(values[13]) + int(values[14])) / os.sysconf("SC_CLK_TCK")
    except (FileNotFoundError, ProcessLookupError):
        return 0.0


def stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass


def start_server(
    fixture: Fixture, label: str, mtls: bool
) -> tuple[subprocess.Popen[bytes], int, Path]:
    port = free_port()
    server_root = fixture.root / f"server-{label}"
    logs = server_root / "logs"
    www = server_root / "www"
    logs.mkdir(parents=True)
    www.mkdir()
    (www / "ok.txt").write_text("ok\n")
    user = pwd.getpwuid(os.geteuid()).pw_name
    group = grp.getgrgid(os.getegid()).gr_name
    config = server_root / "httpd-rs.conf"
    config.write_text(
        f'''ServerRoot "{server_root}"
Listen 127.0.0.1:{port}
User {user}
Group {group}
PidFile "{logs / 'httpd-rs.pid'}"
ErrorLog "{logs / 'error.log'}"
ServerName localhost
SSLEngine On
SSLProtocol TLSv1.3
SSLCertificateFile "{fixture.server_cert}"
SSLCertificateKeyFile "{fixture.server_key}"
SSLSessionCache none
SSLSessionTickets Off
{'SSLVerifyClient require' if mtls else 'SSLVerifyClient none'}
{'SSLCACertificateFile ' + chr(34) + os.fspath(fixture.root_cert) + chr(34) if mtls else ''}
DocumentRoot "{www}"
<Directory "{www}">
    Require all granted
</Directory>
'''
    )
    process = subprocess.Popen(
        [os.fspath(HTTPD), "-f", os.fspath(config), "-X"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    deadline = time.monotonic() + 10
    pid_file = logs / "httpd-rs.pid"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output, _ = process.communicate()
            raise RuntimeError(output.decode(errors="replace"))
        # A probe TCP connection itself consumes one TLS/mTLS rate unit and
        # would skew the low-cardinality signature measurements. The pid file
        # is written only after listener setup has succeeded.
        if pid_file.exists():
            return process, port, config
        time.sleep(0.05)
    stop(process)
    raise RuntimeError("httpd-rs did not become ready")


def context(chain: Path | None, key: Path | None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.options |= getattr(ssl, "OP_NO_TICKET", 0)
    if chain is not None and key is not None:
        ctx.load_cert_chain(chain, key)
    return ctx


def one_handshake(port: int, ctx: ssl.SSLContext, source: str) -> bool:
    raw = socket.socket()
    raw.settimeout(20)
    raw.bind((source, 0))
    try:
        raw.connect(("127.0.0.1", port))
        with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            tls.sendall(
                b"GET /ok.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            response = b""
            while True:
                block = tls.recv(4096)
                if not block:
                    break
                response += block
            return b" 200 " in response.split(b"\r\n", 1)[0]
    except (ConnectionError, OSError, ssl.SSLError):
        raw.close()
        return False


def one_raw_client_hello(port: int, payload: bytes, source: str) -> bool:
    """Send one hostile ClientHello and report prompt terminal handling."""

    raw = socket.socket()
    raw.settimeout(5)
    raw.bind((source, 0))
    try:
        raw.connect(("127.0.0.1", port))
        raw.sendall(payload)
        raw.shutdown(socket.SHUT_WR)
        while raw.recv(4096):
            pass
        return True
    except TimeoutError:
        return False
    except (ConnectionError, OSError):
        # An alert followed by reset is also a prompt terminal rejection.
        return True
    finally:
        raw.close()


def measure(
    fixture: Fixture,
    label: str,
    mtls: bool,
    chain_count: int,
    handshakes: int,
    concurrency: int,
) -> None:
    process, port, _ = start_server(fixture, label, mtls)
    try:
        chain = fixture.chain(chain_count) if mtls else None
        ctx = context(chain, fixture.client_key if mtls else None)
        baseline_rss = proc_value(process.pid, "VmRSS")
        baseline_hwm = proc_value(process.pid, "VmHWM")
        baseline_cpu = cpu_seconds(process.pid)
        started = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [
                pool.submit(
                    one_handshake,
                    port,
                    ctx,
                    f"127.0.0.{2 + (index % 200)}",
                )
                for index in range(handshakes)
            ]
            peak_rss = baseline_rss
            while not all(future.done() for future in futures):
                peak_rss = max(peak_rss, proc_value(process.pid, "VmRSS"))
                time.sleep(0.001)
            results = [future.result() for future in futures]
        elapsed = time.perf_counter() - started
        final_hwm = proc_value(process.pid, "VmHWM")
        peak_rss = max(peak_rss, final_hwm)
        print(
            f"case={label} mtls={str(mtls).lower()} chain={chain_count if mtls else 0} "
            f"handshakes={handshakes} concurrency={concurrency} success={sum(results)} "
            f"wall_s={elapsed:.6f} cpu_s={cpu_seconds(process.pid) - baseline_cpu:.6f} "
            f"rss_before_kib={baseline_rss} rss_after_kib={proc_value(process.pid, 'VmRSS')} "
            f"rss_peak_kib={peak_rss} rss_delta_kib={max(0, final_hwm - baseline_hwm)} "
            f"server_exit={process.poll()}"
        )
    finally:
        stop(process)


def measure_client_hello(
    fixture: Fixture,
    label: str,
    payload: bytes,
    handshakes: int,
    concurrency: int,
) -> None:
    process, port, _ = start_server(fixture, f"clienthello-{label}", False)
    try:
        baseline_rss = proc_value(process.pid, "VmRSS")
        baseline_hwm = proc_value(process.pid, "VmHWM")
        baseline_cpu = cpu_seconds(process.pid)
        started = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [
                pool.submit(
                    one_raw_client_hello,
                    port,
                    payload,
                    f"127.0.0.{2 + (index % 200)}",
                )
                for index in range(handshakes)
            ]
            peak_rss = baseline_rss
            while not all(future.done() for future in futures):
                peak_rss = max(peak_rss, proc_value(process.pid, "VmRSS"))
                time.sleep(0.001)
            results = [future.result() for future in futures]
        elapsed = time.perf_counter() - started
        final_hwm = proc_value(process.pid, "VmHWM")
        peak_rss = max(peak_rss, final_hwm)
        record_count = 0
        cursor = 0
        while cursor + 5 <= len(payload):
            length = int.from_bytes(payload[cursor + 3 : cursor + 5], "big")
            cursor += 5 + length
            record_count += 1
        print(
            f"case=clienthello-{label} wire_bytes={len(payload)} records={record_count} "
            f"handshakes={handshakes} concurrency={concurrency} terminal={sum(results)} "
            f"wall_s={time.perf_counter() - started:.6f} "
            f"cpu_s={cpu_seconds(process.pid) - baseline_cpu:.6f} "
            f"rss_before_kib={baseline_rss} rss_after_kib={proc_value(process.pid, 'VmRSS')} "
            f"rss_peak_kib={peak_rss} rss_delta_kib={max(0, final_hwm - baseline_hwm)} "
            f"server_exit={process.poll()}"
        )
    finally:
        stop(process)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--max-chain",
        type=int,
        default=32,
        help="maximum presented intermediate count (the leaf is additional)",
    )
    parser.add_argument("--names", type=int, default=0)
    parser.add_argument(
        "--algorithm",
        choices=("p256", "p384", "ed25519", "rsa2048", "rsa4096", "rsa8192"),
        default="p256",
    )
    parser.add_argument("--handshakes", type=int, default=32)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument(
        "--skip-clienthello",
        action="store_true",
        help="skip hostile ClientHello cardinality/fragmentation profiles",
    )
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if args.max_chain < 1 or args.max_chain > 64:
        parser.error("--max-chain must be 1..64")
    if args.names < 0 or args.names > 128:
        parser.error("--names must be 0..128")
    work = Path(tempfile.mkdtemp(prefix="httpd-rs-tls-dependency-profile-"))
    try:
        fixture = make_fixture(work, args.max_chain, args.names, args.algorithm)
        print(f"binary={HTTPD}")
        print(f"fixture={work}")
        print(f"signature_algorithm={args.algorithm}")
        print(f"name_constraints_and_sans={args.names}")
        measure(fixture, "ordinary-tls", False, 0, args.handshakes, args.concurrency)
        counts = sorted({1, 4, 7, 8, 16, args.max_chain})
        for count in (value for value in counts if value <= args.max_chain):
            measure(
                fixture,
                f"mtls-chain-{count}",
                True,
                count,
                args.handshakes,
                args.concurrency,
            )
        if not args.skip_clienthello:
            for label, payload in client_hello_shapes().items():
                measure_client_hello(
                    fixture,
                    label,
                    payload,
                    args.handshakes,
                    args.concurrency,
                )
        return 0
    finally:
        if args.keep:
            print(f"retained_fixture={work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
