#!/usr/bin/env python3
"""Profile request-reachable rustls/webpki TLS and mTLS resource shapes.

The harness is entirely loopback-local. It creates a root, server identity and
same-subject client intermediates. A leaf is signed by the final intermediate,
while preceding certificates are valid CA certificates with the same subject
but different keys. Presenting the real signer last makes webpki explore the
issuer candidates without relying on malformed DER or an untrusted chain.
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
        return 0
    finally:
        if args.keep:
            print(f"retained_fixture={work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
