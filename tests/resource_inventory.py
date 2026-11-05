#!/usr/bin/env python3
"""Keep mutable process state and hierarchical request resources explicit."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "crates" / "server" / "src"

EXPECTED_SLOTS = {
    "DynamicBackend", "H2Stream", "SlowOutput", "ResponseBodyRead", "Websocket",
    "ExpensiveCpu", "PendingConnection", "H1Connection", "RequestWorker",
    "RequestBodyWorker", "H2Connection", "TlsHandshake",
    "RewriteProgram", "SpoolFile", "SlowSpoolFile",
    "FilesystemWork",
}
EXPECTED_BYTES = {
    "Spool", "SlowSpool", "RequestResident", "ResponseResident",
    "SlowResponseResident", "PolicyExpansion", "CacheResident",
}
EXPECTED_PHYSICAL = {"FileDescriptor", "Task", "ResidentMemory"}

# These are generation/process infrastructure, bounded caches, telemetry,
# thread-local request state, temporary-name counters, or test-only state.
# Adding one is a security-review action and requires updating
# docs/resource-inventory.md.
ALLOWED_MUTABLE_STATICS = {
    ("access.rs", "SENDER"),
    ("auth.rs", "CACHE"), ("auth.rs", "NEXT_TEMP"),
    ("cache.rs", "CACHE_EPOCH"), ("cache.rs", "BARRIER"),
    ("cache.rs", "CACHE"),
    ("cache.rs", "USAGE"), ("cache.rs", "SCAN"), ("cache.rs", "LOCKS"),
    ("cgi.rs", "POOL"),
    ("config.rs", "NEXT"), ("config.rs", "NEXT_FIXTURE"),
    ("config.rs", "NEXT_CONFIG_GENERATION"),
    ("expr.rs", "REQUEST_HTTPS"), ("expr.rs", "REQUEST_PORT"),
    ("expr.rs", "REQUEST_SERVER_NAME"),
    ("fastcgi.rs", "COUNTER"),
    ("fault.rs", "TASK_PLAN"), ("fault.rs", "THREAD_PLAN"),
    ("files.rs", "DIR"), ("files.rs", "REQUEST_ROOT_FDS"),
    ("files.rs", "REQUEST_METADATA"),
    ("files.rs", "REQUEST_SYMLINK_METADATA"),
    ("h2.rs", "POOL"), ("htaccess.rs", "CACHE"),
    ("htaccess.rs", "TEST_REJECT_SPEC"),
    ("htaccess.rs", "TEST_UNHANDLED_SPEC"),
    ("http.rs", "COUNTER"),
    ("log.rs", "STDERR_WRITER_BUSY"), ("log.rs", "LOG_WRITER_BUSY"),
    ("log.rs", "LOG_TIME_CACHE"), ("log.rs", "ACCESS_LINE"),
    ("log.rs", "TEST_GATE"),
    ("main.rs", "STOP"), ("main.rs", "RELOAD"), ("main.rs", "REOPEN"),
    ("main.rs", "GLOBAL_ALLOCATOR"),
    ("ocsp.rs", "CACHE"), ("ocsp.rs", "NEXT_TEMP"), ("ocsp.rs", "DISK"),
    ("proxy.rs", "DEAD"), ("proxy.rs", "HEALTH"),
    ("proxy.rs", "GENERATION"), ("proxy.rs", "COUNTERS"),
    ("proxy.rs", "DNS"),
    ("proxy.rs", "TEST_BUDGET"),
    ("request_plan.rs", "NEXT_FIXTURE"),
    ("resource.rs", "CURRENT_CONTEXT"), ("resource.rs", "BUDGET"),
    ("server.rs", "ACTIVE_CONNECTIONS"),
    ("server.rs", "ADMISSION_RUNTIME"),
    ("server.rs", "CONNECTION_WORK_POOL"),
    ("server.rs", "INLINE_DYNAMIC_WORKERS"),
    ("server.rs", "ADMISSION_TEST_LOCK"),
    ("status.rs", "START"), ("status.rs", "REQUESTS"),
    ("status.rs", "BYTES"),
    ("tls.rs", "PRIVILEGED_FILE_BROKER"),
    ("util.rs", "HTTP_DATE_CACHE"),
}

FORBIDDEN_SPLIT_LEDGERS = {
    "ACTIVE_WORKERS", "ACTIVE_BODY_WORKERS", "PENDING_CONNECTIONS",
    "H2_CONNECTIONS", "TLS_HANDSHAKES", "ACTIVE_PRG_MAPS",
    "EXPENSIVE_OPS", "POLICY_RESIDENT_BYTES",
}


def enum_variants(text: str, name: str) -> set[str]:
    match = re.search(rf"enum\s+{name}\s*\{{(?P<body>.*?)\n\}}", text, re.S)
    if not match:
        raise AssertionError(f"missing {name}")
    return set(re.findall(r"^\s*([A-Z][A-Za-z0-9_]*)\s*,", match["body"], re.M))


def main() -> int:
    resource = (SRC / "resource.rs").read_text()
    errors: list[str] = []
    if enum_variants(resource, "SlotKind") != EXPECTED_SLOTS:
        errors.append("SlotKind changed without updating the resource inventory")
    if enum_variants(resource, "ByteKind") != EXPECTED_BYTES:
        errors.append("ByteKind changed without updating the resource inventory")
    if enum_variants(resource, "PhysicalKind") != EXPECTED_PHYSICAL:
        errors.append("PhysicalKind changed without updating the resource inventory")

    observed: set[tuple[str, str]] = set()
    static_pattern = re.compile(r"\bstatic\s+([A-Z][A-Z0-9_]*)\s*:")
    all_source = ""
    for path in sorted(SRC.glob("*.rs")):
        text = path.read_text()
        all_source += text
        observed.update((path.name, name) for name in static_pattern.findall(text))
    unknown = observed - ALLOWED_MUTABLE_STATICS
    missing = ALLOWED_MUTABLE_STATICS - observed
    if unknown:
        errors.append(f"unreviewed mutable static state: {sorted(unknown)}")
    if missing:
        errors.append(f"stale resource-inventory allowlist: {sorted(missing)}")
    leaked = sorted(
        name
        for name in FORBIDDEN_SPLIT_LEDGERS
        if re.search(rf"\b{re.escape(name)}\b", all_source)
    )
    if leaked:
        errors.append(f"standalone attacker resource ledgers returned: {leaked}")

    for required in (
        "with_resource_context(context", "try_dynamic_in", "try_h2_stream_in",
        "try_slow_output_in",
        "try_filesystem_work_in", "try_disk", "try_transport_buffers",
        "try_tls_handshake", "try_rewrite_program",
        "attribute_context(resource_context", "enter_resource_context(resource_context",
    ):
        if required not in all_source:
            errors.append(f"hierarchical integration marker disappeared: {required}")

    if errors:
        for error in errors:
            print(f"resource inventory: {error}", file=sys.stderr)
        return 1
    print(
        f"resource inventory: {len(EXPECTED_SLOTS)} slot classes, "
        f"{len(EXPECTED_BYTES)} byte classes, {len(EXPECTED_PHYSICAL)} physical classes, "
        f"{len(observed)} reviewed statics"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
