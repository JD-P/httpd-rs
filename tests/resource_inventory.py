#!/usr/bin/env python3
"""Keep mutable process state and hierarchical request resources explicit."""

from pathlib import Path
import re
import sys

from resource_warrant import mask_non_code, strip_test_modules

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "crates" / "server" / "src"

EXPECTED_SLOTS = {
    "DynamicBackend", "H2Stream", "SlowInput", "SlowOutput", "ResponseBodyRead", "Websocket",
    "ExpensiveCpu", "PendingConnection", "H1Connection", "RequestWorker",
    "RequestBodyWorker", "H2Connection", "TlsHandshake",
    "RewriteProgram", "SpoolFile", "SlowSpoolFile",
    "FilesystemWork", "BlockingIo", "BcryptCpu", "CompressionCpu", "AsyncRequestWork",
}
EXPECTED_BYTES = {
    "Spool", "SlowSpool", "RequestResident", "ResponseResident",
    "SlowResponseResident", "PolicyExpansion", "CacheResident", "CompressionTransient",
}
EXPECTED_PHYSICAL = {"FileDescriptor", "Task", "ResidentMemory"}

# These are generation/process infrastructure, bounded caches, telemetry,
# thread-local request state, temporary-name counters, or test-only state.
# Adding one is a security-review action and requires updating
# docs/resource-inventory.md.
ALLOWED_MUTABLE_STATICS = {
    ("access.rs", "SENDER"),
    ("auth.rs", "CACHE"), ("auth.rs", "NEXT_TEMP"),
    ("auth.rs", "PASSWORD_VERIFY_CALLS"),
    ("cache.rs", "CACHE_EPOCH"), ("cache.rs", "BARRIER"),
    ("cache.rs", "CACHE"),
    ("cache.rs", "USAGE"), ("cache.rs", "SCAN"), ("cache.rs", "LOCKS"),
    ("cgi.rs", "POOL"),
    ("config.rs", "NEXT"), ("config.rs", "NEXT_FIXTURE"),
    ("config.rs", "REGISTRY"),
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
    ("resource.rs", "CURRENT_CONTEXT"), ("resource.rs", "CURRENT_REQUEST_SCOPE"),
    ("resource.rs", "BLOCKING_IO_OWNER"),
    ("resource.rs", "BUDGET"),
    ("server.rs", "ACTIVE_CONNECTIONS"),
    ("server.rs", "ADMISSION_RUNTIME"),
    ("server.rs", "CONNECTION_WORK_POOL"),
    ("server.rs", "INLINE_DYNAMIC_WORKERS"),
    ("server.rs", "ADMISSION_TEST_LOCK"),
    ("status.rs", "START"), ("status.rs", "REQUESTS"),
    ("status.rs", "BYTES"),
    ("tls.rs", "PRIVILEGED_FILE_BROKER"),
    ("util.rs", "HTTP_DATE_CACHE"),
    ("whole_request_fuzz.rs", "FIXTURE"),
}

FORBIDDEN_SPLIT_LEDGERS = {
    "ACTIVE_WORKERS", "ACTIVE_BODY_WORKERS", "PENDING_CONNECTIONS",
    "H2_CONNECTIONS", "TLS_HANDSHAKES", "ACTIVE_PRG_MAPS",
    "EXPENSIVE_OPS", "POLICY_RESIDENT_BYTES",
}

# Request-reachable process/generation collections must carry a locally
# checkable cardinality/byte/ownership contract. The ordinary mutable-static
# allowlist above answers "was this reviewed?"; this table additionally
# answers "what keeps it finite?". Evidence tokens are intentionally source
# names rather than prose so renaming/removing a bound fails CI.
SHARED_STATIC_CONTRACTS = {
    ("access.rs", "SENDER"): ("DNS_QUEUE", "sync_channel", "AsyncWorkLease"),
    ("auth.rs", "CACHE"): (
        "MAX_AUTH_CACHE_ENTRIES", "MAX_AUTH_CACHE_BYTES", "shared_map_insert_admit",
    ),
    ("cache.rs", "CACHE"): (
        "MAX_ENTRIES", "max_memory_size", "CacheResidentLease", "shared_map_insert_admit",
    ),
    ("cache.rs", "USAGE"): ("MAX_DISK_ENTRIES", "max_disk_size", "DiskLease"),
    ("cache.rs", "SCAN"): ("try_lock", "MAX_DISK_SCAN_RECORDS"),
    ("cache.rs", "LOCKS"): ("STRIPES", "disk_io_locks"),
    ("cgi.rs", "POOL"): ("clamp(8, 64)", "wait_timeout", "CgiWorker"),
    ("config.rs", "REGISTRY"): ("OnceLock", "known_directives"),
    ("h2.rs", "POOL"): ("POOL_MAX_ENTRIES", "POOL_MAX_TOTAL"),
    ("htaccess.rs", "CACHE"): (
        "MAX_ACCESS_CACHE_ENTRIES", "MAX_ACCESS_CACHE_BYTES", "shared_map_insert_admit",
    ),
    ("ocsp.rs", "CACHE"): (
        "MAX_OCSP_MEMORY_CACHE_ENTRIES", "MAX_OCSP_MEMORY_CACHE_BYTES",
        "shared_map_insert_admit",
    ),
    ("ocsp.rs", "DISK"): ("DiskLease", "try_disk_at"),
    ("proxy.rs", "DEAD"): ("MAX_PROXY_GENERATION_STATE", "drop_generation_state"),
    ("proxy.rs", "HEALTH"): ("MAX_PROXY_GENERATION_STATE", "drop_generation_state"),
    ("proxy.rs", "COUNTERS"): ("MAX_PROXY_GENERATION_STATE", "drop_generation_state"),
    ("proxy.rs", "DNS"): ("sync_channel", "AsyncWorkLease"),
    ("resource.rs", "BUDGET"): ("ResourceBudget", "try_slot", "release_physical"),
    ("server.rs", "CONNECTION_WORK_POOL"): (
        "CONNECTION_WORK_QUEUE", "shared_queue_push_admit", "VecDeque",
    ),
    ("tls.rs", "PRIVILEGED_FILE_BROKER"): ("tls_file_specs", "HashMap"),
}

# Shared collections owned by a Config/connection rather than a static still
# need explicit structural bounds. Anchors are unique type declarations; the
# listed evidence must stay in the same source file.
OWNED_SHARED_CONTRACTS = {
    ("cache.rs", "struct MemoryCache"): ("MAX_ENTRIES", "CacheResidentLease"),
    ("config.rs", "struct BoundedPolicyCache"): (
        "POLICY_CACHE_MAX_ENTRIES", "POLICY_CACHE_MAX_BYTES", "shared_map_insert_admit",
    ),
    ("config.rs", "struct BoundedLayeredPolicyCache"): (
        "POLICY_CACHE_MAX_ENTRIES", "POLICY_CACHE_MAX_BYTES", "shared_map_insert_admit",
    ),
    ("h2.rs", "struct H2ConnectionLedger"): (
        "max_concurrent_streams", "mpsc::channel", "H2TaskEventGuard",
    ),
    ("http.rs", "struct StreamingBody {"): (
        "STREAMING_BODY_CHANNEL_CHUNKS", "mpsc::Receiver", "ResidentLease",
    ),
    ("proxy.rs", "struct ProxySession"): (
        "MAX_PROXY_SESSION_BACKENDS", "shared_map_insert_admit", "DynamicLease",
    ),
    ("proxy.rs", "struct BackendIdentityRegistry"): (
        "MAX_BACKEND_IDENTITIES", "shared_map_insert_admit", "generation",
    ),
    ("resource.rs", "struct RateWindow"): (
        "MAX_REQUESTS_PER_SECOND", "clients.clear", "hierarchical_weighted_rate_admit",
    ),
    ("resource.rs", "struct DiskLedgers"): ("DiskLease", "DEFAULT_DISK_FILE_BUDGET"),
    ("server.rs", "struct ConnectionWorkState"): (
        "CONNECTION_WORK_QUEUE", "shared_queue_push_admit", "VecDeque",
    ),
    ("tls.rs", "struct ExpiringSessionCache"): (
        "capacity", "shared_map_insert_admit", "prune_expired",
    ),
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
    sources: dict[str, str] = {}
    static_pattern = re.compile(r"\bstatic\s+([A-Z][A-Z0-9_]*)\s*:")
    all_source = ""
    for path in sorted(SRC.glob("*.rs")):
        text = path.read_text()
        sources[path.name] = text
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

    for key, evidence in SHARED_STATIC_CONTRACTS.items():
        if key not in observed:
            errors.append(f"shared-state contract has no static: {key}")
            continue
        text = sources[key[0]]
        missing_evidence = [token for token in evidence if token not in text]
        if missing_evidence:
            errors.append(f"shared-state contract {key} lost evidence: {missing_evidence}")
    for (filename, anchor), evidence in OWNED_SHARED_CONTRACTS.items():
        text = sources.get(filename, "")
        if text.count(anchor) != 1:
            errors.append(f"owned shared-state anchor must occur once: {(filename, anchor)}")
        missing_evidence = [token for token in evidence if token not in text]
        if missing_evidence:
            errors.append(
                f"owned shared-state contract {(filename, anchor)} lost evidence: "
                f"{missing_evidence}"
            )

    # There is no acceptable production use of a conventionally one-message
    # unbounded channel. Use oneshot/sync_channel/bounded Tokio mpsc, or add a
    # real capacity tied to an ownership ceiling. Test modules are excluded.
    unbounded = re.compile(r"\b(?:std::sync::)?mpsc::(?:unbounded_channel|channel)\s*\(\s*\)")
    for filename, raw in sources.items():
        masked = mask_non_code(raw)
        production, production_masked = strip_test_modules(raw, masked)
        del production
        for match in unbounded.finditer(production_masked):
            line = production_masked.count("\n", 0, match.start()) + 1
            errors.append(f"unbounded production channel: {filename}:{line}")

    for required in (
        "with_resource_context(context", "try_dynamic_in", "try_h2_stream_in",
        "try_slow_input_in", "try_slow_output_in",
        "try_filesystem_work_in", "try_blocking_io_in", "begin_blocking_io",
        "try_compression_in", "try_async_work", "try_disk", "try_transport_buffers",
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
        f"{len(observed)} reviewed statics, "
        f"{len(SHARED_STATIC_CONTRACTS) + len(OWNED_SHARED_CONTRACTS)} shared-state contracts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
