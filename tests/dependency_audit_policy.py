#!/usr/bin/env python3
"""Keep Vapache's cargo-vet evidence from quietly regressing."""

from pathlib import Path
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "supply-chain" / "config.toml"
AUDITS = ROOT / "supply-chain" / "audits.toml"
MAX_EXEMPTIONS = 105
REQUIRED_IMPORTS = {
    "actix",
    "ariel-os",
    "bytecode-alliance",
    "embark-studios",
    "fermyon",
    "google",
    "isrg",
    "mozilla",
    "zcash",
}
REQUIRED_LOCAL_AUDITS = {
    "bitflags",
    "linux-raw-sys",
    "rustix",
    "smallvec",
    "webpki-roots",
}


def fail(message: str) -> None:
    print(f"dependency-audit-policy: {message}", file=sys.stderr)
    raise SystemExit(1)


config = tomllib.loads(CONFIG.read_text(encoding="utf-8"))
audits = tomllib.loads(AUDITS.read_text(encoding="utf-8"))

imports = config.get("imports", {})
if set(imports) != REQUIRED_IMPORTS:
    fail(
        "trusted import set changed: expected "
        f"{sorted(REQUIRED_IMPORTS)}, found {sorted(imports)}"
    )
for name, settings in imports.items():
    url = settings.get("url", "")
    if not url.startswith("https://"):
        fail(f"{name} audit import is not authenticated HTTPS: {url!r}")

exemptions = config.get("exemptions", {})
exemption_count = sum(len(entries) for entries in exemptions.values())
if exemption_count > MAX_EXEMPTIONS:
    fail(f"exemptions increased from the {MAX_EXEMPTIONS}-entry ceiling to {exemption_count}")

local_audits = audits.get("audits", {})
missing = REQUIRED_LOCAL_AUDITS - set(local_audits)
if missing:
    fail(f"required local audits disappeared: {sorted(missing)}")
for crate in REQUIRED_LOCAL_AUDITS:
    entries = local_audits[crate]
    if not entries or any(not entry.get("notes", "").strip() for entry in entries):
        fail(f"{crate} local audit must retain its review notes")

print(
    "dependency-audit-policy: "
    f"{len(local_audits)} locally audited crates, "
    f"{len(imports)} trusted audit imports, {exemption_count} exemptions"
)
