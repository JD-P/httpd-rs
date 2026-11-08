# CVE root-cause triage matrices

## Apache HTTP Server

This directory contains a complete static triage of the Apache HTTP Server
CVEs in the NVD CPE set:

```text
cpe:2.3:a:apache:http_server
```

The snapshot contains **371 CVEs**. It is a triage of whether the current
Vapache specification and implementation boundary would prevent each CVE
*in principle*, not a claim that every CVE has a working replay test.

### Files

- `nvd-cpe.json` — NVD 2.0 response used as the source snapshot.
- `apache2-cve-matrix.json` — one row per CVE with status, surface,
  severity, confidence, rationale and description.
- `apache2-cve-matrix.csv` — the same full matrix in spreadsheet form.
- `apache2-cve-matrix.md` — summary and the highest-risk gap list.

Regenerate and validate:

```sh
python3 tests/cve_matrix.py
python3 tests/cve_matrix.py --check
```

### Current result

| classification | count |
|---|---:|
| prevented by construction / verified primitive | 126 |
| fail closed / not applicable | 244 |
| **spec prevents in principle** | **370** |
| partial: some layers verified, full class not | 0 |
| **not covered by the formal spec** | **1** |

The sole not-covered CVE is:

| surface | count |
|---|---:|
| TLS client certificate / OCSP (external Rustls parser) | 1 |

It has medium severity; there are **0 high/critical not-covered rows**. There are no remaining partial rows.

This means the current spec is not a blanket “all Apache CVEs prevented”
claim. It is strong on the parsed/fail-closed core and weak on the
implemented-but-unmodelled protocol surfaces.

### Method and limits

Status meanings:

- **prevented** — Rust memory safety, verified parsing, `openat2`
  containment, Rustls, or another implementation or verification property
  prevents the root cause described by the advisory.
- **fail_closed / not_applicable** — the module, platform, directive or
  feature is absent or rejected.
- **partial** — a relevant layer is verified, but the complete CVE class is
  not; for example HTTP/1 framing is verified while HTTP/2 or proxy
  translation is not.
- **not_covered** — the production behavior is implemented but outside the
  formal model.
- **needs_review** — the public source record is internally inconsistent or
  does not describe the cause in enough detail for a reliable comparison.

Classification is static and intentionally conservative. It uses NVD
descriptions plus explicit human overrides for ambiguous historical cases.
It does not execute each CVE PoC, and NVD descriptions can be incomplete.
The grouping and proposed spec strengthening for the 1 not-covered row are
in `not-covered-strengthening.md`.  The next step is a replay corpus for the
0 high/critical not-covered rows.

## Cross-server histories

`cross-server-nvd.json` is a reproducible NVD API 2.0 snapshot for eleven
widely deployed server/proxy families: nginx, Microsoft IIS/HTTP.sys,
lighttpd, HAProxy, Tomcat/Coyote, Jetty, Squid, Varnish, Apache Traffic
Server, LiteSpeed/OpenLiteSpeed and Envoy. It retains the query aliases,
publication/modification dates, CVSS data, references and exact vulnerable
CPE criteria. Rows shared by products are deduplicated by CVE ID.

The current snapshot contains **1,047 distinct CVEs**:

| classification | count |
|---|---:|
| prevented by Vapache's design/implementation | 370 |
| explicitly fail closed | 54 |
| affected feature/platform is absent | 580 |
| partial: exact trigger or complete invariant remains unresolved | 41 |
| NVD source record needs review | 2 |

Combined with the separate 371-row Apache HTTP Server ledger, the repository
now contains **1,412 unique CVE IDs** across twelve server/proxy families; six
IDs are present in both source sets.

The comparison includes **539 explicit advisory/patch overrides** and 508
conservative description/feature rules. Rule-derived rows identify that fact
in `classification_method`; they are not presented as individually replayed
PoCs. The 41 partial and 2 source-conflict rows are deliberately not counted
as prevented.

Files:

- `cross-server-nvd.json` — normalized source snapshot and query provenance.
- `cross-server-cve-matrix.json` — complete per-CVE root cause, Vapache
  comparison, implementation evidence, confidence and advisory links.
- `cross-server-cve-matrix.csv` — the same complete ledger for review.
- `cross-server-cve-matrix.md` — product counts and the high/critical open set.

Regenerate from the checked-in snapshot or refresh it from NVD:

```sh
python3 tests/cross_server_cve_matrix.py
python3 tests/cross_server_cve_matrix.py --check
python3 tests/cross_server_cve_matrix.py --fetch  # NVD rate limits apply
```

This remains a static root-cause/design comparison. `prevented` means the
specific primitive was removed or bounded; it does not mean Vapache is free
of independent bugs in the same subsystem.
