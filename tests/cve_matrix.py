#!/usr/bin/env python3
"""Build and validate the Apache HTTP Server CVE triage matrix.

The source data is the NVD CPE query for `cpe:2.3:a:apache:http_server`
(371 CVEs at the time this matrix was built).  Classification is a *static
triage* of whether the current httpd-rs specification/implementation boundary
would prevent the vulnerability in principle.  It is not a claim that every
CVE has a working PoC replay test.

Status meanings:
  prevented      construction/verified primitive prevents the primitive
  fail_closed    unsupported feature/config is rejected or returns 500
  not_applicable feature/platform absent
  partial        some relevant layer is verified; the whole class is not
  not_covered    implemented behavior is outside the formal spec
  needs_review   classifier could not decide
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "docs" / "cve" / "nvd-cpe.json"
OUT = ROOT / "docs" / "cve" / "apache2-cve-matrix.json"
CSV_OUT = ROOT / "docs" / "cve" / "apache2-cve-matrix.csv"
REPORT = ROOT / "docs" / "cve" / "apache2-cve-matrix.md"

# Explicit human triage where keyword classification would be wrong or
# incomplete.  Keep reasons short; the JSON retains the NVD description.
OVERRIDES: dict[str, tuple[str, str, str, str]] = {
    "CVE-2004-0488": ("not_covered", "tls-client", "Rustls replaces the legacy OpenSSL certificate parser, but the external parser is an explicit trusted dependency rather than a httpd-rs formal proof", "medium"),
    "CVE-2019-0215": ("fail_closed", "tls-client-location", "per-location SSLVerifyClient/SSLCACertificateFile is rejected; Rustls client authentication is connection-scoped", "high"),
    "CVE-2025-23048": ("prevented", "tls-client-policy", "one uniform client-certificate policy per TLS listener is enforced; vhosts with different SSLVerifyClient/SSLCACertificateFile policies are rejected, so resumption cannot cross policy", "high"),
    "CVE-2026-44185": ("prevented", "tls-ocsp", "the custom OCSP response path is safe Rust, bounds HTTP lines/headers/body to 16 KiB/64 KiB/2 MiB, and has no C buffer over-read primitive", "high"),
    "CVE-1999-0045": ("not_applicable", "cgi-sample", "nph-test-cgi is a sample script not shipped by httpd-rs; only administrator-configured scripts execute", "high"),
    "CVE-1999-0067": ("not_applicable", "cgi-sample", "phf is a sample CGI script not shipped by httpd-rs", "high"),
    "CVE-1999-0070": ("not_applicable", "cgi-sample", "test-cgi is a sample CGI script not shipped by httpd-rs", "high"),
    "CVE-2000-0868": ("not_applicable", "cgi-distro", "the SuSE-specific /cgi-bin-sdb/ package alias is not shipped; httpd-rs has no implicit CGI alias", "medium"),
    "CVE-2000-1205": ("not_applicable", "cgi-sample-xss", "printenv sample scripts are not shipped and httpd-rs error pages set an explicit charset", "medium"),
    "CVE-2002-1592": ("prevented", "cgi-error-path", "CGI failure uses the generic error page and does not include script filesystem paths", "high"),
    "CVE-2002-1658": ("not_applicable", "cgi-tool", "htdigest is not part of httpd-rs and has no CGI execution path", "high"),
    "CVE-2002-1850": ("prevented", "cgi-stderr", "stdout/stderr are drained on separate threads with a 64 KiB stderr cap and timeout/kill; no read/write deadlock", "high"),
    "CVE-2005-1344": ("not_applicable", "cgi-tool", "htdigest is not part of httpd-rs and has no CGI execution path", "high"),
    "CVE-2012-1181": ("not_applicable", "fcgid", "mod_fcgid process management/limits are not implemented; the FastCGI client does not spawn backend processes", "high"),
    "CVE-2013-4365": ("prevented", "fcgi-header", "FastCGI response headers are collected in bounded Rust Vec buffers; no fcgid header bucket buffer", "high"),
    "CVE-2014-0231": ("prevented", "cgi-timeout", "CGI execution has an explicit deadline and kills the process group on timeout", "high"),
    "CVE-2014-3583": ("prevented", "fcgi-header", "FastCGI/CGI response headers are bounded to 64 KiB and parsed in safe Rust; no over-read", "high"),
    "CVE-2025-65082": ("prevented", "cgi-env", "configured/rewrite environment entries cannot override reserved request/connection CGI variables; regression test", "high"),
    "CVE-2026-42356": ("fail_closed", "cgi-internal-redirect", "CGI internal redirects are not followed; Location is returned as an external redirect", "high"),
    "CVE-1999-0926": ("prevented", "dos-headers", "verified request-head parser bounds header count and size and the exact head buffer", "high"),
    "CVE-1999-1199": ("prevented", "dos-headers", "verified request-head parser bounds header count and size and the exact head buffer", "high"),
    "CVE-2002-0392": ("prevented", "dos-chunk", "strict verified chunk framing rejects inconsistent sizes; no C chunk parser", "high"),
    "CVE-2003-0134": ("not_applicable", "platform", "OS/2 filestat device-name behavior; httpd-rs is Linux/Rust and uses no APR file-stat", "high"),
    "CVE-2004-0786": ("not_applicable", "apr-uri", "APR-util IPv6 URI parser is not used; Rust URL/authority parsing is the boundary", "medium"),
    "CVE-2004-0942": ("prevented", "dos-headers", "strict parser rejects obs-fold/multiline whitespace and scans headers linearly", "high"),
    "CVE-2009-1891": ("prevented", "dos-compression", "compression is capped at 8 MiB and completed before response I/O; no worker continues after disconnect", "medium"),
    "CVE-2009-1956": ("not_applicable", "apr-big-endian", "APR-util big-endian off-by-one is not used by httpd-rs", "medium"),
    "CVE-2011-1928": ("not_applicable", "apr-fnmatch", "APR fnmatch is not used; path/autoindex matching is Rust regex/string logic", "medium"),
    "CVE-2011-4415": ("prevented", "setenvif-expansion", "SetEnvIf capture replacement is admitted before allocation against a 1 MiB value and 4 MiB request-wide expansion budget; over-limit evaluation poisons authorization and fails closed", "high"),
    "CVE-2014-0118": ("fail_closed", "request-decompression", "request-body decompression filters are unsupported and fail closed", "medium"),
    "CVE-2018-1301": ("prevented", "dos-headers", "verified head size limit and strict parser reject the out-of-bounds boundary", "high"),
    "CVE-2022-22719": ("prevented", "dos-body", "Rust body/framing handling is memory-safe and bounded", "high"),
    "CVE-2026-49975": ("prevented", "http2-hpack-flow", "H2HeaderState/H2Settings bound decoded headers; H2Flow and reserve/poll-capacity sends bound zero-window response buffering", "high"),
    "CVE-2001-0730": ("not_applicable", "log-split", "split-logfile utility is not implemented; httpd-rs writes its configured access log directly", "medium"),
    "CVE-2001-1556": ("prevented", "log-injection", "verified escape_log_bytes is used by the access-log formatter for client-derived fields", "high"),
    "CVE-2002-2012": ("not_applicable", "platform", "HP Secure OS-specific behavior; not the Linux/Rust implementation", "medium"),
    "CVE-2003-1581": ("not_applicable", "log-dns", "httpd-rs does not perform reverse DNS lookup for log fields; it logs the numeric peer address", "medium"),
    "CVE-2006-3918": ("prevented", "error-reflection", "generic error pages do not reflect the Expect header", "high"),
    "CVE-2007-6203": ("prevented", "error-reflection", "generic 413/error pages do not reflect the request method", "high"),
    "CVE-2009-2299": ("not_applicable", "third-party-waf", "Hyperguard WAF module is not loaded", "high"),
    "CVE-2013-5704": ("prevented", "chunk-trailers", "chunk trailers are parsed and discarded; they are never merged into request headers", "high"),
    "CVE-2022-22720": ("prevented", "body-discard", "body read/discard errors return an error and drop the connection; pipelined requests are not reused", "high"),
    "CVE-1999-1237": ("not_applicable", "auth-third-party", "SMB authentication library/module is not implemented", "high"),
    "CVE-2001-0131": ("not_applicable", "auth-tool", "htpasswd/htdigest utilities are not shipped by httpd-rs", "high"),
    "CVE-2001-1534": ("not_applicable", "auth-usertrack", "mod_usertrack session ID generation is not implemented", "high"),
    "CVE-2004-0811": ("prevented", "auth-satisfy", "legacy Satisfy/Order merge is implemented in the single access evaluator and covered by differential cases", "high"),
    "CVE-2008-2384": ("not_applicable", "auth-third-party", "mod_auth_mysql is not implemented", "high"),
    "CVE-2013-0942": ("not_applicable", "auth-third-party", "RSA Authentication Agent module is not loaded", "high"),
    "CVE-2015-3185": ("prevented", "auth-policy", "PolicyResult distinguishes AuthRequired from Denied; access checks never treat a pure authorization provider as authentication", "high"),
    "CVE-2026-24072": ("prevented", "htaccess-expr", "expression file()/filesize() data paths are confined below DOCUMENT_ROOT, closing the local .htaccess file-read path", "high"),
    "CVE-2026-44119": ("prevented", "htaccess-expr", "the same expression data-path confinement applies to .htaccess Require expr/RewriteCond expr", "high"),
    "CVE-2004-1834": ("prevented", "cache-credentials", "cache metadata stores response headers only and explicitly excludes Authorization/Proxy-Authorization credentials", "high"),
    "CVE-2005-2088": ("prevented", "cache-smuggling", "verified CL/TE conflict rejection and GET/HEAD-only cache policy prevent the smuggled-body cache primitive", "high"),
    "CVE-2014-3581": ("prevented", "cache-header", "empty Content-Type is handled as an empty header value in safe Rust; no NULL dereference path", "high"),
    "CVE-2021-40438": ("prevented", "proxy-target", "ProxyPassMatch and rewrite [P] authority templates cannot be derived from captures/variables; targets are canonical and policy-bound", "high"),
    "CVE-2024-38473": ("prevented", "proxy-encoding", "proxy paths are encoded exactly once and canonical target identity is policy-bound; regression covers double encoding", "high"),
    "CVE-2024-38476": ("prevented", "proxy-response", "all backend response headers, including Location, pass the verified header sanitizer; framing ambiguity is rejected", "high"),
    "CVE-2024-38477": ("prevented", "proxy-memory", "Rust proxy state/body handling has no nullable pointer dereference; proxy framing and buffers are bounded", "high"),
    "CVE-2002-0257": ("not_applicable", "third-party-app", "auction.pl application XSS is not part of the server", "high"),
    "CVE-2004-0173": ("prevented", "path-backslash", "verified path bytes reject backslash and encoded-backslash traversal", "high"),
    "CVE-2005-2728": ("prevented", "range", "multi-range parsing is rejected and Range bytes are bounded by the verified single-range parser", "high"),
    "CVE-2007-0086": ("prevented", "range", "multi-range/repeated-fragment parsing is rejected before body generation", "high"),
    "CVE-2007-1741": ("not_applicable", "suexec", "suexec is not implemented; CGI workers drop to the configured account", "high"),
    "CVE-2007-1742": ("not_applicable", "suexec", "suexec is not implemented; there is no suexec path-prefix comparison", "high"),
    "CVE-2007-1743": ("not_applicable", "suexec", "suexec is not implemented; no suexec uid/gid command-line path", "high"),
    "CVE-2011-3192": ("prevented", "range", "multiple overlapping ranges are rejected; only one bounded range is generated", "high"),
    "CVE-2000-0913": ("not_applicable", "rewrite-legacy", "Apache 1.3.12-and-earlier implementation only; httpd-rs applies current canonical rewrite/filesystem semantics", "medium"),
    "CVE-2001-1072": ("prevented", "rewrite-slash", "verified normalize_uri_path collapses duplicate slashes before rewrite matching; conformance regression", "medium"),
    "CVE-2003-0542": ("prevented", "rewrite-captures", "Rust regex captures are heap-allocated and dynamically sized; no fixed nine-capture buffer, with a 12-capture regression", "medium"),
    "CVE-2013-1862": ("fail_closed", "rewrite-log", "RewriteLog/RewriteLogLevel output is not implemented; no rewrite log receives request bytes", "medium"),
    "CVE-2019-10098": ("prevented", "rewrite-redirect", "verified percent_decode_path rejects encoded controls before rewrite; redirect locations are escaped", "medium"),
    "CVE-2020-1927": ("prevented", "rewrite-redirect", "verified percent_decode_path rejects encoded controls before rewrite; redirect locations are escaped", "medium"),
    "CVE-2023-25690": ("prevented", "rewrite-proxy-target", "verified rewrite_backref_no_qmark prevents capture/variable '?' injection by default; proxy framing is strict and UnsafeAllow3F is explicit", "high"),
    "CVE-2024-38474": ("prevented", "rewrite-substitution", "default backreference/variable encoding proves no '?' is introduced; UnsafeAllow3F is an explicit opt-in", "high"),
    "CVE-2024-38475": ("prevented", "rewrite-filesystem", "verified rewrite_filesystem_admit limits absolute rewritten files to the current document/alias root; UnsafePrefixStat is parsed for compatibility but never changes the authorization base, and target scope is re-evaluated", "high"),
    "CVE-2024-39573": ("prevented", "rewrite-proxy", "only an explicit [P] flag selects proxying; external substitutions otherwise redirect, and proxy targets are canonical and access-checked", "high"),
    "CVE-2025-54090": ("not_applicable", "rewrite-expr", "Apache 2.4.64-specific regression; httpd-rs has an independent expression evaluator with a false-expression regression", "medium"),
    "CVE-2026-56154": ("fail_closed", "rewrite-lookahead", "LA-U/LA-F lookahead variables are rejected at configuration load instead of evaluated", "high"),
    "CVE-2026-23918": ("prevented", "http2-early-reset", "Rust h2 keys stream storage by StreamId with an ABA guard and has no Apache spurge array; the adapter's verified idempotent purge set makes duplicate early-reset/close cleanup a no-op, with an early-reset regression test", "high"),
    "CVE-2017-7659": ("prevented", "http2-memory", "Rust/h2 stack cannot dereference a freed Apache C pool pointer", "medium"),
    "CVE-2017-9789": ("prevented", "http2-memory", "Rust ownership and the safe h2 stack remove the Apache C pool UAF primitive", "medium"),
    "CVE-2018-1302": ("prevented", "http2-memory", "Rust/h2 object lifetimes remove the freed-pool write primitive", "medium"),
    "CVE-2019-0196": ("prevented", "http2-method", "Rust string/method handling removes the freed-memory comparison primitive", "medium"),
    "CVE-2019-10081": ("fail_closed", "http2-push", "HTTP/2 server push is not implemented", "high"),
    "CVE-2019-10082": ("prevented", "http2-shutdown", "Rust/h2 session lifetimes remove the shutdown UAF primitive", "medium"),
    "CVE-2020-11993": ("prevented", "http2-logging", "httpd-rs logging has no Apache pool/connection association", "medium"),
    "CVE-2020-9490": ("fail_closed", "http2-push", "HTTP/2 server push is not implemented", "high"),
    "CVE-2021-41524": ("prevented", "http2-memory", "Rust/h2 request processing removes the NULL dereference primitive", "medium"),
    "CVE-2023-45802": ("prevented", "http2-reset", "H2Budget/stream-ID ledger bound reset lifecycle and TTL; Rust h2 ownership replaces Apache deferred pool cleanup", "medium"),
    "CVE-2021-31618": ("prevented", "http2-headers", "h2_head_admit plus a verified total-header budget reject violating heads before a Rust error response is built", "high"),
    "CVE-2021-33193": ("prevented", "http2-method", "h2_method_ok/h2_head_admit verify the RFC token and length before the method reaches the proxy request line", "high"),
    "CVE-2016-8740": ("prevented", "http2-header-budget", "verified H2Settings and H2HeaderState bound decoded header lists; h2_head_admit also checks target/field/count limits", "high"),
    "CVE-2018-11763": ("prevented", "http2-settings", "H2Settings bounds frame/header resources and the connection idle timeout bounds a SETTINGS-only connection", "medium"),
    "CVE-2018-1333": ("prevented", "http2-timeout", "per-stream timeout and the H2Budget active bound prevent worker/task accumulation; no Apache worker allocation exists", "high"),
    "CVE-2018-17189": ("prevented", "http2-body-timeout", "request-body timeout and stream limits bound slow-body cleanup", "medium"),
    "CVE-2019-9517": ("prevented", "http2-flow", "verified H2Flow bounds windows/send buffering, and the adapter uses h2 reserve/poll capacity before each DATA send; no unbounded response buffering", "high"),
    "CVE-2024-27316": ("prevented", "http2-header-budget", "verified total-header state and the h2 header-list limit bound continuation/header buffering; h2_head_admit rejects excess", "high"),
    "CVE-2025-49630": ("not_applicable", "proxy-h2", "httpd-rs's proxy client offers only HTTP/1.1 ALPN and has no HTTP/2 backend path", "high"),
    "CVE-2019-0197": ("fail_closed", "h2c-upgrade", "cleartext h2c and HTTP/1-to-h2 upgrade are not implemented", "high"),
    "CVE-2024-36387": ("fail_closed", "h2-websocket", "WebSocket upgrade over HTTP/2 is not implemented", "high"),
    "CVE-2019-17567": ("prevented", "websocket-handshake", "strict client/upstream 101 handshake and exact target validation; non-upgraded upstream responses are not tunneled", "high"),
    "CVE-2022-31813": ("prevented", "proxy-forwarded", "client Forwarded/X-Forwarded headers are stripped and httpd-rs emits its own chain", "high"),
    "CVE-2010-2791": ("prevented", "proxy-lifecycle", "backend connections are not reused, so a stale timeout response cannot leak into a later request", "medium"),
    "CVE-2013-4352": ("fail_closed", "forward-proxy", "caching forward proxy/ProxyRequests is unsupported and rejected", "high"),
    "CVE-2014-0117": ("prevented", "proxy-framing", "Connection-nominated headers are stripped and backend connections are not reused", "medium"),
    "CVE-1999-1293": ("fail_closed", "mod_proxy_ftp", "FTP proxy is unsupported and rejected", "high"),
    "CVE-2004-0492": ("prevented", "proxy-framing", "negative/invalid Content-Length handling is bounded and memory-safe", "medium"),
    "CVE-2004-0751": ("prevented", "proxy-tls", "Rustls replaces the mod_ssl proxy implementation", "high"),
    "CVE-2007-6420": ("fail_closed", "balancer-manager", "balancer-manager UI is not implemented", "high"),
    "CVE-2007-6421": ("fail_closed", "balancer-manager", "balancer-manager UI is not implemented", "high"),
    "CVE-2007-6422": ("fail_closed", "balancer-manager", "balancer-manager UI is not implemented", "high"),
    "CVE-2008-2364": ("prevented", "proxy-framing", "interim 1xx proxy responses are rejected", "high"),
    "CVE-2010-0010": ("prevented", "proxy-framing", "Rust memory safety and bounded proxy body handling", "high"),
    "CVE-2012-4558": ("fail_closed", "balancer-manager", "balancer-manager UI is not implemented", "high"),
    "CVE-2019-10092": ("prevented", "proxy-error-page", "proxy error pages HTML-escape URL/host data", "high"),
    "CVE-2020-13950": ("prevented", "proxy-framing", "proxy rejects Content-Length + Transfer-Encoding ambiguity", "high"),
    "CVE-2021-44224": ("fail_closed", "forward-proxy", "ProxyRequests is unsupported and rejected", "high"),
    "CVE-2024-43204": ("fail_closed", "proxy-headers", "RequestHeader/mod_headers request mutation is unsupported and rejected", "high"),
    "CVE-2026-34356": ("prevented", "proxy-memory", "Rust memory safety removes the buffer overflow primitive", "medium"),
    "CVE-2017-12171": ("not_applicable", "parser-legacy", "RHEL 6.9-specific legacy Allow/Deny comment regression; not the modern parser path", "medium"),
    "CVE-2021-26691": ("fail_closed", "mod_session", "mod_session/session header handling is not implemented", "high"),
    "CVE-2026-59797": ("fail_closed", "sslrequire", "SSLRequire and file-expression policy are rejected as unimplemented security directives", "high"),
    "CVE-1999-0236": ("prevented", "cgi-source", "ScriptAlias is executed as CGI; it is not served as a readable source directory", "high"),
    "CVE-2001-0766": ("not_applicable", "platform", "MacOS HFS+ case-folding behavior", "high"),
    "CVE-2004-0174": ("not_applicable", "platform", "legacy MPM/listener behavior; httpd-rs has no Apache MPM", "high"),
    "CVE-2004-1387": ("not_applicable", "local-utility", "apache-utils local symlink issue, not the server", "high"),
    "CVE-2004-2343": ("not_applicable", "htaccess-local", "disputed/local .htaccess/ErrorDocument privilege case", "medium"),
    "CVE-2006-20001": ("prevented", "memory-safety", "Rust memory safety removes the out-of-bounds primitive", "high"),
    "CVE-2012-0883": ("not_applicable", "local-utility", "envvars packaging/local LD_LIBRARY_PATH issue", "high"),
    "CVE-2017-3167": ("fail_closed", "third-party-auth", "third-party modules using ap_get_basic_auth_pw are not loaded", "high"),
    # id: status, surface, rationale, confidence
    "CVE-2026-8743": ("prevented", "http-parser", "strict verified request framing rejects obsolete whitespace forms", "high"),
    "CVE-2016-8743": ("prevented", "http-parser", "strict verified request framing rejects obsolete whitespace forms", "high"),
    "CVE-2015-3183": ("prevented", "http-framing", "verified HTTP/1 chunk framing and request-head parser", "high"),
    "CVE-2016-5387": ("prevented", "cgi-env", "CGI environment explicitly excludes Proxy/HTTP_PROXY", "high"),
    "CVE-2017-15715": ("prevented", "path", "control bytes are rejected by percent-decoding and canonical-path parsing", "high"),
    "CVE-2019-0220": ("prevented", "path", "URI canonicalization collapses duplicate slashes before Location/rewrite matching", "medium"),
    "CVE-2021-41773": ("prevented", "path", "verified canonicalization plus openat2 RESOLVE_BENEATH", "high"),
    "CVE-2021-42013": ("prevented", "path", "verified canonicalization plus openat2 RESOLVE_BENEATH; double encoding is not re-decoded", "high"),
    "CVE-2023-38709": ("prevented", "response-header", "verified sanitize_header_value is applied to every response header before serialization", "high"),
    "CVE-2025-53020": ("prevented", "memory-lifetime", "Rust RAII and bounded caches/streams replace Apache pool late-release lifetime", "high"),
    "CVE-2019-10097": ("fail_closed", "remoteip-proxy", "PROXY protocol input is not implemented and is rejected", "high"),
    "CVE-2021-30641": ("prevented", "path", "httpd-rs canonicalizes duplicate slashes rather than supporting MergeSlashes Off", "medium"),
    "CVE-2026-44631": ("prevented", "regex-native", "the Apache configuration-buffer implementation and production PCRE2 C boundary are absent; expression regexes compile at startup through a safe-Rust non-backtracking compatibility frontend with verified resource ceilings", "high"),
    "CVE-2002-0840": ("prevented", "error-page", "error bodies HTML-escape URL/host data", "high"),
    "CVE-2007-4465": ("prevented", "autoindex", "autoindex file names are HTML-escaped", "high"),
    "CVE-2006-5752": ("prevented", "status", "server-status page contains no attacker-controlled request fields", "high"),
    "CVE-2007-6388": ("prevented", "status", "server-status page contains no attacker-controlled request fields", "high"),
    "CVE-2005-3352": ("fail_closed", "mod_imap", "mod_imap/imagemap is not implemented", "high"),
    "CVE-2007-5000": ("fail_closed", "mod_imap", "mod_imap/imagemap is not implemented", "high"),
    "CVE-2017-7679": ("prevented", "memory-safety", "Rust memory safety removes the out-of-bounds primitive", "high"),
    "CVE-2021-39275": ("fail_closed", "external-modules", "third-party modules are not loaded; unsupported module families fail closed", "high"),
    "CVE-2022-30556": ("fail_closed", "mod_lua", "mod_lua is not implemented", "high"),
    "CVE-2025-58098": ("fail_closed", "ssi", "SSI/mod_include is unsupported and fails closed", "high"),
    "CVE-2026-79768": ("fail_closed", "userdir", "UserDir is not implemented", "high"),
    "CVE-2026-63292": ("fail_closed", "vhost-alias", "mod_vhost_alias is not implemented", "high"),
    "CVE-2001-1449": ("not_applicable", "autoindex-distro", "Mandrake default directory-index behavior; httpd-rs has no implicit autoindex default", "high"),
    "CVE-2003-0020": ("prevented", "logging", "error-log messages use the verified escape_log_bytes primitive for terminal controls", "high"),
    "CVE-2003-0083": ("prevented", "logging", "access-log client fields use the verified escape_log_bytes primitive", "high"),
    "CVE-2003-1418": ("not_applicable", "platform", "OpenBSD/legacy ETag behavior; not the Linux server target", "high"),
    "CVE-2003-1580": ("not_applicable", "logging", "legacy reverse-DNS logging format; httpd-rs uses configured peer text", "medium"),
    "CVE-2002-2103": ("not_applicable", "logging", "legacy reverse-DNS log spoofing behavior", "medium"),
    "CVE-1999-0678": ("not_applicable", "default-config", "Debian ServerRoot documentation exposure is a package configuration issue", "medium"),
}

PLATFORM = re.compile(
    r"Windows|WinNT|Win32|Win64|NetWare|OS/2|Mac OS X|Apple Mac|MPM|prefork|"
    r"worker MPM|scoreboard|itk|WinNT MPM|ISAPI",
    re.I,
)
MEMORY = re.compile(
    r"buffer overflow|buffer over-read|buffer overread|out.of.bounds|use.after.free|"
    r"double free|heap-based|stack-based|memory corruption|integer overflow|"
    r"NULL pointer|segmentation fault|memory leak|buffer underwrite",
    re.I,
)
HTTP2 = re.compile(r"HTTP/2|\bh2\b|HPACK|SETTINGS frame|stream worker|h2c", re.I)
REWRITE = re.compile(r"mod_rewrite|RewriteRule|RewriteCond|RewriteMap|rewrite", re.I)
PROXY = re.compile(r"mod_proxy|ProxyPass|ProxyRequests|reverse proxy|forward proxy|proxying", re.I)
CGI = re.compile(r"\bCGI\b|mod_cgi|mod_cgid|cgi-bin|ScriptAlias|FastCGI|mod_fcgid|fcgi", re.I)
CACHE = re.compile(r"mod_cache|cache|cached", re.I)
AUTH = re.compile(r"mod_auth|authentication|authorization|Require directive|\.htpasswd|Basic auth|Digest", re.I)
TLS = re.compile(r"mod_ssl|OpenSSL|SSL/TLS|TLS|SSL|OCSP|certificate|session resumption", re.I)
EXPR = re.compile(r"expression|expr|FilesMatch|LocationMatch|DirectoryMatch|RewriteCond", re.I)
REGEX = re.compile(r"regex|PCRE|regular expression", re.I)
PARSER = re.compile(
    r"request header|request line|header parsing|chunked|Transfer-Encoding|"
    r"Content-Length|whitespace|request body|protocol|request smuggling|HTTP request",
    re.I,
)
PATH = re.compile(
    r"path traversal|directory traversal|path normalization|URI path|url-path|alias|"
    r"document root|encoded slash|MergeSlashes|traversal",
    re.I,
)
SMUGGLE = re.compile(r"request smuggling|smuggling|request splitting|response smuggling|desynchron|Transfer-Encoding|Content-Length", re.I)
RESP_SPLIT = re.compile(r"response splitting|response smuggling|CRLF|header injection|headers to be truncated|split HTTP|response desynchron", re.I)
RANGE = re.compile(r"Range header|byte range|range filter|Content-Range", re.I)
DOS = re.compile(r"denial of service|DoS|resource exhaustion|memory exhaustion|CPU consumption|crash|exhaust|flood|slow loris|worker exhaustion|stack consumption|infinite loop", re.I)

# Module families httpd-rs does not implement.  The first match wins.
UNIMPLEMENTED = [
    ("mod_dav", r"mod_dav|WebDAV|\bDAV\b|mod_dav_fs|mod_dav_lock"),
    ("mod_session", r"mod_session|session_cookie|session_crypto|session_dbd"),
    ("mod_auth_digest", r"mod_auth_digest|Digest authentication|Digest nonce|Digest auth"),
    ("mod_ldap", r"mod_ldap|mod_authnz_ldap|LDAP"),
    ("mod_openidc", r"mod_auth_openidc|OpenID"),
    ("mod_perl", r"mod_perl|Perl"),
    ("mod_php", r"mod_php|PHP"),
    ("mod_wsgi", r"mod_wsgi|WSGI"),
    ("mod_lua", r"mod_lua|\bLua\b|r:parsebody|r:wsread"),
    ("mod_md", r"mod_md|\bACME\b"),
    ("mod_macro", r"mod_macro"),
    ("mod_sed", r"mod_sed"),
    ("mod_isapi", r"mod_isapi|ISAPI"),
    ("mod_proxy_ajp", r"mod_proxy_ajp|\bAJP\b|mod_jk"),
    ("mod_proxy_uwsgi", r"mod_proxy_uwsgi|uwsgi"),
    ("mod_proxy_ftp", r"mod_proxy_ftp|FTP proxy|FTP server"),
    ("mod_proxy_html", r"mod_proxy_html"),
    ("mod_xml2enc", r"mod_xml2enc"),
    ("mod_charset_lite", r"mod_charset_lite"),
    ("mod_vhost_alias", r"mod_vhost_alias"),
    ("mod_userdir", r"mod_userdir|UserDir"),
    ("mod_include", r"mod_include|\bSSI\b|server.side include|server-side include"),
    ("mod_negotiation", r"mod_negotiation|MultiViews|content negotiation"),
    ("mod_heartmonitor", r"mod_heartmonitor|heartbeat"),
    ("mod_reqtimeout", r"mod_reqtimeout"),
    ("mod_filter", r"mod_filter|FilterProvider|ext_filter"),
    ("mod_ext_filter", r"mod_ext_filter"),
    ("mod_pagespeed", r"mod_pagespeed"),
    ("mod_authnz_external", r"mod_authnz_external"),
    ("mod_accounting", r"mod_accounting"),
    ("mod_rpaf", r"mod_rpaf"),
    ("mod_cluster", r"mod_cluster"),
    ("mod_gnutls", r"mod_gnutls"),
    ("mod_hfs_apple", r"mod_hfs_apple"),
    ("mod_imap", r"mod_imap|imagemap|mod_imagemap"),
    ("mod_socache", r"socache|mod_authn_socache"),
    ("mod_xml", r"libxml|expat|XML parser"),
]


def description(v: dict) -> str:
    for d in v["cve"].get("descriptions", []):
        if d.get("lang") == "en":
            return d["value"].replace("\n", " ")
    return ""


def severity(v: dict) -> str:
    m = v["cve"].get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if m.get(key):
            return m[key][0].get("cvssData", {}).get("baseSeverity", "unknown").lower()
    if m.get("cvssMetricV2"):
        score = m["cvssMetricV2"][0].get("baseScore", 0)
        return "high" if score >= 7 else "medium"
    return "unknown"


def match_unimplemented(text: str) -> str | None:
    for name, pattern in UNIMPLEMENTED:
        if re.search(pattern, text, re.I):
            return name
    return None


def classify(v: dict) -> tuple[str, str, str, str]:
    ident = v["cve"]["id"]
    if ident in OVERRIDES:
        return OVERRIDES[ident]
    text = description(v)
    if PLATFORM.search(text):
        return ("not_applicable", "platform", "platform/MPM-specific behavior", "high")
    mod = match_unimplemented(text)
    if mod:
        return ("fail_closed", mod, f"unimplemented module family: {mod}", "high")
    if HTTP2.search(text):
        return ("not_covered", "http2", "HTTP/2 is implemented outside the formal model", "high")
    if REWRITE.search(text):
        return ("not_covered", "rewrite", "mod_rewrite substitution/conditions are outside the formal model", "high")
    if PROXY.search(text):
        return ("not_covered", "proxy", "proxy protocol/target semantics are outside the formal model", "high")
    if CGI.search(text):
        return ("partial", "cgi", "CGI/FastCGI execution is path/inode bound but environment/protocol semantics are not verified", "medium")
    if CACHE.search(text):
        return ("partial", "cache", "cache policy key is bound but representation/key semantics are not verified", "medium")
    if TLS.search(text):
        if re.search(r"client certificate|client cert|session resumption|OCSP|certificate validation|certificate chain", text, re.I):
            return ("not_covered", "tls-client", "TLS client/certificate/OCSP policy is outside the formal model", "high")
        return ("prevented", "rustls", "Rustls replaces the OpenSSL/mod_ssl implementation", "high")
    if AUTH.search(text):
        return ("partial", "auth", "Basic auth/Require providers are partially verified; provider semantics are not", "medium")
    if RESP_SPLIT.search(text):
        if PARSER.search(text) or PATH.search(text):
            return ("partial", "response", "header sanitizer exists; backend/proxy response semantics are outside the model", "medium")
        return ("prevented", "header-sanitizer", "response header sanitizer rejects CR/LF/NUL", "high")
    if SMUGGLE.search(text):
        return ("partial", "http-framing", "HTTP/1 framing is verified; proxy/HTTP-2 translation is not", "medium")
    if PATH.search(text):
        return ("partial", "path", "verified path canonicalization/openat2, but alias/rewrite matching is not fully verified", "medium")
    if RANGE.search(text):
        return ("partial", "range", "range parser is verified; aggregate range/overlap limits are runtime policy", "medium")
    if MEMORY.search(text):
        return ("prevented", "memory-safety", "Rust memory safety removes the memory-corruption primitive", "medium")
    if DOS.search(text):
        return ("partial", "dos", "generic DoS class; only selected bounds are verified", "low")
    if EXPR.search(text) or REGEX.search(text):
        return ("not_covered", "expr-regex", "expression/regex semantics outside the formal model", "medium")
    if PARSER.search(text):
        return ("partial", "http-parser", "HTTP/1 parser parts are verified; remaining parser/protocol surfaces are not", "medium")
    return ("needs_review", "unclassified", "no classifier matched", "low")


def spec_prevents(status: str) -> str:
    if status in ("prevented", "fail_closed", "not_applicable"):
        return "yes"
    if status == "partial":
        return "partial"
    if status == "not_covered":
        return "no"
    return "unknown"


def build() -> list[dict]:
    raw = json.loads(DATA.read_text())["vulnerabilities"]
    rows = []
    for item in raw:
        cve = item["cve"]
        ident = cve["id"]
        status, surface, rationale, confidence = classify(item)
        rows.append(
            {
                "id": ident,
                "year": int(ident[4:8]),
                "severity": severity(item),
                "status": status,
                "spec_prevents": spec_prevents(status),
                "surface": surface,
                "confidence": confidence,
                "rationale": rationale,
                "description": description(item),
            }
        )
    rows.sort(key=lambda row: row["id"])
    return rows


def report(rows: list[dict]) -> str:
    counts = collections.Counter(row["status"] for row in rows)
    prevents = collections.Counter(row["spec_prevents"] for row in rows)
    high = [row for row in rows if row["severity"] in ("critical", "high")]
    uncovered = [row for row in rows if row["status"] == "not_covered"]
    partial = [row for row in rows if row["status"] == "partial"]
    review = [row for row in rows if row["status"] == "needs_review"]
    lines = [
        "# Apache HTTP Server CVE triage matrix",
        "",
        "Source: NVD CPE `cpe:2.3:a:apache:http_server` (371 CVEs).",
        "This is a static, per-CVE triage against the current httpd-rs specification",
        "and implementation boundary. It is not a PoC replay result.",
        "",
        "## Status definitions",
        "",
        "| status | meaning |",
        "|---|---|",
        "| `prevented` | verified/construction-level primitive prevents the class |",
        "| `fail_closed` | unsupported feature/module/config is rejected or 500s |",
        "| `not_applicable` | feature or platform is absent |",
        "| `partial` | some relevant layer is verified, but the full class is not |",
        "| `not_covered` | implemented behavior is outside the formal spec |",
        "| `needs_review` | triage could not decide |",
        "",
        "## Totals",
        "",
        f"- CVEs: **{len(rows)}**",
        f"- spec prevents in principle: **{prevents['yes']}**",
        f"- partial: **{prevents['partial']}**",
        f"- not covered: **{prevents['no']}**",
        f"- unknown: **{prevents['unknown']}**",
        "",
        "| status | count |",
        "|---|---:|",
    ]
    for status in ("prevented", "fail_closed", "not_applicable", "partial", "not_covered", "needs_review"):
        lines.append(f"| `{status}` | {counts[status]} |")
    lines += [
        "",
        f"### Highest-risk gaps ({len(uncovered)} not covered, {len(partial)} partial)",
        "",
        "The rows below are the priority replay corpus targets: implemented behavior",
        "that the formal model does not cover. Severity is the NVD base severity.",
        "",
        "| CVE | Severity | Surface | Why |",
        "|---|---|---|---|",
    ]
    for row in high:
        if row["status"] in ("not_covered", "partial", "needs_review"):
            lines.append(
                f"| {row['id']} | {row['severity']} | {row['surface']} | {row['rationale']} |"
            )
    if review:
        lines += ["", "## Manual review queue", "", "| CVE | Severity | Description |", "|---|---|---|"]
        for row in review:
            lines.append(f"| {row['id']} | {row['severity']} | {row['description'][:180]} |")
    lines += [
        "",
        "The complete machine-readable matrix is `docs/cve/apache2-cve-matrix.json`.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate existing output instead of writing")
    args = parser.parse_args()
    rows = build()
    if args.check:
        existing = json.loads(OUT.read_text())
        if existing != rows:
            print(f"{OUT} is stale; run {Path(__file__).name} without --check")
            return 1
        if not CSV_OUT.exists():
            print(f"{CSV_OUT} is missing; run {Path(__file__).name} without --check")
            return 1
        print(f"{OUT}: {len(rows)} CVEs, matrix is current")
        return 0
    OUT.write_text(json.dumps(rows, indent=2) + "\n")
    with CSV_OUT.open("w", newline="") as f:
        fields = ["id", "year", "severity", "status", "spec_prevents", "surface", "confidence", "rationale", "description"]
        writer = csv.DictWriter(
            f,
            fieldnames=fields,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)
    REPORT.write_text(report(rows) + "\n")
    counts = collections.Counter(row["status"] for row in rows)
    print(f"wrote {OUT} and {CSV_OUT} ({len(rows)} CVEs)")
    print("status:", dict(counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
