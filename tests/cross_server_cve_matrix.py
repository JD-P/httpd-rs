#!/usr/bin/env python3
"""Fetch, build, and validate the cross-server CVE root-cause matrix.

The source set deliberately uses NVD CPE aliases rather than keyword-only
searches.  Product projects have changed CPE vendor/product names over time;
every alias is recorded in the snapshot and rows are deduplicated by CVE ID.

This is a static design/implementation comparison, not a claim that every CVE
has a runnable Vapache reproducer.  Rows whose primitive overlaps an implemented
Vapache surface remain partial until the specific invariant is evidenced.
"""
from __future__ import annotations

import argparse
import collections
import csv
import datetime as dt
import io
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
CVE_DIR = ROOT / "docs" / "cve"
SOURCE = CVE_DIR / "cross-server-nvd.json"
OUT = CVE_DIR / "cross-server-cve-matrix.json"
CSV_OUT = CVE_DIR / "cross-server-cve-matrix.csv"
REPORT = CVE_DIR / "cross-server-cve-matrix.md"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


PRODUCTS: dict[str, dict[str, Any]] = {
    "nginx": {
        "label": "nginx",
        "queries": [
            {"virtualMatchString": "cpe:2.3:a:f5:nginx"},
            {"virtualMatchString": "cpe:2.3:a:f5:nginx_open_source"},
            {"virtualMatchString": "cpe:2.3:a:nginx:nginx"},
        ],
    },
    "iis-http-sys": {
        "label": "Microsoft IIS / HTTP.sys",
        "queries": [
            {"virtualMatchString": "cpe:2.3:a:microsoft:iis"},
            {"virtualMatchString": "cpe:2.3:a:microsoft:internet_information_server"},
            {"virtualMatchString": "cpe:2.3:a:microsoft:internet_information_services"},
            {"keywordSearch": "HTTP.sys"},
        ],
    },
    "lighttpd": {
        "label": "lighttpd",
        "queries": [{"virtualMatchString": "cpe:2.3:a:lighttpd:lighttpd"}],
    },
    "haproxy": {
        "label": "HAProxy",
        "queries": [{"virtualMatchString": "cpe:2.3:a:haproxy:haproxy"}],
    },
    "tomcat": {
        "label": "Apache Tomcat / Coyote",
        "queries": [{"virtualMatchString": "cpe:2.3:a:apache:tomcat"}],
    },
    "jetty": {
        "label": "Eclipse Jetty",
        "queries": [
            {"virtualMatchString": "cpe:2.3:a:eclipse:jetty"},
            {"virtualMatchString": "cpe:2.3:a:mortbay:jetty"},
        ],
    },
    "squid": {
        "label": "Squid",
        "queries": [{"virtualMatchString": "cpe:2.3:a:squid-cache:squid"}],
    },
    "varnish": {
        "label": "Varnish Cache",
        "queries": [
            {"virtualMatchString": "cpe:2.3:a:varnish-cache:varnish_cache"},
            {"virtualMatchString": "cpe:2.3:a:varnish-cache:varnish"},
            {"virtualMatchString": "cpe:2.3:a:varnish_cache_project:varnish_cache"},
            {"virtualMatchString": "cpe:2.3:a:varnish-software:varnish_cache"},
            {"virtualMatchString": "cpe:2.3:a:varnish-software:varnich_cache"},
        ],
    },
    "traffic-server": {
        "label": "Apache Traffic Server",
        "queries": [{"virtualMatchString": "cpe:2.3:a:apache:traffic_server"}],
    },
    "litespeed": {
        "label": "LiteSpeed / OpenLiteSpeed",
        "queries": [
            {"virtualMatchString": "cpe:2.3:a:litespeedtech:litespeed_web_server"},
            {"virtualMatchString": "cpe:2.3:a:litespeedtech:openlitespeed"},
        ],
    },
    "envoy": {
        "label": "Envoy",
        "queries": [{"virtualMatchString": "cpe:2.3:a:envoyproxy:envoy"}],
    },
}


EVIDENCE: dict[str, list[str]] = {
    "memory-safety": ["Rust ownership in crates/server/src", "tests/unsafe_inventory.py"],
    "http-framing": [
        "crates/server/src/http.rs::read_request",
        "crates/verified/src/lib.rs::request_framing",
        "crates/server/src/proxy.rs::read_async_head",
    ],
    "http-parser": [
        "crates/server/src/http.rs::read_request",
        "crates/verified/src/lib.rs::normalize_uri_path",
    ],
    "http2": [
        "crates/server/src/h2.rs",
        "crates/verified/src/lib.rs::h2_head_admit",
        "crates/verified/src/lib.rs::H2Flow",
    ],
    "path": [
        "crates/verified/src/lib.rs::normalize_uri_path",
        "crates/server/src/files.rs::open_beneath",
        "crates/server/src/request_plan.rs",
    ],
    "rewrite": ["crates/server/src/rewrite.rs", "crates/server/src/request_plan.rs"],
    "proxy": ["crates/server/src/proxy.rs", "crates/server/src/server.rs"],
    "cache": ["crates/server/src/cache.rs", "crates/verified/src/lib.rs::cache_key_hex"],
    "range": ["crates/server/src/files.rs::parse_range", "crates/verified/src/lib.rs"],
    "compression": ["crates/server/src/compression.rs", "crates/server/src/resource.rs"],
    "tls": ["crates/server/src/tls.rs", "rustls 0.23 dependency"],
    "auth": ["crates/server/src/access.rs", "crates/server/src/auth.rs"],
    "cgi": ["crates/server/src/cgi.rs", "crates/server/src/fastcgi.rs"],
    "logging": ["crates/server/src/log.rs", "crates/verified/src/lib.rs::escape_log_bytes"],
    "response-header": [
        "crates/server/src/http.rs::write_response",
        "crates/verified/src/lib.rs::sanitize_header_value",
    ],
    "dos": ["crates/server/src/resource.rs", "crates/server/src/config.rs request limits"],
    "request-body": ["crates/server/src/http.rs", "crates/server/src/resource.rs"],
    "websocket": ["crates/server/src/proxy.rs", "crates/server/src/server.rs"],
    "request-lifecycle": ["crates/server/src/server.rs", "crates/server/src/http.rs::Response"],
    "error-page": ["crates/server/src/files.rs::error_response"],
    "privilege-drop": ["crates/server/src/main.rs::drop_privileges"],
    "protocol-other": ["crates/server/src/http.rs", "crates/server/src/server.rs"],
    "unimplemented": ["crates/server/src/config.rs::known_directives"],
    "platform": ["Linux-only target documented in README.md"],
    "third-party": ["Cargo.lock", "tests/native_dependency_policy.py"],
    "digest-auth": ["crates/server/src/auth.rs::authenticate", "crates/server/src/access.rs"],
    "extension-module": ["crates/server/src/config.rs::known_directives"],
    "java-container": ["crates/server/src/config.rs::known_directives"],
    "iis-extension": ["README.md Linux-only platform contract"],
    "admin-control-plane": ["crates/server/src/config.rs", "crates/server/src/main.rs"],
    "source-data": ["docs/cve/cross-server-nvd.json"],
}


REJECTED = re.compile(r"\*\*\s*REJECT\s*\*\*", re.I)
MEMORY = re.compile(
    r"buffer overflow|buffer over-read|buffer overread|out.of.bounds|use.after.free|"
    r"double.free|heap overflow|stack(?:-based)? buffer overflow|memory corruption|"
    r"uninitialized memory|wild pointer",
    re.I,
)
SMUGGLE = re.compile(
    r"request smuggling|response smuggling|desynchron|request splitting|response splitting|"
    r"content.length|transfer.encoding|chunked encoding|chunk parser|framing",
    re.I,
)
PATH = re.compile(
    r"path traversal|directory traversal|canonicali[sz]|normaliz|encoded slash|dot segment|"
    r"document root|alias|symlink|short file name|8\.3 filename|alternate data stream|"
    r"UNC path|backslash|drive letter|file disclosure|arbitrary file",
    re.I,
)
HTTP2 = re.compile(
    r"HTTP/2|HPACK|RST_STREAM|SETTINGS frame|CONTINUATION frame|GOAWAY frame|rapid reset",
    re.I,
)
HTTP3 = re.compile(r"HTTP/3|QUIC|QPACK", re.I)
PROXY = re.compile(
    r"reverse proxy|forward proxy|proxy protocol|upstream|backend|CONNECT method|tunnel|"
    r"load balanc|routing|route match|host rewrite|X-Forwarded|Forwarded header",
    re.I,
)
CACHE = re.compile(r"cache poisoning|cache key|cached response|cache lookup|cache purge|cache ban", re.I)
RANGE = re.compile(r"Range header|byte range|Content-Range|multipart/byteranges", re.I)
COMPRESSION = re.compile(r"compress|decompress|gzip|brotli|deflate|zlib", re.I)
TLS = re.compile(r"TLS|SSL|certificate|OCSP|SNI|ALPN|cipher|session resumption", re.I)
AUTH = re.compile(
    r"authentication|authorization|access control|credential|password|basic auth|digest auth|"
    r"client identity|permission bypass|security constraint",
    re.I,
)
CGI = re.compile(r"CGI|FastCGI|SCGI|fcgi|gateway interface", re.I)
WEBSOCKET = re.compile(r"WebSocket|upgrade request|101 Switching Protocols", re.I)
LOGGING = re.compile(r"log injection|log file|access log|error log|terminal escape", re.I)
HEADER = re.compile(r"header injection|CRLF|response header|newline injection", re.I)
DOS = re.compile(
    r"denial of service|resource exhaustion|memory exhaustion|CPU consumption|infinite loop|"
    r"algorithmic complexity|stack exhaustion|connection exhaustion|slowloris|crash",
    re.I,
)
REQUEST_BODY = re.compile(r"request body|multipart|form data|upload|trailer|body parser", re.I)
XSS = re.compile(r"cross.site scripting|\bXSS\b|HTML injection", re.I)
LIFECYCLE = re.compile(
    r"wrong request|different request|another request|other clients?|different users?|"
    r"object recycl|object reuse|reused object|processor cache|pipelined requests?|"
    r"request mix.up|response mix.up|stale pointer|does not clear|incomplete cleanup|"
    r"concurrent requests?.*(?:overwrite|shared)|cross.request",
    re.I,
)
ERROR_DISCLOSURE = re.compile(
    r"web root path|fully qualified.*(?:path|directory)|pathname in an error|"
    r"error message.*sensitive|error page.*(?:path|information)|stack trace|"
    r"internal path|installation path",
    re.I,
)
PRIVDROP = re.compile(
    r"does not check the return value of.*set(?:uid|gid|groups)|retain privileges|"
    r"failed privilege drop|leave_suid|saved UID",
    re.I,
)
METHOD_AUTHORITY = re.compile(
    r"absolute.URI|absolute form|request target|method name|HTTP method|Host header|"
    r":authority|authority segment|hostname|userinfo|port-based access|URL parser|URI parser",
    re.I,
)

ADMIN = re.compile(
    r"admin(?:istration|istrator)? (?:interface|console|API|endpoint|panel)|management (?:interface|console|app)|"
    r"manager application|HTML Manager Interface|host.manager|dashboard|control panel|stats socket|CLI socket|"
    r"xDS|control plane|configuration API|status API|API authentication",
    re.I,
)
JAVA_APP = re.compile(
    r"\bJSP\b|\bservlet\b|\bJNDI\b|\bWAR file\b|classloader|Java deseriali[sz]|"
    r"Java SecurityManager|Jakarta|session replication|WebSocket endpoint deployment|"
    r"Apache Jasper|Expression Language|\bEL parser\b|\bRMI\b|\bJMX\b|SecurityManager|"
    r"web\.xml|HttpSession|HttpServlet|servlets?|\bValve(?:s)?\b|"
    r"JSESSIONID|session fixation|session persistence|session-persistence|SingleSignOn|"
    r"session cookie|session ID|session attribute|EncryptInterceptor|LockOutRealm|\bAJP\b|"
    r"Commons FileUpload|DiskFileItem|CORS filter|Tomcat Native|APR/Native connector|"
    r"cloud membership|clustering component|number guess example|CookieDump\.java|"
    r"FFM based connector|VirtualDirContext|\bJASPI\b",
    re.I,
)
IIS_EXTENSION = re.compile(
    r"ASP\.NET|Active Server Pages|\bASP\b|ISAPI|WebDAV|FrontPage|IIS Manager|FTP service|"
    r"SMTP service|CGI application supplied with|URLScan|SharePoint|\.htr\b|dllhost\.exe|"
    r"\.bat or \.cmd|ActiveX|webhits\.dll|iisext\.dll|\bperl(?:\.exe)?\b|\.COM(?:\s|$)|"
    r"executable file.*operating system commands|FrontPage Server Extensions|\bHTR\b|"
    r"Help File search facility|ColdFusion",
    re.I,
)
EXTENSION = re.compile(
    r"third.party (?:module|plugin)|Lua script|njs|WAF|ModSecurity|GeoIP|LDAP|Kerberos|"
    r"OpenID|OAuth|SAML|mod_security|PageSpeed|image filter|mail proxy|POP3|IMAP|"
    r"ngx_mail|ngx_http_scgi|ngx_http_uwsgi|SCGI module|uWSGI module|"
    r"ESI plugin|Edge Side Includes|\bESI\b|Slicer plugin|regex_remap plugin|txn_box plugin|webp_transform plugin|"
    r"health check plugin|experimental plugin|sslheaders plugin|SNMP|Cache Manager|"
    r"cache manager|cachemgr\.cgi|nginx mp4 module|ngx_http_mp4_module|\bmp4 module|"
    r"ngx_http_dav_module|ngx_http_proxy_v2_module|ngx_http_grpc_module|"
    r"ngx_http_charset_module|SPDY implementation|"
    r"\bURN(?: request| access| processing)?\b|urn: scheme|"
    r"FTP server|FTP gateway|ftp:// URLs|Gopher gateway|WCCP|pinger utility|ICMPv6|"
    r"Cache Digest|cache digests|collapsed forwarding|follow_x_forwarded_for|SSL-Bump|"
    r"ext_lm_group_acl|certifier plugin|uri_signing|url_sig plugin|ts_lua plugin|"
    r"prefetch plugin|header_rewrite plugin|HostDB SRV|health checks|plugins reset|"
    r"\bICP\b|HTCP protocol|PROXY protocol|mod_mysql_vhost|"
    r"cachekey plugin|stats-over-http plugin|intercept plugin|Cripts framework|"
    r"Dynamic Forward(?:ing)? (?:Proxy|Filter)|mirror response|request mirroring|"
    r"NTLM|SSPI|SMB authentication|SSI printenv|"
    r"ext_authz|ext_proc|tap filter|ratelimit filter|gRPC access log service",
    re.I,
)
PLATFORM_PATH = re.compile(
    r"NTFS|Windows ACL|Windows file system|Windows path|Windows authentication|kernel.mode driver|"
    r"named pipe|registry key|local privilege|service account privilege",
    re.I,
)
FORWARD_PROXY = re.compile(r"forward proxy|proxy client|cache peer|ICP protocol|HTCP|Proxy-Authorization", re.I)
LOCAL_PACKAGING = re.compile(
    r"installer for Windows|Windows installer|postrm script|package before|local users?|local attacker|"
    r"untrusted search path|service installation|init script|logrotate|temporary file|locally",
    re.I,
)
DIGEST_AUTH = re.compile(r"Digest authentication|DIGEST authenticator|HTTP Digest", re.I)


CWE_ROOT_CAUSE = {
    "CWE-20": "insufficient validation of attacker-controlled protocol input",
    "CWE-22": "path canonicalization or containment failure",
    "CWE-23": "relative path traversal",
    "CWE-59": "unsafe link or filesystem indirection",
    "CWE-74": "injection through insufficiently escaped input",
    "CWE-78": "operating-system command injection",
    "CWE-79": "attacker-controlled data emitted into HTML without contextual escaping",
    "CWE-89": "SQL injection in an application or management component",
    "CWE-94": "code injection into an executable extension surface",
    "CWE-119": "memory access outside the intended buffer",
    "CWE-120": "unbounded copy into a fixed-size buffer",
    "CWE-121": "attacker-controlled data overflows a stack buffer",
    "CWE-122": "attacker-controlled data overflows a heap buffer",
    "CWE-125": "out-of-bounds read",
    "CWE-190": "integer overflow in size or resource accounting",
    "CWE-200": "unintended information exposure",
    "CWE-209": "error output discloses sensitive implementation information",
    "CWE-212": "reused storage retains data from a prior security context",
    "CWE-213": "information is exposed through an observable discrepancy",
    "CWE-252": "a security-critical operation's failure return is ignored",
    "CWE-254": "a security feature is omitted from the generated response",
    "CWE-264": "permissions or access-control state are applied incorrectly",
    "CWE-269": "privilege state is broader than intended",
    "CWE-287": "authentication state is missing or incorrectly validated",
    "CWE-295": "certificate validation failure",
    "CWE-306": "missing authentication for a privileged operation",
    "CWE-319": "sensitive data sent without transport protection",
    "CWE-326": "cryptographic protection is too weak for the protected state",
    "CWE-352": "state-changing browser request lacks CSRF binding",
    "CWE-362": "concurrent request state is not isolated",
    "CWE-367": "a security-relevant object can change between validation and use",
    "CWE-384": "session identity is not rotated or bound at the security transition",
    "CWE-388": "an exceptional path leaves reusable request state inconsistent",
    "CWE-390": "a detected security error does not change control flow",
    "CWE-400": "attacker-controlled work or allocation lacks a resource bound",
    "CWE-416": "use of an object after its lifetime ended",
    "CWE-426": "an executable is resolved through an attacker-influenced search path",
    "CWE-444": "inconsistent HTTP message framing between components",
    "CWE-476": "unexpected null state reaches a dereference",
    "CWE-401": "attacker-triggered objects are not released",
    "CWE-404": "connection or stream resources are not released on exceptional shutdown",
    "CWE-440": "an exceptional protocol state violates the expected state machine",
    "CWE-502": "unsafe deserialization of attacker-controlled data",
    "CWE-551": "an error response discloses filesystem or configuration details",
    "CWE-601": "untrusted input selects a redirect target",
    "CWE-613": "expired session identity remains accepted",
    "CWE-639": "attacker-controlled identity selects another security context",
    "CWE-642": "externally controlled data changes security-critical state",
    "CWE-668": "a resource is exposed to the wrong security context",
    "CWE-670": "control flow skips a required validation or policy step",
    "CWE-674": "attacker input drives unbounded recursion",
    "CWE-697": "security decisions compare non-equivalent representations as equal",
    "CWE-770": "allocation or lifetime is not capped per attacker",
    "CWE-754": "an exceptional protocol condition is not handled safely",
    "CWE-755": "an exceptional input takes an unsafe control-flow path",
    "CWE-777": "an unanchored regular expression matches outside the intended domain",
    "CWE-787": "out-of-bounds write",
    "CWE-835": "attacker input can cause a non-terminating loop",
    "CWE-863": "authorization is evaluated against the wrong resource identity",
    "CWE-918": "attacker-controlled server-side request target",
}


# Manual corrections belong here after advisory/patch review.  Tuple fields are
# status, surface, root cause, Vapache rationale, confidence, analysis basis.
OVERRIDES: dict[str, tuple[str, str, str, str, str, str]] = {
    "CVE-2000-0258": (
        "prevented", "path",
        "many percent escapes caused superlinear or unbounded URL-decoding work",
        "Vapache decodes the bounded request target in one linear pass with a proved decreasing loop and rejects malformed, control, encoded-separator, or over-limit output",
        "high", "Microsoft advisory description and verified percent-decoder review",
    ),
    "CVE-2000-0884": (
        "prevented", "path",
        "non-canonical Unicode encodings reached filesystem traversal handling",
        "percent-decoding is byte-exact, malformed/overlong UTF-8 fails closed, dot segments are normalized, and filesystem opens remain beneath the configured root",
        "high", "NVD/CNA description and Vapache decode/UTF-8/containment pipeline review",
    ),
    "CVE-2001-0902": (
        "prevented", "logging",
        "decoded request controls were written as log record delimiters",
        "path decoding rejects control bytes and every client-derived log field also passes the verified control/terminal escaping primitive",
        "high", "NVD/CNA description and Vapache log-sink review",
    ),
    "CVE-2002-0150": (
        "prevented", "http-parser",
        "header value validation could be spoofed before a fixed native buffer copy",
        "Vapache validates every byte of the bounded complete field value, performs no C-string copy, and rejects the entire head instead of truncating a field",
        "high", "Microsoft/NVD description and verified request-head parser review",
    ),
    "CVE-2003-1567": (
        "fail_closed", "protocol-other",
        "an undocumented request-reflection method exposed cookies and authorization headers to browser script",
        "TRACK is not implemented and receives 405; TRACE is independently disabled unless TraceEnable explicitly enables its bounded diagnostic response",
        "high", "NVD/CNA description and method-dispatch review",
    ),
    "CVE-2005-4360": (
        "not_applicable", "iis-extension",
        "IIS dispatched a malformed .dll extension target into ntdll and ignored the native loader's failure result",
        "Vapache has no IIS DLL/FrontPage handler or Windows native loader path; .dll files are opaque static bytes unless an unrelated explicit handler is configured",
        "high", "NVD/CNA description and Vapache platform/handler inventory",
    ),
    "CVE-2007-1870": (
        "prevented", "cache",
        "a zero Unix modification time reached an unexpected null date-cache value",
        "Vapache treats mtime as an ordinary signed timestamp, formats epoch time without nullable cache state, and omits the validator if conversion fails",
        "high", "lighttpd advisory and file-validator implementation review",
    ),
    "CVE-2007-3949": (
        "prevented", "path",
        "trailing slash removal made an access-control URL pattern compare against a different resource identity",
        "Vapache preserves a trailing slash in the canonical URL policy identity and rejects a regular-file target requested with one",
        "high", "NVD/CNA description and canonical path/regular-file dispatch review",
    ),
    "CVE-2008-4359": (
        "prevented", "rewrite",
        "rewrite and redirect policy ran against an encoded URI before URL decoding",
        "Vapache percent-decodes and normalizes into one canonical RequestPlan before rewrite, redirect, authorization, proxy, cache, or filesystem selection",
        "high", "NVD/CNA description and canonical request-plan review",
    ),
    "CVE-2008-4360": (
        "prevented", "path",
        "case-sensitive policy matching was applied to a case-insensitive filesystem lookup identity",
        "after opening a target Vapache obtains the descriptor's resolved path, reapplies Directory, Files and access-file authorization to that actual basename, and intersects it with the lexical policy",
        "medium", "NVD/CNA description and opened-target authorization review",
    ),
    "CVE-2009-3555": (
        "prevented", "tls",
        "legacy TLS renegotiation did not bind the new handshake to the existing connection",
        "the Rustls server does not implement TLS renegotiation, so the vulnerable state transition is absent",
        "high", "protocol advisory and Rustls handshake feature review",
    ),
    "CVE-2013-1305": (
        "prevented", "http-parser",
        "a crafted request header drove the native HTTP parser into a non-terminating loop",
        "request-head parsing advances over bounded input, has verified terminating loops, and is capped by absolute byte, field-count and time limits",
        "high", "NVD/CNA description, request parser proof, and resource-limit review",
    ),
    "CVE-2013-1839": (
        "not_applicable", "unimplemented",
        "the Accept-Language parser failed to advance past an empty comma-separated item",
        "Vapache does not parse Accept-Language values; it can only copy the validated opaque header into a bounded Vary response",
        "high", "NVD/CNA description and Accept-Language data-flow review",
    ),
    "CVE-2013-4115": (
        "not_applicable", "third-party",
        "Squid copied an overlong domain into a fixed buffer in its in-process DNS lookup implementation",
        "Vapache has no in-process DNS packet/name builder; bounded host text is passed to the operating-system resolver in a disposable worker",
        "high", "Squid/NVD description and resolver-worker implementation review",
    ),
    "CVE-2013-2028": (
        "prevented", "http-framing",
        "a signedness error let an oversized chunk length drive a stack-buffer overflow",
        "the verified chunk-size parser uses checked u64 arithmetic, enforces the body budget before reading data, and never indexes a native stack buffer from the declared length",
        "high", "nginx advisory and verified chunk/body-budget review",
    ),
    "CVE-2013-4547": (
        "prevented", "http-parser",
        "a literal request-target space was accepted and canonicalized inconsistently",
        "the verified request-line parser requires exactly two SP delimiters and rejects any additional literal whitespace in the target",
        "high", "NVD/CNA description and verified request-line parser review",
    ),
    "CVE-2013-4508": (
        "prevented", "tls",
        "SNI-specific configuration silently selected obsolete weak TLS cipher suites",
        "Vapache uses Rustls' modern fixed cipher-suite set and does not implement the affected legacy cipher directives; SNI cannot weaken the listener's cryptographic policy",
        "high", "lighttpd advisory and Rustls/listener-policy review",
    ),
    "CVE-2014-0230": (
        "prevented", "request-lifecycle",
        "a response could be dispatched while an attacker-controlled request body still occupied a worker",
        "HTTP/1 request bodies are fully consumed under one absolute deadline and size/resource budgets before dispatch; a read failure closes the connection",
        "high", "NVD/CNA description and request lifecycle review",
    ),
    "CVE-2014-2323": (
        "not_applicable", "extension-module",
        "a Host value was interpolated into mod_mysql_vhost SQL",
        "Vapache has no SQL-backed virtual-host module or request-time SQL execution surface",
        "high", "NVD/CNA description and Vapache feature inventory",
    ),
    "CVE-2014-3624": (
        "fail_closed", "proxy",
        "CONNECT remap tunneling skipped the configured access restriction",
        "Vapache implements no forward-proxy CONNECT tunnel: authority-form CONNECT is rejected and path-form CONNECT cannot dispatch to a static or reverse-proxy handler",
        "high", "NVD/CNA description and method/proxy dispatch review",
    ),
    "CVE-2015-3249": (
        "prevented", "http2",
        "unknown frame types indexed past a handler table and HPACK table shrinkage removed entries after accounting the wrong size",
        "the vendored h2 codec represents unknown frame types as ignorable protocol items and its safe-Rust HPACK table evicts against current decoded size with checked collection access",
        "high", "Traffic Server 81a6807/4281f20 patch comparison and vendored h2/HPACK review",
    ),
    "CVE-2015-5168": (
        "prevented", "http2",
        "an HPACK Huffman decoder treated the NUL symbol as an internal non-leaf marker",
        "the vendored h2 HPACK decoder uses an RFC-derived finite decode table with explicit symbol/error states rather than sentinel character values",
        "high", "Traffic Server 3c4ee38 patch comparison and vendored HPACK decoder review",
    ),
    "CVE-2015-5206": (
        "prevented", "http2",
        "incorrect code lengths and values in the HPACK Huffman table decoded attacker input under the wrong tree",
        "the vendored h2 HPACK implementation uses the corrected RFC 7541 static Huffman table and rejects invalid padding/codes as compression errors",
        "high", "Traffic Server b3d75bf patch comparison and vendored HPACK decoder review",
    ),
    "CVE-2015-1635": (
        "prevented", "range",
        "crafted byte-range arithmetic overflowed native HTTP.sys buffer accounting",
        "Vapache's verified parser accepts one range, parses only checked u64 decimal arithmetic, proves start and end are inside the representation, and performs no native buffer indexing from client arithmetic",
        "high", "MS15-034/NVD root cause and verified byte-range parser review",
    ),
    "CVE-2015-2080": (
        "prevented", "http-parser",
        "an illegal header-character exception reflected uninitialized process memory",
        "illegal field bytes are rejected before dispatch and generic errors contain no parser buffers; the parser is safe initialized Rust",
        "high", "JetLeak advisory and request/error-path review",
    ),
    "CVE-2015-3200": (
        "prevented", "logging",
        "malformed Basic credentials containing NUL and newline bytes reached the log sink",
        "request headers reject NUL/newline controls, Basic credentials must contain a colon, and every client-derived log field is control-escaped",
        "high", "NVD/CNA description and authentication/log-sink review",
    ),
    "CVE-2015-8852": (
        "prevented", "http-framing",
        "a bare carriage return plus duplicate Content-Length fields created a response-splitting boundary across stacked servers",
        "Vapache requires exact CRLF lines, rejects bare controls and every duplicate Content-Length field (including equal values), rejects CL plus TE, and reconstructs proxy framing",
        "high", "NVD/CNA description and HTTP/proxy framing review",
    ),
    "CVE-2016-0742": (
        "not_applicable", "third-party",
        "nginx's custom asynchronous DNS response parser dereferenced invalid state",
        "Vapache has no in-process DNS packet parser; name resolution runs through the operating-system resolver in a bounded disposable worker",
        "high", "nginx advisory and resolver-worker implementation review",
    ),
    "CVE-2016-0746": (
        "not_applicable", "third-party",
        "nginx's custom CNAME response parser retained an object after its lifetime ended",
        "Vapache has no in-process DNS packet or CNAME parser; name resolution is isolated in a bounded operating-system resolver worker",
        "high", "nginx advisory and resolver-worker implementation review",
    ),
    "CVE-2016-2569": (
        "prevented", "proxy",
        "an overlong upstream Vary field violated a custom string-append invariant and asserted",
        "upstream field lines, aggregate head bytes and field count are bounded before allocation; Vary is retained as an opaque initialized Rust byte vector and malformed/over-limit responses return 502",
        "high", "Squid advisory and upstream response-head limit/data-flow review",
    ),
    "CVE-2016-2571": (
        "prevented", "proxy",
        "storage processing continued after upstream response parsing had already failed",
        "Vapache constructs no Response or cache entry until the full status line, fields and framing pass validation; every parser failure returns an error and drops the upstream stream",
        "high", "Squid advisory and upstream parse/cache control-flow review",
    ),
    "CVE-2016-2572": (
        "prevented", "proxy",
        "an upstream status code was consumed after response parsing failed before status initialization",
        "the strict status parser returns an initialized 100-599 code or an error; the error branch cannot access a partial response and produces a generic 502",
        "high", "Squid advisory and upstream status parser review",
    ),
    "CVE-2016-3948": (
        "prevented", "proxy",
        "crafted Vary response fields exceeded native parser bounds",
        "Vary remains an opaque field inside strict per-line, aggregate-byte and field-count limits, with safe-Rust owned storage and no fixed-buffer copy",
        "high", "Squid advisory and upstream response-head parser review",
    ),
    "CVE-2016-4450": (
        "prevented", "request-body",
        "a request-body temporary-file error path dereferenced a null native file object",
        "Vapache's spool file is an initialized Rust File or an error; secure creation, writes and budget acquisition are fallible and abort the request without nullable file state",
        "high", "nginx advisory and request spool lifecycle review",
    ),
    "CVE-2016-4553": (
        "prevented", "http-parser",
        "absolute-form authority and Host selected different cache/routing identities",
        "absolute form is capability-gated and now requires its scheme, effective port and normalized authority to match the transport and Host before routing or caching",
        "high", "vendor root cause, implementation review, and authority mismatch regression tests",
    ),
    "CVE-2016-4554": (
        "prevented", "http-parser",
        "a leading-whitespace header line bypassed exact Host lookup and created a smuggled authority",
        "Vapache rejects obs-fold and every header line that begins with whitespace before Host selection, cache lookup, routing, or proxy reconstruction",
        "high", "Squid vendor patch comparison and request-head regression tests",
    ),
    "CVE-2016-4800": (
        "prevented", "path",
        "backslash and escaped-character normalization differed between policy and filesystem lookup",
        "literal and percent-decoded backslashes are rejected before policy, rewrite, proxy, or openat2-contained filesystem mapping",
        "high", "NVD/CNA description and canonical-target tests",
    ),
    "CVE-2016-5360": (
        "prevented", "auth",
        "a deny-rule path read uninitialized native request state",
        "authorization decisions operate on initialized Rust values and denial returns a newly constructed response; no request buffer is reused as policy state",
        "medium", "NVD/CNA root cause and Vapache deny-response lifecycle review",
    ),
    "CVE-2017-12425": (
        "prevented", "http-framing",
        "a chunk size above signed 64-bit range passed one check and triggered an internal assertion",
        "the verified chunk parser uses checked u64 arithmetic and rejects any declared chunk above the configured body budget before conversion, allocation, or reads",
        "high", "VSV00001/issue 2379 and verified chunk-size budget review",
    ),
    "CVE-2017-5659": (
        "prevented", "http-framing",
        "a Content-Length/Transfer-Encoding mismatch reached an assertion rather than one framing decision",
        "the verified request parser rejects every CL-plus-TE message and conflicting/malformed lengths before body reads, caching, policy, or proxy dispatch",
        "high", "Traffic Server advisory and verified framing parser review",
    ),
    "CVE-2017-5660": (
        "prevented", "http-parser",
        "obsolete line folding changed the Host seen across proxy hops",
        "the verified request parser rejects every obs-fold line before header merge, Host selection, or proxy reconstruction",
        "high", "NVD/CNA description and request-head regression tests",
    ),
    "CVE-2017-7656": (
        "prevented", "http-framing",
        "an HTTP/1-shaped request declaring HTTP/0.9 produced an ambiguously framed response",
        "only exact HTTP/1.0 and HTTP/1.1 request versions are admitted; HTTP/0.9 is rejected before dispatch",
        "high", "NVD/CNA description and verified version parser review",
    ),
    "CVE-2017-7529": (
        "prevented", "range",
        "signed range arithmetic overflow disclosed bytes preceding the requested representation",
        "the verified single-range parser uses checked u64 arithmetic and proves start and end are within the representation before file offsets are constructed",
        "high", "nginx advisory and verified byte-range parser review",
    ),
    "CVE-2017-7671": (
        "prevented", "tls",
        "a malformed TLS handshake reached an invalid native handshake state and coredumped",
        "Rustls parses the bounded handshake in safe Rust and returns a connection error before HTTP dispatch; Vapache holds no nullable OpenSSL handshake state",
        "medium", "Traffic Server advisory and Vapache/Rustls handshake boundary review",
    ),
    "CVE-2018-1318": (
        "prevented", "auth",
        "a crafted method reached nullable method-ACL state in remap processing",
        "Vapache validates every method as a non-empty token and represents method restrictions as initialized sets evaluated before proxy dispatch; a deny/error constructs a response without native callback state",
        "medium", "Traffic Server advisory and method/access dispatch review",
    ),
    "CVE-2018-8022": (
        "prevented", "tls",
        "an invalid TLS handshake dereferenced malformed native parser state",
        "Rustls rejects malformed handshake records in safe Rust and no HTTP request or Vapache TLS policy object is constructed on handshake failure",
        "medium", "Traffic Server advisory and Vapache/Rustls handshake boundary review",
    ),
    "CVE-2018-10184": (
        "prevented", "http2",
        "an inbound peer-controlled frame-size setting was confused with the local receive-buffer bound, overflowing a defragmentation buffer",
        "the vendored safe-Rust h2 codec enforces its local maximum receive frame size before payload allocation and Vapache adds independent connection/header resident budgets",
        "high", "HAProxy patch/advisory and vendored h2 frame decoder review",
    ),
    "CVE-2018-14645": (
        "prevented", "http2",
        "an HPACK dynamic-table index was read without checking it against the table bounds",
        "the vendored safe-Rust HPACK decoder bounds every static/dynamic lookup and converts an invalid index into a compression error",
        "high", "HAProxy advisory and vendored h2 HPACK table review",
    ),
    "CVE-2018-20103": (
        "not_applicable", "third-party",
        "HAProxy's in-process DNS decompressor recursively followed a self-referential compression pointer",
        "Vapache has no DNS packet decompressor; operating-system resolution runs in a bounded disposable child process",
        "high", "HAProxy advisory and resolver-worker feature review",
    ),
    "CVE-2018-20615": (
        "prevented", "http2",
        "a HEADERS frame with PRIORITY set was advanced by five bytes without rechecking that those bytes existed",
        "the vendored safe-Rust frame decoder verifies the priority payload length before decoding and cannot create an out-of-bounds slice",
        "high", "HAProxy advisory and vendored h2 HEADERS decoder review",
    ),
    "CVE-2018-11783": (
        "not_applicable", "extension-module",
        "a client-certificate-to-header plugin failed to remove attacker-supplied copies of its trusted headers",
        "Vapache has no sslheaders-style identity injection plugin; direct client-certificate authorization remains internal state rather than a request-header convention",
        "high", "NVD/CNA description and Vapache TLS/extension inventory",
    ),
    "CVE-2018-1000027": (
        "not_applicable", "unimplemented",
        "Squid parsed an upstream X-Forwarded-For response value through a nullable forwarding-policy object",
        "Vapache never interprets an upstream X-Forwarded-For field as client identity or forwarding policy; it is only a bounded ordinary response field",
        "high", "Squid advisory and forwarded-header data-flow review",
    ),
    "CVE-2018-19052": (
        "prevented", "path",
        "Alias slash mismatch allowed a relative component to escape one directory above the alias target",
        "alias matching uses component boundaries, regex aliases retain a stable base, canonical paths contain no parent segments, and final opens use openat2 beneath that base",
        "high", "NVD/CNA description, alias mapping tests, and containment review",
    ),
    "CVE-2019-18277": (
        "prevented", "http-framing",
        "a Transfer-Encoding list that omitted chunked was accepted under a different framing rule than the next hop",
        "Vapache rejects every request Transfer-Encoding value except a single exact chunked coding and always rejects CL plus TE before proxy reconstruction",
        "high", "HAProxy advisory and verified transfer-coding parser tests",
    ),
    "CVE-2019-15892": (
        "prevented", "http-parser",
        "a request header ending exactly at the receive-buffer boundary advanced past the end and hit an assertion",
        "the verified request-head parser admits only a complete CRLF-terminated head within bounds and every index/slice operation is proved in range; incomplete boundaries remain buffered or fail",
        "high", "Varnish 406b583 patch comparison and partial-head regression tests",
    ),
    "CVE-2019-11072": (
        "prevented", "path",
        "encoded-slash normalization used signed length arithmetic that underflowed",
        "encoded slashes fail closed by default; the opt-in path performs bounded safe-Rust decoding and verified canonical normalization without attacker-derived pointer arithmetic",
        "high", "NVD/CNA description and URI normalization implementation review",
    ),
    "CVE-2019-12520": (
        "prevented", "cache",
        "decoded URL userinfo changed the authority/path boundary used as a reverse-proxy cache key",
        "userinfo is forbidden by the strict authority parser, absolute form is off by default, and opt-in absolute form must match Host, scheme, transport and effective port before caching or routing",
        "high", "NVD/CNA description and authority/cache-key review",
    ),
    "CVE-2019-12854": (
        "not_applicable", "extension-module",
        "the cachemgr.cgi helper read beyond an incorrectly terminated native string",
        "Vapache has no cache-manager CGI helper or Squid management protocol",
        "high", "NVD/CNA description and Vapache feature inventory",
    ),
    "CVE-2019-14241": (
        "not_applicable", "unimplemented",
        "HAProxy's persistence/cookie management routine entered an internal panic state on crafted client cookies",
        "Vapache does not parse cookies for load-balancer persistence or rewrite them through an HTX cookie state machine; Cookie is an opaque bounded request field",
        "high", "NVD/CNA description and Vapache cookie data-flow review",
    ),
    "CVE-2019-17559": (
        "prevented", "http-parser",
        "an invalid or unknown absolute-URI scheme was parsed as a different authority/path identity",
        "client absolute form is disabled by default and, when enabled, admits only exact http/https with strict authority syntax plus scheme/transport/Host agreement",
        "high", "Traffic Server 6affb92 patch comparison and absolute-form regression tests",
    ),
    "CVE-2019-17565": (
        "prevented", "http-framing",
        "a completed chunked message and bytes left in an initial tunnel buffer were accounted under inconsistent boundaries",
        "Vapache parses exact chunk records into a bounded body, consumes the terminating chunk and trailers before dispatch, and never tunnels residual HTTP bytes or reuses an upstream connection",
        "high", "Traffic Server 60e0a8c patch comparison and chunk-boundary regression tests",
    ),
    "CVE-2019-18676": (
        "prevented", "http-parser",
        "a crafted URI scheme was copied into a heap buffer before normal security checks with insufficient validation",
        "Vapache accepts origin form by default; opt-in absolute form admits only exact http/https and parses its bounded authority/path into owned safe-Rust values before routing or authorization",
        "high", "Squid advisory and absolute-form request parser review",
    ),
    "CVE-2019-18802": (
        "prevented", "http-parser",
        "trailing Host whitespace produced a different policy identity from the routed authority",
        "header OWS is canonicalized once by the verified parser and the resulting Host must pass the strict authority parser before routing",
        "high", "NVD/CNA description and Host parser review",
    ),
    "CVE-2019-19330": (
        "prevented", "http2",
        "HTTP/2 header controls survived intermediary encapsulation",
        "the HTTP/2 codec rejects invalid HeaderValue controls and Vapache independently rejects connection-specific downgrade fields before constructing its request",
        "high", "NVD/CNA description, vendored h2 review, and adapter tests",
    ),
    "CVE-2019-9900": (
        "prevented", "http-parser",
        "embedded NUL made header matching disagree with C-string consumers",
        "HTTP/1 field values reject NUL and all other non-HTAB controls; HTTP/2 HeaderValue decoding enforces the same boundary",
        "high", "NVD/CNA description and HTTP/1/HTTP/2 header validation review",
    ),
    "CVE-2020-14058": (
        "prevented", "tls",
        "an unrecognized TLS validation error mapped to null and was later treated as a valid diagnostic string",
        "Rustls returns typed errors with owned formatting and the proxy converts every handshake/validation failure directly into an I/O error and generic 502 without nullable error-string lookup",
        "high", "Squid advisory and upstream TLS error-path review",
    ),
    "CVE-2020-17509": (
        "prevented", "cache",
        "negative-cache enablement was confused with response cacheability, allowing request-specific 400/405 responses to poison later cache lookups",
        "Vapache's proved status allowlist excludes 400, 401, 405, 407 and 5xx; only standard cacheable statuses including 404/410 proceed, then policy, credentials, Vary, Set-Cookie, size and freshness gates all apply",
        "high", "Traffic Server ac7ed95 patch comparison and Vapache cache-store gate review",
    ),
    "CVE-2020-25097": (
        "prevented", "http-framing",
        "a permissive uri_whitespace mode let whitespace select different request-target and framing interpretations across hops",
        "Vapache has no permissive whitespace mode: the verified request line requires exactly two SP delimiters and rejects whitespace or controls inside the target before proxying",
        "high", "Squid advisory and verified request-line parser review",
    ),
    "CVE-2020-8449": (
        "prevented", "http-parser",
        "control/whitespace bytes in request-target components were normalized differently before and after security filters",
        "the request target is byte-validated, percent-decoded and canonicalized once before authorization; controls, backslashes, fragments, malformed escapes and literal request-line whitespace fail closed",
        "high", "SQUID-2020_1 patch/advisory and canonical request-plan review",
    ),
    "CVE-2020-8659": (
        "prevented", "request-body",
        "decoded-body accounting did not bound per-chunk metadata/work for a message containing many tiny HTTP/1 chunks",
        "both client request and upstream response decoders stream payload bytes without retaining chunk objects and independently cap chunk count, framing bytes, line length, decoded bytes and read lifetime",
        "high", "Envoy GHSA-jwcm-4pwp-c2qv root cause, shared chunk-framing budget, and regression tests",
    ),
    "CVE-2020-15049": (
        "prevented", "http-framing",
        "signed or non-HTTP-whitespace Content-Length values were parsed differently by adjacent hops",
        "Content-Length is accepted only as one non-empty ASCII decimal field after SP/HTAB OWS trimming; duplicates and every CL/TE combination are rejected",
        "high", "NVD/CNA description and verified framing parser tests",
    ),
    "CVE-2020-1944": (
        "prevented", "http-framing",
        "Transfer-Encoding and Content-Length validation selected inconsistent message boundaries",
        "the verified parser rejects CL plus TE, conflicting or malformed CL, and every transfer-coding list other than one exact final chunked coding before any body or proxy processing",
        "high", "Traffic Server header-validation patch comparison and verified framing tests",
    ),
    "CVE-2020-11653": (
        "not_applicable", "unimplemented",
        "PROXY protocol v2 TLS metadata exhausted or violated Varnish's connection workspace invariant",
        "Vapache does not accept PROXY protocol v1/v2 connection prefaces or TLS metadata from a separate termination proxy",
        "high", "VSV00005 advisory and listener feature inventory",
    ),
    "CVE-2021-27577": (
        "prevented", "cache",
        "a URL fragment survived into the cache identity under a different interpretation from routing",
        "the verified request-target splitter rejects every fragment marker before canonicalization, cache-key construction, authorization, proxying, or filesystem mapping",
        "high", "Traffic Server advisory and request-target/cache-key proof review",
    ),
    "CVE-2021-32565": (
        "prevented", "http-framing",
        "invalid Content-Length syntax was accepted under a different boundary than an adjacent hop",
        "Content-Length is one non-empty checked ASCII decimal field; duplicates, overflow and every Transfer-Encoding combination fail before body processing",
        "high", "Traffic Server advisory and verified Content-Length parser tests",
    ),
    "CVE-2021-38161": (
        "prevented", "tls",
        "origin TLS verification could complete without authenticating the intended peer identity",
        "Vapache's HTTPS upstream returns an HTTP-capable stream only after Rustls/webpki verifies the configured trust roots and exact backend ServerName; there is no insecure verification mode",
        "high", "Traffic Server advisory and upstream TLS connection-state review",
    ),
    "CVE-2021-44040": (
        "prevented", "http-parser",
        "an invalid request line was admitted into later HTTP processing",
        "the verified parser requires a valid method token, exactly two SP separators, a non-empty bounded target, and exact HTTP/1.0 or 1.1 before constructing Request",
        "high", "Traffic Server advisory and verified request-line parser tests",
    ),
    "CVE-2021-44759": (
        "prevented", "tls",
        "origin TLS validation failed to bind the authenticated certificate to the intended upstream",
        "every HTTPS backend connection supplies its configured host as Rustls ServerName and completes webpki chain/name validation before exposing the stream to HTTP parsing",
        "high", "Traffic Server advisory and upstream TLS connection-state review",
    ),
    "CVE-2021-39240": (
        "prevented", "http2",
        "invalid :scheme or :path characters produced a different downstream authority/routing identity",
        "the adapter requires scheme/transport agreement, a strict authority, an absolute fragment-free canonical path, and re-encodes the one admitted target before an HTTP/1 proxy request",
        "high", "HAProxy advisory and HTTP/2 target/proxy downgrade review",
    ),
    "CVE-2021-40346": (
        "prevented", "http-parser",
        "header-size integer overflow truncated a security-relevant field before ACL evaluation and enabled request smuggling",
        "Vapache uses checked usize bounds, rejects the complete over-limit head atomically, never truncates field names or values, and evaluates policy only on the admitted representation",
        "high", "HAProxy advisory and verified request-head limit review",
    ),
    "CVE-2021-26758": (
        "not_applicable", "admin-control-plane",
        "an authenticated web-admin user could configure a privileged external application group and trigger a restart",
        "Vapache exposes no web administration panel, remote configuration mutation, external-app user/group editor, or privileged restart endpoint",
        "high", "OpenLiteSpeed issue 217 proof-of-concept and Vapache control-plane inventory",
    ),
    "CVE-2021-41611": (
        "prevented", "tls",
        "Squid's certificate classification marked a failed origin/peer validation result as trusted",
        "Vapache's HTTPS upstream is usable only after Rustls/webpki validates the chain, name and trust root; handshake failure yields no HTTP stream or trust signal to a client",
        "high", "Squid advisory and upstream Rustls state-transition review",
    ),
    "CVE-2021-23017": (
        "not_applicable", "third-party",
        "nginx's in-process DNS compression parser wrote one byte past a native name buffer",
        "Vapache has no DNS packet/compression parser; bounded host text is resolved by the operating system inside a disposable child worker",
        "high", "nginx advisory and resolver-worker architecture review",
    ),
    "CVE-2021-29492": (
        "prevented", "path",
        "escaped separators were compared by policy before a backend decoded and normalized them",
        "encoded slash/backslash is rejected by default; when encoded slash support is explicitly enabled it is decoded and normalized before access policy and proxy selection",
        "high", "vendor advisory and canonical request-plan review",
    ),
    "CVE-2021-32779": (
        "prevented", "path",
        "URI fragments were admitted into a server-side path authorization identity",
        "the verified target splitter rejects every fragment marker before canonicalization, routing, authorization, caching, or proxying",
        "high", "vendor advisory and request-target parser tests",
    ),
    "CVE-2021-39242": (
        "prevented", "http-parser",
        "Host and absolute-form authority mismatch yielded an attacker-controlled routing identity",
        "absolute-form requests now require exact normalized host, effective port, scheme and transport agreement with Host",
        "high", "NVD/CNA description and authority mismatch regression tests",
    ),
    "CVE-2022-28129": (
        "prevented", "http-parser",
        "invalid HTTP/1.1 field syntax was admitted into downstream processing",
        "the verified parser requires non-empty token field names, exact colon placement, rejects obs-fold and controls, and applies line/count/aggregate limits before Request construction",
        "high", "Traffic Server advisory and verified header parser tests",
    ),
    "CVE-2022-31778": (
        "prevented", "http-framing",
        "an invalid Transfer-Encoding value was normalized into a cacheable message under a different boundary",
        "Vapache accepts only one exact chunked transfer-coding, rejects CL plus TE and malformed lists, fully decodes the body, and stores no hop-by-hop framing fields in cache",
        "high", "Traffic Server advisory and framing/cache-store review",
    ),
    "CVE-2022-0711": (
        "not_applicable", "unimplemented",
        "HAProxy's response-cookie normalization loop failed to advance on a crafted Set-Cookie2 value",
        "Vapache does not parse or normalize Set-Cookie/Set-Cookie2 semantics; validated response fields remain opaque bounded byte strings",
        "high", "HAProxy advisory and upstream-response header data-flow review",
    ),
    "CVE-2022-23959": (
        "prevented", "request-lifecycle",
        "a response was generated without exhausting the current request body, so remaining bytes became a second request",
        "Vapache consumes and frames the complete HTTP/1 body before dispatch and closes on every body parse/read failure; it never reuses an upstream connection",
        "high", "Varnish vendor advisory/workaround and Vapache connection-loop review",
    ),
    "CVE-2022-41742": (
        "not_applicable", "extension-module",
        "the optional nginx MP4 metadata parser wrote outside a native buffer while processing a crafted local media file",
        "Vapache has no MP4 transformation or metadata-parsing module and serves media files as opaque bytes",
        "high", "nginx advisory and Vapache feature inventory",
    ),
    "CVE-2022-30780": (
        "prevented", "http-parser",
        "a state update typo made a multi-read large request head spin without progress",
        "Vapache's bounded head reader either consumes bytes, reaches the terminator, returns I/O failure, or hits the absolute size/deadline; its parser loops have proved decreasing measures",
        "high", "lighttpd advisory and request-head loop/proof review",
    ),
    "CVE-2022-37797": (
        "prevented", "websocket",
        "an invalid WebSocket handshake left a native handler function pointer uninitialized",
        "the upgrade path is an ordinary Rust branch that requires an exact GET/Upgrade/Connection/version/key handshake and returns an error before a tunnel object exists",
        "high", "lighttpd advisory and WebSocket admission review",
    ),
    "CVE-2022-38150": (
        "prevented", "proxy",
        "a malformed upstream HTTP reason phrase reached an internal assertion",
        "the upstream status parser accepts only HTTP/1.0 or 1.1, a three-digit 100-599 status, and a control-free reason phrase with exact delimiters, returning 502 on failure",
        "high", "VSV00009 advisory and upstream status-line regression tests",
    ),
    "CVE-2022-41556": (
        "prevented", "cgi",
        "exceptional chunked client shutdown leaked gateway connection slots",
        "request bodies are consumed before gateway dispatch; per-request FastCGI/proxy streams, resource leases, spool files and timeouts are RAII-owned and dropped on every error return",
        "medium", "lighttpd advisory and request/gateway resource-lifecycle review",
    ),
    "CVE-2022-42252": (
        "prevented", "http-framing",
        "invalid Content-Length syntax was tolerated at one hop",
        "there is no permissive parser mode: malformed, empty, signed, conflicting, or CL-plus-TE framing is rejected before body reads",
        "high", "NVD/CNA description and verified framing tests",
    ),
    "CVE-2022-45059": (
        "prevented", "proxy",
        "a client-nominated hop-by-hop field suppressed a critical backend framing header",
        "Vapache strips all inbound hop-by-hop fields and Connection-nominated fields, then reconstructs Host and one exact Content-Length from the admitted body",
        "high", "NVD/CNA description and outbound proxy-head review",
    ),
    "CVE-2022-45060": (
        "prevented", "http2",
        "invalid method or path bytes in HTTP/2 pseudo-headers were serialized into an ambiguous HTTP/1 backend request line",
        "the adapter validates the method token and canonical absolute path, rejects controls/fragments, and the proxy re-encodes the admitted path before constructing one request line",
        "high", "VSV00011 advisory and HTTP/2-to-proxy downgrade review",
    ),
    "CVE-2023-38522": (
        "prevented", "http-parser",
        "an invalid HTTP field name was forwarded under a different downstream interpretation",
        "HTTP/1 field names must be non-empty RFC tokens and are never truncated; proxy requests are serialized only from the validated representation",
        "high", "NVD/CNA description and verified header-name parser tests",
    ),
    "CVE-2023-40225": (
        "prevented", "http-framing",
        "an empty Content-Length field was forwarded and interpreted as no body by only one hop",
        "empty Content-Length is invalid in the verified parser and closes the connection before proxying",
        "high", "NVD/CNA description and Content-Length parser review",
    ),
    "CVE-2023-45539": (
        "prevented", "path",
        "a fragment marker was treated as part of a path matcher identity",
        "fragment markers are rejected at request-target parsing and cannot reach suffix, rewrite, authorization, or filesystem matching",
        "high", "NVD/CNA description and request-target regression tests",
    ),
    "CVE-2023-46589": (
        "prevented", "http-framing",
        "an over-limit trailer was reinterpreted as a second request",
        "trailers are disabled by default; when enabled every line, aggregate bytes and field count are bounded and any failure closes the connection",
        "high", "NVD/CNA description and trailer boundary tests",
    ),
    "CVE-2023-46846": (
        "prevented", "http-framing",
        "a lenient chunk decoder accepted 0x-prefixed sizes, non-CRLF delimiters, or partially consumed invalid extensions",
        "Vapache requires a complete RFC 9112 chunk-size/extension line, exact CRLF delimiters, and a valid delimiter after each chunk in both request and upstream-response decoders",
        "high", "Squid vendor patch comparison and malformed-chunk regression tests",
    ),
    "CVE-2023-49285": (
        "prevented", "proxy",
        "an empty or truncated RFC 1123 month token was read as though three bytes were present",
        "HTTP date parsing is delegated to the safe-Rust httpdate parser over a bounded slice; malformed dates return None and cannot create an out-of-bounds read",
        "high", "Squid 77b3fb4/deee944 patch comparison and conditional/cache date parser review",
    ),
    "CVE-2023-49286": (
        "not_applicable", "unimplemented",
        "a local file-descriptor duplication failure asserted inside Squid's external-helper child bootstrap",
        "Vapache has no Squid helper-process manager; its CGI/FastCGI execution paths check spawn and descriptor errors and return a request error",
        "high", "Squid 6014c66 patch comparison and process feature inventory",
    ),
    "CVE-2023-30631": (
        "fail_closed", "protocol-other",
        "a configuration option intended to disable the nonstandard PUSH method was not enforced",
        "PUSH has no handler in Vapache and cannot dispatch to static, CGI, FastCGI, or proxy content unless an administrator separately creates explicit rewrite behavior",
        "high", "Traffic Server advisory and Vapache method dispatch inventory",
    ),
    "CVE-2023-0836": (
        "prevented", "cgi",
        "five uninitialized bytes in FCGI_BEGIN_REQUEST padding were disclosed to a configured backend",
        "Vapache initializes the full eight-byte begin-request body to zero and explicitly writes zero bytes for every FastCGI padding octet",
        "high", "HAProxy advisory and FastCGI record encoder review",
    ),
    "CVE-2023-25950": (
        "fail_closed", "http3",
        "HTTP/3 field names containing uppercase or non-token bytes were forwarded rather than rejected",
        "Vapache does not implement HTTP/3 or QUIC; both implemented HTTP versions reject non-token field names and HTTP/2 additionally requires lowercase codec names",
        "high", "HAProxy 3ca4223 patch comparison and protocol inventory",
    ),
    "CVE-2023-33934": (
        "prevented", "range",
        "an unsatisfiable reversed byte range reached an inconsistent cache/DNS transaction state and crashed the proxy",
        "the verified range parser returns an explicit unsatisfiable decision for start greater than end before cache or file dispatch and never enters proxy DNS state",
        "high", "Traffic Server 5d0835e patch comparison and verified range tests",
    ),
    "CVE-2024-35161": (
        "prevented", "http-framing",
        "malformed chunk trailers were forwarded to an origin under a different parser interpretation",
        "trailers are disabled by default; when enabled, every trailer line uses strict field syntax and byte/count bounds, forbidden framing fields are rejected, and proxy requests are reconstructed without forwarding client trailers",
        "high", "Traffic Server advisory and trailer/proxy reconstruction review",
    ),
    "CVE-2024-50305": (
        "prevented", "http-parser",
        "a syntactically valid Host value overflowed or crashed platform-specific native processing",
        "Host is bounded by the request-head limit, parsed into owned safe-Rust host/optional-u16-port values, and forbidden characters or malformed IPv6 fail before vhost lookup",
        "high", "Traffic Server advisory and strict authority parser review",
    ),
    "CVE-2024-53868": (
        "prevented", "http-framing",
        "malformed chunk syntax was accepted under a different message boundary and enabled request smuggling",
        "Vapache validates the full chunk-size/extension grammar, exact CRLF delimiters, body budget, zero chunk and strict trailers before dispatch; any failure closes the connection",
        "high", "Traffic Server advisory and malformed-chunk regression tests",
    ),
    "CVE-2024-25111": (
        "prevented", "http-framing",
        "the chunk decoder recursively re-entered parsing for crafted extension/data boundaries until stack exhaustion",
        "both Vapache chunk decoders are iterative state machines over bounded lines/bodies with proved or explicit decreasing input progress and no recursive parse calls",
        "high", "Squid GHSA-72c2-c3wm-8qxc and chunk parser implementation review",
    ),
    "CVE-2024-45802": (
        "not_applicable", "extension-module",
        "multiple lifetime and validation bugs in Squid's optional ESI XML element processors caused global proxy denial of service",
        "Vapache has no Edge Side Includes parser or response-template execution engine and serves/proxies response bodies as opaque bounded streams",
        "high", "Squid GHSA-f975-v7qw-q7hj and Vapache feature inventory",
    ),
    "CVE-2024-27919": (
        "prevented", "http2",
        "CONTINUATION frames remained unbounded after the decoded header limit was exceeded",
        "the vendored h2 codec caps raw continuation count/block bytes and decoded header abuse size, while Vapache applies a second decoded head budget",
        "high", "vendor advisory and vendored h2 framed-read implementation review",
    ),
    "CVE-2024-31309": (
        "prevented", "http2",
        "a CONTINUATION-frame flood consumed work beyond the request header budget",
        "the vendored h2 codec derives a hard continuation-frame cap from the configured header/frame limits and aborts an over-limit connection",
        "high", "NVD/CNA description and vendored h2 framed-read implementation review",
    ),
    "CVE-2024-45506": (
        "not_applicable", "http2",
        "HAProxy's zero-copy H2 mux cleared output buffers without clearing coupled full/no-room flags, causing its send loop to spin",
        "Vapache's vendored h2 state machine has no HAProxy zero-copy mux, ring-buffer full flags, or equivalent flag/buffer coupling",
        "high", "HAProxy c725db1/d636e51 patch comparison and vendored h2 architecture review",
    ),
    "CVE-2024-53271": (
        "prevented", "proxy",
        "a non-101 informational upstream response entered an ordinary final-response path",
        "normal reverse-proxy responses reject every 1xx status; WebSocket upgrades use a separate exact 101 path that rejects response framing metadata and reconstructs the switching head",
        "high", "NVD/CNA description and upstream status parser regression tests",
    ),
    "CVE-2025-55754": (
        "prevented", "logging",
        "terminal escape controls from a request were emitted verbatim to operator-visible logs",
        "the verified log encoder hex-escapes every control byte including ESC before any client-derived field reaches access or error logs",
        "high", "NVD/CNA description and verified logging sink review",
    ),
    "CVE-2025-58136": (
        "prevented", "request-body",
        "an Expect/POST buffering transition reused a request-body tunnel after its backing buffer had been cleared",
        "Vapache fully owns and consumes each request body/spool before dispatch; Expect: 100-continue does not create or reuse a proxy tunnel buffer and fallible reads close the request",
        "high", "Traffic Server cb9e4a1 patch comparison and Vapache request-body lifecycle review",
    ),
    "CVE-2025-65114": (
        "prevented", "http-framing",
        "stale carriage-return state across chunk-parser iterations accepted malformed chunk boundaries",
        "the iterative Vapache parser requires exact CRLF at every chunk boundary and validates each complete size/extension line without cross-iteration sentinel state",
        "high", "Traffic Server e5accd7 patch comparison and partial-CRLF regression tests",
    ),
    "CVE-2025-11230": (
        "not_applicable", "unimplemented",
        "HAProxy's mjson parser performed attacker-amplified work on crafted JSON syntax",
        "Vapache does not parse JSON request bodies or implement HAProxy's JSON fetch/converter language",
        "high", "CNA description and Vapache request-body feature inventory",
    ),
    "CVE-2025-31651": (
        "prevented", "rewrite",
        "literal percent, semicolon, or question-mark path data crossed the rewrite substitution/query delimiter boundary",
        "rewrite rules consume one decoded canonical path; semicolons remain path bytes, percent is not decoded a second time, and captured question marks are verified-escaped unless an explicit UnsafeAllow3F opt-out is configured",
        "high", "Tomcat a633fe7/f4374b3 patch comparison and Vapache rewrite delimiter tests",
    ),
    "CVE-2025-62168": (
        "prevented", "error-page",
        "proxy authentication credentials were copied into attacker-visible diagnostic error output",
        "Vapache's generic proxy errors contain only an escaped canonical path and server signature; Authorization values and backend configuration are never interpolated, and backend URLs reject userinfo",
        "high", "Squid advisory/patch and generated proxy-error data-flow review",
    ),
    "CVE-2025-66614": (
        "prevented", "tls",
        "SNI and Host could select virtual hosts with different client-certificate requirements",
        "Vapache refuses startup when virtual hosts on one TLS listener have different client-auth modes or CA files, so Host/SNI choice cannot weaken client-certificate policy",
        "high", "NVD/CNA description and TLS listener-policy invariant tests",
    ),
    "CVE-2026-1642": (
        "prevented", "tls",
        "an event-order race parsed upstream plaintext before the configured TLS handshake had been initialized",
        "both synchronous and asynchronous HTTPS upstream paths construct and complete a Rustls transport before returning any object to the HTTP response parser; raw TCP bytes are never parsed on that branch",
        "high", "nginx 376c373 patch comparison and proxy transport-state review",
    ),
    "CVE-2026-111497": (
        "not_applicable", "third-party",
        "Google's native Brotli decoder overflowed a buffer while decoding attacker-supplied compressed input",
        "Vapache links the independent safe-Rust brotli crate and uses only its response encoder; it does not decode request or upstream Brotli streams",
        "high", "CNA description, Cargo.lock, and compression data-flow review",
    ),
    "CVE-2026-32990": (
        "prevented", "tls",
        "case-sensitive virtual-host comparison left a Host/SNI variant outside the client-certificate policy check",
        "authority parsing normalizes registered names, host selection is case-insensitive, and startup independently forbids different client-auth policies on one TLS listener",
        "high", "Tomcat 021d1f8 patch comparison and listener-policy invariant review",
    ),
    "CVE-2026-33267": (
        "not_applicable", "extension-module",
        "Traffic Server exposed internal @-prefixed metadata fields to plugin hooks as if they were external headers",
        "Vapache has no Traffic Server plugin-hook header namespace or @-metadata convention; all emitted fields originate in typed response policy and pass header validation",
        "high", "Traffic Server 1fc1430 patch comparison and Vapache extension inventory",
    ),
    "CVE-2026-31386": (
        "not_applicable", "admin-control-plane",
        "an administrative configuration input was interpolated into an operating-system command",
        "Vapache has no remote administration interface or request-time configuration command runner",
        "high", "JVN/CNA description and Vapache control-plane inventory",
    ),
    "CVE-2026-41293": (
        "prevented", "http2",
        "an HTTP/2 :scheme value could disagree with whether the connection was protected by TLS",
        "the adapter now requires exact http on cleartext and https on TLS before constructing a request, and the verified h2 target gate records the same invariant",
        "high", "Tomcat 96817a0 patch comparison, proof, and HTTP/2 regression tests",
    ),
    "CVE-2026-43515": (
        "prevented", "auth",
        "the constraint search stopped after one extension match and failed to evaluate another method-specific rule for the same extension",
        "Vapache collects and applies every matching Files/FilesMatch rule in phase order; method-limited authorization rules are not used as a reason to stop the match scan",
        "high", "Tomcat 276087d patch comparison and configuration merge review",
    ),
    "CVE-2026-55203": (
        "prevented", "cgi",
        "a 16-bit FastCGI remaining-length field wrapped when contentLength 65535 was combined with padding",
        "Vapache widens both wire fields to usize before addition, reads exactly content plus padding into one checked allocation, then truncates padding; no sum is stored back into u16",
        "high", "HAProxy 5985276 patch comparison and FastCGI record parser review",
    ),
    "CVE-2026-55204": (
        "prevented", "http2",
        "an HPACK dynamic-table defragmentation allocation failure was dereferenced without a null check",
        "the safe-Rust HPACK implementation has no nullable native allocation result, and Vapache caps per-connection and aggregate decoded/resident header memory before dispatch",
        "high", "HAProxy 9a6d1fe patch comparison and vendored h2/resource-budget review",
    ),
    "CVE-2026-57834": (
        "prevented", "http-framing",
        "malformed chunk syntax was admitted under a different boundary than an adjacent HTTP parser",
        "both request and upstream decoders require the complete RFC chunk grammar, exact CRLF, a bounded body, terminating zero chunk and strict trailers; failures close rather than forward",
        "high", "Traffic Server release-fix lineage and malformed chunk regression tests",
    ),
    "CVE-2026-58159": (
        "prevented", "auth",
        "nonstandard-method ACL matching used an inverted/under-bounded comparison, while Unix listeners lacked the intended client-address identity",
        "Vapache accepts only TCP HTTP listeners, validates the full method token, and evaluates exact initialized method sets without prefix-length comparison or PROXY/UDS-derived client identities",
        "high", "Traffic Server 7606f49/956e623 patch comparison and listener/method ACL review",
    ),
    "CVE-2026-59083": (
        "prevented", "rewrite",
        "a generic form decoder converted a literal plus in a rewritten URL path into a space",
        "Vapache's path percent decoder and rewrite pipeline preserve literal plus bytes; plus-to-space conversion exists only in explicitly form-style RewriteMap escaping/unescaping",
        "high", "Tomcat f00ab28 patch comparison and rewrite/path decoder review",
    ),
    "CVE-2026-65182": (
        "prevented", "auth",
        "mutable longest-match bookkeeping let an earlier longer pattern make a later shorter match suppress a more-specific constraint",
        "Vapache does not select one authorization section through shared longest-match state: every matching Directory, Files and Location rule is collected and merged in the documented Apache phase/order model",
        "high", "Tomcat 8bafd79 patch comparison and configuration match-loop review",
    ),
    "CVE-2026-65637": (
        "prevented", "http2",
        "an absent HTTP/2 authority fell through to a default virtual host and bypassed the intended host-bound TLS policy",
        "every HTTP/2 request now requires a non-empty strictly parsed :authority, and startup forbids per-host client-auth differences on the same listener",
        "high", "Tomcat 8639b20 fix lineage and HTTP/2 authority/listener-policy tests",
    ),
    "CVE-2026-68525": (
        "not_applicable", "java-container",
        "container FORM authentication changed the request method without refreshing the selected servlet security constraints",
        "Vapache has no servlet FORM-authentication flow, saved-request replay, or Java security-constraint layer",
        "high", "Tomcat 10d048e patch comparison and Vapache feature inventory",
    ),
    "CVE-2026-24880": (
        "prevented", "http-framing",
        "an invalid chunk extension was accepted under a different message boundary than an intermediary",
        "both request and upstream-response decoders now validate the complete RFC 9112 chunk-extension grammar and exact chunk delimiters",
        "high", "vendor root cause and malformed-extension regression tests",
    ),
    "CVE-2026-2332": (
        "prevented", "http-framing",
        "a CRLF inside an unterminated quoted chunk extension ended the extension instead of invalidating the message",
        "the chunk parser validates the complete quoted-string grammar and rejects CR, LF, missing closing quotes, and any bytes after a closed value other than BWS or a new extension",
        "high", "vendor advisory and malformed quoted-extension regression tests",
    ),
    "CVE-2026-5795": (
        "prevented", "request-lifecycle",
        "an early authentication return left thread-local identity state visible to the next request",
        "Vapache clears its request identity before every dispatch and destructively takes it afterward; HTTP/1 requests are sequential and HTTP/2 dispatches run inside the same reset/take boundary",
        "high", "vendor advisory and Vapache request identity lifecycle review",
    ),
    "CVE-2026-58150": (
        "prevented", "http2",
        "HTTP/2 Transfer-Encoding survived into an HTTP/1 downgrade",
        "the adapter explicitly rejects Transfer-Encoding and every other HTTP/2 connection-specific field; TE is restricted to the exact value trailers",
        "high", "vendor root cause and HTTP/2 adapter regression tests",
    ),
    "CVE-2026-58155": (
        "prevented", "http-parser",
        "over-long field names were truncated into aliases of security-relevant headers",
        "Vapache rejects over-limit header lines and field counts atomically and never truncates a field name",
        "high", "vendor root cause and verified request-head limit review",
    ),
    "CVE-2026-73550": (
        "prevented", "http2",
        "duplicate decoded Host values were copied and discarded without charging header limits",
        "the h2 codec charges decoded fields, and Vapache separately reserves every decoded header byte and counts each Host before discarding it in favor of :authority",
        "high", "vendor advisory and HTTP/2 resident/header-budget review",
    ),
    "CVE-2026-73553": (
        "prevented", "path",
        "routing stripped semicolon path parameters while authorization compared the raw path",
        "Vapache has no path-parameter stripping mode: semicolons remain ordinary bytes in the one canonical identity used by routing, authorization, cache, proxy and filesystem mapping",
        "high", "vendor advisory and canonical request-plan review",
    ),
    "CVE-2019-15225": (
        "prevented", "rewrite",
        "a backtracking C++ regex engine was run against an attacker-controlled unbounded URI",
        "request targets are capped before matching and every route/rewrite regex uses a non-backtracking finite-automata engine with an admitted regular dialect",
        "high", "Envoy advisory and Vapache regex-engine/request-line limit review",
    ),
    "CVE-2019-15226": (
        "prevented", "http-parser",
        "header-size accounting rescanned all prior fields for every new field, making many small headers quadratic",
        "Vapache caps the field count at 100 and total head at 128 KiB before constructing the request; parser accounting advances once over each input byte",
        "high", "Envoy advisory and verified request-head parser complexity review",
    ),
    "CVE-2019-18836": (
        "not_applicable", "extension-module",
        "an idle listener-filter timeout repeatedly resumed the same filter state without progress",
        "Vapache has no listener-filter chain or continue_on_listener_filters_timeout mode; accepted sockets enter one bounded HTTP/TLS state machine",
        "high", "Envoy advisory and listener feature inventory",
    ),
    "CVE-2019-18838": (
        "fail_closed", "http-parser",
        "a missing Host reached an error-response filter that dereferenced the absent routing value",
        "HTTP/1.1 without exactly one valid Host and HTTP/2 without a valid :authority are rejected before dispatch, and generated errors do not traverse a plugin filter chain",
        "high", "Envoy advisory and request admission/error response review",
    ),
    "CVE-2020-12603": (
        "prevented", "http2",
        "per-DATA-frame bookkeeping made memory consumption proportional to frame count rather than payload bytes",
        "the vendored h2 codec charges small-frame overhead to a connection budget, caps empty DATA frames, and Vapache copies accepted payload into byte/spool budgets rather than retaining frame objects",
        "high", "Envoy advisory and vendored h2 DataFrameBudget implementation/tests",
    ),
    "CVE-2020-12604": (
        "prevented", "http2",
        "response bytes accumulated without a bound while a client withheld flow-control credit",
        "response sends wait for capacity under one response deadline, h2's per-stream send buffer is capped, and file bodies are read only after capacity is granted",
        "high", "Envoy advisory and Vapache send_capacity/streaming response review",
    ),
    "CVE-2020-12605": (
        "prevented", "http-parser",
        "long URLs and long field names were allocated before a sufficiently strict aggregate limit",
        "both HTTP versions enforce request-target, per-field, field-count, decoded-head and process-resident limits before dispatch",
        "high", "Envoy advisory and HTTP/1 plus HTTP/2 admission review",
    ),
    "CVE-2020-25017": (
        "prevented", "http-parser",
        "a replace operation updated only the first occurrence of a repeated non-inline field",
        "Headers::insert removes every existing occurrence before adding one value; input duplicates are retained or merged with field-specific separators and security consumers see that canonical view",
        "high", "Envoy advisory and Headers insert/merge semantics review",
    ),
    "CVE-2020-25018": (
        "prevented", "http-parser",
        "request URL host canonicalization failed and left routing with an inconsistent authority identity",
        "the strict authority parser produces one normalized registered-name or literal-IP identity and reconciles absolute-form authority with Host, port and transport before vhost routing",
        "high", "Envoy advisory and authority canonicalization regression tests",
    ),
    "CVE-2020-35471": (
        "not_applicable", "protocol-other",
        "a truncated oversized UDP datagram reached an invalid native buffer state",
        "Vapache has no UDP listener, UDP proxy, QUIC, or datagram processing path",
        "high", "Envoy advisory and transport feature inventory",
    ),
    "CVE-2020-8663": (
        "prevented", "dos",
        "accepted connections consumed descriptors and memory without global admission control",
        "connection admission is atomically capped by MaxRequestWorkers and a per-client quota before a worker is spawned; rejected sockets are closed and EMFILE/ENFILE backs off",
        "high", "Envoy advisory and connection admission implementation/tests",
    ),
    "CVE-2021-21378": (
        "not_applicable", "extension-module",
        "JWT result aggregation converted unknown-issuer failure into the allow-missing state",
        "Vapache has no JWT authentication filter, issuer aggregation, or allow-missing JWT policy",
        "high", "Envoy GHSA root cause and authentication feature inventory",
    ),
    "CVE-2021-28682": (
        "not_applicable", "extension-module",
        "an oversized grpc-timeout value overflowed gRPC timeout arithmetic",
        "Vapache does not parse gRPC timeout metadata or implement a gRPC filter",
        "high", "Envoy advisory and protocol feature inventory",
    ),
    "CVE-2021-28683": (
        "prevented", "tls",
        "an unknown TLS alert was converted through a nullable native lookup and dereferenced",
        "Rustls parses alerts into safe typed errors; all handshake failures become a generic bounded connection/proxy error without nullable alert lookup",
        "high", "Envoy advisory and Rustls error-path review",
    ),
    "CVE-2021-29258": (
        "not_applicable", "extension-module",
        "an empty value for Envoy's nonstandard HTTP/2 METADATA extension frame reached an assertion",
        "Vapache exposes no HTTP/2 METADATA API or metadata filter; unsupported extension frames are owned by the h2 codec and never dispatched as requests",
        "high", "Envoy advisory and HTTP/2 extension inventory",
    ),
    "CVE-2021-32777": (
        "not_applicable", "extension-module",
        "the ext_authz adapter sent only the last repeated header instead of the RFC-combined authorization input",
        "Vapache has no external-authorization filter or ext_authz serialization boundary",
        "high", "Envoy GHSA root cause and authorization feature inventory",
    ),
    "CVE-2021-32780": (
        "not_applicable", "proxy",
        "GOAWAY followed by SETTINGS from an HTTP/2 upstream drove an illegal closed-to-draining transition",
        "Vapache never speaks HTTP/2 to an upstream: proxy connections are fresh HTTP/1.1 transports and cannot enter this upstream codec state",
        "high", "Envoy GHSA root cause and upstream protocol inventory",
    ),
    "CVE-2021-39162": (
        "not_applicable", "proxy",
        "Pomerium inherited Envoy's upstream GOAWAY-plus-SETTINGS invalid transition",
        "Vapache is not Pomerium and has no HTTP/2 upstream client path",
        "high", "Pomerium advisory and upstream protocol inventory",
    ),
    "CVE-2021-39204": (
        "prevented", "http2",
        "reset-stream cleanup performed attacker-amplified work across an insufficiently bounded retained-stream set",
        "the h2 codec caps local, remote-pending and error resets and expires retained resets; Vapache adds process/per-client stream caps and an idempotent reset ledger",
        "high", "Pomerium/Envoy advisory and h2 reset-budget implementation review",
    ),
    "CVE-2021-39206": (
        "not_applicable", "extension-module",
        "Pomerium inherited Envoy ext_authz duplicate-header and path-prefix policy inconsistencies",
        "Vapache has neither Pomerium's policy layer nor Envoy ext_authz; its local access evaluator consumes one canonical path and merged header view",
        "high", "Pomerium advisory and authorization architecture comparison",
    ),
    "CVE-2021-43824": (
        "not_applicable", "extension-module",
        "a path-less CONNECT request reached a JWT regex filter that assumed a normal request target",
        "Vapache has no JWT filter and rejects CONNECT instead of sending it through rewrite/regex request dispatch",
        "high", "Envoy advisory and method/filter inventory",
    ),
    "CVE-2021-43826": (
        "not_applicable", "extension-module",
        "disconnect during Envoy generic upstream-tunnel establishment left inconsistent tunnel state",
        "Vapache has no generic TCP proxy tunneling_config; its only tunnel is a WebSocket path entered after an exact completed 101 handshake",
        "high", "Envoy advisory and tunnel feature inventory",
    ),
    "CVE-2022-21654": (
        "prevented", "tls",
        "an upstream TLS connection was reused after certificate-validation policy changed",
        "Vapache does not pool or reuse upstream connections, and each HTTPS request creates Rustls state from an immutable configuration keyed by the configured backend identity",
        "high", "Envoy advisory and upstream TLS lifecycle review",
    ),
    "CVE-2022-21655": (
        "not_applicable", "extension-module",
        "an Envoy internal redirect selected a direct-response route whose state was incompatible with the common router",
        "Vapache has no Envoy direct-response route action or common-router filter; internal rewrite loops are bounded and re-enter the canonical request planner",
        "high", "Envoy advisory and routing feature inventory",
    ),
    "CVE-2022-21656": (
        "prevented", "tls",
        "certificate SAN types were confused so an email or URI identity could satisfy a DNS-name check",
        "Rustls/webpki uses typed DNS/IP ServerName verification and does not coerce rfc822Name or URI SAN entries into DNS identities",
        "high", "Envoy advisory and rustls-webpki identity model review",
    ),
    "CVE-2022-29225": (
        "not_applicable", "extension-module",
        "a decompression filter buffered unbounded expanded output before replacing the message body",
        "Vapache has no request or upstream-response decompression filter; supported compression only encodes already bounded responses",
        "high", "Envoy advisory and compression data-flow inventory",
    ),
    "CVE-2022-29227": (
        "prevented", "memory-safety",
        "an internal-redirect local reply reset an already-deleted upstream stream, causing use-after-free",
        "Vapache's rewrite and proxy state is owned safe Rust, upstream requests are synchronous and unpooled, and redirect/error teardown cannot retain a pointer to deleted stream state",
        "high", "Envoy advisory and Vapache ownership/proxy lifecycle comparison",
    ),
    "CVE-2023-27487": (
        "not_applicable", "extension-module",
        "an untrusted x-envoy-original-path header survived ingress and replaced the path used by JWT policy",
        "Vapache has no trusted x-envoy-original-path convention or JWT filter; routing and authorization use the parsed canonical request target rather than that field",
        "high", "Envoy advisory and trusted-header/authorization inventory",
    ),
    "CVE-2023-35944": (
        "prevented", "http2",
        "mixed-case :scheme values crossed code paths that compared scheme with different case rules",
        "the HTTP/2 adapter accepts only exact lowercase http or https and requires it to agree with the actual TLS transport before request construction",
        "high", "Envoy advisory and H2 scheme/transport admission proof and tests",
    ),
    "CVE-2023-35945": (
        "not_applicable", "proxy",
        "nghttp2 leaked pending compressed headers when an upstream RST_STREAM was immediately followed by GOAWAY",
        "Vapache has no HTTP/2 upstream client and does not link nghttp2; downstream HTTP/2 uses safe-Rust h2 with bounded reset retention",
        "high", "Envoy advisory and upstream/dependency inventory",
    ),
    "CVE-2024-23322": (
        "not_applicable", "extension-module",
        "coincident hedge, per-try and idle timers double-transitioned one Envoy retry attempt",
        "Vapache has no hedged-request or per-try retry filter and performs one bounded upstream attempt per selected backend",
        "high", "Envoy advisory and proxy retry feature inventory",
    ),
    "CVE-2024-23324": (
        "not_applicable", "extension-module",
        "failure_mode_allow treated a locally malformed ext_authz gRPC request as authorization success",
        "Vapache has no ext_authz/gRPC filter or fail-open external authorization mode",
        "high", "Envoy advisory and authorization feature inventory",
    ),
    "CVE-2024-23327": (
        "not_applicable", "extension-module",
        "PROXY protocol v2 LOCAL input lacked the address block assumed by upstream PPv2 serialization",
        "Vapache deliberately does not implement PROXY protocol on either listener or upstream transport",
        "high", "Envoy advisory and listener/proxy protocol inventory",
    ),
    "CVE-2024-32475": (
        "prevented", "tls",
        "auto_sni assumed conversion of an oversized request authority into a legal TLS server name could not fail",
        "upstream SNI comes from the bounded configured backend rather than an inbound Host, and every Rustls ServerName conversion error is propagated as a generic 502 instead of asserted",
        "high", "Envoy advisory and HTTPS backend/SNI error-path review",
    ),
    "CVE-2024-32976": (
        "not_applicable", "extension-module",
        "the Brotli request decompression filter failed to consume extra input and looped without progress",
        "Vapache never Brotli-decompresses client or upstream data and has no decompression filter",
        "high", "Envoy advisory and compression feature inventory",
    ),
    "CVE-2024-34363": (
        "not_applicable", "extension-module",
        "untrusted invalid UTF-8 caused an uncaught exception in nlohmann JSON serialization",
        "Vapache neither links nlohmann JSON nor parses request bodies as JSON; client bytes remain bounded byte strings or fail explicit UTF-8 conversion",
        "high", "Envoy advisory and JSON/dependency inventory",
    ),
    "CVE-2024-45807": (
        "not_applicable", "http2",
        "Envoy's optional oghttp2 codec had inconsistent stream-management state",
        "Vapache does not link or enable oghttp2 and uses the separately vendored safe-Rust h2 state machine",
        "high", "Envoy advisory and HTTP/2 codec inventory",
    ),
    "CVE-2024-53270": (
        "not_applicable", "extension-module",
        "an optional HTTP/1 load-shed hook assumed an active request still existed after an upstream reset",
        "Vapache has no Envoy load_shed_points hook or cross-protocol active_request pointer; overload rejection happens before worker admission",
        "high", "Envoy advisory and overload architecture comparison",
    ),
    "CVE-2026-26308": (
        "not_applicable", "extension-module",
        "RBAC deny rules exact-matched one comma-joined duplicate-header value instead of evaluating each value",
        "Vapache has no Envoy RBAC filter; its implemented authorization directives consume a documented canonical header view and do not expose this deny-rule matcher",
        "high", "Envoy advisory and authorization feature inventory",
    ),
    "CVE-2026-47220": (
        "prevented", "logging",
        "a requested-server-name log formatter dereferenced a missing Host value under host-selection options",
        "HTTP/1.1 and HTTP/2 require a valid authority before dispatch; HTTP/1.0's optional Host is represented as Option and all log-field lookups emit a bounded placeholder rather than dereference null",
        "high", "Envoy advisory and log formatter/authority admission review",
    ),
    "CVE-2026-48042": (
        "not_applicable", "extension-module",
        "recursive destruction of a deeply nested JSON object exhausted the native stack",
        "Vapache has no JSON object parser/filter and treats request bodies as opaque bounded bytes",
        "high", "Envoy advisory and request-body feature inventory",
    ),
    "CVE-2026-48044": (
        "not_applicable", "extension-module",
        "zstd request decompression admitted an extreme expansion ratio and allocated the expanded output",
        "Vapache has no zstd or request decompression path",
        "high", "Envoy advisory and compression feature inventory",
    ),
    "CVE-2026-73513": (
        "not_applicable", "proxy",
        "the optional oghttp2 upstream codec retained a stream after accepting trailers without END_STREAM, leaving a dangling decoder",
        "Vapache has no HTTP/2 upstream codec, oghttp2 dependency, connection pool, or upstream trailer stream state",
        "high", "Envoy advisory and upstream protocol inventory",
    ),
    "CVE-2026-73547": (
        "not_applicable", "extension-module",
        "ext_authz query mutation dereferenced an absent :path on path-less CONNECT",
        "Vapache has no ext_authz query mutation and rejects CONNECT; every dispatched ordinary request has a canonical target",
        "high", "Envoy advisory and method/filter inventory",
    ),
    "CVE-2026-73548": (
        "prevented", "websocket",
        "extended CONNECT data was forwarded before upgrade acceptance and the HTTP/1 upstream socket was then reused across clients",
        "Vapache does not implement HTTP/2 extended CONNECT, supports only an exact HTTP/1 WebSocket upgrade after a validated 101 response, and never pools or reuses upstream sockets",
        "high", "Envoy advisory and WebSocket handshake/upstream lifecycle review",
    ),
    "CVE-2026-73552": (
        "not_applicable", "extension-module",
        "an RBAC byte-string header was evaluated by a UTF-8 regex domain, turning invalid text into a deny-rule no-match",
        "Vapache has no Envoy RBAC filter; implemented request-header regexes are byte-oriented and never reinterpret obs-text as UTF-8",
        "high", "Envoy advisory and byte-regex/authorization feature review",
    ),
    "CVE-2002-2272": (
        "not_applicable", "java-container",
        "malformed chunked framing desynchronized the Apache mod_jk-to-Tomcat AJP bridge",
        "Vapache has no mod_jk or AJP bridge; its HTTP/1 chunk decoder validates the complete transfer coding and exact delimiters before dispatch",
        "high", "Tomcat advisory and connector/protocol inventory",
    ),
    "CVE-2016-6817": (
        "prevented", "http2",
        "an oversized HTTP/2 header block exhausted a fixed decode buffer without advancing parser state",
        "the h2 decoder has explicit compressed continuation and decoded-list bounds and aborts over-limit blocks; Vapache adds independent per-field/count/resident limits",
        "high", "Tomcat advisory and vendored h2 header decoder review",
    ),
    "CVE-2017-5650": (
        "prevented", "http2",
        "GOAWAY failed to wake and close streams blocked waiting for send-window credit, leaking one thread each",
        "h2 senders are async tasks rather than blocked OS threads, retained streams are capped, and both capacity waits and complete stream handling have fixed deadlines and cancellation cleanup",
        "high", "Tomcat advisory and H2 send/task lifecycle review",
    ),
    "CVE-2017-7675": (
        "prevented", "path",
        "the HTTP/2 connector bypassed URL normalization and security checks used by HTTP/1",
        "both adapters construct the same Request and enter one canonical request planner; percent decoding, dot-segment normalization, authorization and beneath-root open are protocol-independent",
        "high", "Tomcat advisory and shared-dispatch architecture review",
    ),
    "CVE-2018-1336": (
        "prevented", "http-parser",
        "supplementary-character overflow left the Java UTF-8 decoder in a non-progressing loop",
        "bounded URL bytes are validated with safe-Rust UTF-8 conversion and one-pass percent decoding; malformed or overlong sequences fail without incremental decoder state",
        "high", "Tomcat advisory and URI decoder review",
    ),
    "CVE-2018-8034": (
        "prevented", "tls",
        "the WebSocket TLS client authenticated the certificate chain without verifying the backend hostname",
        "wss/https upstreams always construct a typed Rustls ServerName from the configured host and webpki verifies that identity as part of the handshake",
        "high", "Tomcat advisory and upstream TLS configuration review",
    ),
    "CVE-2019-10072": (
        "prevented", "http2",
        "withheld connection WINDOW_UPDATE frames left response writers blocking indefinitely until all threads were occupied",
        "send-window waits are async, globally/locally stream-capped, and terminate at one response deadline; the response body is read only as credit is granted",
        "high", "Tomcat advisory and H2 capacity/deadline tests",
    ),
    "CVE-2020-11996": (
        "prevented", "http2",
        "a high numbered stream caused Tomcat to loop over every absent intermediate stream ID while implicitly closing idle streams",
        "the h2 stream store is sparse and never loops across unallocated numeric IDs; priority/control frames are additionally token-bucketed and active stream state is capped",
        "high", "Tomcat BZ 64467 / 9a023168 patch comparison and vendored h2 stream-store review",
    ),
    "CVE-2020-13934": (
        "not_applicable", "http2",
        "an h2c upgrade retained the superseded HTTP/1 processor for the life of the HTTP/2 connection",
        "Vapache does not support h2c prior-knowledge or HTTP/1 Upgrade to h2; HTTP/2 is entered only as a separate TLS ALPN protocol",
        "high", "Tomcat advisory and protocol negotiation inventory",
    ),
    "CVE-2020-13935": (
        "not_applicable", "websocket",
        "Tomcat's WebSocket frame parser accepted an invalid payload length and looped without consuming input",
        "Vapache is a byte-transparent WebSocket proxy after the handshake and does not parse, allocate from, or loop over WebSocket frame lengths",
        "high", "Tomcat advisory and WebSocket data-path review",
    ),
    "CVE-2020-17527": (
        "prevented", "request-lifecycle",
        "a recycled HTTP/2 header value retained bytes from the preceding stream",
        "each h2 request owns fresh HeaderMap/Headers storage, dispatch state is per-task, and no mutable request/header processor object is pooled across streams",
        "high", "Tomcat advisory and H2 request ownership review",
    ),
    "CVE-2021-25122": (
        "not_applicable", "http2",
        "h2c connection setup copied request header/body bytes into a second request context",
        "Vapache implements no h2c upgrade path; TLS HTTP/2 streams are independently owned and cannot inherit an HTTP/1 upgrade request",
        "high", "Tomcat advisory and protocol negotiation inventory",
    ),
    "CVE-2021-25329": (
        "not_applicable", "java-container",
        "a Tomcat session-persistence configuration still allowed attacker-selected serialized session loading",
        "Vapache has no servlet sessions, Java deserialization, persistent session store, or application class loading",
        "high", "Tomcat advisory lineage and application-container inventory",
    ),
    "CVE-2021-30639": (
        "not_applicable", "java-container",
        "a recycled servlet non-blocking Request object retained its prior I/O error flag",
        "Vapache has no servlet non-blocking I/O API or recycled Request processor; every request is a new owned value",
        "high", "Tomcat advisory and request lifecycle inventory",
    ),
    "CVE-2021-41079": (
        "prevented", "tls",
        "Tomcat's native OpenSSL connector looped on a malformed TLS packet without input progress",
        "Vapache uses Rustls rather than Tomcat NIO/OpenSSL, bounds the handshake to 20 seconds, and caps admitted connection workers",
        "high", "Tomcat advisory and TLS dependency/lifecycle review",
    ),
    "CVE-2021-42340": (
        "not_applicable", "java-container",
        "Tomcat's metrics object for upgraded connections was never detached after WebSocket close",
        "Vapache has no Tomcat upgrade metrics registry; WebSocket socket/task/lease state is stack-owned and released together on tunnel exit",
        "high", "Tomcat advisory and WebSocket lifecycle review",
    ),
    "CVE-2022-25762": (
        "not_applicable", "java-container",
        "concurrent servlet WebSocket send/close double-returned one processor object to a pool",
        "Vapache exposes no application WebSocket send API and pools no connection processor objects; its two copy directions own their state and terminate the tunnel together",
        "high", "Tomcat advisory and WebSocket architecture comparison",
    ),
    "CVE-2022-45143": (
        "not_applicable", "java-container",
        "JsonErrorReportValve interpolated attacker-controlled values into JSON without JSON escaping",
        "Vapache has no JSON error-report valve; generated error pages are HTML-context escaped and never claim to be JSON",
        "high", "Tomcat advisory and generated-error feature inventory",
    ),
    "CVE-2023-28709": (
        "not_applicable", "java-container",
        "query parameter count and multipart part count shared an off-by-one budget that let upload parts escape their limit",
        "Vapache does not parse application query parameters or multipart parts; bodies remain opaque under byte, time, spool and framing limits",
        "high", "Tomcat advisory and request-body feature inventory",
    ),
    "CVE-2024-24549": (
        "prevented", "http2",
        "an over-limit header block was fully processed before its stream was reset",
        "the vendored codec caps raw continuation frames/bytes and decoded abuse size during decode, before yielding a request, and the adapter applies a second strict head budget",
        "high", "Tomcat advisory and vendored h2 framed-read/header tests",
    ),
    "CVE-2024-34750": (
        "prevented", "http2",
        "exceptional oversized-header cleanup miscounted active streams and selected an infinite connection timeout",
        "h2 owns stream counts with RAII cleanup; Vapache's independent active/reset ledgers are idempotent, all stream tasks have a deadline, and the connection has an idle deadline",
        "high", "Tomcat advisory and H2 stream lifecycle/budget review",
    ),
    "CVE-2024-38286": (
        "prevented", "tls",
        "TLS handshakes could allocate attacker-controlled state without a connection or lifetime bound",
        "Vapache admits a connection under global/per-client worker limits before TLS, Rustls bounds handshake messages, and the complete handshake has a 20-second deadline",
        "high", "Tomcat advisory and TLS connection admission review",
    ),
    "CVE-2025-31650": (
        "not_applicable", "java-container",
        "Tomcat parsed invalid RFC Priority header semantics and failed to release the rejected request",
        "Vapache implements no HTTP Priority scheduler; Priority is an opaque bounded field and request/task storage is RAII-owned on every error path",
        "high", "Tomcat advisory and priority/request lifecycle review",
    ),
    "CVE-2025-48988": (
        "not_applicable", "java-container",
        "Tomcat FileUpload allocated per-part header state for an unbounded number of multipart parts",
        "Vapache has no multipart/FileUpload parser and retains only the opaque body under body, resident-memory, spool-file, spool-byte and lifetime limits",
        "high", "Tomcat advisory title/root cause and request-body feature inventory",
    ),
    "CVE-2025-48989": (
        "prevented", "http2",
        "invalid streams forced unbounded RST_STREAM generation and retained reset state (MadeYouReset)",
        "the h2 codec limits local error resets, locally retained resets and remote pending resets; Vapache additionally caps streams globally/per client and tracks reset reclamation idempotently",
        "high", "Tomcat advisory and vendored h2 reset limits/tests",
    ),
    "CVE-2025-49125": (
        "not_applicable", "java-container",
        "non-root PreResources/PostResources mounts exposed one resource through an alternate path lacking servlet constraints",
        "Vapache has no Java web-resource overlays; aliases and filesystem paths enter the same canonical authorization/request-plan pipeline and beneath-root open",
        "high", "Tomcat advisory and resource-mount feature inventory",
    ),
    "CVE-2025-52520": (
        "not_applicable", "java-container",
        "multipart size/count arithmetic overflowed and bypassed FileUpload limits",
        "Vapache has no multipart parser; opaque body and chunk lengths use checked/saturating u64/usize admission before allocation or spooling",
        "high", "Tomcat advisory and request-body arithmetic review",
    ),
    "CVE-2025-53506": (
        "prevented", "http2",
        "the server relied on acknowledgement of its reduced concurrent-stream setting before enforcing that limit",
        "h2 enforces the configured local max on received stream creation independently of peer acknowledgement, while Vapache also requires process-wide and per-client stream leases before spawning work",
        "high", "Tomcat advisory and h2 stream-admission implementation review",
    ),
    "CVE-2025-55752": (
        "prevented", "rewrite",
        "a rewritten path was normalized before percent-decoding, allowing encoded traversal to appear after the security check",
        "input is decoded and canonicalized before rewrite, substitutions are validated/escaped, and every internal rewrite re-enters canonical request planning and beneath-root filesystem resolution",
        "high", "Tomcat advisory and Vapache rewrite/path ordering tests",
    ),
    "CVE-2026-29129": (
        "prevented", "tls",
        "configured server cipher preference was discarded when constructing the TLS connector",
        "SSLHonorCipherOrder maps directly to Rustls ignore_client_order, is tested in the constructed ServerConfig, and inconsistent vhost settings on one listener are rejected",
        "high", "Tomcat advisory and Vapache TLS configuration tests",
    ),
    "CVE-2026-34483": (
        "not_applicable", "java-container",
        "JsonAccessLogValve emitted request-derived values without JSON-context escaping",
        "Vapache has no JSON access-log valve; its byte-oriented log formatter escapes all control and terminal bytes and does not advertise JSON syntax",
        "high", "Tomcat advisory and logging feature inventory",
    ),
    "CVE-2026-41284": (
        "not_applicable", "java-container",
        "WebDAV LOCK and PROPFIND handling read attacker-controlled structured bodies without a bound",
        "Vapache has no WebDAV method implementation or XML property parser; LOCK/PROPFIND fail closed and opaque bodies remain under global body/time/spool limits",
        "high", "Tomcat/Openwall advisory title and method feature inventory",
    ),
    "CVE-2026-42498": (
        "not_applicable", "java-container",
        "Tomcat's WebSocket authentication client forwarded an HTTP Authorization field after selecting a different host",
        "Vapache does not perform WebSocket authentication challenges, redirects, or cross-host retries; a configured fixed backend receives one reconstructed handshake",
        "high", "Tomcat advisory and WebSocket proxy lifecycle review",
    ),
    "CVE-2026-53404": (
        "prevented", "rewrite",
        "a true first RewriteCond in an OR chain skipped a later condition that began the next required AND group",
        "Vapache explicitly partitions RewriteCond sequences into OR groups joined by AND, evaluates every required group, and regression-tests false/true group boundaries",
        "high", "Tomcat advisory and rewrite condition evaluator/tests",
    ),
    "CVE-2026-55957": (
        "not_applicable", "java-container",
        "JNDIRealm GSSAPI bind authentication omitted password verification",
        "Vapache has no JNDI, LDAP realm, GSSAPI or SPNEGO provider; implemented Basic auth verifies an admitted htpasswd hash before creating identity",
        "high", "Tomcat advisory and authentication provider inventory",
    ),
    "CVE-2026-66422": (
        "not_applicable", "java-container",
        "servlet security-role-ref aliases were incorrectly promoted into global Realm authorization roles",
        "Vapache has no servlet role-ref or Realm role alias system; local user/group requirements have one explicit namespace",
        "high", "Tomcat advisory and authorization feature inventory",
    ),
    "CVE-2026-68569": (
        "not_applicable", "java-container",
        "CLIENT-CERT/SPNEGO identity was accepted even when no DataSourceRealm user existed",
        "Vapache has no DataSourceRealm or SPNEGO and does not combine client-certificate transport identity with an external user database lookup",
        "high", "Tomcat advisory and authentication provider inventory",
    ),
    "CVE-2026-68763": (
        "prevented", "http2",
        "reset streams leaked entries from HTTP/2 backlog tracking",
        "active and pending-reset IDs are removed through one RAII completion event and timed reclamation; the verified budget and h2 limits cap both sets even on cancellation or panic",
        "high", "Tomcat advisory and H2 reset ledger implementation/tests",
    ),
    "CVE-2017-9735": (
        "prevented", "auth",
        "password verification returned after the first unequal byte and exposed the matching prefix through timing",
        "SHA/SSHA and apr1/MD5-crypt verification now compare the complete fixed digest/hash representation with subtle::ConstantTimeEq; bcrypt uses its constant-time verifier",
        "high", "Jetty advisory and all Vapache password-verifier branches review",
    ),
    "CVE-2018-12545": (
        "prevented", "http2",
        "repeated SETTINGS changes caused per-frame allocation and CPU work without a control-frame rate limit",
        "the h2 codec retains only one pending setting/ACK, and the vendored connection now charges SETTINGS heavily to a slowly refilled control-frame token bucket before applying it",
        "high", "Jetty advisory plus vendored h2 control-frame budget and tests",
    ),
    "CVE-2021-28165": (
        "prevented", "tls",
        "an oversized invalid TLS record drove Jetty's incremental parser into sustained CPU work",
        "Rustls rejects records beyond its protocol bounds, the handshake has one 20-second deadline, and connection admission limits concurrent parser instances",
        "high", "Jetty advisory and Rustls/handshake containment review",
    ),
    "CVE-2022-2048": (
        "prevented", "http2",
        "invalid HTTP/2 request cleanup failed to release connection/stream resources",
        "the safe-Rust h2 state machine owns stream cleanup, Vapache wraps every task in an RAII completion guard, and active/pending-reset/process/per-client counts all have hard caps",
        "high", "Jetty advisory and H2 error lifecycle review",
    ),
    "CVE-2022-2191": (
        "prevented", "tls",
        "TLS error paths failed to return Java ByteBuffers to a configured pool",
        "Vapache uses Rustls-owned RAII buffers rather than Jetty's ByteBufferPool and bounds accepted TLS connections and handshake lifetime",
        "high", "Jetty advisory and TLS dependency/ownership comparison",
    ),
    "CVE-2024-13009": (
        "not_applicable", "extension-module",
        "a request-gzip inflate error double-released a pooled buffer that was later shared across requests",
        "Vapache does not decompress gzip request bodies and does not pool request buffers across request identities",
        "high", "Jetty advisory and compression/request lifecycle inventory",
    ),
    "CVE-2024-7708": (
        "prevented", "request-body",
        "a zero-byte/slow body read leaked its checked-out buffer, especially around 100-continue",
        "HTTP/1 body buffers are owned locals and zero from a blocking socket is terminal EOF; HTTP/2 body/spool/resident leases are RAII values and the complete body has one deadline",
        "high", "Jetty advisory and fixed/H2 body read error-path review",
    ),
    "CVE-2025-1948": (
        "prevented", "http2",
        "the peer's SETTINGS_MAX_HEADER_LIST_SIZE value was trusted as a response-encoding allocation size",
        "the h2 codec stores the peer setting as a scalar and Vapache generates already bounded response headers; no allocation is sized to the advertised u32 value",
        "high", "Jetty advisory and vendored h2 remote-settings/response encoder review",
    ),
    "CVE-2025-5115": (
        "prevented", "http2",
        "invalid short-lived streams forced unlimited RST_STREAM work and retained state",
        "the h2 codec limits local error resets, retained local resets and pending remote resets; Vapache also caps active streams and uses an idempotent timed reset ledger",
        "high", "Jetty advisory and vendored h2 reset limits/tests",
    ),
    "CVE-2026-1605": (
        "not_applicable", "extension-module",
        "a request gzip Inflater was released only by the response compression path and leaked when the response was uncompressed",
        "Vapache has no request decompression/Inflater allocation; response compression owns an independent bounded encoder per response",
        "high", "Jetty advisory and compression data-flow inventory",
    ),
    "CVE-2016-5396": (
        "prevented", "http2",
        "a small HPACK block expanded into unbounded decoded headers and compression-table work",
        "the h2 codec caps HPACK table size, compressed continuation frames/bytes and decoded header abuse; Vapache then applies independent field/count/resident budgets",
        "high", "Traffic Server HPACK-bomb advisory and vendored h2 decoder review",
    ),
    "CVE-2019-10079": (
        "prevented", "http2",
        "repeated SETTINGS frames caused unbounded control-frame acknowledgement and settings-application work",
        "the h2 codec holds only one pending SETTINGS/ACK and charges each received SETTINGS at sixteen tokens against a 256-token, two-token-per-second control-frame bucket",
        "high", "Traffic Server advisory and vendored h2 control-frame budget/tests",
    ),
    "CVE-2019-9511": (
        "prevented", "http2",
        "window and priority manipulation forced response queueing and scheduling in one-byte units",
        "Vapache ignores priority state, caps buffers/streams/response lifetime, and charges every priority or sub-1024-byte WINDOW_UPDATE against the slowly refilled control-frame bucket",
        "high", "HTTP/2 Network DoS advisory and vendored control-frame/send-budget tests",
    ),
    "CVE-2019-9512": (
        "prevented", "http2",
        "PING acknowledgements accumulated faster than they could be written",
        "the h2 codec retains at most one pending pong and flushes control output before reading another frame, so memory cannot grow with ping count",
        "high", "HTTP/2 Network DoS advisory and h2 ping_pong state review",
    ),
    "CVE-2019-9513": (
        "prevented", "http2",
        "priority updates repeatedly restructured an expensive dependency tree",
        "the vendored h2 server deliberately ignores PRIORITY frames and maintains no dependency tree to churn",
        "high", "HTTP/2 Network DoS advisory and h2 PRIORITY dispatch review",
    ),
    "CVE-2019-9514": (
        "prevented", "http2",
        "invalid streams forced unbounded RST_STREAM output and retained reset objects",
        "local error resets, retained local resets and pending remote resets are each capped; Vapache also caps stream tasks and reset-ledger entries",
        "high", "HTTP/2 Network DoS advisory and vendored h2 reset-limit tests",
    ),
    "CVE-2019-9515": (
        "prevented", "http2",
        "an endless SETTINGS stream forced one mandatory acknowledgement and settings update per small input frame",
        "only one ACK is pending at once, buffers are bounded, and SETTINGS consumes the control-frame token bucket sixteen times faster than it refills",
        "high", "HTTP/2 Network DoS advisory and vendored h2 token-bucket tests",
    ),
    "CVE-2019-9517": (
        "prevented", "http2",
        "a closed TCP receive window combined with an open HTTP/2 window caused unconstrained response buffering",
        "h2's per-stream send buffer is capped, response data is produced only after capacity, resident response bytes are globally leased, and sends have one deadline",
        "high", "HTTP/2 Network DoS advisory and streaming response implementation review",
    ),
    "CVE-2019-9518": (
        "prevented", "http2",
        "empty frames imposed parser/state work disproportionate to their wire size",
        "empty DATA and continuation/header abuse have hard limits; SETTINGS, PING, PRIORITY and tiny flow updates share a slowly refilled control-frame budget before state work",
        "high", "HTTP/2 Network DoS advisory and vendored frame-budget implementation/tests",
    ),
    "CVE-2020-9481": (
        "prevented", "http2",
        "a slow-reading client retained queued response data and stream state without an expiry",
        "send buffers and active streams are capped, file data is read after capacity, and each response/stream has an absolute write deadline",
        "high", "Traffic Server advisory and H2 slow-reader path review",
    ),
    "CVE-2020-9494": (
        "prevented", "http2",
        "crafted HEADERS/CONTINUATION input allocated excessive decoded state and spun while processing an over-limit block",
        "the h2 framed reader limits continuation count/raw bytes and decoded abuse during HPACK load, before yielding a request, with a second adapter head budget",
        "high", "Traffic Server advisory and vendored h2 header decoder review",
    ),
    "CVE-2021-32566": (
        "partial", "http2",
        "a specific malformed HTTP/2 frame sequence reached a crashing state transition",
        "Vapache uses a different safe-Rust state machine with strict frame/error handling, but the public advisory omits the sequence needed for an exact replay",
        "medium", "Traffic Server CNA title/description and dependency comparison",
    ),
    "CVE-2021-32567": (
        "partial", "http2",
        "one input event repeatedly re-entered HTTP/2 frame reading and consumed disproportionate CPU",
        "the vendored parser advances per decoded frame and Tokio yields at I/O boundaries, but the advisory omits the trigger and no generic frame-rate invariant proves equivalence",
        "medium", "Traffic Server CNA title and h2 frame-loop review",
    ),
    "CVE-2021-37147": (
        "prevented", "http-framing",
        "a bare-LF header line was accepted with a different message boundary than an adjacent parser",
        "HTTP/1 requires exact CRLF for the request line, every header and chunk delimiter; bare LF is rejected before dispatch and the connection closes",
        "high", "Traffic Server CNA title and verified request-head parser tests",
    ),
    "CVE-2021-37148": (
        "prevented", "http-framing",
        "Transfer-Encoding syntax/ordering was insufficiently validated and produced a different body boundary",
        "Vapache accepts only one syntactically valid coding list whose sole/final coding is chunked, rejects CL plus TE, and reconstructs proxy messages",
        "high", "Traffic Server CNA title and verified framing/chunk tests",
    ),
    "CVE-2021-37149": (
        "partial", "http-framing",
        "multiple header-parser differentials enabled request smuggling",
        "strict CRLF, field syntax, CL/TE and chunk rules cover the disclosed families, but the umbrella advisory does not identify every differential for exact replay",
        "medium", "Traffic Server CNA description and Vapache framing invariant comparison",
    ),
    "CVE-2021-37150": (
        "prevented", "http-parser",
        "the URL scheme could disagree with the protected/clear transport used for access policy",
        "absolute-form HTTP/1 and HTTP/2 :scheme must exactly match the actual TLS state, and authority/Host are reconciled before policy selection",
        "high", "Traffic Server CNA title and scheme/transport admission tests",
    ),
    "CVE-2021-41585": (
        "not_applicable", "platform",
        "a FreeBSD-specific accept/socket condition stopped the listener from accepting further connections",
        "Vapache's supported deployment target is Linux; it does not build or run the affected FreeBSD accept path",
        "high", "Traffic Server CNA title and Vapache platform contract",
    ),
    "CVE-2022-25763": (
        "partial", "http2",
        "insufficient HTTP/2 request-header validation enabled a framing or cache identity differential",
        "hop-by-hop fields, CL disagreement, pseudo-header authority/scheme and decoded budgets fail closed, but the umbrella advisory does not expose the exact field sequence",
        "medium", "Traffic Server CNA description and H2 adapter comparison",
    ),
    "CVE-2022-31779": (
        "prevented", "http2",
        "HTTP/2 scheme and method validation accepted a target under inconsistent semantics",
        "method is a bounded token, :scheme is exact lowercase http/https and transport-bound, CONNECT is rejected, and authority is mandatory and strictly parsed",
        "high", "Traffic Server CNA title and H2 head-admission proof/tests",
    ),
    "CVE-2022-31780": (
        "partial", "http2",
        "HTTP/2 frame handling exposed a cross-protocol framing differential",
        "Vapache never forwards H2 framing and reconstructs a strict HTTP/1 upstream request, but the public umbrella does not disclose the exact malformed frame sequence",
        "medium", "Traffic Server CNA title and downgrade boundary review",
    ),
    "CVE-2022-32749": (
        "not_applicable", "extension-module",
        "specific Traffic Server plugins crashed when exceptional request state reached their hooks",
        "Vapache has no Traffic Server plugin ABI or those request hooks",
        "high", "Traffic Server CNA title and extension inventory",
    ),
    "CVE-2022-47184": (
        "fail_closed", "protocol-other",
        "TRACE reflected proxy/network metadata to the requester",
        "TRACE is disabled by default and requires both TraceEnable and an explicit security capability; ordinary static-host configurations return 405",
        "high", "Traffic Server CNA title and Vapache TRACE capability gate",
    ),
    "CVE-2023-33933": (
        "not_applicable", "extension-module",
        "the optional s3_auth plugin calculated an authentication hash over the wrong request representation",
        "Vapache has no S3 authentication/signing plugin or AWS hash canonicalization path",
        "high", "Traffic Server CNA title and extension inventory",
    ),
    "CVE-2023-39456": (
        "partial", "http2",
        "a malformed HTTP/2 frame reached an abort rather than a protocol error",
        "the safe-Rust h2 parser rejects malformed public frame classes, but the advisory omits the exact bytes/state needed to prove the dependency path",
        "medium", "Traffic Server CNA title and h2 dependency boundary review",
    ),
    "CVE-2023-41752": (
        "not_applicable", "extension-module",
        "the optional s3_auth plugin calculated a request authentication hash incorrectly",
        "Vapache has no S3 authentication/signing plugin or AWS canonical request implementation",
        "high", "Traffic Server CNA title and extension inventory",
    ),
    "CVE-2024-35296": (
        "prevented", "cache",
        "invalid Accept-Encoding made the cache lookup fail open to origin forwarding",
        "Vapache never caches proxy routes, so an encoding variant miss cannot force an origin request; static variants are byte-keyed, capped per resource and fall back only to bounded local-file dispatch",
        "high", "Traffic Server CNA title and Vapache cache lookup/proxy exclusion review",
    ),
    "CVE-2024-38479": (
        "not_applicable", "extension-module",
        "the optional Traffic Server cache-key plugin admitted an attacker-controlled key collision",
        "Vapache has no cache-key plugin API; its internal cache key binds the canonical target, vhost, method and representation-policy inputs",
        "high", "Traffic Server CNA title and cache extension inventory",
    ),
    "CVE-2026-41920": (
        "prevented", "tls",
        "a configured SNI-to-Host matching policy was not enforced",
        "Vapache binds every HTTP/1 request and HTTP/2 stream to the SNI-selected certificate/client-auth policy and returns 421 on an incompatible transition; aliases with an identical TLS policy remain intentionally valid rather than requiring textual SNI/Host equality",
        "high", "Traffic Server CNA title and Vapache TLS/vhost policy review",
    ),
    "CVE-2026-58151": (
        "partial", "http2",
        "an umbrella of abusive HTTP/2 framing and flow-control paths could crash or exhaust the server",
        "Vapache has explicit header, frame-overhead, stream, reset, flow, resident-memory and deadline bounds, but the advisory groups undisclosed triggers that cannot all be replayed",
        "medium", "Traffic Server umbrella advisory and H2 budget inventory",
    ),
    "CVE-2026-58161": (
        "partial", "tls",
        "an umbrella of null/dangling-reference failures in TLS and SNI handling crashed Traffic Server",
        "safe Rust and Rustls remove the disclosed native lifetime primitives, but the advisory does not identify each state transition and a semantic panic-equivalent cannot be ruled out",
        "medium", "Traffic Server umbrella advisory and TLS architecture comparison",
    ),
    "CVE-2026-58163": (
        "not_applicable", "cache",
        "deserialization of Traffic Server's persistent on-disk cache combined invalid fields with unsafe object lifetimes",
        "Vapache has no persistent serialized cache format or cache-object deserializer; cached responses are process-local typed values",
        "high", "Traffic Server CNA title and cache storage inventory",
    ),
    "CVE-2026-59173": (
        "prevented", "http2",
        "stalled HTTP/2 flow control retained response work/resources indefinitely",
        "stream and send buffers are capped, response bytes are generated only after capacity, and both send-capacity waits and the enclosing stream have absolute deadlines",
        "high", "Traffic Server/Openwall advisory title and H2 send deadline tests",
    ),
    "CVE-2021-3618": (
        "not_applicable", "tls",
        "a network attacker redirected TLS traffic between different application protocols covered by the same certificate",
        "Vapache TLS listeners negotiate only enabled HTTP/1.1 or HTTP/2 by exact ALPN and expose no SMTP, FTP, POP, IMAP or other cross-protocol command interpreter",
        "high", "ALPACA paper/advisory and Vapache ALPN/protocol inventory",
    ),
    "CVE-2023-40518": (
        "prevented", "http-parser",
        "permissive request-header validation admitted syntax with ambiguous downstream semantics",
        "HTTP/1 parsing is verified strict on CRLF, field names, whitespace, controls, counts and CL/TE; HTTP/2 separately rejects uppercase and hop-by-hop fields before dispatch",
        "high", "OpenLiteSpeed 1.7.18 release note and Vapache parser invariant review",
    ),
    "CVE-2021-26442": (
        "not_applicable", "platform",
        "an undisclosed Windows HTTP.sys kernel-mode flaw allowed network-triggered privilege elevation",
        "Vapache is a Linux userspace process, shares no HTTP.sys code or kernel request-queue object, and drops to the configured service identity before serving",
        "medium", "Microsoft/NVD scope statement; technical root cause not publicly disclosed",
    ),
    "CVE-2022-41057": (
        "not_applicable", "platform",
        "an undisclosed Windows HTTP.sys kernel-mode flaw allowed network-triggered privilege elevation",
        "Vapache is a Linux userspace process with no HTTP.sys driver/request queue and no corresponding kernel privilege transition",
        "medium", "Microsoft/NVD scope statement; technical root cause not publicly disclosed",
    ),
    "CVE-2023-23410": (
        "not_applicable", "platform",
        "an undisclosed Windows HTTP.sys kernel-mode flaw allowed network-triggered privilege elevation",
        "Vapache is a Linux userspace process with no HTTP.sys driver/request queue and no corresponding kernel privilege transition",
        "medium", "Microsoft/NVD scope statement; technical root cause not publicly disclosed",
    ),
    "CVE-2026-20929": (
        "not_applicable", "platform",
        "HTTP.sys access control allowed an already authorized network attacker to cross a Windows privilege boundary",
        "Vapache has no Windows HTTP.sys identity/ACL boundary; it runs as one dropped Linux service identity and shares no affected authorization component",
        "medium", "Microsoft CNA description; further technical details not publicly disclosed",
    ),
    "CVE-2018-16843": (
        "prevented", "http2",
        "unread SETTINGS/PING acknowledgements caused one newly allocated outbound control-frame object per received frame",
        "h2 retains only one pending pong/SETTINGS acknowledgement, flushes it before reading another frame, and the added control-frame token bucket terminates sustained floods",
        "high", "nginx 8ec4146 patch comparison and vendored h2 control-output/budget review",
    ),
    "CVE-2018-16844": (
        "prevented", "http2",
        "repeated active-to-idle transitions freed and recreated nginx connection pool caches, amplifying CPU work",
        "Vapache/h2 maintains one owned connection state across idle/active transitions rather than destroy/recreate a native memory pool, and the connection idle timer bounds inactive lifetime",
        "high", "nginx 60b9359 patch comparison and Vapache h2 connection lifecycle review",
    ),
    "CVE-2001-1186": (
        "prevented", "request-body",
        "an incomplete fixed-length body retained a connection indefinitely",
        "Vapache gives the complete body one absolute deadline, treats EOF before the declared length as an error, and closes a connection after any request-read failure",
        "high", "Microsoft advisory description and fixed-body connection lifecycle review",
    ),
    "CVE-2005-2089": (
        "prevented", "http-framing",
        "Transfer-Encoding and Content-Length selected different request boundaries across hops",
        "the verified request parser rejects every CL-plus-TE message before reading a body or selecting a proxy route",
        "high", "Microsoft advisory description and verified request-framing review",
    ),
    "CVE-2014-0099": (
        "prevented", "http-framing",
        "Content-Length integer overflow changed the body boundary seen by a downstream component",
        "Content-Length uses checked u64 decimal parsing, must agree across duplicates, is capped before allocation, and is reserialized from the actual decoded body length",
        "high", "Tomcat advisory and verified Content-Length arithmetic review",
    ),
    "CVE-2014-0227": (
        "prevented", "http-framing",
        "a chunk-decoder error left the connection parser consuming attacker bytes as another request",
        "any malformed chunk size, extension, delimiter or trailer aborts read_request; the connection loop sends one error and disables keep-alive rather than resuming request parsing",
        "high", "Tomcat advisory and chunk-error connection lifecycle review",
    ),
    "CVE-2015-0881": (
        "prevented", "response-header",
        "untrusted upstream response bytes introduced a second CRLF-delimited header",
        "proxy and gateway response parsers require exact CRLF and valid field syntax, while the final serializer rejects controls in every response header value",
        "high", "Squid advisory and proxy/final response-header gate review",
    ),
    "CVE-2019-17569": (
        "prevented", "http-framing",
        "an invalid Transfer-Encoding list was nevertheless treated as a valid body framing instruction",
        "Vapache accepts only one exact, final chunked transfer coding on HTTP/1.1 and rejects empty, duplicate, prefixed, suffixed or additional codings",
        "high", "Tomcat advisory and Transfer-Encoding parser tests",
    ),
    "CVE-2019-18678": (
        "prevented", "http-framing",
        "whitespace before a header colon created different field-name interpretations across hops",
        "HTTP/1 request and proxy-response parsing require a non-empty token immediately followed by colon; whitespace before the colon is rejected",
        "high", "Squid advisory and strict field-line parser review",
    ),
    "CVE-2019-20372": (
        "prevented", "http-framing",
        "an external error_page redirect reused a connection without first consuming the request body",
        "Vapache consumes and validates the complete request body before dispatch can select any ErrorDocument or redirect, so no unread body bytes can become a next request",
        "high", "nginx c1be55f patch comparison and Vapache read-before-dispatch architecture review",
    ),
    "CVE-2020-15810": (
        "prevented", "http-framing",
        "a whitespace-prefixed Content-Length was ignored locally but forwarded as a field upstream",
        "Vapache rejects whitespace before every field-name colon and reconstructs upstream requests from parsed fields and the actual body length",
        "high", "Squid advisory and HTTP/1/proxy serialization review",
    ),
    "CVE-2020-15811": (
        "prevented", "http-framing",
        "a substring search mistook an invalid Transfer-Encoding value for chunked framing",
        "the verified parser tokenizes the full transfer-coding list and permits only one exact final chunked token",
        "high", "Squid advisory and verified Transfer-Encoding parser review",
    ),
    "CVE-2020-1935": (
        "prevented", "http-framing",
        "permissive line-ending parsing admitted malformed headers with a different intermediary interpretation",
        "request heads require exact CRLF line endings, reject bare CR/LF and obs-fold, and are reconstructed rather than forwarded verbatim",
        "high", "Tomcat advisory and strict request-head parser review",
    ),
    "CVE-2021-33037": (
        "prevented", "http-framing",
        "Transfer-Encoding validation depended on response version and accepted identity or non-final chunked codings",
        "HTTP/1.0 transfer coding always fails; HTTP/1.1 accepts only one exact chunked coding in final position and rejects CL coexistence",
        "high", "Tomcat advisory and verified framing decision review",
    ),
    "CVE-2021-36740": (
        "prevented", "http2",
        "an oversized HTTP/2 Content-Length wrapped or disagreed with received DATA while authorization still proceeded",
        "Vapache parses H2 Content-Length as checked u64, caps decoded body bytes before dispatch, and requires the declared length to equal the received stream length",
        "high", "Varnish advisory and H2 declared-length/body admission review",
    ),
    "CVE-2023-27491": (
        "prevented", "http-parser",
        "a malformed HTTP/1 request line could be normalized into a different upstream request target",
        "the verified request-line parser requires exactly three non-empty components separated by two single SP delimiters and validates the method and target before reconstruction",
        "high", "Envoy advisory and verified request-line/proxy gate review",
    ),
    "CVE-2024-23326": (
        "prevented", "websocket",
        "a 200 response carrying Upgrade metadata was mistaken for a completed protocol switch",
        "ordinary proxying never enters tunnel mode and strips hop-by-hop response fields; the separate WebSocket path requires exact 101, Upgrade, Connection and Sec-WebSocket-Accept validation, rejects CL/TE, and reconstructs the switching head",
        "high", "Envoy advisory and split ordinary/WebSocket proxy response paths",
    ),
    "CVE-2024-31617": (
        "prevented", "http-framing",
        "a Transfer-Encoding value with a chunked prefix or duplicate field was treated as chunked",
        "Vapache requires one exact chunked coding, rejects duplicate/combined invalid lists and CL coexistence, and independently bounds chunk framing",
        "high", "OpenLiteSpeed 1.8.0-to-1.8.1 patch comparison and verified framing tests",
    ),
    "CVE-2025-12642": (
        "prevented", "http-framing",
        "request trailers were merged into the already-authorized header map",
        "trailers are disabled by default; when explicitly enabled they are syntax-checked, forbidden framing/routing names are rejected, budgets apply, and values are discarded rather than merged into request headers",
        "high", "lighttpd patch description and Vapache trailer parser/tests",
    ),
    "CVE-2025-30346": (
        "prevented", "http-framing",
        "a duplicate Host or Content-Length error kept the connection alive with its unread body becoming a later request",
        "duplicate Host and every duplicate or malformed Content-Length fail during head parsing, and every read error forces connection close before buffered bytes can be parsed again",
        "high", "VSV00015 advisory and request-error connection lifecycle review",
    ),
    "CVE-2026-58153": (
        "not_applicable", "http2",
        "HTTP/2 origin trailers were serialized to an HTTP/1 client without chunk framing",
        "Vapache has no HTTP/2 upstream/origin client and never translates an H2 origin response to H1; its H1 upstream trailers are validated and discarded",
        "high", "Traffic Server advisory and Vapache upstream protocol inventory",
    ),
    "CVE-2019-9516": (
        "prevented", "http2",
        "zero-length header names and values consumed retained allocation without consuming the configured header-list budget",
        "the vendored HPACK decoder charges the RFC 7540 32-byte per-field overhead, bounds raw CONTINUATION bytes and decoded list size, and Vapache separately limits field count and resident copies",
        "high", "HTTP/2 Network DoS advisory and vendored HPACK header-size accounting review",
    ),
    "CVE-2020-11767": (
        "not_applicable", "http2",
        "a shared forward proxy reused one coalesced HTTP/2 origin connection for a different hostname without issuing 421",
        "Vapache is not a forward proxy, opens a fresh HTTP/1 connection for every reverse-proxy request, and has no coalesced H2 upstream pool",
        "high", "Envoy advisory and Vapache upstream connection/protocol inventory",
    ),
    "CVE-2020-13943": (
        "prevented", "http2",
        "a refused over-limit stream reused pseudo-header state from a previous request",
        "each accepted h2 stream yields a fresh owned Request/HeaderMap task, refused streams never enter dispatch, and no mutable header processor is pooled across streams",
        "high", "Tomcat advisory and H2 request ownership/stream admission review",
    ),
    "CVE-2021-32778": (
        "prevented", "http2",
        "resetting many concurrent streams performed quadratic work over the active stream set",
        "Vapache advertises at most 32 concurrent streams, caps retained local/remote reset state, uses sparse keyed stream storage, and closes a connection when its verified reset budget is exhausted",
        "high", "Envoy advisory and vendored h2/Vapache reset accounting review",
    ),
    "CVE-2024-30255": (
        "prevented", "http2",
        "the parser continued consuming unlimited CONTINUATION frames after the header list was already over limit",
        "the vendored framed reader caps CONTINUATION count and raw accumulated bytes, aborts the connection with ENHANCE_YOUR_CALM, and does so before yielding a request",
        "high", "Envoy advisory and vendored framed_read continuation-limit review",
    ),
    "CVE-2026-42926": (
        "not_applicable", "http2",
        "request-body bytes controlled an HTTP/2 frame stream sent to an upstream peer",
        "Vapache has no HTTP/2 upstream client: every reverse-proxy request is rebuilt as bounded HTTP/1.1 with a computed Content-Length",
        "high", "nginx advisory and Vapache upstream protocol/serialization review",
    ),
    "CVE-2026-58152": (
        "prevented", "http2",
        "overflowing HPACK integers corrupted native decoder memory",
        "the safe-Rust HPACK decoder limits an integer to five octets, uses bounded usize arithmetic and returns a typed decoder error; decoded/raw header budgets independently cap the enclosing block",
        "high", "Traffic Server advisory and vendored h2 HPACK integer decoder review",
    ),
    "CVE-2026-65100": (
        "prevented", "http2",
        "an HPACK encode failure mutated the dynamic table before a header block was committed",
        "the vendored encoder's admitted HeaderMap-to-HPACK operation is infallible and writes into an owned scratch block; it has no recoverable mid-encode failure path that could retain a partially committed peer-visible table state",
        "high", "Traffic Server advisory and vendored h2 HPACK encoder control-flow review",
    ),
    "CVE-2014-3616": (
        "prevented", "tls",
        "TLS session resumption crossed virtual hosts that had different security contexts",
        "Vapache refuses startup when virtual hosts on one listener differ in client-certificate, protocol, cipher-preference or resumption policy; Rustls binds resumed sessions to one ServerConfig",
        "high", "nginx advisory and listener-wide TLS policy validation review",
    ),
    "CVE-2025-23419": (
        "prevented", "tls",
        "session resumption selected a virtual host whose client-certificate policy differed from the handshake's default host",
        "all vhosts on a TLS listener must have an identical SSLVerifyClient mode and CA file or Vapache refuses startup, so resumption cannot cross into a weaker client-auth policy",
        "high", "nginx advisory and uniform client-policy startup check/tests",
    ),
    "CVE-2026-28755": (
        "fail_closed", "unimplemented",
        "a failed client-certificate OCSP revocation result did not abort the handshake",
        "Vapache does not claim client-certificate OCSP checking; SSLOCSP* is a security-sensitive unsupported directive and configuration requesting it is rejected at startup",
        "high", "nginx advisory and security-directive disposition review",
    ),
    "CVE-2020-15104": (
        "prevented", "tls",
        "a wildcard DNS SAN matched more than one label in the configured upstream hostname",
        "HTTPS/WSS upstreams pass a typed ServerName to Rustls/webpki, whose DNS identity verifier applies RFC wildcard label rules rather than a custom suffix matcher",
        "high", "Envoy advisory and Rustls/webpki upstream verifier review",
    ),
    "CVE-2022-21657": (
        "prevented", "tls",
        "certificate validation accepted a chain without the TLS serverAuth/clientAuth extended key usage",
        "Rustls/webpki verifies HTTPS/WSS peers for serverAuth and Vapache does not install a dangerous custom verifier; inbound client certificates use WebPkiClientVerifier",
        "high", "Envoy advisory and Rustls server/client certificate verifier construction review",
    ),
    "CVE-2026-47778": (
        "prevented", "tls",
        "a C-string conversion truncated an embedded NUL in a DNS SAN before hostname comparison",
        "Rustls/webpki parses length-delimited certificate names and the Vapache upstream path contains no C-string conversion or custom SAN matcher",
        "high", "Envoy advisory and Rustls/webpki upstream verifier boundary review",
    ),
    "CVE-2026-65325": (
        "not_applicable", "http2",
        "a multiplexed HTTP/2 origin connection was reused for a hostname not covered by its certificate",
        "Vapache has no HTTP/2 upstream support or upstream connection pool and performs a fresh typed-hostname TLS handshake for every HTTPS reverse-proxy request",
        "high", "Traffic Server advisory and upstream protocol/connection lifecycle review",
    ),
    "CVE-2026-58157": (
        "prevented", "proxy",
        "a server session or tunnel was reused across unrelated client connections",
        "ordinary reverse-proxy connections are never pooled, and every WebSocket tunnel owns a new dedicated upstream connection whose lifetime is scoped to one admitted client request",
        "high", "Traffic Server advisory and proxy connection ownership review",
    ),
    "CVE-2025-64763": (
        "fail_closed", "unimplemented",
        "early CONNECT payload was forwarded before an upstream 2xx established the tunnel",
        "Vapache implements neither forward-proxy nor CONNECT tunneling; CONNECT receives no proxy tunnel path and cannot forward early data",
        "high", "Envoy advisory and method/proxy feature inventory",
    ),
    "CVE-2022-23606": (
        "not_applicable", "admin-control-plane",
        "deleting a dynamic CDS cluster recursively disconnected a large idle upstream pool",
        "Vapache has no xDS/CDS control plane, dynamic cluster deletion, or idle upstream connection pool",
        "high", "Envoy advisory and configuration/upstream lifecycle inventory",
    ),
    "CVE-2024-53269": (
        "not_applicable", "proxy",
        "a Happy Eyeballs address sorter assumed every additional address was an IP address",
        "Vapache has no Happy Eyeballs/additional-address configuration and accepts only parsed SocketAddr values from its bounded resolver worker",
        "high", "Envoy advisory and upstream address-resolution implementation review",
    ),
    "CVE-2025-30157": (
        "not_applicable", "extension-module",
        "an ext_proc filter callback outlived a failed WebSocket handshake and dereferenced stale state",
        "Vapache has no external-processing filter; its WebSocket handshake state is owned by one async task and failures return before tunnel mode",
        "high", "Envoy advisory and filter/WebSocket feature inventory",
    ),
    "CVE-2026-66299": (
        "not_applicable", "java-container",
        "Tomcat's bundled WebSocket chat example retained attacker-controlled resources without a bound",
        "Vapache ships no web application, chat example, servlet container or WebSocket message handler; it only byte-forwards an explicitly configured tunnel",
        "high", "Tomcat advisory and packaged application inventory",
    ),
    "CVE-2020-27218": (
        "not_applicable", "compression",
        "unconsumed decompressed request-body state leaked into a later multiplexed request",
        "Vapache does not decompress request bodies and owns each decoded HTTP/1 or HTTP/2 body in fresh per-request storage",
        "high", "Jetty advisory and request compression/lifecycle inventory",
    ),
    "CVE-2022-40743": (
        "not_applicable", "extension-module",
        "the Traffic Server xdebug plugin emitted untrusted data into HTML and a cache identity",
        "Vapache has no xdebug plugin or equivalent diagnostic-header cache extension, and proxy routes are never entered into its static response cache",
        "high", "Traffic Server advisory and plugin/cache feature inventory",
    ),
    "CVE-2019-9901": (
        "prevented", "path",
        "path authorization ran before dot-segment normalization used by the backend",
        "one percent-decoded, dot-normalized RequestPlan identity is shared by authorization, rewrite, routing, cache and proxy selection before any sink runs",
        "high", "Envoy advisory and canonical RequestPlan data-flow review",
    ),
    "CVE-2026-73511": (
        "prevented", "proxy",
        "semicolon matrix parameters made proxy policy and a servlet backend resolve different path identities",
        "Vapache now rejects any semicolon-bearing reverse-proxy or WebSocket target before connection, including percent-decoded client paths, rather than guessing an upstream's parameter semantics",
        "high", "Envoy advisory and proxy path-identity gate/tests",
    ),
    "CVE-2026-73551": (
        "prevented", "path",
        "a dot segment carrying semicolon parameters survived intermediary normalization but was collapsed by the backend",
        "static serving treats such a segment as a literal name under openat2 containment, while every reverse-proxy path containing a semicolon now fails closed before forwarding",
        "high", "Envoy advisory and canonical/static/proxy path comparison",
    ),
    "CVE-2026-8384": (
        "prevented", "path",
        "semicolon path parameters made an application receive an unresolved identity different from its policy path",
        "Vapache static dispatch opens only the literal normalized path beneath its root and rejects semicolon-bearing reverse-proxy/WebSocket targets before an application can reinterpret them",
        "high", "Jetty advisory and static/proxy path identity review",
    ),
    "CVE-2000-0071": (
        "prevented", "error-page",
        "an extension-specific error response disclosed the physical document-root pathname",
        "Vapache has no IDA/IDQ handler and all not-found/error bodies omit filesystem paths and stack traces",
        "high", "Microsoft advisory and generated error-page review",
    ),
    "CVE-2006-5858": (
        "not_applicable", "extension-module",
        "a double-decoded NUL crossed the ColdFusion/JRun filename boundary",
        "Vapache has no ColdFusion or JRun handler; percent decoding rejects NUL and double decoding never occurs",
        "high", "NVD description and handler/decoder inventory",
    ),
    "CVE-2007-0450": (
        "prevented", "path",
        "proxy and backend disagreed whether slash, backslash and encoded backslash were path separators",
        "literal backslash is rejected during canonicalization, encoded separators fail closed by default, and proxy output re-encodes delimiter bytes from the shared authorization identity",
        "high", "Tomcat advisory and canonical proxy-path review",
    ),
    "CVE-2007-5342": (
        "not_applicable", "java-container",
        "a Java security policy granted deployed applications permission to reconfigure logging files",
        "Vapache has no Java policy, deployed application classloader or application-controlled logging configuration",
        "high", "Tomcat advisory and runtime feature inventory",
    ),
    "CVE-2007-5461": (
        "not_applicable", "java-container",
        "WebDAV XML entity resolution read an attacker-selected filesystem path",
        "Vapache implements neither WebDAV writes nor XML entity parsing",
        "high", "Tomcat advisory and method/parser inventory",
    ),
    "CVE-2008-1270": (
        "not_applicable", "extension-module",
        "mod_userdir defaulted an unset user directory to an account home directory",
        "Vapache does not implement mod_userdir or tilde-to-home expansion",
        "high", "lighttpd advisory and URL mapping inventory",
    ),
    "CVE-2008-2370": (
        "not_applicable", "java-container",
        "a servlet RequestDispatcher normalized a URI before separating its query string",
        "Vapache has no RequestDispatcher; the HTTP adapter separates query bytes before one canonical path plan is constructed",
        "high", "Tomcat advisory and request-target split review",
    ),
    "CVE-2008-2938": (
        "prevented", "path",
        "encoded traversal crossed a linked-resource mapping after inconsistent UTF-8 decoding",
        "percent decoding is single-pass and byte exact, invalid/overlong UTF-8 and encoded separators fail closed, dot segments normalize, and openat2 contains the final open",
        "high", "Tomcat advisory and decode-to-open path review",
    ),
    "CVE-2008-5515": (
        "not_applicable", "java-container",
        "servlet RequestDispatcher normalized dot segments before removing query data and applying WEB-INF policy",
        "Vapache has no RequestDispatcher or WEB-INF namespace and separates queries before canonicalization",
        "high", "Tomcat advisory and request dispatcher inventory",
    ),
    "CVE-2009-1523": (
        "prevented", "path",
        "dot-segment traversal escaped the static document root",
        "the verified normalizer eliminates dot segments and the descriptor-relative open uses RESOLVE_BENEATH/NO_MAGICLINKS containment",
        "high", "Jetty advisory and verified normalization/openat2 review",
    ),
    "CVE-2009-2902": (
        "not_applicable", "java-container",
        "a crafted WAR deployment filename deleted a work-directory file",
        "Vapache has no WAR deployment manager, application work directory or remote deployment operation",
        "high", "Tomcat advisory and deployment feature inventory",
    ),
    "CVE-2009-3898": (
        "not_applicable", "extension-module",
        "WebDAV COPY/MOVE accepted traversal in the Destination header",
        "Vapache implements no WebDAV COPY or MOVE handler and does not map Destination into a filesystem write",
        "high", "nginx advisory and method/handler inventory",
    ),
    "CVE-2010-2263": (
        "not_applicable", "platform",
        "the Windows NTFS ::$DATA alternate stream suffix exposed unparsed file bytes",
        "Vapache targets Linux and performs no NTFS alternate-data-stream lookup",
        "high", "nginx advisory and platform boundary",
    ),
    "CVE-2014-0119": (
        "not_applicable", "java-container",
        "an application-selected Java XML/XSLT classloader enabled external-entity file reads across applications",
        "Vapache has no servlet classloader, XSLT engine or application XML parser",
        "high", "Tomcat advisory and application runtime inventory",
    ),
    "CVE-2015-5345": (
        "prevented", "path",
        "directory slash redirects ran before the resource's security constraints and leaked existence",
        "Vapache evaluates URL, directory, files and access-file authorization before resolving a directory action or emitting its slash redirect",
        "high", "Tomcat advisory and directory dispatch ordering review",
    ),
    "CVE-2021-28163": (
        "not_applicable", "java-container",
        "a symlinked webapps deployment directory was itself auto-deployed as static content",
        "Vapache has no webapps auto-deployer; static symlinks remain subject to configured Options, actual-target reauthorization and beneath-root opening",
        "high", "Jetty advisory and deployment/static mapping inventory",
    ),
    "CVE-2000-0649": (
        "prevented", "auth",
        "the server's internal IP address was substituted for a missing Basic authentication realm",
        "Vapache uses the literal configured AuthName or the fixed string Restricted and never derives a realm from a local address",
        "high", "Microsoft advisory and WWW-Authenticate construction review",
    ),
    "CVE-2002-0419": (
        "prevented", "auth",
        "authentication challenges disclosed the server IP, NetBIOS name or Windows domain",
        "Vapache supports only Basic challenges with configured/fixed realm text and has no NTLM, NetBIOS or Windows-domain identity",
        "high", "Microsoft advisory and authentication feature/header review",
    ),
    "CVE-2009-0580": (
        "not_applicable", "java-container",
        "FORM authentication error differences exposed realm-backed usernames",
        "Vapache has no FORM authentication, j_security_check or Java Realm providers",
        "high", "Tomcat advisory and authentication provider inventory",
    ),
    "CVE-2009-2901": (
        "not_applicable", "java-container",
        "failed servlet application undeployment left files that auto-deployment served under a different policy",
        "Vapache has no application deployer, undeployer or appBase directory",
        "high", "Tomcat advisory and deployment inventory",
    ),
    "CVE-2012-3546": (
        "not_applicable", "java-container",
        "FORM authentication reused a prior Java principal for a crafted j_security_check path",
        "Vapache has neither FORM authentication nor a reusable servlet principal/request object",
        "high", "Tomcat advisory and authentication/request lifecycle inventory",
    ),
    "CVE-2018-11469": (
        "prevented", "cache",
        "responses to requests carrying Authorization were admitted to a shared cache",
        "Vapache's cache-store and cache-lookup gates reject authenticated/Authorization requests and include the effective policy fingerprint in every key",
        "high", "HAProxy advisory and cache admission review",
    ),
    "CVE-2018-1304": (
        "not_applicable", "java-container",
        "the empty servlet URL-pattern failed to apply a web.xml security constraint",
        "Vapache has no servlet URL-pattern or web.xml constraint evaluator; root Location/Directory scopes use explicit canonical prefix matching",
        "high", "Tomcat advisory and authorization model inventory",
    ),
    "CVE-2020-8664": (
        "not_applicable", "admin-control-plane",
        "an xDS combined validation context omitted its static certificate-validation component",
        "Vapache has no SDS/xDS dynamic secret or combined validation context",
        "high", "Envoy advisory and TLS configuration inventory",
    ),
    "CVE-2021-34429": (
        "prevented", "path",
        "encoded URI characters made servlet security constraints and WEB-INF lookup use different paths",
        "Vapache single-pass decodes into one canonical policy/mapping identity and has no separately interpreted WEB-INF namespace",
        "high", "Jetty advisory and canonical RequestPlan review",
    ),
    "CVE-2022-34305": (
        "not_applicable", "java-container",
        "Tomcat's example FORM-authentication page reflected user input without HTML escaping",
        "Vapache ships no example web application or FORM login page; generated HTML passes reflected text through html_escape",
        "high", "Tomcat advisory and packaged/generated-content inventory",
    ),
    "CVE-2023-41080": (
        "not_applicable", "java-container",
        "Tomcat's default ROOT application FORM-auth flow accepted an untrusted redirect target",
        "Vapache has no ROOT webapp, FORM authentication or saved-request redirect mechanism",
        "high", "Tomcat advisory and application/authentication inventory",
    ),
    "CVE-2025-64527": (
        "not_applicable", "extension-module",
        "a re-entrant remote-JWKS callback cleared the state of a second JWT fetch",
        "Vapache has no JWT filter, JWKS fetcher or async authentication callback reuse",
        "high", "Envoy advisory and authentication filter inventory",
    ),
    "CVE-2026-34500": (
        "prevented", "tls",
        "a native FFM client-certificate connector soft-failed when certificate authentication should reject",
        "Vapache uses Rustls WebPkiClientVerifier, has no FFM/native connector, and refuses mixed client-auth policies on one listener",
        "high", "Tomcat advisory and inbound client-certificate verifier review",
    ),
    "CVE-2026-55955": (
        "not_applicable", "java-container",
        "a cluster EncryptionInterceptor accepted replayed authentication material",
        "Vapache has no servlet cluster, replication interceptor or shared cluster authentication protocol",
        "high", "Tomcat advisory and clustering feature inventory",
    ),
    "CVE-2002-1908": (
        "prevented", "http-parser",
        "many slash characters in Host triggered superlinear or unsafe authority processing",
        "Host is bounded by the request-field limit and the single-pass authority parser rejects slash on the first invalid byte",
        "high", "Microsoft advisory and authority parser review",
    ),
    "CVE-2012-2213": (
        "fail_closed", "forward-proxy",
        "CONNECT authorization trusted a Host field different from the tunnel authority",
        "Vapache has no forward-proxy CONNECT tunnel and cannot route one from Host",
        "high", "Squid advisory and proxy method inventory",
    ),
    "CVE-2013-4123": (
        "prevented", "http-parser",
        "a malformed or overflowing Host port reached an unsafe parser state",
        "the authority parser accepts only bounded decimal u16 ports with checked arithmetic and rejects empty, extra or malformed delimiters",
        "high", "Squid advisory and strict authority parser/tests",
    ),
    "CVE-2014-2324": (
        "prevented", "http-parser",
        "dot segments in Host were interpolated into a filesystem virtual-host root",
        "Host is parsed as an authority and used only to select statically configured vhosts; it is never concatenated into a filesystem path",
        "high", "lighttpd advisory and vhost mapping review",
    ),
    "CVE-2019-18677": (
        "not_applicable", "forward-proxy",
        "append_domain rewrote an over-limit forward-proxy origin hostname to a different destination",
        "Vapache has no append_domain behavior or forward-proxy origin selection",
        "high", "Squid advisory and hostname routing inventory",
    ),
    "CVE-2021-39241": (
        "prevented", "http-parser",
        "a space inside an apparent method caused adjacent components to select different request targets",
        "the verified request line permits exactly two delimiter spaces and validates the method as a non-empty token, so the crafted extra components fail closed",
        "high", "HAProxy advisory and verified request-line parser review",
    ),
    "CVE-2022-2047": (
        "prevented", "http-parser",
        "an invalid absolute-URI authority was accepted as a hostname in proxy routing",
        "absolute-form is disabled by default; when enabled, the strict shared authority parser rejects userinfo, fragments, invalid brackets/ports and reconciles the exact endpoint with Host and transport scheme",
        "high", "Jetty advisory and absolute-form authority reconciliation review",
    ),
    "CVE-2026-58156": (
        "prevented", "http-parser",
        "userinfo and malformed port syntax made URL authorization and routing use different endpoints",
        "Vapache's shared authority parser rejects userinfo and malformed ports and its verified endpoint comparison binds host, effective port and TLS scheme before policy selection",
        "high", "Traffic Server advisory and strict authority/endpoint comparison review",
    ),
    "CVE-2015-5400": (
        "fail_closed", "forward-proxy",
        "a CONNECT peer response bypassed restrictions on a chained backend proxy",
        "Vapache implements no CONNECT tunnel, cache_peer or chained forward-proxy response path",
        "high", "Squid advisory and proxy feature inventory",
    ),
    "CVE-2022-29224": (
        "not_applicable", "extension-module",
        "a gRPC health-check callback dereferenced a host removed by dynamic service discovery",
        "Vapache has no gRPC health checker, EDS service discovery or dynamically held upstream host objects",
        "high", "Envoy advisory and health-check/control-plane inventory",
    ),
    "CVE-2023-45648": (
        "prevented", "http-framing",
        "invalid request trailers changed the next HTTP/1 request boundary",
        "trailers are disabled by default; enabled trailers require strict field syntax, forbid framing/routing names, are bounded and discarded, and any parse error closes the connection",
        "high", "Tomcat advisory and trailer parser/error lifecycle tests",
    ),
    "CVE-2025-62409": (
        "not_applicable", "proxy",
        "a closing pooled TCP connection retained a buffer-watermark callback while mixed ALPN data arrived",
        "Vapache has no upstream connection pool, TCP-proxy mode or mixed HTTP/1-and-H2 upstream ALPN; one request owns each upstream connection",
        "high", "Envoy advisory and upstream connection ownership inventory",
    ),
    "CVE-2026-47221": (
        "not_applicable", "extension-module",
        "an upstream 303 internal-redirect filter drained a request-body buffer that did not exist",
        "Vapache does not follow upstream redirects internally and has no router internal_redirect_policy filter",
        "high", "Envoy advisory and proxy redirect behavior review",
    ),
    "CVE-2013-4322": (
        "prevented", "request-body",
        "unbounded chunk data and permissive trailer whitespace allowed a streaming denial of service",
        "decoded body bytes, chunk count, framing bytes, chunk lines, trailer count/bytes and absolute read time are independently capped; invalid trailer syntax fails closed",
        "high", "Tomcat advisory and shared chunk/trailer budget review",
    ),
    "CVE-2025-61795": (
        "prevented", "request-body",
        "multipart upload failure left temporary part files until garbage collection",
        "Vapache does not parse multipart parts; its raw request spool is an unlinked mode-0600 file owned by one RAII value and is closed immediately on every success/error/drop path",
        "high", "Tomcat advisory and request spool lifecycle review",
    ),
    "CVE-2026-10051": (
        "prevented", "request-lifecycle",
        "HTTP/1 trailers remained in a reusable request object and appeared on later requests",
        "Vapache creates fresh request headers for every parse and validates then discards trailer fields rather than retaining or merging them",
        "high", "Jetty advisory and per-request trailer ownership review",
    ),
    "CVE-2002-1717": (
        "not_applicable", "iis-extension",
        "FrontPage private configuration files were installed beneath the served IIS tree",
        "Vapache ships no FrontPage metadata or site content; it serves only operator-selected document-root files under normal access policy",
        "high", "Microsoft advisory and packaged content inventory",
    ),
    "CVE-2003-1566": (
        "fail_closed", "protocol-other",
        "TRACK requests bypassed normal access logging",
        "TRACK is unimplemented and receives 405 through the ordinary logged request lifecycle; TRACE remains separately capability-gated",
        "high", "Microsoft advisory and method/logging path review",
    ),
    "CVE-2005-2678": (
        "prevented", "http-parser",
        "absolute-form localhost made SERVER_NAME disagree with the actual authority",
        "absolute-form is disabled by default; when enabled its strict authority must equal Host including effective port and transport scheme, and that bound identity feeds server variables",
        "high", "Microsoft advisory and absolute-form identity review",
    ),
    "CVE-2006-0760": (
        "not_applicable", "platform",
        "case-sensitive handler policy was applied before a case-insensitive filesystem lookup",
        "Vapache targets case-sensitive Linux filesystems and also reauthorizes the descriptor's resolved basename before handler execution",
        "high", "lighttpd advisory and platform/opened-target policy review",
    ),
    "CVE-2006-0814": (
        "not_applicable", "platform",
        "Windows ignored trailing dots/spaces that the handler selector treated as significant",
        "Vapache's Linux target does not apply Win32 trailing-dot/space filename normalization",
        "high", "lighttpd advisory and platform boundary",
    ),
    "CVE-2010-2333": (
        "prevented", "path",
        "an embedded NUL truncated a script filename before handler selection",
        "literal and percent-encoded NUL are rejected before canonical mapping and safe Rust paths are never passed through attacker-controlled C strings",
        "high", "LiteSpeed advisory and percent/path decoder review",
    ),
    "CVE-2010-4312": (
        "not_applicable", "java-container",
        "Tomcat's default session cookie omitted HttpOnly",
        "Vapache has no built-in application session or session cookie generator; operator/application Set-Cookie values are not invented by the web server",
        "high", "Tomcat advisory and session feature inventory",
    ),
    "CVE-2011-1088": (
        "not_applicable", "java-container",
        "ServletSecurity annotations were ignored when constructing application access constraints",
        "Vapache has no servlet annotations or deployment-time Java security metadata",
        "high", "Tomcat advisory and authorization feature inventory",
    ),
    "CVE-2011-2729": (
        "prevented", "privilege-drop",
        "the daemon retained Linux capabilities after changing service identity",
        "Vapache does not enable keepcaps, sets no_new_privs, checks initgroups/setgroups/setgid/setuid, verifies the resulting IDs and aborts on failure",
        "high", "Tomcat jsvc advisory and Vapache privilege transition review",
    ),
    "CVE-2011-3375": (
        "prevented", "request-lifecycle",
        "recycled request state exposed another client's address or header bytes",
        "each request owns fresh parsed headers/address state, HTTP/1 dispatch is sequential per connection and mutable request processors are never pooled",
        "high", "Tomcat advisory and request ownership review",
    ),
    "CVE-2011-4963": (
        "not_applicable", "platform",
        "Windows path normalization ignored a trailing dot or NTFS allocation-stream suffix",
        "Vapache targets Linux and performs no Win32/NTFS path canonicalization",
        "high", "nginx advisory and platform boundary",
    ),
    "CVE-2011-4968": (
        "prevented", "tls",
        "the HTTPS proxy client encrypted traffic without authenticating the origin identity",
        "every HTTPS/WSS upstream handshake uses Rustls with trusted roots and a typed ServerName derived from the configured backend host",
        "high", "nginx advisory and upstream TLS connector review",
    ),
    "CVE-2013-2071": (
        "not_applicable", "java-container",
        "an application AsyncListener exception exposed another application's recycled request state",
        "Vapache has no servlet AsyncContext/AsyncListener or cross-application request-object pool",
        "high", "Tomcat advisory and application runtime inventory",
    ),
    "CVE-2016-2102": (
        "not_applicable", "admin-control-plane",
        "an OpenStack image exposed HAProxy's statistics endpoint without authentication",
        "Vapache neither consumes that image nor exposes an HAProxy statistics service; server-status is disabled unless explicitly capability-enabled and still passes access policy",
        "high", "NVD description and administrative endpoint inventory",
    ),
    "CVE-2018-12536": (
        "prevented", "error-page",
        "a filesystem exception string containing the document-root path was reflected in the default error page",
        "Vapache's generated errors use fixed public messages and never include io::Error text, resolved paths or stack traces in the response body",
        "high", "Jetty advisory and error response sinks review",
    ),
    "CVE-2021-43980": (
        "prevented", "request-lifecycle",
        "concurrent connections shared one mutable HTTP/1 processor and exchanged response bytes",
        "each accepted connection has an owned buffer/stream handled by one worker and response objects never cross connection ownership",
        "high", "Tomcat advisory and connection ownership review",
    ),
    "CVE-2024-45806": (
        "prevented", "auth",
        "private source addresses were trusted by default to supply internal control headers",
        "Vapache trusts forwarded client identity only from explicitly configured RemoteIPInternalProxy/TrustedProxy networks and strips/rebuilds forwarding headers on proxy output",
        "high", "Envoy advisory and trusted-proxy/header boundary review",
    ),
    "CVE-2025-46821": (
        "not_applicable", "extension-module",
        "an Envoy URI-template RBAC matcher omitted a valid asterisk character",
        "Vapache has no URI-template matcher; Location prefixes and configured PCRE2 expressions operate on the same canonical path used by authorization",
        "high", "Envoy advisory and authorization matcher inventory",
    ),
    "CVE-2026-24733": (
        "prevented", "http-parser",
        "a non-GET HTTP/0.9 request bypassed method-specific authorization",
        "Vapache accepts only explicit HTTP/1.0 or HTTP/1.1 request lines (or decoded H2 requests) and rejects HTTP/0.9 before authorization",
        "high", "Tomcat advisory and request-version parser review",
    ),
    "CVE-2026-25854": (
        "not_applicable", "java-container",
        "LoadBalancerDrainingValve occasionally selected an untrusted redirect destination",
        "Vapache has no servlet Valve or load-balancer draining redirect mechanism",
        "high", "Tomcat advisory and application pipeline inventory",
    ),
    "CVE-2026-26080": (
        "not_applicable", "http3",
        "an unchecked malformed QUIC frame-type varint was treated as PADDING and caused a loop or crash",
        "Vapache implements neither QUIC nor HTTP/3 and exposes no UDP frame parser",
        "high", "HAProxy 5bb098c patch comparison and protocol inventory",
    ),
    "CVE-2026-26081": (
        "not_applicable", "http3",
        "a malformed QUIC NEW_TOKEN length was used without validating the fixed token format",
        "Vapache implements neither QUIC, 0-RTT nor NEW_TOKEN parsing",
        "high", "HAProxy 4765277 patch comparison and protocol inventory",
    ),
    "CVE-2026-48497": (
        "not_applicable", "extension-module",
        "Envoy's UDP DNS filter asserted that a standards-valid 255-octet name was shorter",
        "Vapache has no UDP DNS filter/server; its proxy resolver accepts configured hostnames no longer than 253 bytes in an isolated worker",
        "high", "Envoy advisory and DNS feature inventory",
    ),
    "CVE-2005-0453": (
        "prevented", "cgi",
        "an embedded decoded NUL changed the extension used for CGI/FastCGI handler selection",
        "percent decoding rejects NUL before mapping and handler selection, and the opened script identity is bound before execution",
        "high", "lighttpd advisory and canonical CGI target review",
    ),
    "CVE-2007-3950": (
        "not_applicable", "platform",
        "32-bit-incompatible debug format specifiers crashed SCGI/FastCGI/WebDAV modules",
        "Vapache's supported target is 64-bit Linux, has no SCGI/WebDAV module, and Rust formatting is type checked",
        "high", "lighttpd advisory and target/runtime inventory",
    ),
    "CVE-2008-1111": (
        "prevented", "cgi",
        "a CGI fork failure fell through to static serving of the script source",
        "CGI selection is terminal: worker spawn/IPC failure returns an error response and never re-enters static file dispatch",
        "high", "lighttpd advisory and CGI failure control-flow review",
    ),
    "CVE-2011-5279": (
        "prevented", "cgi",
        "a newline in a request header injected an additional uppercase CGI environment variable",
        "request header values reject CR/LF and all controls except HTAB; CGI environment names come from a fixed allowlist and are constructed without parsing embedded lines",
        "high", "Microsoft advisory and request-to-CGI environment review",
    ),
    "CVE-2007-1858": (
        "prevented", "tls",
        "the default TLS policy enabled anonymous or obsolete cipher suites",
        "Rustls 0.23 defaults expose only authenticated modern TLS 1.2/1.3 suites and Vapache never enables anonymous ciphers",
        "high", "Tomcat advisory and Rustls provider/protocol construction review",
    ),
    "CVE-2007-6286": (
        "prevented", "request-lifecycle",
        "an empty native-TLS connection replayed a recently recycled request object",
        "each TLS connection and HTTP request owns fresh Rust state; EOF before a request returns cleanly without dispatch and no processor object is reused",
        "high", "Tomcat advisory and TLS/HTTP request ownership review",
    ),
    "CVE-2008-1531": (
        "prevented", "tls",
        "one connection's TLS error tore down shared state for all active TLS connections",
        "each accepted Rustls ServerConnection is independently owned; a handshake/read/write error closes only that connection and cannot mutate other connection tasks",
        "high", "lighttpd advisory and TLS connection ownership review",
    ),
    "CVE-2010-4180": (
        "not_applicable", "third-party",
        "an OpenSSL legacy compatibility option allowed session-resumption cipher downgrade",
        "Vapache uses Rustls rather than OpenSSL and has no SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG mode or TLS renegotiation",
        "high", "OpenSSL/nginx advisory and TLS dependency inventory",
    ),
    "CVE-2016-2390": (
        "prevented", "tls",
        "plaintext received on a TLS proxy path reached an unhandled OpenSSL handshake error",
        "Rustls returns a typed handshake error which Vapache converts to a bounded per-request proxy failure; it cannot crash the process",
        "high", "Squid advisory and upstream TLS error-path review",
    ),
    "CVE-2018-1172": (
        "not_applicable", "forward-proxy",
        "Squid SSL-Bump access checking dereferenced absent interception context",
        "Vapache implements no SSL-Bump, forward-proxy TLS interception or ClientRequestContext",
        "high", "Squid advisory and proxy feature inventory",
    ),
    "CVE-2018-19131": (
        "prevented", "error-page",
        "attacker certificate fields were inserted unescaped into a browser-visible TLS error page",
        "upstream TLS validation failures produce a fixed generic 502 body and never reflect certificate subject/SAN/error strings into HTML",
        "high", "Squid advisory and proxy TLS error response review",
    ),
    "CVE-2019-11323": (
        "not_applicable", "third-party",
        "HAProxy reload used an uninitialized HMAC key after certificate/key rotation",
        "Vapache uses Rustls-owned initialized ticket/key material and has no HAProxy ssl_sock reload structure or C uninitialized-memory path",
        "high", "HAProxy advisory and TLS key lifecycle/dependency comparison",
    ),
    "CVE-2020-8660": (
        "not_applicable", "extension-module",
        "a pre-routing TLS inspector failed to recognize TLS 1.3 and selected a plaintext filter chain",
        "Vapache has no protocol-inspection filter chain: a TLS listener always performs a Rustls handshake before HTTP routing",
        "high", "Envoy advisory and listener architecture review",
    ),
    "CVE-2025-66220": (
        "not_applicable", "tls",
        "a custom mTLS OTHERNAME SAN matcher truncated an embedded NUL",
        "Vapache exposes no configurable client-certificate SAN matcher and Rustls WebPkiClientVerifier does not coerce OTHERNAME values into application identities",
        "high", "Envoy advisory and inbound client-certificate feature inventory",
    ),
    "CVE-2010-2952": (
        "not_applicable", "third-party",
        "an internal DNS client generated predictable query IDs/source ports and incompletely validated replies",
        "Vapache has no internal DNS packet parser or cache; name resolution is delegated to the host resolver in a disposable bounded worker process",
        "high", "Traffic Server advisory and proxy resolver boundary review",
    ),
    "CVE-2008-0983": (
        "prevented", "memory-safety",
        "a native file-descriptor array was undersized when many connections were accepted",
        "Vapache uses safe growable ownership rather than an indexed C fd array and enforces process/per-client connection admission before worker dispatch",
        "high", "lighttpd advisory and listener connection storage review",
    ),
    "CVE-2009-2621": (
        "prevented", "http-parser",
        "incomplete or oversized request headers bypassed native buffer bounds",
        "request-head bytes, line/field count, field size, resident memory and read time are capped before the verified parser creates owned fields",
        "high", "Squid advisory and request-head admission review",
    ),
    "CVE-2009-3896": (
        "prevented", "http-parser",
        "a long URI reached a null native parser state",
        "the request line and target have hard byte limits, are parsed into owned safe-Rust values, and over-limit input fails before dispatch",
        "high", "nginx advisory and verified request-line limit review",
    ),
    "CVE-2010-2227": (
        "prevented", "http-framing",
        "invalid Transfer-Encoding corrupted a recycled parser buffer and affected later requests",
        "only exact final chunked is admitted, malformed framing closes the connection, and request buffers are owned rather than recycled across clients",
        "high", "Tomcat advisory and framing/request ownership review",
    ),
    "CVE-2010-2266": (
        "prevented", "path",
        "malformed/overlong encoded traversal reached native decoder memory corruption",
        "the safe-Rust percent decoder rejects malformed/overlong UTF-8 and encoded traversal before verified normalization and beneath-root open",
        "high", "nginx advisory and decode/path containment review",
    ),
    "CVE-2011-3205": (
        "fail_closed", "forward-proxy",
        "a long Gopher response overflowed the forward-proxy HTML converter",
        "Vapache rejects forward-proxy configuration and implements neither Gopher fetching nor Gopher-to-HTML conversion",
        "high", "Squid advisory and protocol feature inventory",
    ),
    "CVE-2011-4315": (
        "prevented", "proxy",
        "a malicious compressed DNS reply overflowed a native resolver buffer",
        "DNS packet parsing occurs only in the disposable libc resolver child; the parent accepts at most parsed SocketAddr lines under size/count/deadline limits, so a child fault cannot corrupt the server",
        "medium", "nginx advisory and isolated resolver process boundary review",
    ),
    "CVE-2011-4362": (
        "prevented", "auth",
        "signedness in native Base64 decoding indexed before a buffer",
        "Basic credentials are field-size bounded and decoded by a safe-Rust Base64 library whose error path rejects malformed input without indexing native memory",
        "high", "lighttpd advisory and Basic credential decoder review",
    ),
    "CVE-2012-0256": (
        "prevented", "http-parser",
        "a long Host field overflowed or exhausted native heap allocation",
        "Host is limited by the request-field and total-head caps before owned allocation and then parsed by checked safe-Rust authority code",
        "high", "Traffic Server advisory and Host admission review",
    ),
    "CVE-2012-2942": (
        "prevented", "response-header",
        "header rewriting copied into a fixed native scratch buffer smaller than configured input",
        "Vapache header/rewrite values use growable Rust vectors/strings, enforce field and resident-output limits, and pass the final control-byte serialization gate",
        "high", "HAProxy advisory and header rewrite/serialization review",
    ),
    "CVE-2013-1912": (
        "prevented", "request-lifecycle",
        "pipelined request realignment plus appended rewrite data overflowed a shared native buffer",
        "each parsed request owns its bytes, rewrites produce bounded owned values, and pipelined remainder bytes stay in a separate per-connection buffer",
        "high", "HAProxy advisory and pipeline/rewrite ownership review",
    ),
    "CVE-2013-4484": (
        "prevented", "http-parser",
        "trailing whitespace with no request target reached an invalid native parser state",
        "the verified request line requires exactly three non-empty components and rejects trailing/extra whitespace before dispatch",
        "high", "Varnish advisory and request-line parser review",
    ),
    "CVE-2013-4560": (
        "not_applicable", "extension-module",
        "a filesystem-monitor failure freed a directory object still in use",
        "Vapache has no FAM/inotify directory monitor or live configuration directory object",
        "high", "lighttpd advisory and runtime feature inventory",
    ),
    "CVE-2014-6269": (
        "prevented", "request-body",
        "large streamed request-body counters overflowed and drove native out-of-bounds access",
        "body lengths and additions use checked/saturating u64/usize arithmetic under hard decoded/spool/resident/time limits; copying uses safe slices",
        "high", "HAProxy advisory and request body accounting review",
    ),
    "CVE-2014-7141": (
        "not_applicable", "extension-module",
        "Squid's privileged ICMP/ICMPv6 pinger parsed a crafted packet out of bounds",
        "Vapache has no ICMP pinger helper or raw-packet parser",
        "high", "Squid advisory and helper inventory",
    ),
    "CVE-2022-22707": (
        "prevented", "proxy",
        "an unusual Forwarded-header configuration wrote a sentinel through a fixed stack buffer",
        "trusted-proxy header parsing uses safe Rust owned values under field limits; outbound Forwarded/X-Forwarded fields are reconstructed rather than mutated in place",
        "high", "lighttpd advisory and forwarded-header data-flow review",
    ),
    "CVE-2023-35942": (
        "not_applicable", "extension-module",
        "a drained listener freed state retained by a gRPC access logger",
        "Vapache has no gRPC access logger, dynamic listener drain or xDS listener update",
        "high", "Envoy advisory and logging/control-plane inventory",
    ),
    "CVE-2023-35943": (
        "not_applicable", "extension-module",
        "a CORS filter dereferenced an Origin field removed between decode and encode phases",
        "Vapache has no CORS filter pipeline or mutable cross-phase header reference",
        "high", "Envoy advisory and filter inventory",
    ),
    "CVE-2024-45809": (
        "not_applicable", "extension-module",
        "a JWT filter cleared routing state in the wrong async callback order",
        "Vapache has no JWT/JWKS filter, route-cache clearing callback or async filter chain",
        "high", "Envoy advisory and filter inventory",
    ),
    "CVE-2024-45810": (
        "not_applicable", "extension-module",
        "an async-client local-reply path retained a destroyed router during authz/mirroring/upgrade filters",
        "Vapache has no ext_authz filter, request mirroring or Envoy async HTTP client/filter lifecycle",
        "high", "Envoy advisory and filter inventory",
    ),
    "CVE-2026-26309": (
        "prevented", "logging",
        "a JSON escaper wrote one byte beyond a fixed C++ string and corrupted NUL termination",
        "Vapache log escaping is a verified safe-Rust append loop with an explicit expansion bound and no C-string termination requirement",
        "high", "Envoy advisory and verified log escaping review",
    ),
    "CVE-2026-26330": (
        "not_applicable", "extension-module",
        "a reused gRPC rate-limit client retained request-phase state into a failing response-phase call",
        "Vapache has no external rate-limit filter or gRPC filter client",
        "high", "Envoy advisory and filter inventory",
    ),
    "CVE-2026-47205": (
        "not_applicable", "extension-module",
        "a per-route ext_authz client outlived a rapidly reset stream",
        "Vapache has no ext_authz HTTP/gRPC client or per-route external authorization override",
        "high", "Envoy advisory and filter inventory",
    ),
    "CVE-2026-47207": (
        "not_applicable", "extension-module",
        "batched ext_proc responses continued after the first response destroyed the stream",
        "Vapache has no ext_proc gRPC filter or batched processing-response state machine",
        "high", "Envoy advisory and filter inventory",
    ),
    "CVE-2026-48706": (
        "not_applicable", "extension-module",
        "an attacker-derived metric name overflowed the fixed TCP StatsD flush slice",
        "Vapache has no StatsD sink or grpc_stats filter; request paths are also capped before any log formatting",
        "high", "Envoy advisory and telemetry feature inventory",
    ),
    "CVE-2026-50572": (
        "not_applicable", "extension-module",
        "an HTTP ext_authz callback survived rejection and invoked a destroyed owner",
        "Vapache has no external-authorization HTTP client or asynchronous filter callback owner",
        "high", "Envoy advisory and filter inventory",
    ),
    "CVE-2026-58187": (
        "not_applicable", "extension-module",
        "Traffic Server's multiplexer plugin overran its upstream chunk-decode buffer",
        "Vapache has no multiplexer plugin; its core upstream chunk decoder uses safe slices plus decoded, framing, line and trailer limits",
        "high", "Traffic Server advisory and plugin/chunk decoder inventory",
    ),
    "CVE-1999-0281": (
        "prevented", "http-parser",
        "an overlong URL exhausted or crashed the request parser",
        "the total request head and request target have hard limits, and an over-limit line fails before path decoding or dispatch",
        "high", "IIS advisory description and request-line admission review",
    ),
    "CVE-2000-0408": (
        "prevented", "path",
        "a long URL with many apparent extensions drove unsafe or disproportionate extension handling",
        "the request target is hard-capped and canonicalized linearly; handler extension selection performs bounded suffix work on the resulting path",
        "medium", "IIS advisory description and handler/path complexity review",
    ),
    "CVE-2000-0631": (
        "not_applicable", "iis-extension",
        "an IIS directory-browser administrative script crashed when a required argument was absent",
        "Vapache ships no IIS administrative scripts or directory-browser CGI application",
        "high", "Microsoft advisory and packaged application inventory",
    ),
    "CVE-2002-0224": (
        "not_applicable", "platform",
        "malformed traffic crashed the Windows Distributed Transaction Coordinator service",
        "Vapache has no MSDTC/COM transaction service or Windows RPC listener",
        "high", "Microsoft advisory and platform/service inventory",
    ),
    "CVE-2002-0935": (
        "prevented", "http-parser",
        "NUL-bearing requests left worker threads hung",
        "literal and encoded NUL fail during bounded head/path parsing; per-client/process connection slots and read deadlines bound even incomplete peers",
        "high", "Tomcat advisory and parser/connection resource review",
    ),
    "CVE-2003-0866": (
        "prevented", "request-lifecycle",
        "malformed connections poisoned shared connector state and caused later valid requests to be rejected",
        "request parse failure is scoped to one owned connection and fresh requests/connections share no mutable parser object",
        "high", "Tomcat advisory and parser ownership review",
    ),
    "CVE-2005-0808": (
        "not_applicable", "java-container",
        "a crafted AJP12 packet crashed Tomcat's separate AJP connector",
        "Vapache exposes no AJP listener or packet parser",
        "high", "Tomcat advisory and protocol inventory",
    ),
    "CVE-2005-3510": (
        "prevented", "dos",
        "concurrent listings of very large directories consumed unbounded CPU",
        "autoindex is disabled unless capability-enabled, expensive operations have a process gate, and scan count, rendered entries, output bytes and resident memory are all hard-capped",
        "high", "Tomcat advisory and Vapache autoindex budgets/tests",
    ),
    "CVE-2007-3946": (
        "fail_closed", "digest-auth",
        "malformed Digest authentication variants leaked/crashed native auth state",
        "Digest authentication is unimplemented and never parsed; Basic uses bounded safe-Rust Base64 plus admitted hash formats",
        "high", "lighttpd advisory and authentication feature inventory",
    ),
    "CVE-2007-3947": (
        "prevented", "http-parser",
        "duplicate request fields triggered a native null/invalid state",
        "header duplicates are represented in owned safe-Rust storage under count/byte limits; security-special fields are rejected or canonicalized by explicit rules",
        "high", "lighttpd advisory and duplicate-header parser review",
    ),
    "CVE-2007-3948": (
        "prevented", "dos",
        "the accept path exceeded its configured connection maximum and hit an assertion",
        "Vapache reserves a process worker and per-client connection lease before dispatch and sheds excess accepts without asserting",
        "high", "lighttpd advisory and connection admission tests",
    ),
    "CVE-2008-4298": (
        "prevented", "http-parser",
        "duplicate request headers leaked parser allocations across requests",
        "every parsed request owns bounded headers that are dropped at request completion; no duplicate-header allocation is retained in connection state",
        "high", "lighttpd advisory and request ownership review",
    ),
    "CVE-2009-2622": (
        "prevented", "http-parser",
        "missing/invalid protocol and status tokens reached unsafe request or response parser states",
        "request lines require exact HTTP versions/components and proxy status lines require exact HTTP/1.0-or-1.1 plus a three-digit 100-599 status; failures close the message path",
        "high", "Squid advisory and strict request/proxy status parsers",
    ),
    "CVE-2009-2855": (
        "prevented", "auth",
        "comma-delimited authentication parsing failed to advance and looped indefinitely",
        "Vapache does not parse Digest lists; Basic uses one bounded scheme/payload split and one finite Base64 decode",
        "high", "Squid advisory and authentication parser review",
    ),
    "CVE-2010-0295": (
        "prevented", "dos",
        "each tiny socket read allocated a new retained request buffer",
        "one per-connection vector is extended under total resident/head limits and a hard header deadline; partial reads do not allocate one persistent object each",
        "high", "lighttpd advisory and incremental head reader review",
    ),
    "CVE-2010-0308": (
        "prevented", "proxy",
        "a header-only DNS reply tripped an assertion in the in-process DNS packet parser",
        "DNS packets are parsed by the host resolver in a disposable worker process; the server validates only bounded textual SocketAddr results and survives worker failure",
        "medium", "Squid advisory and isolated resolver boundary review",
    ),
    "CVE-2010-2951": (
        "not_applicable", "third-party",
        "an internal IPv4 DNS-over-TCP fallback accessed a disabled/invalid socket",
        "Vapache has no internal UDP/TCP DNS socket state machine and delegates resolution to the host resolver worker",
        "high", "Squid advisory and resolver architecture inventory",
    ),
    "CVE-2010-3072": (
        "prevented", "memory-safety",
        "a crafted request reached a null native string-comparison operand",
        "request fields/targets are owned safe-Rust values and comparisons operate on slices/Options whose absent cases fail without dereference",
        "medium", "Squid advisory and implementation-language/request parser comparison",
    ),
    "CVE-2011-0534": (
        "prevented", "http-parser",
        "one connector failed to enforce the configured request-header size and exhausted heap",
        "the shared HTTP/1 reader applies immutable total/line/count/field/resident limits before parsing, independent of listener mode",
        "high", "Tomcat advisory and request-head admission review",
    ),
    "CVE-2011-4096": (
        "prevented", "proxy",
        "a malformed CNAME chain leaked/aborted state in an in-process DNS parser",
        "the disposable resolver worker owns libc DNS state; the parent bounds job queue, deadline and returned addresses and remains alive if the child fails",
        "medium", "Squid advisory and isolated resolver boundary review",
    ),
    "CVE-2011-4461": (
        "not_applicable", "java-container",
        "predictable Java HashMap collisions in parsed form parameters caused quadratic CPU work",
        "Vapache treats request bodies as opaque bounded bytes and does not parse form parameters into a hash table",
        "high", "Jetty advisory and request-body feature inventory",
    ),
    "CVE-2011-4858": (
        "not_applicable", "java-container",
        "predictable Java HashMap collisions in parsed form parameters caused quadratic CPU work",
        "Vapache does not parse application form parameters or populate a parameter hash table",
        "high", "Tomcat advisory and request-body feature inventory",
    ),
    "CVE-2012-0022": (
        "not_applicable", "java-container",
        "servlet parameter parsing performed superlinear work over many names and values",
        "Vapache does not parse query/form parameters into a servlet parameter map; query bytes remain bounded opaque data",
        "high", "Tomcat advisory and application parameter inventory",
    ),
    "CVE-2012-2733": (
        "prevented", "http-parser",
        "a connector accepted request headers beyond its configured maximum",
        "all HTTP/1 listeners share the same hard total-head, field-count, field-size, resident-memory and deadline enforcement",
        "high", "Tomcat advisory and request-head admission review",
    ),
    "CVE-2012-3544": (
        "prevented", "request-body",
        "streamed chunk extensions consumed unbounded input/work",
        "chunk-size lines are length-capped and strictly parsed while total chunk count, framing bytes, decoded bytes and absolute body time are independently bounded",
        "high", "Tomcat advisory and chunk-framing budget/tests",
    ),
    "CVE-2012-4534": (
        "prevented", "request-lifecycle",
        "TLS sendfile peer termination left the response loop spinning without progress",
        "file/TLS response writes propagate EOF/errors, run under socket/write deadlines, and do not retry a zero-progress native sendfile state",
        "medium", "Tomcat advisory and response writer control-flow review",
    ),
    "CVE-2012-5533": (
        "prevented", "http-parser",
        "an empty comma token in Connection parsing failed to advance",
        "Connection tokens are split with a finite iterator over a field-size-bounded slice; empty items are skipped without re-entering the same position",
        "high", "lighttpd advisory and hop-by-hop token parser review",
    ),
    "CVE-2012-5568": (
        "prevented", "dos",
        "many partial HTTP requests held all worker connections indefinitely",
        "request heads have a hard absolute timeout, process/per-client connection caps apply before worker dispatch, and incomplete connections release their leases on error",
        "high", "Tomcat advisory and connection/header deadline review",
    ),
    "CVE-2013-2070": (
        "prevented", "proxy",
        "negative/overflowed upstream chunk counters reached native out-of-bounds disclosure or crash",
        "the upstream chunk parser accepts only checked unsigned hexadecimal sizes, enforces decoded/framing limits, and copies through safe slices into bounded sinks",
        "high", "nginx patch.2013.proxy.txt comparison and proxy chunk decoder review",
    ),
    "CVE-2013-2175": (
        "not_applicable", "extension-module",
        "a configured negative hdr_* occurrence indexed before a fixed header-history array",
        "Vapache has no HAProxy hdr_ip/hdr_* sample-fetch occurrence configuration or header-history array",
        "high", "HAProxy advisory and expression feature inventory",
    ),
    "CVE-2014-0075": (
        "prevented", "request-body",
        "chunk-size integer overflow converted malformed input into excessive work",
        "chunk sizes use checked u64 hexadecimal parsing, must fit sink usize, and are rejected above the decoded body limit before allocation/copy",
        "high", "Tomcat advisory and chunk-size arithmetic review",
    ),
    "CVE-2014-7142": (
        "not_applicable", "extension-module",
        "Squid's ICMP/ICMPv6 pinger mishandled an attacker-controlled packet size",
        "Vapache has no raw ICMP pinger helper or packet parser",
        "high", "Squid advisory and helper inventory",
    ),
    "CVE-2016-0747": (
        "prevented", "proxy",
        "unbounded CNAME following consumed an in-process resolver worker",
        "each resolution runs in a disposable child under one deadline, a bounded eight-worker/64-job queue and a maximum returned-address count; timeout kills the child",
        "medium", "nginx advisory and isolated resolver resource review",
    ),
    "CVE-2018-8005": (
        "prevented", "range",
        "a multi-range request forced an entire large cached object to be read",
        "the verified range parser deliberately ignores every multi-range list and Vapache never caches reverse-proxy objects",
        "high", "Traffic Server advisory and verified single-range/cache policy review",
    ),
    "CVE-2020-14059": (
        "not_applicable", "cache",
        "Squid's shared-memory SMP cache page stack suffered an ABA race",
        "Vapache has no SMP shared-memory cache allocator or cross-process PageStack; its static cache uses Rust synchronization and owned entries",
        "high", "Squid advisory and cache architecture inventory",
    ),
    "CVE-2020-27223": (
        "prevented", "dos",
        "many Accept quality parameters caused disproportionate parsing CPU",
        "each header field is hard-capped and Accept-Encoding negotiation is one finite linear scan; Vapache does not parse general Accept quality values",
        "high", "Jetty advisory and content-negotiation parser review",
    ),
    "CVE-2021-31806": (
        "prevented", "range",
        "Range processing retained or corrupted memory across requests",
        "Vapache uses a proved single-range parser with checked arithmetic and owned response state; multi-range input is ignored",
        "medium", "Squid advisory and verified range parser review",
    ),
    "CVE-2021-31807": (
        "prevented", "range",
        "an upstream Content-Range integer overflow crashed range processing",
        "Vapache does not synthesize/cache proxy ranges; static range arithmetic is verified over u64 and malformed/overflowed values cannot select an out-of-bounds slice",
        "high", "Squid advisory and range/proxy behavior review",
    ),
    "CVE-2021-31808": (
        "prevented", "range",
        "client Range input reached an insufficiently validated resource path",
        "the verified parser accepts only one syntactically valid satisfiable byte range with checked bounds; all list/overflow/malformed cases are ignored or rejected",
        "high", "Squid advisory and verified range parser review",
    ),
    "CVE-2021-46784": (
        "fail_closed", "forward-proxy",
        "a long Gopher response exhausted or corrupted the forward-proxy response path",
        "Vapache implements no Gopher client/gateway and rejects forward-proxy operation",
        "high", "Squid advisory and protocol inventory",
    ),
    "CVE-2023-27492": (
        "not_applicable", "extension-module",
        "a reset request re-entered an Envoy Lua filter buffering a large body",
        "Vapache has no Lua filter/coroutine or application body-buffer filter pipeline",
        "high", "Envoy advisory and extension inventory",
    ),
    "CVE-2024-23323": (
        "prevented", "rewrite",
        "route regular expressions were recompiled for every request",
        "configuration parsing compiles each PCRE2 expression once into an immutable rule; request evaluation only executes the compiled pattern under input limits",
        "high", "Envoy advisory and Vapache regex lifecycle review",
    ),
    "CVE-2024-25617": (
        "prevented", "http-parser",
        "oversized request or upstream response headers were accepted under unsafe configurable defaults",
        "Vapache applies non-disableable total/line/count/field caps to both client request heads and proxy response heads before allocation/forwarding",
        "high", "Squid advisory and request/proxy header admission review",
    ),
    "CVE-2024-54677": (
        "not_applicable", "java-container",
        "Tomcat's bundled examples web application exposed an unbounded application operation",
        "Vapache ships no servlet examples or application runtime",
        "high", "Tomcat advisory and packaged application inventory",
    ),
    "CVE-2024-6762": (
        "not_applicable", "java-container",
        "Jetty PushSessionCacheFilter retained attacker-created session push state",
        "Vapache has no HTTP push, servlet session cache or PushSessionCacheFilter",
        "high", "Jetty advisory and filter/session inventory",
    ),
    "CVE-2024-8184": (
        "not_applicable", "java-container",
        "Jetty ThreadLimitHandler derived unbounded remote identities from crafted requests",
        "Vapache has no ThreadLimitHandler; client quotas use canonical IP or explicitly trusted proxy identity with bounded maps/leases",
        "high", "Jetty advisory and connection quota architecture review",
    ),
    "CVE-2024-9823": (
        "not_applicable", "java-container",
        "Jetty DosFilter retained unbounded attacker state",
        "Vapache has no servlet DosFilter and its process/per-client admission uses bounded resource leases rather than application filter objects",
        "high", "Jetty advisory and filter/resource inventory",
    ),
    "CVE-2026-26310": (
        "not_applicable", "extension-module",
        "a scoped IPv6 address crashed Envoy original_src/DNS filter formatting",
        "Vapache has neither original_src nor DNS filter; SocketAddr parsing/formatting uses the Rust standard library",
        "high", "Envoy advisory and filter inventory",
    ),
    "CVE-2026-47204": (
        "not_applicable", "extension-module",
        "a CONNECT-protocol request reached a null grpc_stats direct-response filter state",
        "Vapache has no grpc_stats filter, Connect-protocol application parser or Envoy direct_response route",
        "high", "Envoy advisory and filter inventory",
    ),
    "CVE-2002-1694": (
        "not_applicable", "platform",
        "the Windows server opened log files with write-sharing permissions that let another process modify active logs",
        "Vapache is Linux-only and opens logs under Unix descriptor and filesystem-permission semantics; it has no FILE_SHARE_WRITE mode",
        "high", "NVD description and Vapache platform/log-opening review",
    ),
    "CVE-2002-1695": (
        "needs_review", "source-data",
        "the NVD description identifies Norton Internet Security log sharing, while the record also marks IIS CPEs vulnerable",
        "the public record does not expose an IIS-specific root cause that can be compared honestly with Vapache",
        "low", "NVD description/CPE inconsistency",
    ),
    "CVE-2007-1358": (
        "not_applicable", "java-container",
        "an application deployed on Tomcat reflected a malformed Accept-Language value into its own HTML",
        "Vapache is not a servlet application runtime and cannot supply the affected application response path",
        "high", "NVD description and application/container boundary review",
    ),
    "CVE-2007-1869": (
        "prevented", "dos",
        "disconnecting during CRLF parsing left the parser in a non-advancing loop while retaining its descriptor",
        "Vapache's bounded line reader treats EOF as an error, advances on every byte, and releases the connection lease under an absolute head deadline",
        "high", "lighttpd advisory and request line-reader lifecycle review",
    ),
    "CVE-2008-0002": (
        "not_applicable", "java-container",
        "Tomcat's application-parameter processor retained state after an exception and reused it for another request",
        "Vapache has no servlet parameter parser or pooled request-parameter object; application bodies remain opaque",
        "high", "Tomcat advisory and request/application feature inventory",
    ),
    "CVE-2016-10002": (
        "prevented", "cache",
        "conditional revalidation could associate a client-specific Cookie response with another cache user",
        "Vapache never stores Set-Cookie responses, keys request cookies and authorization conservatively, gives If-None-Match precedence, and constructs each conditional response from the selected immutable entry",
        "high", "Squid advisory and Vapache conditional/cache-admission review",
    ),
    "CVE-2017-20005": (
        "prevented", "error-page",
        "a year outside the formatter's assumed four-digit range overflowed nginx autoindex date storage",
        "Vapache autoindex does not render modification dates; its shared HTTP-date formatter uses checked civil arithmetic and a dynamic fallback for years outside 0000-9999",
        "high", "nginx patch and Vapache autoindex/date formatter review",
    ),
    "CVE-2017-7657": (
        "prevented", "http-framing",
        "chunk-size integer overflow shortened the body and reinterpreted its remainder as a pipelined request",
        "the verified chunk parser uses checked u64 hexadecimal arithmetic, rejects values above the body budget before conversion, and requires the exact payload delimiter",
        "high", "Jetty advisory and verified chunk-framing review",
    ),
    "CVE-2017-7658": (
        "prevented", "http-framing",
        "duplicate Content-Length and Content-Length plus Transfer-Encoding produced a different body boundary across hops",
        "Vapache accepts exactly one valid Content-Length field and rejects every duplicate or Content-Length plus Transfer-Encoding request before reading or proxying a body",
        "high", "Jetty advisory and verified request-framing review",
    ),
    "CVE-2018-8037": (
        "not_applicable", "java-container",
        "Tomcat raced an application async-completion callback against its servlet timeout and recycled the response into another request",
        "Vapache has no servlet async API, application completion callback, or pooled servlet response object",
        "high", "Tomcat advisory and application-container inventory",
    ),
    "CVE-2018-9481": (
        "needs_review", "source-data",
        "the NVD description is an Android Bluetooth out-of-bounds read, while a separate configuration node and reference attach the same CVE ID to Traffic Server",
        "the Traffic Server root cause is absent from the public CVE description, so no Vapache prevention claim is made",
        "low", "NVD description/configuration inconsistency",
    ),
    "CVE-2018-20102": (
        "not_applicable", "third-party",
        "HAProxy's in-process DNS packet parser read beyond a crafted AAAA response buffer",
        "Vapache has no DNS wire parser; a bounded disposable worker calls the operating-system resolver and returns only parsed socket addresses",
        "high", "HAProxy advisory and resolver architecture review",
    ),
    "CVE-2020-8661": (
        "prevented", "dos",
        "internally generated responses accumulated without bound behind pipelined requests",
        "Vapache processes HTTP/1 requests sequentially per connection, completes or closes each bounded response before the next request, and charges retained bytes to a process-wide response quota",
        "high", "Envoy advisory and HTTP/1 response lifecycle/resource review",
    ),
    "CVE-2021-28662": (
        "prevented", "proxy",
        "Squid's registered-header lookup returned its OTHER sentinel as a normal typed header and later processing crashed",
        "Vapache represents upstream fields as validated token/value byte strings rather than an enum sentinel; malformed or over-limit proxy heads return 502 before caching",
        "high", "Squid 0518249 patch and upstream response parser review",
    ),
    "CVE-2023-27493": (
        "prevented", "proxy",
        "request-derived properties were inserted into upstream header values without validation, enabling response/request splitting at the next hop",
        "every configured, rewritten, certificate-derived, and forwarded upstream field passes the final control-free header serialization gate immediately before write",
        "high", "Envoy advisory and proxy_header_admit sink review",
    ),
    "CVE-2023-5824": (
        "prevented", "cache",
        "cached response metadata could grow across 304 updates beyond the receive-time header limit and later stall or crash deserialization",
        "Vapache does not merge upstream 304 fields into stored entries; proxy heads are capped before entry construction and disk metadata has a hard one-megabyte load limit plus total cache quota",
        "high", "Squid GHSA-543m-w2m2-g255 and cache metadata lifecycle review",
    ),
    "CVE-2024-23672": (
        "prevented", "websocket",
        "incomplete WebSocket cleanup let clients retain connections and grow server resource use",
        "Vapache caps tunnels process-wide and per effective client and closes them on an independent idle/write deadline, releasing the RAII tunnel lease on every exit",
        "high", "Tomcat advisory and WebSocket tunnel lifecycle review",
    ),
    "CVE-2026-33096": (
        "partial", "memory-safety",
        "HTTP.sys read outside a buffer and could be crashed by a remote request, but the public record omits the triggering parser state",
        "safe Rust removes the native out-of-bounds read, but without the input/state sequence an equivalent panic or resource path cannot be excluded",
        "low", "NVD/CNA summary; trigger undisclosed",
    ),
    "CVE-2026-33930": (
        "not_applicable", "proxy",
        "Traffic Server copied Host into a fixed stack buffer while following an upstream redirect",
        "Vapache does not follow upstream redirects; it returns them as bounded responses, and all accepted Host fields are size- and syntax-bounded owned values",
        "high", "Traffic Server advisory and proxy redirect/Host handling review",
    ),
    "CVE-2026-40701": (
        "prevented", "tls",
        "nginx freed client-certificate/OCSP resolver state while a later callback still referenced it",
        "Vapache uses Rustls-owned handshake state and isolated owned OCSP validation results with no nginx resolver callback or shared native certificate lifetime",
        "medium", "nginx advisory and TLS/OCSP ownership review",
    ),
    "CVE-2026-58154": (
        "prevented", "http-parser",
        "native MIME/HTTP header parsing used unchecked integer and write bounds",
        "Vapache's complete head is byte-, line-, field- and count-bounded before safe-Rust parsing; numeric framing uses checked conversion and no parser writes through raw pointers",
        "high", "Traffic Server advisory and request/proxy header parser review",
    ),
    "CVE-2026-58160": (
        "not_applicable", "third-party",
        "Traffic Server's in-process DNS answer parser read outside the received packet",
        "Vapache has no DNS wire parser; bounded disposable workers call the operating-system resolver and return parsed socket addresses",
        "high", "Traffic Server advisory and resolver architecture review",
    ),
    "CVE-2026-58164": (
        "prevented", "admin-control-plane",
        "concurrent remap configuration replacement left stale references and a validation/use race",
        "Vapache loads a complete immutable Config generation, prepares every fallible listener/TLS/background resource, then swaps generations at one commit boundary; active requests retain their Arc-owned generation",
        "high", "Traffic Server advisory and transactional reload ownership review",
    ),
    "CVE-2026-65927": (
        "prevented", "rewrite",
        "Tomcat's rewrite [N] transition restarted at rule index one instead of index zero",
        "Vapache's shared verified rewrite_advance transition returns Restart and both execution paths explicitly set the program counter to zero; regression coverage exercises a first-rule [N] restart",
        "high", "Tomcat advisory, rewrite interpreter review, and Verus rewrite transition proof",
    ),
    "CVE-2026-69597": (
        "prevented", "memory-safety",
        "a use-after-free in privileged HTTP.sys state allowed an authorized network peer to cross a privilege boundary",
        "Vapache request state is safe-Rust owned, active generations are Arc-retained, and the request-serving process permanently drops root before accepting traffic",
        "medium", "NVD/CNA root cause and ownership/privilege architecture review",
    ),
    "CVE-1999-0007": (
        "prevented", "tls",
        "RSA PKCS#1 v1.5 error behavior exposed an adaptive chosen-ciphertext oracle",
        "Vapache's Rustls configuration supports TLS 1.2/1.3 with forward-secret key exchange and does not negotiate static RSA key exchange or expose PKCS#1 decryption errors",
        "high", "MS98-002/Bleichenbacher root cause and Rustls protocol configuration review",
    ),
    "CVE-1999-0012": (
        "not_applicable", "platform",
        "Windows long/8.3 filename aliases bypassed the access-control name used by the web server",
        "Vapache is Linux-only, rejects Windows separators and drive/UNC syntax, and binds policy to the descriptor opened beneath the configured root",
        "high", "NVD description and Vapache platform/path identity review",
    ),
    "CVE-1999-0191": (
        "not_applicable", "iis-extension",
        "the bundled newdsn.exe CGI accepted a remote file-overwrite operation",
        "Vapache does not ship or dispatch newdsn.exe, and CGI execution requires an explicitly configured contained executable",
        "high", "NVD description and bundled-handler inventory",
    ),
    "CVE-1999-0229": (
        "prevented", "path",
        "a backslash dot-dot path drove IIS into an exceptional denial-of-service path",
        "Vapache rejects literal and decoded backslashes and canonicalizes dot segments before policy, mapping, proxying, or filesystem access",
        "medium", "NVD description and canonical path parser review",
    ),
    "CVE-1999-0349": (
        "not_applicable", "extension-module",
        "the IIS FTP LIST command copied an attacker-controlled listing argument beyond a native buffer",
        "Vapache implements no FTP listener, command parser, or LIST operation",
        "high", "MS99-003 and protocol inventory",
    ),
    "CVE-1999-0407": (
        "not_applicable", "admin-control-plane",
        "a default IISADMPWD virtual directory exposed password-administration scripts as a brute-force/user-enumeration oracle",
        "Vapache ships no IISADMPWD directory, password administration endpoint, or remotely mutable control plane",
        "high", "NVD description and installed endpoint inventory",
    ),
    "CVE-1999-0448": (
        "prevented", "logging",
        "an unbounded method token displaced or hid the actual URL in request logs",
        "the whole request line and method token are hard-bounded before parsing, and access logs emit separately escaped method and canonical target fields",
        "high", "NVD description and request-line/log serialization review",
    ),
    "CVE-1999-0725": (
        "prevented", "path",
        "a multibyte Windows code-page lead byte changed extension/path interpretation and disclosed parsed source",
        "Vapache accepts only strict UTF-8 after one byte-exact percent decode, rejects ambiguous separators, and uses the same canonical bytes for handler policy and contained open",
        "high", "MS99-022 and Vapache decode/handler/open pipeline review",
    ),
    "CVE-1999-1011": (
        "not_applicable", "iis-extension",
        "the MDAC Remote Data Service DataFactory exposed command-capable methods over an IIS endpoint",
        "Vapache has no MDAC, RDS, DataFactory, COM automation, or equivalent bundled data endpoint",
        "high", "MS98-004/MS99-025 and feature inventory",
    ),
    "CVE-1999-1233": (
        "prevented", "auth",
        "a failed reverse-DNS lookup bypassed an IP/domain access rule on the initial request",
        "Vapache accepts a hostname rule only after forward-confirmed reverse DNS; resolution failure, timeout, mismatch, or queue overload returns no match and therefore cannot satisfy an allow rule",
        "high", "NVD description and fail-closed FCrDNS authorization review",
    ),
    "CVE-1999-1451": (
        "not_applicable", "iis-extension",
        "the bundled Winmsdp.exe sample accepted an arbitrary file-read request",
        "Vapache ships no Winmsdp/Site Server sample and executes no CGI without explicit contained handler configuration",
        "high", "MS99-013 and bundled-handler inventory",
    ),
    "CVE-1999-1478": (
        "not_applicable", "java-container",
        "a Sun HotSpot VM URL-processing defect crashed Java application servers",
        "Vapache has no JVM, HotSpot engine, servlet runtime, or Java URL handler",
        "high", "NVD description and runtime inventory",
    ),
    "CVE-1999-1538": (
        "not_applicable", "iis-extension",
        "an upgrade left an unauthenticated ism.dll IIS administration endpoint installed",
        "Vapache ships no ism.dll, IIS upgrade residue, or web administration endpoint",
        "high", "NVD description and installed endpoint inventory",
    ),
    "CVE-2000-0024": (
        "prevented", "path",
        "IIS and a downstream policy component canonicalized escaped URL characters differently",
        "one strict percent decode, separator rejection, canonical dot-segment removal, descriptor containment, and exact proxy re-encoding keep policy and sink on one path identity",
        "high", "NVD description and Vapache canonical target pipeline review",
    ),
    "CVE-2000-0126": (
        "not_applicable", "iis-extension",
        "bundled sample IDQ scripts passed dot-dot input into an arbitrary file-read operation",
        "Vapache ships no IDQ scripts or Internet Data Query handler",
        "high", "NVD description and bundled-handler inventory",
    ),
    "CVE-2000-0226": (
        "prevented", "request-body",
        "a declared POST/PUT body size caused an attacker-sized resident allocation before bounded receipt",
        "Vapache rejects lengths over LimitRequestBody, retains at most a 64 KiB prefix for large bodies, spools under shared byte/file quotas, and applies one hard body deadline",
        "high", "MS00-018 and request body allocation/lifecycle review",
    ),
    "CVE-2000-0770": (
        "not_applicable", "platform",
        "IIS combined Windows parent and child ACL names incorrectly and granted access to a more restricted file",
        "Vapache runs under an unprivileged Unix identity and the final descriptor open must pass kernel permissions as well as the resource-bound policy grant",
        "high", "NVD description and filesystem authorization boundary review",
    ),
    "CVE-2000-1090": (
        "prevented", "path",
        "a double-byte code-page lead byte changed extension parsing and exposed parsed source",
        "Vapache uses strict UTF-8, one byte-exact percent decode, and one canonical path/handler identity with no locale-dependent code-page parser",
        "high", "vendor advisory and canonical path/handler review",
    ),
    "CVE-2001-0333": (
        "prevented", "path",
        "double percent decoding plus Windows backslash handling converted a policy-safe name into dot-dot traversal",
        "Vapache decodes exactly once, rejects decoded backslashes, removes dot segments, re-encodes percent signs at proxy boundaries, and opens below the configured root",
        "high", "MS01-026/CERT CA-2001-12 and canonical path tests",
    ),
    "CVE-2001-0545": (
        "prevented", "http-framing",
        "URL redirection processed a request whose declared body length disagreed with the bytes actually available and crashed",
        "Vapache validates one unambiguous framing decision and consumes the complete bounded body before dispatch; a short fixed body is a connection error and cannot enter redirect handling",
        "high", "MS01-044 and request framing/redirect lifecycle review",
    ),
    "CVE-2003-1342": (
        "not_applicable", "extension-module",
        "Trend Micro ActiveSupport.exe retained unbounded state under repeated requests while hosted by IIS",
        "Vapache neither ships nor dispatches the Trend Micro TVCS ActiveSupport application",
        "high", "NVD description and application inventory",
    ),
    "CVE-2007-2897": (
        "not_applicable", "platform",
        "Windows DOS-device path normalization reached a COM device despite a blacklist and could hang the device/server",
        "Vapache is Linux-only, rejects Windows path syntax, and opens canonical targets beneath a directory descriptor without DOS device namespaces",
        "high", "NVD description and platform/path inventory",
    ),
    "CVE-2013-0942": (
        "not_applicable", "extension-module",
        "the third-party EMC RSA Authentication Agent reflected attacker input into its web UI",
        "Vapache does not bundle the RSA Authentication Agent or its application response templates",
        "high", "NVD description and authentication provider inventory",
    ),
    "CVE-2014-4078": (
        "prevented", "auth",
        "wildcard domain allow/deny rules were matched with the wrong hostname semantics",
        "Vapache uses case-insensitive DNS-label-boundary matching after forward-confirmed reverse DNS; wildcard-like strings are not treated as broader suffixes and failures deny",
        "high", "MS14-076 and hostname_in_domain regression review",
    ),
    "CVE-2024-39305": (
        "not_applicable", "extension-module",
        "an Envoy route hash policy retained cookie-attribute storage after configuration parsing freed it",
        "Vapache has no cookie-based route hash policy or request filter callback that reuses parsed configuration storage",
        "high", "Envoy advisory and proxy routing feature inventory",
    ),
    "CVE-2026-26311": (
        "not_applicable", "extension-module",
        "Envoy invoked stream filter callbacks after reset cleanup and onDestroy had logically ended their lifetime",
        "Vapache has no extensible HTTP stream filter chain, deferred filter deletion, or onDestroy/decodeData callback lifecycle",
        "high", "Envoy advisory and HTTP filter architecture inventory",
    ),
}


def english_description(cve: dict[str, Any]) -> str:
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            return item.get("value", "").replace("\n", " ")
    return ""


def metric(cve: dict[str, Any]) -> tuple[str, float | None, str | None]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            return (
                str(data.get("baseSeverity", "unknown")).lower(),
                data.get("baseScore"),
                data.get("vectorString"),
            )
    if metrics.get("cvssMetricV2"):
        data = metrics["cvssMetricV2"][0].get("cvssData", {})
        score = data.get("baseScore")
        severity = "high" if score is not None and score >= 7 else "medium"
        return severity, score, data.get("vectorString")
    return "unknown", None, None


def cwes(cve: dict[str, Any]) -> list[str]:
    found: set[str] = set()
    for weakness in cve.get("weaknesses", []):
        for item in weakness.get("description", []):
            value = item.get("value", "")
            if re.fullmatch(r"CWE-\d+", value):
                found.add(value)
    return sorted(found, key=lambda value: int(value.split("-")[1]))


def references(cve: dict[str, Any]) -> list[dict[str, Any]]:
    refs = []
    for item in cve.get("references", []):
        url = item.get("url")
        if not url:
            continue
        refs.append({"url": url, "tags": sorted(item.get("tags", []))})
    refs.sort(key=lambda item: ("Vendor Advisory" not in item["tags"], "Patch" not in item["tags"], item["url"]))
    return refs[:16]


def vulnerable_cpes(cve: dict[str, Any]) -> list[str]:
    """Retain exact vulnerable CPE criteria for source/provenance auditing."""
    found: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("vulnerable") is True and isinstance(value.get("criteria"), str):
                found.add(value["criteria"])
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(cve.get("configurations", []))
    return sorted(found)


def request_json(parameters: dict[str, str], last_request: list[float]) -> dict[str, Any]:
    api_key = os.environ.get("NVD_API_KEY")
    minimum_delay = 0.7 if api_key else 6.2
    wait = minimum_delay - (time.monotonic() - last_request[0])
    if wait > 0:
        time.sleep(wait)
    url = f"{NVD_API}?{urllib.parse.urlencode(parameters)}"
    headers = {"User-Agent": "vapache-cross-server-cve-audit/1"}
    if api_key:
        headers["apiKey"] = api_key
    for attempt in range(6):
        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, context=ssl.create_default_context(), timeout=60) as response:
                data = json.load(response)
            last_request[0] = time.monotonic()
            return data
        except urllib.error.HTTPError as error:
            if error.code != 429 or attempt == 5:
                raise
            delay = int(error.headers.get("Retry-After", "30"))
            print(f"NVD rate limit; retrying in {delay}s", file=sys.stderr)
            time.sleep(delay)
            last_request[0] = time.monotonic()
    raise AssertionError("unreachable")


def fetch() -> dict[str, Any]:
    records: dict[str, dict[str, Any]] = {}
    product_counts: dict[str, int] = {}
    last_request = [0.0]
    for product, spec in PRODUCTS.items():
        product_ids: set[str] = set()
        for query in spec["queries"]:
            start = 0
            while True:
                parameters = {**query, "resultsPerPage": "2000", "startIndex": str(start)}
                data = request_json(parameters, last_request)
                vulnerabilities = data.get("vulnerabilities", [])
                print(
                    f"{product}: {query} -> {data.get('totalResults', 0)} records"
                    + (f" (page {start})" if start else "")
                )
                for wrapper in vulnerabilities:
                    cve = wrapper["cve"]
                    ident = cve["id"]
                    description = english_description(cve)
                    # The HTTP.sys keyword query occasionally returns prose that
                    # merely links to HTTP.sys. Keep Microsoft protocol-stack
                    # records, not unrelated products with a passing mention.
                    if product == "iis-http-sys" and "keywordSearch" in query:
                        if not re.search(r"HTTP\.sys|HTTP Protocol Stack", description, re.I):
                            continue
                    severity, score, vector = metric(cve)
                    normalized = records.setdefault(
                        ident,
                        {
                            "id": ident,
                            "source_identifier": cve.get("sourceIdentifier"),
                            "published": cve.get("published"),
                            "last_modified": cve.get("lastModified"),
                            "vuln_status": cve.get("vulnStatus"),
                            "description": description,
                            "severity": severity,
                            "score": score,
                            "vector": vector,
                            "cwes": cwes(cve),
                            "references": references(cve),
                            "vulnerable_cpes": vulnerable_cpes(cve),
                            "products": [],
                        },
                    )
                    if product not in normalized["products"]:
                        normalized["products"].append(product)
                    product_ids.add(ident)
                start += len(vulnerabilities)
                if start >= data.get("totalResults", 0) or not vulnerabilities:
                    break
        product_counts[product] = len(product_ids)
    for record in records.values():
        record["products"].sort()
    return {
        "schema": 2,
        "source": "NVD CVE API 2.0",
        "fetched_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "products": PRODUCTS,
        "product_counts": product_counts,
        "records": [records[ident] for ident in sorted(records)],
    }


def feature_absence(text: str, products: list[str]) -> tuple[str, str] | None:
    if ADMIN.search(text):
        return "admin-control-plane", "Vapache has no remotely mutable administration/control-plane API"
    if JAVA_APP.search(text) and any(product in {"tomcat", "jetty"} for product in products):
        return "java-container", "Vapache is not a Java servlet/JSP application container"
    if IIS_EXTENSION.search(text) and "iis-http-sys" in products:
        return "iis-extension", "the IIS/Windows extension surface is not implemented"
    if EXTENSION.search(text):
        return "extension-module", "the affected extension/module is not loaded by Vapache"
    if HTTP3.search(text):
        return "http3", "HTTP/3 and QUIC are not implemented"
    if DIGEST_AUTH.search(text):
        return "digest-auth", "Digest authentication is not implemented and protected resources fail closed rather than accepting Digest credentials"
    if PLATFORM_PATH.search(text):
        return "platform", "the Windows-specific platform primitive is absent on Vapache's Linux target"
    if LOCAL_PACKAGING.search(text) and (
        re.search(r"installer|package|init script|logrotate|service installation", text, re.I)
        or not re.search(r"remote attacker|remote user", text, re.I)
    ):
        return "platform", "the affected installer, package-maintenance, or local-user boundary is not part of Vapache's request-serving path"
    if FORWARD_PROXY.search(text) and "squid" in products:
        return "forward-proxy", "Vapache rejects forward-proxy configuration and does not implement Squid peer protocols"
    return None


def root_from_cwe(values: list[str], fallback: str) -> str:
    for value in values:
        if value in CWE_ROOT_CAUSE:
            return CWE_ROOT_CAUSE[value]
    return fallback


def classify(record: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
    ident = record["id"]
    if ident in OVERRIDES:
        return OVERRIDES[ident]
    text = record["description"]
    products = record["products"]
    values = record["cwes"]
    if record.get("vuln_status", "").lower() == "rejected" or REJECTED.search(text):
        return (
            "rejected",
            "rejected-record",
            "the CVE record was rejected by its assigning authority",
            "no vulnerability primitive remains to compare",
            "high",
            "NVD record status",
        )
    absent = feature_absence(text, products)
    if absent:
        surface, why = absent
        return (
            "not_applicable" if surface not in {"http3", "forward-proxy", "digest-auth"} else "fail_closed",
            surface,
            root_from_cwe(values, f"defect in the product-specific {surface} feature"),
            why,
            "high",
            "NVD/CNA description plus Vapache feature inventory",
        )
    if PRIVDROP.search(text):
        return (
            "prevented",
            "privilege-drop",
            root_from_cwe(values, "a failed privilege-drop operation is ignored"),
            "Vapache checks initgroups, setgroups, setgid and setuid and aborts startup if any transition fails",
            "high",
            "NVD/CNA description and startup privilege-transition review",
        )
    if LIFECYCLE.search(text):
        return (
            "prevented",
            "request-lifecycle",
            root_from_cwe(values, "reusable connection/request state survives into another request"),
            "Vapache creates request/response state per dispatch, processes HTTP/1 pipelining sequentially, and does not pool mutable request processors",
            "medium",
            "NVD/CNA description and request lifecycle review",
        )
    if ERROR_DISCLOSURE.search(text):
        return (
            "prevented",
            "error-page",
            root_from_cwe(values, "generated error output exposes an internal filesystem or configuration path"),
            "Vapache's generic error bodies contain no filesystem paths or stack traces and HTML-escape reflected text",
            "high",
            "NVD/CNA description and generated-error review",
        )
    if MEMORY.search(text) or any(
        value in {
            "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-416", "CWE-787"
        }
        for value in values
    ):
        availability_remains = DOS.search(text) is not None
        return (
            "partial" if availability_remains else "prevented",
            "memory-safety",
            root_from_cwe(values, "memory-unsafe lifetime or bounds handling"),
            (
                "safe Rust removes the memory corruption primitive, but a semantically equivalent panic or resource-exhaustion path still requires case-specific replay"
                if availability_remains
                else "the corresponding Vapache path is safe Rust and the unsafe-site budget contains no protocol buffer manipulation"
            ),
            "medium",
            "NVD/CNA description and CWE; implementation-language comparison",
        )
    if SMUGGLE.search(text) or "CWE-444" in values:
        return (
            "partial",
            "http-framing",
            root_from_cwe(values, "inconsistent HTTP framing or hop-by-hop normalization between components"),
            "Vapache rejects HTTP/1 CL/TE ambiguity and reconstructs proxy requests, but each cross-protocol variant requires an exact replay",
            "medium",
            "NVD/CNA description and framing implementation review",
        )
    if METHOD_AUTHORITY.search(text):
        return (
            "partial",
            "http-parser",
            root_from_cwe(values, "request-target, method, authority, or Host representations are interpreted inconsistently"),
            "Vapache validates method tokens, canonicalizes request targets, and reconciles Host/:authority, but the exact differential requires replay",
            "medium",
            "NVD/CNA description and request-target parser comparison",
        )
    if HTTP2.search(text):
        return (
            "partial",
            "http2",
            root_from_cwe(values, "HTTP/2 state, compression, flow-control, or stream-lifecycle invariant failure"),
            "Vapache bounds headers, streams and flow control, but the vendored h2 adapter and exact frame sequence require case-specific review",
            "medium",
            "NVD/CNA description and HTTP/2 design comparison",
        )
    if PATH.search(text) or any(value in {"CWE-22", "CWE-23", "CWE-59"} for value in values):
        return (
            "partial",
            "path",
            root_from_cwe(values, "URL/filesystem canonicalization or containment is applied in the wrong order"),
            "Vapache canonicalizes URL paths and uses openat2 containment, but alias/rewrite/authorization ordering requires case-specific proof",
            "medium",
            "NVD/CNA description and path-resolution design comparison",
        )
    if RANGE.search(text):
        return (
            "prevented",
            "range",
            root_from_cwe(values, "range parsing or aggregation permits excessive or inconsistent work"),
            "Vapache accepts only one bounded byte range and rejects multipart/overlapping ranges",
            "high",
            "NVD/CNA description and range implementation review",
        )
    if CACHE.search(text):
        return (
            "partial",
            "cache",
            root_from_cwe(values, "cache identity omits a representation- or policy-selecting input"),
            "Vapache binds cache entries to canonical policy keys, but the exact omitted input must be compared per CVE",
            "medium",
            "NVD/CNA description and cache-key design comparison",
        )
    if COMPRESSION.search(text):
        return (
            "partial",
            "compression",
            root_from_cwe(values, "compression/decompression work or output is insufficiently bounded"),
            "Vapache caps compression input and output, but algorithm-specific dependency behavior is outside the formal model",
            "medium",
            "NVD/CNA description and compression budget review",
        )
    if WEBSOCKET.search(text):
        return (
            "partial",
            "websocket",
            root_from_cwe(values, "upgrade/tunnel state is accepted without a complete handshake or lifetime invariant"),
            "Vapache implements HTTP/1 WebSocket proxy tunneling, so the exact handshake and close sequence requires replay",
            "medium",
            "NVD/CNA description and tunnel implementation review",
        )
    if PROXY.search(text):
        return (
            "partial",
            "proxy",
            root_from_cwe(values, "proxy target, routing identity, or upstream response is insufficiently constrained"),
            "Vapache canonicalizes configured upstreams and does not reuse backend connections, but routing/translation cases require individual review",
            "medium",
            "NVD/CNA description and proxy design comparison",
        )
    if CGI.search(text):
        return (
            "partial",
            "cgi",
            root_from_cwe(values, "gateway environment, response framing, or process lifetime is insufficiently constrained"),
            "Vapache bounds CGI/FastCGI headers, output and time, but parameter semantics require case-specific comparison",
            "medium",
            "NVD/CNA description and gateway implementation review",
        )
    if TLS.search(text):
        return (
            "partial",
            "tls",
            root_from_cwe(values, "TLS certificate, handshake, or session policy is applied inconsistently"),
            "Rustls replaces the affected native TLS implementation, while certificate and session policy remain an external dependency boundary",
            "medium",
            "NVD/CNA description and TLS architecture comparison",
        )
    if AUTH.search(text):
        return (
            "partial",
            "auth",
            root_from_cwe(values, "authentication or authorization state is not bound to the selected request target"),
            "Vapache has a single policy evaluator, but provider- and phase-specific behavior requires individual comparison",
            "medium",
            "NVD/CNA description and authorization design comparison",
        )
    if HEADER.search(text):
        return (
            "prevented",
            "response-header",
            root_from_cwe(values, "attacker-controlled bytes reach an HTTP header without validation"),
            "all generated and proxied response headers pass the CR/LF/NUL sanitizer before serialization",
            "high",
            "NVD/CNA description and response serialization review",
        )
    if LOGGING.search(text):
        return (
            "prevented",
            "logging",
            root_from_cwe(values, "attacker-controlled bytes reach a log sink without escaping"),
            "client-derived log fields use the verified byte escaping primitive",
            "high",
            "NVD/CNA description and log sink review",
        )
    if XSS.search(text) or "CWE-79" in values:
        return (
            "prevented",
            "response-header",
            root_from_cwe(values, "attacker-controlled data is emitted into generated HTML without escaping"),
            "Vapache's generated error, status and autoindex HTML escapes request- and filename-derived bytes",
            "medium",
            "NVD/CNA description and generated-HTML sink review",
        )
    if REQUEST_BODY.search(text):
        return (
            "partial",
            "request-body",
            root_from_cwe(values, "request body parsing or retention is insufficiently bounded"),
            "Vapache bounds aggregate body memory and streams gateway/proxy bodies, but does not parse application multipart formats",
            "medium",
            "NVD/CNA description and request-body lifecycle review",
        )
    if DOS.search(text) or any(value in {"CWE-400", "CWE-770", "CWE-835"} for value in values):
        return (
            "partial",
            "dos",
            root_from_cwe(values, "attacker-controlled work, allocation, or lifetime lacks a complete resource bound"),
            "Vapache has process-wide and per-request budgets, but the triggering operation must be mapped to a specific counter",
            "low",
            "NVD/CNA description and generic resource-budget comparison",
        )
    return (
        "partial",
        "protocol-other",
        root_from_cwe(values, "the vendor summary identifies a behavior error but not a more specific implementation primitive"),
        "no Vapache prevention claim is made without a feature-specific invariant or replay; vendor advisory/patch review remains required",
        "low",
        "NVD/CNA description; conservative unresolved mapping",
    )


def spec_prevents(status: str) -> str:
    if status in {"prevented", "fail_closed", "not_applicable"}:
        return "yes"
    if status == "partial":
        return "partial"
    if status in {"not_covered", "needs_review"}:
        return "no" if status == "not_covered" else "unknown"
    return "not_applicable"


def build(source: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for record in source["records"]:
        status, surface, root_cause, rationale, confidence, basis = classify(record)
        rows.append(
            {
                "id": record["id"],
                "year": int(record["id"][4:8]),
                "published": record.get("published"),
                "last_modified": record.get("last_modified"),
                "vuln_status": record.get("vuln_status"),
                "products": record["products"],
                "severity": record["severity"],
                "score": record["score"],
                "vector": record.get("vector"),
                "cwes": record["cwes"],
                "status": status,
                "spec_prevents": spec_prevents(status),
                "surface": surface,
                "root_cause": root_cause,
                "confidence": confidence,
                "classification_method": (
                    "manual_override" if record["id"] in OVERRIDES else "conservative_rule"
                ),
                "analysis_basis": basis,
                "vapache_mapping": rationale,
                "implementation_evidence": EVIDENCE.get(surface, EVIDENCE.get("unimplemented", [])),
                "description": record["description"],
                "vulnerable_cpes": record.get("vulnerable_cpes", []),
                "references": list(dict.fromkeys(item["url"] for item in record["references"])),
            }
        )
    rows.sort(key=lambda row: row["id"])
    return rows


def report(source: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    status_counts = collections.Counter(row["status"] for row in rows)
    product_rows: dict[str, list[dict[str, Any]]] = {
        product: [row for row in rows if product in row["products"]] for product in PRODUCTS
    }
    gaps = [row for row in rows if row["status"] in {"partial", "not_covered", "needs_review"}]
    high_gaps = [row for row in gaps if row["severity"] in {"critical", "high"}]
    methods = collections.Counter(row["classification_method"] for row in rows)
    source_conflicts = [row for row in rows if row["surface"] == "source-data"]
    lines = [
        "# Cross-server CVE root-cause matrix",
        "",
        f"Source: NVD CVE API 2.0 snapshot `{source['fetched_at']}`.",
        "CPE aliases and query provenance are retained in `cross-server-nvd.json`.",
        "Rows are deduplicated by CVE ID; one row may name multiple products.",
        "",
        "This is a static root-cause/design comparison, not a PoC result. A `partial`",
        "row is deliberately not counted as prevented until its exact primitive is",
        "mapped to a Vapache invariant or replay test.",
        f"Explicit advisory/patch overrides: **{methods['manual_override']}**; "
        f"conservative description/feature rules: **{methods['conservative_rule']}**.",
        "",
        "## Coverage",
        "",
        "| product | NVD records | partial/not-covered/review |",
        "|---|---:|---:|",
    ]
    for product, spec in PRODUCTS.items():
        selected = product_rows[product]
        open_count = sum(row["status"] in {"partial", "not_covered", "needs_review"} for row in selected)
        lines.append(f"| {spec['label']} | {len(selected)} | {open_count} |")
    lines += [
        "",
        f"Distinct CVEs: **{len(rows)}**",
        "",
        "| classification | count |",
        "|---|---:|",
    ]
    for status in ("prevented", "fail_closed", "not_applicable", "partial", "not_covered", "needs_review", "rejected"):
        lines.append(f"| `{status}` | {status_counts[status]} |")
    lines += [
        "",
        f"## High/critical review set ({len(high_gaps)})",
        "",
        "| CVE | Products | Severity | Surface | Root cause | Vapache comparison |",
        "|---|---|---|---|---|---|",
    ]
    for row in high_gaps:
        products = ", ".join(row["products"])
        lines.append(
            f"| {row['id']} | {products} | {row['severity']} | {row['surface']} | "
            f"{row['root_cause']} | {row['vapache_mapping']} |"
        )
    if source_conflicts:
        lines += [
            "",
            f"## NVD source-data conflicts ({len(source_conflicts)})",
            "",
            "These records are retained in the history but make no prevention claim because",
            "their public description and affected-product configuration disagree.",
            "",
            "| CVE | Products | Conflict |",
            "|---|---|---|",
        ]
        for row in source_conflicts:
            lines.append(
                f"| {row['id']} | {', '.join(row['products'])} | {row['root_cause']} |"
            )
    lines += [
        "",
        "The complete per-CVE analysis, implementation evidence and advisory links",
        "are in `cross-server-cve-matrix.json` and `.csv`.",
        "",
    ]
    return "\n".join(lines)


def csv_text(rows: list[dict[str, Any]]) -> str:
    fields = [
        "id", "year", "published", "last_modified", "vuln_status", "products", "severity",
        "score", "vector", "cwes", "status", "spec_prevents", "surface", "root_cause",
        "confidence", "classification_method", "analysis_basis", "vapache_mapping",
        "implementation_evidence", "description", "vulnerable_cpes", "references",
    ]
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        flattened = dict(row)
        for field in (
            "products", "cwes", "implementation_evidence", "vulnerable_cpes", "references"
        ):
            flattened[field] = "; ".join(str(value) for value in row[field])
        writer.writerow(flattened)
    return handle.getvalue()


def validation_errors(source: dict[str, Any], rows: list[dict[str, Any]]) -> list[str]:
    """Check that the snapshot and every generated comparison remain auditable."""
    errors: list[str] = []
    if source.get("schema") != 2:
        errors.append("source snapshot schema is stale; refresh with --fetch")
    if source.get("products") != PRODUCTS:
        errors.append("source query provenance differs from PRODUCTS; refresh with --fetch")

    records = source.get("records", [])
    record_ids = [record.get("id") for record in records]
    if len(record_ids) != len(set(record_ids)):
        errors.append("source snapshot contains duplicate CVE IDs")
    row_ids = [row["id"] for row in rows]
    if row_ids != sorted(record_ids):
        errors.append("generated row IDs do not exactly match the source snapshot")

    known_products = set(PRODUCTS)
    for record in records:
        ident = record.get("id", "<missing-id>")
        products = record.get("products", [])
        if not products or not set(products) <= known_products:
            errors.append(f"{ident}: missing or unknown product association")
        if "vulnerable_cpes" not in record:
            errors.append(f"{ident}: missing vulnerable CPE provenance")
    for product in PRODUCTS:
        actual = sum(product in record.get("products", []) for record in records)
        expected = source.get("product_counts", {}).get(product)
        if actual != expected:
            errors.append(f"{product}: product count {expected!r} does not match {actual}")

    stale_overrides = sorted(set(OVERRIDES) - set(record_ids))
    if stale_overrides:
        errors.append("manual overrides absent from source: " + ", ".join(stale_overrides))

    allowed_statuses = {
        "prevented", "fail_closed", "not_applicable", "partial",
        "not_covered", "needs_review", "rejected",
    }
    for row in rows:
        ident = row["id"]
        if row["status"] not in allowed_statuses:
            errors.append(f"{ident}: unknown status {row['status']!r}")
        if not row["root_cause"] or not row["vapache_mapping"]:
            errors.append(f"{ident}: missing root cause or Vapache comparison")
        if not row["implementation_evidence"]:
            errors.append(f"{ident}: missing implementation evidence")
        expected_method = "manual_override" if ident in OVERRIDES else "conservative_rule"
        if row["classification_method"] != expected_method:
            errors.append(f"{ident}: incorrect classification method")
        if row["spec_prevents"] != spec_prevents(row["status"]):
            errors.append(f"{ident}: status/spec_prevents disagreement")
    return errors


def write_outputs(source: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    OUT.write_text(json.dumps(rows, indent=2) + "\n")
    CSV_OUT.write_text(csv_text(rows))
    REPORT.write_text(report(source, rows) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true", help="refresh the NVD source snapshot")
    parser.add_argument("--check", action="store_true", help="validate generated outputs")
    args = parser.parse_args()
    if args.fetch:
        source = fetch()
        SOURCE.write_text(json.dumps(source, indent=2) + "\n")
    else:
        if not SOURCE.exists():
            parser.error(f"missing {SOURCE}; run with --fetch")
        source = json.loads(SOURCE.read_text())
    rows = build(source)
    errors = validation_errors(source, rows)
    if errors:
        for error in errors:
            print(f"cross-server CVE validation: {error}", file=sys.stderr)
        return 1
    if args.check:
        failures = []
        if not OUT.exists() or json.loads(OUT.read_text()) != rows:
            failures.append(str(OUT))
        expected_report = report(source, rows) + "\n"
        if not REPORT.exists() or REPORT.read_text() != expected_report:
            failures.append(str(REPORT))
        expected_csv = csv_text(rows)
        if not CSV_OUT.exists() or CSV_OUT.read_text() != expected_csv:
            failures.append(str(CSV_OUT))
        if failures:
            print("stale or missing cross-server CVE outputs: " + ", ".join(failures))
            return 1
        print(f"{OUT}: {len(rows)} distinct CVEs, matrix is current")
        return 0
    write_outputs(source, rows)
    counts = collections.Counter(row["status"] for row in rows)
    print(f"wrote {OUT}, {CSV_OUT}, and {REPORT} ({len(rows)} distinct CVEs)")
    print("status:", dict(counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
