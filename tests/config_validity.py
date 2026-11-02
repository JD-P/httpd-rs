#!/usr/bin/env python3
"""Compare Apache/vapached acceptance of security-sensitive config contexts.

Many directives are accepted by one server in a context where the other
rejects them.  A permissive parser is not automatically a vulnerability, but
for access-control directives it is exactly the kind of surprise that turns
into a bypass.  This harness deliberately uses `-t` only: the question is
whether the configuration is accepted, not how it behaves after startup.
The MALFORMED_CASES rows require Apache, normal Vapache, and strict Vapache to
reject the same malformed directive. HARDENED_CASES records legacy inputs that
Apache 2.4 accepts through empty/default/numeric coercions but that Vapache
deliberately rejects rather than guessing at policy. Compatibility mode must
never turn either class into an accepted no-op.
"""

import argparse
import os
import grp
import pwd
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VAPACHED = Path(os.environ.get("VAPACHED", ROOT / "target" / "release" / "vapached"))
APACHE = os.environ.get("APACHE", shutil.which("apache2") or "/usr/sbin/apache2")
MODDIR = Path(
    os.environ.get(
        "APACHE_MODDIR",
        "/usr/lib/apache2/modules"
        if Path("/usr/lib/apache2/modules").is_dir()
        else "/workspace/.vapache-setup/sysroot/usr/lib/apache2/modules",
    )
)
BASE = Path(tempfile.mkdtemp(prefix="vapache-config-validity-"))
DOCROOT = BASE / "www"
PORT = 18190
SERVICE_USER = "www-data" if os.geteuid() == 0 else pwd.getpwuid(os.geteuid()).pw_name
SERVICE_GROUP = "www-data" if os.getegid() == 0 else grp.getgrgid(os.getegid()).gr_name

MODULES = [
    "mpm_event_module",
    "mime_module",
    "dir_module",
    "alias_module",
    "autoindex_module",
    "authz_core_module",
    "authz_host_module",
    "access_compat_module",
    "allowmethods_module",
    "headers_module",
    "env_module",
    "setenvif_module",
    "auth_basic_module",
    "authn_core_module",
    "authn_file_module",
    "authz_user_module",
    "authz_groupfile_module",
    "rewrite_module",
    "proxy_module",
    "proxy_balancer_module",
    "proxy_hcheck_module",
    "expires_module",
    "filter_module",
    "deflate_module",
    "brotli_module",
    "reqtimeout_module",
    "remoteip_module",
    "cache_module",
    "cache_disk_module",
    "socache_shmcb_module",
    "ssl_module",
]

VAPACHE_CAPABILITIES = """VapacheCapability AbsoluteRequestTarget On
VapacheCapability AccessFiles On
VapacheCapability AutoIndex On
VapacheCapability Cgi On
VapacheCapability FastCgi On
VapacheCapability LegacyAuthz On
VapacheCapability RequestTrailers On
VapacheCapability RewriteProgram On
VapacheCapability ServerStatus On
VapacheCapability Trace On
VapacheCapability UnstableFastCgiPaths On
VapacheCapability MutableAuthFiles On
"""


def prefix(port: int) -> str:
    lines = []
    for mod in MODULES:
        lines.append(f"LoadModule {mod} {MODDIR}/mod_{mod.replace('_module','')}.so")
    lines += [
        f'ServerRoot "{BASE}"',
        f"Listen {port}",
        f"User {SERVICE_USER}",
        f"Group {SERVICE_GROUP}",
        f"PidFile {BASE}/logs/httpd-{port}.pid",
        f"ErrorLog {BASE}/logs/error-{port}.log",
        "LogLevel warn",
        "ServerName localhost",
        f'DocumentRoot "{DOCROOT}"',
        "TypesConfig /etc/mime.types",
        "DirectoryIndex index.html",
        "<Directory />",
        "    AllowOverride None",
        "    Require all denied",
        "</Directory>",
        f'<Directory "{DOCROOT}">',
        "    Options FollowSymLinks",
        "    AllowOverride None",
        "    Require all granted",
        "</Directory>",
    ]
    return "\n".join(lines) + "\n"


CASES = [
    ("server-level AllowOverride", "AllowOverride All\n"),
    (
        "AllowOverride in Location",
        f'<Location "/x">\n    AllowOverride All\n</Location>\n',
    ),
    (
        "AllowOverride in Directory tilde regex",
        f'<Directory ~ "^{DOCROOT}/x">\n    AllowOverride All\n</Directory>\n',
    ),
    (
        "AllowOverride in DirectoryMatch",
        f'<DirectoryMatch "^{DOCROOT}/x">\n    AllowOverride All\n</DirectoryMatch>\n',
    ),
    (
        "AllowOverride in Files",
        '<Files "x">\n    AllowOverride All\n</Files>\n',
    ),
    (
        "AllowOverride in VirtualHost",
        f"<VirtualHost *:{PORT}>\n    ServerName vh.test\n    AllowOverride All\n</VirtualHost>\n",
    ),
    (
        "nested Directory",
        f'<Directory "{DOCROOT}">\n    <Directory "{DOCROOT}/sub">\n        AllowOverride None\n    </Directory>\n</Directory>\n',
    ),
    (
        "Directory inside Location",
        f'<Location "/x">\n    <Directory "{DOCROOT}/x">\n        Require all granted\n    </Directory>\n</Location>\n',
    ),
    (
        "Location inside Directory",
        f'<Directory "{DOCROOT}/x">\n    <Location "/x">\n        Require all granted\n    </Location>\n</Directory>\n',
    ),
    (
        "Files inside Location",
        '<Location "/x">\n    <Files "x">\n        Require all denied\n    </Files>\n</Location>\n',
    ),
    (
        "Limit outside Directory",
        "<Limit POST>\n    Require all denied\n</Limit>\n",
    ),
    (
        "RequireAll at server level",
        "<RequireAll>\n    Require all granted\n</RequireAll>\n",
    ),
    (
        "RequireAll in VirtualHost",
        f"<VirtualHost *:{PORT}>\n    ServerName vh.test\n    <RequireAll>\n        Require all granted\n    </RequireAll>\n</VirtualHost>\n",
    ),
    (
        "Satisfy at server level",
        "Satisfy any\n",
    ),
    (
        "Order at server level",
        "Order allow,deny\n",
    ),
    (
        "Allow at server level",
        "Allow from all\n",
    ),
    (
        "AuthType at server level",
        "AuthType Basic\n",
    ),
    (
        "Require at server level",
        "Require all denied\n",
    ),
    (
        "Require in VirtualHost",
        f"<VirtualHost *:{PORT}>\n    ServerName vh.test\n    Require all denied\n</VirtualHost>\n",
    ),
    (
        "Limit in Location",
        '<Location "/x">\n    <Limit POST>\n        Require all denied\n    </Limit>\n</Location>\n',
    ),
    (
        "Limit in Files",
        '<Files "x">\n    <Limit POST>\n        Require all denied\n    </Limit>\n</Files>\n',
    ),
    (
        "legacy Location tilde regex",
        '<Location ~ "^/private/">\n    Require all denied\n</Location>\n',
    ),
    (
        "legacy Files tilde regex",
        '<Files ~ "^secret\\.txt$">\n    Require all denied\n</Files>\n',
    ),
    (
        "RequireAll inside If at server level",
        "<If \"%{HTTP:X} == 'yes'\">\n    <RequireAll>\n        Require all granted\n    </RequireAll>\n</If>\n",
    ),
    (
        "AllowOverride in If inside Directory",
        f"<Directory \"{DOCROOT}\">\n    <If \"%{{HTTP:X}} == 'yes'\">\n        AllowOverride All\n    </If>\n</Directory>\n",
    ),
    (
        "Directory inside Proxy",
        '<Proxy "http://example.invalid/">\n    <Directory "/srv">\n        Require all granted\n    </Directory>\n</Proxy>\n',
    ),
    (
        "Proxy inside Directory",
        f'<Directory "{DOCROOT}">\n    <Proxy "http://example.invalid/">\n        Require all granted\n    </Proxy>\n</Directory>\n',
    ),
    (
        "Directory inside If",
        f'<If "%{{HTTP:X}} == \'yes\'">\n    <Directory "{DOCROOT}">\n        Require all granted\n    </Directory>\n</If>\n',
    ),
    (
        "Require inside If at server level",
        "<If \"%{HTTP:X} == 'yes'\">\n    Require all denied\n</If>\n",
    ),
    (
        "AuthType inside If at server level",
        "<If \"%{HTTP:X} == 'yes'\">\n    AuthType Basic\n</If>\n",
    ),
    (
        "AllowOverrideList at server level",
        "AllowOverrideList Require\n",
    ),
    (
        "AllowOverrideList None with directive",
        f'<Directory "{DOCROOT}">\n    AllowOverride None\n    AllowOverrideList None Require\n</Directory>\n',
    ),
    (
        "valid AllowOverrideList",
        f'<Directory "{DOCROOT}">\n    AllowOverride None\n    AllowOverrideList Require\n</Directory>\n',
    ),
    (
        "Include fragment",
        f"Include {BASE}/inc.conf\n",
    ),
    (
        "IncludeOptional missing",
        f"IncludeOptional {BASE}/does-not-exist.conf\n",
    ),
    (
        "valid Directory AllowOverride",
        f'<Directory "{DOCROOT}/ok">\n    AllowOverride All\n</Directory>\n',
    ),
    (
        "Require all rejects extra operands",
        f'<Directory "{DOCROOT}">\n    Require all granted denied\n</Directory>\n',
    ),
    (
        "negative Require is invalid in implicit RequireAny",
        f'<Directory "{DOCROOT}">\n    Require not ip 192.0.2.1\n</Directory>\n',
    ),
    (
        "RequireAny rejects a negative provider",
        f'<Directory "{DOCROOT}">\n    <RequireAny>\n'
        "        Require not ip 192.0.2.1\n"
        "    </RequireAny>\n</Directory>\n",
    ),
    (
        "RequireAll rejects only-negative providers",
        f'<Directory "{DOCROOT}">\n    <RequireAll>\n'
        "        Require not ip 192.0.2.1\n"
        "    </RequireAll>\n</Directory>\n",
    ),
    (
        "RequireNone cannot independently authorize",
        f'<Directory "{DOCROOT}">\n    <RequireNone>\n'
        "        Require ip 192.0.2.1\n"
        "    </RequireNone>\n</Directory>\n",
    ),
    (
        "unknown conditional section is not transparent",
        f'<Directory "{DOCROOT}">\n    <DefinitelyMissingSection>\n'
        "        Require all granted\n"
        "    </DefinitelyMissingSection>\n</Directory>\n",
    ),
    (
        "IfModule requires an operand",
        f'<Directory "{DOCROOT}">\n    <IfModule>\n'
        "        Require all granted\n"
        "    </IfModule>\n</Directory>\n",
    ),
]

# Apache rejects each of these snippets at plain `-t`. Vapache must reject
# them in every mode rather than discarding the malformed policy payload.
MALFORMED_CASES = [
    ("AddType requires two args", "AddType image/png\n"),
    ("AddHandler requires two args", "AddHandler cgi-script\n"),
    ("Header requires an action pair", "Header set\n"),
    ("ExpiresByType requires type + code", "ExpiresByType text/html\n"),
    ("ProxyPass requires path and url", "ProxyPass /x\n"),
    ("RewriteOptions unknown token", "RewriteEngine On\nRewriteOptions Bogus\n"),
    (
        "Options unknown token",
        f'<Directory "{DOCROOT}">\n    Options Bogus\n</Directory>\n',
    ),
    (
        "ProxyPass failonstatus unparsable",
        "ProxyPass /b http://127.0.0.1:1/ failonstatus=9xx,foo\n",
    ),
    (
        "ProxySet failonstatus unparsable",
        '<Proxy "balancer://alpha">\n'
        '    BalancerMember "http://127.0.0.1:1"\n'
        "    ProxySet failonstatus=9xx,foo\n"
        "</Proxy>\n",
    ),
    ("FileETag unknown keyword", "FileETag Unknown\n"),
    ("EnableSendfile invalid boolean", "EnableSendfile Maybe\n"),
    ("DirectorySlash invalid boolean", "DirectorySlash Maybe\n"),
    ("ExpiresActive invalid boolean", "ExpiresActive Maybe\n"),
    ("KeepAlive invalid boolean", "KeepAlive Maybe\n"),
    ("KeepAliveTimeout invalid duration", "KeepAliveTimeout nope\n"),
    ("HostnameLookups invalid value", "HostnameLookups Maybe\n"),
    ("ServerTokens invalid value", "ServerTokens Unknown\n"),
    ("ServerSignature invalid value", "ServerSignature Maybe\n"),
    ("RequestReadTimeout invalid syntax", "RequestReadTimeout nonsense\n"),
    ("LimitRequestBody invalid integer", "LimitRequestBody nope\n"),
    ("AllowEncodedSlashes invalid value", "AllowEncodedSlashes Maybe\n"),
    ("DeflateCompressionLevel out of range", "DeflateCompressionLevel 100\n"),
    ("DeflateAlterETag invalid value", "DeflateAlterETag Bogus\n"),
    ("SSLProtocol unknown token", "SSLProtocol nonsense\n"),
    ("SSLPassPhraseDialog invalid value", "SSLPassPhraseDialog nonsense\n"),
    ("SSLStaplingCache invalid value", "SSLStaplingCache nonsense\n"),
    ("ProxyPass unknown parameter", "ProxyPass /x http://127.0.0.1:1/ unknown=yes\n"),
    ("ProxyPassReverse requires backend", "ProxyPassReverse /x\n"),
    ("ProxyPassMatch requires backend", "ProxyPassMatch ^/x$\n"),
    ("AddOutputFilterByType requires type", "AddOutputFilterByType DEFLATE\n"),
    ("CustomLog requires format", "CustomLog logs/access.log\n"),
    ("SetEnv rejects an unquoted extra value", "SetEnv NAME one two\n"),
    ("ServerRoot rejects an extra value", f'ServerRoot "{BASE}" extra\n'),
    ("Define rejects an extra value", "Define NAME value extra\n"),
    ("Undefine requires one name", "Undefine NAME extra\n"),
    ("LoadModule rejects an extra value", "LoadModule dummy_module nowhere.so extra\n"),
    ("Include requires one path", f'Include "{BASE}/inc.conf" extra\n'),
    ("Directory rejects an extra path", "<Directory /x /y>\n</Directory>\n"),
    ("Location rejects an extra pattern", "<Location /x /y>\n</Location>\n"),
    ("Files rejects an extra pattern", "<Files x y>\n</Files>\n"),
    ("Proxy rejects an extra URL", "<Proxy http://a http://b>\n</Proxy>\n"),
    ("Else rejects operands", "<If true>\n</If>\n<Else ignored>\n</Else>\n"),
]

# Apache 2.4 currently accepts these legacy coercions/presentation forms. They
# are not compatibility requirements: Vapache treats each one as ambiguous
# policy and rejects it in every mode.
HARDENED_CASES = [
    ("Options requires an operand", f'<Directory "{DOCROOT}">\nOptions\n</Directory>\n'),
    ("ExpiresDefault invalid duration", "ExpiresDefault nonsense\n"),
    ("ErrorDocument rejects a non-error status", "ErrorDocument 200 /error.html\n"),
    ("Timeout invalid integer", "Timeout nope\n"),
    ("LimitRequestLine invalid integer", "LimitRequestLine nope\n"),
    ("IfFile rejects extra operand", "<IfFile first second>\n</IfFile>\n"),
    ("explicit cipher policy is unsupported", "SSLCipherSuite HIGH\n"),
    ("conditional Header is unsupported", "Header set X-Test yes env=FLAG\n"),
    (
        "conditional CustomLog is unsupported",
        "CustomLog logs/access.log combined env=FLAG\n",
    ),
    ("module-specific LogLevel is unsupported", "LogLevel ssl:info\n"),
    (
        "RewriteRule DPI flag is unsupported",
        "RewriteEngine On\nRewriteRule ^/x$ /y [DPI]\n",
    ),
    (
        "RewriteRule NS flag is unsupported",
        "RewriteEngine On\nRewriteRule ^/x$ /y [NS]\n",
    ),
    (
        "unsupported nested Files inside If is not evaluated by Apache",
        '<If "true">\n<Files "secret.txt">\nRequire all granted\n</Files>\n</If>\n',
    ),
]


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=20)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if not VAPACHED.exists():
        sys.exit(f"missing {VAPACHED}; cargo build --release first")
    if not Path(APACHE).exists():
        sys.exit(f"missing Apache httpd at {APACHE}")
    try:
        DOCROOT.mkdir(parents=True, exist_ok=True)
        os.chmod(BASE, 0o755)
        os.chmod(DOCROOT, 0o755)
        (BASE / "logs").mkdir(exist_ok=True)
        os.chmod(BASE / "logs", 0o777)
        (BASE / "inc.conf").write_text(
            f'<Directory "{DOCROOT}/inc">\n    Require all denied\n</Directory>\n'
        )
        (DOCROOT / "inc").mkdir(exist_ok=True)
        failures = 0
        for name, snippet in CASES:
            acfg = BASE / "apache.conf"
            vcfg = BASE / "vapache.conf"
            acfg.write_text(prefix(PORT) + snippet)
            vcfg.write_text(VAPACHE_CAPABILITIES + prefix(PORT + 1) + snippet)
            a = run([APACHE, "-t", "-f", str(acfg)])
            v = run([str(VAPACHED), "-t", "-f", str(vcfg)])
            aok = a.returncode == 0
            vok = v.returncode == 0
            status = "ok  " if aok == vok else "DIFF"
            if aok != vok:
                failures += 1
            print(f"{status} {name}: apache={aok} vapache={vok}")
            if args.verbose or aok != vok:
                print(f"  apache: {(a.stderr or a.stdout).strip()[-500:]}")
                print(f"  vapache: {(v.stderr or v.stdout).strip()[-500:]}")
        malformed_failures = 0
        for name, snippet in MALFORMED_CASES:
            acfg = BASE / "apache.conf"
            vcfg = BASE / "vapache.conf"
            acfg.write_text(prefix(PORT) + snippet)
            vcfg.write_text(VAPACHE_CAPABILITIES + prefix(PORT + 1) + snippet)
            a = run([APACHE, "-t", "-f", str(acfg)])
            v = run([str(VAPACHED), "-t", "-f", str(vcfg)])
            s = run([str(VAPACHED), "-t", "--strict-config", "-f", str(vcfg)])
            aok = a.returncode == 0
            vok = v.returncode == 0
            sok = s.returncode == 0
            # Expected triple: every parser refuses malformed input.
            bad = aok or vok or sok
            status = "reject" if not bad else "MALFORMED-DIFF"
            if bad:
                malformed_failures += 1
            print(f"{status} {name}: apache={aok} vapache={vok} strict={sok}")
            if args.verbose or bad:
                print(f"  apache: {(a.stderr or a.stdout).strip()[-400:]}")
                print(f"  vapache: {(v.stderr or v.stdout).strip()[-300:]}")
                print(f"  strict: {(s.stderr or s.stdout).strip()[-300:]}")
        hardened_failures = 0
        for name, snippet in HARDENED_CASES:
            acfg = BASE / "apache.conf"
            vcfg = BASE / "vapache.conf"
            acfg.write_text(prefix(PORT) + snippet)
            vcfg.write_text(VAPACHE_CAPABILITIES + prefix(PORT + 1) + snippet)
            a = run([APACHE, "-t", "-f", str(acfg)])
            v = run([str(VAPACHED), "-t", "-f", str(vcfg)])
            s = run([str(VAPACHED), "-t", "--strict-config", "-f", str(vcfg)])
            aok = a.returncode == 0
            vok = v.returncode == 0
            sok = s.returncode == 0
            bad = vok or sok
            status = "hardened" if not bad else "HARDENING-REGRESSION"
            if bad:
                hardened_failures += 1
            print(f"{status} {name}: apache={aok} vapache={vok} strict={sok}")
            if args.verbose or bad:
                print(f"  apache: {(a.stderr or a.stdout).strip()[-400:]}")
                print(f"  vapache: {(v.stderr or v.stdout).strip()[-300:]}")
                print(f"  strict: {(s.stderr or s.stdout).strip()[-300:]}")
        print(f"\n{failures} context divergence(s)")
        print(f"{malformed_failures} malformed acceptance divergence(s)")
        print(f"{hardened_failures} hardening regression(s)")
        print(f"tree: {BASE}")
        return 1 if failures or malformed_failures or hardened_failures else 0
    finally:
        shutil.rmtree(BASE, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
