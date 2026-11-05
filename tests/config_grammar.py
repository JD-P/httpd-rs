#!/usr/bin/env python3
"""Finite grammar check for supported Apache configuration contexts.

The goal is to make the supported subset explicit: for each directive we
support, enumerate the contexts in which Apache accepts it and compare
`apache2 -t` with `vapached -t`.  This is the executable approximation of the
two acceptance/rejection obligations:

  * every valid Apache configuration in the supported subset is accepted;
  * every configuration we call invalid in that subset is rejected.

It is not a proof over arbitrary Apache syntax; it is an exhaustive check over
the finite grammar below.  Add directives/contexts here when support grows.
"""

import argparse
import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VAPACHED = Path(os.environ.get("VAPACHED", ROOT / "target" / "release" / "vapached"))
APACHE = shutil.which("apache2") or "/usr/sbin/apache2"


def load_validity():
    path = Path(__file__).with_name("config_validity.py")
    spec = importlib.util.spec_from_file_location("config_validity", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


V = load_validity()
BASE = V.BASE
DOCROOT = V.DOCROOT
PORT = V.PORT


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30)


def contexts():
    return {
        "server": ("", ""),
        "vhost": (
            f"<VirtualHost *:{PORT}>\n",
            "</VirtualHost>\n",
        ),
        "directory": (f'<Directory "{DOCROOT}/x">\n', "</Directory>\n"),
        "directorymatch": (f'<DirectoryMatch "^{DOCROOT}/x">\n', "</DirectoryMatch>\n"),
        "files": ('<Files "x">\n', "</Files>\n"),
        "location": ('<Location "/x">\n', "</Location>\n"),
        "if": ('<If "true">\n', "</If>\n"),
        "limit": (
            f'<Directory "{DOCROOT}/x">\n    <Limit GET>\n',
            "    </Limit>\n</Directory>\n",
        ),
        "requireall": (
            f'<Directory "{DOCROOT}/x">\n    <RequireAll>\n',
            "    </RequireAll>\n</Directory>\n",
        ),
    }


DIRECTIVES = [
    ("require", "Require all granted\n"),
    ("order", "Order allow,deny\n"),
    ("allow", "Allow from all\n"),
    ("deny", "Deny from all\n"),
    ("satisfy", "Satisfy any\n"),
    ("auth", f"AuthType Basic\nAuthName x\nAuthUserFile {BASE}/htpasswd\n"),
    ("authmerging", "AuthMerging And\n"),
    ("allowoverride", "AllowOverride All\n"),
    ("allowoverridelist", "AllowOverrideList Require\n"),
    ("allowmethods", "AllowMethods GET\n"),
    ("options", "Options Indexes\n"),
    ("directoryindex", "DirectoryIndex index.html\n"),
    ("header", "Header set X yes\n"),
    ("setenvif", "SetEnvIf X yes Y\n"),
    ("rewriteengine", "RewriteEngine On\n"),
    ("errordocument", "ErrorDocument 404 /x\n"),
    ("limitdirective", None),  # handled by the limit context only
]

INVALID = [
    ("bad-allowoverride", "AllowOverride NotACategory\n"),
    ("bad-allowoverridelist-none", f'<Directory "{DOCROOT}/x">\nAllowOverride None\nAllowOverrideList None Require\n</Directory>\n'),
    ("bad-require-ip", f'<Directory "{DOCROOT}/x">\nRequire ip not-an-ip\n</Directory>\n'),
    ("bad-require-method", f'<Directory "{DOCROOT}/x">\nRequire method BOGUS\n</Directory>\n'),
    ("bad-order", f'<Directory "{DOCROOT}/x">\nOrder nonsense\n</Directory>\n'),
    ("bad-satisfy", f'<Directory "{DOCROOT}/x">\nSatisfy nonsense\n</Directory>\n'),
    ("bad-allowmethods", f'<Directory "{DOCROOT}/x">\nAllowMethods BOGUS\n</Directory>\n'),
    ("bad-limit-method", f'<Directory "{DOCROOT}/x">\n<Limit BOGUS>\nRequire all granted\n</Limit>\n</Directory>\n'),
    ("bad-limit-trace", f'<Directory "{DOCROOT}/x">\n<Limit TRACE>\nRequire all granted\n</Limit>\n</Directory>\n'),
    ("bad-directory-regex", '<DirectoryMatch "[">\nRequire all granted\n</DirectoryMatch>\n'),
    ("bad-errordocument", f'<Directory "{DOCROOT}/x">\nErrorDocument nope /x\n</Directory>\n'),
    ("unmatched-section", f'<Directory "{DOCROOT}/x">\nRequire all granted\n'),
    ("nested-directory", f'<Directory "{DOCROOT}">\n<Directory "{DOCROOT}/x">\nRequire all granted\n</Directory>\n</Directory>\n'),
    ("files-inside-location", f'<Location "/x">\n<Files "x">\nRequire all granted\n</Files>\n</Location>\n'),
    ("limit-outside-directory", "<Limit GET>\nRequire all granted\n</Limit>\n"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    if not VAPACHED.exists():
        sys.exit(f"missing {VAPACHED}")
    try:
        DOCROOT.mkdir(parents=True, exist_ok=True)
        os.chmod(BASE, 0o755)
        os.chmod(DOCROOT, 0o755)
        (BASE / "logs").mkdir(exist_ok=True)
        os.chmod(BASE / "logs", 0o777)
        (BASE / "htpasswd").write_text("alice:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=\n")
        failures = 0

        def compare(name, snippet):
            nonlocal failures
            acfg = BASE / "grammar-apache.conf"
            vcfg = BASE / "grammar-vapache.conf"
            acfg.write_text(V.prefix(PORT) + snippet)
            vcfg.write_text(V.VAPACHE_CAPABILITIES + V.prefix(PORT + 1) + snippet)
            a = run([APACHE, "-t", "-f", str(acfg)])
            v = run([str(VAPACHED), "-t", "-f", str(vcfg)])
            aok = a.returncode == 0
            vok = v.returncode == 0
            if aok != vok:
                failures += 1
                print(f"DIFF {name}: apache={aok} vapache={vok}")
                print(f"  apache: {(a.stderr or a.stdout).strip()[-500:]}")
                print(f"  vapache: {(v.stderr or v.stdout).strip()[-500:]}")
            elif args.verbose:
                print(f"ok   {name}: {aok}")

        for cname, (open_tag, close_tag) in contexts().items():
            for dname, body in DIRECTIVES:
                if body is None:
                    continue
                compare(
                    f"{cname}/{dname}",
                    open_tag + body + close_tag,
                )
        # The <Limit> container itself is only valid inside a directory.
        compare(
            "limit/section",
            f'<Directory "{DOCROOT}/x">\n<Limit GET>\nRequire all granted\n</Limit>\n</Directory>\n',
        )
        for name, snippet in INVALID:
            compare(name, snippet)

        print(f"\n{failures} grammar divergence(s)")
        print(f"tree: {BASE}")
        return 1 if failures else 0
    finally:
        shutil.rmtree(BASE, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
