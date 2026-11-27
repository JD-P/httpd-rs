---
doc_type: reference
audience: nginx-operator
status: draft
---

# nginx configuration frontend

httpd-rs can load either its established Apache 2.4 configuration language or
a deliberately bounded nginx HTTP subset. Both frontends compile into the same
source-neutral `ConfigIr`, policy objects, request planner, authorization gate,
backend identities, cache classifier, and terminal sinks. This is a second
configuration frontend, not an nginx runtime or module-compatibility layer.

Select it explicitly:

```sh
httpd-rs --config-format nginx -d /etc/nginx -f /etc/nginx/nginx.conf -t
httpd-rs --config-format nginx -d /etc/nginx -f /etc/nginx/nginx.conf
```

If `-f` is omitted, nginx mode reads `nginx.conf` below the selected server
root. Apache remains the default format so existing installations do not
change behavior.

## Semantic boundary

The frontend lexes includes and configuration with explicit size, depth,
statement, argument, token, location, and transformation bounds. Unknown
directives are errors. A request-handling directive whose nginx semantics
cannot be represented exactly by the shared IR is also an error; it is never
silently translated to the nearest Apache feature. A small documented class of
operational tuning and log-format declarations is instead normalized to the
bounded httpd-rs implementation and emits a configuration warning. Include
globs use nginx's lexical ordering and empty-glob behavior, while their parent
directories remain registered as administrative trust boundaries.

Source-language defaults are emitted into the IR before user directives, so
an omitted setting does not fall through to an Apache default. In particular,
the default document root is `<server-root>/html`, the request-body ceiling is
1 MiB, keep-alive idle time is 75 seconds, and a connection may serve 1000
requests. `client_max_body_size 0` removes that semantic ceiling as it does in
nginx; httpd-rs's independent resident-memory, spool, rate and concurrency
budgets still apply.

The supported request-routing core includes:

- `http`, `server`, and flat `location` blocks;
- exact (`=`), literal-prefix, `^~`, case-sensitive regex (`~`), and
  case-insensitive regex (`~*`) locations with nginx winner selection;
- literal and wildcard `server_name` values, including nginx's exact-name and
  longest-wildcard precedence; regex/variable names are rejected;
- `listen` addresses plus `default_server`, `ssl`, and `http2`; other listen
  options are rejected rather than ignored;
- static `root` and literal-prefix `alias`, index files, bounded static
  `try_files`, MIME `types`, autoindex, local `error_page`, nonnegative
  `expires`, exact literal `return` redirects, Basic authentication, gzip
  policy, TLS files/protocols, HTTP/2, reverse proxy, WebSocket forwarding,
  round-robin upstreams, and FastCGI;
- scoped `client_max_body_size`, literal response headers with nginx's
  replacement inheritance, common logging forms, and a finite set of
  operational tuning directives that httpd-rs owns and reports as normalized.

Explicit `default_server` blocks are compiled ahead of ordinary blocks for the
same listener. A configuration that mixes default and non-default listener
identities in one server block is rejected because a single Apache-style vhost
order cannot encode that shape without ambiguity.

Nested and named locations, arbitrary `map`, `if`, `set`, `rewrite`, dynamic
module scripting, variable backend targets, non-round-robin upstream selection,
ordered nginx `allow`/`deny`, and stream/mail configuration are outside this
frontend. The conventional WebSocket map from `$http_upgrade` to
`$connection_upgrade` is the only accepted `map`.

`try_files` deliberately accepts the conventional bounded static forms:
`$uri`, optional `$uri/`, and either `=404` or one absolute local fallback
with an optional complete `$args`/`$query_string` suffix. Named-location,
variable, and arbitrary expression fallbacks are rejected. `alias` is limited
to literal exact/prefix locations because regex captures would introduce a
second template language. `error_page` accepts ordinary error codes and a
literal local or HTTP(S) target; status substitution and named locations are
rejected. `expires` accepts `off`, zero, and nonnegative bounded durations;
calendar/negative forms that cannot be represented exactly fail closed.
Common proxy/FastCGI connect, read and send timeout declarations are parsed
and bounded, then normalized to httpd-rs's cancellation deadlines with a load
warning; they cannot widen the daemon's resource budget. `gzip_comp_level`
maps exactly to the shared DEFLATE level, while `gzip_vary` is normalized to
the cache-safe behavior that always emits `Vary` for negotiable responses.
`proxy_redirect off|default`, `fastcgi_index`, and the conventional PHP
`fastcgi_split_path_info` form are also accepted; custom redirect and split
expressions remain outside the closed grammar.

## Proxy headers and FastCGI parameters

`proxy_set_header` and `fastcgi_param` do not become arbitrary string-template
interpreters. Their values are parsed into a closed expression grammar with at
most 32 literal/variable segments and a 16 KiB result. Supported variables are
the ordinary request, authority, connection, URI, CGI identity, selected
document-root, header, cookie, and query-argument values used by conventional
proxy and FastCGI configurations. Any unknown variable fails configuration
loading.

The runtime revalidates every evaluated proxy field before serialization.
`Transfer-Encoding`, `TE`, trailers, and `Content-Length` remain owned
by the HTTP serializer. `Connection` and `Upgrade` accept only their finite
WebSocket forms. Client-supplied `X-Forwarded-For` is not promoted to a trusted
assertion: `$proxy_add_x_forwarded_for` emits the canonical peer address.

FastCGI parameter output is capped at 64 KiB. Standard CGI/request identity
fields may be restated only if the evaluated value equals the already
authorized identity. Custom application parameters may be added.
`SCRIPT_FILENAME` can be derived only from the authorized request filename,
document root, real-path root, FastCGI script name, and literals. Dynamic PHP
configuration values must be root-controlled literals.

`add_header` currently accepts literal values only. Its array inheritance is
represented explicitly: the first child declaration replaces the inherited
header set, while a child with no declarations inherits it. Internal
`try_files` and `error_page` redirects reselect the target location's response
policy rather than retaining Apache's outer-location finalizer.

Literal `proxy_pass` URI projection is preserved: a backend without a URI part
receives the complete canonical request path, while a backend URI replaces the
selected literal location prefix. nginx itself forbids a URI part in a regex
location, and this frontend rejects it as well. The same bounded projection is
supported for named round-robin upstreams, so `proxy_pass http://app/base/`
retains `/base/` before selecting a member.

Literal `return 301|302|303|307|308 URL` is represented as an exact terminal
redirect rather than an Apache prefix redirect. It therefore neither appends
the unmatched request path nor preserves the original query implicitly.

## Extensions and capabilities

Security-sensitive runtime capabilities remain explicit in nginx mode:

```nginx
httpd_rs_capability FastCgi On;
httpd_rs_fastcgi_stable_path On unix:/run/php/php-fpm.sock 33 0 0;
```

These two `httpd_rs_*` directives are the only frontend extensions. They map
to the same capability and stable-path checks used by Apache configuration.

## Testing the frontend

Unit tests compare overlapping Apache and nginx configurations after compilation
and exercise the exact route machine. The parser/lowerer is a long-fuzz target.
Its structured projection enumerates route matcher, route action, server-name,
body-limit, expiry and compression families even when mutation corrupts the
raw configuration grammar. To seed a run from the separately downloaded
public corpus without committing third-party configuration files, use:

```sh
tests/long_fuzz.sh --targets nginx_config --hours 12 \
  --nginx-corpus /path/to/extracted-nginx-corpus
```

When a stock nginx binary is installed, run the end-to-end oracle differential:

```sh
cargo build -p httpd-rs
python3 tests/nginx_differential.py
```

It starts both binaries on loopback from temporary configuration and roots,
then compares exact, `^~`, regex, longest-prefix, and fallback route outcomes;
direct and named-upstream URI projection; evaluated request headers; exact
redirect projection; alias, try-files, error-page and expiry behavior; header
replacement inheritance; and scoped request-body admission. A minimal
FastCGI oracle also compares the script, request-URI, Host, and custom
parameter values emitted by both servers. `--benchmark` additionally runs the
same static and proxy deployment through httpd-rs's Apache- and nginx-syntax
frontends. This optional test skips when nginx is absent; nginx is not a build
dependency.
