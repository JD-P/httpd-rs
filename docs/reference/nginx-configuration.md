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

The supported request-routing core includes:

- `http`, `server`, and flat `location` blocks;
- exact (`=`), literal-prefix, `^~`, case-sensitive regex (`~`), and
  case-insensitive regex (`~*`) locations with nginx winner selection;
- literal and wildcard `server_name` values, including nginx's exact-name and
  longest-wildcard precedence; regex/variable names are rejected;
- `listen` addresses plus `default_server`, `ssl`, and `http2`; other listen
  options are rejected rather than ignored;
- static roots, index files, bounded static `try_files`, MIME `types`, autoindex,
  exact literal `return` redirects, Basic authentication, gzip policy, TLS files/protocols,
  HTTP/2, reverse proxy, WebSocket forwarding, round-robin upstreams, and
  FastCGI;
- literal response headers, common logging forms, and a finite set of
  operational tuning directives that httpd-rs owns and reports as normalized.

Explicit `default_server` blocks are compiled ahead of ordinary blocks for the
same listener. A configuration that mixes default and non-default listener
identities in one server block is rejected because a single Apache-style vhost
order cannot encode that shape without ambiguity.

Nested and named locations, arbitrary `map`, `if`, `set`, `rewrite`, dynamic
module scripting, variable backend targets, non-round-robin upstream selection,
ordered nginx `allow`/`deny`, and stream/mail configuration are outside this
frontend. The conventional WebSocket map from `$http_upgrade` to
`$connection_upgrade` is the only accepted `map`. Scoped
`client_max_body_size` is rejected until body admission is driven by the route
IR. `error_page` is rejected until its internal-request projection is part of
the source-neutral terminal-outcome model.

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

`add_header` currently accepts literal values only. A configuration that
declares `add_header` both in an inherited scope and a child location is
rejected because nginx replaces the inherited set while Apache merges it.

Literal `proxy_pass` URI projection is preserved: a backend without a URI part
receives the complete canonical request path, while a backend URI replaces the
selected literal location prefix. nginx itself forbids a URI part in a regex
location, and this frontend rejects it as well. A URI suffix on a named
`upstream` currently fails configuration loading because the bounded balancer
IR does not yet carry that second path projection; direct literal backends and
named upstreams without a suffix are supported.

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
When a stock nginx binary is installed, run the end-to-end oracle differential:

```sh
cargo build -p httpd-rs
python3 tests/nginx_differential.py
```

It starts both binaries on loopback from temporary configuration and roots,
then compares exact, `^~`, regex, longest-prefix, and fallback route outcomes,
both forms of proxy URI projection, evaluated request headers, and exact
redirect projection. A minimal FastCGI oracle also compares the script,
request-URI, Host, and custom parameter values emitted by both servers. This
optional test skips when nginx is absent; nginx is not a build dependency.
