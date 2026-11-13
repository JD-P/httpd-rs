# Internal request transition review

This campaign reviewed every place where httpd-rs selects a new request target
without parsing a new request from the client.  The boundary includes local
`ErrorDocument`, `DirectoryIndex`, internal rewrites, CGI/FastCGI `PATH_INFO`,
deferred handler probes, and proxy query retargeting.

## Transition contract

| Transition | Method/body/query | Wire identity | Authorization and sink state |
|---|---|---|---|
| `DirectoryIndex` | preserves all three; POST is admitted until the selected target applies its own method policy | preserves the original method/target/version for `%{THE_REQUEST}` | directory is authorized first; the index URL is mapped and authorized again; prepared handlers retain target-bound grants |
| local `ErrorDocument` | becomes GET, discards the body/framing/expectation and representation or hop-by-hop headers, and uses only the configured target query | preserves the original method/target/version and client/TLS/vhost identity | the error target is mapped and authorized normally; one request-owned depth step prevents recursive recovery |
| internal rewrite | preserves method/body/wire target; only the explicit rewrite query changes | `%{THE_REQUEST}` remains the client request while `%{REQUEST_URI}` is the canonical rewritten path | original and final URL policy are conjoined; the final target is rebound |
| CGI/FastCGI `PATH_INFO` | no synthetic request is created | original request is retained | script path, inode, handler and backend bindings are explicit grant inputs |
| prepared handler probe | body acquisition completes after route selection | the request object remains the same outer request | typed CGI/FastCGI/proxy IR carries the authorized target and is rechecked at the sink |
| proxy query override | only the selected upstream query is temporarily projected | original request-target remains available to policy/logging | the prepared proxy grant binds the front path and concrete upstream target |

The executable projection and recursion-depth step are in the Verus crate and
are consumed directly by the dispatcher.  They prove that an error recovery
cannot preserve application method/body/query state, that a directory index
does preserve that state, that both preserve the client/wire identity, and
that an error request at depth one cannot transition again.

## Remediated flaws

1. **Deferred ErrorDocument body replay.**  The old shared helper cleared the
   cloned body while routing, but a prepared CGI/FastCGI/proxy handler later
   executed against the completed outer request.  A POST body, its framing,
   and its original query could therefore be delivered to a local error
   handler even though routing had inspected a bodyless clone.  The prepared
   finalizer now reconstructs the same verified GET projection at execution.

2. **DirectoryIndex/ErrorDocument semantic conflation.**  The shared helper
   cleared bodies for both transitions.  Immediate DirectoryIndex execution
   lost an application body, while deferred execution happened to regain it.
   DirectoryIndex now preserves method, body, framing and query in both paths;
   ErrorDocument clears them in both paths.

3. **Synthetic `%{THE_REQUEST}` identity.**  The helper replaced
   `Request::target` with the internal URL, and changing an ErrorDocument's
   dispatch method to GET would otherwise also rewrite the reported request
   line. Rewrite policy that intentionally inspected the original request
   line could therefore see a value that never appeared on the wire. Internal
   transitions now snapshot an immutable, clone-shared wire
   method/target/version identity and change only the canonicalization input
   (`raw_path`) plus the transition-authorized dispatch fields.

4. **ErrorDocument query confusion.**  A configured target such as
   `/error.cgi?status=404` was placed wholesale in `raw_path`, then the
   original query was appended to `target`, while `Request::query` still held
   the original bytes.  Mapping, policy and the handler could see three
   different identities.  The target is now split once into path and its own
   exact query; an absent target query means an empty error-handler query.

5. **Entity and upgrade state crossing into recovery.**  A GET error request
   could retain `Content-Length`, `Transfer-Encoding`, `Expect`, conditional
   range state, WebSocket upgrade state, or a field nominated by
   `Connection`.  Recovery now removes the complete entity/conditional/hop
   set, including connection-nominated extension fields, before any backend
   serializer can observe it.  Host, credentials, cookies and ordinary client
   context remain available for target authorization and customization.

6. **Thread-scoped recovery state.**  Recursion and cache provenance were
   thread-local booleans.  That made correctness depend on executor scheduling
   and explicit reset order instead of the request/response that owned the
   state.  Recursion depth now travels in the cloned request.  A local error
   response marks itself ineligible for shared caching, so provenance travels
   through deferred execution and cannot bleed between requests.

7. **POST stopped before DirectoryIndex selection.**  httpd-rs rejected every
   POST to a directory before checking its index.  Apache's `mod_dir` admits
   GET/POST, then lets the selected target decide the method.  httpd-rs now
   does the same: a CGI/FastCGI/proxy index receives POST, while a static index
   or a directory without a viable index still returns 405.

8. **Ambiguous local recovery targets.**  Local ErrorDocument values with a
   fragment, control/DEL byte, backslash, raw whitespace, malformed percent
   escape, encoded control/backslash, traversal above root, or a canonical
   non-UTF-8 path were accepted into configuration and failed only after
   entering the synthetic request path. The configuration compiler and runtime
   projection now share one fail-closed validator backed by the verified
   percent decoder, normalizer and syntax gate.

9. **DirectoryIndex probe/dispatch identity split.** httpd-rs probes a literal
   filename before internally dispatching its URL. A configured name such as
   `index%2ehtml` could therefore open the literal percent-named file during
   selection and then dispatch `index.html` after URL decoding; `?`, `#`, or
   a separator created related query/path splits. Until the full Apache URI
   subrequest form is implemented, the sealed main/access configuration now
   admits only literal, unescaped single-component index names through a
   verified gate. The selected filesystem name and internal URL component are
   therefore the same bytes.

## Apache oracle

Apache's `ap_send_error_response` explicitly changes a local ErrorDocument to
GET before calling `ap_internal_redirect`.  The internal redirect retains
`the_request`, connection/client state and incoming headers, while parsing the
new URI and query.  `mod_dir` admits GET and POST and performs an internal fast
redirect to the selected index.  httpd-rs follows those method/query/wire
identity semantics, while additionally stripping body and hop metadata from
error recovery so a bodyless GET cannot make a backend wait for or interpret
an outer message body.

References:

- Apache `modules/http/http_request.c`, `ap_send_error_response` and
  `internal_internal_redirect`
- Apache `modules/mappers/mod_dir.c`, `fixup_dir`

## Regression coverage

The deterministic suite checks the complete concrete request projection,
connection-nominated header removal, exact target-query splitting, invalid
target rejection, DirectoryIndex probe/URL identity, request-owned recursion,
response-local cache exclusion, and the deferred CGI boundary.  The CGI
regression routes before execution,
then proves that a POST ErrorDocument becomes `GET|configured-query|no-body`
while a POST DirectoryIndex remains `POST|original-query|original-body`.

