# vapache pass-38 subagent review: unreviewed dynamic-backend/proxy commits

Scope: 179b865, 75c6e5c, 05d397f, a0ac855, af736d7, 47fcb28, 1f35e19, 25c7c33, dc603b6,
262e643, 67ca87b, with focus on proxy.rs, fastcgi.rs, cgi.rs, server.rs dynamic
execution/terminal outcomes. HEAD 67ca87b.

Method: diff reading; `cargo build --release -p vapached`; live loopback servers
(vapached + Apache 2.4.69 mod_proxy_fcgi as oracle) against a python FastCGI
responder that records SCRIPT_FILENAME/SCRIPT_NAME/PATH_INFO/PATH_TRANSLATED;
balancer failover tests with two local HTTP backends; `cargo +nightly fuzz build
multi_request_state` and libFuzzer runs on the new corpus.

## Finding 1 (CONFIRMED, tooling integrity, not a server vulnerability)

`multi_request_state` fuzz harness reports a spurious crash: cross-step
FastCGI/proxy exchange queue leakage makes a cancelled request look effectful.

- Root cause: `execute_prepared_snapshot` pops exactly one exchange
  (`whole_request_fuzz.rs:1152-1162`) and asserts
  `backend_effect == !cancel_before_sink` (`:1174-1177`). A balancer request that
  fails over performs two upstream exchanges (proxy.rs:4141-4209: failed status
  or transport error -> `alternate_target` retry), but only one is popped. The
  queue is drained only once per protocol run
  (`drain_backend_exchanges` at `:1398`, called at `:1710/:1722/:1725`), not
  between the steps of `run_stateful_protocol` (`:1594`). The next step then
  pops the previous step's leftover and observes `backend_effect=true` even
  though its own request was cancelled and never reached a backend.
- Repro (built binary):
  `./multi_request_state -runs=1 /tmp/opencode/vhunt/exp.bin` with
  `exp.bin = 1300000000000000 3030303030303030 1300000000000080 0000000000000000`
  (step 0: `/balanced/...` with `x-fuzz` mode 3 -> malformed response -> failover;
  step 1: cancelled `/balanced/...`).
  Panic: `whole_request_fuzz.rs:1174: assertion left == right failed:
  pre-sink cancellation did not suppress the dynamic effect`.
- Controls that pass (proving cancellation itself is correct):
  * `ctl.bin = ...00...` step 0 well-formed, step 1 cancelled -> pass.
  * `b.bin`: direct `/proxy` malformed (single exchange, no failover), then
    cancelled `/proxy` -> pass.
  * `d.bin`: step 0 failover, step 1 cancelled CGI (`/access/guard.cgi`) -> pass;
    if the cancelled CGI had executed, the response would carry `X-Backend`.
- Impact: nightly fuzz campaign emits a false "cancellation did not suppress the
  dynamic effect" crash and can mask real findings. This is a defect in the
  verification harness added by 67ca87b, not in request handling.

## Finding 2 (HYPOTHESIS, low severity, fail-closed DoS)

Cross-request URL-policy cache poisoning on per-request policy-budget
exhaustion (new `url_policy_cache`, added by a0ac855).

- `Config::url_translation_scope_req_deferred` (config.rs:17816-17877) builds a
  request-independent scope for `(vhost, fs_path, url_path)`. If a rule matcher
  returns `Err` because the *request's* policy budget is exhausted
  (`rule_kind_matches_req` -> `req.charge_policy_work` -> `resource.rs:488-497`,
  `MAX_POLICY_WORK_UNITS = 16 MiB` units at `resource.rs:440`), the code sets
  `scope.conditional_error = true; break;` (`config.rs:17851-17856`) and still
  inserts the partial scope into the process-wide cache (`:17869-17875`).
- Any later request that hits that cache entry gets `conditional_error`, and
  `access::check` (access.rs:799-801) returns `Access::Misconfigured` -> 500.
  The cache is bounded (256 entries / 32 MiB, config.rs:3072-3074), so impact
  is transient per-URL denial.
- Reachability requires >16M charged units in one request, i.e. configs with
  thousands of URL/Location rules (each rule charges ~1 + pattern + path
  length). Not reproduced in the benchmark deployments; not demonstrated.

## Negative observations (all reproduced; no bypass found)

FastCGI script/authority construction (ProxyPassMatch, `UnstableFastCgiPaths On`):
- `/uploads/must-not-execute.php`, `.../x.png`, `.../`, `.../.`,
  `/uploads//must-not-execute.php`, `//uploads/...`, `/./uploads/...`,
  `/sub/other.php/../../uploads/...` all 403 (deny applied to the canonical
  script; `server.rs:9627-9761`, `authorize_resolved_target`).
- `AllowEncodedSlashes On`: `%2F`, `%2E`, `%00` spellings either normalize
  correctly (`/uploads/must-not-execute.php%2F..%2F..%2Findex.php` -> `/index.php`,
  which is the correct identity) or are rejected (400/404/403). No spelling
  reached the denied script.
- Out-of-docroot FastCGI prefix + `<Directory private> <FilesMatch \.php$>
  Require all denied` -> 403. Symlink `www/pub.php -> ../private/secret.php`
  with `<Directory private>` deny -> 403.
- Apache 2.4.69 differential: Apache returns 200 and executes
  `/uploads/must-not-execute.php[/x.png]` through `mod_proxy_fcgi` because
  `<Files>` does not apply to proxy routes; vapache returns 403. Vapache is
  stricter here, not weaker.
- Config-time authority capture rejection verified (`config.rs:10669`,
  callers `config.rs:10509`, `config_payload.rs:754`): `http://$1/`,
  `http://\1/`, `http://%1/`, `http://%{HTTP_HOST}/` all fail config load;
  `http://backend/$1` is allowed. `expand_regex_captures` (util.rs:115-144)
  can only inject into the path, never the statically checked authority.

Proxy / balancer / failover:
- `<Proxy "http://127.0.0.1:42101"> Require all denied` with member A returning
  503 + `failonstatus=503`: request -> 403 and member B was never contacted
  (failover re-authorization, `authorize_failover`, works).
- Location deny across a per-directory rewrite (`/dir/go -> /target` with
  `<Location /target> Require all denied`) -> 403; the a0ac855
  `url_translation_may_terminate` fast path did not skip target policy.
- Cancelled requests do not contact proxy/CGI (fuzz controls above).
- `url_policy_cache`/`dir_scope_cache` are bounded (256 entries / 32 MiB);
  access-file cache is keyed by config generation + dev/ino/mtime
  (htaccess.rs:705-760).

Other:
- `ignore_sigpipe` is fuzz-fixture-only; production relies on Rust runtime
  SIGPIPE ignore.
- Release build uses `panic = "abort"`; no request-reachable `expect`/`unwrap`
  panic was found in proxy.rs/fastcgi.rs/cgi.rs/dynamic server paths. The new
  `DynamicOutcomeToken` machine fails closed on every invalid transition
  (verified crate: dynamic_outcome_step).
- 72 of 799 `cargo test -p vapached --lib` tests fail with the default TMPDIR
  because `load_text*` writes configs under `/tmp`, which the new admin-path
  check rejects ("administrative path parent /tmp is writable by the service
  account"). With `TMPDIR=<private dir>` the same tests pass; environment
  artifact, not a regression.

## Limitations

- PHP-FPM itself was unavailable; a FastCGI stub recorded parameters. Execution
  semantics of a real FPM (security.limit_extensions) were not tested, but the
  request-controlled SCRIPT_FILENAME/PATH_INFO surface was.
- Stable-path policy (`VapacheFastCGIStablePath`) was reviewed statically; live
  tests used `UnstableFastCgiPaths On`.
- Another session was concurrently modifying `adversarial/` and fuzzing
  `h2_stateful` during this review; those files were not touched.
