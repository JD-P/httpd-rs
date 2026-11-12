//! Whole-request HTTP/1 versus HTTP/2 differential campaign.
//!
//! Inputs describe one bounded logical request. The harness encodes that
//! request through both wire protocols, then compares the canonical request,
//! production plan, authorization/terminal route, backend binding, cache
//! classification and response semantics. Every owned policy/sink artifact is
//! dropped before the complete resource ledger is checked for zero.

use crate::config::Config;
use crate::http::{Body, Limits, Request, Response};
use crate::request_plan::{CanonicalErrorOrPlan, RequestPlan};
use crate::server::{BodyRouteDecision, PreparedHandler, PreparedRouteDecision};
use std::io::{Cursor, Read};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::OnceLock;

const LOCAL_IP: &str = "127.0.0.1";
const LOCAL_PORT: u16 = 443;
const PEER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 44));

#[derive(Clone, Debug)]
struct LogicalRequest {
    method: &'static str,
    target: String,
    fields: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
    denied_route: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct CanonicalRequestSnapshot {
    method: String,
    target: Vec<u8>,
    raw_path: Vec<u8>,
    query: Vec<u8>,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
    framing: crate::verified::BodyFraming,
}

#[derive(Debug, PartialEq, Eq)]
enum PlanSnapshot {
    UrlSpace {
        url_path: String,
        norm: Vec<u8>,
    },
    Filesystem {
        url_path: String,
        norm: Vec<u8>,
        root: PathBuf,
        rel: PathBuf,
        fs_path: PathBuf,
        script_alias: bool,
        layers: Vec<crate::request_plan::LayerIdentity>,
    },
    Rejected {
        status: u16,
        class: &'static str,
    },
}

#[derive(Debug, PartialEq, Eq)]
enum AuthorizationSnapshot {
    Granted,
    Denied(u16),
    Rejected(u16),
}

#[derive(Debug, PartialEq, Eq)]
enum SinkSnapshot {
    None,
    StaticFile,
    Redirect,
    Proxy,
    FastCgi,
    Cgi,
}

#[derive(Debug, PartialEq, Eq)]
struct BackendSnapshot {
    kind: &'static str,
    selected: String,
    authorized: Option<String>,
    resource: crate::access::ResourceKey,
}

#[derive(Debug, PartialEq, Eq)]
enum CacheSnapshot {
    Bypass,
    Eligible {
        path: String,
        target: PathBuf,
        resource: crate::access::ResourceKey,
    },
}

#[derive(Debug, PartialEq, Eq)]
enum ResponseSnapshot {
    Prepared(&'static str),
    Complete {
        status: u16,
        headers: Vec<(String, Vec<u8>)>,
        body_kind: &'static str,
        body: Vec<u8>,
    },
}

#[derive(Debug, PartialEq, Eq)]
struct WholeRequestSnapshot {
    canonical: CanonicalRequestSnapshot,
    plan: PlanSnapshot,
    authorization: AuthorizationSnapshot,
    sink: SinkSnapshot,
    backend: Option<BackendSnapshot>,
    cache: CacheSnapshot,
    response: ResponseSnapshot,
}

struct Fixture {
    config: Config,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let root =
            std::env::temp_dir().join(format!("vapache-whole-request-fuzz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("www/cache")).expect("create cache document root");
        std::fs::create_dir_all(root.join("www/denied")).expect("create denied document root");
        std::fs::create_dir_all(root.join("cache")).expect("create response cache root");
        std::fs::write(root.join("www/public.txt"), b"public representation\n")
            .expect("write public fixture");
        std::fs::write(root.join("www/cache/item.txt"), b"cache representation\n")
            .expect("write cache fixture");
        std::fs::write(
            root.join("www/denied/secret.txt"),
            b"denied representation\n",
        )
        .expect("write denied fixture");
        std::fs::write(root.join("www/index.html"), b"index representation\n")
            .expect("write index fixture");

        let config_path = root.join("httpd.conf");
        let config_text = format!(
            "ServerRoot \"{}\"\n\
             Listen 127.0.0.1:0\n\
             ServerName localhost\n\
             PidFile \"{}/httpd.pid\"\n\
             ErrorLog \"{}/error.log\"\n\
             DocumentRoot \"{}/www\"\n\
             DirectoryIndex index.html\n\
             CacheRoot \"{}/cache\"\n\
             CacheEnable disk /cache\n\
             Header set Cache-Control no-store\n\
             ProxyPass /proxy http://127.0.0.1:9/upstream/\n\
             Redirect 302 /redirect /public.txt\n\
             RewriteEngine On\n\
             RewriteRule ^/rewrite$ /public.txt [L]\n\
             <Directory \"{}/www\">\n\
             Require all granted\n\
             </Directory>\n\
             <Directory \"{}/www/denied\">\n\
             Require all denied\n\
             </Directory>\n\
             <Location /location-denied>\n\
             Require all denied\n\
             </Location>\n",
            root.display(),
            root.display(),
            root.display(),
            root.display(),
            root.display(),
            root.display(),
            root.display(),
        );
        std::fs::write(&config_path, config_text).expect("write whole-request config");
        let config = Config::load(
            &config_path,
            &root,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap_or_else(|errors| panic!("whole-request config: {errors:?}"));
        assert!(config.resource_budget.transition_usage_is_zero());
        Fixture { config }
    })
}

fn hex_token(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().saturating_mul(2));
    for byte in data.iter().take(24) {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    if out.is_empty() {
        out.push('0');
    }
    out
}

fn logical_request(data: &[u8]) -> LogicalRequest {
    let byte = |index: usize| data.get(index).copied().unwrap_or(0);
    let token = hex_token(data.get(8..).unwrap_or_default());
    let (path, denied_route) = match byte(0) % 12 {
        0 => ("/public.txt".to_string(), false),
        1 => ("/./public.txt".to_string(), false),
        2 => ("/%70ublic.txt".to_string(), false),
        3 => ("/cache/item.txt".to_string(), false),
        4 => ("/denied/secret.txt".to_string(), true),
        5 => ("/location-denied".to_string(), true),
        6 => (format!("/proxy/{token}"), false),
        7 => ("/redirect".to_string(), false),
        8 => ("/rewrite".to_string(), false),
        9 => (format!("/missing-{token}"), false),
        10 => ("/dir/../public.txt".to_string(), false),
        _ => ("/".to_string(), false),
    };
    let query = if byte(1) & 1 == 0 {
        String::new()
    } else {
        format!("?q={token}&n={}", byte(2))
    };
    let method = match byte(3) % 6 {
        0 => "GET",
        1 => "HEAD",
        2 => "POST",
        3 => "PUT",
        4 => "OPTIONS",
        _ => "DELETE",
    };
    let mut fields = vec![("x-fuzz".to_string(), token.as_bytes().to_vec())];
    if byte(4) & 1 != 0 {
        fields.push(("x-merge".to_string(), b"first".to_vec()));
        fields.push(("x-merge".to_string(), token.as_bytes().to_vec()));
    }
    if byte(4) & 2 != 0 {
        fields.push(("cookie".to_string(), b"a=1".to_vec()));
        fields.push(("cookie".to_string(), format!("b={token}").into_bytes()));
    }
    if byte(4) & 4 != 0 {
        fields.push(("range".to_string(), b"bytes=0-3".to_vec()));
    }
    if byte(4) & 8 != 0 {
        fields.push(("cache-control".to_string(), b"no-cache".to_vec()));
    }
    if byte(5) & 1 != 0 {
        fields.push((
            "accept-encoding".to_string(),
            b"gzip, identity;q=0.5".to_vec(),
        ));
    }
    if byte(5) & 2 != 0 {
        fields.push((
            "if-none-match".to_string(),
            format!("\"not-{token}\"").into_bytes(),
        ));
    }
    let body = if byte(5) & 4 != 0 {
        let available = data.get(8..).unwrap_or_default();
        if available.is_empty() {
            vec![byte(6)]
        } else {
            available.iter().copied().take(64).collect()
        }
    } else {
        Vec::new()
    };
    LogicalRequest {
        method,
        target: format!("{path}{query}"),
        fields,
        body,
        denied_route,
    }
}

fn encode_h1(logical: &LogicalRequest) -> Vec<u8> {
    let mut wire = Vec::new();
    wire.extend_from_slice(logical.method.as_bytes());
    wire.push(b' ');
    wire.extend_from_slice(logical.target.as_bytes());
    wire.extend_from_slice(b" HTTP/1.1\r\nHost: localhost\r\n");
    for (name, value) in &logical.fields {
        wire.extend_from_slice(name.as_bytes());
        wire.extend_from_slice(b": ");
        wire.extend_from_slice(value);
        wire.extend_from_slice(b"\r\n");
    }
    if !logical.body.is_empty() {
        wire.extend_from_slice(format!("Content-Length: {}\r\n", logical.body.len()).as_bytes());
    }
    wire.extend_from_slice(b"\r\n");
    wire.extend_from_slice(&logical.body);
    wire
}

fn decode_h1(cfg: &Config, logical: &LogicalRequest) -> Request {
    let mut limits = Limits::default();
    limits.request_line = cfg.limit_request_line;
    limits.fields = cfg.limit_request_fields;
    limits.field_size = cfg.limit_request_field_size;
    limits.body = cfg.limit_request_body;
    limits.resource_budget = cfg.resource_budget.clone();
    limits.max_spool_bytes = cfg.max_spool_bytes;
    limits.max_spool_files = cfg.max_spool_files;
    limits.https = true;
    let mut stream = Cursor::new(encode_h1(logical));
    let mut buffered = Vec::new();
    let context = cfg.resource_budget.context(PEER);
    let mut request = crate::resource::with_resource_context(context.clone(), || {
        crate::http::read_request(&mut stream, &mut buffered, &limits, |_| {})
    })
    .expect("generated HTTP/1 request must parse")
    .expect("generated HTTP/1 request must not be EOF");
    assert!(buffered.is_empty());
    request
        .headers
        .bind_request_scope(crate::resource::RequestScope::new(context));
    request
}

fn request_body(request: &Request) -> Vec<u8> {
    if let Some(spooled) = &request.body_spool {
        let mut body = Vec::new();
        spooled
            .reader()
            .expect("open spooled differential body")
            .read_to_end(&mut body)
            .expect("read spooled differential body");
        body
    } else {
        request.body.clone()
    }
}

fn canonical_snapshot(request: &Request) -> CanonicalRequestSnapshot {
    let mut headers = request
        .headers
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_vec()))
        .collect::<Vec<_>>();
    headers.sort();
    CanonicalRequestSnapshot {
        method: request.method.clone(),
        target: request.target.clone(),
        raw_path: request.raw_path.clone(),
        query: request.query.clone(),
        headers,
        body: request_body(request),
        framing: request.framing,
    }
}

fn vhost_for<'a>(cfg: &'a Config, request: &Request) -> Option<&'a crate::config::VHost> {
    cfg.select_vhost(
        Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        LOCAL_PORT,
        request.header_str("host"),
    )
}

fn plan_snapshot(cfg: &Config, request: &Request) -> (PlanSnapshot, Option<RequestPlan>) {
    let allow_encoded = cfg.encoded_slashes == crate::config::EncodedSlashes::On;
    let vhost = vhost_for(cfg, request);
    let target = match crate::request_plan::CanonicalTarget::from_request(request, allow_encoded) {
        Ok(target) => target,
        Err(error) => {
            return (
                PlanSnapshot::Rejected {
                    status: error.status(),
                    class: "canonical",
                },
                None,
            );
        }
    };
    if cfg.url_translation_may_terminate(vhost, &target.url_path) {
        return (
            PlanSnapshot::UrlSpace {
                url_path: target.url_path.to_string(),
                norm: target.norm,
            },
            None,
        );
    }
    match RequestPlan::from_request(cfg, vhost, request, allow_encoded) {
        Ok(plan) => {
            let snapshot = PlanSnapshot::Filesystem {
                url_path: plan.url_path().to_string(),
                norm: plan.target().norm.clone(),
                root: plan.root().to_path_buf(),
                rel: plan.rel().to_path_buf(),
                fs_path: plan.fs_path().to_path_buf(),
                script_alias: plan.script_alias(),
                layers: plan
                    .layers()
                    .iter()
                    .map(|layer| layer.identity.clone())
                    .collect(),
            };
            (snapshot, Some(plan))
        }
        Err(CanonicalErrorOrPlan::Canonical(error)) => (
            PlanSnapshot::Rejected {
                status: error.status(),
                class: "canonical",
            },
            None,
        ),
        Err(CanonicalErrorOrPlan::Plan(error)) => (
            PlanSnapshot::Rejected {
                status: match error {
                    crate::request_plan::PlanError::PolicyLimit(_) => 414,
                    crate::request_plan::PlanError::Unmapped => 404,
                    crate::request_plan::PlanError::AccessFiles(_) => 500,
                },
                class: "filesystem",
            },
            None,
        ),
    }
}

fn cache_snapshot(cfg: &Config, request: &Request, plan: Option<&RequestPlan>) -> CacheSnapshot {
    let Some(plan) = plan else {
        return CacheSnapshot::Bypass;
    };
    let vhost = vhost_for(cfg, request);
    let host = request.header_str("host").unwrap_or("");
    let path = String::from_utf8_lossy(&request.raw_path);
    let server_name = crate::server::server_name_for_public(cfg, request, LOCAL_IP, LOCAL_PORT);
    let peer = SocketAddr::new(PEER, 4242);
    let context = crate::cache::request_scope_with_plan(
        cfg,
        vhost,
        request,
        peer,
        plan,
        &path,
        LOCAL_PORT,
        true,
        &server_name,
        host,
        LOCAL_IP,
    );
    match context {
        Some(context) => CacheSnapshot::Eligible {
            path: context.path().to_string(),
            target: context.target().to_path_buf(),
            resource: cache_decision_resource(context.authorization().resource()),
        },
        None => CacheSnapshot::Bypass,
    }
}

fn cache_decision_resource(resource: &crate::access::ResourceKey) -> crate::access::ResourceKey {
    let mut resource = resource.clone();
    // Cache policy fingerprints deliberately partition HTTP protocol
    // versions even for static representations. That is stored-entry
    // isolation, not a different eligibility/target decision; compare every
    // other authorization binding while preserving that conservative split.
    resource.policy_fingerprint = None;
    resource
}

fn response_snapshot(response: Response) -> ResponseSnapshot {
    let status = response.status;
    let mut headers = response
        .headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect::<Vec<_>>();
    headers.sort();
    let (body_kind, body) = match response.body {
        Body::Empty => ("empty", Vec::new()),
        Body::Bytes(body) => ("bytes", body),
        Body::File { file, offset, len } => {
            assert!(
                len <= 1024 * 1024,
                "differential fixture response is bounded"
            );
            let mut body = vec![0; len as usize];
            let mut filled = 0usize;
            while filled < body.len() {
                let read = file
                    .read_at(&mut body[filled..], offset.saturating_add(filled as u64))
                    .expect("read differential file response");
                if read == 0 {
                    break;
                }
                filled += read;
            }
            body.truncate(filled);
            ("file", body)
        }
        Body::Stream { reader, len } => {
            assert!(
                len <= 1024 * 1024,
                "differential fixture response is bounded"
            );
            let mut body = Vec::with_capacity(len as usize);
            reader
                .take(len.saturating_add(1))
                .read_to_end(&mut body)
                .expect("read differential stream response");
            assert_eq!(body.len() as u64, len);
            ("stream", body)
        }
    };
    ResponseSnapshot::Complete {
        status,
        headers,
        body_kind,
        body,
    }
}

struct RouteSnapshot {
    authorization: AuthorizationSnapshot,
    sink: SinkSnapshot,
    backend: Option<BackendSnapshot>,
    route_cache: Option<CacheSnapshot>,
    response: ResponseSnapshot,
}

fn cache_context_snapshot(context: &crate::cache::CacheContext) -> CacheSnapshot {
    CacheSnapshot::Eligible {
        path: context.path().to_string(),
        target: context.target().to_path_buf(),
        resource: cache_decision_resource(context.authorization().resource()),
    }
}

fn prepared_snapshot(handler: PreparedHandler) -> RouteSnapshot {
    match handler {
        PreparedHandler::FinalizeDispatch { handler, cache, .. } => {
            let mut snapshot = prepared_snapshot(*handler);
            snapshot.route_cache = cache.as_deref().map(cache_context_snapshot);
            snapshot
        }
        PreparedHandler::FinalizeErrorDocument { handler, .. }
        | PreparedHandler::FinalizeInternalRequest { handler, .. } => prepared_snapshot(*handler),
        PreparedHandler::Proxy {
            authorization,
            target,
            ..
        } => {
            let selected = target.binding_key();
            let authorized = authorization.resource().backend_target.clone();
            RouteSnapshot {
                authorization: AuthorizationSnapshot::Granted,
                sink: SinkSnapshot::Proxy,
                backend: Some(BackendSnapshot {
                    kind: "proxy",
                    selected,
                    authorized,
                    resource: authorization.resource().clone(),
                }),
                route_cache: None,
                response: ResponseSnapshot::Prepared("proxy"),
            }
        }
        PreparedHandler::FastCgi {
            authorization,
            target,
            ..
        } => {
            let authorized_path = authorization
                .identity()
                .resolved_fs_path()
                .expect("FastCGI authorization retained its target");
            let selected = target.binding_key(authorized_path);
            let authorized = authorization.resource().backend_target.clone();
            assert_eq!(authorized.as_deref(), Some(selected.as_str()));
            RouteSnapshot {
                authorization: AuthorizationSnapshot::Granted,
                sink: SinkSnapshot::FastCgi,
                backend: Some(BackendSnapshot {
                    kind: "fastcgi",
                    selected,
                    authorized,
                    resource: authorization.resource().clone(),
                }),
                route_cache: None,
                response: ResponseSnapshot::Prepared("fastcgi"),
            }
        }
        PreparedHandler::Cgi {
            authorization,
            script_meta,
            ..
        } => {
            use std::os::unix::fs::MetadataExt as _;
            let selected = format!("{}:{}", script_meta.dev(), script_meta.ino());
            RouteSnapshot {
                authorization: AuthorizationSnapshot::Granted,
                sink: SinkSnapshot::Cgi,
                backend: Some(BackendSnapshot {
                    kind: "cgi",
                    selected,
                    authorized: authorization.resource().backend_target.clone(),
                    resource: authorization.resource().clone(),
                }),
                route_cache: None,
                response: ResponseSnapshot::Prepared("cgi"),
            }
        }
    }
}

fn response_route(response: Response) -> RouteSnapshot {
    let status = response.status;
    let denied = matches!(status, 401 | 403);
    let redirect = (300..400).contains(&status)
        && response
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("location"));
    let static_file = matches!(response.body, Body::File { .. }) && (200..400).contains(&status);
    let sink = if denied {
        SinkSnapshot::None
    } else if redirect {
        SinkSnapshot::Redirect
    } else if static_file {
        SinkSnapshot::StaticFile
    } else {
        SinkSnapshot::None
    };
    let authorization = if denied {
        AuthorizationSnapshot::Denied(status)
    } else if (200..400).contains(&status) {
        AuthorizationSnapshot::Granted
    } else {
        AuthorizationSnapshot::Rejected(status)
    };
    RouteSnapshot {
        authorization,
        sink,
        backend: None,
        route_cache: None,
        response: response_snapshot(response),
    }
}

fn route_snapshot(cfg: &Config, request: &mut Request) -> RouteSnapshot {
    let peer = SocketAddr::new(PEER, 4242);
    if !matches!(request.framing, crate::verified::BodyFraming::None) {
        match crate::server::probe_request_body(cfg, request, peer, LOCAL_IP, LOCAL_PORT, true) {
            BodyRouteDecision::Read { handler, .. } => prepared_snapshot(handler),
            BodyRouteDecision::Drain(response, _) | BodyRouteDecision::Respond(response, _) => {
                response_route(response)
            }
        }
    } else {
        match crate::server::probe_prepared_handler(cfg, request, peer, LOCAL_IP, LOCAL_PORT, true)
        {
            PreparedRouteDecision::Prepared { handler, .. } => prepared_snapshot(handler),
            PreparedRouteDecision::Respond(response, _) => response_route(response),
        }
    }
}

fn evaluate(cfg: &Config, mut request: Request) -> WholeRequestSnapshot {
    let canonical = canonical_snapshot(&request);
    let (plan, owned_plan) = plan_snapshot(cfg, &request);
    let cache = crate::expr::with_connection(true, LOCAL_PORT, || {
        cache_snapshot(cfg, &request, owned_plan.as_ref())
    });
    let route = route_snapshot(cfg, &mut request);
    if let Some(route_cache) = route.route_cache.as_ref() {
        assert_eq!(route_cache, &cache);
    }
    if matches!(route.authorization, AuthorizationSnapshot::Denied(_)) {
        assert_eq!(route.sink, SinkSnapshot::None);
        assert!(route.backend.is_none());
    }
    WholeRequestSnapshot {
        canonical,
        plan,
        authorization: route.authorization,
        sink: route.sink,
        backend: route.backend,
        cache,
        response: route.response,
    }
}

fn compare_protocols(data: &[u8]) -> WholeRequestSnapshot {
    let fixture = fixture();
    let cfg = &fixture.config;
    let logical = logical_request(data);
    assert!(cfg.resource_budget.transition_usage_is_zero());
    let baseline = cfg.resource_budget.transition_snapshot();

    let h1 = evaluate(cfg, decode_h1(cfg, &logical));
    assert_eq!(cfg.resource_budget.transition_snapshot(), baseline);
    assert!(cfg.resource_budget.transition_usage_is_zero());

    let h2_request = crate::h2::differential_decode_request(
        cfg,
        logical.method,
        &logical.target,
        &logical.fields,
        &logical.body,
        PEER,
    )
    .unwrap_or_else(|error| panic!("generated HTTP/2 request failed: {error}; {logical:?}"));
    let h2 = evaluate(cfg, h2_request);
    assert_eq!(cfg.resource_budget.transition_snapshot(), baseline);
    assert!(cfg.resource_budget.transition_usage_is_zero());

    assert_eq!(h1, h2, "protocol projections diverged for {logical:?}");
    if logical.denied_route {
        assert!(matches!(h1.authorization, AuthorizationSnapshot::Denied(_)));
        assert_eq!(h1.sink, SinkSnapshot::None);
        assert!(h1.backend.is_none());
    }
    h1
}

/// Run one bounded logical request through both complete protocol paths.
pub fn run(data: &[u8]) {
    let _ = compare_protocols(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_whole_request_protocol_matrix_agrees() {
        let empty = compare_protocols(&[]);
        assert_eq!(empty.sink, SinkSnapshot::StaticFile);

        let public = compare_protocols(b"\x00\x00\x00\x00\x00\x00\x00\x00public");
        assert!(matches!(public.plan, PlanSnapshot::Filesystem { .. }));
        assert_eq!(public.authorization, AuthorizationSnapshot::Granted);
        assert_eq!(public.sink, SinkSnapshot::StaticFile);

        let cache = compare_protocols(b"\x03\x01\x01\x00\x01\x03\x00\x00cache");
        assert!(matches!(cache.plan, PlanSnapshot::Filesystem { .. }));
        assert!(matches!(cache.cache, CacheSnapshot::Eligible { .. }));

        let denied = compare_protocols(b"\x04\x00\x00\x00\x03\x00\x00\x00denied");
        assert!(matches!(
            denied.authorization,
            AuthorizationSnapshot::Denied(_)
        ));
        assert_eq!(denied.sink, SinkSnapshot::None);
        assert!(denied.backend.is_none());

        let proxy = compare_protocols(b"\x06\x01\x02\x02\x03\x04\x00\x00proxy");
        assert!(matches!(proxy.plan, PlanSnapshot::UrlSpace { .. }));
        assert_eq!(proxy.sink, SinkSnapshot::Proxy);
        assert!(matches!(
            proxy.backend,
            Some(BackendSnapshot { kind: "proxy", .. })
        ));

        let redirect = compare_protocols(b"\x07\x00\x00\x01\x00\x00\x00\x00redirect");
        assert_eq!(redirect.sink, SinkSnapshot::Redirect);

        let rewrite = compare_protocols(b"\x08\x01\x00\x00\x00\x00\x00\x00rewrite");
        assert_eq!(rewrite.sink, SinkSnapshot::StaticFile);
    }
}
