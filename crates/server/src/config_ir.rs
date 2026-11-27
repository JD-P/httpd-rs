//! Source-neutral configuration IR shared by the Apache and nginx frontends.
//!
//! The runtime deliberately does not expose a generic module or scripting
//! interface.  Frontends may emit only the finite route and value operations
//! in this module; everything else is rejected while loading configuration.

use crate::apache_regex::Regex;
use std::net::IpAddr;

pub const MAX_ROUTES_PER_SERVER: usize = 512;
pub const MAX_VALUE_SEGMENTS: usize = 32;
pub const MAX_TRANSFORMS_PER_SCOPE: usize = 128;
pub const MAX_TRANSFORM_VALUE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Apache,
    Nginx,
}

/// A compiled, source-neutral configuration before process-wide derived
/// indexes and conservative feature bits are finalized.  Apache and nginx
/// both produce this value; only their route-selection programs differ.
#[derive(Debug, Clone)]
pub struct ConfigIr {
    pub(crate) config: crate::config::Config,
    pub(crate) routes: RouteProgram<crate::config::Scope>,
}

impl ConfigIr {
    pub(crate) fn apache(config: crate::config::Config) -> Self {
        Self {
            config,
            routes: RouteProgram::Apache,
        }
    }

    pub(crate) fn nginx(
        config: crate::config::Config,
        servers: Vec<Vec<Route<crate::config::Scope>>>,
    ) -> Result<Self, String> {
        let server_names = config
            .vhosts
            .iter()
            .map(|vhost| {
                vhost
                    .server_name
                    .iter()
                    .chain(vhost.aliases.iter())
                    .cloned()
                    .collect()
            })
            .collect();
        Ok(Self {
            config,
            routes: RouteProgram::nginx(servers, server_names)?,
        })
    }
}

impl ConfigFormat {
    pub fn parse(value: &str) -> Option<Self> {
        if value.eq_ignore_ascii_case("apache") || value.eq_ignore_ascii_case("apache2") {
            Some(Self::Apache)
        } else if value.eq_ignore_ascii_case("nginx") {
            Some(Self::Nginx)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub enum RouteMatcher {
    Exact(String),
    Prefix { value: String, suppress_regex: bool },
    Regex { value: String, regex: Regex },
}

#[derive(Debug, Clone)]
pub struct Route<T> {
    pub matcher: RouteMatcher,
    pub policy: T,
    pub declaration_order: usize,
}

#[derive(Debug, Clone)]
pub enum RouteProgram<T> {
    Apache,
    Nginx {
        servers: Vec<Vec<Route<T>>>,
        server_names: Vec<Vec<String>>,
    },
}

impl<T> Default for RouteProgram<T> {
    fn default() -> Self {
        Self::Apache
    }
}

impl<T> RouteProgram<T> {
    pub fn nginx(
        servers: Vec<Vec<Route<T>>>,
        server_names: Vec<Vec<String>>,
    ) -> Result<Self, String> {
        if servers.len() != server_names.len() {
            return Err("nginx server route/name cardinality mismatch".into());
        }
        if servers
            .iter()
            .any(|routes| routes.len() > MAX_ROUTES_PER_SERVER)
        {
            return Err(format!(
                "nginx server exceeds the {MAX_ROUTES_PER_SERVER}-location bound"
            ));
        }
        Ok(Self::Nginx {
            servers,
            server_names,
        })
    }

    pub fn is_nginx(&self) -> bool {
        matches!(self, Self::Nginx { .. })
    }

    pub fn select(&self, server: usize, path: &str) -> Option<&T> {
        let Self::Nginx { servers, .. } = self else {
            return None;
        };
        select_nginx_route(servers.get(server)?, path).map(|route| &route.policy)
    }

    pub fn policies(&self) -> impl Iterator<Item = &T> {
        let routes: &[Vec<Route<T>>] = match self {
            Self::Apache => &[],
            Self::Nginx { servers, .. } => servers,
        };
        routes
            .iter()
            .flat_map(|server| server.iter().map(|route| &route.policy))
    }

    pub fn select_metered(
        &self,
        server: usize,
        path: &str,
        req: &crate::http::Request,
    ) -> Result<Option<&T>, &'static str> {
        let Self::Nginx { servers, .. } = self else {
            return Ok(None);
        };
        let Some(routes) = servers.get(server) else {
            return Ok(None);
        };
        let work = routes.iter().fold(1u64, |total, route| {
            let matcher = match &route.matcher {
                RouteMatcher::Exact(value) | RouteMatcher::Prefix { value, .. } => value.len(),
                RouteMatcher::Regex { value, .. } => value.len(),
            };
            total
                .saturating_add(matcher as u64)
                .saturating_add(path.len() as u64)
                .saturating_add(1)
        });
        req.charge_policy_work(work)?;
        Ok(select_nginx_route(routes, path).map(|route| &route.policy))
    }

    /// Select an nginx virtual server from the address-bucket candidates.
    /// Exact names win, followed by the longest leading-wildcard suffix, then
    /// the longest trailing-wildcard prefix. Regex server names are rejected
    /// by the frontend, so the first candidate is the address default.
    pub fn select_nginx_server(&self, candidates: &[usize], host: Option<&str>) -> Option<usize> {
        let Self::Nginx { server_names, .. } = self else {
            return None;
        };
        let default = *candidates.first()?;
        let Some(host) = host else {
            return Some(default);
        };
        let authority = host.trim();
        let bare = if let Some(rest) = authority.strip_prefix('[') {
            rest.split_once(']').map(|(value, _)| value).unwrap_or(rest)
        } else if authority
            .as_bytes()
            .iter()
            .filter(|byte| **byte == b':')
            .count()
            == 1
        {
            authority
                .split_once(':')
                .map(|(value, _)| value)
                .unwrap_or(authority)
        } else {
            authority
        }
        .trim_end_matches('.')
        .to_ascii_lowercase();
        for &index in candidates {
            if server_names.get(index).is_some_and(|names| {
                names.iter().any(|name| {
                    !name.contains('*') && name.trim_end_matches('.').eq_ignore_ascii_case(&bare)
                })
            }) {
                return Some(index);
            }
        }
        let mut leading: Option<(usize, usize)> = None;
        let mut trailing: Option<(usize, usize)> = None;
        for &index in candidates {
            let Some(names) = server_names.get(index) else {
                continue;
            };
            for name in names {
                if let Some(suffix) = name.strip_prefix('*') {
                    if bare.len() > suffix.len()
                        && bare.ends_with(suffix)
                        && leading.is_none_or(|(_, width)| suffix.len() > width)
                    {
                        leading = Some((index, suffix.len()));
                    }
                } else if let Some(prefix) = name.strip_suffix('*') {
                    if bare.len() > prefix.len()
                        && bare.starts_with(prefix)
                        && trailing.is_none_or(|(_, width)| prefix.len() > width)
                    {
                        trailing = Some((index, prefix.len()));
                    }
                }
            }
        }
        leading
            .or(trailing)
            .map(|(index, _)| index)
            .or(Some(default))
    }
}

/// nginx HTTP location selection: exact first; remember the longest literal
/// prefix; a `^~` prefix suppresses regex evaluation; otherwise the first
/// matching regex in declaration order wins; finally use the longest prefix.
pub fn select_nginx_route<'a, T>(routes: &'a [Route<T>], path: &str) -> Option<&'a Route<T>> {
    let mut exact: Option<&Route<T>> = None;
    let mut prefix: Option<&Route<T>> = None;
    for route in routes {
        match &route.matcher {
            RouteMatcher::Exact(value) if value == path => {
                if exact
                    .as_ref()
                    .is_none_or(|current| route.declaration_order < current.declaration_order)
                {
                    exact = Some(route);
                }
            }
            RouteMatcher::Prefix { value, .. } if path.starts_with(value) => {
                let replace = prefix.as_ref().is_none_or(|current| {
                    let RouteMatcher::Prefix {
                        value: current_value,
                        ..
                    } = &current.matcher
                    else {
                        return true;
                    };
                    value.len() > current_value.len()
                        || (value.len() == current_value.len()
                            && route.declaration_order < current.declaration_order)
                });
                if replace {
                    prefix = Some(route);
                }
            }
            _ => {}
        }
    }
    if exact.is_some() {
        return exact;
    }
    if prefix.is_some_and(|route| {
        matches!(
            route.matcher,
            RouteMatcher::Prefix {
                suppress_regex: true,
                ..
            }
        )
    }) {
        return prefix;
    }
    let mut regex_match: Option<&Route<T>> = None;
    for route in routes {
        let RouteMatcher::Regex { regex, .. } = &route.matcher else {
            continue;
        };
        if regex.is_match(path.as_bytes())
            && regex_match
                .as_ref()
                .is_none_or(|current| route.declaration_order < current.declaration_order)
        {
            regex_match = Some(route);
        }
    }
    regex_match.or(prefix)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueVariable {
    Host,
    HttpHost,
    RemoteAddr,
    ProxyAddXForwardedFor,
    ProxyHost,
    Scheme,
    HttpUpgrade,
    ConnectionUpgrade,
    ServerPort,
    ServerName,
    RequestUri,
    Uri,
    DocumentUri,
    RequestMethod,
    QueryString,
    ContentType,
    ContentLength,
    DocumentRoot,
    RealPathRoot,
    FastCgiScriptName,
    FastCgiPathInfo,
    RequestFilename,
    ServerProtocol,
    Https,
    RemotePort,
    ServerAddr,
    GatewayInterface,
    ServerSoftware,
    HttpHeader(String),
    Cookie(String),
    Argument(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueSegment {
    Literal(Vec<u8>),
    Variable(ValueVariable),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueExpr {
    segments: Vec<ValueSegment>,
}

impl ValueExpr {
    pub fn parse(value: &str) -> Result<Self, String> {
        if value.as_bytes().contains(&0) {
            return Err("NUL is not permitted in a transformation value".into());
        }
        if value.len() > MAX_TRANSFORM_VALUE_BYTES {
            return Err(format!(
                "transformation value exceeds {MAX_TRANSFORM_VALUE_BYTES} bytes"
            ));
        }
        let bytes = value.as_bytes();
        let mut segments = Vec::new();
        let mut literal = Vec::new();
        let mut index = 0usize;
        while index < bytes.len() {
            if bytes[index] == b'\\' && bytes.get(index + 1) == Some(&b'$') {
                literal.push(b'$');
                index += 2;
                continue;
            }
            if bytes[index] != b'$' {
                literal.push(bytes[index]);
                index += 1;
                continue;
            }
            if !literal.is_empty() {
                segments.push(ValueSegment::Literal(std::mem::take(&mut literal)));
            }
            let (name, next) = if bytes.get(index + 1) == Some(&b'{') {
                let end = bytes[index + 2..]
                    .iter()
                    .position(|byte| *byte == b'}')
                    .map(|offset| index + 2 + offset)
                    .ok_or_else(|| "unterminated ${...} transformation variable".to_string())?;
                (&value[index + 2..end], end + 1)
            } else {
                let mut end = index + 1;
                while bytes
                    .get(end)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    end += 1;
                }
                if end == index + 1 {
                    return Err("bare '$' in transformation value".into());
                }
                (&value[index + 1..end], end)
            };
            segments.push(ValueSegment::Variable(parse_variable(name)?));
            index = next;
            if segments.len() > MAX_VALUE_SEGMENTS {
                return Err(format!(
                    "transformation contains more than {MAX_VALUE_SEGMENTS} segments"
                ));
            }
        }
        if !literal.is_empty() || segments.is_empty() {
            segments.push(ValueSegment::Literal(literal));
        }
        if segments.len() > MAX_VALUE_SEGMENTS {
            return Err(format!(
                "transformation contains more than {MAX_VALUE_SEGMENTS} segments"
            ));
        }
        Ok(Self { segments })
    }

    pub fn segments(&self) -> &[ValueSegment] {
        &self.segments
    }

    pub fn evaluate(
        &self,
        mut resolve: impl FnMut(&ValueVariable) -> Option<Vec<u8>>,
    ) -> Result<Vec<u8>, &'static str> {
        let mut output = Vec::new();
        for segment in &self.segments {
            let value = match segment {
                ValueSegment::Literal(value) => value.clone(),
                ValueSegment::Variable(variable) => {
                    resolve(variable).ok_or("transformation variable is unavailable")?
                }
            };
            let Some(next) = output.len().checked_add(value.len()) else {
                return Err("transformation value length overflow");
            };
            if next > MAX_TRANSFORM_VALUE_BYTES {
                return Err("transformation value exceeds its runtime byte bound");
            }
            output.extend_from_slice(&value);
        }
        Ok(output)
    }
}

fn parse_variable(name: &str) -> Result<ValueVariable, String> {
    let variable = match name {
        "host" => ValueVariable::Host,
        "http_host" => ValueVariable::HttpHost,
        "remote_addr" => ValueVariable::RemoteAddr,
        "proxy_add_x_forwarded_for" => ValueVariable::ProxyAddXForwardedFor,
        "proxy_host" => ValueVariable::ProxyHost,
        "scheme" => ValueVariable::Scheme,
        "http_upgrade" => ValueVariable::HttpUpgrade,
        // This is the conventional finite map of $http_upgrade to
        // "upgrade"/"close". nginx_frontend accepts only that exact map.
        "connection_upgrade" => ValueVariable::ConnectionUpgrade,
        "server_port" => ValueVariable::ServerPort,
        "server_name" => ValueVariable::ServerName,
        "request_uri" => ValueVariable::RequestUri,
        "uri" => ValueVariable::Uri,
        "document_uri" => ValueVariable::DocumentUri,
        "request_method" => ValueVariable::RequestMethod,
        "query_string" | "args" => ValueVariable::QueryString,
        "content_type" => ValueVariable::ContentType,
        "content_length" => ValueVariable::ContentLength,
        "document_root" => ValueVariable::DocumentRoot,
        "realpath_root" => ValueVariable::RealPathRoot,
        "fastcgi_script_name" => ValueVariable::FastCgiScriptName,
        "fastcgi_path_info" | "path_info" => ValueVariable::FastCgiPathInfo,
        "request_filename" => ValueVariable::RequestFilename,
        "server_protocol" => ValueVariable::ServerProtocol,
        "https" => ValueVariable::Https,
        "remote_port" => ValueVariable::RemotePort,
        "server_addr" => ValueVariable::ServerAddr,
        "gateway_interface" => ValueVariable::GatewayInterface,
        "server_software" => ValueVariable::ServerSoftware,
        _ if name.starts_with("http_") && name.len() > 5 => {
            ValueVariable::HttpHeader(name[5..].replace('_', "-"))
        }
        _ if name.starts_with("cookie_") && name.len() > 7 => {
            ValueVariable::Cookie(name[7..].to_string())
        }
        _ if name.starts_with("arg_") && name.len() > 4 => {
            ValueVariable::Argument(name[4..].to_string())
        }
        _ => return Err(format!("unsupported transformation variable '${name}'")),
    };
    Ok(variable)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHeaderTransform {
    pub name: String,
    pub value: ValueExpr,
}

impl ProxyHeaderTransform {
    pub fn new(name: &str, value: &str) -> Result<Self, String> {
        if !httpd_rs_verified::proxy_header_admit(name.as_bytes(), b"") {
            return Err(format!("invalid proxy header name '{name}'"));
        }
        let lower = name.to_ascii_lowercase();
        if matches!(lower.as_str(), "transfer-encoding" | "te" | "trailer") {
            return Err(format!("proxy header '{name}' is owned by the serializer"));
        }
        if lower == "content-length" {
            return Err("proxy Content-Length is owned by the serializer".into());
        }
        let expression = ValueExpr::parse(value)?;
        if lower == "connection" {
            let allowed = matches!(
                expression.segments(),
                [ValueSegment::Literal(value)]
                    if matches!(value.as_slice(), b"" | b"close" | b"keep-alive" | b"upgrade" | b"Upgrade")
            ) || matches!(
                expression.segments(),
                [ValueSegment::Variable(ValueVariable::ConnectionUpgrade)]
            );
            if !allowed {
                return Err("Connection may only be close, keep-alive, upgrade, or the finite $connection_upgrade map".into());
            }
        }
        if lower == "upgrade"
            && !matches!(
                expression.segments(),
                [ValueSegment::Literal(value)] if value.is_empty()
            )
            && !matches!(
                expression.segments(),
                [ValueSegment::Variable(ValueVariable::HttpUpgrade)]
            )
        {
            return Err("Upgrade may only be empty or $http_upgrade".into());
        }
        if lower == "host"
            && expression.segments().iter().any(|segment| {
                matches!(
                    segment,
                    ValueSegment::Variable(
                        ValueVariable::RemoteAddr
                            | ValueVariable::HttpUpgrade
                            | ValueVariable::HttpHeader(_)
                            | ValueVariable::Cookie(_)
                            | ValueVariable::Argument(_)
                    )
                )
            })
        {
            return Err("Host may only use canonical authority variables or literals".into());
        }
        if lower == "x-forwarded-for"
            && expression.segments().iter().any(|segment| {
                matches!(segment, ValueSegment::Variable(ValueVariable::HttpHeader(name)) if name.eq_ignore_ascii_case("x-forwarded-for"))
            })
        {
            return Err("client-asserted X-Forwarded-For cannot become a trusted proxy assertion".into());
        }
        Ok(Self {
            name: lower,
            value: expression,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastCgiParamTransform {
    pub name: String,
    pub value: ValueExpr,
    pub only_if_not_empty: bool,
}

impl FastCgiParamTransform {
    pub fn new(name: &str, value: &str, only_if_not_empty: bool) -> Result<Self, String> {
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(format!("invalid FastCGI parameter name '{name}'"));
        }
        let expression = ValueExpr::parse(value)?;
        let upper = name.to_ascii_uppercase();
        if upper == "SCRIPT_FILENAME" {
            let safe = expression.segments().iter().all(|segment| {
                matches!(
                    segment,
                    ValueSegment::Literal(_)
                        | ValueSegment::Variable(ValueVariable::DocumentRoot)
                        | ValueSegment::Variable(ValueVariable::RealPathRoot)
                        | ValueSegment::Variable(ValueVariable::FastCgiScriptName)
                        | ValueSegment::Variable(ValueVariable::RequestFilename)
                )
            });
            if !safe {
                return Err(
                    "SCRIPT_FILENAME must be derived only from an authorized script identity"
                        .into(),
                );
            }
        }
        if matches!(
            upper.as_str(),
            "PHP_VALUE" | "PHP_ADMIN_VALUE" | "PHP_FLAG" | "PHP_ADMIN_FLAG"
        ) && expression
            .segments()
            .iter()
            .any(|segment| matches!(segment, ValueSegment::Variable(_)))
        {
            return Err("PHP configuration parameters must be root-controlled literals".into());
        }
        Ok(Self {
            name: upper,
            value: expression,
            only_if_not_empty,
        })
    }
}

pub fn request_value(
    variable: &ValueVariable,
    req: &crate::http::Request,
    peer: IpAddr,
    https: bool,
    host_name: &str,
    server_name: &str,
    server_port: u16,
) -> Option<Vec<u8>> {
    let header = |name: &str| {
        req.header(name)
            .map(|value| value.to_vec())
            .unwrap_or_default()
    };
    Some(match variable {
        ValueVariable::Host => host_name.as_bytes().to_vec(),
        ValueVariable::HttpHost => header("host"),
        ValueVariable::RemoteAddr | ValueVariable::ProxyAddXForwardedFor => {
            peer.to_string().into_bytes()
        }
        ValueVariable::Scheme => {
            if https {
                b"https".to_vec()
            } else {
                b"http".to_vec()
            }
        }
        ValueVariable::HttpUpgrade => header("upgrade"),
        ValueVariable::ConnectionUpgrade => {
            if req.header("upgrade").is_some_and(|value| !value.is_empty()) {
                b"upgrade".to_vec()
            } else {
                b"close".to_vec()
            }
        }
        ValueVariable::ServerPort => server_port.to_string().into_bytes(),
        ValueVariable::ServerName => server_name.as_bytes().to_vec(),
        ValueVariable::RequestUri => req.target.clone(),
        ValueVariable::Uri | ValueVariable::DocumentUri => req.raw_path.clone(),
        ValueVariable::RequestMethod => req.method.as_bytes().to_vec(),
        ValueVariable::QueryString => req.query.clone(),
        ValueVariable::ContentType => header("content-type"),
        ValueVariable::ContentLength => {
            if let Some(value) = req.header("content-length") {
                value.to_vec()
            } else if req.body_len() > 0 {
                req.body_len().to_string().into_bytes()
            } else {
                Vec::new()
            }
        }
        ValueVariable::HttpHeader(name) => header(name),
        ValueVariable::Cookie(name) => cookie_value(req.header("cookie"), name),
        ValueVariable::Argument(name) => argument_value(&req.query, name),
        ValueVariable::ProxyHost
        | ValueVariable::DocumentRoot
        | ValueVariable::RealPathRoot
        | ValueVariable::FastCgiScriptName
        | ValueVariable::FastCgiPathInfo
        | ValueVariable::RequestFilename
        | ValueVariable::ServerProtocol
        | ValueVariable::Https
        | ValueVariable::RemotePort
        | ValueVariable::ServerAddr
        | ValueVariable::GatewayInterface
        | ValueVariable::ServerSoftware => return None,
    })
}

fn cookie_value(header: Option<&[u8]>, name: &str) -> Vec<u8> {
    let Some(header) = header else {
        return Vec::new();
    };
    for pair in header.split(|byte| *byte == b';') {
        let pair = pair.strip_prefix(b" ").unwrap_or(pair);
        let Some(split) = pair.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        if pair[..split].eq_ignore_ascii_case(name.as_bytes()) {
            return pair[split + 1..].to_vec();
        }
    }
    Vec::new()
}

fn argument_value(query: &[u8], name: &str) -> Vec<u8> {
    for pair in query.split(|byte| *byte == b'&') {
        let split = pair
            .iter()
            .position(|byte| *byte == b'=')
            .unwrap_or(pair.len());
        if pair[..split] == name.as_bytes()[..] {
            return pair.get(split + 1..).unwrap_or_default().to_vec();
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route<T>(matcher: RouteMatcher, policy: T, order: usize) -> Route<T> {
        Route {
            matcher,
            policy,
            declaration_order: order,
        }
    }

    #[test]
    fn nginx_location_selection_is_exact_prefix_then_regex() {
        let routes = vec![
            route(
                RouteMatcher::Prefix {
                    value: "/".into(),
                    suppress_regex: false,
                },
                "root",
                0,
            ),
            route(
                RouteMatcher::Prefix {
                    value: "/images/".into(),
                    suppress_regex: false,
                },
                "images",
                1,
            ),
            route(
                RouteMatcher::Regex {
                    value: "[.]php$".into(),
                    regex: Regex::compile("[.]php$", false).unwrap(),
                },
                "php",
                2,
            ),
            route(RouteMatcher::Exact("/images/logo.php".into()), "exact", 3),
        ];
        assert_eq!(select_nginx_route(&routes, "/x").unwrap().policy, "root");
        assert_eq!(
            select_nginx_route(&routes, "/images/x.png").unwrap().policy,
            "images"
        );
        assert_eq!(
            select_nginx_route(&routes, "/images/x.php").unwrap().policy,
            "php"
        );
        assert_eq!(
            select_nginx_route(&routes, "/images/logo.php")
                .unwrap()
                .policy,
            "exact"
        );
    }

    #[test]
    fn caret_prefix_suppresses_regex() {
        let routes = vec![
            route(
                RouteMatcher::Prefix {
                    value: "/assets/".into(),
                    suppress_regex: true,
                },
                "assets",
                0,
            ),
            route(
                RouteMatcher::Regex {
                    value: "[.]php$".into(),
                    regex: Regex::compile("[.]php$", false).unwrap(),
                },
                "php",
                1,
            ),
        ];
        assert_eq!(
            select_nginx_route(&routes, "/assets/x.php").unwrap().policy,
            "assets"
        );
    }

    #[test]
    fn nginx_server_selection_uses_nginx_name_precedence() {
        let program = RouteProgram::<()>::nginx(
            vec![vec![], vec![], vec![], vec![]],
            vec![
                vec!["_".into()],
                vec!["*.example.test".into()],
                vec!["*.deep.example.test".into()],
                vec!["api.deep.example.test".into(), "mail.*".into()],
            ],
        )
        .unwrap();
        let candidates = [0, 1, 2, 3];
        assert_eq!(
            program.select_nginx_server(&candidates, Some("api.deep.example.test:443")),
            Some(3)
        );
        assert_eq!(
            program.select_nginx_server(&candidates, Some("www.deep.example.test")),
            Some(2)
        );
        assert_eq!(
            program.select_nginx_server(&candidates, Some("mail.invalid")),
            Some(3)
        );
        assert_eq!(
            program.select_nginx_server(&candidates, Some("unmatched.invalid")),
            Some(0)
        );
    }

    #[test]
    fn transform_grammar_is_closed() {
        assert!(ValueExpr::parse("$scheme://$host$request_uri").is_ok());
        assert!(ValueExpr::parse("$arbitrary_module_variable").is_err());
        assert!(ProxyHeaderTransform::new("Connection", "$http_connection").is_err());
        assert!(ProxyHeaderTransform::new("Connection", "$connection_upgrade").is_ok());
        assert!(ProxyHeaderTransform::new("Transfer-Encoding", "chunked").is_err());
        assert!(ProxyHeaderTransform::new("Content-Length", "").is_err());
        assert!(ValueExpr::parse("bad\0value").is_err());
        assert!(FastCgiParamTransform::new(
            "SCRIPT_FILENAME",
            "$document_root$fastcgi_script_name",
            false,
        )
        .is_ok());
        assert!(
            FastCgiParamTransform::new("SCRIPT_FILENAME", "$document_root$uri", false).is_err()
        );
    }
}
