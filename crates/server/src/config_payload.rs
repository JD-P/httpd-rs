//! Sealed directive payloads shared by the main and access-file compilers.
//!
//! Tokenization is intentionally a separate stage.  Once a directive has
//! been classified, this module establishes the schema facts that every later
//! compiler stage may rely on: argument cardinality, whether an empty token is
//! admissible, and the directive's parsed semantic value.  The fields are
//! private so neither compiler can construct an unsealed payload or recover a
//! mutable argument vector.

use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PayloadArity {
    pub(crate) min: usize,
    pub(crate) max: Option<usize>,
}

impl PayloadArity {
    pub(crate) const ANY: Self = Self { min: 0, max: None };
    pub(crate) const ONE: Self = Self {
        min: 1,
        max: Some(1),
    };
    pub(crate) const TWO: Self = Self {
        min: 2,
        max: Some(2),
    };

    pub(crate) const fn at_least(min: usize) -> Self {
        Self { min, max: None }
    }

    pub(crate) const fn between(min: usize, max: usize) -> Self {
        Self {
            min,
            max: Some(max),
        }
    }

    pub(crate) fn requirement(self) -> String {
        match self.max {
            Some(max) if max == self.min => format!("exactly {}", self.min),
            Some(max) => format!("between {} and {max}", self.min),
            None => format!("at least {}", self.min),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PayloadSchema {
    pub(crate) arity: PayloadArity,
    pub(crate) reject_empty: bool,
    pub(crate) value: PayloadValueSchema,
}

impl PayloadSchema {
    pub(crate) const fn new(arity: PayloadArity, reject_empty: bool) -> Self {
        Self {
            arity,
            reject_empty,
            value: PayloadValueSchema::Tokens,
        }
    }

    pub(crate) const fn typed(
        arity: PayloadArity,
        reject_empty: bool,
        value: PayloadValueSchema,
    ) -> Self {
        Self {
            arity,
            reject_empty,
            value,
        }
    }
}

/// Primitive semantic domains that can be completely compiled while the
/// payload is sealed. More structured directives retain their exact token
/// vector and are compiled by a dedicated typed parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PayloadValueSchema {
    Tokens,
    OnOff,
    Unsigned {
        min: u64,
        max: u64,
    },
    Keyword(&'static [&'static str]),
    Options,
    Require,
    LegacyHosts,
    FileEtag,
    ErrorDocument,
    DirectoryIndex,
    Header,
    Redirect {
        forced_status: Option<u16>,
        regex: bool,
    },
    RewriteCond,
    RewriteRule,
    RepeatedKeyword(&'static str),
    HttpProtocols,
    ExpiresDefault,
    ExpiresByType,
    EnvironmentRule,
    GlobPatterns,
    AllowMethods,
    RequestReadTimeout,
    Listen,
    RemoteIpNetworks,
    SslProtocol,
    UnitFloat,
    OcspResponderUrl,
    AliasRegex,
    ProxyPass,
    ProxyPassReverse,
    ProxyPassMatch,
    Validated(PayloadValidation),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PayloadValidation {
    Capability,
    FastCgiStablePath,
    ServerAliases,
    AllowOverride,
    AllowOverrideList,
    RewriteMap,
    LogLevel,
    SslRandomSeed,
    SslPassphraseDialog,
    SslSessionCache,
    SslStaplingCache,
    SslOptions,
    BalancerMember,
    ProxySet,
    ProxyHealthTemplate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SealedOptions {
    pub(crate) policy: crate::scope_policy::OptionsPolicy,
    pub(crate) requires_autoindex: bool,
    pub(crate) requires_cgi: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct SealedHeader {
    always: bool,
    action: HeaderAction,
    name: String,
    value: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SealedAliasRegex {
    pub(crate) pattern: std::sync::Arc<regex::bytes::Regex>,
    pub(crate) target: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SealedProxyPass {
    pub(crate) prefix: String,
    pub(crate) backend: String,
    pub(crate) sticky_cookie: Option<String>,
    pub(crate) fail_on_status: Vec<u16>,
    pub(crate) fastcgi: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct SealedProxyReverse {
    pub(crate) front: String,
    pub(crate) backend: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SealedProxyMatch {
    pub(crate) pattern: std::sync::Arc<regex::bytes::Regex>,
    pub(crate) backend: String,
    pub(crate) fastcgi: bool,
}

#[derive(Debug, Clone, Copy)]
enum HeaderAction {
    Set,
    Add,
    Unset,
}

impl SealedHeader {
    pub(crate) fn apply(&self, policy: &mut crate::scope_policy::HeaderPolicy) {
        match (self.action, self.always) {
            (HeaderAction::Set, true) => policy
                .always_set_headers
                .push((self.name.clone(), self.value.clone())),
            (HeaderAction::Set, false) => policy
                .set_headers
                .push((self.name.clone(), self.value.clone())),
            (HeaderAction::Add, true) => policy
                .always_add_headers
                .push((self.name.clone(), self.value.clone())),
            (HeaderAction::Add, false) => policy
                .add_headers
                .push((self.name.clone(), self.value.clone())),
            (HeaderAction::Unset, true) => policy.always_unset_headers.push(self.name.clone()),
            (HeaderAction::Unset, false) => policy.unset_headers.push(self.name.clone()),
        }
    }
}

#[derive(Debug, Clone)]
enum SealedValue {
    Tokens,
    OnOff(bool),
    Unsigned(u64),
    Keyword(usize),
    Options(SealedOptions),
    Require(crate::config::Require),
    LegacyHosts(Vec<crate::config::HostSpec>),
    FileEtag(u32),
    ErrorDocument(u16, crate::config::ErrorDoc),
    Header(SealedHeader),
    Redirect(crate::config::Redirect),
    RewriteCond(crate::config::RewriteCond),
    RewriteRule(crate::config::RewriteRule),
    HttpProtocols(Vec<crate::config::HttpProtocol>),
    ExpiresDefault(String),
    ExpiresByType(String, String),
    EnvironmentRule(crate::config::EnvRule),
    GlobPatterns(Vec<String>),
    AllowMethods(crate::config::AllowMethods),
    RequestReadTimeout {
        header: Option<Duration>,
        body: Option<Duration>,
        header_rate: Option<u64>,
        body_rate: Option<u64>,
    },
    Listen(crate::config::ListenSpec),
    RemoteIpNetworks(Vec<(IpAddr, u8)>),
    SslProtocol(String),
    UnitFloat(f64),
    OcspResponderUrl(String),
    AliasRegex(SealedAliasRegex),
    ProxyPass(SealedProxyPass),
    ProxyPassReverse(SealedProxyReverse),
    ProxyPassMatch(SealedProxyMatch),
}

/// Immutable token payload carrying an executable schema certificate.
///
/// Policy compilation consumes this object rather than reparsing an arbitrary
/// `Vec<String>`. Regex matching semantics remain an external engine contract,
/// but regex construction and every other fallible payload parse happen before
/// the program can mutate a `Scope`.
#[derive(Debug, Clone)]
pub(crate) struct SealedPayload {
    args: Box<[String]>,
    value: SealedValue,
}

impl SealedPayload {
    pub(crate) fn seal(
        directive: &str,
        args: Vec<String>,
        schema: PayloadSchema,
    ) -> Result<Self, String> {
        let has_empty = args.iter().any(String::is_empty);
        if !vapache_verified::config_payload_schema_admit(
            args.len(),
            schema.arity.min,
            schema.arity.max,
            schema.reject_empty,
            has_empty,
        ) {
            if !vapache_verified::config_argument_arity_admit(
                args.len(),
                schema.arity.min,
                schema.arity.max,
            ) {
                return Err(format!(
                    "directive '{directive}' requires {} argument(s), got {}",
                    schema.arity.requirement(),
                    args.len()
                ));
            }
            return Err(format!(
                "directive '{directive}' does not permit an empty argument"
            ));
        }
        let value = match schema.value {
            PayloadValueSchema::Tokens => SealedValue::Tokens,
            PayloadValueSchema::DirectoryIndex => {
                for name in &args {
                    let bytes = name.as_bytes();
                    if !vapache_verified::directory_index_name_admit(
                        !name.is_empty(),
                        matches!(name.as_str(), "." | ".."),
                        bytes.iter().any(|byte| matches!(*byte, b'/' | b'\\')),
                        bytes.iter().any(|byte| matches!(*byte, b'?' | b'#')),
                        bytes.contains(&b'%'),
                        bytes.iter().any(|byte| *byte <= b' ' || *byte == 0x7f),
                    ) {
                        return Err(
                            "DirectoryIndex currently requires literal single-component names"
                                .to_string(),
                        );
                    }
                }
                SealedValue::Tokens
            }
            PayloadValueSchema::OnOff => match args.as_slice() {
                [value] if value.eq_ignore_ascii_case("on") => SealedValue::OnOff(true),
                [value] if value.eq_ignore_ascii_case("off") => SealedValue::OnOff(false),
                _ => {
                    return Err(format!(
                        "directive '{directive}' requires exactly On or Off"
                    ))
                }
            },
            PayloadValueSchema::Unsigned { min, max } => {
                let value = match args.as_slice() {
                    [value] => crate::util::parse_u64(value.as_bytes()),
                    _ => None,
                }
                .filter(|value| *value >= min && *value <= max)
                .ok_or_else(|| {
                    format!(
                        "directive '{directive}' requires an unsigned integer from {min} through {max}"
                    )
                })?;
                SealedValue::Unsigned(value)
            }
            PayloadValueSchema::Keyword(keywords) => {
                let index = match args.as_slice() {
                    [value] => keywords
                        .iter()
                        .position(|keyword| value.eq_ignore_ascii_case(keyword)),
                    _ => None,
                }
                .ok_or_else(|| {
                    format!(
                        "directive '{directive}' requires one of: {}",
                        keywords.join(", ")
                    )
                })?;
                SealedValue::Keyword(index)
            }
            PayloadValueSchema::Options => SealedValue::Options(compile_options(&args)?),
            PayloadValueSchema::Require => {
                let require = crate::config::parse_require(&args);
                if let crate::config::Require::Unsupported(message) = &require {
                    if crate::config::require_syntax_error(message) {
                        return Err(message.clone());
                    }
                }
                SealedValue::Require(require)
            }
            PayloadValueSchema::LegacyHosts => {
                SealedValue::LegacyHosts(compile_legacy_hosts(directive, &args)?)
            }
            PayloadValueSchema::FileEtag => SealedValue::FileEtag(compile_file_etag(&args)?),
            PayloadValueSchema::ErrorDocument => {
                let code = crate::util::parse_u64(args[0].as_bytes())
                    .filter(|code| (400..=599).contains(code))
                    .ok_or_else(|| {
                        "ErrorDocument requires an HTTP error status from 400 through 599"
                            .to_string()
                    })? as u16;
                let target = args[1..].join(" ");
                let document = if target.starts_with("http://") || target.starts_with("https://") {
                    crate::config::ErrorDoc::External(target)
                } else if target.starts_with('/') {
                    if crate::util::split_internal_request_target(&target).is_none() {
                        return Err(
                            "local ErrorDocument requires an unambiguous absolute URL-path"
                                .to_string(),
                        );
                    }
                    crate::config::ErrorDoc::Local(target)
                } else {
                    crate::config::ErrorDoc::Text(target)
                };
                SealedValue::ErrorDocument(code, document)
            }
            PayloadValueSchema::Header => SealedValue::Header(compile_header(&args)?),
            PayloadValueSchema::Redirect {
                forced_status,
                regex,
            } => {
                let (status, from, to) =
                    crate::config::parse_redirect_arguments(&args, forced_status)?;
                let redirect = if regex {
                    let compiled = crate::config::compile_regex(&from)
                        .map_err(|error| format!("bad RedirectMatch regex: {error}"))?;
                    crate::config::Redirect {
                        from: String::new(),
                        to,
                        status,
                        regex: Some(std::sync::Arc::new(compiled)),
                    }
                } else {
                    crate::config::Redirect {
                        from,
                        to,
                        status,
                        regex: None,
                    }
                };
                SealedValue::Redirect(redirect)
            }
            PayloadValueSchema::RewriteCond => {
                SealedValue::RewriteCond(crate::config::parse_rewrite_cond(&args)?)
            }
            PayloadValueSchema::RewriteRule => {
                SealedValue::RewriteRule(crate::config::parse_rewrite_rule(&args, "/", false)?)
            }
            PayloadValueSchema::RepeatedKeyword(keyword) => {
                if let Some(invalid) = args
                    .iter()
                    .find(|argument| !argument.eq_ignore_ascii_case(keyword))
                {
                    return Err(format!(
                        "unsupported {directive} flag '{invalid}'; expected {keyword}"
                    ));
                }
                SealedValue::Tokens
            }
            PayloadValueSchema::HttpProtocols => {
                SealedValue::HttpProtocols(crate::config::parse_http_protocols(&args)?)
            }
            PayloadValueSchema::ExpiresDefault => {
                let spec = args.join(" ");
                if !crate::expires::valid_spec(&spec) {
                    return Err("ExpiresDefault has invalid expiry syntax".into());
                }
                SealedValue::ExpiresDefault(spec)
            }
            PayloadValueSchema::ExpiresByType => {
                let spec = args[1..].join(" ");
                if !crate::expires::valid_spec(&spec) {
                    return Err("ExpiresByType has invalid expiry syntax".into());
                }
                SealedValue::ExpiresByType(args[0].to_ascii_lowercase(), spec)
            }
            PayloadValueSchema::EnvironmentRule => {
                SealedValue::EnvironmentRule(crate::config::parse_env_rule(directive, &args)?)
            }
            PayloadValueSchema::GlobPatterns => {
                for pattern in &args {
                    crate::config::validate_glob_pattern(pattern)?;
                }
                SealedValue::GlobPatterns(args.clone())
            }
            PayloadValueSchema::AllowMethods => {
                SealedValue::AllowMethods(crate::config::parse_allow_methods(&args)?)
            }
            PayloadValueSchema::RequestReadTimeout => {
                let (header, body, header_rate, body_rate) =
                    crate::config::parse_request_read_timeout(&args.join(" "))
                        .ok_or_else(|| "RequestReadTimeout has invalid syntax".to_string())?;
                SealedValue::RequestReadTimeout {
                    header,
                    body,
                    header_rate,
                    body_rate,
                }
            }
            PayloadValueSchema::Listen => {
                if let Some(protocol) = args.get(1) {
                    if !matches!(protocol.to_ascii_lowercase().as_str(), "http" | "https") {
                        return Err(format!("unsupported Listen protocol hint '{protocol}'"));
                    }
                }
                SealedValue::Listen(crate::config::parse_listen(&args[0])?)
            }
            PayloadValueSchema::RemoteIpNetworks => {
                let mut networks = Vec::with_capacity(args.len());
                for raw in &args {
                    let network = if raw.eq_ignore_ascii_case("all") {
                        (IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
                    } else {
                        crate::config::parse_ip_net(raw).ok_or_else(|| {
                            let display = if directive == "remoteipinternalproxy" {
                                "RemoteIPInternalProxy"
                            } else if directive == "remoteiptrustedproxy" {
                                "RemoteIPTrustedProxy"
                            } else {
                                directive
                            };
                            format!("bad {display} address '{raw}'")
                        })?
                    };
                    networks.push(network);
                }
                SealedValue::RemoteIpNetworks(networks)
            }
            PayloadValueSchema::SslProtocol => {
                let policy = args.join(" ");
                crate::tls::protocol_policy(Some(&policy))?;
                SealedValue::SslProtocol(policy)
            }
            PayloadValueSchema::UnitFloat => {
                let value = args[0]
                    .parse::<f64>()
                    .ok()
                    .filter(|value| value.is_finite() && (0.0..=1.0).contains(value))
                    .ok_or_else(|| {
                        format!("directive '{directive}' requires a finite number from 0 through 1")
                    })?;
                SealedValue::UnitFloat(value)
            }
            PayloadValueSchema::OcspResponderUrl => {
                if !crate::ocsp::supported_responder_url(&args[0]) {
                    return Err(format!(
                        "directive '{directive}' requires one supported http:// responder URL"
                    ));
                }
                SealedValue::OcspResponderUrl(args[0].clone())
            }
            PayloadValueSchema::AliasRegex => {
                let pattern = crate::config::compile_regex(&args[0])
                    .map_err(|error| format!("bad {directive} regex: {error}"))?;
                SealedValue::AliasRegex(SealedAliasRegex {
                    pattern: std::sync::Arc::new(pattern),
                    target: args[1].clone(),
                })
            }
            PayloadValueSchema::ProxyPass => {
                if args[1] == "!" || args[1].starts_with('!') {
                    return Err("ProxyPass exclusions (!) are not implemented; refusing to ignore a route exclusion".into());
                }
                if args[0].starts_with('!') {
                    return Err("ProxyPass path cannot start with '!'; exclusions use '!' as the backend argument".into());
                }
                if !crate::config::supported_proxy_backend(&args[1], false) {
                    return Err(format!("unsupported ProxyPass backend '{}'", args[1]));
                }
                let mut sticky_cookie = None;
                let mut fail_on_status = Vec::new();
                for item in &args[2..] {
                    let (key, value) = item.split_once('=').ok_or_else(|| {
                        format!("ProxyPass parameter '{item}' must use name=value syntax")
                    })?;
                    match key.to_ascii_lowercase().as_str() {
                        "stickysession" => sticky_cookie = Some(value.to_string()),
                        "failonstatus" => {
                            let (statuses, unparsable) = crate::config::parse_status_list(value);
                            if !unparsable.is_empty() {
                                return Err(format!(
                                    "ProxyPass failonstatus contains non-numeric entries {unparsable:?}"
                                ));
                            }
                            fail_on_status = statuses;
                        }
                        _ => return Err(format!("unsupported ProxyPass parameter '{key}'")),
                    }
                }
                SealedValue::ProxyPass(SealedProxyPass {
                    prefix: args[0].clone(),
                    fastcgi: args[1].to_ascii_lowercase().contains("fcgi://"),
                    backend: args[1].clone(),
                    sticky_cookie,
                    fail_on_status,
                })
            }
            PayloadValueSchema::ProxyPassReverse => {
                if !crate::config::supported_proxy_backend(&args[1], false) {
                    return Err(format!(
                        "unsupported ProxyPassReverse backend '{}'",
                        args[1]
                    ));
                }
                SealedValue::ProxyPassReverse(SealedProxyReverse {
                    front: args[0].clone(),
                    backend: args[1].clone(),
                })
            }
            PayloadValueSchema::ProxyPassMatch => {
                if args[1] == "!" || args[1].starts_with('!') {
                    return Err("ProxyPassMatch exclusions (!) are not implemented; refusing to ignore a route exclusion".into());
                }
                if !crate::config::supported_proxy_backend(&args[1], true) {
                    return Err(format!("unsupported ProxyPassMatch backend '{}'", args[1]));
                }
                if !crate::config::proxy_template_authority_safe(&args[1]) {
                    return Err(format!(
                        "ProxyPassMatch backend authority may not be derived from a capture: '{}'",
                        args[1]
                    ));
                }
                let pattern = crate::config::compile_regex(&args[0])
                    .map_err(|error| format!("bad ProxyPassMatch regex: {error}"))?;
                SealedValue::ProxyPassMatch(SealedProxyMatch {
                    pattern: std::sync::Arc::new(pattern),
                    fastcgi: args[1].to_ascii_lowercase().contains("fcgi://"),
                    backend: args[1].clone(),
                })
            }
            PayloadValueSchema::Validated(kind) => {
                validate_compatibility_payload(directive, &args, kind)?;
                SealedValue::Tokens
            }
        };
        Ok(Self {
            args: args.into_boxed_slice(),
            value,
        })
    }

    pub(crate) fn as_slice(&self) -> &[String] {
        &self.args
    }

    pub(crate) fn on_off(&self) -> Option<bool> {
        match self.value {
            SealedValue::OnOff(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn unsigned(&self) -> Option<u64> {
        match self.value {
            SealedValue::Unsigned(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn keyword(&self) -> Option<usize> {
        match self.value {
            SealedValue::Keyword(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn options(&self) -> Option<&SealedOptions> {
        match &self.value {
            SealedValue::Options(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn require(&self) -> Option<&crate::config::Require> {
        match &self.value {
            SealedValue::Require(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn legacy_hosts(&self) -> Option<&[crate::config::HostSpec]> {
        match &self.value {
            SealedValue::LegacyHosts(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn file_etag(&self) -> Option<u32> {
        match self.value {
            SealedValue::FileEtag(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn error_document(&self) -> Option<(u16, &crate::config::ErrorDoc)> {
        match &self.value {
            SealedValue::ErrorDocument(code, document) => Some((*code, document)),
            _ => None,
        }
    }

    pub(crate) fn header(&self) -> Option<&SealedHeader> {
        match &self.value {
            SealedValue::Header(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn redirect(&self) -> Option<&crate::config::Redirect> {
        match &self.value {
            SealedValue::Redirect(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn rewrite_cond(&self) -> Option<&crate::config::RewriteCond> {
        match &self.value {
            SealedValue::RewriteCond(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn rewrite_rule(&self) -> Option<&crate::config::RewriteRule> {
        match &self.value {
            SealedValue::RewriteRule(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn http_protocols(&self) -> Option<&[crate::config::HttpProtocol]> {
        match &self.value {
            SealedValue::HttpProtocols(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn expires_default(&self) -> Option<&str> {
        match &self.value {
            SealedValue::ExpiresDefault(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn expires_by_type(&self) -> Option<(&str, &str)> {
        match &self.value {
            SealedValue::ExpiresByType(content_type, value) => Some((content_type, value)),
            _ => None,
        }
    }

    pub(crate) fn environment_rule(&self) -> Option<&crate::config::EnvRule> {
        match &self.value {
            SealedValue::EnvironmentRule(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn glob_patterns(&self) -> Option<&[String]> {
        match &self.value {
            SealedValue::GlobPatterns(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn allow_methods(&self) -> Option<&crate::config::AllowMethods> {
        match &self.value {
            SealedValue::AllowMethods(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn request_read_timeout(
        &self,
    ) -> Option<(Option<Duration>, Option<Duration>, Option<u64>, Option<u64>)> {
        match self.value {
            SealedValue::RequestReadTimeout {
                header,
                body,
                header_rate,
                body_rate,
            } => Some((header, body, header_rate, body_rate)),
            _ => None,
        }
    }

    pub(crate) fn listen(&self) -> Option<&crate::config::ListenSpec> {
        match &self.value {
            SealedValue::Listen(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn remote_ip_networks(&self) -> Option<&[(IpAddr, u8)]> {
        match &self.value {
            SealedValue::RemoteIpNetworks(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn ssl_protocol(&self) -> Option<&str> {
        match &self.value {
            SealedValue::SslProtocol(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn unit_float(&self) -> Option<f64> {
        match self.value {
            SealedValue::UnitFloat(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn ocsp_responder_url(&self) -> Option<&str> {
        match &self.value {
            SealedValue::OcspResponderUrl(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn alias_regex(&self) -> Option<&SealedAliasRegex> {
        match &self.value {
            SealedValue::AliasRegex(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn proxy_pass(&self) -> Option<&SealedProxyPass> {
        match &self.value {
            SealedValue::ProxyPass(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn proxy_pass_reverse(&self) -> Option<&SealedProxyReverse> {
        match &self.value {
            SealedValue::ProxyPassReverse(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn proxy_pass_match(&self) -> Option<&SealedProxyMatch> {
        match &self.value {
            SealedValue::ProxyPassMatch(value) => Some(value),
            _ => None,
        }
    }
}

fn validate_compatibility_payload(
    directive: &str,
    args: &[String],
    kind: PayloadValidation,
) -> Result<(), String> {
    match kind {
        PayloadValidation::Capability => {
            crate::config::Capability::parse(&args[0])
                .ok_or_else(|| format!("unknown vapache capability '{}'", args[0]))?;
            if !matches!(args[1].to_ascii_lowercase().as_str(), "on" | "off") {
                return Err("VapacheCapability requires On or Off".into());
            }
        }
        PayloadValidation::FastCgiStablePath => {
            if args.len() == 1 && args[0].eq_ignore_ascii_case("off") {
                return Ok(());
            }
            if args.len() < 5 || !args[0].eq_ignore_ascii_case("on") {
                return Err("VapacheFastCGIStablePath requires 'Off' or 'On <unix-endpoint> <backend-uid> <endpoint-owner-uid> <trusted-owner-uid>...'".into());
            }
            if matches!(
                crate::config::parse_fastcgi_policy_endpoint(&args[1])?,
                crate::config::FastCgiEndpoint::Tcp { .. }
            ) {
                return Err("VapacheFastCGIStablePath requires a Unix socket; TCP cannot authenticate the backend process".into());
            }
            let backend_uid = args[2]
                .parse::<u32>()
                .map_err(|_| format!("invalid FastCGI backend uid '{}'", args[2]))?;
            if backend_uid == 0 {
                return Err("VapacheFastCGIStablePath rejects uid 0 backends".into());
            }
            args[3]
                .parse::<u32>()
                .map_err(|_| format!("invalid Unix FastCGI endpoint-owner uid '{}'", args[3]))?;
            for raw in &args[4..] {
                raw.parse::<u32>()
                    .map_err(|_| format!("invalid trusted path-owner uid '{raw}'"))?;
            }
        }
        PayloadValidation::ServerAliases => {
            for alias in args {
                let wildcard = alias.contains('*') || alias.contains('?');
                let supported = alias == "*"
                    || alias.strip_prefix("*.").is_some_and(|suffix| {
                        !suffix.is_empty() && !suffix.contains('*') && !suffix.contains('?')
                    });
                if wildcard && !supported {
                    return Err(format!(
                        "ServerAlias wildcard '{alias}' is not implemented; only '*' or a leading '*.suffix' wildcard is supported"
                    ));
                }
            }
        }
        PayloadValidation::AllowOverride => validate_allow_override(args)?,
        PayloadValidation::AllowOverrideList => {
            let none = args.iter().any(|arg| arg.eq_ignore_ascii_case("none"));
            if none && args.len() != 1 {
                return Err(
                    "AllowOverrideList None cannot be combined with directive names".into(),
                );
            }
        }
        PayloadValidation::RewriteMap => {
            let (map_kind, source) = args[1].split_once(':').unwrap_or(("txt", &args[1]));
            if source.is_empty() {
                return Err("RewriteMap requires a non-empty map source".into());
            }
            match map_kind.to_ascii_lowercase().as_str() {
                "txt" | "rnd" | "prg" => {}
                "int" if matches!(source.to_ascii_lowercase().as_str(), "tolower" | "toupper") => {}
                "int" => return Err(format!("unsupported RewriteMap int function '{source}'")),
                other => return Err(format!("unsupported RewriteMap type '{other}'")),
            }
        }
        PayloadValidation::LogLevel => {
            let value = &args[0];
            if value.contains(':') {
                return Err("module-specific LogLevel is not implemented; refusing to replace the configured audit policy with a global level".into());
            }
            if !matches!(
                value.to_ascii_lowercase().as_str(),
                "emerg"
                    | "alert"
                    | "crit"
                    | "error"
                    | "warn"
                    | "notice"
                    | "info"
                    | "debug"
                    | "trace1"
                    | "trace2"
                    | "trace3"
                    | "trace4"
                    | "trace5"
                    | "trace6"
                    | "trace7"
                    | "trace8"
            ) {
                return Err("LogLevel contains an invalid level".into());
            }
        }
        PayloadValidation::SslRandomSeed => {
            if !(2..=3).contains(&args.len())
                || !matches!(args[0].to_ascii_lowercase().as_str(), "startup" | "connect")
            {
                return Err("SSLRandomSeed requires startup|connect, a builtin/file:/exec:/egd: source, and optional byte count".into());
            }
            let source = args[1].to_ascii_lowercase();
            if source != "builtin"
                && !["file:", "exec:", "egd:"]
                    .iter()
                    .any(|prefix| source.starts_with(prefix) && source.len() > prefix.len())
            {
                return Err("SSLRandomSeed requires startup|connect, a builtin/file:/exec:/egd: source, and optional byte count".into());
            }
            if args
                .get(2)
                .is_some_and(|value| crate::util::parse_u64(value.as_bytes()).is_none())
            {
                return Err("SSLRandomSeed requires startup|connect, a builtin/file:/exec:/egd: source, and optional byte count".into());
            }
        }
        PayloadValidation::SslPassphraseDialog => {
            let value = &args[0];
            if !value.eq_ignore_ascii_case("builtin")
                && !value
                    .strip_prefix("exec:")
                    .is_some_and(|program| std::path::Path::new(program).is_absolute())
            {
                return Err(
                    "SSLPassPhraseDialog requires builtin or exec:/absolute/program".into(),
                );
            }
        }
        PayloadValidation::SslSessionCache => {
            let value = &args[0];
            if !value.eq_ignore_ascii_case("none")
                && !value.eq_ignore_ascii_case("nonenotnull")
                && !valid_provider_target(value)
            {
                return Err("SSLSessionCache requires none or a provider:target value".into());
            }
        }
        PayloadValidation::SslStaplingCache => {
            if !valid_provider_target(&args[0]) {
                return Err("SSLStaplingCache requires a provider:target value".into());
            }
        }
        PayloadValidation::SslOptions => {
            if args
                .iter()
                .any(|value| !value.eq_ignore_ascii_case("+StrictRequire"))
            {
                return Err("only SSLOptions +StrictRequire is supported".into());
            }
        }
        PayloadValidation::BalancerMember => validate_proxy_parameters(directive, &args[1..])?,
        PayloadValidation::ProxySet => validate_proxy_parameters(directive, args)?,
        PayloadValidation::ProxyHealthTemplate => validate_proxy_parameters(directive, &args[1..])?,
    }
    Ok(())
}

fn valid_provider_target(value: &str) -> bool {
    value
        .split_once(':')
        .is_some_and(|(provider, target)| !provider.is_empty() && !target.is_empty())
}

fn validate_allow_override(args: &[String]) -> Result<(), String> {
    for argument in args {
        let lower = argument.to_ascii_lowercase();
        if let Some(mode) = lower.strip_prefix("nonfatal=") {
            if !matches!(mode, "override" | "unknown" | "all") {
                return Err(format!("invalid Nonfatal mode '{mode}'"));
            }
            continue;
        }
        if let Some(options) = lower.strip_prefix("options=") {
            if options.is_empty()
                || options.split(',').any(|option| {
                    !matches!(
                        option,
                        "all"
                            | "none"
                            | "execcgi"
                            | "includes"
                            | "includesnoexec"
                            | "followsymlinks"
                            | "indexes"
                            | "multiviews"
                            | "symlinksifownermatch"
                    )
                })
            {
                return Err(format!("invalid AllowOverride option '{argument}'"));
            }
            continue;
        }
        if !matches!(
            lower.as_str(),
            "all"
                | "none"
                | "authconfig"
                | "fileinfo"
                | "indexes"
                | "limit"
                | "options"
                | "execcgi"
                | "includes"
                | "includesnoexec"
                | "languagepriority"
        ) {
            return Err(format!("unsupported AllowOverride category '{argument}'"));
        }
    }
    Ok(())
}

fn validate_proxy_parameters(directive: &str, parameters: &[String]) -> Result<(), String> {
    for item in parameters {
        let (key, value) = item
            .split_once('=')
            .ok_or_else(|| format!("{directive} parameter '{item}' must use name=value syntax"))?;
        let key_lower = key.to_ascii_lowercase();
        let recognized = matches!(key_lower.as_str(), "hcmethod" | "hcuri")
            || (directive == "balancermember"
                && matches!(key_lower.as_str(), "template" | "route"))
            || (directive == "proxyset"
                && matches!(
                    key_lower.as_str(),
                    "stickysession" | "stickysessionsep" | "failonstatus"
                ));
        if recognized {
            if key.eq_ignore_ascii_case("failonstatus") {
                let (_, bad) = crate::config::parse_status_list(value);
                if !bad.is_empty() {
                    return Err(format!(
                        "{directive} failonstatus contains non-numeric entries {bad:?}"
                    ));
                }
            }
            continue;
        }
        match key_lower.as_str() {
            "hcinterval" => {
                parse_duration(value)
                    .ok_or_else(|| format!("invalid {directive} hcinterval '{value}'"))?;
            }
            "hcpasses" | "hcfails" => {
                value
                    .parse::<u32>()
                    .map_err(|_| format!("invalid {directive} {key} '{value}'"))?;
            }
            _ => return Err(format!("unsupported {directive} parameter '{key}'")),
        }
    }
    Ok(())
}

fn parse_duration(value: &str) -> Option<Duration> {
    let value = value.trim();
    let (digits, multiplier) = if let Some(value) = value.strip_suffix("ms") {
        (value, 1u64)
    } else if let Some(value) = value.strip_suffix('s') {
        (value, 1_000)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60_000)
    } else {
        (value, 1_000)
    };
    let millis = crate::util::parse_u64(digits.as_bytes())?.checked_mul(multiplier)?;
    Some(Duration::from_millis(millis))
}

fn compile_legacy_hosts(
    directive: &str,
    args: &[String],
) -> Result<Vec<crate::config::HostSpec>, String> {
    if !args[0].eq_ignore_ascii_case("from") {
        return Err(format!("{directive} must be followed by 'from'"));
    }
    args[1..]
        .iter()
        .map(|argument| {
            if argument.eq_ignore_ascii_case("all") {
                Ok(crate::config::HostSpec::All)
            } else if let Some((network, bits)) = crate::config::parse_ip_net(argument) {
                Ok(crate::config::HostSpec::Net(network, bits))
            } else {
                Err(format!("unsupported {directive} host '{argument}'"))
            }
        })
        .collect()
}

fn compile_file_etag(args: &[String]) -> Result<u32, String> {
    use crate::config::{ETAG_ALL, ETAG_INODE, ETAG_MTIME, ETAG_SIZE};
    let mut value = 0u32;
    for argument in args {
        match argument.to_ascii_lowercase().as_str() {
            "none" => value = 0,
            "all" => value = ETAG_ALL,
            "inode" => value |= ETAG_INODE,
            "mtime" => value |= ETAG_MTIME,
            "size" => value |= ETAG_SIZE,
            _ => {
                return Err(format!(
                    "FileETag contains unsupported keyword '{argument}'"
                ))
            }
        }
    }
    Ok(value)
}

fn compile_header(args: &[String]) -> Result<SealedHeader, String> {
    let mut index = 0;
    let always = args[0].eq_ignore_ascii_case("always");
    if always || args[0].eq_ignore_ascii_case("onsuccess") {
        index = 1;
    }
    if args.len() < index + 2 {
        return Err("Header requires an action and a header name".into());
    }
    let action = match args[index].to_ascii_lowercase().as_str() {
        "set" => HeaderAction::Set,
        "add" => HeaderAction::Add,
        "unset" => HeaderAction::Unset,
        other => {
            return Err(format!(
                "Header action '{other}' is not implemented; refusing to ignore a response-header policy"
            ))
        }
    };
    let minimum = match action {
        HeaderAction::Set | HeaderAction::Add => index + 3,
        HeaderAction::Unset => index + 2,
    };
    let conditional = args[index + 2..].iter().any(|argument| {
        argument.eq_ignore_ascii_case("early")
            || argument.to_ascii_lowercase().starts_with("env=")
            || argument.to_ascii_lowercase().starts_with("expr=")
    });
    if args.len() < minimum
        || (matches!(action, HeaderAction::Unset) && args.len() != minimum)
        || conditional
    {
        return Err(
            "conditional or extended Header forms are not implemented; refusing to broaden the header policy"
                .into(),
        );
    }
    Ok(SealedHeader {
        always,
        action,
        name: args[index + 1].trim_end_matches(':').to_string(),
        value: args[index + 2..].join(" "),
    })
}

fn compile_options(args: &[String]) -> Result<SealedOptions, String> {
    use crate::config::Options;

    let mut requires_autoindex = false;
    let mut requires_cgi = false;
    for argument in args {
        if argument.starts_with('-') {
            continue;
        }
        match argument
            .trim_start_matches('+')
            .to_ascii_lowercase()
            .as_str()
        {
            "all" => {
                requires_autoindex = true;
                requires_cgi = true;
            }
            "indexes" => requires_autoindex = true,
            "execcgi" => requires_cgi = true,
            _ => {}
        }
    }

    // A signless list is an absolute set. Build that set before applying the
    // signed operations, preserving Apache's within-directive order.
    let mut reset_mask = Options::empty().0;
    let mut resets = false;
    for argument in args {
        if argument.starts_with('+') || argument.starts_with('-') {
            continue;
        }
        let bit = match argument.to_ascii_lowercase().as_str() {
            "indexes" => Some(Options::INDEXES),
            "followsymlinks" => Some(Options::FOLLOW_SYMLINKS),
            "symlinksifownermatch" => Some(Options::SYMLINKS_IF_OWNER_MATCH),
            "execcgi" => Some(Options::EXEC_CGI),
            "includes" => Some(Options::INCLUDES),
            "includesnoexec" => Some(Options::INCLUDES_NOEXEC),
            "multiviews" => Some(Options::MULTIVIEWS),
            // None and All are represented by their explicit Set below.
            "none" | "all" => None,
            _ => continue,
        };
        if let Some(bit) = bit {
            reset_mask |= bit;
            resets = true;
        }
    }

    let mut policy = crate::scope_policy::OptionsPolicy::default();
    if resets {
        policy.push_set(Options::empty().0);
        policy.push_add(reset_mask);
    }
    for argument in args {
        let (operation, flag) = match argument.as_bytes().first() {
            Some(b'+') => (1, &argument[1..]),
            Some(b'-') => (2, &argument[1..]),
            _ => (0, argument.as_str()),
        };
        let lower = flag.to_ascii_lowercase();
        let bits = match lower.as_str() {
            "none" => Options::empty().0,
            "all" => Options::all().0,
            "indexes" => Options::INDEXES,
            "followsymlinks" => Options::FOLLOW_SYMLINKS,
            "symlinksifownermatch" => Options::SYMLINKS_IF_OWNER_MATCH,
            "execcgi" => Options::EXEC_CGI,
            "includes" => Options::INCLUDES,
            "includesnoexec" => Options::INCLUDES_NOEXEC,
            "multiviews" => Options::MULTIVIEWS,
            _ => return Err(format!("unsupported Options flag '{argument}'")),
        };
        match operation {
            1 => policy.push_add(bits),
            2 => policy.push_remove(bits),
            _ if lower == "none" || lower == "all" => policy.push_set(bits),
            _ => policy.push_add(bits),
        }
    }
    Ok(SealedOptions {
        policy,
        requires_autoindex,
        requires_cgi,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_payload_enforces_the_complete_structural_schema() {
        let one_nonempty = PayloadSchema::new(PayloadArity::ONE, true);
        assert_eq!(
            SealedPayload::seal("Path", vec!["/srv".into()], one_nonempty)
                .unwrap()
                .as_slice(),
            &["/srv"]
        );
        assert!(SealedPayload::seal("Path", Vec::new(), one_nonempty)
            .unwrap_err()
            .contains("exactly 1"));
        assert!(
            SealedPayload::seal("Path", vec![String::new()], one_nonempty)
                .unwrap_err()
                .contains("empty argument")
        );
        assert!(
            SealedPayload::seal("Path", vec!["one".into(), "two".into()], one_nonempty).is_err()
        );
    }

    #[test]
    fn sealed_payload_compiles_primitive_values_once() {
        let toggle = PayloadSchema::typed(PayloadArity::ONE, true, PayloadValueSchema::OnOff);
        assert_eq!(
            SealedPayload::seal("Toggle", vec!["oN".into()], toggle)
                .unwrap()
                .on_off(),
            Some(true)
        );
        assert!(SealedPayload::seal("Toggle", vec!["maybe".into()], toggle).is_err());

        let bounded = PayloadSchema::typed(
            PayloadArity::ONE,
            true,
            PayloadValueSchema::Unsigned { min: 1, max: 9 },
        );
        assert_eq!(
            SealedPayload::seal("Level", vec!["9".into()], bounded)
                .unwrap()
                .unsigned(),
            Some(9)
        );
        assert!(SealedPayload::seal("Level", vec!["10".into()], bounded).is_err());
    }
}
