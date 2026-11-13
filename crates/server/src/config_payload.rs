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

impl PayloadValueSchema {
    pub(crate) const fn semantic_kind(self) -> httpd_rs_verified::ConfigSemanticKind {
        use httpd_rs_verified::ConfigSemanticKind as Kind;
        match self {
            Self::Tokens => Kind::Tokens,
            Self::DirectoryIndex => Kind::DirectoryIndex,
            Self::OnOff => Kind::OnOff,
            Self::Unsigned { .. } => Kind::Unsigned,
            Self::Keyword(_) => Kind::Keyword,
            Self::Options => Kind::Options,
            Self::Require => Kind::Require,
            Self::LegacyHosts => Kind::LegacyHosts,
            Self::FileEtag => Kind::FileEtag,
            Self::ErrorDocument => Kind::ErrorDocument,
            Self::Header => Kind::Header,
            Self::Redirect { .. } => Kind::Redirect,
            Self::RewriteCond => Kind::RewriteCond,
            Self::RewriteRule => Kind::RewriteRule,
            Self::RepeatedKeyword(_) => Kind::RepeatedKeyword,
            Self::HttpProtocols => Kind::HttpProtocols,
            Self::ExpiresDefault => Kind::ExpiresDefault,
            Self::ExpiresByType => Kind::ExpiresByType,
            Self::EnvironmentRule => Kind::EnvironmentRule,
            Self::GlobPatterns => Kind::GlobPatterns,
            Self::AllowMethods => Kind::AllowMethods,
            Self::RequestReadTimeout => Kind::RequestReadTimeout,
            Self::Listen => Kind::Listen,
            Self::RemoteIpNetworks => Kind::RemoteIpNetworks,
            Self::SslProtocol => Kind::SslProtocol,
            Self::UnitFloat => Kind::UnitFloat,
            Self::OcspResponderUrl => Kind::OcspResponderUrl,
            Self::AliasRegex => Kind::AliasRegex,
            Self::ProxyPass => Kind::ProxyPass,
            Self::ProxyPassReverse => Kind::ProxyPassReverse,
            Self::ProxyPassMatch => Kind::ProxyPassMatch,
            Self::Validated(kind) => match kind {
                PayloadValidation::Capability => Kind::Capability,
                PayloadValidation::FastCgiStablePath => Kind::FastCgiStablePath,
                PayloadValidation::ServerAliases => Kind::ServerAliases,
                PayloadValidation::AllowOverride => Kind::AllowOverride,
                PayloadValidation::AllowOverrideList => Kind::AllowOverrideList,
                PayloadValidation::RewriteMap => Kind::RewriteMap,
                PayloadValidation::LogLevel => Kind::LogLevel,
                PayloadValidation::SslRandomSeed => Kind::SslRandomSeed,
                PayloadValidation::SslPassphraseDialog => Kind::SslPassphraseDialog,
                PayloadValidation::SslSessionCache => Kind::SslSessionCache,
                PayloadValidation::SslStaplingCache => Kind::SslStaplingCache,
                PayloadValidation::SslOptions => Kind::SslOptions,
                PayloadValidation::BalancerMember => Kind::BalancerMember,
                PayloadValidation::ProxySet => Kind::ProxySet,
                PayloadValidation::ProxyHealthTemplate => Kind::ProxyHealthTemplate,
            },
        }
    }
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
    pub(crate) pattern: std::sync::Arc<crate::apache_regex::Regex>,
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
    pub(crate) pattern: std::sync::Arc<crate::apache_regex::Regex>,
    pub(crate) backend: String,
    pub(crate) fastcgi: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct SealedProxySet {
    pub(crate) health: crate::config::HealthTemplate,
    pub(crate) sticky_cookie: Option<String>,
    pub(crate) sticky_sep: Option<String>,
    pub(crate) fail_on_status: Option<Vec<u16>>,
}

#[derive(Debug, Clone)]
pub(crate) struct SealedAllowOverride {
    pub(crate) mode: crate::config::OverrideMode,
    pub(crate) nonfatal: crate::config::NonfatalMode,
    pub(crate) enables_access_files: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct SealedAllowOverrideList {
    pub(crate) directives: Vec<String>,
    pub(crate) enables_access_files: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SealedRewriteMap {
    pub(crate) name: String,
    pub(crate) source: SealedRewriteMapSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SealedRewriteMapSource {
    Txt(String),
    Rnd(String),
    Prg { program: String, args: Vec<String> },
    Int(String),
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
    TokenClass(httpd_rs_verified::ConfigSemanticKind),
    Capability(crate::config::Capability, bool),
    FastCgiStablePath(Option<crate::config::FastCgiStablePathPolicy>),
    ServerAliases(Vec<String>),
    RewriteMap(SealedRewriteMap),
    LogLevel(String),
    SslSessionCache(bool),
    BalancerMember(crate::config::BalancerMember),
    ProxySet(SealedProxySet),
    ProxyHealthTemplate(String, crate::config::HealthTemplate),
    AllowOverride(SealedAllowOverride),
    AllowOverrideList(SealedAllowOverrideList),
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

impl SealedValue {
    fn semantic_kind(&self) -> httpd_rs_verified::ConfigSemanticKind {
        use httpd_rs_verified::ConfigSemanticKind as Kind;
        match self {
            Self::TokenClass(kind) => *kind,
            Self::Capability(_, _) => Kind::Capability,
            Self::FastCgiStablePath(_) => Kind::FastCgiStablePath,
            Self::ServerAliases(_) => Kind::ServerAliases,
            Self::RewriteMap(_) => Kind::RewriteMap,
            Self::LogLevel(_) => Kind::LogLevel,
            Self::SslSessionCache(_) => Kind::SslSessionCache,
            Self::BalancerMember(_) => Kind::BalancerMember,
            Self::ProxySet(_) => Kind::ProxySet,
            Self::ProxyHealthTemplate(_, _) => Kind::ProxyHealthTemplate,
            Self::AllowOverride(_) => Kind::AllowOverride,
            Self::AllowOverrideList(_) => Kind::AllowOverrideList,
            Self::OnOff(_) => Kind::OnOff,
            Self::Unsigned(_) => Kind::Unsigned,
            Self::Keyword(_) => Kind::Keyword,
            Self::Options(_) => Kind::Options,
            Self::Require(_) => Kind::Require,
            Self::LegacyHosts(_) => Kind::LegacyHosts,
            Self::FileEtag(_) => Kind::FileEtag,
            Self::ErrorDocument(_, _) => Kind::ErrorDocument,
            Self::Header(_) => Kind::Header,
            Self::Redirect(_) => Kind::Redirect,
            Self::RewriteCond(_) => Kind::RewriteCond,
            Self::RewriteRule(_) => Kind::RewriteRule,
            Self::HttpProtocols(_) => Kind::HttpProtocols,
            Self::ExpiresDefault(_) => Kind::ExpiresDefault,
            Self::ExpiresByType(_, _) => Kind::ExpiresByType,
            Self::EnvironmentRule(_) => Kind::EnvironmentRule,
            Self::GlobPatterns(_) => Kind::GlobPatterns,
            Self::AllowMethods(_) => Kind::AllowMethods,
            Self::RequestReadTimeout { .. } => Kind::RequestReadTimeout,
            Self::Listen(_) => Kind::Listen,
            Self::RemoteIpNetworks(_) => Kind::RemoteIpNetworks,
            Self::SslProtocol(_) => Kind::SslProtocol,
            Self::UnitFloat(_) => Kind::UnitFloat,
            Self::OcspResponderUrl(_) => Kind::OcspResponderUrl,
            Self::AliasRegex(_) => Kind::AliasRegex,
            Self::ProxyPass(_) => Kind::ProxyPass,
            Self::ProxyPassReverse(_) => Kind::ProxyPassReverse,
            Self::ProxyPassMatch(_) => Kind::ProxyPassMatch,
        }
    }
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
    semantic_kind: httpd_rs_verified::ConfigSemanticKind,
}

impl SealedPayload {
    pub(crate) fn seal(
        directive: &str,
        args: Vec<String>,
        schema: PayloadSchema,
    ) -> Result<Self, String> {
        let has_empty = args.iter().any(String::is_empty);
        if !httpd_rs_verified::config_payload_schema_admit(
            args.len(),
            schema.arity.min,
            schema.arity.max,
            schema.reject_empty,
            has_empty,
        ) {
            if !httpd_rs_verified::config_argument_arity_admit(
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
        let source_argument_count = args.len();
        let schema_kind = schema.value.semantic_kind();
        let value = match schema.value {
            PayloadValueSchema::Tokens => SealedValue::TokenClass(schema_kind),
            PayloadValueSchema::DirectoryIndex => {
                for name in &args {
                    let bytes = name.as_bytes();
                    if !httpd_rs_verified::directory_index_name_admit(
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
                SealedValue::TokenClass(schema_kind)
            }
            PayloadValueSchema::OnOff => match args.as_slice() {
                [value] => match httpd_rs_verified::config_on_off(value.as_bytes()) {
                    Some(value) => SealedValue::OnOff(value),
                    None => {
                        return Err(format!(
                            "directive '{directive}' requires exactly On or Off"
                        ))
                    }
                },
                _ => {
                    return Err(format!(
                        "directive '{directive}' requires exactly On or Off"
                    ))
                }
            },
            PayloadValueSchema::Unsigned { min, max } => {
                let value = match args.as_slice() {
                    [value] => httpd_rs_verified::config_bounded_unsigned(
                        httpd_rs_verified::parse_decimal_u64(value.as_bytes()),
                        min,
                        max,
                    ),
                    _ => None,
                }
                .ok_or_else(|| {
                    format!(
                        "directive '{directive}' requires an unsigned integer from {min} through {max}"
                    )
                })?;
                SealedValue::Unsigned(value)
            }
            PayloadValueSchema::Keyword(keywords) => {
                let index = match args.as_slice() {
                    [value] => {
                        let vocabulary = keywords
                            .iter()
                            .map(|keyword| keyword.as_bytes().to_vec())
                            .collect::<Vec<_>>();
                        httpd_rs_verified::config_keyword_index(value.as_bytes(), &vocabulary)
                    }
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
                SealedValue::TokenClass(schema_kind)
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
            PayloadValueSchema::Validated(PayloadValidation::Capability) => {
                let capability = crate::config::Capability::parse(&args[0])
                    .ok_or_else(|| format!("unknown httpd-rs capability '{}'", args[0]))?;
                let enabled = httpd_rs_verified::config_on_off(args[1].as_bytes())
                    .ok_or_else(|| "HttpdRsCapability requires On or Off".to_string())?;
                SealedValue::Capability(capability, enabled)
            }
            PayloadValueSchema::Validated(PayloadValidation::FastCgiStablePath) => {
                if args.len() == 1 && args[0].eq_ignore_ascii_case("off") {
                    SealedValue::FastCgiStablePath(None)
                } else {
                    if args.len() < 5 || !args[0].eq_ignore_ascii_case("on") {
                        return Err("HttpdRsFastCGIStablePath requires 'Off' or 'On <unix-endpoint> <backend-uid> <endpoint-owner-uid> <trusted-owner-uid>...'".into());
                    }
                    let endpoint = crate::config::parse_fastcgi_policy_endpoint(&args[1])?;
                    if matches!(endpoint, crate::config::FastCgiEndpoint::Tcp { .. }) {
                        return Err("HttpdRsFastCGIStablePath requires a Unix socket; TCP cannot authenticate the backend process".into());
                    }
                    let parse_uid = |raw: &str, field: &str| {
                        httpd_rs_verified::parse_decimal_u64(raw.as_bytes())
                            .and_then(|value| u32::try_from(value).ok())
                            .ok_or_else(|| format!("invalid {field} uid '{raw}'"))
                    };
                    let backend_uid = parse_uid(&args[2], "FastCGI backend")?;
                    if backend_uid == 0 {
                        return Err("HttpdRsFastCGIStablePath rejects uid 0 backends".into());
                    }
                    let endpoint_owner_uid = parse_uid(&args[3], "Unix FastCGI endpoint-owner")?;
                    let mut trusted_owner_uids = Vec::new();
                    for raw in &args[4..] {
                        let uid = parse_uid(raw, "trusted path-owner")?;
                        if !trusted_owner_uids.contains(&uid) {
                            trusted_owner_uids.push(uid);
                        }
                    }
                    SealedValue::FastCgiStablePath(Some(crate::config::FastCgiStablePathPolicy {
                        endpoint,
                        backend_uid,
                        endpoint_owner_uid: Some(endpoint_owner_uid),
                        trusted_owner_uids,
                    }))
                }
            }
            PayloadValueSchema::Validated(PayloadValidation::ServerAliases) => {
                for alias in &args {
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
                SealedValue::ServerAliases(args.clone())
            }
            PayloadValueSchema::Validated(PayloadValidation::RewriteMap) => {
                SealedValue::RewriteMap(compile_rewrite_map(&args)?)
            }
            PayloadValueSchema::Validated(PayloadValidation::LogLevel) => {
                SealedValue::LogLevel(compile_log_level(&args)?)
            }
            PayloadValueSchema::Validated(PayloadValidation::SslSessionCache) => {
                SealedValue::SslSessionCache(compile_ssl_session_cache(&args)?)
            }
            PayloadValueSchema::Validated(PayloadValidation::BalancerMember) => {
                SealedValue::BalancerMember(compile_balancer_member(directive, &args)?)
            }
            PayloadValueSchema::Validated(PayloadValidation::ProxySet) => {
                SealedValue::ProxySet(compile_proxy_set(directive, &args)?)
            }
            PayloadValueSchema::Validated(PayloadValidation::ProxyHealthTemplate) => {
                let (name, template) = compile_proxy_health_template(directive, &args)?;
                SealedValue::ProxyHealthTemplate(name, template)
            }
            PayloadValueSchema::Validated(PayloadValidation::AllowOverride) => {
                SealedValue::AllowOverride(compile_allow_override(&args)?)
            }
            PayloadValueSchema::Validated(PayloadValidation::AllowOverrideList) => {
                SealedValue::AllowOverrideList(compile_allow_override_list(&args)?)
            }
            PayloadValueSchema::Validated(kind) => {
                validate_compatibility_payload(directive, &args, kind)?;
                SealedValue::TokenClass(schema_kind)
            }
        };
        if !httpd_rs_verified::config_semantic_seal_admit(
            schema_kind,
            value.semantic_kind(),
            source_argument_count,
            args.len(),
        ) {
            return Err(format!(
                "internal semantic schema mismatch while sealing directive '{directive}'"
            ));
        }
        Ok(Self {
            args: args.into_boxed_slice(),
            value,
            semantic_kind: schema_kind,
        })
    }

    pub(crate) fn refines(&self, consumer: httpd_rs_verified::ConfigSemanticKind) -> bool {
        httpd_rs_verified::config_semantic_projection_admit(self.semantic_kind, consumer)
    }

    pub(crate) fn as_slice(&self) -> &[String] {
        &self.args
    }

    pub(crate) fn capability(&self) -> Option<(crate::config::Capability, bool)> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::Capability) {
            return None;
        }
        match self.value {
            SealedValue::Capability(capability, enabled) => Some((capability, enabled)),
            _ => None,
        }
    }

    pub(crate) fn fastcgi_stable_path(
        &self,
    ) -> Option<&Option<crate::config::FastCgiStablePathPolicy>> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::FastCgiStablePath) {
            return None;
        }
        match &self.value {
            SealedValue::FastCgiStablePath(policy) => Some(policy),
            _ => None,
        }
    }

    pub(crate) fn server_aliases(&self) -> Option<&[String]> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::ServerAliases) {
            return None;
        }
        match &self.value {
            SealedValue::ServerAliases(aliases) => Some(aliases),
            _ => None,
        }
    }

    pub(crate) fn rewrite_map(&self) -> Option<&SealedRewriteMap> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::RewriteMap) {
            return None;
        }
        match &self.value {
            SealedValue::RewriteMap(map) => Some(map),
            _ => None,
        }
    }

    pub(crate) fn log_level(&self) -> Option<&str> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::LogLevel) {
            return None;
        }
        match &self.value {
            SealedValue::LogLevel(level) => Some(level),
            _ => None,
        }
    }

    pub(crate) fn ssl_session_cache(&self) -> Option<bool> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::SslSessionCache) {
            return None;
        }
        match self.value {
            SealedValue::SslSessionCache(enabled) => Some(enabled),
            _ => None,
        }
    }

    pub(crate) fn balancer_member(&self) -> Option<&crate::config::BalancerMember> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::BalancerMember) {
            return None;
        }
        match &self.value {
            SealedValue::BalancerMember(member) => Some(member),
            _ => None,
        }
    }

    pub(crate) fn proxy_set(&self) -> Option<&SealedProxySet> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::ProxySet) {
            return None;
        }
        match &self.value {
            SealedValue::ProxySet(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn proxy_health_template(&self) -> Option<(&str, &crate::config::HealthTemplate)> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::ProxyHealthTemplate) {
            return None;
        }
        match &self.value {
            SealedValue::ProxyHealthTemplate(name, template) => Some((name, template)),
            _ => None,
        }
    }

    pub(crate) fn allow_override(&self) -> Option<&SealedAllowOverride> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::AllowOverride) {
            return None;
        }
        match &self.value {
            SealedValue::AllowOverride(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn allow_override_list(&self) -> Option<&SealedAllowOverrideList> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::AllowOverrideList) {
            return None;
        }
        match &self.value {
            SealedValue::AllowOverrideList(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn on_off(&self) -> Option<bool> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::OnOff) {
            return None;
        }
        match self.value {
            SealedValue::OnOff(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn unsigned(&self) -> Option<u64> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::Unsigned) {
            return None;
        }
        match self.value {
            SealedValue::Unsigned(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn keyword(&self) -> Option<usize> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::Keyword) {
            return None;
        }
        match self.value {
            SealedValue::Keyword(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn options(&self) -> Option<&SealedOptions> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::Options) {
            return None;
        }
        match &self.value {
            SealedValue::Options(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn require(&self) -> Option<&crate::config::Require> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::Require) {
            return None;
        }
        match &self.value {
            SealedValue::Require(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn legacy_hosts(&self) -> Option<&[crate::config::HostSpec]> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::LegacyHosts) {
            return None;
        }
        match &self.value {
            SealedValue::LegacyHosts(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn file_etag(&self) -> Option<u32> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::FileEtag) {
            return None;
        }
        match self.value {
            SealedValue::FileEtag(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn error_document(&self) -> Option<(u16, &crate::config::ErrorDoc)> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::ErrorDocument) {
            return None;
        }
        match &self.value {
            SealedValue::ErrorDocument(code, document) => Some((*code, document)),
            _ => None,
        }
    }

    pub(crate) fn header(&self) -> Option<&SealedHeader> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::Header) {
            return None;
        }
        match &self.value {
            SealedValue::Header(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn redirect(&self) -> Option<&crate::config::Redirect> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::Redirect) {
            return None;
        }
        match &self.value {
            SealedValue::Redirect(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn rewrite_cond(&self) -> Option<&crate::config::RewriteCond> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::RewriteCond) {
            return None;
        }
        match &self.value {
            SealedValue::RewriteCond(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn rewrite_rule(&self) -> Option<&crate::config::RewriteRule> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::RewriteRule) {
            return None;
        }
        match &self.value {
            SealedValue::RewriteRule(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn http_protocols(&self) -> Option<&[crate::config::HttpProtocol]> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::HttpProtocols) {
            return None;
        }
        match &self.value {
            SealedValue::HttpProtocols(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn expires_default(&self) -> Option<&str> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::ExpiresDefault) {
            return None;
        }
        match &self.value {
            SealedValue::ExpiresDefault(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn expires_by_type(&self) -> Option<(&str, &str)> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::ExpiresByType) {
            return None;
        }
        match &self.value {
            SealedValue::ExpiresByType(content_type, value) => Some((content_type, value)),
            _ => None,
        }
    }

    pub(crate) fn environment_rule(&self) -> Option<&crate::config::EnvRule> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::EnvironmentRule) {
            return None;
        }
        match &self.value {
            SealedValue::EnvironmentRule(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn glob_patterns(&self) -> Option<&[String]> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::GlobPatterns) {
            return None;
        }
        match &self.value {
            SealedValue::GlobPatterns(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn allow_methods(&self) -> Option<&crate::config::AllowMethods> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::AllowMethods) {
            return None;
        }
        match &self.value {
            SealedValue::AllowMethods(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn request_read_timeout(
        &self,
    ) -> Option<(Option<Duration>, Option<Duration>, Option<u64>, Option<u64>)> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::RequestReadTimeout) {
            return None;
        }
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
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::Listen) {
            return None;
        }
        match &self.value {
            SealedValue::Listen(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn remote_ip_networks(&self) -> Option<&[(IpAddr, u8)]> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::RemoteIpNetworks) {
            return None;
        }
        match &self.value {
            SealedValue::RemoteIpNetworks(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn ssl_protocol(&self) -> Option<&str> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::SslProtocol) {
            return None;
        }
        match &self.value {
            SealedValue::SslProtocol(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn unit_float(&self) -> Option<f64> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::UnitFloat) {
            return None;
        }
        match self.value {
            SealedValue::UnitFloat(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn ocsp_responder_url(&self) -> Option<&str> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::OcspResponderUrl) {
            return None;
        }
        match &self.value {
            SealedValue::OcspResponderUrl(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn alias_regex(&self) -> Option<&SealedAliasRegex> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::AliasRegex) {
            return None;
        }
        match &self.value {
            SealedValue::AliasRegex(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn proxy_pass(&self) -> Option<&SealedProxyPass> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::ProxyPass) {
            return None;
        }
        match &self.value {
            SealedValue::ProxyPass(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn proxy_pass_reverse(&self) -> Option<&SealedProxyReverse> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::ProxyPassReverse) {
            return None;
        }
        match &self.value {
            SealedValue::ProxyPassReverse(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn proxy_pass_match(&self) -> Option<&SealedProxyMatch> {
        if !self.refines(httpd_rs_verified::ConfigSemanticKind::ProxyPassMatch) {
            return None;
        }
        match &self.value {
            SealedValue::ProxyPassMatch(value) => Some(value),
            _ => None,
        }
    }
}

pub(crate) fn valid_rewrite_map_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphanumeric() && (index != 0 || !byte.is_ascii_digit())
        })
}

fn compile_rewrite_map(args: &[String]) -> Result<SealedRewriteMap, String> {
    let name = args[0].clone();
    if !valid_rewrite_map_name(&name) {
        return Err(format!("invalid RewriteMap name '{name}'"));
    }
    let (kind, source) = args[1].split_once(':').unwrap_or(("txt", &args[1]));
    if source.is_empty() {
        return Err("RewriteMap requires a non-empty map source".into());
    }
    let source = match kind.to_ascii_lowercase().as_str() {
        "txt" => SealedRewriteMapSource::Txt(source.to_string()),
        "rnd" => SealedRewriteMapSource::Rnd(source.to_string()),
        "prg" => {
            let (program, args) = match source.split_once(char::is_whitespace) {
                Some((program, rest)) => (
                    program.to_string(),
                    rest.split_whitespace().map(str::to_string).collect(),
                ),
                None => (source.to_string(), Vec::new()),
            };
            SealedRewriteMapSource::Prg { program, args }
        }
        "int" => {
            let function = source.to_ascii_lowercase();
            if !matches!(function.as_str(), "tolower" | "toupper") {
                return Err(format!(
                    "unsupported RewriteMap int function '{source}' (expected tolower or toupper)"
                ));
            }
            SealedRewriteMapSource::Int(function)
        }
        other => return Err(format!("unsupported RewriteMap type '{other}'")),
    };
    Ok(SealedRewriteMap { name, source })
}

fn compile_log_level(args: &[String]) -> Result<String, String> {
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
    Ok(value.clone())
}

fn compile_ssl_session_cache(args: &[String]) -> Result<bool, String> {
    if args.len() != 1 {
        return Err("SSLSessionCache requires exactly one value".into());
    }
    let value = &args[0];
    if value.eq_ignore_ascii_case("none") || value.eq_ignore_ascii_case("nonenotnull") {
        Ok(false)
    } else if valid_provider_target(value) {
        Ok(true)
    } else {
        Err("SSLSessionCache requires none or a provider:target value".into())
    }
}

fn validate_compatibility_payload(
    directive: &str,
    args: &[String],
    kind: PayloadValidation,
) -> Result<(), String> {
    match kind {
        PayloadValidation::Capability | PayloadValidation::FastCgiStablePath => {
            return Err("internal typed payload routed through compatibility validation".into());
        }
        PayloadValidation::ServerAliases
        | PayloadValidation::RewriteMap
        | PayloadValidation::LogLevel
        | PayloadValidation::SslSessionCache => {
            return Err("internal typed payload routed through compatibility validation".into());
        }
        PayloadValidation::AllowOverride | PayloadValidation::AllowOverrideList => {
            return Err(
                "internal typed override payload routed through compatibility validation".into(),
            );
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
            if args.get(2).is_some_and(|value| {
                httpd_rs_verified::parse_decimal_u64(value.as_bytes()).is_none()
            }) {
                return Err("SSLRandomSeed requires startup|connect, a builtin/file:/exec:/egd: source, and optional byte count".into());
            }
        }
        PayloadValidation::SslPassphraseDialog => {
            if args.len() != 1 {
                return Err(
                    "SSLPassPhraseDialog requires builtin or exec:/absolute/program".into(),
                );
            }
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
        PayloadValidation::BalancerMember
        | PayloadValidation::ProxySet
        | PayloadValidation::ProxyHealthTemplate => {
            return Err(
                "internal typed proxy payload routed through compatibility validation".into(),
            );
        }
    }
    Ok(())
}

fn valid_provider_target(value: &str) -> bool {
    value
        .split_once(':')
        .is_some_and(|(provider, target)| !provider.is_empty() && !target.is_empty())
}

fn compile_allow_override(args: &[String]) -> Result<SealedAllowOverride, String> {
    use crate::config::{NonfatalMode, OverrideCategories, OverrideMode};
    let mut all = false;
    let mut none = false;
    let mut nonfatal = NonfatalMode::None;
    let mut flags = OverrideCategories::empty();
    for argument in args {
        let lower = argument.to_ascii_lowercase();
        if let Some(mode) = lower.strip_prefix("nonfatal=") {
            nonfatal = match mode {
                "override" => NonfatalMode::Override,
                "unknown" => NonfatalMode::Unknown,
                "all" => NonfatalMode::All,
                _ => return Err(format!("invalid Nonfatal mode '{mode}'")),
            };
            continue;
        }
        if let Some(options) = lower.strip_prefix("options=") {
            if options.is_empty() {
                return Err(format!("invalid AllowOverride option '{argument}'"));
            }
            for option in options.split(',') {
                flags.0 |= match option {
                    "all" => OverrideCategories::OPTIONS,
                    "none" => OverrideCategories::OPT_NONE,
                    "execcgi" => OverrideCategories::EXEC_CGI,
                    "includes" => OverrideCategories::INCLUDES,
                    "includesnoexec" => OverrideCategories::INCLUDES_NOEXEC,
                    "followsymlinks" => OverrideCategories::OPT_FOLLOW_SYMLINKS,
                    "indexes" => OverrideCategories::OPT_INDEXES,
                    "multiviews" => OverrideCategories::OPT_MULTIVIEWS,
                    "symlinksifownermatch" => OverrideCategories::OPT_SYMLINKS_IF_OWNER_MATCH,
                    _ => return Err(format!("invalid AllowOverride option '{argument}'")),
                };
            }
            continue;
        }
        match lower.as_str() {
            "all" => all = true,
            "none" => none = true,
            "authconfig" => flags.0 |= OverrideCategories::AUTH_CONFIG,
            "fileinfo" => flags.0 |= OverrideCategories::FILE_INFO,
            "indexes" => flags.0 |= OverrideCategories::INDEXES,
            "limit" => flags.0 |= OverrideCategories::LIMIT,
            "options" => flags.0 |= OverrideCategories::OPTIONS,
            "execcgi" => flags.0 |= OverrideCategories::EXEC_CGI,
            "includes" => flags.0 |= OverrideCategories::INCLUDES,
            "includesnoexec" => flags.0 |= OverrideCategories::INCLUDES_NOEXEC,
            "languagepriority" => flags.0 |= OverrideCategories::LANGUAGE_PRIORITY,
            _ => return Err(format!("unsupported AllowOverride category '{argument}'")),
        }
    }
    if !all && !none && flags.0 == 0 {
        return Err("AllowOverride has no supported categories".into());
    }
    let mode = if all {
        OverrideMode::All
    } else if none || flags.0 == 0 {
        OverrideMode::None
    } else {
        OverrideMode::Categories(flags)
    };
    Ok(SealedAllowOverride {
        mode,
        nonfatal,
        enables_access_files: all || (!none && flags.0 != 0),
    })
}

fn compile_allow_override_list(args: &[String]) -> Result<SealedAllowOverrideList, String> {
    let none = args.iter().any(|arg| arg.eq_ignore_ascii_case("none"));
    if none && args.len() != 1 {
        return Err("AllowOverrideList None cannot be combined with directive names".into());
    }
    Ok(SealedAllowOverrideList {
        directives: if none { Vec::new() } else { args.to_vec() },
        enables_access_files: !none,
    })
}

#[derive(Default)]
struct CompiledProxyParameters {
    health: crate::config::HealthTemplate,
    template: Option<String>,
    route: Option<String>,
    sticky_cookie: Option<String>,
    sticky_sep: Option<String>,
    fail_on_status: Option<Vec<u16>>,
}

fn compile_proxy_parameters(
    directive: &str,
    parameters: &[String],
) -> Result<CompiledProxyParameters, String> {
    let mut out = CompiledProxyParameters::default();
    for item in parameters {
        let (key, value) = item
            .split_once('=')
            .ok_or_else(|| format!("{directive} parameter '{item}' must use name=value syntax"))?;
        let key_lower = key.to_ascii_lowercase();
        match key_lower.as_str() {
            "hcmethod" => out.health.method = Some(value.to_string()),
            "hcuri" => out.health.uri = Some(value.to_string()),
            "hcinterval" => {
                out.health.interval = Some(
                    parse_duration(value)
                        .ok_or_else(|| format!("invalid {directive} hcinterval '{value}'"))?,
                );
            }
            "hcpasses" => {
                out.health.passes = Some(parse_proxy_u32(directive, key, value)?);
            }
            "hcfails" => {
                out.health.fails = Some(parse_proxy_u32(directive, key, value)?);
            }
            "template" if directive == "balancermember" => {
                out.template = Some(value.to_string());
            }
            "route" if directive == "balancermember" => {
                out.route = Some(value.to_string());
            }
            "stickysession" if directive == "proxyset" => {
                out.sticky_cookie = Some(value.to_string());
            }
            "stickysessionsep" if directive == "proxyset" => {
                out.sticky_sep = Some(value.to_string());
            }
            "failonstatus" if directive == "proxyset" => {
                let (statuses, bad) = crate::config::parse_status_list(value);
                if !bad.is_empty() {
                    return Err(format!(
                        "{directive} failonstatus contains non-numeric entries {bad:?}"
                    ));
                }
                out.fail_on_status = Some(statuses);
            }
            _ => return Err(format!("unsupported {directive} parameter '{key}'")),
        }
    }
    Ok(out)
}

fn parse_proxy_u32(directive: &str, key: &str, value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| format!("invalid {directive} {key} '{value}'"))
}

fn compile_balancer_member(
    directive: &str,
    args: &[String],
) -> Result<crate::config::BalancerMember, String> {
    let compiled = compile_proxy_parameters(directive, &args[1..])?;
    Ok(crate::config::BalancerMember {
        url: args[0].clone(),
        hcmethod: compiled.health.method,
        hcuri: compiled.health.uri,
        hcinterval: compiled.health.interval,
        hcpasses: compiled.health.passes,
        hcfails: compiled.health.fails,
        template: compiled.template,
        route: compiled.route,
    })
}

fn compile_proxy_set(directive: &str, args: &[String]) -> Result<SealedProxySet, String> {
    let compiled = compile_proxy_parameters(directive, args)?;
    Ok(SealedProxySet {
        health: compiled.health,
        sticky_cookie: compiled.sticky_cookie,
        sticky_sep: compiled.sticky_sep,
        fail_on_status: compiled.fail_on_status,
    })
}

fn compile_proxy_health_template(
    directive: &str,
    args: &[String],
) -> Result<(String, crate::config::HealthTemplate), String> {
    let compiled = compile_proxy_parameters(directive, &args[1..])?;
    Ok((args[0].clone(), compiled.health))
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
    let millis =
        httpd_rs_verified::parse_decimal_u64(digits.as_bytes())?.checked_mul(multiplier)?;
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

        let keyword = PayloadSchema::typed(
            PayloadArity::ONE,
            true,
            PayloadValueSchema::Keyword(&["alpha", "beta"]),
        );
        assert_eq!(
            SealedPayload::seal("Choice", vec!["BeTa".into()], keyword)
                .unwrap()
                .keyword(),
            Some(1)
        );

        for invalid in ["", "+1", "-1", "10", "18446744073709551616"] {
            assert!(
                SealedPayload::seal("Level", vec![invalid.into()], bounded).is_err(),
                "bounded unsigned payload accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn semantic_refinement_codes_are_complete_and_projections_fail_closed() {
        use httpd_rs_verified::ConfigSemanticKind as Kind;
        let kinds = [
            Kind::Tokens,
            Kind::DirectoryIndex,
            Kind::OnOff,
            Kind::Unsigned,
            Kind::Keyword,
            Kind::Options,
            Kind::Require,
            Kind::LegacyHosts,
            Kind::FileEtag,
            Kind::ErrorDocument,
            Kind::Header,
            Kind::Redirect,
            Kind::RewriteCond,
            Kind::RewriteRule,
            Kind::RepeatedKeyword,
            Kind::HttpProtocols,
            Kind::ExpiresDefault,
            Kind::ExpiresByType,
            Kind::EnvironmentRule,
            Kind::GlobPatterns,
            Kind::AllowMethods,
            Kind::RequestReadTimeout,
            Kind::Listen,
            Kind::RemoteIpNetworks,
            Kind::SslProtocol,
            Kind::UnitFloat,
            Kind::OcspResponderUrl,
            Kind::AliasRegex,
            Kind::ProxyPass,
            Kind::ProxyPassReverse,
            Kind::ProxyPassMatch,
            Kind::Capability,
            Kind::FastCgiStablePath,
            Kind::ServerAliases,
            Kind::AllowOverride,
            Kind::AllowOverrideList,
            Kind::RewriteMap,
            Kind::LogLevel,
            Kind::SslRandomSeed,
            Kind::SslPassphraseDialog,
            Kind::SslSessionCache,
            Kind::SslStaplingCache,
            Kind::SslOptions,
            Kind::BalancerMember,
            Kind::ProxySet,
            Kind::ProxyHealthTemplate,
        ];
        let mut codes = kinds
            .into_iter()
            .map(httpd_rs_verified::config_semantic_kind_code)
            .collect::<Vec<_>>();
        codes.sort_unstable();
        assert_eq!(codes, (0u8..46).collect::<Vec<_>>());

        let toggle = SealedPayload::seal(
            "Toggle",
            vec!["On".into()],
            PayloadSchema::typed(PayloadArity::ONE, true, PayloadValueSchema::OnOff),
        )
        .unwrap();
        assert_eq!(toggle.on_off(), Some(true));
        assert_eq!(toggle.unsigned(), None);
        assert_eq!(toggle.keyword(), None);
        assert!(toggle.refines(Kind::OnOff));
        assert!(!toggle.refines(Kind::Tokens));
        assert!(httpd_rs_verified::config_semantic_seal_admit(
            Kind::OnOff,
            Kind::OnOff,
            1,
            1
        ));
        assert!(!httpd_rs_verified::config_semantic_seal_admit(
            Kind::OnOff,
            Kind::Unsigned,
            1,
            1
        ));
        assert!(!httpd_rs_verified::config_semantic_seal_admit(
            Kind::OnOff,
            Kind::OnOff,
            1,
            2
        ));
    }

    #[test]
    fn effectful_validated_payloads_are_compiled_once() {
        let capability = SealedPayload::seal(
            "httpdrscapability",
            vec!["FastCgi".into(), "oN".into()],
            PayloadSchema::typed(
                PayloadArity::TWO,
                true,
                PayloadValueSchema::Validated(PayloadValidation::Capability),
            ),
        )
        .unwrap();
        assert_eq!(
            capability.capability(),
            Some((crate::config::Capability::FastCgi, true))
        );
        assert!(capability.fastcgi_stable_path().is_none());

        let stable = SealedPayload::seal(
            "httpdrsfastcgistablepath",
            vec![
                "On".into(),
                "unix:/run/php.sock".into(),
                "33".into(),
                "0".into(),
                "0".into(),
                "33".into(),
                "33".into(),
            ],
            PayloadSchema::typed(
                PayloadArity::at_least(1),
                true,
                PayloadValueSchema::Validated(PayloadValidation::FastCgiStablePath),
            ),
        )
        .unwrap();
        let policy = stable.fastcgi_stable_path().unwrap().as_ref().unwrap();
        assert_eq!(policy.backend_uid, 33);
        assert_eq!(policy.endpoint_owner_uid, Some(0));
        assert_eq!(policy.trusted_owner_uids, vec![0, 33]);

        let set = SealedPayload::seal(
            "proxyset",
            vec![
                "hcinterval=5ms".into(),
                "hcpasses=2".into(),
                "hcfails=3".into(),
                "stickysession=ROUTE".into(),
                "failonstatus=500,503".into(),
            ],
            PayloadSchema::typed(
                PayloadArity::at_least(1),
                true,
                PayloadValueSchema::Validated(PayloadValidation::ProxySet),
            ),
        )
        .unwrap();
        let set = set.proxy_set().unwrap();
        assert_eq!(set.health.interval, Some(Duration::from_millis(5)));
        assert_eq!(set.health.passes, Some(2));
        assert_eq!(set.health.fails, Some(3));
        assert_eq!(set.sticky_cookie.as_deref(), Some("ROUTE"));
        assert_eq!(set.fail_on_status, Some(vec![500, 503]));

        let overflow = SealedPayload::seal(
            "proxyset",
            vec!["hcpasses=4294967296".into()],
            PayloadSchema::typed(
                PayloadArity::at_least(1),
                true,
                PayloadValueSchema::Validated(PayloadValidation::ProxySet),
            ),
        );
        assert!(overflow.is_err());

        let override_policy = SealedPayload::seal(
            "allowoverride",
            vec![
                "AuthConfig".into(),
                "Options=Indexes".into(),
                "Nonfatal=Unknown".into(),
            ],
            PayloadSchema::typed(
                PayloadArity::at_least(1),
                true,
                PayloadValueSchema::Validated(PayloadValidation::AllowOverride),
            ),
        )
        .unwrap();
        let override_policy = override_policy.allow_override().unwrap();
        let crate::config::OverrideMode::Categories(categories) = override_policy.mode else {
            panic!("expected category-scoped AllowOverride")
        };
        assert!(categories.contains(crate::config::OverrideCategories::AUTH_CONFIG));
        assert!(categories.contains(crate::config::OverrideCategories::OPT_INDEXES));
        assert_eq!(
            override_policy.nonfatal,
            crate::config::NonfatalMode::Unknown
        );
        assert!(override_policy.enables_access_files);

        let override_list = SealedPayload::seal(
            "allowoverridelist",
            vec!["None".into()],
            PayloadSchema::typed(
                PayloadArity::at_least(1),
                true,
                PayloadValueSchema::Validated(PayloadValidation::AllowOverrideList),
            ),
        )
        .unwrap();
        assert!(override_list
            .allow_override_list()
            .unwrap()
            .directives
            .is_empty());
        assert!(SealedPayload::seal(
            "allowoverridelist",
            vec!["None".into(), "Require".into()],
            PayloadSchema::typed(
                PayloadArity::at_least(1),
                true,
                PayloadValueSchema::Validated(PayloadValidation::AllowOverrideList),
            ),
        )
        .is_err());

        let rewrite_map = SealedPayload::seal(
            "rewritemap",
            vec!["case".into(), "prg:/usr/bin/helper --safe".into()],
            PayloadSchema::typed(
                PayloadArity::TWO,
                true,
                PayloadValueSchema::Validated(PayloadValidation::RewriteMap),
            ),
        )
        .unwrap();
        assert_eq!(
            rewrite_map.rewrite_map().unwrap().source,
            SealedRewriteMapSource::Prg {
                program: "/usr/bin/helper".into(),
                args: vec!["--safe".into()],
            }
        );
        assert!(SealedPayload::seal(
            "rewritemap",
            vec!["bad".into(), "int:escape".into()],
            PayloadSchema::typed(
                PayloadArity::TWO,
                true,
                PayloadValueSchema::Validated(PayloadValidation::RewriteMap),
            ),
        )
        .is_err());

        let session_cache = SealedPayload::seal(
            "sslsessioncache",
            vec!["shmcb:/run/cache".into()],
            PayloadSchema::typed(
                PayloadArity::ONE,
                true,
                PayloadValueSchema::Validated(PayloadValidation::SslSessionCache),
            ),
        )
        .unwrap();
        assert_eq!(session_cache.ssl_session_cache(), Some(true));
    }
}
