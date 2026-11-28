//! Bounded, fail-closed nginx configuration frontend.
//!
//! This frontend accepts a deliberately finite HTTP subset and lowers it to
//! the same typed compiler input used by the Apache frontend. Unknown or
//! semantically wider directives are errors; operational tuning directives
//! whose effect is intentionally owned by httpd-rs are accepted only through
//! an explicit no-op table.

use crate::config::{Event, SourceLoc};
use crate::config_ir::RouteMatcher;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_INCLUDE_DEPTH: usize = 32;
const MAX_INCLUDES: usize = 10_000;
const MAX_INCLUDE_DIRECTORY_ENTRIES: usize = 10_000;
const MAX_NODES: usize = 65_536;
const MAX_ARGS: usize = 128;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_BLOCK_DEPTH: usize = 64;

#[derive(Debug, Clone)]
pub(crate) struct NginxError {
    pub file: String,
    pub line: usize,
    pub message: String,
}

#[derive(Debug, Clone)]
struct Node {
    name: String,
    args: Vec<String>,
    children: Option<Vec<Node>>,
    loc: SourceLoc,
}

#[derive(Debug)]
pub(crate) struct LoweredNginx {
    pub events: Vec<Event>,
    pub routes: Vec<Vec<RouteMatcher>>,
    pub warnings: Vec<String>,
    pub admin_inputs: Vec<PathBuf>,
}

pub(crate) fn load(
    path: &Path,
    server_root: &Path,
    trust: crate::files::AdminFileTrust,
    service_uid: Option<u32>,
) -> Result<LoweredNginx, Vec<NginxError>> {
    let mut loader = Loader {
        server_root: server_root.to_path_buf(),
        trust,
        service_uid,
        bytes: 0,
        includes: 0,
        nodes: 0,
        active_includes: Vec::new(),
        admin_inputs: Vec::new(),
        errors: Vec::new(),
    };
    let nodes = loader.load_file(path, 0).unwrap_or_default();
    if !loader.errors.is_empty() {
        return Err(loader.errors);
    }
    match lower(nodes, &server_root.join("html")) {
        Ok(mut lowered) => {
            lowered.admin_inputs = loader.admin_inputs;
            Ok(lowered)
        }
        Err(errors) => Err(errors),
    }
}

struct Loader {
    server_root: PathBuf,
    trust: crate::files::AdminFileTrust,
    service_uid: Option<u32>,
    bytes: u64,
    includes: usize,
    nodes: usize,
    active_includes: Vec<PathBuf>,
    admin_inputs: Vec<PathBuf>,
    errors: Vec<NginxError>,
}

impl Loader {
    fn error(&mut self, path: &Path, line: usize, message: impl Into<String>) {
        self.errors.push(NginxError {
            file: path.display().to_string(),
            line,
            message: message.into(),
        });
    }

    fn register(&mut self, path: &Path, line: usize) -> bool {
        if !self.admin_inputs.iter().any(|known| known == path) {
            self.admin_inputs.push(path.to_path_buf());
        }
        if self.trust == crate::files::AdminFileTrust::RootOwned {
            if let Some(uid) = self.service_uid {
                if let Err(error) = crate::files::validate_admin_parents(path, uid) {
                    self.error(
                        path,
                        line,
                        format!("administrative input parent is unsafe: {error}"),
                    );
                    return false;
                }
            }
        }
        true
    }

    fn load_file(&mut self, path: &Path, depth: usize) -> Option<Vec<Node>> {
        let lexical = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.server_root.join(path)
        };
        let identity = std::fs::canonicalize(&lexical).unwrap_or(lexical);
        if self
            .active_includes
            .iter()
            .any(|active| active == &identity)
        {
            self.error(path, 0, "nginx include cycle detected");
            return None;
        }
        self.active_includes.push(identity);
        let result = self.load_file_inner(path, depth);
        self.active_includes.pop();
        result
    }

    fn load_file_inner(&mut self, path: &Path, depth: usize) -> Option<Vec<Node>> {
        if depth > MAX_INCLUDE_DEPTH {
            self.error(path, 0, "nginx include nesting is too deep");
            return None;
        }
        if self.includes >= MAX_INCLUDES {
            self.error(path, 0, "too many nginx include files");
            return None;
        }
        self.includes += 1;
        if !self.register(path, 0) {
            return None;
        }
        let data = match crate::files::read_admin_file_with_trust(path, MAX_FILE_BYTES, self.trust)
        {
            Ok(data) => data,
            Err(error) => {
                self.error(
                    path,
                    0,
                    format!("could not open nginx configuration: {error}"),
                );
                return None;
            }
        };
        let Some(total) = self.bytes.checked_add(data.len() as u64) else {
            self.error(path, 0, "aggregate nginx configuration size overflow");
            return None;
        };
        if total > MAX_TOTAL_BYTES {
            self.error(
                path,
                0,
                format!("aggregate nginx configuration exceeds {MAX_TOTAL_BYTES} bytes"),
            );
            return None;
        }
        self.bytes = total;
        let text = match std::str::from_utf8(&data) {
            Ok(text) => text,
            Err(_) => {
                self.error(path, 0, "nginx configuration is not valid UTF-8");
                return None;
            }
        };
        let parsed = match Parser::new(text, path).parse() {
            Ok(nodes) => nodes,
            Err(error) => {
                self.errors.push(error);
                return None;
            }
        };
        self.nodes = self.nodes.saturating_add(count_nodes(&parsed));
        if self.nodes > MAX_NODES {
            self.error(
                path,
                0,
                format!("nginx configuration exceeds {MAX_NODES} statements"),
            );
            return None;
        }
        Some(self.expand_includes(parsed, depth))
    }

    fn expand_includes(&mut self, nodes: Vec<Node>, depth: usize) -> Vec<Node> {
        let mut output = Vec::new();
        for mut node in nodes {
            if node.name.eq_ignore_ascii_case("include") {
                if node.children.is_some() || node.args.len() != 1 {
                    self.error(
                        Path::new(&node.loc.file),
                        node.loc.line,
                        "include requires exactly one path and no block",
                    );
                    continue;
                }
                for path in self.include_paths(&node.args[0], &node.loc) {
                    if let Some(mut included) = self.load_file(&path, depth + 1) {
                        output.append(&mut included);
                    }
                }
                continue;
            }
            if let Some(children) = node.children.take() {
                node.children = Some(self.expand_includes(children, depth));
            }
            output.push(node);
        }
        output
    }

    fn include_paths(&mut self, raw: &str, loc: &SourceLoc) -> Vec<PathBuf> {
        let path = Path::new(raw);
        let full = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.server_root.join(path)
        };
        let Some(text) = full.to_str() else {
            self.error(
                Path::new(&loc.file),
                loc.line,
                "include path is not valid UTF-8",
            );
            return Vec::new();
        };
        if !text.bytes().any(|byte| matches!(byte, b'*' | b'?' | b'[')) {
            return vec![full];
        }
        let Some(parent) = full.parent() else {
            self.error(Path::new(&loc.file), loc.line, "invalid include glob");
            return Vec::new();
        };
        if parent
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .any(|byte| matches!(byte, b'*' | b'?' | b'['))
        {
            self.error(
                Path::new(&loc.file),
                loc.line,
                "wildcards in nginx include parent directories are not supported",
            );
            return Vec::new();
        }
        let Some(pattern) = full.file_name().and_then(|name| name.to_str()) else {
            self.error(Path::new(&loc.file), loc.line, "invalid include glob name");
            return Vec::new();
        };
        let trust_target = parent.join(".httpd-rs-nginx-include-entry");
        if !self.register(&trust_target, loc.line) {
            return Vec::new();
        }
        let mut matches = Vec::new();
        let entries = match std::fs::read_dir(parent) {
            Ok(entries) => entries,
            Err(error) => {
                self.error(
                    Path::new(&loc.file),
                    loc.line,
                    format!("cannot enumerate nginx include glob: {error}"),
                );
                return Vec::new();
            }
        };
        for (index, entry) in entries.enumerate() {
            if index >= MAX_INCLUDE_DIRECTORY_ENTRIES {
                self.error(
                    Path::new(&loc.file),
                    loc.line,
                    format!(
                        "nginx include directory exceeds {MAX_INCLUDE_DIRECTORY_ENTRIES} entries"
                    ),
                );
                return Vec::new();
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    self.error(
                        Path::new(&loc.file),
                        loc.line,
                        format!("cannot enumerate nginx include glob: {error}"),
                    );
                    return Vec::new();
                }
            };
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                self.error(
                    Path::new(&loc.file),
                    loc.line,
                    "include directory contains a non-UTF-8 path",
                );
                return Vec::new();
            };
            if crate::config::glob_match(pattern.as_bytes(), name.as_bytes()) {
                matches.push(entry.path());
            }
        }
        matches.sort();
        // nginx treats an unmatched include glob as an empty expansion.  The
        // parent has still been registered above as an administrative trust
        // boundary, so accepting the empty set does not let the service
        // identity populate it after privilege drop without a reload check.
        matches
    }
}

fn count_nodes(nodes: &[Node]) -> usize {
    nodes
        .iter()
        .map(|node| 1 + node.children.as_deref().map(count_nodes).unwrap_or(0))
        .sum()
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TokenKind {
    Word(String),
    Semi,
    Open,
    Close,
}

#[derive(Clone, Debug)]
struct Token {
    kind: TokenKind,
    line: usize,
}

struct Parser<'a> {
    text: &'a str,
    file: String,
    tokens: Vec<Token>,
    position: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str, path: &Path) -> Self {
        Self {
            text,
            file: path.display().to_string(),
            tokens: Vec::new(),
            position: 0,
        }
    }

    fn parse(mut self) -> Result<Vec<Node>, NginxError> {
        self.tokens = lex(self.text, &self.file)?;
        struct BlockFrame {
            name: String,
            args: Vec<String>,
            loc: SourceLoc,
            parent: Vec<Node>,
        }

        let mut state = httpd_rs_verified::nginx_parse_start();
        let mut nodes = Vec::new();
        let mut frames: Vec<BlockFrame> = Vec::new();
        let mut directive: Option<(String, Vec<String>, SourceLoc)> = None;
        loop {
            let token = self.tokens.get(self.position).cloned();
            let class = match token.as_ref().map(|token| &token.kind) {
                Some(TokenKind::Word(_)) => httpd_rs_verified::NginxTokenClass::Word,
                Some(TokenKind::Semi) => httpd_rs_verified::NginxTokenClass::Semi,
                Some(TokenKind::Open) => httpd_rs_verified::NginxTokenClass::Open,
                Some(TokenKind::Close) => httpd_rs_verified::NginxTokenClass::Close,
                None => httpd_rs_verified::NginxTokenClass::Eof,
            };
            let step = httpd_rs_verified::nginx_parse_step(
                state,
                class,
                MAX_ARGS as u64,
                MAX_BLOCK_DEPTH as u64,
            );
            if step.action == httpd_rs_verified::NginxParseAction::Reject {
                let line = token.as_ref().map_or_else(
                    || directive.as_ref().map_or(0, |(_, _, loc)| loc.line),
                    |token| token.line,
                );
                let message = match (state.phase, class) {
                    (
                        httpd_rs_verified::NginxParsePhase::NeedDirective,
                        httpd_rs_verified::NginxTokenClass::Close,
                    ) if state.depth == 0 => "unexpected '}'",
                    (
                        httpd_rs_verified::NginxParsePhase::NeedDirective,
                        httpd_rs_verified::NginxTokenClass::Eof,
                    ) => "unclosed nginx configuration block",
                    (
                        httpd_rs_verified::NginxParsePhase::Arguments,
                        httpd_rs_verified::NginxTokenClass::Word,
                    ) => "too many nginx directive arguments",
                    (
                        httpd_rs_verified::NginxParsePhase::Arguments,
                        httpd_rs_verified::NginxTokenClass::Open,
                    ) => "nginx configuration block nesting is too deep",
                    (
                        httpd_rs_verified::NginxParsePhase::Arguments,
                        httpd_rs_verified::NginxTokenClass::Close,
                    ) => "directive is missing ';' or '{'",
                    (
                        httpd_rs_verified::NginxParsePhase::Arguments,
                        httpd_rs_verified::NginxTokenClass::Eof,
                    ) => "unterminated nginx directive",
                    _ => "expected nginx directive name",
                };
                return Err(self.error(line, message));
            }
            match step.action {
                httpd_rs_verified::NginxParseAction::StartDirective => {
                    let Some(Token {
                        kind: TokenKind::Word(name),
                        line,
                    }) = token
                    else {
                        unreachable!("verified parser starts only on a word")
                    };
                    directive = Some((
                        name.to_ascii_lowercase(),
                        Vec::new(),
                        SourceLoc {
                            file: self.file.clone(),
                            line,
                        },
                    ));
                    self.position += 1;
                }
                httpd_rs_verified::NginxParseAction::PushArgument => {
                    let Some(Token {
                        kind: TokenKind::Word(value),
                        ..
                    }) = token
                    else {
                        unreachable!("verified parser arguments are words")
                    };
                    directive
                        .as_mut()
                        .expect("verified argument state owns a directive")
                        .1
                        .push(value);
                    self.position += 1;
                }
                httpd_rs_verified::NginxParseAction::EmitLeaf => {
                    let (name, args, loc) = directive
                        .take()
                        .expect("verified leaf state owns a directive");
                    nodes.push(Node {
                        name,
                        args,
                        children: None,
                        loc,
                    });
                    self.position += 1;
                }
                httpd_rs_verified::NginxParseAction::OpenBlock => {
                    let (name, args, loc) = directive
                        .take()
                        .expect("verified block state owns a directive");
                    frames.push(BlockFrame {
                        name,
                        args,
                        loc,
                        parent: std::mem::take(&mut nodes),
                    });
                    self.position += 1;
                }
                httpd_rs_verified::NginxParseAction::CloseBlock => {
                    let frame = frames
                        .pop()
                        .expect("verified close state has a parent block");
                    let children = std::mem::take(&mut nodes);
                    nodes = frame.parent;
                    nodes.push(Node {
                        name: frame.name,
                        args: frame.args,
                        children: Some(children),
                        loc: frame.loc,
                    });
                    self.position += 1;
                }
                httpd_rs_verified::NginxParseAction::Complete => {
                    debug_assert!(frames.is_empty());
                    debug_assert!(directive.is_none());
                    debug_assert_eq!(self.position, self.tokens.len());
                    return Ok(nodes);
                }
                httpd_rs_verified::NginxParseAction::Reject => unreachable!(),
            }
            state = step.state;
            debug_assert_eq!(state.depth as usize, frames.len());
            debug_assert_eq!(
                state.phase == httpd_rs_verified::NginxParsePhase::Arguments,
                directive.is_some()
            );
        }
    }

    fn error(&self, line: usize, message: impl Into<String>) -> NginxError {
        NginxError {
            file: self.file.clone(),
            line,
            message: message.into(),
        }
    }
}

fn lex(text: &str, file: &str) -> Result<Vec<Token>, NginxError> {
    let bytes = text.as_bytes();
    let mut checked_line = 1usize;
    for byte in bytes {
        if *byte == b'\n' {
            checked_line += 1;
        } else if (*byte < b' ' && !matches!(*byte, b'\t' | b'\r')) || *byte == 0x7f {
            return Err(NginxError {
                file: file.into(),
                line: checked_line,
                message: "nginx configuration contains a forbidden control byte".into(),
            });
        }
    }
    let mut tokens = Vec::new();
    let mut index = 0usize;
    let mut line = 1usize;
    while index < bytes.len() {
        match bytes[index] {
            b' ' | b'\t' | b'\r' => index += 1,
            b'\n' => {
                line += 1;
                index += 1;
            }
            b'#' => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b';' => {
                tokens.push(Token {
                    kind: TokenKind::Semi,
                    line,
                });
                index += 1;
            }
            b'{' => {
                tokens.push(Token {
                    kind: TokenKind::Open,
                    line,
                });
                index += 1;
            }
            b'}' => {
                tokens.push(Token {
                    kind: TokenKind::Close,
                    line,
                });
                index += 1;
            }
            _ => {
                let start_line = line;
                let mut word = Vec::new();
                let mut state = httpd_rs_verified::NginxLexState::Bare;
                let mut token_started = false;
                while index < bytes.len() {
                    let byte = bytes[index];
                    let step = httpd_rs_verified::nginx_lex_step(
                        state,
                        byte,
                        bytes.get(index + 1).is_some(),
                    );
                    match step.action {
                        httpd_rs_verified::NginxLexAction::Push => {
                            token_started = true;
                            if byte == b'\n' {
                                line += 1;
                            }
                            word.push(byte);
                            index += step.advance as usize;
                        }
                        httpd_rs_verified::NginxLexAction::PushNext => {
                            token_started = true;
                            word.push(bytes[index + 1]);
                            index += step.advance as usize;
                        }
                        httpd_rs_verified::NginxLexAction::Skip => {
                            token_started = true;
                            index += step.advance as usize;
                        }
                        httpd_rs_verified::NginxLexAction::Finish => break,
                        httpd_rs_verified::NginxLexAction::Reject => {
                            let quoted = state != httpd_rs_verified::NginxLexState::Bare;
                            return Err(NginxError {
                                file: file.into(),
                                line,
                                message: if quoted {
                                    "trailing escape in quoted nginx token".into()
                                } else {
                                    "trailing escape in nginx token".into()
                                },
                            });
                        }
                    }
                    state = step.state;
                    if word.len() > MAX_TOKEN_BYTES {
                        return Err(NginxError {
                            file: file.into(),
                            line: start_line,
                            message: format!("nginx token exceeds {MAX_TOKEN_BYTES} bytes"),
                        });
                    }
                }
                if !httpd_rs_verified::nginx_lex_finish(state) {
                    return Err(NginxError {
                        file: file.into(),
                        line: start_line,
                        message: "unterminated quoted nginx token".into(),
                    });
                }
                if !token_started {
                    return Err(NginxError {
                        file: file.into(),
                        line: start_line,
                        message: "empty nginx token".into(),
                    });
                }
                let value = String::from_utf8(word).map_err(|_| NginxError {
                    file: file.into(),
                    line: start_line,
                    message: "nginx token is not valid UTF-8".into(),
                })?;
                tokens.push(Token {
                    kind: TokenKind::Word(value),
                    line: start_line,
                });
            }
        }
        if tokens.len() > MAX_NODES.saturating_mul(8) {
            return Err(NginxError {
                file: file.into(),
                line,
                message: "too many nginx configuration tokens".into(),
            });
        }
    }
    Ok(tokens)
}

struct Lowerer {
    events: Vec<Event>,
    routes: Vec<Vec<RouteMatcher>>,
    warnings: Vec<String>,
    errors: Vec<NginxError>,
    listeners: HashSet<String>,
    upstreams: HashSet<String>,
}

/// The only source-neutral operations the nginx frontend may emit. Keeping
/// this map beside the emitter makes additions fail closed until their arity
/// has also been represented in the verified lowering vocabulary.
fn nginx_ir_operation(name: &str) -> Option<httpd_rs_verified::NginxIrOperation> {
    use httpd_rs_verified::NginxIrOperation as Op;
    Some(match name {
        "user" | "group" => Op::ProcessIdentity,
        "pidfile" => Op::PidFile,
        "errorlog" => Op::ErrorLog,
        "loglevel" => Op::LogLevel,
        "httpdrscapability" => Op::Capability,
        "httpdrsfastcgistablepath" => Op::StableFastCgiPath,
        "documentroot" => Op::DocumentRoot,
        "httpdrsscopedroot" => Op::ScopedRoot,
        "limitrequestbody" => Op::RequestBodyLimit,
        "httpdrsscopedbodylimit" => Op::ScopedBodyLimit,
        "keepalivetimeout" => Op::KeepAliveTimeout,
        "maxkeepaliverequests" => Op::KeepAliveRequests,
        "httpdrsnginxresponsesemantics" => Op::ResponseSemantics,
        "httpdrsnginxresetheaders" => Op::ResetResponseHeaders,
        "listen" => Op::Listen,
        "servername" => Op::ServerName,
        "serveralias" => Op::ServerAlias,
        "addtype" => Op::MimeType,
        "customlog" => Op::AccessLog,
        "balancermember" => Op::BalancerMember,
        "sslcertificatefile" => Op::Certificate,
        "sslcertificatekeyfile" => Op::CertificateKey,
        "sslciphersuite" => Op::CipherSuite,
        "sslengine" => Op::TlsEngine,
        "sslprotocol" => Op::TlsProtocol,
        "protocols" => Op::Protocols,
        "directoryindex" => Op::DirectoryIndex,
        "enablesendfile" => Op::Sendfile,
        "servertokens" => Op::ServerTokens,
        "options" => Op::Options,
        "setoutputfilter" => Op::OutputFilter,
        "addoutputfilterbytype" => Op::OutputFilterByType,
        "deflatecompressionlevel" => Op::CompressionLevel,
        "httpdrsproxysetheader" => Op::ProxyHeader,
        "httpdrsfastcgiparam" => Op::FastCgiParam,
        "authtype" => Op::AuthType,
        "authname" => Op::AuthName,
        "authuserfile" => Op::AuthUserFile,
        "require" => Op::Require,
        "proxypreservehost" => Op::PreserveHost,
        "httpdrsnginxalias" => Op::Alias,
        "httpdrsnginxtryfiles" => Op::TryFiles,
        "errordocument" => Op::ErrorDocument,
        "expiresactive" => Op::ExpiresActive,
        "expiresdefault" => Op::ExpiresDefault,
        "httpdrsrouteproxypass" => Op::RouteProxyPass,
        "httpdrsrouteproxypassreverse" => Op::RouteProxyReverse,
        "header" => Op::ResponseHeader,
        "httpdrsnginxreturn" => Op::Return,
        _ => return None,
    })
}

fn lower(nodes: Vec<Node>, default_document_root: &Path) -> Result<LoweredNginx, Vec<NginxError>> {
    let mut lowerer = Lowerer {
        events: Vec::new(),
        routes: Vec::new(),
        warnings: Vec::new(),
        errors: Vec::new(),
        listeners: HashSet::new(),
        upstreams: HashSet::new(),
    };
    let mut http = None;
    for node in &nodes {
        match node.name.as_str() {
            "http" => {
                if http.replace(node).is_some() {
                    lowerer.error(node, "only one nginx http block is supported");
                }
            }
            "events" => lowerer.lower_events(node),
            "user" => lowerer.lower_user(node),
            "pid" => lowerer.simple(node, "PidFile", 1, 1),
            "error_log" => lowerer.lower_error_log(node),
            "httpd_rs_capability" => lowerer.simple(node, "HttpdRsCapability", 2, 2),
            "httpd_rs_fastcgi_stable_path" => {
                lowerer.simple(node, "HttpdRsFastCGIStablePath", 1, 32)
            }
            "env" | "load_module" => lowerer.error(
                node,
                "this directive changes process or module semantics and cannot be treated as an operational no-op",
            ),
            name if main_operational_noop(name) => lowerer.noop(node),
            _ => lowerer.unsupported(node),
        }
    }
    let Some(http) = http else {
        lowerer.errors.push(NginxError {
            file: String::new(),
            line: 0,
            message: "nginx configuration requires one http block".into(),
        });
        return Err(lowerer.errors);
    };
    // These are nginx HTTP defaults, not Apache compiler defaults. Emitting
    // them as ordinary typed IR operations keeps the shared runtime neutral
    // and also makes an omitted directive behave like stock nginx.
    lowerer.directive(
        http,
        "DocumentRoot",
        vec![default_document_root.display().to_string()],
    );
    lowerer.directive(http, "LimitRequestBody", vec![(1024 * 1024).to_string()]);
    lowerer.directive(http, "KeepAliveTimeout", vec!["75".into()]);
    lowerer.directive(http, "MaxKeepAliveRequests", vec!["1000".into()]);
    lowerer.lower_http(http);
    if !lowerer.errors.is_empty() {
        return Err(lowerer.errors);
    }
    Ok(LoweredNginx {
        events: lowerer.events,
        routes: lowerer.routes,
        warnings: lowerer.warnings,
        admin_inputs: Vec::new(),
    })
}

impl Lowerer {
    fn error(&mut self, node: &Node, message: impl Into<String>) {
        self.errors.push(NginxError {
            file: node.loc.file.clone(),
            line: node.loc.line,
            message: message.into(),
        });
    }

    fn directive(&mut self, node: &Node, name: &str, args: Vec<String>) {
        let name = name.to_ascii_lowercase();
        let Some(operation) = nginx_ir_operation(&name) else {
            self.error(
                node,
                format!("internal nginx lowering emitted unknown IR operation '{name}'"),
            );
            return;
        };
        if !httpd_rs_verified::nginx_ir_operation_arg_admit(operation, args.len() as u64) {
            self.error(
                node,
                format!(
                    "internal nginx lowering emitted invalid arity {} for IR operation '{name}'",
                    args.len()
                ),
            );
            return;
        }
        self.events.push(Event::Directive {
            name,
            args,
            loc: node.loc.clone(),
        });
    }

    fn simple(&mut self, node: &Node, name: &str, min: usize, max: usize) {
        if node.children.is_some() || !(min..=max).contains(&node.args.len()) {
            self.error(
                node,
                format!(
                    "{} requires {min}..={max} arguments and no block",
                    node.name
                ),
            );
        } else {
            self.directive(node, name, node.args.clone());
        }
    }

    fn simple_literal(&mut self, node: &Node, name: &str, min: usize, max: usize) {
        if node.args.iter().any(|arg| arg.contains('$')) {
            self.error(
                node,
                format!(
                    "{} variables are outside the finite source-neutral value grammar",
                    node.name
                ),
            );
        } else {
            self.simple(node, name, min, max);
        }
    }

    fn lower_user(&mut self, node: &Node) {
        if node.children.is_some() || !(1..=2).contains(&node.args.len()) {
            self.error(node, "user requires a user and optional group");
            return;
        }
        self.directive(node, "User", vec![node.args[0].clone()]);
        self.directive(
            node,
            "Group",
            vec![node.args.get(1).unwrap_or(&node.args[0]).clone()],
        );
    }

    fn noop(&mut self, node: &Node) {
        let Some(rationale) = operational_noop_rationale(&node.name) else {
            self.error(
                node,
                format!(
                    "internal nginx frontend error: operational directive '{}' has no audited classification",
                    node.name
                ),
            );
            return;
        };
        if let Err(message) = validate_operational_noop(node) {
            self.error(node, message);
            return;
        }
        if self.warnings.len() < 500 {
            self.warnings.push(format!(
                "{} line {}: nginx operational directive '{}' is accepted and normalized by httpd-rs ({rationale})",
                node.loc.file, node.loc.line, node.name,
            ));
        }
    }

    fn unsupported(&mut self, node: &Node) {
        self.error(
            node,
            format!(
                "unsupported nginx directive '{}'; refusing to ignore configuration semantics",
                node.name
            ),
        );
    }

    fn lower_error_log(&mut self, node: &Node) {
        if node.children.is_some() || node.args.is_empty() || node.args.len() > 2 {
            self.error(node, "error_log requires a path and optional level");
            return;
        }
        self.directive(node, "ErrorLog", vec![node.args[0].clone()]);
        if let Some(level) = node.args.get(1) {
            self.directive(node, "LogLevel", vec![level.clone()]);
        }
    }

    fn lower_events(&mut self, node: &Node) {
        if !node.args.is_empty() {
            self.error(node, "events block takes no arguments");
            return;
        }
        let Some(children) = node.children.as_deref() else {
            self.error(node, "events must be a block");
            return;
        };
        for child in children {
            match child.name.as_str() {
                "worker_connections" => {
                    if child.children.is_some()
                        || child.args.len() != 1
                        || child.args[0]
                            .parse::<u64>()
                            .ok()
                            .is_none_or(|value| value == 0)
                    {
                        self.error(child, "worker_connections requires one positive integer");
                    } else {
                        // nginx counts event-loop connections per worker;
                        // MaxRequestWorkers counts httpd-rs request workers.
                        // Equating them rejects ordinary 768/1024-valued nginx
                        // files and does not preserve either resource model.
                        self.noop(child);
                    }
                }
                "multi_accept" | "use" | "accept_mutex" | "accept_mutex_delay" => self.noop(child),
                _ => self.unsupported(child),
            }
        }
    }

    fn lower_http(&mut self, node: &Node) {
        if !node.args.is_empty() {
            self.error(node, "http block takes no arguments");
            return;
        }
        let Some(children) = node.children.as_deref() else {
            self.error(node, "http must be a block");
            return;
        };
        // Response-header and expiry eligibility are part of the source
        // language's semantics, not an implementation convenience. Carry
        // nginx's exact status whitelist through the common IR.
        self.directive(node, "HttpdRsNginxResponseSemantics", Vec::new());
        let http_has_headers = children.iter().any(|node| node.name == "add_header");
        for child in children {
            match child.name.as_str() {
                "server" | "upstream" | "map" => {}
                "types" => self.lower_types(child),
                "default_type" if child.args.as_slice() == ["application/octet-stream"] => {}
                "access_log" => self.lower_access_log(child),
                "log_format" => self.lower_log_format(child),
                name if http_operational_noop(name) => self.noop(child),
                _ => self.lower_policy_directive(child, "/", false, Context::Http),
            }
        }
        for child in children.iter().filter(|node| node.name == "upstream") {
            self.lower_upstream(child);
        }
        for child in children.iter().filter(|node| node.name == "map") {
            self.lower_map(child);
        }
        let mut servers: Vec<_> = children
            .iter()
            .filter(|node| node.name == "server")
            .collect();
        if servers.is_empty() {
            self.error(node, "http block contains no server blocks");
            return;
        }
        let mut default_listeners = HashSet::new();
        let mut declared_names = HashSet::new();
        let mut wildcard_servers: HashMap<u16, (HashSet<usize>, HashSet<usize>)> = HashMap::new();
        for (server_index, server) in servers.iter().enumerate() {
            let mut default = false;
            let mut ordinary = false;
            let mut server_listeners = HashSet::new();
            for listen in server_listen_specs(server) {
                match listen {
                    Ok(listen) => {
                        if !server_listeners.insert(listen.address.clone()) {
                            self.error(
                                server,
                                format!(
                                    "listener '{}' is declared more than once in one server block",
                                    listen.address
                                ),
                            );
                            continue;
                        }
                        default |= listen.default_server;
                        ordinary |= !listen.default_server;
                        if listen.default_server
                            && !default_listeners.insert(listen.address.clone())
                        {
                            self.error(
                                server,
                                format!(
                                    "more than one default_server is declared for {}",
                                    listen.address
                                ),
                            );
                        }
                        if self.listeners.insert(listen.address.clone()) {
                            self.directive(server, "Listen", vec![listen.address.clone()]);
                        }
                        if let Some((port, ipv4)) = nginx_wildcard_listener(&listen.address) {
                            let families = wildcard_servers.entry(port).or_default();
                            if ipv4 {
                                families.0.insert(server_index);
                            } else {
                                families.1.insert(server_index);
                            }
                        }
                    }
                    Err(message) => self.error(server, message),
                }
            }
            if default && ordinary {
                self.error(
                    server,
                    "a server block may not mix default_server and non-default listen identities in the supported subset",
                );
            }
            let listeners: Vec<String> = server_listen_specs(server)
                .filter_map(Result::ok)
                .map(|listen| listen.address)
                .collect();
            let names = server
                .children
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter(|child| child.name == "server_name")
                .filter_map(|child| normalize_server_names(child).ok())
                .flatten();
            for name in names {
                for listener in &listeners {
                    if !declared_names.insert((listener.clone(), name.clone())) {
                        self.error(
                            server,
                            format!(
                                "duplicate server_name '{name}' on listener '{listener}' is outside the deterministic subset"
                            ),
                        );
                    }
                }
            }
        }
        for (port, (ipv4, ipv6)) in wildcard_servers {
            if !ipv4.is_empty() && !ipv6.is_empty() && ipv4 != ipv6 {
                self.error(
                    node,
                    format!(
                        "IPv4 and IPv6 wildcard listeners on port {port} select different server blocks; the supported subset requires identical dual-stack routing sets"
                    ),
                );
            }
        }
        servers.sort_by_key(|server| {
            !server_listen_specs(server)
                .filter_map(Result::ok)
                .any(|listen| listen.default_server)
        });
        for server in servers {
            self.lower_server(server, http_has_headers);
        }
    }

    fn lower_types(&mut self, node: &Node) {
        if !node.args.is_empty() {
            self.error(node, "types block takes no arguments");
            return;
        }
        let Some(children) = node.children.as_deref() else {
            self.error(node, "types must be a block");
            return;
        };
        for entry in children {
            if entry.children.is_some() || entry.args.is_empty() {
                self.error(entry, "MIME type entries require one or more extensions");
            } else {
                let mut args = vec![entry.name.clone()];
                args.extend(entry.args.clone());
                self.directive(entry, "AddType", args);
            }
        }
    }

    fn lower_access_log(&mut self, node: &Node) {
        if node.children.is_some() || node.args.is_empty() || node.args.len() > 3 {
            self.error(
                node,
                "access_log requires a path, optional format, and optional buffer control",
            );
            return;
        }
        if node.args[0].eq_ignore_ascii_case("off") {
            return;
        }
        if node
            .args
            .iter()
            .skip(2)
            .any(|arg| !arg.starts_with("buffer=") && !arg.starts_with("flush="))
        {
            self.error(node, "unsupported access_log option");
            return;
        }
        self.directive(
            node,
            "CustomLog",
            vec![node.args[0].clone(), "combined".into()],
        );
        if node.args.get(1).is_some_and(|name| name != "combined") && self.warnings.len() < 500 {
            self.warnings.push(format!(
                "{} line {}: nginx access log format is normalized to bounded Apache combined format",
                node.loc.file, node.loc.line
            ));
        }
    }

    fn lower_log_format(&mut self, node: &Node) {
        if node.children.is_some() || node.args.len() < 2 {
            self.error(node, "log_format requires a name and format");
        } else if self.warnings.len() < 500 {
            self.warnings.push(format!(
                "{} line {}: nginx log_format '{}' is accepted for access_log selection but normalized at runtime",
                node.loc.file, node.loc.line, node.args[0]
            ));
        }
    }

    fn lower_upstream(&mut self, node: &Node) {
        if node.args.len() != 1 || node.children.is_none() {
            self.error(node, "upstream requires one name and a block");
            return;
        }
        let name = &node.args[0];
        if !valid_symbol(name) || !self.upstreams.insert(name.clone()) {
            self.error(node, "invalid or duplicate upstream name");
            return;
        }
        self.events.push(Event::SectionStart {
            name: "proxy".into(),
            args: vec![format!("balancer://{name}")],
            loc: node.loc.clone(),
            active: true,
            transparent: false,
        });
        let mut member_count = 0usize;
        for child in node.children.as_deref().unwrap_or_default() {
            match child.name.as_str() {
                "server" if child.children.is_none() && child.args.len() == 1 => {
                    let backend = normalize_upstream_backend(&child.args[0]);
                    if crate::proxy::valid_http_backend(&backend) {
                        member_count += 1;
                        self.directive(child, "BalancerMember", vec![backend]);
                    } else {
                        self.error(child, "invalid literal upstream server authority");
                    }
                }
                "keepalive" | "keepalive_requests" | "keepalive_timeout" | "zone" => {
                    self.noop(child)
                }
                "least_conn" | "ip_hash" | "hash" | "random" => self.error(
                    child,
                    "this upstream selection algorithm is outside the supported round-robin subset",
                ),
                _ => self.unsupported(child),
            }
        }
        if member_count == 0 {
            self.error(node, "upstream requires at least one valid server");
        }
        self.events.push(Event::SectionEnd {
            loc: node.loc.clone(),
        });
    }

    fn lower_map(&mut self, node: &Node) {
        let conventional = node.args.as_slice() == ["$http_upgrade", "$connection_upgrade"]
            && node.children.as_deref().is_some_and(|children| {
                children.len() == 2
                    && children.iter().any(|entry| {
                        entry.name == "default" && entry.args.as_slice() == ["upgrade"]
                    })
                    && children
                        .iter()
                        .any(|entry| entry.name.is_empty() && entry.args.as_slice() == ["close"])
            });
        if !conventional {
            self.error(node, "only the conventional finite $http_upgrade to $connection_upgrade map is supported");
        }
    }

    fn lower_server(&mut self, node: &Node, inherited_headers: bool) {
        if !node.args.is_empty() || node.children.is_none() {
            self.error(node, "server requires a block and no arguments");
            return;
        }
        let listen_specs: Vec<_> = server_listen_specs(node).filter_map(Result::ok).collect();
        let listens = listen_specs
            .iter()
            .map(|listen| listen.address.clone())
            .collect();
        self.events.push(Event::SectionStart {
            name: "virtualhost".into(),
            args: listens,
            loc: node.loc.clone(),
            active: true,
            transparent: false,
        });
        let server_has_headers = node
            .children
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|child| child.name == "add_header");
        if inherited_headers && server_has_headers {
            self.directive(node, "HttpdRsNginxResetHeaders", Vec::new());
        }
        let mut server_names = Vec::new();
        for child in node.children.as_deref().unwrap_or_default() {
            match child.name.as_str() {
                "listen" | "location" => {}
                "server_name" => match normalize_server_names(child) {
                    Ok(names) => server_names.extend(names),
                    Err(message) => self.error(child, message),
                },
                "ssl_certificate" => self.simple_literal(child, "SSLCertificateFile", 1, 1),
                "ssl_certificate_key" => self.simple_literal(child, "SSLCertificateKeyFile", 1, 1),
                "ssl_protocols" => self.lower_ssl_protocols(child),
                "ssl_ciphers" => self.simple(child, "SSLCipherSuite", 1, 1),
                "http2" => self.lower_http2(child),
                "access_log" => self.lower_access_log(child),
                "error_log" => self.lower_error_log(child),
                "ssl_session_cache"
                | "ssl_session_timeout"
                | "ssl_session_tickets"
                | "ssl_prefer_server_ciphers"
                | "ssl_stapling"
                | "ssl_stapling_verify" => self.error(
                    child,
                    "TLS security/session directives are not operational no-ops; this frontend rejects them until their exact policy is represented in the common IR",
                ),
                _ => self.lower_policy_directive(child, "/", false, Context::Server),
            }
        }
        if listen_specs.iter().any(|listen| listen.ssl) {
            self.directive(node, "SSLEngine", vec!["On".into()]);
        }
        if listen_specs.iter().any(|listen| listen.http2) {
            self.directive(node, "Protocols", vec!["h2".into(), "http/1.1".into()]);
        }
        if let Some(primary) = server_names.first() {
            if primary != "_" {
                self.directive(node, "ServerName", vec![primary.clone()]);
            }
            let aliases: Vec<String> = server_names
                .into_iter()
                .skip(1)
                .filter(|name| name != "_")
                .collect();
            if !aliases.is_empty() {
                self.directive(node, "ServerAlias", aliases);
            }
        }
        let mut route_matchers = Vec::new();
        for location in node
            .children
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter(|child| child.name == "location")
        {
            self.lower_location(
                location,
                &mut route_matchers,
                inherited_headers || server_has_headers,
            );
        }
        self.events.push(Event::SectionEnd {
            loc: node.loc.clone(),
        });
        self.routes.push(route_matchers);
    }

    fn lower_location(
        &mut self,
        node: &Node,
        routes: &mut Vec<RouteMatcher>,
        inherited_headers: bool,
    ) {
        let Some(children) = node.children.as_deref() else {
            self.error(node, "location requires a block");
            return;
        };
        if children.iter().any(|child| child.name == "location") {
            self.error(
                node,
                "nested nginx locations are not supported; refusing ambiguous winner selection",
            );
            return;
        }
        if children.iter().any(|child| child.name == "root")
            && children.iter().any(|child| child.name == "alias")
        {
            self.error(node, "a location cannot declare both root and alias");
            return;
        }
        let (matcher, section, path) = match parse_location(node) {
            Ok(value) => value,
            Err(message) => {
                self.error(node, message);
                return;
            }
        };
        let duplicate = routes.iter().any(|existing| match (existing, &matcher) {
            (RouteMatcher::Exact(left), RouteMatcher::Exact(right)) => left == right,
            (
                RouteMatcher::Prefix { value: left, .. },
                RouteMatcher::Prefix { value: right, .. },
            ) => left == right,
            _ => false,
        });
        if duplicate {
            self.error(node, "duplicate nginx literal location");
            return;
        }
        let route_is_regex = matches!(matcher, RouteMatcher::Regex { .. });
        let proxy_redirect_off = children
            .iter()
            .find(|child| child.name == "proxy_redirect")
            .and_then(|child| child.args.first())
            .is_some_and(|value| value == "off");
        routes.push(matcher);
        self.events.push(Event::SectionStart {
            name: section.to_ascii_lowercase(),
            args: vec![path.clone()],
            loc: node.loc.clone(),
            active: true,
            transparent: false,
        });
        if inherited_headers && children.iter().any(|child| child.name == "add_header") {
            self.directive(node, "HttpdRsNginxResetHeaders", Vec::new());
        }
        for child in children {
            match child.name.as_str() {
                "access_log" => self.lower_access_log(child),
                "error_log" => self.lower_error_log(child),
                "proxy_pass" => {
                    self.lower_proxy_pass(child, &path, route_is_regex, proxy_redirect_off)
                }
                "proxy_redirect" => self.lower_proxy_redirect(child),
                name if location_operational_noop(name) => self.noop(child),
                _ => self.lower_policy_directive(child, &path, route_is_regex, Context::Location),
            }
        }
        self.events.push(Event::SectionEnd {
            loc: node.loc.clone(),
        });
    }

    fn lower_policy_directive(
        &mut self,
        node: &Node,
        route: &str,
        route_is_regex: bool,
        context: Context,
    ) {
        if node.children.is_some() {
            self.unsupported(node);
            return;
        }
        match node.name.as_str() {
            "root" => self.simple_literal(
                node,
                if context == Context::Location {
                    "HttpdRsScopedRoot"
                } else {
                    "DocumentRoot"
                },
                1,
                1,
            ),
            "index" => self.simple_literal(node, "DirectoryIndex", 1, 128),
            "sendfile" => self.simple_on_off(node, "EnableSendfile"),
            "keepalive_timeout" if context == Context::Http => match node.args.as_slice() {
                [value] => match nginx_duration_seconds(value) {
                    Some(seconds) => {
                        self.directive(node, "KeepAliveTimeout", vec![seconds.to_string()])
                    }
                    None => self.error(node, "keepalive_timeout requires one bounded time value"),
                },
                _ => self.error(node, "keepalive_timeout requires one bounded time value"),
            },
            "keepalive_requests" if context == Context::Http => self.simple(node, "MaxKeepAliveRequests", 1, 1),
            "client_max_body_size" => match node.args.as_slice() {
                [value] => match nginx_size(value) {
                    Ok(value) => self.directive(
                        node,
                        if context == Context::Http {
                            "LimitRequestBody"
                        } else {
                            "HttpdRsScopedBodyLimit"
                        },
                        // nginx uses zero to disable only this semantic body
                        // ceiling. The independent spool/resident/throughput
                        // resource budgets remain in force.
                        vec![if value == 0 {
                            u64::MAX.to_string()
                        } else {
                            value.to_string()
                        }],
                    ),
                    Err(message) => self.error(node, message),
                },
                _ => self.error(node, "client_max_body_size requires one value"),
            },
            "server_tokens" if context == Context::Http => {
                if node.args.as_slice() == ["off"] { self.directive(node, "ServerTokens", vec!["Prod".into()]); }
                else if node.args.as_slice() == ["on"] { self.directive(node, "ServerTokens", vec!["Full".into()]); }
                else { self.error(node, "server_tokens accepts on or off"); }
            }
            "autoindex" => {
                if node.args.as_slice() == ["on"] { self.directive(node, "Options", vec!["+Indexes".into()]); }
                else if node.args.as_slice() == ["off"] { self.directive(node, "Options", vec!["-Indexes".into()]); }
                else { self.error(node, "autoindex accepts on or off"); }
            }
            "gzip" => {
                if node.args.as_slice() == ["on"] { self.directive(node, "SetOutputFilter", vec!["DEFLATE".into()]); }
                else if node.args.as_slice() == ["off"] { self.directive(node, "SetOutputFilter", vec!["None".into()]); }
                else { self.error(node, "gzip accepts on or off"); }
            }
            "gzip_types" => {
                if node.args.is_empty() { self.error(node, "gzip_types requires MIME types"); }
                else { let mut args = vec!["DEFLATE".into()]; args.extend(node.args.clone()); self.directive(node, "AddOutputFilterByType", args); }
            }
            "gzip_comp_level" => match node.args.as_slice() {
                [level] if level.parse::<u8>().is_ok_and(|value| (1..=9).contains(&value)) => {
                    self.directive(node, "DeflateCompressionLevel", vec![level.clone()]);
                }
                _ => self.error(node, "gzip_comp_level requires an integer from 1 through 9"),
            },
            "gzip_vary" => {
                if node.args.len() == 1 && matches!(node.args[0].as_str(), "on" | "off") {
                    // httpd-rs always emits Vary when a representation is
                    // negotiable; allowing `off` to remove it would make a
                    // shared cache unsound. Normalize both values explicitly.
                    self.noop(node);
                } else {
                    self.error(node, "gzip_vary accepts on or off");
                }
            }
            "proxy_connect_timeout" | "proxy_read_timeout" | "proxy_send_timeout"
            | "fastcgi_connect_timeout" | "fastcgi_read_timeout" | "fastcgi_send_timeout"
            | "client_body_timeout" | "client_header_timeout" | "send_timeout" => {
                self.lower_runtime_timeout(node)
            }
            "proxy_http_version" => {
                if node.args.as_slice() != ["1.1"] { self.error(node, "only proxy_http_version 1.1 is supported"); }
            }
            "proxy_set_header" => self.simple(node, "HttpdRsProxySetHeader", 2, 2),
            "proxy_pass" if context == Context::Location => {
                self.lower_proxy_pass(node, route, route_is_regex, false)
            }
            "proxy_pass" => self.error(node, "proxy_pass is only valid in a location block"),
            "fastcgi_pass" if context == Context::Location => self.lower_fastcgi_pass(node),
            "fastcgi_pass" => self.error(node, "fastcgi_pass is only valid in a location block"),
            "fastcgi_param" => self.simple(node, "HttpdRsFastCgiParam", 2, 3),
            "fastcgi_index" => self.simple_literal(node, "DirectoryIndex", 1, 1),
            "fastcgi_split_path_info" => self.lower_fastcgi_split_path_info(node),
            "alias" if context == Context::Location => {
                self.lower_alias(node, route, route_is_regex)
            }
            "alias" => self.error(node, "alias is only valid in a location block"),
            "add_header" => self.lower_add_header(node),
            "expires" => self.lower_expires(node),
            "auth_basic" => {
                if node.args.iter().any(|arg| arg.contains('$')) {
                    self.error(node, "auth_basic variables are not supported");
                }
                else if node.args.as_slice() == ["off"] { self.error(node, "auth_basic off cannot safely cancel an inherited authorization policy"); }
                else if node.args.len() == 1 { self.directive(node, "AuthType", vec!["Basic".into()]); self.directive(node, "AuthName", node.args.clone()); }
                else { self.error(node, "auth_basic requires one realm or off"); }
            }
            "auth_basic_user_file" => {
                self.simple(node, "AuthUserFile", 1, 1);
                self.directive(node, "Require", vec!["valid-user".into()]);
            }
            "try_files" if context != Context::Http => {
                self.lower_try_files(node)
            }
            "try_files" => self.error(node, "try_files is only valid in server or location context"),
            "return" if context != Context::Http => self.lower_return(node),
            "return" => self.error(node, "return is only valid in server or location context"),
            "allow" | "deny" => self.error(node, "nginx ordered allow/deny rules require an explicit ACL compiler and are not silently approximated"),
            "error_page" => self.lower_error_page(node),
            _ => self.unsupported(node),
        }
    }

    fn simple_on_off(&mut self, node: &Node, name: &str) {
        if node.args.len() == 1 && matches!(node.args[0].as_str(), "on" | "off") {
            self.directive(
                node,
                name,
                vec![if node.args[0] == "on" { "On" } else { "Off" }.into()],
            );
        } else {
            self.error(node, format!("{} accepts on or off", node.name));
        }
    }

    fn lower_alias(&mut self, node: &Node, route: &str, route_is_regex: bool) {
        if node.children.is_some() || node.args.len() != 1 {
            self.error(node, "alias requires one literal filesystem path");
            return;
        }
        if route_is_regex {
            self.error(
                node,
                "regex-location alias requires capture substitution outside the finite path-mapping IR",
            );
            return;
        }
        if node.args[0].contains('$') || node.args[0].as_bytes().contains(&0) {
            self.error(node, "alias path must be literal and contain no NUL byte");
            return;
        }
        self.directive(
            node,
            "HttpdRsNginxAlias",
            vec![route.to_string(), node.args[0].clone()],
        );
    }

    fn lower_try_files(&mut self, node: &Node) {
        if node.children.is_some() || node.args.len() < 2 {
            self.error(
                node,
                "try_files requires bounded candidates and one fallback",
            );
            return;
        }
        let candidates = &node.args[..node.args.len() - 1];
        let candidate_mode = match candidates {
            [uri] if uri == "$uri" => "file",
            [uri, directory] if uri == "$uri" && directory == "$uri/" => "file-directory",
            _ => {
                self.error(
                    node,
                    "try_files candidates are limited to '$uri' or '$uri $uri/'",
                );
                return;
            }
        };
        let fallback = node.args.last().expect("length checked");
        if fallback == "=404" {
            if candidate_mode == "file" {
                // The common static handler also recognizes directories. It
                // therefore cannot exactly encode `$uri =404`, where nginx
                // requires the explicit `$uri/` candidate before admitting a
                // directory. Reject that shape instead of silently widening
                // what can be served.
                self.error(
                    node,
                    "try_files '$uri =404' is ambiguous; include the explicit '$uri/' candidate",
                );
            }
            // The ordinary static path already returns 404 after the same
            // file/directory probes for `$uri $uri/ =404`, so no synthetic
            // transition is needed.
            return;
        }
        if !fallback.starts_with('/') || fallback.contains('#') {
            self.error(
                node,
                "try_files fallback must be =404 or an absolute local URI",
            );
            return;
        }
        let fallback = if let Some(path) = fallback.strip_suffix("?$args") {
            path
        } else if let Some(path) = fallback.strip_suffix("?$query_string") {
            path
        } else if fallback.contains('$') {
            self.error(
                node,
                "try_files fallback permits only the complete $args/$query_string suffix",
            );
            return;
        } else {
            fallback.as_str()
        };
        if crate::request_plan::CanonicalTarget::from_url_path(
            fallback
                .split_once('?')
                .map(|(path, _)| path)
                .unwrap_or(fallback),
        )
        .is_none()
        {
            self.error(node, "try_files fallback is not a canonical local URI");
            return;
        }
        self.directive(
            node,
            "HttpdRsNginxTryFiles",
            vec![fallback.to_string(), candidate_mode.into()],
        );
    }

    fn lower_error_page(&mut self, node: &Node) {
        if node.children.is_some() || node.args.len() < 2 {
            self.error(
                node,
                "error_page requires one or more statuses and a target URI",
            );
            return;
        }
        let target = node.args.last().expect("length checked");
        if target.starts_with('=') || target.starts_with('@') || target.contains('$') {
            self.error(
                node,
                "error_page status overrides, named locations, and variable targets are outside the finite terminal projection",
            );
            return;
        }
        let local = target.starts_with('/');
        let external = target.starts_with("http://") || target.starts_with("https://");
        if (!local && !external)
            || (local && crate::util::split_internal_request_target(target).is_none())
        {
            self.error(
                node,
                "error_page target must be an unambiguous local or HTTP(S) URI",
            );
            return;
        }
        for status in &node.args[..node.args.len() - 1] {
            if status
                .parse::<u16>()
                .ok()
                .is_none_or(|status| !(400..=599).contains(&status))
            {
                self.error(
                    node,
                    "error_page statuses are limited to HTTP errors from 400 through 599",
                );
                return;
            }
        }
        for status in &node.args[..node.args.len() - 1] {
            self.directive(node, "ErrorDocument", vec![status.clone(), target.clone()]);
        }
    }

    fn lower_expires(&mut self, node: &Node) {
        if node.children.is_some() || node.args.is_empty() || node.args.len() > 2 {
            self.error(node, "expires requires a time or 'modified' plus a time");
            return;
        }
        if node.args.as_slice() == ["off"] {
            self.directive(node, "ExpiresActive", vec!["Off".into()]);
            return;
        }
        let (base, value) = match node.args.as_slice() {
            [value] => ("access", value.as_str()),
            [modified, value] if modified == "modified" => ("modification", value.as_str()),
            _ => {
                self.error(
                    node,
                    "expires supports only a duration or 'modified duration'",
                );
                return;
            }
        };
        let Some(seconds) = nginx_duration_seconds(value) else {
            self.error(
                node,
                "expires duration must be a non-negative bounded nginx time value",
            );
            return;
        };
        self.directive(node, "ExpiresActive", vec!["On".into()]);
        self.directive(
            node,
            "ExpiresDefault",
            vec![format!("{base} plus {seconds} seconds")],
        );
    }

    fn lower_proxy_pass(
        &mut self,
        node: &Node,
        route: &str,
        route_is_regex: bool,
        proxy_redirect_off: bool,
    ) {
        if node.args.len() != 1 {
            self.error(node, "proxy_pass requires one literal backend");
            return;
        }
        let mut backend = node.args[0].clone();
        if backend.contains('$') {
            self.error(
                node,
                "variable proxy_pass targets are outside the finite backend identity model",
            );
            return;
        }
        let Some((authority, uri)) = proxy_pass_authority_and_uri(&backend) else {
            self.error(
                node,
                "proxy_pass backend must be http:// or https:// with a literal authority",
            );
            return;
        };
        let has_uri = uri.is_some();
        if self.upstreams.contains(authority) {
            backend = format!("balancer://{authority}{}", uri.unwrap_or(""));
        }
        if route_is_regex && has_uri {
            self.error(
                node,
                "nginx forbids a proxy_pass URI suffix in a regex location",
            );
            return;
        }
        if !backend.starts_with("http://")
            && !backend.starts_with("https://")
            && !backend.starts_with("balancer://")
        {
            self.error(
                node,
                "proxy_pass backend must be http://, https://, or a declared upstream",
            );
            return;
        }
        // nginx preserves the complete normalized request URI when
        // proxy_pass has no URI part.  When it does have one, nginx replaces
        // the selected literal location prefix. Apache ProxyPass expresses
        // those as `/ -> backend` and `location -> backend/uri`
        // respectively; because the nginx location winner has already been
        // selected, the catch-all route cannot escape its policy scope.
        let dispatch_prefix = if has_uri { route } else { "/" };
        self.directive(
            node,
            "HttpdRsRouteProxyPass",
            vec![dispatch_prefix.into(), backend.clone()],
        );
        if !proxy_redirect_off
            && (backend.starts_with("http://") || backend.starts_with("https://"))
        {
            self.directive(
                node,
                "HttpdRsRouteProxyPassReverse",
                vec![route.into(), backend],
            );
        }
    }

    fn lower_proxy_redirect(&mut self, node: &Node) {
        if node.children.is_some()
            || node.args.len() != 1
            || !matches!(node.args[0].as_str(), "off" | "default")
        {
            self.error(
                node,
                "proxy_redirect supports only the finite 'off' or 'default' forms",
            );
        }
    }

    fn lower_runtime_timeout(&mut self, node: &Node) {
        if node.children.is_some()
            || node.args.len() != 1
            || nginx_duration_seconds(&node.args[0]).is_none()
        {
            self.error(
                node,
                format!("{} requires one bounded nginx time value", node.name),
            );
            return;
        }
        // Dependency I/O is protected by httpd-rs's own bounded cancellation
        // deadlines. Retaining an arbitrary nginx timeout would widen that
        // resource budget, so accepted values are deliberately normalized and
        // surfaced as a load warning through the ordinary operational path.
        self.noop(node);
    }

    fn lower_fastcgi_split_path_info(&mut self, node: &Node) {
        const CONVENTIONAL: &[&str] = &[
            "^(.+[.]php)(/.+)$",
            "^(.+\\.php)(/.+)$",
            "^(.+[.]php)(/.*)$",
            "^(.+\\.php)(/.*)$",
        ];
        if node.children.is_none()
            && node.args.len() == 1
            && CONVENTIONAL.contains(&node.args[0].as_str())
        {
            // The runtime derives the longest existing script prefix and
            // bounded PATH_INFO, which refines these conventional PHP splits.
            self.noop(node);
        } else {
            self.error(
                node,
                "fastcgi_split_path_info supports only the conventional PHP script/path-info split",
            );
        }
    }

    fn lower_fastcgi_pass(&mut self, node: &Node) {
        if node.args.len() != 1 || node.args[0].contains('$') {
            self.error(node, "fastcgi_pass requires one literal endpoint");
            return;
        }
        let backend = if let Some(socket) = node.args[0].strip_prefix("unix:") {
            if !Path::new(socket).is_absolute() {
                self.error(node, "FastCGI unix socket must be absolute");
                return;
            }
            format!("unix:{socket}|fcgi://localhost/")
        } else {
            format!("fcgi://{}/", node.args[0])
        };
        self.directive(
            node,
            "HttpdRsRouteProxyPass",
            // The selected location controls admission; FastCGI script
            // identity remains the complete canonical URL path and is then
            // constrained by the configured SCRIPT_FILENAME expression.
            vec!["/".into(), backend],
        );
    }

    fn lower_add_header(&mut self, node: &Node) {
        if !(2..=3).contains(&node.args.len())
            || node.args.get(2).is_some_and(|value| value != "always")
        {
            self.error(
                node,
                "add_header requires name, closed value expression, and optional 'always'",
            );
            return;
        }
        if node.args[1].contains('$') {
            self.error(
                node,
                "add_header currently accepts literal values only; response-variable expressions are not silently approximated",
            );
            return;
        }
        let mut args = Vec::new();
        if node.args.len() == 3 {
            args.push("always".into());
        }
        // nginx appends response fields; it does not replace an identically
        // named field supplied by the content handler. `Header add` is the
        // exact shared-IR operation, while the separate reset marker models
        // nginx's array inheritance between configuration scopes.
        args.extend(["add".into(), node.args[0].clone(), node.args[1].clone()]);
        self.directive(node, "Header", args);
    }

    fn lower_return(&mut self, node: &Node) {
        match node.args.as_slice() {
            [status, target]
                if matches!(status.as_str(), "301" | "302" | "303" | "307" | "308")
                    && !target.contains('$') =>
            {
                self.directive(
                    node,
                    "HttpdRsNginxReturn",
                    vec![status.clone(), "/".into(), target.clone()],
                );
            }
            _ => self.error(
                node,
                "return supports only literal 301/302/303/307/308 redirects in this frontend",
            ),
        }
    }

    fn lower_ssl_protocols(&mut self, node: &Node) {
        if node.children.is_some()
            || node.args.is_empty()
            || node
                .args
                .iter()
                .any(|arg| !matches!(arg.as_str(), "TLSv1.2" | "TLSv1.3"))
        {
            self.error(node, "ssl_protocols supports only TLSv1.2 and TLSv1.3");
            return;
        }
        let mut args = vec!["-all".into()];
        args.extend(node.args.iter().map(|arg| format!("+{arg}")));
        self.directive(node, "SSLProtocol", args);
    }

    fn lower_http2(&mut self, node: &Node) {
        if node.args.as_slice() == ["on"] {
            self.directive(node, "Protocols", vec!["h2".into(), "http/1.1".into()]);
        } else if node.args.as_slice() == ["off"] {
            self.directive(node, "Protocols", vec!["http/1.1".into()]);
        } else {
            self.error(node, "http2 accepts on or off");
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Context {
    Http,
    Server,
    Location,
}

fn parse_location(node: &Node) -> Result<(RouteMatcher, &'static str, String), String> {
    let (modifier, value) = match node.args.as_slice() {
        [value] => ("", value.as_str()),
        [modifier, value] => (modifier.as_str(), value.as_str()),
        _ => return Err("location requires a path and optional =, ^~, ~, or ~* modifier".into()),
    };
    if value.is_empty() || value.starts_with('@') {
        return Err("named or empty nginx locations are not supported".into());
    }
    match modifier {
        "" => {
            if !value.starts_with('/') || value.contains('$') {
                return Err("literal location must start with '/' and contain no variables".into());
            }
            Ok((
                RouteMatcher::Prefix {
                    value: value.into(),
                    suppress_regex: false,
                },
                "Location",
                value.into(),
            ))
        }
        "=" => {
            if !value.starts_with('/') || value.contains('$') {
                return Err("exact location must start with '/' and contain no variables".into());
            }
            Ok((RouteMatcher::Exact(value.into()), "Location", value.into()))
        }
        "^~" => {
            if !value.starts_with('/') || value.contains('$') {
                return Err("^~ location must start with '/' and contain no variables".into());
            }
            Ok((
                RouteMatcher::Prefix {
                    value: value.into(),
                    suppress_regex: true,
                },
                "Location",
                value.into(),
            ))
        }
        "~" | "~*" => {
            let regex_modifier = if modifier == "~*" {
                httpd_rs_verified::NginxRegexModifier::Caseless
            } else {
                httpd_rs_verified::NginxRegexModifier::Sensitive
            };
            let regex = crate::apache_regex::Regex::compile_nginx(value, regex_modifier)
                .map_err(|error| format!("unsupported nginx location regex: {error}"))?;
            Ok((
                RouteMatcher::Regex {
                    value: value.into(),
                    regex,
                },
                "LocationMatch",
                value.into(),
            ))
        }
        _ => Err(format!("unsupported nginx location modifier '{modifier}'")),
    }
}

#[derive(Debug, Clone)]
struct NginxListen {
    address: String,
    default_server: bool,
    ssl: bool,
    http2: bool,
}

fn parse_listen(node: &Node) -> Result<NginxListen, String> {
    if node.children.is_some() || node.args.is_empty() {
        return Err("listen requires an address and optional supported flags".into());
    }
    let is_option = |value: &str| matches!(value, "default_server" | "ssl" | "http2");
    let (raw_address, options) = if is_option(&node.args[0]) {
        ("80".to_string(), node.args.as_slice())
    } else {
        (node.args[0].clone(), &node.args[1..])
    };
    if raw_address.contains('$') || raw_address.is_empty() {
        return Err("listen address must be a non-empty literal".into());
    }
    let address = canonical_nginx_listen_address(&raw_address)?;
    let mut default_server = false;
    let mut ssl = false;
    let mut http2 = false;
    for option in options {
        match option.as_str() {
            "default_server" if !default_server => default_server = true,
            "ssl" if !ssl => ssl = true,
            "http2" if !http2 => http2 = true,
            "default_server" | "ssl" | "http2" => {
                return Err(format!("duplicate listen option '{option}'"));
            }
            _ => {
                return Err(format!(
                    "listen option '{option}' is outside the supported nginx subset"
                ));
            }
        }
    }
    Ok(NginxListen {
        address,
        default_server,
        ssl,
        http2,
    })
}

fn canonical_nginx_listen_address(raw: &str) -> Result<String, String> {
    // The shared compiler uses Apache's listener syntax. nginx additionally
    // permits an IPv4 literal without a port; normalize that spelling before
    // asking the common parser to validate the complete endpoint.
    let parse_input = if raw.parse::<std::net::Ipv4Addr>().is_ok() {
        format!("{raw}:80")
    } else {
        raw.to_string()
    };
    let parsed = crate::config::parse_listen(&parse_input)
        .map_err(|error| format!("unsupported nginx listen endpoint '{raw}': {error}"))?;
    let address = parsed
        .addr
        .parse::<std::net::IpAddr>()
        .map(crate::access::canonical_ip)
        .map_err(|_| "nginx listen endpoints must use literal IP addresses".to_string())?;
    if address.is_ipv4() {
        if address.is_unspecified() {
            Ok(format!("*:{}", parsed.port))
        } else {
            Ok(format!("{address}:{}", parsed.port))
        }
    } else {
        Ok(format!("[{address}]:{}", parsed.port))
    }
}

fn nginx_wildcard_listener(address: &str) -> Option<(u16, bool)> {
    let parsed = crate::config::parse_listen(address).ok()?;
    let ip = parsed.addr.parse::<std::net::IpAddr>().ok()?;
    ip.is_unspecified().then_some((parsed.port, ip.is_ipv4()))
}

fn server_listen_specs(node: &Node) -> impl Iterator<Item = Result<NginxListen, String>> + '_ {
    let explicit: Vec<_> = node
        .children
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|child| child.name == "listen")
        .map(parse_listen)
        .collect();
    if explicit.is_empty() {
        vec![Ok(NginxListen {
            // nginx's omitted listen directive is the IPv4 wildcard on port
            // 80. Keep the virtual-host identity in the same canonical form
            // as an explicit `listen 80` so request routing cannot lose the
            // wildcard bucket while the socket itself still binds.
            address: "*:80".into(),
            default_server: false,
            ssl: false,
            http2: false,
        })]
        .into_iter()
    } else {
        explicit.into_iter()
    }
}

fn normalize_server_names(node: &Node) -> Result<Vec<String>, String> {
    if node.children.is_some() || node.args.is_empty() {
        return Err("server_name requires one or more names and no block".into());
    }
    let mut names = Vec::new();
    for name in &node.args {
        if name == "_" || name.is_empty() {
            names.push("_".into());
            continue;
        }
        if name.starts_with('~') || name.contains('$') {
            return Err("regex and variable server_name forms are not supported".into());
        }
        if let Some(suffix) = name.strip_prefix('.') {
            if !valid_server_name(suffix) {
                return Err(format!("invalid server_name '{name}'"));
            }
            names.push(suffix.to_ascii_lowercase());
            names.push(format!("*.{}", suffix.to_ascii_lowercase()));
            continue;
        }
        let wildcard = name.strip_prefix("*.").or_else(|| name.strip_suffix(".*"));
        if (name.contains('*') && wildcard.is_none())
            || !wildcard.is_none_or(valid_server_name)
            || (wildcard.is_none() && !valid_server_name(name))
        {
            return Err(format!("invalid or unsupported server_name '{name}'"));
        }
        names.push(name.to_ascii_lowercase());
    }
    Ok(names)
}

fn valid_server_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b':'))
}

fn proxy_pass_authority_and_uri(value: &str) -> Option<(&str, Option<&str>)> {
    let rest = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))?;
    let (authority, uri) = match rest.split_once('/') {
        Some((authority, _path)) => (authority, Some(&rest[authority.len()..])),
        None => (rest, None),
    };
    (!authority.is_empty()
        && uri.is_none_or(|uri| !uri.contains(['?', '#']) && !uri.contains("..")))
    .then_some((authority, uri))
}

fn valid_symbol(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn normalize_upstream_backend(value: &str) -> String {
    if value.starts_with("http://") || value.starts_with("https://") {
        value.into()
    } else {
        format!("http://{value}")
    }
}

fn nginx_size(value: &str) -> Result<u64, String> {
    let (digits, multiplier) = match value.as_bytes().last().copied() {
        Some(b'k' | b'K') => (&value[..value.len() - 1], 1024u64),
        Some(b'm' | b'M') => (&value[..value.len() - 1], 1024u64 * 1024),
        Some(b'g' | b'G') => (&value[..value.len() - 1], 1024u64 * 1024 * 1024),
        _ => (value, 1),
    };
    digits
        .parse::<u64>()
        .ok()
        .and_then(|number| number.checked_mul(multiplier))
        .ok_or_else(|| format!("invalid or overflowing nginx size '{value}'"))
}

fn nginx_duration_seconds(value: &str) -> Option<u64> {
    if value.is_empty() || value.starts_with('-') || value.starts_with('+') {
        return None;
    }
    let split = value
        .char_indices()
        .find(|(_, ch)| !ch.is_ascii_digit())
        .map(|(index, _)| index)
        .unwrap_or(value.len());
    let amount = value[..split].parse::<u64>().ok()?;
    let multiplier = match &value[split..] {
        "" | "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        "w" => 7 * 24 * 60 * 60,
        "M" => 30 * 24 * 60 * 60,
        "y" => 365 * 24 * 60 * 60,
        _ => return None,
    };
    amount
        .checked_mul(multiplier)
        .filter(|seconds| *seconds <= i64::MAX as u64)
}

fn main_operational_noop(name: &str) -> bool {
    matches!(
        name,
        "worker_processes"
            | "worker_cpu_affinity"
            | "worker_priority"
            | "worker_rlimit_nofile"
            | "daemon"
            | "master_process"
            | "pcre_jit"
            | "thread_pool"
            | "timer_resolution"
            | "worker_shutdown_timeout"
    )
}

fn http_operational_noop(name: &str) -> bool {
    matches!(
        name,
        "tcp_nopush"
            | "tcp_nodelay"
            | "types_hash_max_size"
            | "types_hash_bucket_size"
            | "server_names_hash_max_size"
            | "server_names_hash_bucket_size"
            | "variables_hash_max_size"
            | "variables_hash_bucket_size"
            | "open_file_cache"
            | "open_file_cache_errors"
            | "open_file_cache_min_uses"
            | "open_file_cache_valid"
            | "reset_timedout_connection"
    )
}

fn location_operational_noop(name: &str) -> bool {
    matches!(
        name,
        "proxy_buffering"
            | "proxy_buffers"
            | "proxy_buffer_size"
            | "proxy_busy_buffers_size"
            | "proxy_request_buffering"
            | "fastcgi_buffering"
            | "fastcgi_buffers"
            | "fastcgi_buffer_size"
    )
}

fn positive_integer(value: &str) -> bool {
    value.parse::<u64>().is_ok_and(|number| number > 0)
}

fn nginx_time_syntax(value: &str) -> bool {
    if value.is_empty() || value.starts_with(['+', '-']) {
        return false;
    }
    let split = value
        .char_indices()
        .find(|(_, ch)| !ch.is_ascii_digit())
        .map(|(index, _)| index)
        .unwrap_or(value.len());
    split > 0
        && value[..split].parse::<u64>().is_ok()
        && matches!(
            &value[split..],
            "" | "ms" | "s" | "m" | "h" | "d" | "w" | "M" | "y"
        )
}

fn nginx_size_syntax(value: &str) -> bool {
    nginx_size(value).is_ok_and(|size| size > 0)
}

/// Syntax remains part of the accepted source language even when httpd-rs
/// deliberately owns the corresponding operational effect. Keeping the
/// finite grammar beside the rationale table prevents a misspelled or
/// over-wide nginx directive from being silently normalized.
fn validate_operational_noop(node: &Node) -> Result<(), String> {
    if node.children.is_some() {
        return Err(format!(
            "operational directive '{}' must end with ';'",
            node.name
        ));
    }
    let one = |predicate: fn(&str) -> bool| {
        (node.args.len() == 1 && predicate(&node.args[0])).then_some(())
    };
    let on_off = |value: &str| matches!(value, "on" | "off");
    let valid = match node.name.as_str() {
        "worker_processes" => one(|value| value == "auto" || positive_integer(value)),
        "worker_cpu_affinity" => {
            let masks = if node.args.first().is_some_and(|value| value == "auto") {
                &node.args[1..]
            } else {
                node.args.as_slice()
            };
            (!node.args.is_empty()
                && (masks.is_empty()
                    || masks.iter().all(|mask| {
                        !mask.is_empty()
                            && mask.len() <= 1024
                            && mask.bytes().all(|byte| matches!(byte, b'0' | b'1'))
                    })))
            .then_some(())
        }
        "worker_priority" => one(|value| {
            value
                .parse::<i32>()
                .is_ok_and(|priority| (-20..=20).contains(&priority))
        }),
        "worker_rlimit_nofile"
        | "worker_connections"
        | "keepalive"
        | "keepalive_requests"
        | "open_file_cache_min_uses" => one(positive_integer),
        "daemon"
        | "master_process"
        | "pcre_jit"
        | "multi_accept"
        | "accept_mutex"
        | "tcp_nopush"
        | "tcp_nodelay"
        | "open_file_cache_errors"
        | "reset_timedout_connection"
        | "proxy_buffering"
        | "proxy_request_buffering"
        | "fastcgi_buffering"
        | "gzip_vary" => one(on_off),
        "timer_resolution"
        | "worker_shutdown_timeout"
        | "accept_mutex_delay"
        | "open_file_cache_valid"
        | "keepalive_timeout"
        | "proxy_connect_timeout"
        | "proxy_read_timeout"
        | "proxy_send_timeout"
        | "fastcgi_connect_timeout"
        | "fastcgi_read_timeout"
        | "fastcgi_send_timeout"
        | "client_body_timeout"
        | "client_header_timeout"
        | "send_timeout" => one(nginx_time_syntax),
        "use" => one(|value| {
            matches!(
                value,
                "select" | "poll" | "kqueue" | "epoll" | "/dev/poll" | "eventport"
            )
        }),
        "thread_pool" => {
            if node.args.is_empty() || !valid_symbol(&node.args[0]) {
                None
            } else {
                let mut threads = false;
                let mut queue = false;
                let ok = node.args[1..].iter().all(|arg| {
                    if let Some(value) = arg.strip_prefix("threads=") {
                        let fresh = !threads && positive_integer(value);
                        threads = true;
                        fresh
                    } else if let Some(value) = arg.strip_prefix("max_queue=") {
                        let fresh = !queue && value.parse::<u64>().is_ok();
                        queue = true;
                        fresh
                    } else {
                        false
                    }
                });
                (ok && threads).then_some(())
            }
        }
        "types_hash_max_size"
        | "types_hash_bucket_size"
        | "server_names_hash_max_size"
        | "server_names_hash_bucket_size"
        | "variables_hash_max_size"
        | "variables_hash_bucket_size" => one(positive_integer),
        "open_file_cache" => {
            if node.args.as_slice() == ["off"] {
                Some(())
            } else {
                let mut maximum = false;
                let mut inactive = false;
                let ok = !node.args.is_empty()
                    && node.args.len() <= 2
                    && node.args.iter().all(|arg| {
                        if let Some(value) = arg.strip_prefix("max=") {
                            let fresh = !maximum && positive_integer(value);
                            maximum = true;
                            fresh
                        } else if let Some(value) = arg.strip_prefix("inactive=") {
                            let fresh = !inactive && nginx_time_syntax(value);
                            inactive = true;
                            fresh
                        } else {
                            false
                        }
                    });
                (ok && maximum).then_some(())
            }
        }
        "proxy_buffers" | "fastcgi_buffers" => (node.args.len() == 2
            && positive_integer(&node.args[0])
            && nginx_size_syntax(&node.args[1]))
        .then_some(()),
        "proxy_buffer_size" | "proxy_busy_buffers_size" | "fastcgi_buffer_size" => {
            one(nginx_size_syntax)
        }
        "zone" => (matches!(node.args.len(), 1 | 2)
            && valid_symbol(&node.args[0])
            && node
                .args
                .get(1)
                .is_none_or(|value| nginx_size_syntax(value)))
        .then_some(()),
        "fastcgi_split_path_info" => (node.args.len() == 1).then_some(()),
        _ => None,
    };
    valid.ok_or_else(|| {
        format!(
            "invalid syntax for normalized operational directive '{}'",
            node.name
        )
    })
}

/// Audited classification for every directive deliberately normalized rather
/// than represented in the common policy IR. Callers still enforce nginx's
/// source contexts; this table makes it impossible to silently add a no-op
/// without documenting which httpd-rs subsystem owns the effect.
fn operational_noop_rationale(name: &str) -> Option<&'static str> {
    match name {
        "worker_processes"
        | "worker_cpu_affinity"
        | "worker_priority"
        | "worker_rlimit_nofile"
        | "daemon"
        | "master_process"
        | "timer_resolution"
        | "worker_shutdown_timeout" => {
            Some("process topology and shutdown are controlled by the httpd-rs service/runtime")
        }
        "pcre_jit" => Some("the bounded PCRE2 wrapper owns compilation and JIT policy"),
        "thread_pool" => Some("blocking work uses the bounded httpd-rs worker pools"),
        "worker_connections" | "multi_accept" | "use" | "accept_mutex" | "accept_mutex_delay" => {
            Some("connection admission and event-loop scheduling use httpd-rs resource budgets")
        }
        "tcp_nopush" | "tcp_nodelay" => {
            Some("socket write policy is selected by the httpd-rs protocol adapters")
        }
        "types_hash_max_size"
        | "types_hash_bucket_size"
        | "server_names_hash_max_size"
        | "server_names_hash_bucket_size"
        | "variables_hash_max_size"
        | "variables_hash_bucket_size" => {
            Some("compiled maps have explicit entry/byte caps and implementation-owned indexes")
        }
        "open_file_cache"
        | "open_file_cache_errors"
        | "open_file_cache_min_uses"
        | "open_file_cache_valid" => {
            Some("stable filesystem opens and metadata caching are owned by the file subsystem")
        }
        "reset_timedout_connection" => {
            Some("protocol cancellation closes timed-out connections without nginx linger policy")
        }
        "proxy_buffering"
        | "proxy_buffers"
        | "proxy_buffer_size"
        | "proxy_busy_buffers_size"
        | "proxy_request_buffering"
        | "fastcgi_buffering"
        | "fastcgi_buffers"
        | "fastcgi_buffer_size" => {
            Some("streaming, resident memory and spill thresholds use typed httpd-rs leases")
        }
        "keepalive" | "keepalive_requests" | "keepalive_timeout" | "zone" => {
            Some("backend pool lifetime and shared balancer state are bounded by httpd-rs")
        }
        "gzip_vary" => Some("httpd-rs always emits the cache-safety Vary field when required"),
        "proxy_connect_timeout"
        | "proxy_read_timeout"
        | "proxy_send_timeout"
        | "fastcgi_connect_timeout"
        | "fastcgi_read_timeout"
        | "fastcgi_send_timeout"
        | "client_body_timeout"
        | "client_header_timeout"
        | "send_timeout" => Some("dependency and client I/O use bounded cancellation deadlines"),
        "fastcgi_split_path_info" => {
            Some("the stable-path resolver derives the conventional PHP split without regex replay")
        }
        _ => None,
    }
}

#[cfg(feature = "fuzzing")]
pub fn fuzz_nginx_frontend(data: &[u8]) {
    if data.len() > 1024 * 1024 {
        return;
    }
    // Raw bytes exercise the lexer, parser and fail-closed rejection surface.
    // A second, structured projection keeps the semantic compiler and route
    // machine reachable even after libFuzzer mutates delimiters in the raw
    // configuration.  The selector grammar is deliberately byte-oriented so
    // every input, including non-UTF-8 input, reaches a valid nginx program.
    if let Ok(text) = std::str::from_utf8(data) {
        fuzz_nginx_text(text, data, "raw-nginx.conf");
    }
    let structured = structured_nginx_config(data);
    fuzz_nginx_text(&structured, structured.as_bytes(), "structured-nginx.conf");
}

/// Exercise the filesystem/include topology which a flat byte target cannot
/// represent: lexical glob ordering, empty globs, duplicate inclusion,
/// cycles, final symlinks and a replacement between generations.
#[cfg(feature = "fuzzing")]
pub fn fuzz_nginx_include_tree(data: &[u8]) {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let root = ROOT.get_or_init(|| {
        let root = std::env::temp_dir().join(format!(
            "httpd-rs-nginx-include-fuzz-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join("conf.d")).expect("create include fuzz conf.d");
        std::fs::create_dir_all(root.join("nested")).expect("create include fuzz nested");
        root
    });
    let byte = |index: usize| data.get(index).copied().unwrap_or(index as u8);
    let main = root.join("nginx.conf");
    let first = root.join("conf.d/10-default.conf");
    let second = root.join("conf.d/20-wildcard.conf");
    let nested = root.join("nested/10-route.conf");
    let cycle_a = root.join("cycle-a.conf");
    let cycle_b = root.join("cycle-b.conf");
    let symlink = root.join("conf.d/30-symlink.conf");
    let _ = std::fs::remove_file(&symlink);

    let extra = if byte(0) & 1 == 0 {
        "include empty/*.conf;"
    } else {
        ""
    };
    std::fs::create_dir_all(root.join("empty")).expect("create empty include directory");
    std::fs::write(
        &main,
        format!("events {{ worker_connections 64; }}\nhttp {{ include conf.d/*.conf; {extra} }}\n"),
    )
    .expect("write include fuzz main");
    let nested_include = if byte(1) & 1 == 0 {
        "include nested/*.conf;"
    } else {
        "include nested/10-route.conf;"
    };
    std::fs::write(
        &first,
        format!(
            "server {{ listen 127.0.0.1:18080 default_server; server_name default.test; root /tmp; {nested_include} }}\n"
        ),
    )
    .expect("write default include");
    std::fs::write(
        &second,
        "server { listen 127.0.0.1:18080; server_name *.example.test api.*; root /tmp; location / { add_header X-Route wildcard always; } }\n",
    )
    .expect("write wildcard include");
    let nested_text = if byte(2) & 1 == 0 {
        "location ^~ /assets/ { add_header X-Route assets always; }\n"
    } else {
        "location ~ '[.]php$' { add_header X-Route php always; }\n"
    };
    std::fs::write(&nested, nested_text).expect("write nested include");
    std::fs::write(&cycle_a, "include cycle-b.conf;\n").expect("write include cycle a");
    std::fs::write(&cycle_b, "include cycle-a.conf;\n").expect("write include cycle b");
    if byte(3) & 1 != 0 {
        std::fs::write(&nested, "include cycle-a.conf;\n").expect("activate include cycle");
    }
    if byte(4) & 1 != 0 {
        std::os::unix::fs::symlink(&second, &symlink).expect("create include fuzz symlink");
    }

    let empty = HashMap::new();
    let loaded = crate::config::Config::load_format(
        crate::config_ir::ConfigFormat::Nginx,
        &main,
        root,
        &empty,
        &empty,
        false,
    );
    if let Ok(config) = loaded {
        config.route_program.assert_nginx_refinement(
            &["/", "/assets/x.php", "/other.php"],
            &["default.test", "www.example.test", "api.invalid"],
        );
        if byte(5) & 1 != 0 {
            let replacement = root.join("nested/.replacement.conf");
            std::fs::write(
                &replacement,
                "location = /replacement { add_header X-Reload replacement always; }\n",
            )
            .expect("write include replacement");
            std::fs::rename(&replacement, &nested).expect("replace included configuration");
            let _ = crate::config::Config::load_for_reload_format(
                crate::config_ir::ConfigFormat::Nginx,
                &main,
                root,
                &empty,
                &empty,
                false,
                &config,
                httpd_rs_os::effective_uid(),
            );
        }
    }
}

#[cfg(feature = "fuzzing")]
fn fuzz_nginx_text(text: &str, bytes: &[u8], name: &str) {
    if let Ok(nodes) = Parser::new(text, Path::new(name)).parse() {
        let has_include = nodes_contain_include(&nodes);
        let first = lower(nodes.clone(), Path::new("/tmp/httpd-rs-nginx-default/html"));
        let second = lower(nodes, Path::new("/tmp/httpd-rs-nginx-default/html"));
        assert_eq!(
            format!("{first:?}"),
            format!("{second:?}"),
            "nginx lowering is not deterministic"
        );
        if !has_include {
            use std::collections::HashMap;
            use std::sync::OnceLock;
            static ROOT: OnceLock<PathBuf> = OnceLock::new();
            let root = ROOT.get_or_init(|| {
                let root = std::env::temp_dir()
                    .join(format!("httpd-rs-nginx-fuzz-{}", std::process::id()));
                std::fs::create_dir_all(&root).expect("create nginx fuzz root");
                root
            });
            let path = root.join(name);
            std::fs::write(&path, bytes).expect("write nginx fuzz configuration");
            if let Ok(config) = crate::config::Config::load_format(
                crate::config_ir::ConfigFormat::Nginx,
                &path,
                root,
                &HashMap::new(),
                &HashMap::new(),
                false,
            ) {
                let request_paths = [
                    "/",
                    "/exact",
                    "/assets/item.txt",
                    "/assets/item.php",
                    "/api/item",
                    "/script.php",
                    "/missing/deep/path",
                ];
                let request_hosts = [
                    "fuzz.example",
                    "api.fuzz.example:18080",
                    "www.deep.fuzz.example",
                    "api.invalid",
                    "unmatched.invalid",
                ];
                config
                    .route_program
                    .assert_nginx_refinement(&request_paths, &request_hosts);
                for request_path in request_paths {
                    for request_host in request_hosts {
                        let first_vhost = config
                            .select_vhost(None, 18080, Some(request_host))
                            .and_then(|vhost| config.vhost_position(vhost));
                        let second_vhost = config
                            .select_vhost(None, 18080, Some(request_host))
                            .and_then(|vhost| config.vhost_position(vhost));
                        assert_eq!(first_vhost, second_vhost);
                        if let Some(vhost) = config.select_vhost(None, 18080, Some(request_host)) {
                            let scope = config.base_scope_with_route(Some(vhost), request_path);
                            assert!(scope.header_policy.within_limits());
                            let route_matches = crate::proxy::matches_route(&scope, request_path);
                            let selected =
                                crate::proxy::match_target(&config, &scope, request_path);
                            assert_eq!(
                                route_matches,
                                selected.is_some(),
                                "a compiled nginx proxy route has no valid backend"
                            );
                            if let Some(target) = selected {
                                assert!(target.logical_url.is_some());
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(feature = "fuzzing")]
fn structured_nginx_config(data: &[u8]) -> String {
    fn byte(data: &[u8], index: usize) -> u8 {
        data.get(index).copied().unwrap_or(index as u8)
    }
    fn pick<'a>(data: &[u8], index: usize, values: &'a [&'a str]) -> &'a str {
        values[byte(data, index) as usize % values.len()]
    }

    let server_name = pick(data, 0, &["fuzz.example", "*.fuzz.example", "api.*", "_"]);
    let body_limit = pick(data, 1, &["0", "1", "1k", "64k", "1m", "1g"]);
    let expiry = pick(data, 2, &["off", "0", "30s", "10m", "1h", "modified 1d"]);
    let compression = pick(data, 3, &["off", "on"]);
    let parent_header = pick(data, 4, &["parent", "root", "fixed"]);
    let proxy_value = pick(
        data,
        5,
        &[
            "$host",
            "$http_host",
            "$request_uri",
            "$proxy_add_x_forwarded_for",
            "literal-$scheme-$server_port",
            "$http_x_fuzz",
        ],
    );
    let try_files = pick(
        data,
        6,
        &[
            "$uri =404",
            "$uri $uri/ =404",
            "$uri /index.html",
            "$uri $uri/ /index.html?$args",
        ],
    );
    let error_code = pick(data, 7, &["400", "403", "404", "500", "502"]);
    let upstream = if byte(data, 8) & 1 == 0 {
        "http://127.0.0.1:19001"
    } else {
        "http://app/base/"
    };
    let mut locations = String::new();
    let count = 3 + usize::from(byte(data, 9) % 8);
    for index in 0..count {
        let selector = byte(data, 10 + index * 2) % 8;
        let action = byte(data, 11 + index * 2) % 8;
        let (modifier, path, regex) = match selector {
            0 => ("= ", "/exact", false),
            1 => ("^~ ", "/assets/", false),
            2 => ("", "/api/", false),
            3 => ("~ ", "[.]php$", true),
            4 => ("~* ", "[.]JPEG$", true),
            5 => ("", "/nested/deep/", false),
            6 => ("", "/missing/", false),
            _ => ("", "/", false),
        };
        let body = match action {
            0 => format!("add_header X-Fuzz child-{index} always;"),
            1 if !regex => format!("try_files {try_files};"),
            2 if !regex => format!("alias /tmp/httpd-rs-nginx-alias-{index}/;"),
            3 => format!(
                "proxy_set_header X-Fuzz {proxy_value}; proxy_pass {upstream};"
            ),
            4 => "fastcgi_param SCRIPT_FILENAME $request_filename; fastcgi_param REQUEST_URI $request_uri; fastcgi_pass 127.0.0.1:19002;".into(),
            5 => format!("client_max_body_size {body_limit};"),
            6 => format!("expires {expiry};"),
            _ => format!("error_page {error_code} /index.html;"),
        };
        locations.push_str(&format!("location {modifier}{path} {{ {body} }}\n"));
    }

    format!(
        "user nobody nogroup;\n\
         events {{ worker_connections 64; }}\n\
         http {{\n\
           httpd_rs_capability FastCgi On;\n\
           httpd_rs_capability UnstableFastCgiPaths On;\n\
           client_max_body_size {body_limit};\n\
           add_header X-Parent {parent_header} always;\n\
           gzip {compression};\n\
           upstream app {{ server 127.0.0.1:19001; server 127.0.0.1:19003; }}\n\
           server {{\n\
             listen 127.0.0.1:18080 default_server;\n\
             server_name {server_name};\n\
             root /tmp;\n\
             index index.html index.htm;\n\
             error_page {error_code} /index.html;\n\
             {locations}\
           }}\n\
         }}\n"
    )
}

#[cfg(feature = "fuzzing")]
fn nodes_contain_include(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| {
        node.name == "include" || node.children.as_deref().is_some_and(nodes_contain_include)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "httpd-rs-nginx-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn lexer_and_parser_preserve_quoted_transform_values() {
        let parsed = Parser::new(
            "http { server { location / { proxy_set_header X-Test '$scheme:$host'; } } }",
            Path::new("nginx.conf"),
        )
        .parse()
        .unwrap();
        let location = &parsed[0].children.as_ref().unwrap()[0]
            .children
            .as_ref()
            .unwrap()[0];
        assert_eq!(
            location.children.as_ref().unwrap()[0].args,
            ["X-Test", "$scheme:$host"]
        );
    }

    #[test]
    fn verified_lexer_and_parser_fail_closed_at_their_bounds() {
        for text in ["http { x 'unterminated; }", "http { x trailing\\"] {
            assert!(Parser::new(text, Path::new("nginx.conf")).parse().is_err());
        }

        let mut nested = String::new();
        for _ in 0..=MAX_BLOCK_DEPTH {
            nested.push_str("block {");
        }
        assert!(Parser::new(&nested, Path::new("nginx.conf"))
            .parse()
            .unwrap_err()
            .message
            .contains("nesting is too deep"));

        let arguments = (0..=MAX_ARGS)
            .map(|index| format!("arg{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        let wide = format!("directive {arguments};");
        assert!(Parser::new(&wide, Path::new("nginx.conf"))
            .parse()
            .unwrap_err()
            .message
            .contains("too many"));
    }

    #[test]
    fn lowering_emitter_accepts_only_the_verified_vocabulary_and_arity() {
        let node = Node {
            name: "test".into(),
            args: Vec::new(),
            children: None,
            loc: SourceLoc {
                file: "nginx.conf".into(),
                line: 1,
            },
        };
        let mut lowerer = Lowerer {
            events: Vec::new(),
            routes: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
            listeners: HashSet::new(),
            upstreams: HashSet::new(),
        };
        lowerer.directive(&node, "RawUnsealedDirective", Vec::new());
        lowerer.directive(
            &node,
            "HttpdRsNginxResponseSemantics",
            vec!["unexpected".into()],
        );
        lowerer.directive(&node, "HttpdRsNginxResponseSemantics", Vec::new());
        assert_eq!(lowerer.errors.len(), 2);
        assert_eq!(lowerer.events.len(), 1);

        let protocols = Node {
            name: "ssl_protocols".into(),
            args: vec!["TLSv1.2".into(), "TLSv1.3".into()],
            children: None,
            loc: node.loc.clone(),
        };
        lowerer.lower_ssl_protocols(&protocols);
        assert_eq!(lowerer.errors.len(), 2);
        assert!(matches!(
            lowerer.events.last(),
            Some(Event::Directive { name, args, .. })
                if name == "sslprotocol" && args == &["-all", "+TLSv1.2", "+TLSv1.3"]
        ));
    }

    #[test]
    fn control_bytes_and_unusable_upstreams_fail_configuration_loading() {
        let control = Parser::new(
            "events { worker_connections 64; }\nhttp { upstream app { server 127.0.\u{1f}.0.1:9000; } }",
            Path::new("nginx.conf"),
        )
        .parse()
        .unwrap_err();
        assert!(control.message.contains("control byte"));

        for text in [
            "events { worker_connections 64; } http { upstream app {} }",
            "events { worker_connections 64; } http { upstream app { server bad@host; } }",
        ] {
            let nodes = Parser::new(text, Path::new("nginx.conf")).parse().unwrap();
            let errors = lower(nodes, Path::new("/tmp/httpd-rs-nginx-default/html")).unwrap_err();
            assert!(errors
                .iter()
                .any(|error| error.message.contains("at least one valid server")));
        }
    }

    #[test]
    fn listen_aliases_are_canonical_before_server_identity_checks() {
        assert_eq!(canonical_nginx_listen_address("18085").unwrap(), "*:18085");
        assert_eq!(
            canonical_nginx_listen_address("0.0.0.0:18085").unwrap(),
            "*:18085"
        );
        assert_eq!(
            canonical_nginx_listen_address("*:18085").unwrap(),
            "*:18085"
        );
        assert_eq!(
            canonical_nginx_listen_address("[::]:18085").unwrap(),
            "[::]:18085"
        );
        assert_eq!(
            canonical_nginx_listen_address("127.0.0.1").unwrap(),
            "127.0.0.1:80"
        );
        assert!(canonical_nginx_listen_address("backend.example:18085").is_err());

        let dir = tempdir("canonical-listener");
        let config = dir.join("nginx.conf");
        std::fs::write(
            &config,
            "events { worker_connections 64; }\n\
             http { server { listen 18085 default_server; server_name wildcard.test; } }\n",
        )
        .unwrap();
        let empty = std::collections::HashMap::new();
        let cfg = crate::config::Config::load_format(
            crate::config_ir::ConfigFormat::Nginx,
            &config,
            &dir,
            &empty,
            &empty,
            false,
        )
        .unwrap();
        assert_eq!(
            cfg.select_vhost(
                Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                18085,
                Some("wildcard.test"),
            )
            .and_then(|vhost| vhost.server_name.as_deref()),
            Some("wildcard.test")
        );

        std::fs::write(
            &config,
            "events { worker_connections 64; }\n\
             http {\n\
               server { listen 18085 default_server; server_name one.test; }\n\
               server { listen 0.0.0.0:18085 default_server; server_name two.test; }\n\
             }\n",
        )
        .unwrap();
        let errors = crate::config::Config::load_format(
            crate::config_ir::ConfigFormat::Nginx,
            &config,
            &dir,
            &empty,
            &empty,
            false,
        )
        .unwrap_err();
        assert!(errors
            .iter()
            .any(|error| error.msg.contains("more than one default_server")));

        std::fs::write(
            &config,
            "events { worker_connections 64; }\n\
             http { server { server_name implicit.test; } }\n",
        )
        .unwrap();
        let implicit = crate::config::Config::load_format(
            crate::config_ir::ConfigFormat::Nginx,
            &config,
            &dir,
            &empty,
            &empty,
            false,
        )
        .unwrap();
        assert_eq!(
            implicit
                .select_vhost(
                    Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                    80,
                    Some("implicit.test"),
                )
                .and_then(|vhost| vhost.server_name.as_deref()),
            Some("implicit.test"),
            "an omitted listen directive must share explicit listen 80 routing semantics"
        );

        std::fs::write(
            &config,
            "events { worker_connections 64; }\n\
             http {\n\
               server { listen 18086; server_name ipv4.test; }\n\
               server { listen [::]:18086; server_name ipv6.test; }\n\
             }\n",
        )
        .unwrap();
        let errors = crate::config::Config::load_format(
            crate::config_ir::ConfigFormat::Nginx,
            &config,
            &dir,
            &empty,
            &empty,
            false,
        )
        .unwrap_err();
        assert!(errors.iter().any(|error| {
            error
                .msg
                .contains("requires identical dual-stack routing sets")
        }));

        std::fs::write(
            &config,
            "events { worker_connections 64; }\n\
             http {\n\
               server { listen 18087; listen [::]:18087; server_name dual.test; }\n\
             }\n",
        )
        .unwrap();
        crate::config::Config::load_format(
            crate::config_ir::ConfigFormat::Nginx,
            &config,
            &dir,
            &empty,
            &empty,
            false,
        )
        .expect("candidate-equivalent dual-stack listeners are deterministic");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn location_machine_is_explicit_and_closed() {
        let node = Node {
            name: "location".into(),
            args: vec!["^~".into(), "/assets/".into()],
            children: Some(Vec::new()),
            loc: SourceLoc {
                file: "x".into(),
                line: 1,
            },
        };
        assert!(matches!(
            parse_location(&node).unwrap().0,
            RouteMatcher::Prefix {
                suppress_regex: true,
                ..
            }
        ));
        let mut named = node.clone();
        named.args = vec!["@fallback".into()];
        assert!(parse_location(&named).is_err());

        let mut caseless = node;
        caseless.args = vec!["~*".into(), "^/Admin$".into()];
        let RouteMatcher::Regex { regex, .. } = parse_location(&caseless).unwrap().0 else {
            panic!("~* did not compile to a regex location");
        };
        assert!(regex.is_nginx_match("/admin"));
    }

    #[test]
    fn arbitrary_map_is_rejected() {
        let parsed = Parser::new(
            "http { map $x $y { default z; } server {} }",
            Path::new("x"),
        )
        .parse()
        .unwrap();
        let errors = lower(parsed, Path::new("/tmp/httpd-rs-nginx-default/html")).unwrap_err();
        assert!(errors
            .iter()
            .any(|error| error.message.contains("conventional finite")));
    }

    #[test]
    fn every_accepted_operational_noop_has_an_audited_owner() {
        let accepted = [
            "worker_processes",
            "worker_cpu_affinity",
            "worker_priority",
            "worker_rlimit_nofile",
            "daemon",
            "master_process",
            "pcre_jit",
            "thread_pool",
            "timer_resolution",
            "worker_shutdown_timeout",
            "worker_connections",
            "multi_accept",
            "use",
            "accept_mutex",
            "accept_mutex_delay",
            "tcp_nopush",
            "tcp_nodelay",
            "types_hash_max_size",
            "types_hash_bucket_size",
            "server_names_hash_max_size",
            "server_names_hash_bucket_size",
            "variables_hash_max_size",
            "variables_hash_bucket_size",
            "open_file_cache",
            "open_file_cache_errors",
            "open_file_cache_min_uses",
            "open_file_cache_valid",
            "reset_timedout_connection",
            "proxy_buffering",
            "proxy_buffers",
            "proxy_buffer_size",
            "proxy_busy_buffers_size",
            "proxy_request_buffering",
            "fastcgi_buffering",
            "fastcgi_buffers",
            "fastcgi_buffer_size",
            "keepalive",
            "keepalive_requests",
            "keepalive_timeout",
            "zone",
            "gzip_vary",
            "proxy_connect_timeout",
            "proxy_read_timeout",
            "proxy_send_timeout",
            "fastcgi_connect_timeout",
            "fastcgi_read_timeout",
            "fastcgi_send_timeout",
            "client_body_timeout",
            "client_header_timeout",
            "send_timeout",
            "fastcgi_split_path_info",
        ];
        for directive in accepted {
            assert!(
                operational_noop_rationale(directive).is_some(),
                "{directive} lacks an audited operational owner"
            );
        }
        assert!(operational_noop_rationale("env").is_none());
        assert!(operational_noop_rationale("load_module").is_none());
        assert!(operational_noop_rationale("ssl_session_cache").is_none());
    }

    #[test]
    fn normalized_operational_directives_have_a_closed_syntax() {
        let samples: &[(&str, &[&str])] = &[
            ("worker_processes", &["auto"]),
            ("worker_cpu_affinity", &["auto", "0101"]),
            ("worker_priority", &["-5"]),
            ("worker_rlimit_nofile", &["65535"]),
            ("daemon", &["off"]),
            ("master_process", &["on"]),
            ("pcre_jit", &["on"]),
            ("thread_pool", &["default", "threads=32", "max_queue=65536"]),
            ("timer_resolution", &["100ms"]),
            ("worker_shutdown_timeout", &["10s"]),
            ("worker_connections", &["1024"]),
            ("multi_accept", &["off"]),
            ("use", &["epoll"]),
            ("accept_mutex", &["on"]),
            ("accept_mutex_delay", &["500ms"]),
            ("tcp_nopush", &["on"]),
            ("tcp_nodelay", &["on"]),
            ("types_hash_max_size", &["2048"]),
            ("types_hash_bucket_size", &["64"]),
            ("server_names_hash_max_size", &["512"]),
            ("server_names_hash_bucket_size", &["64"]),
            ("variables_hash_max_size", &["1024"]),
            ("variables_hash_bucket_size", &["64"]),
            ("open_file_cache", &["max=1000", "inactive=20s"]),
            ("open_file_cache_errors", &["on"]),
            ("open_file_cache_min_uses", &["2"]),
            ("open_file_cache_valid", &["30s"]),
            ("reset_timedout_connection", &["on"]),
            ("proxy_buffering", &["on"]),
            ("proxy_buffers", &["8", "16k"]),
            ("proxy_buffer_size", &["4k"]),
            ("proxy_busy_buffers_size", &["24k"]),
            ("proxy_request_buffering", &["off"]),
            ("fastcgi_buffering", &["on"]),
            ("fastcgi_buffers", &["8", "16k"]),
            ("fastcgi_buffer_size", &["4k"]),
            ("keepalive", &["32"]),
            ("keepalive_requests", &["1000"]),
            ("keepalive_timeout", &["60s"]),
            ("zone", &["backend", "64k"]),
            ("gzip_vary", &["on"]),
            ("proxy_connect_timeout", &["5s"]),
            ("proxy_read_timeout", &["60s"]),
            ("proxy_send_timeout", &["60s"]),
            ("fastcgi_connect_timeout", &["5s"]),
            ("fastcgi_read_timeout", &["60s"]),
            ("fastcgi_send_timeout", &["60s"]),
            ("client_body_timeout", &["60s"]),
            ("client_header_timeout", &["60s"]),
            ("send_timeout", &["60s"]),
            ("fastcgi_split_path_info", &["^(.+[.]php)(/.+)$"]),
        ];
        for (name, args) in samples {
            let node = Node {
                name: (*name).into(),
                args: args.iter().map(|value| (*value).into()).collect(),
                children: None,
                loc: SourceLoc {
                    file: "nginx.conf".into(),
                    line: 1,
                },
            };
            assert!(
                validate_operational_noop(&node).is_ok(),
                "valid {name} sample was rejected"
            );
            let mut over_wide = node.clone();
            over_wide.args.push("__invalid_extra__".into());
            assert!(
                validate_operational_noop(&over_wide).is_err(),
                "{name} accepted an unclassified extra argument"
            );
        }
    }

    #[test]
    fn process_and_tls_semantics_are_never_silently_ignored() {
        let parsed = Parser::new(
            "env SECRET; load_module modules/example.so; events { worker_connections 64; }\n\
             http { server { listen 127.0.0.1:18080 ssl; ssl_session_cache shared:TLS:1m; } }",
            Path::new("nginx.conf"),
        )
        .parse()
        .unwrap();
        let errors = lower(parsed, Path::new("/tmp/httpd-rs-nginx-default/html")).unwrap_err();
        assert!(errors
            .iter()
            .any(|error| error.message.contains("process or module")));
        assert!(errors
            .iter()
            .any(|error| error.message.contains("TLS security/session")));
    }

    #[test]
    fn empty_include_glob_matches_stock_nginx_semantics() {
        let dir = tempdir("empty-include");
        std::fs::create_dir_all(dir.join("conf.d")).unwrap();
        let config = dir.join("nginx.conf");
        std::fs::write(
            &config,
            "events { worker_connections 64; }\n\
             http { include conf.d/*.conf; server { listen 127.0.0.1:18080; } }\n",
        )
        .unwrap();
        let empty = std::collections::HashMap::new();
        assert!(crate::config::Config::load_format(
            crate::config_ir::ConfigFormat::Nginx,
            &config,
            &dir,
            &empty,
            &empty,
            false,
        )
        .is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn proxy_uri_projection_and_nginx_return_remain_typed() {
        let dir = tempdir("proxy-uri");
        let config = dir.join("nginx.conf");
        std::fs::write(
            &config,
            "events { worker_connections 64; }\n\
             http { server { listen 127.0.0.1:18081;\n\
               location /keep/ { proxy_pass http://127.0.0.1:9000; }\n\
               location /replace/ { proxy_pass http://127.0.0.1:9000/base/; }\n\
               location = /moved { return 301 https://example.test/final; }\n\
             } }\n",
        )
        .unwrap();
        let empty = std::collections::HashMap::new();
        let cfg = crate::config::Config::load_format(
            crate::config_ir::ConfigFormat::Nginx,
            &config,
            &dir,
            &empty,
            &empty,
            false,
        )
        .unwrap();
        assert_eq!(
            cfg.global.merge_source(),
            httpd_rs_verified::ConfigIrSource::Nginx
        );
        assert!(cfg.vhosts.iter().all(|vhost| vhost
            .scope
            .merge_refined_for(httpd_rs_verified::ConfigIrSource::Nginx)));
        let crate::config_ir::RouteProgram::Nginx { servers, .. } = &cfg.route_program else {
            panic!("nginx route program missing");
        };
        assert!(servers.iter().flatten().all(|route| route
            .policy
            .merge_refined_for(httpd_rs_verified::ConfigIrSource::Nginx)));
        assert_eq!(
            servers[0][0].policy.proxy_policy.proxy_passes[0].prefix,
            "/"
        );
        assert_eq!(
            servers[0][1].policy.proxy_policy.proxy_passes[0].prefix,
            "/replace/"
        );
        assert_eq!(
            servers[0][2].policy.mapping_policy.redirects[0].projection,
            crate::config::RedirectProjection::Exact
        );

        std::fs::write(
            &config,
            "events { worker_connections 64; }\n\
             http { server { listen 127.0.0.1:18081;\n\
               location ~ '[.]php$' { proxy_pass http://127.0.0.1:9000/base/; }\n\
             } }\n",
        )
        .unwrap();
        let errors = crate::config::Config::load_format(
            crate::config_ir::ConfigFormat::Nginx,
            &config,
            &dir,
            &empty,
            &empty,
            false,
        )
        .unwrap_err();
        assert!(errors
            .iter()
            .any(|error| error.msg.contains("regex location")));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn complete_frontend_compiles_to_one_location_winner() {
        let dir = tempdir("compile");
        let root = dir.join("www");
        let assets_root = dir.join("assets-root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&assets_root).unwrap();
        let config = dir.join("nginx.conf");
        std::fs::write(
            &config,
            format!(
                "events {{ worker_connections 64; }}\n\
                 http {{\n\
                   client_max_body_size 1m;\n\
                   server {{\n\
                     listen 127.0.0.1:8080;\n\
                     server_name example.test www.example.test;\n\
                     root {};\n\
                     index index.html;\n\
                     location = /exact {{ add_header X-Route exact; }}\n\
                     location ^~ /assets/ {{ root {}; }}\n\
                     location ~ '[.]php$' {{\n\
                       proxy_http_version 1.1;\n\
                       proxy_set_header Host $host;\n\
                       proxy_pass http://127.0.0.1:9000;\n\
                     }}\n\
                   }}\n\
                 }}\n",
                root.display(),
                assets_root.display()
            ),
        )
        .unwrap();
        let cfg = crate::config::Config::load_format(
            crate::config_ir::ConfigFormat::Nginx,
            &config,
            &dir,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
            false,
        )
        .unwrap_or_else(|errors| panic!("{errors:#?}"));
        assert_eq!(cfg.limit_request_body, 1024 * 1024);
        assert_eq!(cfg.vhosts.len(), 1);
        let routes = match &cfg.route_program {
            crate::config_ir::RouteProgram::Nginx { servers, .. } => &servers[0],
            crate::config_ir::RouteProgram::Apache => panic!("nginx route program missing"),
        };
        assert_eq!(routes.len(), 3);
        assert_eq!(
            crate::config_ir::select_nginx_route(routes, "/assets/x.php").and_then(|route| route
                .policy
                .content_policy
                .document_root
                .as_deref()),
            Some(assets_root.as_path())
        );
        let vhost = cfg.select_vhost(None, 8080, Some("example.test"));
        let (mapped_root, mapped_rel, _) =
            crate::server::map_path(&cfg, vhost, b"/assets/app.js").unwrap();
        assert_eq!(mapped_root, assets_root);
        assert_eq!(mapped_rel, PathBuf::from("assets/app.js"));
        assert!(crate::config_ir::select_nginx_route(routes, "/other.php")
            .unwrap()
            .policy
            .proxy_policy
            .request_headers
            .is_some());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn overlapping_apache_and_nginx_configs_emit_equivalent_policy() {
        let dir = tempdir("equivalence");
        let root = dir.join("www");
        std::fs::create_dir_all(root.join("assets")).unwrap();
        let apache_path = dir.join("apache.conf");
        let nginx_path = dir.join("nginx.conf");
        std::fs::write(
            &apache_path,
            format!(
                "Listen 127.0.0.1:8081\n\
                 <VirtualHost 127.0.0.1:8081>\n\
                 ServerName equivalent.test\n\
                 DocumentRoot {}\n\
                 DirectoryIndex index.html index.htm\n\
                 <Location /assets/>\n\
                 Header add X-Route assets\n\
                 </Location>\n\
                 </VirtualHost>\n",
                root.display()
            ),
        )
        .unwrap();
        std::fs::write(
            &nginx_path,
            format!(
                "events {{ worker_connections 64; }}\n\
                 http {{ server {{\n\
                   listen 127.0.0.1:8081;\n\
                   server_name equivalent.test;\n\
                   root {};\n\
                   index index.html index.htm;\n\
                   location /assets/ {{ add_header X-Route assets; }}\n\
                 }} }}\n",
                root.display()
            ),
        )
        .unwrap();
        let empty = std::collections::HashMap::new();
        let apache =
            crate::config::Config::load(&apache_path, &dir, &empty, &empty, false).unwrap();
        let nginx = crate::config::Config::load_format(
            crate::config_ir::ConfigFormat::Nginx,
            &nginx_path,
            &dir,
            &empty,
            &empty,
            false,
        )
        .unwrap();
        let apache_vhost = apache.select_vhost(None, 8081, Some("equivalent.test"));
        let nginx_vhost = nginx.select_vhost(None, 8081, Some("equivalent.test"));
        let fs_path = root.join("assets/app.js");
        let apache_scope = apache.effective_scope(apache_vhost, &fs_path, "/assets/app.js");
        let nginx_scope = nginx.effective_scope(nginx_vhost, &fs_path, "/assets/app.js");
        assert_eq!(
            apache_scope.content_policy.document_root,
            nginx_scope.content_policy.document_root
        );
        assert_eq!(
            apache_scope.content_policy.directory_index,
            nginx_scope.content_policy.directory_index
        );
        assert_eq!(
            apache_scope.header_policy.add_headers,
            nginx_scope.header_policy.add_headers
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn explicit_default_and_nginx_wildcard_precedence_survive_lowering() {
        let dir = tempdir("server-selection");
        let config = dir.join("nginx.conf");
        std::fs::write(
            &config,
            "events { worker_connections 64; }\n\
             http {\n\
               server { listen 127.0.0.1:18082; server_name first.test *.example.test; }\n\
               server { listen 127.0.0.1:18082 default_server; server_name default.test; }\n\
               server { listen 127.0.0.1:18082; server_name *.deep.example.test; }\n\
             }\n",
        )
        .unwrap();
        let empty = std::collections::HashMap::new();
        let cfg = crate::config::Config::load_format(
            crate::config_ir::ConfigFormat::Nginx,
            &config,
            &dir,
            &empty,
            &empty,
            false,
        )
        .unwrap();
        assert_eq!(
            cfg.select_vhost(None, 18082, Some("unknown.test"))
                .and_then(|vhost| vhost.server_name.as_deref()),
            Some("default.test")
        );
        assert_eq!(
            cfg.select_vhost(None, 18082, Some("first.test"))
                .and_then(|vhost| vhost.server_name.as_deref()),
            Some("first.test")
        );
        assert_eq!(
            cfg.select_vhost(None, 18082, Some("www.deep.example.test"))
                .and_then(|vhost| vhost.server_name.as_deref()),
            Some("*.deep.example.test")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn nginx_specific_policy_compiles_into_route_deltas() {
        let dir = tempdir("nginx-policy");
        let root = dir.join("www");
        let assets = dir.join("assets");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&assets).unwrap();
        let config = dir.join("nginx.conf");
        std::fs::write(
            &config,
            format!(
                "events {{ worker_connections 64; }}\n\
                 http {{\n\
                   add_header X-Http inherited;\n\
                   server {{\n\
                     listen 127.0.0.1:18083;\n\
                     root {};\n\
                     client_max_body_size 8k;\n\
                     add_header X-Server server;\n\
                     error_page 404 /error.html;\n\
                     location /assets/ {{\n\
                       alias {}/;\n\
                       client_max_body_size 1k;\n\
                       add_header X-Location location always;\n\
                       expires 1h;\n\
                       try_files $uri $uri/ /index.php?$args;\n\
                     }}\n\
                   }}\n\
                 }}\n",
                root.display(),
                assets.display(),
            ),
        )
        .unwrap();
        let empty = std::collections::HashMap::new();
        let cfg = crate::config::Config::load_format(
            crate::config_ir::ConfigFormat::Nginx,
            &config,
            &dir,
            &empty,
            &empty,
            false,
        )
        .unwrap_or_else(|errors| panic!("{errors:#?}"));
        let vhost = cfg.select_vhost(None, 18083, None).unwrap();
        assert_eq!(vhost.scope.content_policy.request_body_limit, Some(8192));
        assert_eq!(
            vhost.scope.header_policy.add_headers,
            vec![("X-Server".into(), "server".into())]
        );
        assert!(matches!(
            vhost.scope.error_document(404),
            Some(crate::config::ErrorDoc::Local(target)) if target == "/error.html"
        ));
        let scope = cfg.base_scope_with_route(Some(vhost), "/assets/site.css");
        assert_eq!(scope.content_policy.request_body_limit, Some(1024));
        assert!(scope.header_policy.add_headers.is_empty());
        assert_eq!(
            scope.header_policy.always_add_headers,
            vec![("X-Location".into(), "location".into())]
        );
        assert_eq!(scope.header_policy.expires_active, Some(true));
        assert_eq!(
            scope.header_policy.expires_default.as_deref(),
            Some("access plus 3600 seconds")
        );
        assert_eq!(scope.mapping_policy.aliases[0].fs_path, assets);
        assert!(scope
            .rewrite_policy
            .rewrite_rules
            .iter()
            .any(|rule| rule.filesystem_context && rule.substitution == "/index.php"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn nginx_defaults_and_zero_body_limit_survive_the_shared_compiler() {
        let dir = tempdir("nginx-defaults");
        let config = dir.join("nginx.conf");
        std::fs::write(
            &config,
            "events { worker_connections 64; }\n\
             http {\n\
               server {\n\
                 listen 127.0.0.1:18084;\n\
                 location /unlimited/ { client_max_body_size 0; }\n\
               }\n\
             }\n",
        )
        .unwrap();
        let empty = std::collections::HashMap::new();
        let cfg = crate::config::Config::load_format(
            crate::config_ir::ConfigFormat::Nginx,
            &config,
            &dir,
            &empty,
            &empty,
            false,
        )
        .unwrap_or_else(|errors| panic!("{errors:#?}"));
        assert_eq!(cfg.document_root, dir.join("html"));
        assert_eq!(cfg.limit_request_body, 1024 * 1024);
        assert_eq!(cfg.keep_alive_timeout, std::time::Duration::from_secs(75));
        assert_eq!(cfg.max_keep_alive_requests, 1000);
        let vhost = cfg.select_vhost(None, 18084, None).unwrap();
        assert_eq!(
            cfg.route_request_body_limit(Some(vhost), "/ordinary"),
            1024 * 1024
        );
        assert_eq!(
            cfg.route_request_body_limit(Some(vhost), "/unlimited/body"),
            u64::MAX
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn named_upstream_uri_projection_is_retained() {
        let dir = tempdir("upstream-uri");
        let config = dir.join("nginx.conf");
        std::fs::write(
            &config,
            "events { worker_connections 64; }\n\
             http {\n\
               upstream app { server 127.0.0.1:19001; }\n\
               server {\n\
                 listen 127.0.0.1:18084;\n\
                 location /api/ { proxy_pass http://app/base/; }\n\
               }\n\
             }\n",
        )
        .unwrap();
        let empty = std::collections::HashMap::new();
        let cfg = crate::config::Config::load_format(
            crate::config_ir::ConfigFormat::Nginx,
            &config,
            &dir,
            &empty,
            &empty,
            false,
        )
        .unwrap_or_else(|errors| panic!("{errors:#?}"));
        let vhost = cfg.select_vhost(None, 18084, None).unwrap();
        let scope = cfg.base_scope_with_route(Some(vhost), "/api/item");
        assert_eq!(
            scope.proxy_policy.proxy_passes[0].backend,
            "balancer://app/base/"
        );
        let target = crate::proxy::match_target(&cfg, &scope, "/api/item").unwrap();
        assert_eq!(target.proxy_url, "http://127.0.0.1:19001/base/item");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
