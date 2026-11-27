//! Bounded, fail-closed nginx configuration frontend.
//!
//! This frontend accepts a deliberately finite HTTP subset and lowers it to
//! the same typed compiler input used by the Apache frontend. Unknown or
//! semantically wider directives are errors; operational tuning directives
//! whose effect is intentionally owned by httpd-rs are accepted only through
//! an explicit no-op table.

use crate::config::{Event, SourceLoc};
use crate::config_ir::RouteMatcher;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_INCLUDE_DEPTH: usize = 32;
const MAX_INCLUDES: usize = 10_000;
const MAX_NODES: usize = 65_536;
const MAX_ARGS: usize = 128;
const MAX_TOKEN_BYTES: usize = 16 * 1024;

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
        admin_inputs: Vec::new(),
        errors: Vec::new(),
    };
    let nodes = loader.load_file(path, 0).unwrap_or_default();
    if !loader.errors.is_empty() {
        return Err(loader.errors);
    }
    match lower(nodes) {
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
        for entry in entries.flatten() {
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
        let nodes = self.parse_block(false)?;
        if self.position != self.tokens.len() {
            return Err(self.error(0, "trailing nginx parser state"));
        }
        Ok(nodes)
    }

    fn parse_block(&mut self, nested: bool) -> Result<Vec<Node>, NginxError> {
        let mut nodes = Vec::new();
        loop {
            let Some(token) = self.tokens.get(self.position).cloned() else {
                return if nested {
                    Err(self.error(0, "unclosed nginx configuration block"))
                } else {
                    Ok(nodes)
                };
            };
            if token.kind == TokenKind::Close {
                if !nested {
                    return Err(self.error(token.line, "unexpected '}'"));
                }
                self.position += 1;
                return Ok(nodes);
            }
            let TokenKind::Word(name) = token.kind else {
                return Err(self.error(token.line, "expected nginx directive name"));
            };
            self.position += 1;
            let mut args = Vec::new();
            loop {
                let Some(next) = self.tokens.get(self.position).cloned() else {
                    return Err(self.error(token.line, "unterminated nginx directive"));
                };
                match next.kind {
                    TokenKind::Word(value) => {
                        if args.len() >= MAX_ARGS {
                            return Err(self.error(next.line, "too many nginx directive arguments"));
                        }
                        args.push(value);
                        self.position += 1;
                    }
                    TokenKind::Semi => {
                        self.position += 1;
                        nodes.push(Node {
                            name: name.to_ascii_lowercase(),
                            args,
                            children: None,
                            loc: SourceLoc {
                                file: self.file.clone(),
                                line: token.line,
                            },
                        });
                        break;
                    }
                    TokenKind::Open => {
                        self.position += 1;
                        let children = self.parse_block(true)?;
                        nodes.push(Node {
                            name: name.to_ascii_lowercase(),
                            args,
                            children: Some(children),
                            loc: SourceLoc {
                                file: self.file.clone(),
                                line: token.line,
                            },
                        });
                        break;
                    }
                    TokenKind::Close => {
                        return Err(self.error(next.line, "directive is missing ';' or '{'"));
                    }
                }
            }
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
                let mut quote = None;
                let mut token_started = false;
                while index < bytes.len() {
                    let byte = bytes[index];
                    if let Some(delimiter) = quote {
                        if byte == delimiter {
                            quote = None;
                            index += 1;
                        } else if byte == b'\\' {
                            index += 1;
                            let Some(escaped) = bytes.get(index).copied() else {
                                return Err(NginxError {
                                    file: file.into(),
                                    line,
                                    message: "trailing escape in quoted nginx token".into(),
                                });
                            };
                            word.push(escaped);
                            index += 1;
                        } else {
                            if byte == b'\n' {
                                line += 1;
                            }
                            word.push(byte);
                            index += 1;
                        }
                    } else if matches!(byte, b'\'' | b'"') {
                        token_started = true;
                        quote = Some(byte);
                        index += 1;
                    } else if byte == b'\\' {
                        token_started = true;
                        index += 1;
                        let Some(escaped) = bytes.get(index).copied() else {
                            return Err(NginxError {
                                file: file.into(),
                                line,
                                message: "trailing escape in nginx token".into(),
                            });
                        };
                        word.push(escaped);
                        index += 1;
                    } else if byte.is_ascii_whitespace()
                        || matches!(byte, b';' | b'{' | b'}' | b'#')
                    {
                        break;
                    } else {
                        token_started = true;
                        word.push(byte);
                        index += 1;
                    }
                    if word.len() > MAX_TOKEN_BYTES {
                        return Err(NginxError {
                            file: file.into(),
                            line: start_line,
                            message: format!("nginx token exceeds {MAX_TOKEN_BYTES} bytes"),
                        });
                    }
                }
                if quote.is_some() {
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

fn lower(nodes: Vec<Node>) -> Result<LoweredNginx, Vec<NginxError>> {
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
        self.events.push(Event::Directive {
            name: name.to_ascii_lowercase(),
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
        if node.children.is_some() || node.args.is_empty() {
            self.error(
                node,
                format!(
                    "invalid operational directive '{}'; expected arguments and ';'",
                    node.name
                ),
            );
        } else if self.warnings.len() < 500 {
            self.warnings.push(format!(
                "{} line {}: nginx operational directive '{}' is validated but owned by httpd-rs",
                node.loc.file, node.loc.line, node.name
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
        self.validate_add_header_inheritance(node);
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
        for server in &servers {
            let mut default = false;
            let mut ordinary = false;
            for listen in server_listen_specs(server) {
                match listen {
                    Ok(listen) => {
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
                            self.directive(server, "Listen", vec![listen.address]);
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
        }
        servers.sort_by_key(|server| {
            !server_listen_specs(server)
                .filter_map(Result::ok)
                .any(|listen| listen.default_server)
        });
        for server in servers {
            self.lower_server(server);
        }
    }

    fn validate_add_header_inheritance(&mut self, http: &Node) {
        let children = http.children.as_deref().unwrap_or_default();
        let http_has = children.iter().any(|node| node.name == "add_header");
        for server in children.iter().filter(|node| node.name == "server") {
            let server_children = server.children.as_deref().unwrap_or_default();
            let server_has = server_children.iter().any(|node| node.name == "add_header");
            if http_has && server_has {
                self.error(
                    server,
                    "add_header at both http and server scope has nginx replacement semantics not yet represented by the shared IR",
                );
            }
            for location in server_children
                .iter()
                .filter(|node| node.name == "location")
            {
                let location_has = location
                    .children
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .any(|node| node.name == "add_header");
                if location_has && (http_has || server_has) {
                    self.error(
                        location,
                        "add_header at an inherited and location scope has nginx replacement semantics not yet represented by the shared IR",
                    );
                }
            }
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
        for child in node.children.as_deref().unwrap_or_default() {
            match child.name.as_str() {
                "server" if child.children.is_none() && child.args.len() == 1 => {
                    let backend = normalize_upstream_backend(&child.args[0]);
                    self.directive(child, "BalancerMember", vec![backend]);
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

    fn lower_server(&mut self, node: &Node) {
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
                name if server_operational_noop(name) => self.noop(child),
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
            self.lower_location(location, &mut route_matchers);
        }
        self.events.push(Event::SectionEnd {
            loc: node.loc.clone(),
        });
        self.routes.push(route_matchers);
    }

    fn lower_location(&mut self, node: &Node, routes: &mut Vec<RouteMatcher>) {
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
        routes.push(matcher);
        self.events.push(Event::SectionStart {
            name: section.to_ascii_lowercase(),
            args: vec![path.clone()],
            loc: node.loc.clone(),
            active: true,
            transparent: false,
        });
        for child in children {
            match child.name.as_str() {
                "access_log" => self.lower_access_log(child),
                "error_log" => self.lower_error_log(child),
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
            "keepalive_timeout" if context == Context::Http => {
                if let Some(value) = node.args.first() { self.directive(node, "KeepAliveTimeout", vec![nginx_time_seconds(value)]); }
                else { self.error(node, "keepalive_timeout requires a value"); }
            }
            "keepalive_requests" if context == Context::Http => self.simple(node, "MaxKeepAliveRequests", 1, 1),
            "client_max_body_size" if context == Context::Http => match node.args.as_slice() {
                [value] => match nginx_size(value) {
                    Ok(value) => self.directive(node, "LimitRequestBody", vec![value.to_string()]),
                    Err(message) => self.error(node, message),
                },
                _ => self.error(node, "client_max_body_size requires one value"),
            },
            "client_max_body_size" => self.error(
                node,
                "scoped client_max_body_size is not supported because request-body admission currently precedes route selection",
            ),
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
            "proxy_http_version" => {
                if node.args.as_slice() != ["1.1"] { self.error(node, "only proxy_http_version 1.1 is supported"); }
            }
            "proxy_set_header" => self.simple(node, "HttpdRsProxySetHeader", 2, 2),
            "proxy_pass" if context == Context::Location => {
                self.lower_proxy_pass(node, route, route_is_regex)
            }
            "proxy_pass" => self.error(node, "proxy_pass is only valid in a location block"),
            "fastcgi_pass" if context == Context::Location => self.lower_fastcgi_pass(node),
            "fastcgi_pass" => self.error(node, "fastcgi_pass is only valid in a location block"),
            "fastcgi_param" => self.simple(node, "HttpdRsFastCgiParam", 2, 3),
            "add_header" => self.lower_add_header(node),
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
                if node.args.as_slice() != ["$uri", "$uri/", "=404"] && node.args.as_slice() != ["$uri", "=404"] {
                    self.error(node, "only bounded static try_files '$uri $uri/ =404' is supported");
                }
            }
            "try_files" => self.error(node, "try_files is only valid in server or location context"),
            "return" if context != Context::Http => self.lower_return(node),
            "return" => self.error(node, "return is only valid in server or location context"),
            "allow" | "deny" => self.error(node, "nginx ordered allow/deny rules require an explicit ACL compiler and are not silently approximated"),
            "error_page" => self.error(node, "nginx error_page URI projection is not yet in the source-neutral terminal-outcome IR"),
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

    fn lower_proxy_pass(&mut self, node: &Node, route: &str, route_is_regex: bool) {
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
        let Some((authority, has_uri)) = proxy_pass_authority_and_uri(&backend) else {
            self.error(
                node,
                "proxy_pass backend must be http:// or https:// with a literal authority",
            );
            return;
        };
        if self.upstreams.contains(authority) {
            if has_uri {
                self.error(
                    node,
                    "a URI suffix on a named upstream is not yet represented by the bounded balancer IR",
                );
                return;
            }
            backend = format!("balancer://{authority}");
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
        if backend.starts_with("http://") || backend.starts_with("https://") {
            self.directive(
                node,
                "HttpdRsRouteProxyPassReverse",
                vec![route.into(), backend],
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
        args.extend(["set".into(), node.args[0].clone(), node.args[1].clone()]);
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
            let regex = crate::apache_regex::Regex::compile(value, modifier == "~*")
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
    let (address, options) = if is_option(&node.args[0]) {
        ("80".to_string(), node.args.as_slice())
    } else {
        (node.args[0].clone(), &node.args[1..])
    };
    if address.contains('$') || address.is_empty() {
        return Err("listen address must be a non-empty literal".into());
    }
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
            address: "80".into(),
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

fn proxy_pass_authority_and_uri(value: &str) -> Option<(&str, bool)> {
    let rest = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))?;
    let (authority, has_uri) = match rest.split_once('/') {
        Some((authority, _)) => (authority, true),
        None => (rest, false),
    };
    (!authority.is_empty()).then_some((authority, has_uri))
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

fn nginx_time_seconds(value: &str) -> String {
    value
        .strip_suffix('s')
        .unwrap_or(value)
        .split('.')
        .next()
        .unwrap_or(value)
        .to_string()
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
            | "env"
            | "pcre_jit"
            | "thread_pool"
            | "timer_resolution"
            | "worker_shutdown_timeout"
            | "load_module"
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

fn server_operational_noop(name: &str) -> bool {
    matches!(
        name,
        "ssl_session_cache"
            | "ssl_session_timeout"
            | "ssl_session_tickets"
            | "ssl_prefer_server_ciphers"
            | "ssl_stapling"
            | "ssl_stapling_verify"
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

#[cfg(feature = "fuzzing")]
pub fn fuzz_nginx_frontend(data: &[u8]) {
    if data.len() > 1024 * 1024 {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(nodes) = Parser::new(text, Path::new("fuzz-nginx.conf")).parse() {
        let has_include = nodes_contain_include(&nodes);
        let _ = lower(nodes);
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
            let path = root.join("nginx.conf");
            std::fs::write(&path, data).expect("write nginx fuzz configuration");
            let _ = crate::config::Config::load_format(
                crate::config_ir::ConfigFormat::Nginx,
                &path,
                root,
                &HashMap::new(),
                &HashMap::new(),
                false,
            );
        }
    }
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
    }

    #[test]
    fn arbitrary_map_is_rejected() {
        let parsed = Parser::new(
            "http { map $x $y { default z; } server {} }",
            Path::new("x"),
        )
        .parse()
        .unwrap();
        let errors = lower(parsed).unwrap_err();
        assert!(errors
            .iter()
            .any(|error| error.message.contains("conventional finite")));
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
        let crate::config_ir::RouteProgram::Nginx { servers, .. } = &cfg.route_program else {
            panic!("nginx route program missing");
        };
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
                 Header set X-Route assets\n\
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
            apache_scope.header_policy.set_headers,
            nginx_scope.header_policy.set_headers
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
}
