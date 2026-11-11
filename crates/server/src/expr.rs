//! Apache `ap_expr` subset used by `Require expr` and `<If>`.
//!
//! The parser is intentionally independent of the HTTP server; the evaluator
//! receives a small context with the request, environment, peer address and
//! filesystem root.  Unsupported syntax is a parse error (config fails closed).

use crate::http::Request;
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// Request-time expression evaluation must not turn `file()` into an
/// unbounded heap read or a blocking read from a FIFO/device in a writable
/// document tree.
const MAX_EXPR_FILE_BYTES: u64 = 64 * 1024;
const MAX_EXPR_REGEX_BYTES: u64 = 64 * 1024;
const MAX_EXPR_SOURCE_BYTES: usize = 64 * 1024;
const MAX_EXPR_VALUE_BYTES: usize = 1024 * 1024;
const MAX_EXPR_EVAL_BYTES: usize = 4 * 1024 * 1024;

/// A PCRE2-compatible expression compiled while the configuration is parsed.
/// The in-tree engine accepts the regular PCRE2 subset used by Apache guards
/// (including `\Q...\E`, `\Z`, `\K` and comments) and rejects constructs such
/// as backreferences whose semantics require recursive backtracking.
#[derive(Clone)]
pub struct ExprRegex {
    pattern: String,
    nocase: bool,
    compiled: vapache_pcre2::bytes::Regex,
}

impl std::fmt::Debug for ExprRegex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExprRegex")
            .field("pattern", &self.pattern)
            .field("nocase", &self.nocase)
            .finish()
    }
}

impl ExprRegex {
    fn compile(pattern: String, nocase: bool) -> Result<Self, String> {
        // Keep the verified resource ceiling used by the other regex
        // surfaces. The compatibility parser performs its own structural
        // admission and fails closed on non-regular PCRE2 constructs.
        if pattern.len() > 65_536
            || pattern
                .as_bytes()
                .iter()
                .any(|byte| *byte < 0x20 || *byte == 0x7f)
        {
            return Err("bad expression regex: pattern is too large or contains controls".into());
        }
        let mut builder = vapache_pcre2::bytes::RegexBuilder::new();
        // The engine is non-backtracking and uses no executable-memory JIT.
        // Its deterministic pattern×subject work ceiling is checked on every
        // call in addition to the server-wide expensive-work budget.
        builder.caseless(nocase);
        let compiled = builder
            .build(&pattern)
            .map_err(|error| format!("bad expression regex: {error}"))?;
        Ok(Self {
            pattern,
            nocase,
            compiled,
        })
    }
}

#[derive(Debug, Clone)]
pub enum Expr {
    Bool(bool),
    Str(String),
    Int(i64),
    Var(String),
    Func(String, Vec<Expr>),
    Concat(Vec<Expr>),
    Not(Box<Expr>),
    Neg(Box<Expr>),
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Compare(Box<Expr>, String, Box<Expr>),
    Regex(Box<Expr>, ExprRegex, bool),
    In(Box<Expr>, Vec<Expr>),
    FileTest(String, Box<Expr>),
    /// `<IfFile path>` from the main configuration.  Unlike per-directory
    /// expression file tests this argument is an operator-supplied path and is
    /// not confined to DocumentRoot.
    IfFile(String),
    StrTest(Box<Expr>, bool),
    IpMatch(Box<Expr>, Box<Expr>, bool),
    StrMatch(Box<Expr>, Box<Expr>, bool, bool),
    Capture(usize),
}

#[derive(Debug, Clone)]
pub enum Value {
    Bool(bool),
    Int(i64),
    Str(String),
    Bytes(Vec<u8>),
    List(Vec<Value>),
}

impl Value {
    pub fn truthy(&self) -> bool {
        match self {
            Value::Bool(b) => {
                vapache_verified::expr_value_truthy(vapache_verified::ExprValueKind::Bool, *b, 0, 0)
            }
            Value::Int(i) => vapache_verified::expr_value_truthy(
                vapache_verified::ExprValueKind::Int,
                false,
                *i,
                0,
            ),
            Value::Str(s) => vapache_verified::expr_value_truthy(
                vapache_verified::ExprValueKind::Str,
                false,
                0,
                s.len() as u64,
            ),
            Value::Bytes(bytes) => vapache_verified::expr_value_truthy(
                vapache_verified::ExprValueKind::Str,
                false,
                0,
                bytes.len() as u64,
            ),
            Value::List(v) => vapache_verified::expr_value_truthy(
                vapache_verified::ExprValueKind::List,
                false,
                0,
                v.len() as u64,
            ),
        }
    }

    fn string(&self) -> String {
        match self {
            Value::Bool(b) => if *b { "true" } else { "false" }.into(),
            Value::Int(i) => i.to_string(),
            Value::Str(s) => s.clone(),
            Value::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            Value::List(v) => v.iter().map(Value::string).collect::<Vec<_>>().join(","),
        }
    }

    fn int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Str(s) => s.trim().parse().ok(),
            Value::Bytes(bytes) => std::str::from_utf8(bytes).ok()?.trim().parse().ok(),
            Value::Bool(b) => Some(if *b { 1 } else { 0 }),
            Value::List(_) => None,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        match self {
            Value::Bytes(bytes) => bytes.clone(),
            _ => self.string().into_bytes(),
        }
    }

    fn resident_len(&self) -> usize {
        match self {
            Value::Bool(_) | Value::Int(_) => std::mem::size_of::<Self>(),
            Value::Str(value) => value.len(),
            Value::Bytes(value) => value.len(),
            Value::List(values) => values.iter().fold(0usize, |total, value| {
                total.saturating_add(value.resident_len())
            }),
        }
    }
}

struct EvalBudget {
    remaining: usize,
}

impl EvalBudget {
    fn charge(&mut self, value: &Value) -> Result<(), String> {
        let bytes = value.resident_len();
        if bytes > MAX_EXPR_VALUE_BYTES || bytes > self.remaining {
            return Err("expression value budget exceeded".into());
        }
        self.remaining -= bytes;
        Ok(())
    }
}

thread_local! {
    /// The listener scheme/port for the request currently being dispatched.
    /// These are set by the connection layer, never derived from a client
    /// header such as `X-Forwarded-Proto`.
    static REQUEST_HTTPS: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    static REQUEST_PORT: std::cell::Cell<Option<u16>> = const { std::cell::Cell::new(None) };
    static REQUEST_SERVER_NAME: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

pub(crate) struct ServerNameGuard(Option<String>);

impl Drop for ServerNameGuard {
    fn drop(&mut self) {
        REQUEST_SERVER_NAME.with(|v| *v.borrow_mut() = self.0.take());
    }
}

/// Install the dispatcher-selected canonical name for expression evaluation.
/// The guard restores the previous value when the request finishes.
pub(crate) fn set_server_name(name: &str) -> ServerNameGuard {
    let previous = REQUEST_SERVER_NAME.with(|v| v.borrow_mut().replace(name.to_string()));
    ServerNameGuard(previous)
}

fn request_server_name() -> Option<String> {
    REQUEST_SERVER_NAME.with(|v| v.borrow().clone())
}

/// Run `f` with the real listener TLS state and port visible to expression
/// evaluation.
pub(crate) fn with_connection<T>(https: bool, port: u16, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<bool>, Option<u16>);
    impl Drop for Restore {
        fn drop(&mut self) {
            REQUEST_HTTPS.with(|v| v.set(self.0));
            REQUEST_PORT.with(|v| v.set(self.1));
        }
    }
    let previous = (
        REQUEST_HTTPS.with(|v| v.get()),
        REQUEST_PORT.with(|v| v.get()),
    );
    REQUEST_HTTPS.with(|v| v.set(Some(https)));
    REQUEST_PORT.with(|v| v.set(Some(port)));
    let _restore = Restore(previous.0, previous.1);
    f()
}

pub(crate) fn request_is_https() -> bool {
    REQUEST_HTTPS.with(|v| v.get()).unwrap_or(false)
}

fn request_port() -> u16 {
    REQUEST_PORT.with(|v| v.get()).unwrap_or(80)
}

pub struct Context<'a> {
    pub req: &'a Request,
    pub env: &'a [(String, Vec<u8>)],
    pub peer: IpAddr,
    pub docroot: &'a Path,
    /// The dispatcher-selected canonical URL path: percent-decoded,
    /// query-free and free of dot segments.  `%{REQUEST_URI}` must be bound to
    /// this value, never to `Request::target` (F57/I57).
    pub url_path: &'a str,
    /// The filesystem path mapped for the request, when one exists.
    /// `%{REQUEST_FILENAME}` and `%{SCRIPT_FILENAME}` evaluate against it
    /// (F63/I63); without a binding they fail closed instead of substituting
    /// an empty string that would make a guard silently pass or fail in the
    /// attacker's favor.
    pub fs_path: Option<&'a Path>,
    pub captures: Vec<Vec<u8>>,
}

impl<'a> Context<'a> {
    pub fn new(
        req: &'a Request,
        env: &'a [(String, Vec<u8>)],
        peer: IpAddr,
        docroot: &'a Path,
        url_path: &'a str,
    ) -> Self {
        // The constructor is the single place where expression evaluation
        // binds REQUEST_URI.  The runtime supplies the dispatcher's canonical
        // path; a raw target or query-bearing value is never accepted.
        debug_assert!(vapache_verified::request_uri_identity_admit(
            true, false, false
        ));
        Self {
            req,
            env,
            peer,
            docroot,
            url_path,
            fs_path: None,
            captures: Vec::new(),
        }
    }

    /// Bind the filesystem path backing the request.  Required for the
    /// `REQUEST_FILENAME`/`SCRIPT_FILENAME` variables (F63/I63).
    pub fn with_fs_path(mut self, fs_path: Option<&'a Path>) -> Self {
        self.fs_path = fs_path;
        self
    }
}

fn function_arg(ctx: &Context<'_>, arg: &str) -> Result<String, String> {
    let upper = arg.to_ascii_uppercase();
    let is_var = arg.contains("%{")
        || arg.starts_with("req:")
        || arg.starts_with("http:")
        || arg.starts_with("env:")
        || arg.starts_with("HTTP_")
        || matches!(
            upper.as_str(),
            "TIME"
                | "TIME_YEAR"
                | "TIME_MON"
                | "TIME_DAY"
                | "TIME_HOUR"
                | "TIME_MIN"
                | "TIME_SEC"
                | "REQUEST_METHOD"
                | "QUERY_STRING"
                | "REQUEST_URI"
                | "REQUEST_SCHEME"
                | "HTTPS"
                | "REMOTE_ADDR"
                | "SERVER_NAME"
                | "SERVER_PORT"
                | "DOCUMENT_ROOT"
                | "API_VERSION"
        );
    if is_var {
        if arg.contains("%{") {
            expand(arg, ctx)
        } else {
            Ok(var(ctx, arg)?.string())
        }
    } else {
        Ok(arg.to_string())
    }
}

fn var(ctx: &Context<'_>, name: &str) -> Result<Value, String> {
    if let Some((func, arg)) = name.split_once(':') {
        if matches!(
            func.to_ascii_lowercase().as_str(),
            "toupper" | "tolower" | "escape" | "unescape"
        ) {
            let value = function_arg(ctx, arg)?;
            return Ok(Value::Str(match func.to_ascii_lowercase().as_str() {
                "toupper" => value.to_ascii_uppercase(),
                "tolower" => value.to_ascii_lowercase(),
                "escape" => percent_encode(&value),
                _ => percent_decode(&value),
            }));
        }
    }
    let lower = name.to_ascii_lowercase();
    if let Some(header) = lower.strip_prefix("req:") {
        return Ok(Value::Bytes(
            ctx.req
                .header(header)
                .map(vapache_verified::guard_header_bytes)
                .unwrap_or_default(),
        ));
    }
    if let Some(header) = lower.strip_prefix("http:") {
        return Ok(Value::Bytes(
            ctx.req
                .header(header)
                .map(vapache_verified::guard_header_bytes)
                .unwrap_or_default(),
        ));
    }
    if let Some(env_name) = lower.strip_prefix("env:") {
        return Ok(Value::Bytes(
            ctx.env
                .iter()
                .rev()
                .find(|(k, _)| k.eq_ignore_ascii_case(env_name))
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
        ));
    }
    if let Some(header) = lower.strip_prefix("http_") {
        let header = header.replace('_', "-");
        return Ok(Value::Bytes(
            ctx.req
                .header(&header)
                .map(vapache_verified::guard_header_bytes)
                .unwrap_or_default(),
        ));
    }
    let now = crate::util::unix_now();
    let days = now.div_euclid(86_400);
    let sod = now.rem_euclid(86_400);
    let (year, month, day) = crate::util::civil_from_days(days);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    Ok(Value::Str(match lower.as_str() {
        "time" => format!("{year:04}{month:02}{day:02}{hh:02}{mm:02}{ss:02}"),
        "time_year" => format!("{year:04}"),
        "time_mon" => format!("{month:02}"),
        "time_day" => format!("{day:02}"),
        "time_hour" => format!("{hh:02}"),
        "time_min" => format!("{mm:02}"),
        "time_sec" => format!("{ss:02}"),
        "request_method" => ctx.req.method.clone(),
        // Raw request-target bytes may fail UTF-8; fail closed instead of
        // conflating distinct byte strings through the replacement character.
        "query_string" => String::from_utf8(ctx.req.query.clone())
            .map_err(|_| "QUERY_STRING is not valid UTF-8".to_string())?,
        "request_uri" => ctx.url_path.to_string(),
        "request_scheme" => if request_is_https() { "https" } else { "http" }.into(),
        // Never trust X-Forwarded-Proto here.  Forwarded headers are only a
        // separate, explicitly trusted-proxy input (mod_remoteip); they are
        // not evidence that the client connection itself used TLS.
        "https" => if request_is_https() { "on" } else { "off" }.into(),
        "remote_addr" => ctx.peer.to_string(),
        "server_name" => request_server_name().unwrap_or_else(|| {
            ctx.req
                .header_str("host")
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("")
                .to_string()
        }),
        "server_port" => request_port().to_string(),
        "document_root" => ctx.docroot.to_string_lossy().into_owned(),
        "api_version" => "20120211".into(),
        // F63/I63: the filesystem variables bind to the mapped filesystem
        // path.  Without a binding they fail closed: an unbound filesystem
        // variable must not read as the empty string (which would satisfy
        // `-z`-style guards or make comparisons vacuous in the attacker's
        // favor).
        "request_filename" => match ctx.fs_path {
            Some(p) => p.to_string_lossy().into_owned(),
            None => {
                return Err(format!(
                    "variable '%{{{name}}}' is not available in this context"
                ))
            }
        },
        "script_filename" => match ctx.fs_path {
            Some(p) => p.to_string_lossy().into_owned(),
            None => {
                return Err(format!(
                    "variable '%{{{name}}}' is not available in this context"
                ))
            }
        },
        _ => return Err(format!("unknown expression variable '%{{{name}}}'")),
    }))
}

/// Load-time validation of every variable reference inside an `ap_expr`
/// tree (F63/I63).  `Expr::Str` literals expand `%{...}` at evaluation time,
/// so string contents are scanned as well as `Var` nodes.  A variable the
/// evaluator does not implement is a configuration error: it must never
/// evaluate to an empty string, which could make a guard silently take
/// either direction.
pub fn validate_vars(expr: &Expr) -> Result<(), String> {
    fn var_reference_known(name: &str) -> Result<(), String> {
        if vapache_verified::expr_var_known(name.as_bytes()) {
            Ok(())
        } else {
            Err(format!("unknown expression variable '%{{{name}}}'"))
        }
    }

    /// The argument of a `%{func:arg}` transform is a variable reference when
    /// the evaluator would treat it as one (same rule as `function_arg`).
    fn is_var_reference(arg: &str) -> bool {
        arg.contains("%{")
            || arg.starts_with("req:")
            || arg.starts_with("http:")
            || arg.starts_with("env:")
            || arg.starts_with("HTTP_")
            || matches!(
                arg.to_ascii_uppercase().as_str(),
                "TIME"
                    | "TIME_YEAR"
                    | "TIME_MON"
                    | "TIME_DAY"
                    | "TIME_HOUR"
                    | "TIME_MIN"
                    | "TIME_SEC"
                    | "REQUEST_METHOD"
                    | "QUERY_STRING"
                    | "REQUEST_URI"
                    | "REQUEST_SCHEME"
                    | "HTTPS"
                    | "REMOTE_ADDR"
                    | "SERVER_NAME"
                    | "SERVER_PORT"
                    | "DOCUMENT_ROOT"
                    | "API_VERSION"
            )
    }

    fn scan_text(text: &str) -> Result<(), String> {
        let bytes = text.as_bytes();
        let mut i = 0;
        while i + 1 < bytes.len() {
            if bytes[i] == b'%' && bytes[i + 1] == b'{' {
                let mut depth = 1;
                let mut j = i + 2;
                while j < bytes.len() && depth > 0 {
                    if bytes[j] == b'{' {
                        depth += 1;
                    } else if bytes[j] == b'}' {
                        depth -= 1;
                    }
                    j += 1;
                }
                if depth != 0 {
                    return Err("unterminated %{...} expression".into());
                }
                let inner = &text[i + 2..j - 1];
                if let Some((func, arg)) = inner.split_once(':') {
                    if matches!(
                        func.to_ascii_lowercase().as_str(),
                        "toupper" | "tolower" | "escape" | "unescape"
                    ) {
                        // The argument is expanded recursively.
                        if arg.contains("%{") {
                            scan_text(arg)?;
                        } else if is_var_reference(arg) {
                            var_reference_known(arg)?;
                        }
                        i = j;
                        continue;
                    }
                }
                var_reference_known(inner)?;
                i = j;
            } else {
                i += 1;
            }
        }
        Ok(())
    }

    fn walk(expr: &Expr) -> Result<(), String> {
        match expr {
            Expr::Bool(_) | Expr::Int(_) | Expr::Capture(_) | Expr::IfFile(_) => Ok(()),
            Expr::Str(s) => scan_text(s),
            Expr::Var(v) => var_reference_known(v),
            Expr::Func(_, args) | Expr::Concat(args) | Expr::And(args) | Expr::Or(args) => {
                for arg in args {
                    walk(arg)?;
                }
                Ok(())
            }
            Expr::Not(e) | Expr::Neg(e) => walk(e),
            Expr::Compare(l, _, r) => {
                walk(l)?;
                walk(r)
            }
            Expr::Regex(l, _, _) => walk(l),
            Expr::In(l, list) => {
                walk(l)?;
                for item in list {
                    walk(item)?;
                }
                Ok(())
            }
            Expr::FileTest(_, e) => walk(e),
            Expr::StrTest(e, _) => walk(e),
            Expr::IpMatch(l, r, _) => {
                walk(l)?;
                walk(r)
            }
            Expr::StrMatch(l, r, _, _) => {
                walk(l)?;
                walk(r)
            }
        }
    }

    walk(expr)
}

fn append_expansion(out: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    if !vapache_verified::bounded_expansion_append_admit(
        out.len() as u64,
        value.len() as u64,
        MAX_EXPR_VALUE_BYTES as u64,
    ) {
        return Err("expression value exceeds 1 MiB".into());
    }
    out.extend_from_slice(value);
    Ok(())
}

fn expand_bytes(text: &str, ctx: &Context<'_>) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 1 < b.len() && b[i + 1] == b'{' {
            let mut depth = 1;
            let mut j = i + 2;
            while j < b.len() && depth > 0 {
                if b[j] == b'{' {
                    depth += 1;
                } else if b[j] == b'}' {
                    depth -= 1;
                }
                j += 1;
            }
            if depth != 0 {
                return Err("unterminated %{...} expression".into());
            }
            let inner = &text[i + 2..j - 1];
            if let Some((func, arg)) = inner.split_once(':').filter(|(func, _)| {
                matches!(
                    func.to_ascii_lowercase().as_str(),
                    "toupper" | "tolower" | "escape" | "unescape"
                )
            }) {
                let value = Value::Str(function_arg(ctx, arg)?);
                let expanded = match func.to_ascii_lowercase().as_str() {
                    "toupper" => value.string().to_ascii_uppercase(),
                    "tolower" => value.string().to_ascii_lowercase(),
                    "escape" => percent_encode(&value.string()),
                    "unescape" => percent_decode(&value.string()),
                    _ => return Err(format!("unknown expression function '{func}'")),
                };
                append_expansion(&mut out, expanded.as_bytes())?;
            } else {
                append_expansion(&mut out, &var(ctx, inner)?.bytes())?;
            }
            i = j;
        } else {
            append_expansion(&mut out, &b[i..i + 1])?;
            i += 1;
        }
    }
    Ok(out)
}

fn expand(text: &str, ctx: &Context<'_>) -> Result<String, String> {
    String::from_utf8(expand_bytes(text, ctx)?)
        .map_err(|_| "expanded expression value is not valid UTF-8".to_string())
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02x}"));
        }
    }
    out
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn glob(pattern: &str, value: &str, path_mode: bool) -> Result<bool, String> {
    crate::glob::expr_match(pattern.as_bytes(), value.as_bytes(), path_mode).map_err(str::to_string)
}

fn compare_op(op: &str) -> Option<vapache_verified::ExprCompareOp> {
    Some(match op {
        "=" | "==" | "-eq" => vapache_verified::ExprCompareOp::Eq,
        "!=" | "-ne" => vapache_verified::ExprCompareOp::Ne,
        "<" | "-lt" => vapache_verified::ExprCompareOp::Lt,
        "<=" | "-le" => vapache_verified::ExprCompareOp::Le,
        ">" | "-gt" => vapache_verified::ExprCompareOp::Gt,
        ">=" | "-ge" => vapache_verified::ExprCompareOp::Ge,
        _ => return None,
    })
}

fn cmp(left: &Value, op: &str, right: &Value) -> bool {
    let Some(kind) = compare_op(op) else {
        return false;
    };
    let numeric = matches!(op, "-eq" | "-ne" | "-lt" | "-le" | "-gt" | "-ge")
        && left.int().is_some()
        && right.int().is_some();
    if numeric {
        return vapache_verified::expr_compare_ints(
            kind,
            left.int().unwrap_or_default(),
            right.int().unwrap_or_default(),
        );
    }
    let a = left.bytes();
    let b = right.bytes();
    vapache_verified::expr_compare_strs(kind, &a, &b)
}

/// Resolve an expression file argument beneath the document root.  `.htaccess`
/// authors can use `Require expr`/`RewriteCond expr`; allowing absolute or
/// parent-relative paths there would let a local author read files with the
/// httpd user's privileges (CVE-2026-24072 / CVE-2026-44119). The result is
/// kept relative so the actual probe can consume it through the retained
/// mapping-root descriptor without a path re-walk after canonicalization.
fn confined_expr_relative(raw: &str) -> Option<PathBuf> {
    let path = Path::new(raw);
    let absolute = path.is_absolute();
    let parent_relative = path.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    });
    if !vapache_verified::expr_file_test_admit(absolute, parent_relative, true) {
        return None;
    }
    Some(path.to_path_buf())
}

fn read_expr_file(root: &Path, relative: &Path) -> Result<String, String> {
    let (file, metadata) =
        crate::files::open_read_beneath(root, relative).map_err(|error| error.to_string())?;
    if !vapache_verified::expr_file_read_admit(
        metadata.is_file(),
        metadata.len(),
        MAX_EXPR_FILE_BYTES,
    ) {
        return Err("expression file must be a regular file no larger than 64 KiB".into());
    }
    let data = read_expr_file_contents(&file, metadata.len() as usize)?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    if !vapache_verified::descriptor_snapshot_admit(
        metadata.is_file() && after.is_file(),
        metadata.dev() == after.dev() && metadata.ino() == after.ino(),
        metadata.len() == after.len()
            && data.len() as u64 == metadata.len()
            && metadata.mtime() == after.mtime()
            && metadata.mtime_nsec() == after.mtime_nsec()
            && metadata.ctime() == after.ctime()
            && metadata.ctime_nsec() == after.ctime_nsec()
            && metadata.mode() == after.mode(),
        data.len() as u64 <= MAX_EXPR_FILE_BYTES,
    ) {
        return Err("expression file changed while it was being read".into());
    }
    Ok(data)
}

fn read_expr_file_contents(reader: impl Read, initial_len: usize) -> Result<String, String> {
    let mut data = Vec::with_capacity(initial_len.min(MAX_EXPR_FILE_BYTES as usize));
    reader
        .take(MAX_EXPR_FILE_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|error| error.to_string())?;
    if data.len() as u64 > MAX_EXPR_FILE_BYTES {
        return Err("expression file grew beyond 64 KiB while being read".into());
    }
    String::from_utf8(data).map_err(|_| "expression file is not valid UTF-8".into())
}

impl Expr {
    pub fn eval(&self, ctx: &mut Context<'_>) -> Result<Value, String> {
        let mut budget = EvalBudget {
            remaining: MAX_EXPR_EVAL_BYTES,
        };
        self.eval_budgeted(ctx, &mut budget)
    }

    fn eval_budgeted(
        &self,
        ctx: &mut Context<'_>,
        budget: &mut EvalBudget,
    ) -> Result<Value, String> {
        let value = match self {
            Expr::Bool(b) => Value::Bool(*b),
            Expr::Str(s) => Value::Bytes(expand_bytes(s, ctx)?),
            Expr::Int(i) => Value::Int(*i),
            Expr::Var(v) => var(ctx, v)?,
            Expr::Capture(i) => Value::Bytes(ctx.captures.get(*i).cloned().unwrap_or_default()),
            Expr::Concat(parts) => {
                let mut out = Vec::new();
                for part in parts {
                    let bytes = part.eval_budgeted(ctx, budget)?.bytes();
                    append_expansion(&mut out, &bytes)?;
                }
                Value::Bytes(out)
            }
            Expr::Not(e) => Value::Bool(!e.eval_budgeted(ctx, budget)?.truthy()),
            Expr::Neg(e) => Value::Int(
                -e.eval_budgeted(ctx, budget)?
                    .int()
                    .ok_or("unary - needs a number")?,
            ),
            Expr::And(es) => {
                for e in es {
                    if !e.eval_budgeted(ctx, budget)?.truthy() {
                        return Ok(Value::Bool(false));
                    }
                }
                Value::Bool(true)
            }
            Expr::Or(es) => {
                for e in es {
                    if e.eval_budgeted(ctx, budget)?.truthy() {
                        return Ok(Value::Bool(true));
                    }
                }
                Value::Bool(false)
            }
            Expr::Compare(l, op, r) => Value::Bool(cmp(
                &l.eval_budgeted(ctx, budget)?,
                op,
                &r.eval_budgeted(ctx, budget)?,
            )),
            Expr::Regex(l, regex, negate) => {
                let text = l.eval_budgeted(ctx, budget)?.bytes();
                if !vapache_verified::expr_regex_size_admit(
                    regex.pattern.len() as u64,
                    text.len() as u64,
                    MAX_EXPR_REGEX_BYTES,
                ) {
                    return Err("expression regex input is too large".into());
                }
                let regex_work = (regex.pattern.len() as u64 + 1)
                    .checked_mul(text.len() as u64 + 1)
                    .ok_or("expression regex work overflow")?;
                ctx.req
                    .charge_policy_work(regex_work)
                    .map_err(str::to_string)?;
                let _expensive = crate::resource::try_expensive()
                    .ok_or("expression regex capacity exhausted")?;
                let (caps, eval_error) = match regex.compiled.captures(&text) {
                    Ok(captures) => (captures, None),
                    Err(error) => (None, Some(error.to_string())),
                };
                let matched = caps.is_some();
                let result =
                    vapache_verified::expr_regex_result(eval_error.is_none(), matched, *negate)
                        .ok_or_else(|| {
                            format!(
                                "expression regex evaluation failed: {}",
                                eval_error.as_deref().unwrap_or("unknown regex error")
                            )
                        })?;
                ctx.captures = caps
                    .map(|c| {
                        (0..regex.compiled.captures_len())
                            .map(|i| c.get(i).map(|m| m.as_bytes().to_vec()).unwrap_or_default())
                            .collect()
                    })
                    .unwrap_or_default();
                Value::Bool(result)
            }
            Expr::In(l, list) => {
                let needle = l.eval_budgeted(ctx, budget)?.bytes();
                let mut found = false;
                for expression in list {
                    if expression.eval_budgeted(ctx, budget)?.bytes() == needle {
                        found = true;
                        break;
                    }
                }
                Value::Bool(found)
            }
            Expr::StrTest(e, nonempty) => {
                let s = e.eval_budgeted(ctx, budget)?.bytes();
                Value::Bool(if *nonempty {
                    !s.is_empty()
                } else {
                    s.is_empty()
                })
            }
            Expr::IfFile(path) => Value::Bool(
                crate::files::symlink_metadata_cached(std::path::Path::new(path)).is_ok(),
            ),
            Expr::FileTest(op, e) => {
                let raw = e.eval_budgeted(ctx, budget)?.string();
                // File tests are a metadata oracle too. Inspect only the
                // descriptor returned by the confined mapping-root walk; a
                // post-canonicalization pathname stat can race outside it.
                let meta = confined_expr_relative(&raw).and_then(|relative| {
                    crate::files::probe_beneath(ctx.docroot, &relative, false)
                        .ok()
                        .map(|(_, metadata)| metadata)
                });
                Value::Bool(match op.as_str() {
                    "-f" => meta.as_ref().is_some_and(|m| m.is_file()),
                    "-d" => meta.as_ref().is_some_and(|m| m.is_dir()),
                    "-e" | "-F" | "-U" => meta.is_some(),
                    "-s" => meta.as_ref().is_some_and(|m| m.is_file() && m.len() > 0),
                    "-R" => {
                        let spec = e.eval_budgeted(ctx, budget)?.string();
                        crate::config::parse_ip_net(&spec)
                            .map(|(net, bits)| crate::access::ip_in_net(ctx.peer, net, bits))
                            .unwrap_or(false)
                    }
                    _ => false,
                })
            }
            Expr::IpMatch(l, r, negate) => {
                let ip: IpAddr = l
                    .eval_budgeted(ctx, budget)?
                    .string()
                    .parse()
                    .map_err(|_| "bad IP expression")?;
                let spec = r.eval_budgeted(ctx, budget)?.string();
                let matched = crate::config::parse_ip_net(&spec)
                    .map(|(net, bits)| crate::access::ip_in_net(ip, net, bits))
                    .unwrap_or(false);
                Value::Bool(matched != *negate)
            }
            Expr::StrMatch(l, r, nocase, path_mode) => {
                let mut a = l.eval_budgeted(ctx, budget)?.string();
                let mut b = r.eval_budgeted(ctx, budget)?.string();
                if *nocase {
                    a = a.to_ascii_lowercase();
                    b = b.to_ascii_lowercase();
                }
                let glob_work = (a.len() as u64 + 1)
                    .checked_mul(b.len() as u64 + 1)
                    .ok_or("expression glob work overflow")?;
                ctx.req
                    .charge_policy_work(glob_work)
                    .map_err(str::to_string)?;
                Value::Bool(glob(&b, &a, *path_mode)?)
            }
            Expr::Func(name, args) => {
                let mut vals = Vec::with_capacity(args.len());
                for arg in args {
                    vals.push(arg.eval_budgeted(ctx, budget)?);
                }
                let arg = |i: usize| vals.get(i).map(Value::string).unwrap_or_default();
                match name.to_ascii_lowercase().as_str() {
                    "req" | "http" => Value::Bytes(
                        ctx.req
                            .header(&arg(0))
                            .map(vapache_verified::guard_header_bytes)
                            .unwrap_or_default(),
                    ),
                    "env" => Value::Bytes(
                        ctx.env
                            .iter()
                            .rev()
                            .find(|(k, _)| k.eq_ignore_ascii_case(&arg(0)))
                            .map(|(_, v)| v.clone())
                            .unwrap_or_default(),
                    ),
                    "file" => {
                        let relative = confined_expr_relative(&arg(0)).ok_or_else(|| {
                            "expression file path escapes DOCUMENT_ROOT".to_string()
                        })?;
                        Value::Str(read_expr_file(ctx.docroot, &relative)?)
                    }
                    "filesize" => {
                        let relative = confined_expr_relative(&arg(0)).ok_or_else(|| {
                            "expression file path escapes DOCUMENT_ROOT".to_string()
                        })?;
                        let size = crate::files::probe_beneath(ctx.docroot, &relative, false)
                            .ok()
                            .filter(|(_, metadata)| metadata.is_file())
                            .map(|(_, metadata)| metadata.len() as i64)
                            .unwrap_or(0);
                        Value::Int(size)
                    }
                    "toupper" => Value::Str(arg(0).to_ascii_uppercase()),
                    "tolower" => Value::Str(arg(0).to_ascii_lowercase()),
                    "escape" => Value::Str(percent_encode(&arg(0))),
                    "unescape" => Value::Str(percent_decode(&arg(0))),
                    "sha1" => Value::Str(sha1_hex(&arg(0))),
                    "md5" => Value::Str(md5_hex(&arg(0))),
                    "base64" => Value::Str(base64_encode(arg(0).as_bytes())),
                    "unbase64" => {
                        Value::Str(String::from_utf8_lossy(&base64_decode(&arg(0))).into_owned())
                    }
                    other => return Err(format!("unknown expression function '{other}'")),
                }
            }
        };
        let resident = value.resident_len() as u64;
        ctx.req
            .charge_policy_work(resident.saturating_add(1))
            .map_err(str::to_string)?;
        if matches!(&value, Value::Str(_) | Value::Bytes(_) | Value::List(_)) {
            ctx.req
                .charge_policy_expansion(resident)
                .map_err(str::to_string)?;
        }
        budget.charge(&value)?;
        Ok(value)
    }
}

fn sha1_hex(s: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn md5_hex(s: &str) -> String {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn base64_encode(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_default()
}

/// Cap on parser recursion depth (`!`, `-`, `(` nesting). `primary()` and
/// `unary()` recurse once per operator, so inputs nested deeper than this cap
/// return `Err` instead of overflowing the stack — the parser stays total.
/// `Expr::eval` needs no cap of its own because no expression tree deeper than
/// the cap can be parsed.
///
/// The value is calibrated against the parser's smallest execution stack: the
/// `primary → or → and → compare → concat → unary` descent chain costs several
/// hundred bytes to ~2 KiB per frame on 2 MiB default `std::thread` stacks
/// (request handlers spawn without `stack_size`), and a paren level costs
/// 8 such frames. 64 keeps the reachable worst case around 1 MiB with margin
/// while still accepting nesting far deeper than any real-world expression.
const MAX_EXPR_DEPTH: usize = 64;

struct Parser<'a> {
    input: &'a str,
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            pos: 0,
            depth: 0,
        }
    }

    fn skip(&mut self) {
        while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip();
        self.input.as_bytes().get(self.pos).copied()
    }

    fn take(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn word(&mut self) -> String {
        self.skip();
        let start = self.pos;
        while self.pos < self.input.len() {
            let b = self.input.as_bytes()[self.pos];
            if b.is_ascii_whitespace() || b"()[]{},.'\"=!<>&|".contains(&b) {
                break;
            }
            self.pos += 1;
        }
        self.input[start..self.pos].to_string()
    }

    fn string(&mut self) -> Result<String, String> {
        let quote = self.input.as_bytes()[self.pos];
        self.pos += 1;
        // Accumulate the original UTF-8 bytes instead of widening each byte
        // to a Unicode scalar. The latter turned `é` into `Ã©` and made an
        // escaped non-ASCII character particularly easy to corrupt.
        let mut out = Vec::new();
        while self.pos < self.input.len() {
            let b = self.input.as_bytes()[self.pos];
            self.pos += 1;
            if b == quote {
                return String::from_utf8(out)
                    .map_err(|_| "expression string is not valid UTF-8".to_string());
            }
            if b == b'\\' && self.pos < self.input.len() {
                let n = self.input.as_bytes()[self.pos];
                self.pos += 1;
                out.push(match n {
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    other => other,
                });
            } else {
                out.push(b);
            }
        }
        Err("unterminated expression string".into())
    }

    fn variable(&mut self) -> Result<Expr, String> {
        self.pos += 2; // %{
        let start = self.pos;
        let mut depth = 1;
        while self.pos < self.input.len() {
            match self.input.as_bytes()[self.pos] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        let name = self.input[start..self.pos].to_string();
                        self.pos += 1;
                        return Ok(Expr::Var(name));
                    }
                }
                _ => {}
            }
            self.pos += 1;
        }
        Err("unterminated %{...}".into())
    }

    fn regex(&mut self) -> Result<(String, bool), String> {
        let Some(delim) = self.input.as_bytes().get(self.pos).copied() else {
            return Err("expected a regex after =~".into());
        };
        // Apache rejects non-ASCII expression-regex delimiters. Besides
        // matching that behavior, this preserves the Parser invariant that
        // `pos` is always a UTF-8 character boundary. Treating a UTF-8 lead
        // byte as the delimiter used to stop on the lead byte of a later
        // character and made the next `input[pos..]` slice panic (P24-A).
        if !delim.is_ascii() {
            return Err("regex delimiter must be ASCII".into());
        }
        self.pos += 1;
        let mut out = Vec::new();
        while self.pos < self.input.len() {
            let b = self.input.as_bytes()[self.pos];
            self.pos += 1;
            if b == delim {
                let mut nocase = false;
                while self.pos < self.input.len()
                    && self.input.as_bytes()[self.pos].is_ascii_alphabetic()
                {
                    let modifier = self.input.as_bytes()[self.pos];
                    if modifier != b'i' {
                        return Err(format!(
                            "unsupported expression regex modifier '{}'",
                            modifier as char
                        ));
                    }
                    if nocase {
                        return Err("duplicate expression regex modifier 'i'".into());
                    }
                    nocase = true;
                    self.pos += 1;
                }
                let out = String::from_utf8(out)
                    .map_err(|_| "expression regex is not valid UTF-8".to_string())?;
                return Ok((out, nocase));
            }
            if b == b'\\' && self.pos < self.input.len() {
                out.push(b'\\');
                out.push(self.input.as_bytes()[self.pos]);
                self.pos += 1;
            } else {
                out.push(b);
            }
        }
        Err("unterminated expression regex".into())
    }

    fn primary(&mut self) -> Result<Expr, String> {
        self.depth += 1;
        if self.depth > MAX_EXPR_DEPTH {
            self.depth -= 1;
            return Err("expression exceeds maximum parse depth".into());
        }
        let r = self.primary_inner();
        self.depth -= 1;
        r
    }

    fn primary_inner(&mut self) -> Result<Expr, String> {
        self.skip();
        let Some(c) = self.peek() else {
            return Err("unexpected end of expression".into());
        };
        if c == b'(' {
            self.pos += 1;
            let e = self.or()?;
            if !self.take(b')') {
                return Err("missing ')'".into());
            }
            return Ok(e);
        }
        if c == b'\'' || c == b'"' {
            return Ok(Expr::Str(self.string()?));
        }
        if c == b'%' && self.input.as_bytes().get(self.pos + 1) == Some(&b'{') {
            return self.variable();
        }
        if c == b'$' {
            self.pos += 1;
            let start = self.pos;
            while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
            let idx = self.input[start..self.pos]
                .parse::<usize>()
                .map_err(|_| "bad capture".to_string())?;
            return Ok(Expr::Capture(idx));
        }
        if c == b'{' {
            self.pos += 1;
            let mut list = Vec::new();
            loop {
                self.skip();
                if self.take(b'}') {
                    break;
                }
                list.push(self.or()?);
                self.skip();
                if self.take(b',') {
                    continue;
                }
                if !self.take(b'}') {
                    return Err("expected ',' or '}' in list".into());
                }
                break;
            }
            return Ok(Expr::In(Box::new(Expr::Str(String::new())), list));
        }
        if c == b'-' {
            if let Some(rest) = self.input[self.pos..].strip_prefix("-in") {
                if rest.is_empty() || rest.starts_with(char::is_whitespace) {
                    self.pos += 3;
                    return Ok(Expr::Str("-in".into()));
                }
            }
            self.pos += 1;
            let start = self.pos;
            while self.pos < self.input.len()
                && self.input.as_bytes()[self.pos].is_ascii_alphabetic()
            {
                self.pos += 1;
            }
            let word = &self.input[start..self.pos];
            if !word.is_empty() {
                if matches!(word, "n" | "z" | "f" | "d" | "e" | "s" | "F" | "U" | "R") {
                    return Ok(Expr::Str(format!("-{word}")));
                }
            }
            return self.primary().map(|e| Expr::Neg(Box::new(e)));
        }
        if c.is_ascii_digit() {
            let start = self.pos;
            while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
            return Ok(Expr::Int(self.input[start..self.pos].parse().unwrap_or(0)));
        }
        let w = self.word();
        if w.is_empty() {
            return Err("expected expression".into());
        }
        if w.eq_ignore_ascii_case("true") {
            return Ok(Expr::Bool(true));
        }
        if w.eq_ignore_ascii_case("false") {
            return Ok(Expr::Bool(false));
        }
        if self.peek() == Some(b'(') {
            self.pos += 1;
            let mut args = Vec::new();
            loop {
                self.skip();
                if self.take(b')') {
                    break;
                }
                args.push(self.or()?);
                self.skip();
                if self.take(b',') {
                    continue;
                }
                if self.take(b')') {
                    break;
                }
                return Err("expected ',' or ')' in function".into());
            }
            return Ok(Expr::Func(w, args));
        }
        Err(format!("unknown expression token '{w}'"))
    }

    fn unary(&mut self) -> Result<Expr, String> {
        self.depth += 1;
        if self.depth > MAX_EXPR_DEPTH {
            self.depth -= 1;
            return Err("expression exceeds maximum parse depth".into());
        }
        let r = self.unary_inner();
        self.depth -= 1;
        r
    }

    fn unary_inner(&mut self) -> Result<Expr, String> {
        self.skip();
        if self.peek() == Some(b'!') && self.input.as_bytes().get(self.pos + 1) != Some(&b'=') {
            self.pos += 1;
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        if let Some(c) = self.peek() {
            if c == b'-' {
                let save = self.pos;
                self.pos += 1;
                let start = self.pos;
                while self.pos < self.input.len()
                    && self.input.as_bytes()[self.pos].is_ascii_alphabetic()
                {
                    self.pos += 1;
                }
                let op = &self.input[start..self.pos];
                if matches!(op, "f" | "d" | "e" | "s" | "F" | "U" | "R") {
                    return Ok(Expr::FileTest(format!("-{op}"), Box::new(self.primary()?)));
                }
                if op == "n" || op == "z" {
                    return Ok(Expr::StrTest(Box::new(self.primary()?), op == "n"));
                }
                self.pos = save;
            }
        }
        self.primary()
    }

    fn concat(&mut self) -> Result<Expr, String> {
        let mut parts = vec![self.unary()?];
        while self.peek() == Some(b'.') {
            self.pos += 1;
            parts.push(self.unary()?);
        }
        if parts.len() == 1 {
            Ok(parts.pop().unwrap())
        } else {
            Ok(Expr::Concat(parts))
        }
    }

    fn compare(&mut self) -> Result<Expr, String> {
        let left = self.concat()?;
        self.skip();
        let ops = [
            "==",
            "!=",
            "<=",
            ">=",
            "=~",
            "!~",
            "-eq",
            "-ne",
            "-lt",
            "-le",
            "-gt",
            "-ge",
            "-in",
            "-ipmatch",
            "-strmatch",
            "-strcmatch",
            "-fnmatch",
            "=",
            "<",
            ">",
        ];
        for op in ops {
            if self.input[self.pos..].starts_with(op) {
                self.pos += op.len();
                if op == "=~" || op == "!~" {
                    self.skip();
                    let (pat, nocase) = self.regex()?;
                    let regex = ExprRegex::compile(pat, nocase)?;
                    return Ok(Expr::Regex(Box::new(left), regex, op == "!~"));
                }
                if op == "-in" {
                    self.skip();
                    if !self.take(b'{') {
                        return Err("expected '{' after -in".into());
                    }
                    let mut list = Vec::new();
                    loop {
                        self.skip();
                        if self.take(b'}') {
                            break;
                        }
                        list.push(self.or()?);
                        if self.take(b',') {
                            continue;
                        }
                        if self.take(b'}') {
                            break;
                        }
                    }
                    return Ok(Expr::In(Box::new(left), list));
                }
                let right = self.concat()?;
                return Ok(match op {
                    "-ipmatch" => Expr::IpMatch(Box::new(left), Box::new(right), false),
                    "-strmatch" => Expr::StrMatch(Box::new(left), Box::new(right), false, false),
                    "-strcmatch" => Expr::StrMatch(Box::new(left), Box::new(right), true, false),
                    "-fnmatch" => Expr::StrMatch(Box::new(left), Box::new(right), false, true),
                    _ => Expr::Compare(Box::new(left), op.into(), Box::new(right)),
                });
            }
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut items = vec![self.compare()?];
        loop {
            self.skip();
            if self.input[self.pos..].starts_with("&&") {
                self.pos += 2;
                items.push(self.compare()?);
            } else {
                break;
            }
        }
        if items.len() == 1 {
            Ok(items.pop().unwrap())
        } else {
            Ok(Expr::And(items))
        }
    }

    fn or(&mut self) -> Result<Expr, String> {
        let mut items = vec![self.and()?];
        loop {
            self.skip();
            if self.input[self.pos..].starts_with("||") {
                self.pos += 2;
                items.push(self.and()?);
            } else {
                break;
            }
        }
        if items.len() == 1 {
            Ok(items.pop().unwrap())
        } else {
            Ok(Expr::Or(items))
        }
    }
}

pub fn parse(input: &str) -> Result<Expr, String> {
    if input.len() > MAX_EXPR_SOURCE_BYTES {
        return Err(format!(
            "expression source exceeds {MAX_EXPR_SOURCE_BYTES} bytes"
        ));
    }
    let mut p = Parser::new(input);
    let e = p.or()?;
    p.skip();
    if p.pos != input.len() {
        return Err(format!("trailing expression input '{}'", &input[p.pos..]));
    }
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Headers, Request, Version};

    fn req() -> Request {
        Request {
            method: "GET".into(),
            target: b"/x".to_vec(),
            raw_path: b"/x".to_vec(),
            query: Vec::new(),
            version: Version::Http11,
            headers: Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    fn eval(s: &str) -> bool {
        let e = parse(s).unwrap();
        let r = req();
        let docroot = Path::new("/tmp");
        let mut c = Context::new(&r, &[], "127.0.0.1".parse().unwrap(), docroot, "/x");
        e.eval(&mut c).unwrap().truthy()
    }

    #[test]
    fn expression_expansion_and_glob_work_are_bounded() {
        let mut r = req();
        r.headers.insert("x", vec![b'a'; 8_000]);
        r.headers.insert("x-p", vec![b'a'; 8_000]);
        let mut pattern = b"*a".repeat(4_000);
        pattern.push(b'b');
        r.headers.insert("x-v", pattern);
        let docroot = Path::new("/tmp");
        let mut c = Context::new(&r, &[], "127.0.0.1".parse().unwrap(), docroot, "/x");

        let repeated = format!("'{}'", "%{HTTP:X}".repeat(200));
        assert!(parse(&repeated).unwrap().eval(&mut c).is_err());
        assert!(parse("%{HTTP:X-P} -strmatch %{HTTP:X-V}")
            .unwrap()
            .eval(&mut c)
            .is_err());
        assert!(parse(&"x".repeat(MAX_EXPR_SOURCE_BYTES + 1)).is_err());
    }

    #[test]
    fn repeated_file_values_share_one_evaluation_budget() {
        let dir = std::env::temp_dir().join(format!("vapache-expr-budget-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("big"), vec![b'x'; MAX_EXPR_FILE_BYTES as usize]).unwrap();
        let expression = Expr::Concat(
            (0..100)
                .map(|_| Expr::Func("file".into(), vec![Expr::Str("big".into())]))
                .collect(),
        );
        let r = req();
        let mut c = Context::new(&r, &[], "127.0.0.1".parse().unwrap(), &dir, "/x");
        assert!(expression.eval(&mut c).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn value_and_file_growth_limits_fail_closed() {
        let list = Value::List(vec![Value::Str("abc".into()), Value::Bytes(vec![1, 2])]);
        assert_eq!(list.resident_len(), 5);
        let mut budget = EvalBudget { remaining: 4 };
        assert!(budget.charge(&list).is_err());

        let grew = std::io::Cursor::new(vec![b'x'; MAX_EXPR_FILE_BYTES as usize + 1]);
        assert!(read_expr_file_contents(grew, 8).is_err());
    }

    #[test]
    fn regex_subject_and_if_file_edges_are_bounded() {
        let r = req();
        let mut c = Context::new(
            &r,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
        );
        let expression = Expr::Regex(
            Box::new(Expr::Str("x".repeat(MAX_EXPR_REGEX_BYTES as usize + 1))),
            ExprRegex::compile("x".into(), false).unwrap(),
            false,
        );
        assert!(expression.eval(&mut c).is_err());

        let path =
            std::env::temp_dir().join(format!("vapache-expr-if-file-{}", std::process::id()));
        std::fs::write(&path, b"present").unwrap();
        let mut c = Context::new(
            &r,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
        );
        assert!(Expr::IfFile(path.to_string_lossy().into_owned())
            .eval(&mut c)
            .unwrap()
            .truthy());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn parser_cases_from_apache_suite() {
        let cases = [
            ("true", true),
            ("false", false),
            ("1 -eq 01", true),
            ("1 -ne 2", true),
            ("'aa' == 'aa'", true),
            ("'aa' < 'b'", true),
            ("'a' . 'b' . 'c' = 'abc'", true),
            ("'a1c' = 'a'. 1. 'c'", true),
            ("'a' -in { 'b', 'a' }", true),
            ("'abc' =~ /BC/i", true),
            ("'abc' =~ /(bc)/ && $1 == 'bc'", true),
            ("%{REQUEST_METHOD} == 'GET'", true),
            ("%{API_VERSION} -gt 20101001", true),
            ("toupper('abC12d') = 'ABC12D'", true),
            ("escape('?') = '%3f'", true),
            ("%{toupper:%{escape:?}} = '%3F'", true),
            ("-n '1'", true),
            ("-z ''", true),
            ("-R '127.0.0.1'", true),
            ("'127.0.0.1' -ipmatch '127.0.0.0/8'", true),
            ("'foo' -strmatch 'f*'", true),
            ("'a/b' -fnmatch 'a/*'", true),
            ("true && !false", true),
            ("false || true", true),
        ];
        for (expr, expected) in cases {
            assert_eq!(eval(expr), expected, "{expr}");
        }
    }

    #[test]
    fn query_string_variable_uses_the_current_request_query() {
        let mut r = req();
        r.query = b"a=1".to_vec();
        let e = parse("%{QUERY_STRING} == 'a=1'").unwrap();
        let docroot = Path::new("/tmp");
        let mut c = Context::new(&r, &[], "127.0.0.1".parse().unwrap(), docroot, "/x");
        assert!(e.eval(&mut c).unwrap().truthy());
    }

    #[test]
    fn query_string_variable_fails_closed_on_invalid_utf8() {
        // Raw request-target bytes may fail UTF-8; from_utf8_lossy would
        // conflate \xff and \xfe into one replacement character, so the
        // variable is an evaluation error instead.
        let mut r = req();
        r.query = b"\xff\xfe".to_vec();
        let mut c = Context::new(
            &r,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
        );
        let cond = parse("%{QUERY_STRING} == ''").unwrap();
        assert!(cond.eval(&mut c).is_err());
        assert!(expand("%{QUERY_STRING}", &c).is_err());
        assert!(expand("%{QUERY_STRING}|x", &c).is_err());
    }

    #[test]
    fn expression_file_access_is_confined_to_docroot() {
        let dir = std::env::temp_dir().join(format!("vp-expr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("inside.txt"), "inside").unwrap();
        let r = req();
        let mut c = Context::new(&r, &[], "127.0.0.1".parse().unwrap(), &dir, "/x");
        let inside = parse("file('inside.txt') = 'inside'").unwrap();
        assert!(inside.eval(&mut c).unwrap().truthy());
        let outside = parse("file('/etc/passwd') = ''").unwrap();
        assert!(outside.eval(&mut c).is_err());
        let traversal = parse("-f '../etc/passwd'").unwrap();
        assert!(!traversal.eval(&mut c).unwrap().truthy());
        std::fs::write(dir.join("oversized.txt"), vec![b'x'; 64 * 1024 + 1]).unwrap();
        assert!(parse("file('oversized.txt') = ''")
            .unwrap()
            .eval(&mut c)
            .is_err());
        std::fs::create_dir(dir.join("not-regular")).unwrap();
        assert!(parse("file('not-regular') = ''")
            .unwrap()
            .eval(&mut c)
            .is_err());
        // FileTest uses the same descriptor-relative confinement as
        // file()/filesize().
        for expr in [
            "-f '/etc/passwd'",
            "-e '/etc/passwd'",
            "-s '/etc/passwd'",
            "-d '/etc'",
            "-F '/etc/passwd'",
            "-U '/etc/passwd'",
        ] {
            assert!(
                !parse(expr).unwrap().eval(&mut c).unwrap().truthy(),
                "{expr}"
            );
        }
        let outside_file = dir.with_file_name(format!("vp-expr-outside-{}", std::process::id()));
        std::fs::write(&outside_file, "outside").unwrap();
        std::os::unix::fs::symlink(&outside_file, dir.join("escape")).unwrap();
        assert!(!parse("-f 'escape'").unwrap().eval(&mut c).unwrap().truthy());
        assert!(parse("file('escape') = 'outside'")
            .unwrap()
            .eval(&mut c)
            .is_err());
        assert!(parse("filesize('escape') = 0")
            .unwrap()
            .eval(&mut c)
            .unwrap()
            .truthy());
        let _ = std::fs::remove_file(&outside_file);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verified_expression_kernels_keep_comparison_and_glob_semantics() {
        use vapache_verified::ExprCompareOp::{Eq, Ge, Gt, Le, Ne};
        use vapache_verified::{expr_compare_ints, expr_compare_strs, expr_glob_match};
        assert!(expr_compare_ints(Eq, 1, 1));
        assert!(expr_compare_ints(Le, -1, 1));
        assert!(expr_compare_ints(Ge, 1, 1));
        assert!(expr_compare_ints(Ne, 1, 2));
        assert!(expr_compare_strs(Le, b"aa", b"b"));
        assert!(expr_compare_strs(Gt, b"b", b"aa"));
        assert!(expr_compare_strs(Eq, b"", b""));
        assert!(!expr_compare_strs(Gt, b"aa", b"aa"));
        assert!(expr_glob_match(b"a/*", b"a/b", true));
        assert!(!expr_glob_match(b"a/*", b"a/b/c", true));
        assert!(!expr_glob_match(b"a?b", b"a/b", false));
        assert!(expr_glob_match(b"a?b", b"a/b", true));
        assert!(expr_glob_match(b"*.php", b"index.php", true));
        assert!(!expr_glob_match(b"?.php", b"index.php", true));
        assert!(expr_glob_match(b"", b"", true));
        assert!(!expr_glob_match(b"", b"x", true));
        // The runtime evaluator consumes the verified kernels directly.
        assert!(!eval("'a/b/c' -fnmatch 'a/*'"));
        assert!(eval("'a/b' -fnmatch 'a/*'"));
        assert!(!eval("'a/b' -strmatch 'a?b'"));
        assert!(eval("'a/b' -fnmatch 'a?b'"));
        assert!(eval("'aa' < 'b'"));
        assert!(eval("'2' -lt '10'"));
    }

    #[test]
    fn parses_common_expressions() {
        assert!(eval("true"));
        assert!(!eval("false"));
        assert!(eval("1 -eq 01"));
        assert!(eval("'aa' == 'aa'"));
        assert!(eval("'a' . 'b' = 'ab'"));
        assert!(eval("'a' -in { 'b', 'a' }"));
        assert!(eval("'abc' =~ /bc/"));
        assert!(eval("'abc' =~ /BC/i"));
        assert!(eval("%{REQUEST_METHOD} == 'GET'"));
        assert!(eval("-R '127.0.0.1'"));
    }

    fn eval_result(s: &str) -> Result<Value, String> {
        let e = parse(s)?;
        let r = req();
        let mut c = Context::new(
            &r,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
        );
        e.eval(&mut c)
    }

    #[test]
    fn value_conversions_and_connection_context() {
        assert!(Value::Bool(true).truthy());
        assert!(Value::Int(1).truthy());
        assert!(!Value::Int(0).truthy());
        assert!(Value::Str("x".into()).truthy());
        assert!(!Value::Str(String::new()).truthy());
        assert!(Value::List(vec![Value::Int(1)]).truthy());
        assert!(!Value::List(Vec::new()).truthy());
        assert_eq!(Value::Bool(true).string(), "true");
        assert_eq!(Value::Bool(false).string(), "false");
        assert_eq!(
            Value::List(vec![Value::Int(1), Value::Str("x".into())]).string(),
            "1,x"
        );
        assert_eq!(Value::Bool(true).int(), Some(1));
        assert_eq!(Value::Bool(false).int(), Some(0));
        assert_eq!(Value::List(Vec::new()).int(), None);
        assert_eq!(Value::Str(" 42 ".into()).int(), Some(42));
        assert!(Value::Bytes(vec![0xff]).truthy());
        assert_eq!(Value::Bytes(b" 42 ".to_vec()).int(), Some(42));

        assert!(!request_is_https());
        assert_eq!(request_port(), 80);
        let guard = set_server_name("canonical.test");
        assert_eq!(request_server_name().as_deref(), Some("canonical.test"));
        drop(guard);
        assert_eq!(request_server_name(), None);
        with_connection(true, 8443, || {
            assert!(request_is_https());
            assert_eq!(request_port(), 8443);
        });
        assert!(!request_is_https());
        assert_eq!(request_port(), 80);

        let r = req();
        let c = Context::new(
            &r,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
        );
        assert_eq!(function_arg(&c, "literal").unwrap(), "literal");
        assert_eq!(function_arg(&c, "REQUEST_METHOD").unwrap(), "GET");
        assert_eq!(function_arg(&c, "%{REQUEST_METHOD}").unwrap(), "GET");
        assert_eq!(
            confined_expr_relative("relative.txt"),
            Some(PathBuf::from("relative.txt"))
        );
    }

    #[test]
    fn p16_expression_regex_matches_raw_header_bytes_with_ascii_classes() {
        let mut r = req();
        r.headers
            .insert("x-user", [vec![0xff], b"sqlmap".to_vec()].concat());
        r.headers.insert("x-word", "é".as_bytes().to_vec());
        r.headers.insert("x-boundary", "éadmin".as_bytes().to_vec());
        let mut c = Context::new(
            &r,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
        );
        assert!(parse("%{HTTP:X-User} =~ /sqlmap/")
            .unwrap()
            .eval(&mut c)
            .unwrap()
            .truthy());
        assert!(!parse(r"%{HTTP:X-Word} =~ /^\w+$/")
            .unwrap()
            .eval(&mut c)
            .unwrap()
            .truthy());
        assert!(parse(r"%{HTTP:X-Boundary} =~ /\badmin\b/")
            .unwrap()
            .eval(&mut c)
            .unwrap()
            .truthy());

        // String interpolation must preserve the same bytes, not project an
        // invalid header to an empty or replacement-character string.
        assert!(parse("'%{HTTP:X-User}' =~ /sqlmap/")
            .unwrap()
            .eval(&mut c)
            .unwrap()
            .truthy());
    }

    #[test]
    fn var_expand_and_encoding_edge_paths() {
        let mut r = req();
        r.headers.push("X-Test", "Header");
        r.headers.push("Host", "example.test:8080");
        let env = vec![("FOO".to_string(), b"bar".to_vec())];
        let mut c = Context::new(
            &r,
            &env,
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
        );
        assert_eq!(var(&c, "req:x-test").unwrap().string(), "Header");
        assert_eq!(var(&c, "http:x-test").unwrap().string(), "Header");
        assert_eq!(var(&c, "env:foo").unwrap().string(), "bar");
        assert_eq!(var(&c, "http_x_test").unwrap().string(), "Header");
        assert_eq!(var(&c, "server_name").unwrap().string(), "example.test");
        assert!(var(&c, "httpfoo").is_err());
        assert!(var(&c, "unknown_variable").is_err());
        assert_eq!(var(&c, "tolower:ABC").unwrap().string(), "abc");
        assert_eq!(var(&c, "escape:a b").unwrap().string(), "a%20b");
        assert_eq!(var(&c, "unescape:a%20b").unwrap().string(), "a b");
        assert_eq!(var(&c, "TIME_YEAR").unwrap().string().len(), 4);
        assert_eq!(var(&c, "REQUEST_SCHEME").unwrap().string(), "http");
        assert_eq!(var(&c, "HTTPS").unwrap().string(), "off");

        // F57/I57: REQUEST_URI is the canonical decoded, query-free path
        // supplied by the dispatcher, never the raw request-line target.
        let mut raw = req();
        raw.target = b"/%2eenv?x=1".to_vec();
        raw.raw_path = b"/%2eenv".to_vec();
        raw.query = b"x=1".to_vec();
        let raw_ctx = Context::new(
            &raw,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/.env",
        );
        assert_eq!(var(&raw_ctx, "REQUEST_URI").unwrap().string(), "/.env");
        assert_eq!(function_arg(&raw_ctx, "REQUEST_URI").unwrap(), "/.env");
        assert_eq!(
            expand("%{REQUEST_URI}|%{QUERY_STRING}", &raw_ctx).unwrap(),
            "/.env|x=1"
        );

        assert_eq!(expand("plain text", &c).unwrap(), "plain text");
        assert_eq!(expand("%{toupper:%{REQUEST_METHOD}}", &c).unwrap(), "GET");
        assert_eq!(expand("%{unescape:a%20b}", &c).unwrap(), "a b");
        assert!(expand("%{unknown:%{REQUEST_METHOD}}", &c).is_err());
        assert!(expand("%{REQUEST_METHOD", &c).is_err());
        assert_eq!(percent_encode("a b/?~"), "a%20b%2f%3f~");
        assert_eq!(percent_decode("a%20b%2f%3F%zz"), "a b/?%zz");
        assert_eq!(hex(b'0'), Some(0));
        assert_eq!(hex(b'a'), Some(10));
        assert_eq!(hex(b'F'), Some(15));
        assert_eq!(hex(b'z'), None);
        assert_eq!(sha1_hex("abc").len(), 40);
        assert_eq!(md5_hex("abc").len(), 32);
        assert_eq!(base64_encode(b"abc"), "YWJj");
        assert_eq!(base64_decode("YWJj"), b"abc");
        assert_eq!(base64_decode("!!!"), Vec::<u8>::new());
        assert_eq!(compare_op(">="), Some(vapache_verified::ExprCompareOp::Ge));
        assert!(compare_op("bogus").is_none());
        assert!(!cmp(&Value::Int(1), "bogus", &Value::Int(1)));
    }

    #[test]
    fn eval_branch_coverage() {
        assert_eq!(eval_result("-1 < 0").unwrap().string(), "true");
        assert!(!eval_result("false && true").unwrap().truthy());
        assert!(!eval_result("false || false").unwrap().truthy());
        assert!(eval_result("'ABC' -strcmatch 'abc'").unwrap().truthy());
        assert!(eval_result("req('x-test') == ''").unwrap().truthy());
        assert!(eval_result("env('FOO') == ''").unwrap().truthy());
        let dir = std::env::temp_dir().join(format!("vp-expr-branches-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("inside.txt"), "inside").unwrap();
        let r = req();
        let mut file_ctx = Context::new(&r, &[], "127.0.0.1".parse().unwrap(), &dir, "/x");
        let size = parse("filesize('inside.txt')").unwrap();
        assert_eq!(size.eval(&mut file_ctx).unwrap().int(), Some(6));
        let forbidden = parse("filesize('/etc/passwd')").unwrap();
        assert!(forbidden.eval(&mut file_ctx).is_err());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(eval_result("unescape('a%20b')").unwrap().string(), "a b");
        assert_eq!(
            eval_result("sha1('abc')").unwrap().string(),
            sha1_hex("abc")
        );
        assert_eq!(eval_result("md5('abc')").unwrap().string(), md5_hex("abc"));
        assert_eq!(eval_result("base64('abc')").unwrap().string(), "YWJj");
        assert_eq!(eval_result("unbase64('YWJj')").unwrap().string(), "abc");
        assert!(eval_result("bogus()").is_err());
        assert!(eval_result("'aa' =~ /(a)\\1/").is_err());

        let r = req();
        let mut c = Context::new(
            &r,
            &[],
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp"),
            "/x",
        );
        let bad_test = Expr::FileTest("-x".into(), Box::new(Expr::Str("x".into())));
        assert!(!bad_test.eval(&mut c).unwrap().truthy());
    }

    #[test]
    fn parser_error_and_escape_branches() {
        for text in [
            "'unterminated",
            "%{unterminated",
            "'a' =~ /unterminated",
            "'a' =~ /a/g",
            "'a' =~ /a/ii",
            "(true",
            "true trailing",
            "?",
            "unknown_token",
            "req('x'",
            "req('x' 'y')",
            "'a' -in { 'b'",
            "'a' -in 'b'",
            "{ 'a' 'b' }",
            "=",
            "-inx",
            "-foo",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
        assert!(parse("'a\\nb\\rc\\td\\xe'").is_ok());
        assert!(parse("%{nested{brace}}").is_ok());
        assert!(parse("'a' -in { 'b', 'c' }").is_ok());
        assert!(parse("'a' -in { }").is_ok());
        assert!(parse("{ }").is_ok());
        assert!(parse("{ 'a', }").is_ok());
        assert!(parse("{ 'a', 'b' }").is_ok());
        assert!(parse("(true)").is_ok());
        assert!(parse("!true").is_ok());
        assert!(parse("-in").is_ok());
        let mut direct = Parser::new("-n");
        assert!(matches!(direct.primary().unwrap(), Expr::Str(ref s) if s == "-n"));
        assert!(parse("-1").is_ok());
        assert!(parse("req()").is_ok());
        assert!(parse("req('x',)").is_ok());
        assert!(eval("-in == '-in'"));
    }

    #[test]
    fn parser_is_total_at_regex_operator_boundary() {
        // An expression ending right at =~ / !~ used to index past the end of
        // the input and panic; reachable from main-config <If> and from
        // attacker-writable .htaccess, it must be an error, not an abort.
        assert!(parse("x =~").is_err());
        assert!(parse("'a' !~").is_err());
        assert!(parse("%{REQUEST_URI} =~").is_err());
        assert!(parse("x =~  ").is_err());
        // The delimiter still works normally at every position.
        assert!(eval("'abc' =~ /bc/"));
        // Backreferences require backtracking and fail closed at load time.
        assert!(parse("'aa' =~ /(a)\\1/").is_err());
    }

    #[test]
    fn parser_rejects_non_ascii_regex_delimiters_without_losing_utf8_boundaries() {
        // P24-A: each of these used to leave Parser::pos in the middle of the
        // second character and panic from Parser::and under panic=abort.
        for expression in ["%{X} =~ éé", "%{X} !~ éé", "%{X} =~ €€"] {
            let error = parse(expression).unwrap_err();
            assert_eq!(error, "regex delimiter must be ASCII", "{expression}");
        }

        // Keep the exact coverage-guided artifact as a deterministic parser
        // regression as well as a seed in the rewrite_expr fuzz corpus.
        let crash = include_bytes!("../../../adversarial/p24/crash-input.bin");
        let crash = std::str::from_utf8(crash).expect("P24 artifact is valid UTF-8");
        assert!(parse(crash).is_err());

        // ASCII delimiters may contain non-ASCII pattern bytes, and quoted
        // string values retain their original UTF-8 instead of mojibake.
        assert!(eval("'é' == 'é'"));
        assert!(eval("'é' =~ /é/"));
        assert!(eval("'é' == '\\é'"));
    }

    #[test]
    fn apache_pcre_guard_constructs_are_compiled_at_load_time() {
        for expression in [
            r"'secret' =~ /\Qsecret\E/",
            r"'secret.txt' =~ /secret\.txt\Z/",
            r"'secret' =~ /sec(?#match)ret/",
            r"'secret' =~ /\Ksecret/",
        ] {
            assert!(eval_result(expression).unwrap().truthy(), "{expression}");
        }
        assert!(eval_result(r"'public' !~ /\Qprivate\E/").unwrap().truthy());
        // Compilation occurs in Parser::compare, so an invalid PCRE pattern
        // is a configuration/load error rather than a request-time branch.
        assert!(parse(r"'secret' =~ /(?unterminated/").is_err());
        assert!(parse(r"'secretse' =~ /(se)cret\1/").is_err());
        for pattern in [
            r"(?u)^secret$",
            r"(?u:^secret$)",
            r"(?iu:^secret$)",
            r"(?-u:^secret$)",
            r"(?i-u:^secret$)",
            r"(?iR:^secret$)",
            r"(?i-R:^secret$)",
            r"\b{start}",
            r"\B{end-half}",
        ] {
            assert!(
                ExprRegex::compile(pattern.into(), false).is_err(),
                "accepted Rust-only regex syntax in {pattern:?}",
            );
        }
        assert!(!eval_result(r"'secret' =~ /\</").unwrap().truthy());
        assert!(eval_result(r"'<' =~ /\</").unwrap().truthy());
        assert!(!eval_result(r"'secret' =~ /\>/").unwrap().truthy());
        assert!(eval_result(r"'>' =~ /\>/").unwrap().truthy());
        assert!(eval_result(r"'secret' =~ /(?U)^secret$/").unwrap().truthy());

        let regex = ExprRegex::compile("secret".into(), true).unwrap();
        let debug = format!("{regex:?}");
        assert!(debug.contains("secret") && debug.contains("true"));
        assert!(ExprRegex::compile("\n".into(), false).is_err());
        assert!(ExprRegex::compile("x".repeat(65_537), false).is_err());
        assert!(
            eval_result(r"'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX' =~ /(*LIMIT_MATCH=1)(a+)+$/")
                .is_err()
        );
    }

    #[test]
    fn parser_recursion_is_capped_not_a_stack_overflow() {
        // Recursion depth is capped instead of overflowing the stack, so the
        // deepest inputs Err cleanly even on small (2 MiB) request threads.
        // Depth accounting: a `!` or `-` costs one primary/unary frame; a
        // paren level costs two (unary + primary).
        let deep_not = format!("{}true", "!".repeat(MAX_EXPR_DEPTH + 1));
        assert!(parse(&deep_not).is_err());
        // Inputs just under the cap still parse; semantics unchanged.
        let ok_not = format!("{}true", "!".repeat(MAX_EXPR_DEPTH - 2));
        assert_eq!(eval(&ok_not), true);
        // Paren boundary: MAX_EXPR_DEPTH/2 - 1 levels sit exactly at the cap.
        let ok_parens = format!(
            "{}true{}",
            "(".repeat(MAX_EXPR_DEPTH / 2 - 1),
            ")".repeat(MAX_EXPR_DEPTH / 2 - 1)
        );
        assert!(parse(&ok_parens).is_ok());
        let deep_parens = format!(
            "{}true{}",
            "(".repeat(MAX_EXPR_DEPTH / 2 + 1),
            ")".repeat(MAX_EXPR_DEPTH / 2 + 1)
        );
        assert!(parse(&deep_parens).is_err());
        // Mixed operator nesting is also bounded and erroring.
        let deep_neg = format!("{}1", "-".repeat(MAX_EXPR_DEPTH + 1));
        assert!(parse(&deep_neg).is_err());
    }
}

// ---------------------------------------------------------------------------
// Pass-11 regression kernels (F63): filesystem variables fail closed and are
// validated at load time.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod pass11_kernel_tests {
    use super::*;
    use crate::http::{Headers, Request, Version};

    fn req() -> Request {
        Request {
            method: "GET".into(),
            target: b"/x.cgi".to_vec(),
            raw_path: b"/x.cgi".to_vec(),
            query: Vec::new(),
            version: Version::Http11,
            headers: Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    fn context(fs_path: Option<&'static Path>) -> Context<'static> {
        // The request is leaked for the test only: the borrow lives for the
        // whole case.
        let r: &'static Request = Box::leak(Box::new(req()));
        let docroot: &'static Path = Path::new("/srv");
        let url: &'static str = "/x.cgi";
        Context::new(r, &[], "127.0.0.1".parse().unwrap(), docroot, url).with_fs_path(fs_path)
    }

    #[test]
    fn request_filename_fails_closed_without_a_binding() {
        let e = parse("%{REQUEST_FILENAME} != ''").unwrap();
        let mut c = context(None);
        assert!(
            e.eval(&mut c).is_err(),
            "an unbound filesystem variable must not evaluate (fail closed)"
        );
        let e = parse("%{SCRIPT_FILENAME} == ''").unwrap();
        let mut c = context(None);
        assert!(e.eval(&mut c).is_err());
    }

    #[test]
    fn request_filename_binds_to_the_mapped_filesystem_path() {
        let e = parse("%{REQUEST_FILENAME} == '/srv/www/x.cgi'").unwrap();
        let mut c = context(Some(Path::new("/srv/www/x.cgi")));
        assert!(e.eval(&mut c).unwrap().truthy());
        let e = parse("%{SCRIPT_FILENAME} == '/srv/www/x.cgi'").unwrap();
        let mut c = context(Some(Path::new("/srv/www/x.cgi")));
        assert!(e.eval(&mut c).unwrap().truthy());
    }

    #[test]
    fn validate_vars_rejects_unknown_variables_in_every_position() {
        // A plain Var node.
        assert!(validate_vars(&parse("%{NOSUCHVAR} == 'x'").unwrap()).is_err());
        assert!(validate_vars(&parse("%{HTTPX_BLOCK} == 'yes'").unwrap()).is_err());
        // A %{...} reference inside a string literal.
        assert!(validate_vars(&parse("'%{NOSUCHVAR}' != ''").unwrap()).is_err());
        // Inside a transform argument (recursed).
        assert!(validate_vars(&parse("tolower(%{NOSUCHVAR}) == 'x'").unwrap()).is_err());
        // Known variables validate cleanly.
        assert!(validate_vars(&parse("%{REQUEST_FILENAME} != ''").unwrap()).is_ok());
        assert!(validate_vars(&parse("%{SCRIPT_FILENAME} != ''").unwrap()).is_ok());
        assert!(validate_vars(&parse("'%{REQUEST_URI}' != ''").unwrap()).is_ok());
        // The evaluator and the validator share one source of truth: a name
        // that validates must also evaluate when bound, and vice versa.
        for name in ["REQUEST_FILENAME", "SCRIPT_FILENAME", "NOSUCHVAR"] {
            let known = vapache_verified::expr_var_known(name.as_bytes());
            let expr = parse(&format!("%{{{name}}} != ''")).unwrap();
            assert_eq!(
                validate_vars(&expr).is_ok(),
                known,
                "validator and kernel disagree on {name}"
            );
            let mut c = context(Some(Path::new("/srv/www/x.cgi")));
            assert_eq!(
                expr.eval(&mut c).is_ok(),
                known,
                "evaluator disagrees on {name}"
            );
        }
    }

    #[test]
    fn validate_vars_covers_transforms_and_every_tree_shape() {
        for arg in [
            "req:Host",
            "http:Host",
            "env:NAME",
            "HTTP_HOST",
            "TIME",
            "TIME_YEAR",
            "TIME_MON",
            "TIME_DAY",
            "TIME_HOUR",
            "TIME_MIN",
            "TIME_SEC",
            "REQUEST_METHOD",
            "QUERY_STRING",
            "REQUEST_URI",
            "REQUEST_SCHEME",
            "HTTPS",
            "REMOTE_ADDR",
            "SERVER_NAME",
            "SERVER_PORT",
            "DOCUMENT_ROOT",
            "API_VERSION",
            "literal",
        ] {
            let _ = validate_vars(&Expr::Str(format!("%{{tolower:{arg}}}")));
        }
        assert!(validate_vars(&Expr::Str("%{tolower:%{REQUEST_METHOD}}".into())).is_ok());
        assert!(validate_vars(&Expr::Str("%{REQUEST_METHOD".into())).is_err());

        let leaf = || Expr::Str("literal".into());
        let shapes = vec![
            Expr::Func("tolower".into(), vec![leaf()]),
            Expr::Concat(vec![leaf()]),
            Expr::And(vec![leaf()]),
            Expr::Or(vec![leaf()]),
            Expr::Not(Box::new(leaf())),
            Expr::Neg(Box::new(leaf())),
            Expr::Compare(Box::new(leaf()), "==".into(), Box::new(leaf())),
            Expr::Regex(
                Box::new(leaf()),
                ExprRegex::compile("x".into(), false).unwrap(),
                false,
            ),
            Expr::In(Box::new(leaf()), vec![leaf()]),
            Expr::FileTest("-f".into(), Box::new(leaf())),
            Expr::StrTest(Box::new(leaf()), true),
            Expr::IpMatch(Box::new(leaf()), Box::new(leaf()), false),
            Expr::StrMatch(Box::new(leaf()), Box::new(leaf()), false, false),
        ];
        assert!(shapes.iter().all(|expr| validate_vars(expr).is_ok()));
    }
}
