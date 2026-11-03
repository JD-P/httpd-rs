//! Access and error logging with Apache `LogFormat` compatibility.
//!
//! Log values derived from the request are escaped so that a hostile
//! `User-Agent` or URL cannot inject forged log lines (CWE-117).

use crate::config::{Config, CustomLog};
use crate::util::{http_date, unix_now};
use std::cell::RefCell;
use std::fmt::{self, Write as _};
use std::io::{self, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// One request must never expand a configured LogFormat into an allocation or
/// disk write large enough to become its own denial-of-service primitive.
const MAX_LOG_LINE_BYTES: usize = 128 * 1024;
const MAX_STDERR_MESSAGE_BYTES: usize = MAX_LOG_LINE_BYTES / 4;
/// Preserve service availability even when external rotation is missing or
/// broken. A reopen after rotation starts with the replacement file's size.
const MAX_LOG_FILE_BYTES: u64 = 1024 * 1024 * 1024;
static STDERR_WRITER_BUSY: AtomicBool = AtomicBool::new(false);
static LOG_WRITER_BUSY: AtomicBool = AtomicBool::new(false);

struct WriterGuard(&'static AtomicBool);

impl Drop for WriterGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn try_writer(gate: &'static AtomicBool) -> Option<WriterGuard> {
    gate.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
        .then_some(WriterGuard(gate))
}

struct BoundedMessage(String);

struct CappedLogFile {
    file: std::fs::File,
    bytes: u64,
    disk: Option<crate::resource::DiskLease>,
}

impl Write for CappedLogFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.bytes >= MAX_LOG_FILE_BYTES {
            return Ok(buf.len());
        }
        let allowed = usize::try_from(MAX_LOG_FILE_BYTES - self.bytes)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        if let Some(disk) = &mut self.disk {
            disk.reserve(allowed as u64)?;
        }
        let written = match self.file.write(&buf[..allowed]) {
            Ok(written) => written,
            Err(error) => {
                if let Some(disk) = &mut self.disk {
                    disk.release(allowed as u64);
                }
                return Err(error);
            }
        };
        if written < allowed {
            if let Some(disk) = &mut self.disk {
                disk.release((allowed - written) as u64);
            }
        }
        self.bytes = self.bytes.saturating_add(written as u64);
        if written == allowed && allowed < buf.len() {
            // Report the remainder as consumed so callers do not spin while the
            // overflow is intentionally discarded.
            Ok(buf.len())
        } else {
            Ok(written)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl fmt::Write for BoundedMessage {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let remaining = MAX_STDERR_MESSAGE_BYTES.saturating_sub(self.0.len());
        if remaining == 0 {
            return Err(fmt::Error);
        }
        let mut end = value.len().min(remaining);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        self.0.push_str(&value[..end]);
        (end == value.len()).then_some(()).ok_or(fmt::Error)
    }
}

/// Request and background diagnostics must not queue the worker population on
/// a blocked inherited stderr pipe. The one writer that owns the descriptor is
/// bounded; concurrent messages are deliberately dropped during overload.
pub fn bounded_stderr(arguments: fmt::Arguments<'_>) {
    let Some(_guard) = try_writer(&STDERR_WRITER_BUSY) else {
        return;
    };
    let mut message = BoundedMessage(String::new());
    let _ = fmt::write(&mut message, arguments);
    let escaped = vapache_verified::escape_log_bytes_bounded(
        message.0.as_bytes(),
        MAX_LOG_LINE_BYTES.saturating_sub(1),
    );
    let mut stderr = io::stderr().lock();
    let _ = stderr.write_all(&escaped);
    let _ = stderr.write_all(b"\n");
    let _ = stderr.flush();
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Emerg = 0,
    Alert = 1,
    Crit = 2,
    Error = 3,
    Warn = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl Level {
    pub fn parse(s: &str) -> Level {
        match s.to_ascii_lowercase().as_str() {
            "emerg" => Level::Emerg,
            "alert" => Level::Alert,
            "crit" => Level::Crit,
            "error" => Level::Error,
            "warn" => Level::Warn,
            "notice" => Level::Notice,
            "info" => Level::Info,
            "debug" | "trace1" | "trace2" | "trace3" | "trace4" | "trace5" | "trace6"
            | "trace7" | "trace8" => Level::Debug,
            _ => Level::Warn,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Level::Emerg => "emerg",
            Level::Alert => "alert",
            Level::Crit => "crit",
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Notice => "notice",
            Level::Info => "info",
            Level::Debug => "debug",
        }
    }
}

pub struct Logger {
    error: Mutex<Box<dyn Write + Send>>,
    error_path: String,
    root: PathBuf,
    service_uid: Option<u32>,
    level: Level,
    access: Vec<AccessLog>,
    resource_budget: std::sync::Arc<crate::resource::ResourceBudget>,
    pub errors: Mutex<Vec<String>>,
}

struct AccessLog {
    path: String,
    format: String,
    vhost: Option<usize>,
    writer: Mutex<Box<dyn Write + Send>>,
    discard: bool,
}

pub struct AccessEntry<'a> {
    pub remote_ip: &'a str,
    pub remote_port: u16,
    pub local_ip: &'a str,
    pub local_port: u16,
    pub server_name: &'a str,
    pub method: &'a str,
    /// Original request-target bytes exactly as received from the client.
    pub uri: &'a [u8],
    pub remote_user: Option<&'a str>,
    pub protocol: &'a str,
    pub status: u16,
    pub bytes_sent: u64,
    pub bytes_in: u64,
    pub referer: &'a str,
    pub user_agent: &'a str,
    pub host: &'a str,
    pub vhost_index: Option<usize>,
    pub started: Instant,
}

fn configured_user_id(user: &str) -> std::io::Result<u32> {
    if let Ok(uid) = user.parse::<u32>() {
        return Ok(uid);
    }
    let user = std::ffi::CString::new(user)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid User"))?;
    let uid = unsafe {
        let entry = libc::getpwnam(user.as_ptr());
        (!entry.is_null()).then(|| (*entry).pw_uid)
    };
    uid.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "configured User does not exist",
        )
    })
}

fn running_privileged() -> bool {
    (unsafe { libc::geteuid() }) == 0
}

fn open_log(
    path: &str,
    server_root: &Path,
    service_uid: Option<u32>,
    resource_budget: &std::sync::Arc<crate::resource::ResourceBudget>,
) -> std::io::Result<Box<dyn Write + Send>> {
    if let Some(rest) = path.strip_prefix("syslog:") {
        let _ = rest;
        // Syslog is not implemented; write to stderr rather than silently drop.
        return Ok(Box::new(std::io::stderr()));
    }
    let p = PathBuf::from(path);
    let relative = !p.is_absolute();
    let configured = if !relative { p } else { server_root.join(p) };
    // RPM-family Apache layouts use a root-controlled `logs` symlink below
    // ServerRoot. Resolve an existing parent once, then use only its canonical
    // path for validation and opening. A later symlink replacement cannot
    // redirect the descriptor open, and service-writable targets are rejected
    // below before a privileged process creates anything.
    let full = if relative {
        match (configured.parent(), configured.file_name()) {
            (Some(parent), Some(name)) => match parent.canonicalize() {
                Ok(parent) => parent.join(name),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => configured,
                Err(error) => return Err(error),
            },
            _ => configured,
        }
    } else {
        configured
    };
    if let Some(parent) = full.parent() {
        // The service account must be able to traverse the root-owned parent
        // when reopening an already-owned log after privilege drop, but it
        // must not be able to replace directory entries.
        crate::files::ensure_admin_dir(parent, 0o755)?;
        if relative && parent.starts_with(server_root) {
            let below_root = parent.strip_prefix(server_root).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid log target")
            })?;
            let mut current = server_root.to_path_buf();
            for component in below_root.components() {
                let std::path::Component::Normal(component) = component else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid relative log directory",
                    ));
                };
                current.push(component);
                let directory = crate::files::ensure_admin_dir(&current, 0o755)?;
                crate::files::make_admin_dir_root_owned(&directory, 0o755)?;
            }
        } else if let Some(service_uid) = service_uid {
            crate::files::validate_admin_parents(&full, service_uid)?;
        }
    }
    let f = crate::files::open_admin_path(
        &full,
        libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND | libc::O_NONBLOCK,
        0o640,
    )?;
    let metadata = f.metadata()?;
    let explicit_null = full == Path::new("/dev/null") && metadata.file_type().is_char_device();
    if !metadata.is_file() && !explicit_null {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "log target is not a regular file",
        ));
    }
    let bytes = metadata.len().min(MAX_LOG_FILE_BYTES);
    let disk = if explicit_null {
        None
    } else {
        Some(resource_budget.try_disk_at(&full, bytes, 1)?)
    };
    Ok(Box::new(std::io::BufWriter::new(CappedLogFile {
        file: f,
        bytes,
        disk,
    })))
}

impl Logger {
    pub fn new(cfg: &Config) -> std::io::Result<Logger> {
        let service_uid = running_privileged()
            .then(|| configured_user_id(&cfg.user))
            .transpose()?;
        let error = open_log(
            &cfg.error_log,
            &cfg.server_root,
            service_uid,
            &cfg.resource_budget,
        )?;
        let mut access = Vec::new();
        let mut add = |cl: &CustomLog, vhost: Option<usize>| -> std::io::Result<()> {
            let w = open_log(
                &cl.path,
                &cfg.server_root,
                service_uid,
                &cfg.resource_budget,
            )?;
            let fmt = if cl.format.starts_with('"') && cl.format.ends_with('"') {
                cl.format[1..cl.format.len() - 1].to_string()
            } else {
                cfg.log_formats
                    .get(&cl.format)
                    .cloned()
                    .unwrap_or_else(|| cl.format.clone())
            };
            access.push(AccessLog {
                path: cl.path.clone(),
                format: fmt,
                vhost,
                writer: Mutex::new(w),
                discard: cl.path == "/dev/null",
            });
            Ok(())
        };
        for cl in &cfg.custom_logs {
            add(cl, None)?;
        }
        for (i, v) in cfg.vhosts.iter().enumerate() {
            for cl in &v.custom_logs {
                add(cl, Some(i))?;
            }
        }
        Ok(Logger {
            error: Mutex::new(error),
            error_path: cfg.error_log.clone(),
            root: cfg.server_root.clone(),
            service_uid,
            level: Level::parse(&cfg.log_level),
            access,
            resource_budget: cfg.resource_budget.clone(),
            errors: Mutex::new(Vec::new()),
        })
    }

    /// A graceful reload does not need to reopen log files when its effective
    /// logging configuration is unchanged. This matters after privilege drop:
    /// an inherited descriptor remains writable even when an absolute Apache
    /// log directory is intentionally not traversable by the service account.
    pub fn configuration_matches(&self, cfg: &Config) -> bool {
        if self.error_path != cfg.error_log
            || self.root != cfg.server_root
            || self.level != Level::parse(&cfg.log_level)
        {
            return false;
        }
        let mut expected = Vec::new();
        let mut add = |cl: &CustomLog, vhost: Option<usize>| {
            let format = if cl.format.starts_with('"') && cl.format.ends_with('"') {
                cl.format[1..cl.format.len() - 1].to_string()
            } else {
                cfg.log_formats
                    .get(&cl.format)
                    .cloned()
                    .unwrap_or_else(|| cl.format.clone())
            };
            expected.push((cl.path.clone(), format, vhost));
        };
        for custom in &cfg.custom_logs {
            add(custom, None);
        }
        for (index, vhost) in cfg.vhosts.iter().enumerate() {
            for custom in &vhost.custom_logs {
                add(custom, Some(index));
            }
        }
        self.access.len() == expected.len()
            && self
                .access
                .iter()
                .zip(expected)
                .all(|(actual, (path, format, vhost))| {
                    actual.path == path && actual.format == format && actual.vhost == vhost
                })
    }

    /// Hand configured log files/directories to the account the daemon will
    /// drop to.  Called while still root, so reloads and SIGUSR1 can reopen
    /// logs after privilege dropping.
    pub fn prepare_permissions(&self, cfg: &Config) {
        #[cfg(unix)]
        {
            use std::ffi::CString;
            if !running_privileged() {
                return;
            }
            // coverage:ignore-start - root-only ownership handoff
            let group = CString::new(cfg.group.as_str()).ok();
            let uid = configured_user_id(&cfg.user).ok();
            let gid = group.as_ref().and_then(|g| unsafe {
                let gr = libc::getgrnam(g.as_ptr());
                (!gr.is_null()).then(|| (*gr).gr_gid)
            });
            let Some(uid) = uid else { return };
            let full = |path: &str| {
                let p = PathBuf::from(path);
                if p.is_absolute() {
                    p
                } else {
                    self.root.join(p)
                }
            };
            let mut paths = vec![full(&self.error_path)];
            paths.extend(self.access.iter().map(|a| full(&a.path)));
            for path in paths {
                let Ok(file) = crate::files::open_admin_path(
                    &path,
                    libc::O_WRONLY | libc::O_APPEND | libc::O_NONBLOCK,
                    0,
                ) else {
                    continue;
                };
                if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
                    continue;
                }
                let gid = gid.unwrap_or(u32::MAX);
                unsafe {
                    let _ = libc::fchown(file.as_raw_fd(), uid, gid);
                    let _ = libc::fchmod(file.as_raw_fd(), 0o640); // coverage:ignore-stop
                }
            }
        }
    }

    /// Reopen error/access logs after log rotation (`SIGUSR1`).
    pub fn reopen(&self) -> std::io::Result<()> {
        let error = open_log(
            &self.error_path,
            &self.root,
            self.service_uid,
            &self.resource_budget,
        )?;
        let mut access_writers = Vec::new();
        for entry in &self.access {
            access_writers.push(open_log(
                &entry.path,
                &self.root,
                self.service_uid,
                &self.resource_budget,
            )?);
        }
        *self.error.lock().unwrap_or_else(|e| e.into_inner()) = error;
        for (entry, writer) in self.access.iter().zip(access_writers) {
            *entry.writer.lock().unwrap_or_else(|e| e.into_inner()) = writer;
        }
        Ok(())
    }

    pub fn log(&self, level: Level, module: &str, msg: &str) {
        if level > self.level {
            return;
        }
        // Error-log messages can contain request-derived text.  Escape terminal
        // controls so a hostile request cannot inject escape sequences into a
        // terminal viewing the error log (CVE-2003-0020).
        let escaped = vapache_verified::escape_log_bytes_bounded(
            msg.as_bytes(),
            MAX_LOG_LINE_BYTES.saturating_sub(1024),
        );
        let msg = String::from_utf8_lossy(&escaped);
        let line = format!(
            "[{} {}] [{}:{}] [pid {}] {}\n",
            http_date(unix_now()),
            format_args!("{:?}", std::time::SystemTime::now()),
            module,
            level.name(),
            std::process::id(),
            msg
        );
        if !self.resource_budget.try_log_bytes(
            crate::resource::current_expensive_client(),
            line.len() as u64,
        ) {
            return;
        }
        // Never queue request workers behind a filesystem-stalled logger. One
        // process-wide configured-log writer may block in the kernel;
        // concurrent messages are dropped under that overload instead of
        // consuming the worker pool.
        let Some(_writer_guard) = try_writer(&LOG_WRITER_BUSY) else {
            return;
        };
        if let Ok(mut w) = self.error.try_lock() {
            let _ = w.write_all(line.as_bytes());
            let _ = w.flush();
        }
    }

    pub fn error(&self, msg: &str) {
        self.log(Level::Error, "core", msg);
    }

    pub fn warn(&self, msg: &str) {
        self.log(Level::Warn, "core", msg);
    }

    pub fn info(&self, msg: &str) {
        self.log(Level::Info, "core", msg);
    }

    pub fn wants_access_log(&self) -> bool {
        self.access.iter().any(|log| !log.discard)
    }

    pub fn access(&self, e: &AccessEntry) {
        ACCESS_LINE.with(|buf| {
            let mut line = buf.borrow_mut();
            for log in &self.access {
                if log.discard {
                    continue;
                }
                if let Some(v) = log.vhost {
                    if Some(v) != e.vhost_index {
                        continue;
                    }
                }
                line.clear();
                format_access_into(&mut line, &log.format, e);
                let client = e.remote_ip.parse().ok();
                if !self
                    .resource_budget
                    .try_log_bytes(client, line.len().saturating_add(1) as u64)
                {
                    continue;
                }
                let Some(_writer_guard) = try_writer(&LOG_WRITER_BUSY) else {
                    continue;
                };
                if let Ok(mut w) = log.writer.try_lock() {
                    let _ = w.write_all(&line);
                    let _ = w.write_all(b"\n");
                    let _ = w.flush();
                }
            }
        });
    }
}

#[cfg(test)]
fn escape_log(s: &str) -> String {
    String::from_utf8(vapache_verified::escape_log_bytes(s.as_bytes()))
        .expect("valid UTF-8 remains valid after log escaping")
}

fn escape_log_into(out: &mut Vec<u8>, bytes: &[u8]) {
    let remaining = MAX_LOG_LINE_BYTES.saturating_sub(out.len());
    out.extend_from_slice(&vapache_verified::escape_log_bytes_bounded(
        bytes, remaining,
    ));
}

fn push_str(out: &mut Vec<u8>, value: &str) {
    let remaining = MAX_LOG_LINE_BYTES.saturating_sub(out.len());
    out.extend_from_slice(&value.as_bytes()[..value.len().min(remaining)]);
}
thread_local! {
    /// `%t` only changes once per second; format it once per connection thread.
    static LOG_TIME_CACHE: RefCell<(i64, String)> = const { RefCell::new((i64::MIN, String::new())) };
    /// Reuse the access-log line buffer on each connection thread.
    static ACCESS_LINE: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn request_start_secs(started: Instant) -> i64 {
    let now = std::time::SystemTime::now();
    let start = now
        .checked_sub(Duration::from_millis(started.elapsed().as_millis() as u64))
        .unwrap_or(now);
    crate::util::system_time_secs(start)
}

fn with_common_log_time<F: FnOnce(&str)>(started: Instant, f: F) {
    let secs = request_start_secs(started);
    LOG_TIME_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.0 != secs {
            cache.0 = secs;
            cache.1 = strftime_secs("%d/%b/%Y:%H:%M:%S +0000", secs);
        }
        f(&cache.1);
    });
}

#[cfg(test)]
fn format_access(fmt: &str, e: &AccessEntry) -> String {
    String::from_utf8(format_access_bytes(fmt, e)).expect("test entry formats as UTF-8")
}

#[cfg(test)]
fn format_access_bytes(fmt: &str, e: &AccessEntry) -> Vec<u8> {
    let mut out = Vec::with_capacity(fmt.len() + 128);
    format_access_into(&mut out, fmt, e);
    out
}

fn format_access_into(out: &mut Vec<u8>, fmt: &str, e: &AccessEntry) {
    let b = fmt.as_bytes();
    let mut i = 0;
    while i < b.len() && out.len() < MAX_LOG_LINE_BYTES {
        if b[i] != b'%' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        i += 1;
        if i >= b.len() {
            out.push(b'%');
            break;
        }
        if b[i] == b'{' {
            let end = match fmt[i..].find('}') {
                Some(x) => i + x,
                None => {
                    out.push(b'%');
                    break;
                }
            };
            let arg = &fmt[i + 1..end];
            i = end + 1;
            if i >= b.len() {
                break;
            }
            let conv = b[i] as char;
            i += 1;
            match conv {
                'i' => {
                    let v = match arg.to_ascii_lowercase().as_str() {
                        "referer" => e.referer,
                        "user-agent" => e.user_agent,
                        "host" => e.host,
                        _ => "",
                    };
                    if v.is_empty() {
                        out.push(b'-');
                    } else {
                        escape_log_into(out, v.as_bytes());
                    }
                }
                'o' => out.push(b'-'),
                't' => format_time_into(out, arg, e.started),
                'e' => out.push(b'-'),
                _ => {}
            }
            continue;
        }
        // Optional status modifier.
        let mut conv = b[i] as char;
        if conv == '>' || conv == '<' {
            i += 1;
            if i < b.len() {
                conv = b[i] as char;
            }
        }
        i += 1;
        match conv {
            'h' | 'a' => push_str(out, e.remote_ip),
            'l' => out.push(b'-'),
            'u' => match e.remote_user {
                Some(user) if !user.is_empty() => escape_log_into(out, user.as_bytes()),
                _ => out.push(b'-'),
            },
            't' => {
                out.push(b'[');
                format_time_into(out, "%d/%b/%Y:%H:%M:%S +0000", e.started);
                out.push(b']');
            }
            'r' => {
                if e.uri.is_empty() {
                    out.push(b'-');
                } else {
                    escape_log_into(out, e.method.as_bytes());
                    out.push(b' ');
                    escape_log_into(out, e.uri);
                    out.push(b' ');
                    push_str(out, e.protocol);
                }
            }
            's' => {
                let _ = write!(out, "{}", e.status);
            }
            'b' => {
                if e.bytes_sent == 0 {
                    out.push(b'-');
                } else {
                    let _ = write!(out, "{}", e.bytes_sent);
                }
            }
            'O' => {
                let _ = write!(out, "{}", e.bytes_sent);
            }
            'I' => {
                let _ = write!(out, "{}", e.bytes_in);
            }
            'B' => {
                let _ = write!(out, "{}", e.bytes_sent);
            }
            'v' => escape_log_into(out, e.server_name.as_bytes()),
            'p' => {
                let _ = write!(out, "{}", e.local_port);
            }
            'U' => {
                let path_end = e
                    .uri
                    .iter()
                    .position(|byte| *byte == b'?')
                    .unwrap_or(e.uri.len());
                escape_log_into(out, &e.uri[..path_end]);
            }
            'q' => {
                if let Some(query_start) = e.uri.iter().position(|byte| *byte == b'?') {
                    out.push(b'?');
                    escape_log_into(out, &e.uri[query_start + 1..]);
                }
            }
            'm' => push_str(out, e.method),
            'H' => push_str(out, e.protocol),
            'A' => push_str(out, e.local_ip),
            'D' => {
                let _ = write!(out, "{}", e.started.elapsed().as_micros());
            }
            'T' => {
                let _ = write!(out, "{}", e.started.elapsed().as_secs());
            }
            'P' => {
                let _ = write!(out, "{}", std::process::id());
            }
            '%' => out.push(b'%'),
            _ => {
                out.push(b'%');
                out.push(conv as u8);
            }
        }
    }
    out.truncate(MAX_LOG_LINE_BYTES);
}

fn format_time_into(out: &mut Vec<u8>, arg: &str, started: Instant) {
    match arg {
        "msec" | "msec_frac" => {
            let _ = write!(out, "{}", started.elapsed().as_millis());
        }
        "usec" => {
            let _ = write!(out, "{}", started.elapsed().as_micros());
        }
        "sec" => {
            let _ = write!(out, "{}", started.elapsed().as_secs());
        }
        "%d/%b/%Y:%H:%M:%S +0000" => with_common_log_time(started, |s| push_str(out, s)),
        _ => strftime_common_into(out, arg, started),
    }
}

fn strftime_secs(fmt: &str, secs: i64) -> String {
    let mut out = String::new();
    strftime_secs_into(&mut out, fmt, secs);
    out
}

fn strftime_common_into(out: &mut Vec<u8>, fmt: &str, started: Instant) {
    // Convert Instant to wall clock approximately: the only fields used by
    // standard formats are date/time, so use the current time adjusted by
    // elapsed milliseconds (adequate for sub-second request logging).
    push_str(out, &strftime_secs(fmt, request_start_secs(started)));
}

fn strftime_secs_into(out: &mut String, fmt: &str, secs: i64) {
    let (y, m, d) = crate::util::civil_from_days(secs.div_euclid(86_400));
    let sod = secs.rem_euclid(86_400);
    let hh = sod / 3600;
    let mm = (sod % 3600) / 60;
    let ss = sod % 60;
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let b = fmt.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 1 < b.len() {
            i += 1;
            match b[i] as char {
                'Y' => {
                    let _ = write!(out, "{y:04}");
                }
                'm' => {
                    let _ = write!(out, "{m:02}");
                }
                'd' => {
                    let _ = write!(out, "{d:02}");
                }
                'H' => {
                    let _ = write!(out, "{hh:02}");
                }
                'M' => {
                    let _ = write!(out, "{mm:02}");
                }
                'S' => {
                    let _ = write!(out, "{ss:02}");
                }
                'b' => out.push_str(months[(m as usize - 1) % 12]),
                'a' => out.push_str(
                    ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"]
                        [(secs.div_euclid(86_400)).rem_euclid(7) as usize],
                ),
                'z' => out.push_str("+0000"),
                'Z' => out.push_str("GMT"),
                '%' => out.push('%'),
                c => {
                    out.push('%');
                    out.push(c);
                }
            }
            i += 1;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
}

impl Logger {
    pub fn access_log_count(&self) -> usize {
        self.access.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn escape_control() {
        assert_eq!(escape_log("a\"\n\x01b"), "a\\\"\\x0a\\x01b");

        let mut message = BoundedMessage(String::new());
        assert!(message
            .write_str(&"é".repeat(MAX_STDERR_MESSAGE_BYTES))
            .is_err());
        assert!(message.0.is_char_boundary(message.0.len()));
        assert!(message.0.len() <= MAX_STDERR_MESSAGE_BYTES);
        let mut split_codepoint = BoundedMessage(String::new());
        assert!(split_codepoint
            .write_str(&"€".repeat(MAX_STDERR_MESSAGE_BYTES))
            .is_err());
        assert!(split_codepoint.0.is_char_boundary(split_codepoint.0.len()));
        let mut full = BoundedMessage("x".repeat(MAX_STDERR_MESSAGE_BYTES));
        assert!(full.write_str("more").is_err());

        let stderr_guard = try_writer(&STDERR_WRITER_BUSY).unwrap();
        bounded_stderr(format_args!("deliberately dropped"));
        drop(stderr_guard);

        static TEST_GATE: AtomicBool = AtomicBool::new(false);
        let first = try_writer(&TEST_GATE).unwrap();
        assert!(try_writer(&TEST_GATE).is_none());
        drop(first);
        assert!(try_writer(&TEST_GATE).is_some());

        let path = std::env::temp_dir().join(format!(
            "vapache-capped-log-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = std::fs::File::create(&path).unwrap();
        let mut capped = CappedLogFile {
            file,
            bytes: MAX_LOG_FILE_BYTES - 2,
            disk: None,
        };
        capped.write_all(b"abcd").unwrap();
        capped.flush().unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 2);
        capped.bytes = MAX_LOG_FILE_BYTES;
        assert_eq!(capped.write(b"discarded").unwrap(), 9);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 2);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn configured_log_identity_and_target_errors_are_explicit() {
        let budget = std::sync::Arc::new(crate::resource::ResourceBudget::default());
        assert_eq!(configured_user_id("123").unwrap(), 123);
        assert_eq!(
            configured_user_id(&crate::files::effective_uid().to_string()).unwrap(),
            crate::files::effective_uid()
        );
        assert!(configured_user_id("bad\0user").is_err());
        assert!(configured_user_id("vapache-user-that-does-not-exist").is_err());
        assert!(open_log("/dev/zero", Path::new("/"), None, &budget).is_err());

        let dir = std::env::temp_dir().join(format!(
            "vapache-log-errors-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink("loop", dir.join("loop")).unwrap();
        assert!(open_log("loop/error.log", &dir, None, &budget).is_err());

        let target = dir.join("target.log");
        let linked = dir.join("linked.log");
        std::fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, &linked).unwrap();
        assert!(open_log(linked.to_str().unwrap(), &dir, None, &budget).is_err());
        assert!(open_log("", Path::new(""), None, &budget).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn access_log_drops_a_line_while_the_bounded_writer_is_busy() {
        let logger = Logger {
            error: Mutex::new(Box::new(Vec::<u8>::new())),
            error_path: "/dev/null".into(),
            root: PathBuf::from("/"),
            service_uid: None,
            level: Level::Info,
            access: vec![AccessLog {
                path: "memory".into(),
                format: "%h".into(),
                vhost: None,
                writer: Mutex::new(Box::new(Vec::<u8>::new())),
                discard: false,
            }],
            resource_budget: std::sync::Arc::new(crate::resource::ResourceBudget::default()),
            errors: Mutex::new(Vec::new()),
        };
        let entry = AccessEntry {
            remote_ip: "192.0.2.1",
            remote_port: 1234,
            local_ip: "127.0.0.1",
            local_port: 80,
            server_name: "example.test",
            method: "GET",
            uri: b"/",
            remote_user: None,
            protocol: "HTTP/1.1",
            status: 200,
            bytes_sent: 0,
            bytes_in: 0,
            referer: "",
            user_agent: "",
            host: "example.test",
            vhost_index: None,
            started: Instant::now(),
        };

        let busy = try_writer(&LOG_WRITER_BUSY).unwrap();
        logger.access(&entry);
        drop(busy);
        logger.access(&entry);
    }

    #[test]
    fn format_conversions() {
        let e = AccessEntry {
            remote_ip: "192.0.2.1",
            remote_port: 1234,
            local_ip: "127.0.0.1",
            local_port: 8080,
            server_name: "example.com",
            method: "GET",
            uri: b"/a?b=1",
            remote_user: Some("alice"),
            protocol: "HTTP/1.1",
            status: 200,
            bytes_sent: 0,
            bytes_in: 7,
            referer: "",
            user_agent: "ua\"x",
            host: "example.com",
            vhost_index: None,
            started: Instant::now(),
        };
        let s = format_access(
            "%h %a %l %u %{Referer}i %{User-Agent}i %{Host}i %{Other}i %b %B %I %v %p %U %q %m %H %A %r %% %Z",
            &e,
        );
        assert!(s.starts_with("192.0.2.1 192.0.2.1 - alice - "));
        assert!(s.contains(
            "ua\\\"x example.com - - 0 7 example.com 8080 /a ?b=1 GET HTTP/1.1 127.0.0.1"
        ));
        assert!(s.ends_with("% %Z"));

        let empty = AccessEntry { uri: b"", ..e };
        assert!(format_access("%r %q", &empty).starts_with("- "));
        assert_eq!(format_access("trailing%", &empty), "trailing%");
        assert_eq!(format_access("%{unclosed", &empty), "%");
        assert_eq!(format_access("%{Referer", &empty), "%");
        assert_eq!(format_access("%{Referer}i", &empty), "-");
        assert_eq!(format_access("%{Anything}o %{Anything}e", &empty), "- -");
        assert_eq!(format_access("%{Anything}Z", &empty), "");
        assert_eq!(format_access("%{Referer}", &empty), "");
        assert_eq!(format_access("%<s", &empty), "200");
        assert!(format_access("%D %T %P", &empty).split_whitespace().count() == 3);

        let raw = AccessEntry {
            uri: b"/raw?x=\xff\xfe",
            ..empty
        };
        assert_eq!(
            format_access_bytes("%r|%U|%q|%u", &raw),
            b"GET /raw?x=\xff\xfe HTTP/1.1|/raw|?x=\xff\xfe|alice"
        );

        let repeated = "%r".repeat(MAX_LOG_LINE_BYTES);
        let bounded = format_access_bytes(&repeated, &raw);
        assert_eq!(bounded.len(), MAX_LOG_LINE_BYTES);
        assert!(!bounded.contains(&b'\n'));
    }

    #[test]
    fn time_formats() {
        let e = AccessEntry {
            remote_ip: "127.0.0.1",
            remote_port: 1,
            local_ip: "127.0.0.1",
            local_port: 80,
            server_name: "x",
            method: "GET",
            uri: b"/",
            remote_user: None,
            protocol: "HTTP/1.1",
            status: 200,
            bytes_sent: 0,
            bytes_in: 0,
            referer: "",
            user_agent: "",
            host: "",
            vhost_index: None,
            started: Instant::now(),
        };
        for conv in ["%{msec}t", "%{msec_frac}t", "%{usec}t", "%{sec}t"] {
            assert!(!format_access(conv, &e).is_empty());
        }
        let t = format_access("%{%Y-%m-%d %H:%M:%S %b %a %z %Z %% %Q}t", &e);
        assert!(t.len() > 20);
        assert!(t.contains("+0000 GMT"));
        assert!(t.ends_with("%Q"));
    }

    #[test]
    fn log_format() {
        let started = Instant::now();
        let e = AccessEntry {
            remote_ip: "127.0.0.1",
            remote_port: 1234,
            local_ip: "127.0.0.1",
            local_port: 80,
            server_name: "example.com",
            method: "GET",
            uri: b"/a?b=1",
            remote_user: None,
            protocol: "HTTP/1.1",
            status: 200,
            bytes_sent: 42,
            bytes_in: 100,
            referer: "-",
            user_agent: "test",
            host: "example.com",
            vhost_index: None,
            started,
        };
        let s = format_access(
            "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"",
            &e,
        );
        assert!(s.starts_with("127.0.0.1 - - ["));
        assert!(s.ends_with(" \"-\" \"test\""));
        assert!(s.contains("\"GET /a?b=1 HTTP/1.1\" 200 42"));
    }

    #[test]
    fn logger_opens_writes_filters_and_reopens_configured_logs() {
        for (name, expected) in [
            ("emerg", Level::Emerg),
            ("alert", Level::Alert),
            ("crit", Level::Crit),
            ("error", Level::Error),
            ("warn", Level::Warn),
            ("notice", Level::Notice),
            ("info", Level::Info),
            ("trace8", Level::Debug),
            ("unknown", Level::Warn),
        ] {
            assert!(Level::parse(name) == expected);
            assert!(!expected.name().is_empty());
        }

        let dir = std::env::temp_dir().join(format!("vapache-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("httpd.conf");
        std::fs::write(
            &conf,
            format!(
                "ServerRoot \"{}\"\n\
                 Listen 127.0.0.1:0\n\
                 ErrorLog logs/error.log\n\
                 LogLevel info\n\
                 LogFormat \"%h %>s %b\" common\n\
                 CustomLog logs/access.log common\n\
                 CustomLog /dev/null \"%h\"\n\
                 <VirtualHost 127.0.0.1:0>\n\
                 CustomLog logs/vhost.log common\n\
                 </VirtualHost>\n",
                dir.display()
            ),
        )
        .unwrap();
        let mut cfg = Config::load(&conf, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        cfg.custom_logs.push(CustomLog {
            path: "logs/quoted.log".into(),
            format: "\"%h %s\"".into(),
            condition: None,
        });
        let logger = Logger::new(&cfg).unwrap();
        assert_eq!(logger.access_log_count(), 4);
        assert!(logger.configuration_matches(&cfg));
        let mut changed_logging = cfg.clone();
        changed_logging.log_level = "debug".into();
        assert!(!logger.configuration_matches(&changed_logging));
        let mut changed_format = cfg.clone();
        changed_format
            .log_formats
            .insert("common".into(), "%h %s".into());
        assert!(!logger.configuration_matches(&changed_format));
        assert!(logger.wants_access_log());
        logger.prepare_permissions(&cfg);
        logger.log(Level::Debug, "test", "filtered");
        logger.error("error\nline");
        logger.warn("warning");
        logger.info("information");

        let entry = AccessEntry {
            remote_ip: "192.0.2.1",
            remote_port: 1234,
            local_ip: "127.0.0.1",
            local_port: 80,
            server_name: "example.test",
            method: "GET",
            uri: b"/",
            remote_user: None,
            protocol: "HTTP/1.1",
            status: 200,
            bytes_sent: 5,
            bytes_in: 0,
            referer: "",
            user_agent: "",
            host: "example.test",
            vhost_index: None,
            started: Instant::now(),
        };

        let log_guard = try_writer(&LOG_WRITER_BUSY).unwrap();
        assert!(LOG_WRITER_BUSY.load(Ordering::Acquire));
        logger.error("deliberately dropped");
        logger.access(&entry);
        drop(log_guard);
        logger.access(&entry);
        logger.access(&AccessEntry {
            vhost_index: Some(0),
            ..entry
        });

        let mut saturated_logger = Logger::new(&cfg).unwrap();
        saturated_logger.resource_budget = Arc::new(crate::resource::ResourceBudget::default());
        assert!(saturated_logger
            .resource_budget
            .try_log_bytes(None, crate::resource::MAX_LOG_BYTES_PER_SECOND));
        saturated_logger.error("rate limited");
        saturated_logger.access(&entry);

        logger.reopen().unwrap();
        drop(logger);
        assert!(std::fs::read_to_string(dir.join("logs/error.log"))
            .unwrap()
            .contains("error\\x0aline"));
        assert!(std::fs::read_to_string(dir.join("logs/access.log"))
            .unwrap()
            .contains("192.0.2.1 200 5"));
        assert!(std::fs::read_to_string(dir.join("logs/vhost.log"))
            .unwrap()
            .contains("192.0.2.1 200 5"));

        let budget = std::sync::Arc::new(crate::resource::ResourceBudget::default());
        assert!(open_log("syslog:local0", &dir, None, &budget).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn root_managed_relative_log_symlink_is_canonicalized() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!("vapache-log-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dir = base.join("root");
        let target = base.join("target");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        symlink(&target, dir.join("logs")).unwrap();

        let budget = std::sync::Arc::new(crate::resource::ResourceBudget::default());
        let mut log = open_log("logs/error.log", &dir, None, &budget).unwrap();
        writeln!(log, "through canonical parent").unwrap();
        drop(log);
        assert!(std::fs::read_to_string(target.join("error.log"))
            .unwrap()
            .contains("through canonical parent"));
        assert!(open_log(
            "logs/rejected.log",
            &dir,
            Some(crate::files::effective_uid()),
            &budget,
        )
        .is_err());

        std::fs::remove_dir_all(base).unwrap();
    }
}
