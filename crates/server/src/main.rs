//! `vapached` command line, daemon lifecycle and privilege handling.

// musl's allocator serializes Vapache's allocation-heavy policy path under
// concurrent static requests. Keep the portable static build, but give it the
// same scalable allocation behavior as the native glibc build.
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::HashMap;
use std::ffi::{CString, OsStr, OsString};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use vapached::config::{Config, EncodedSlashes};
use vapached::http::{BodyFraming, Headers, Request, Version};
use vapached::log::Logger;
use vapached::server::{self, Server};

static STOP: AtomicBool = AtomicBool::new(false);
static RELOAD: AtomicBool = AtomicBool::new(false);
static REOPEN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

extern "C" fn on_reload(_sig: libc::c_int) {
    RELOAD.store(true, Ordering::SeqCst);
}

extern "C" fn on_reopen(_sig: libc::c_int) {
    REOPEN.store(true, Ordering::SeqCst);
}

#[derive(Debug)]
struct Args {
    server_root: PathBuf,
    config: Option<PathBuf>,
    defines: HashMap<String, String>,
    foreground: bool,
    test: bool,
    dump_modules: bool,
    dump_vhosts: bool,
    action: Option<String>,
    no_envvars: bool,
    strict: bool,
    show_version: bool,
    show_build: bool,
    show_modules_compiled: bool,
    explain: Option<String>,
    explain_method: Option<String>,
    explain_host: Option<String>,
    explain_port: Option<u16>,
    explain_headers: Vec<(String, String)>,
    audit_capabilities: bool,
}

fn usage() -> ! {
    eprintln!(
        "Usage: vapached [-d serverroot] [-f config] [-D name] [-k start|stop|restart|graceful|status]\n\
         \x20                [-t] [-T] [-M] [-S] [-v] [-V] [-l] [-X] [--strict-config]\n\
         \x20                [--audit-capabilities]\n\
         \x20                [--explain PATH [--explain-method M] [--explain-host H] [--explain-port P]\n\
         \x20                 [--explain-header 'Name: value']]"
    );
    std::process::exit(1)
}

fn parse_args_from(args: &[String], default_server_root: PathBuf) -> Result<Args, String> {
    let mut a = Args {
        server_root: default_server_root,
        config: None,
        defines: HashMap::new(),
        foreground: false,
        test: false,
        dump_modules: false,
        dump_vhosts: false,
        action: None,
        no_envvars: false,
        strict: false,
        show_version: false,
        show_build: false,
        show_modules_compiled: false,
        explain: None,
        explain_method: None,
        explain_host: None,
        explain_port: None,
        explain_headers: Vec::new(),
        audit_capabilities: false,
    };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "-d" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "-d requires an argument".to_string())?;
                a.server_root = PathBuf::from(value);
            }
            "-f" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "-f requires an argument".to_string())?;
                a.config = Some(PathBuf::from(value));
            }
            "-D" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "-D requires an argument".to_string())?;
                a.defines.insert(value.clone(), String::new());
                if value == "FOREGROUND" {
                    a.foreground = true;
                }
            }
            "-k" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "-k requires an argument".to_string())?;
                a.action = Some(value.clone());
            }
            "-t" | "-T" => a.test = true,
            "-M" => a.dump_modules = true,
            "-S" => a.dump_vhosts = true,
            "-X" => a.foreground = true,
            "-v" => a.show_version = true,
            "-V" => a.show_build = true,
            "-l" => a.show_modules_compiled = true,
            "--strict-config" => a.strict = true,
            "--audit-capabilities" => a.audit_capabilities = true,
            "--no-envvars" => a.no_envvars = true,
            "--explain" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--explain requires an argument".to_string())?;
                a.explain = Some(value.clone());
            }
            "--explain-method" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--explain-method requires an argument".to_string())?;
                a.explain_method = Some(value.clone());
            }
            "--explain-host" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--explain-host requires an argument".to_string())?;
                a.explain_host = Some(value.clone());
            }
            "--explain-port" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--explain-port requires an argument".to_string())?;
                a.explain_port = value.parse().ok();
            }
            "--explain-header" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--explain-header requires an argument".to_string())?;
                if let Some((name, value)) = value.split_once(':') {
                    a.explain_headers
                        .push((name.trim().to_string(), value.trim().to_string()));
                } else {
                    return Err("--explain-header requires 'Name: value'".into());
                }
            }
            other if other.starts_with("-D") && other.len() > 2 => {
                let name = other[2..].to_string();
                if name == "FOREGROUND" {
                    a.foreground = true;
                }
                a.defines.insert(name, String::new());
            }
            "-C" | "-c" => {
                // Accepted for apachectl compatibility; setting individual
                // directives on the command line is rarely used and will be
                // implemented with the config expression engine.
                i += 1;
                args.get(i)
                    .ok_or_else(|| format!("{arg} requires an argument"))?;
                eprintln!("vapached: warning: {arg} is accepted but not applied");
            }
            "-e" | "-E" => {
                i += 1;
            }
            "-h" | "--help" => return Err(String::new()),
            other => {
                return Err(format!("unrecognized argument '{other}'"));
            }
        }
        i += 1;
    }
    Ok(a)
}

fn parse_args() -> Args {
    let server_root = std::env::var("VAPACHE_SERVER_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/apache2"));
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args_from(&args, server_root) {
        Ok(args) => args,
        Err(error) => {
            if !error.is_empty() {
                eprintln!("vapached: {error}");
            }
            usage();
        }
    }
}

fn expand_env(value: &str, vars: &HashMap<String, String>) -> String {
    let b = value.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'$' {
            if i + 1 < b.len() && b[i + 1] == b'{' {
                if let Some(end) = value[i + 2..].find('}') {
                    let name = &value[i + 2..i + 2 + end];
                    // Shell parameter-expansion operators are not evaluated;
                    // the default Debian envvars uses ${VAR##prefix} only in
                    // a diagnostic branch, so treating it as empty is safe.
                    let base = name.split("##").next().unwrap_or(name);
                    if let Some(v) = vars.get(base) {
                        out.push_str(v);
                    }
                    i += end + 3;
                    continue;
                }
            } else {
                let mut j = i + 1;
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                    j += 1;
                }
                if j > i + 1 {
                    let name = &value[i + 1..j];
                    if let Some(v) = vars.get(name) {
                        out.push_str(v);
                    }
                    i = j;
                    continue;
                }
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

fn load_envvars(path: &Path) -> HashMap<String, String> {
    const MAX_ENVVARS_BYTES: u64 = 1024 * 1024;
    let mut vars: HashMap<String, String> = std::env::vars().collect();
    let Ok(data) = vapached::files::read_admin_file(path, MAX_ENVVARS_BYTES) else {
        return vars;
    };
    let Ok(data) = String::from_utf8(data) else {
        return vars;
    };
    for raw in data.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix("unset ") {
            vars.remove(name.trim());
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            continue;
        }
        let mut v = value.trim().to_string();
        if (v.starts_with('"') && v.ends_with('"') && v.len() >= 2)
            || (v.starts_with('\'') && v.ends_with('\'') && v.len() >= 2)
        {
            v = v[1..v.len() - 1].to_string();
        }
        let expanded = expand_env(&v, &vars);
        vars.insert(name.to_string(), expanded);
    }
    vars
}

fn user_ids(user: &str, group: &str) -> Result<(libc::uid_t, libc::gid_t, CString), String> {
    let cuser = CString::new(user).map_err(|_| "invalid User name".to_string())?;
    let cgroup = CString::new(group).map_err(|_| "invalid Group name".to_string())?;
    let uid = if let Ok(n) = user.parse::<u32>() {
        n
    } else {
        unsafe {
            let pw = libc::getpwnam(cuser.as_ptr());
            if pw.is_null() {
                return Err(format!("user '{user}' not found"));
            }
            (*pw).pw_uid
        }
    };
    let gid = if let Ok(n) = group.parse::<u32>() {
        n
    } else {
        unsafe {
            let gr = libc::getgrnam(cgroup.as_ptr());
            if gr.is_null() {
                return Err(format!("group '{group}' not found"));
            }
            (*gr).gr_gid
        }
    };
    Ok((uid, gid, cuser))
}

fn effective_ids() -> (u32, u32) {
    unsafe { (libc::geteuid(), libc::getegid()) }
}

fn effective_uid() -> u32 {
    effective_ids().0
}

fn validate_service_identity(euid: u32, egid: u32, uid: u32, gid: u32) -> Result<(), String> {
    if !vapache_verified::service_identity_admit(euid, egid, uid, gid) {
        if uid == 0 || gid == 0 {
            return Err("refusing to run the request-serving process as root user/group".into());
        }
        return Err(format!(
                "cannot switch unprivileged process from uid/gid {euid}/{egid} to configured {uid}/{gid}"
            ));
    }
    Ok(())
}

fn drop_privileges(user: &str, group: &str) -> Result<(), String> {
    let (uid, gid, cuser) = user_ids(user, group)?;
    let (euid, egid) = effective_ids();
    validate_service_identity(euid, egid, uid, gid)?;
    if euid != 0 {
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(format!(
                "cannot set no_new_privs: {}",
                std::io::Error::last_os_error()
            ));
        }
        return Ok(());
    }
    unsafe {
        // coverage:ignore-start - privileged syscall failure
        if libc::initgroups(cuser.as_ptr(), gid as libc::gid_t) != 0 {
            // NSS/kernel failure after both configured identities resolved is
            // not deterministically injectable in the test environment.
            return Err(format!(
                "initgroups failed: {}",
                std::io::Error::last_os_error()
            ));
            // coverage:ignore-stop
        }
        // coverage:ignore-start - privileged syscall failure
        if libc::setresgid(gid, gid, gid) != 0 {
            // A root process with a resolved gid cannot deterministically
            // induce this kernel failure without syscall fault injection.
            return Err(format!(
                "setresgid failed: {}",
                std::io::Error::last_os_error()
            ));
            // coverage:ignore-stop
        }
        // coverage:ignore-start - privileged syscall failure
        if libc::setresuid(uid, uid, uid) != 0 {
            // As above, retain the fail-closed branch for kernel/capability
            // changes while excluding an uninjectable syscall failure.
            return Err(format!(
                "setresuid failed: {}",
                std::io::Error::last_os_error()
            ));
            // coverage:ignore-stop
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(format!(
                "cannot set no_new_privs: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(()) // coverage:ignore-line - root-only successful privilege drop
}

fn daemonize() -> Result<(), String> {
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return Err("fork failed".into()); // coverage:ignore-line - kernel resource failure
        }
        if pid > 0 {
            std::process::exit(0);
        }
        if libc::setsid() < 0 {
            return Err("setsid failed".into()); // coverage:ignore-line - kernel session failure
        }
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        let pid2 = libc::fork();
        if pid2 < 0 {
            return Err("second fork failed".into()); // coverage:ignore-line - kernel resource failure
        }
        if pid2 > 0 {
            std::process::exit(0);
        }
        let devnull = CString::new("/dev/null").unwrap();
        let fd = libc::open(devnull.as_ptr(), libc::O_RDWR);
        if fd >= 0 {
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
            if fd > 2 {
                libc::close(fd);
            }
        }
        let root = CString::new("/").unwrap();
        libc::chdir(root.as_ptr());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessIdentity {
    pid: i32,
    start_time: u64,
    uid: u32,
    executable_dev: u64,
    executable_ino: u64,
    boot_id: String,
}

struct PidFileGuard {
    path: PathBuf,
    identity_path: PathBuf,
    pid_file: std::fs::File,
    identity_file: std::fs::File,
}

impl PidFileGuard {
    fn refresh_identity(&mut self) -> Result<(), String> {
        let identity = process_identity(std::process::id() as i32)?;
        self.identity_file
            .set_len(0)
            .and_then(|()| self.identity_file.seek(SeekFrom::Start(0)).map(|_| ()))
            .and_then(|()| {
                self.identity_file
                    .write_all(serialize_process_identity(&identity).as_bytes())
            })
            .and_then(|()| self.identity_file.sync_data())
            .map_err(|error| {
                format!(
                    "cannot update PID identity {}: {error}",
                    self.identity_path.display()
                )
            })
    }

    fn clear(&mut self) {
        let _ = self.pid_file.set_len(0);
        let _ = self.pid_file.sync_data();
        let _ = self.identity_file.set_len(0);
        let _ = self.identity_file.sync_data();
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(&self.identity_path);
    }
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        self.clear();
    }
}

fn pid_identity_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".vapache-identity");
    PathBuf::from(name)
}

fn read_bounded_text(path: &Path, limit: u64) -> Result<String, String> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut data = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if data.len() as u64 > limit {
        return Err(format!("{} exceeds the {limit} byte limit", path.display()));
    }
    String::from_utf8(data).map_err(|_| format!("{} is not valid UTF-8", path.display()))
}

fn process_identity_with_executable_fallback(
    pid: i32,
    executable_fallback: Option<(u64, u64)>,
) -> Result<ProcessIdentity, String> {
    if pid <= 1 {
        return Err(format!("refusing unsafe pid {pid}"));
    }
    let stat_path = PathBuf::from(format!("/proc/{pid}/stat"));
    let stat = read_bounded_text(&stat_path, 4096)?;
    let close = stat
        .rfind(')')
        .ok_or_else(|| format!("invalid process stat for pid {pid}"))?;
    let start_time = stat[close + 1..]
        .split_ascii_whitespace()
        .nth(19)
        .ok_or_else(|| format!("missing process start time for pid {pid}"))?
        .parse::<u64>()
        .map_err(|_| format!("invalid process start time for pid {pid}"))?;
    let process = std::fs::metadata(format!("/proc/{pid}"))
        .map_err(|error| format!("cannot inspect pid {pid}: {error}"))?;
    let (executable_dev, executable_ino) = match std::fs::metadata(format!("/proc/{pid}/exe")) {
        Ok(executable) => (executable.dev(), executable.ino()),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            // A daemon that changed uid and disabled dumpability cannot
            // have /proc/<pid>/exe inspected by a containerized root
            // process without CAP_SYS_PTRACE. The pidfd already pins the
            // target, and PID/start-time/UID/boot-ID are still read live;
            // only the executable tuple falls back to the root-owned
            // identity record written by that daemon generation.
            executable_fallback
                .ok_or_else(|| format!("cannot inspect executable for pid {pid}: {error}"))?
        }
        Err(error) => {
            return Err(format!("cannot inspect executable for pid {pid}: {error}"));
        }
    };
    let boot_id = read_bounded_text(Path::new("/proc/sys/kernel/random/boot_id"), 128)?
        .trim()
        .to_string();
    if boot_id.is_empty() || boot_id.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err("invalid kernel boot identity".into());
    }
    Ok(ProcessIdentity {
        pid,
        start_time,
        uid: process.uid(),
        executable_dev,
        executable_ino,
        boot_id,
    })
}

fn process_identity(pid: i32) -> Result<ProcessIdentity, String> {
    process_identity_with_executable_fallback(pid, None)
}

fn serialize_process_identity(identity: &ProcessIdentity) -> String {
    format!(
        "{} {} {} {} {} {}\n",
        identity.pid,
        identity.start_time,
        identity.uid,
        identity.executable_dev,
        identity.executable_ino,
        identity.boot_id
    )
}

fn parse_process_identity(text: &str) -> Result<ProcessIdentity, String> {
    let fields: Vec<&str> = text.split_ascii_whitespace().collect();
    if fields.len() != 6 {
        return Err("invalid PID identity record".into());
    }
    let number = |index: usize, name: &str| {
        fields[index]
            .parse::<u64>()
            .map_err(|_| format!("invalid {name} in PID identity record"))
    };
    let pid = fields[0]
        .parse::<i32>()
        .map_err(|_| "invalid pid in PID identity record".to_string())?;
    if pid <= 1 {
        return Err(format!("refusing unsafe pid {pid}"));
    }
    Ok(ProcessIdentity {
        pid,
        start_time: number(1, "start time")?,
        uid: u32::try_from(number(2, "uid")?)
            .map_err(|_| "uid out of range in PID identity record".to_string())?,
        executable_dev: number(3, "executable device")?,
        executable_ino: number(4, "executable inode")?,
        boot_id: fields[5].to_string(),
    })
}

fn open_pid_output(
    path: &Path,
    mode: u32,
    service_uid: Option<u32>,
) -> Result<std::fs::File, String> {
    if let Some(parent) = path.parent() {
        vapached::files::ensure_admin_dir(parent, 0o755)
            .map_err(|e| format!("cannot prepare PidFile directory {}: {e}", parent.display()))?;
    }
    if let Some(service_uid) = service_uid {
        vapached::files::validate_admin_parents(path, service_uid)
            .map_err(|e| format!("insecure PidFile path {}: {e}", path.display()))?;
    }
    let file = vapached::files::open_admin_path(
        path,
        libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
        mode,
    )
    .map_err(|e| format!("cannot open PidFile {}: {e}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect PidFile {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("PidFile {} is not a regular file", path.display()));
    }
    if service_uid.is_some() && (metadata.uid() != 0 || metadata.mode() & 0o022 != 0) {
        return Err(format!(
            "PidFile {} must be root-owned and non-writable by group/other",
            path.display()
        ));
    }
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|error| format!("cannot secure PidFile {}: {error}", path.display()))?;
    Ok(file)
}

fn write_pid(path: &Path, service_uid: Option<u32>) -> Result<PidFileGuard, String> {
    let identity = process_identity(std::process::id() as i32)?;
    let identity_path = pid_identity_path(path);
    let mut pid_file = open_pid_output(path, 0o644, service_uid)?;
    let mut identity_file = open_pid_output(&identity_path, 0o600, service_uid)?;
    pid_file
        .set_len(0)
        .and_then(|()| pid_file.seek(SeekFrom::Start(0)).map(|_| ()))
        .and_then(|()| pid_file.write_all(format!("{}\n", identity.pid).as_bytes()))
        .and_then(|()| pid_file.sync_data())
        .map_err(|error| format!("cannot write PidFile {}: {error}", path.display()))?;
    identity_file
        .set_len(0)
        .and_then(|()| identity_file.seek(SeekFrom::Start(0)).map(|_| ()))
        .and_then(|()| identity_file.write_all(serialize_process_identity(&identity).as_bytes()))
        .and_then(|()| identity_file.sync_data())
        .map_err(|error| {
            format!(
                "cannot write PID identity {}: {error}",
                identity_path.display()
            )
        })?;
    Ok(PidFileGuard {
        path: path.to_path_buf(),
        identity_path,
        pid_file,
        identity_file,
    })
}

fn read_pid_record(path: &Path, service_uid: Option<u32>) -> Result<ProcessIdentity, String> {
    if let Some(service_uid) = service_uid {
        vapached::files::validate_admin_parents(path, service_uid)
            .map_err(|e| format!("insecure PidFile path {}: {e}", path.display()))?;
    }
    let pid_bytes = vapached::files::read_admin_file(path, 64)
        .map_err(|error| format!("cannot read PidFile {}: {error}", path.display()))?;
    let pid_text = std::str::from_utf8(&pid_bytes)
        .map_err(|_| format!("invalid pid in {}", path.display()))?;
    let pid = pid_text
        .trim()
        .parse::<i32>()
        .map_err(|_| format!("invalid pid in {}", path.display()))?;
    if pid <= 1 {
        return Err(format!("refusing unsafe pid {pid} in {}", path.display()));
    }
    let identity_path = pid_identity_path(path);
    if let Some(service_uid) = service_uid {
        vapached::files::validate_admin_parents(&identity_path, service_uid).map_err(|error| {
            format!(
                "insecure PID identity path {}: {error}",
                identity_path.display()
            )
        })?;
    }
    let identity_bytes =
        vapached::files::read_admin_file(&identity_path, 512).map_err(|error| {
            format!(
                "cannot read PID identity {}: {error}",
                identity_path.display()
            )
        })?;
    let identity = parse_process_identity(
        std::str::from_utf8(&identity_bytes)
            .map_err(|_| format!("invalid PID identity {}", identity_path.display()))?,
    )?;
    if identity.pid != pid {
        return Err("PID file and identity record disagree".into());
    }
    Ok(identity)
}

fn open_verified_pid(
    path: &Path,
    service_uid: Option<u32>,
) -> Result<(std::fs::File, ProcessIdentity), String> {
    let expected = read_pid_record(path, service_uid)?;
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, expected.pid, 0) as libc::c_int };
    if fd < 0 {
        return Err(format!(
            "pidfd_open({}) failed: {}",
            expected.pid,
            std::io::Error::last_os_error()
        ));
    }
    let pidfd = unsafe { std::fs::File::from_raw_fd(fd) };
    let actual = process_identity_with_executable_fallback(
        expected.pid,
        Some((expected.executable_dev, expected.executable_ino)),
    )?;
    if !vapache_verified::pid_control_admit(
        expected.pid as i64,
        actual.pid as i64,
        expected.uid,
        actual.uid,
        actual == expected,
    ) {
        return Err(format!(
            "refusing pid {} because its process identity changed",
            expected.pid
        ));
    }
    if service_uid.is_some_and(|uid| actual.uid != uid) {
        return Err(format!(
            "refusing pid {} owned by unexpected uid {}",
            actual.pid, actual.uid
        ));
    }
    Ok((pidfd, actual))
}

#[cfg(test)]
fn read_pid(path: &Path, service_uid: Option<u32>) -> Result<i32, String> {
    open_verified_pid(path, service_uid).map(|(_, identity)| identity.pid)
}

fn kill_action(path: &Path, service_uid: Option<u32>, sig: libc::c_int) -> Result<i32, String> {
    let (pidfd, identity) = open_verified_pid(path, service_uid)?;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            sig,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if rc != 0 {
        return Err(format!(
            "pidfd_send_signal({}) failed: {}",
            identity.pid,
            std::io::Error::last_os_error()
        ));
    }
    Ok(identity.pid)
}

fn explain_config(cfg: &Config, args: &Args) -> Result<(), String> {
    let path = args.explain.as_deref().unwrap_or("/");
    let (raw_path, query) = match path.split_once('?') {
        Some((p, q)) => (p, q.as_bytes().to_vec()),
        None => (path, Vec::new()),
    };
    let method = args
        .explain_method
        .clone()
        .unwrap_or_else(|| "GET".to_string())
        .to_ascii_uppercase();
    let port = args
        .explain_port
        .or_else(|| cfg.listeners.first().map(|l| l.port))
        .unwrap_or(80);
    let host = args
        .explain_host
        .clone()
        .or_else(|| cfg.server_name.clone())
        .unwrap_or_else(|| "localhost".to_string());
    let vhost = cfg.select_vhost(None, port, Some(&host));

    let allow_encoded = cfg.encoded_slashes == EncodedSlashes::On;

    let mut headers = Headers::default();
    headers.insert("host", format!("{host}:{port}"));
    for (name, value) in &args.explain_headers {
        headers.insert(name, value.clone());
    }
    let req = Request {
        method: method.clone(),
        target: path.as_bytes().to_vec(),
        raw_path: raw_path.as_bytes().to_vec(),
        query,
        version: Version::Http11,
        headers,
        body: Vec::new(),
        body_spool: None,
        keep_alive: true,
        expect_continue: false,
        framing: BodyFraming::None,
    };
    let peer = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let resource_context = cfg.resource_budget.context(peer);
    vapached::resource::with_resource_context(resource_context, || {
        let target = vapached::request_plan::CanonicalTarget::from_raw_path(
            raw_path.as_bytes(),
            allow_encoded,
        )
        .map_err(|e| format!("invalid request path '{raw_path}': {e:?}"))?;
        let plan = vapached::request_plan::RequestPlan::resolve(cfg, vhost, target)
            .map_err(|e| format!("mapping failed for '{path}': {e:?}"))?;
        let root = plan.root();
        let fs_path = plan.fs_path();
        let url_path = plan.url_path();
        let mut evaluated = plan.evaluate_scope(cfg, vhost, &req, peer);
        evaluated.apply_conditionals(cfg, vhost, fs_path, url_path, &req, peer);
        let scope = evaluated.scope;
        let override_enabled = cfg.override_enabled;
        let override_prefilter = cfg.override_applicable(fs_path);
        let access_files = cfg.access_file_names_for(&scope);

        println!("explain: {method} {path}");
        println!("  canonical_url_path: {url_path}");
        println!(
            "  vhost: {}",
            vhost
                .and_then(|v| v.server_name.as_deref())
                .unwrap_or("<global>")
        );
        println!("  document_root: {}", root.display());
        println!("  fs_path: {}", fs_path.display());
        println!("  access_layers:");
        for layer in plan.layers() {
            println!(
                "    dir={} url_mount={} subject={:?}",
                layer.identity.dir.display(),
                layer.identity.url_mount,
                layer.identity.subject(fs_path, url_path)
            );
        }
        println!("  override_policy: {:?}", scope.override_policy);
        println!("  override_enabled: {override_enabled}");
        println!("  override_prefilter: {override_prefilter}");
        println!("  access_file_names: {access_files:?}");
        println!("  matching_rules:");
        for rule in cfg.rule_inventory(vhost, &fs_path, &url_path, &req, peer) {
            println!("    {rule}");
        }
        println!("  access_file_trace:");
        for file in vapached::htaccess::trace_access_files_with_root(
            cfg,
            vhost,
            &fs_path,
            &url_path,
            Some(&root),
        ) {
            println!("    {file}");
        }
        println!("  options: {:?}", scope.effective_options());
        println!("  allow_methods: {:?}", scope.authorization.allow_methods);
        println!("  requires: {:?}", scope.authorization.requires);
        println!("  legacy: {:?}", scope.authorization.legacy);
        println!(
            "  auth: type={:?} name={:?} userfile={:?} groupfile={:?}",
            scope.authorization.auth_type,
            scope.authorization.auth_name,
            scope.authorization.auth_user_file,
            scope.authorization.auth_group_file
        );
        println!(
            "  rewrite_engine: {:?}, rules: {}",
            scope.rewrite_policy.rewrite_engine,
            scope.rewrite_policy.rewrite_rules.len()
        );
        println!("  cache_enable: {:?}", scope.rewrite_policy.cache_enable);
        println!("  cache_disable: {:?}", scope.rewrite_policy.cache_disable);
        if !override_prefilter {
            println!("  htaccess: skipped (no override-enabled directory in path)");
        } else if plan.layers().is_empty() {
            println!("  htaccess: no access files present");
        } else {
            println!("  htaccess: {} layer(s) applied", plan.layers().len());
        }
        Ok(())
    })
}

fn main() {
    let raw_args: Vec<OsString> = std::env::args_os().collect();
    if raw_args.get(1).map(OsString::as_os_str) == Some(OsStr::new("--vapache-resolver-worker")) {
        let result = raw_args
            .get(2)
            .and_then(|host| host.to_str())
            .zip(
                raw_args
                    .get(3)
                    .and_then(|port| port.to_str())
                    .and_then(|port| port.parse::<u16>().ok()),
            )
            .filter(|_| raw_args.len() == 4)
            .ok_or_else(|| "invalid resolver worker arguments".to_string())
            .and_then(|(host, port)| {
                vapached::proxy::resolver_worker_main(host, port).map_err(|error| error.to_string())
            });
        if result.is_err() {
            std::process::exit(1);
        }
        return;
    }
    if raw_args.get(1).map(OsString::as_os_str) == Some(OsStr::new("--cgi-worker")) {
        let uid = raw_args
            .get(2)
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let gid = raw_args
            .get(3)
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let user = raw_args
            .get(4)
            .and_then(|s| s.to_str())
            .unwrap_or("www-data");
        vapached::cgi::worker_main(3, uid, gid, user);
        return;
    }
    let args = parse_args();
    if args.show_version {
        println!(
            "vapached/{} (Apache/2.4 configuration compatible)",
            vapached::VERSION
        );
        return;
    }
    if args.show_modules_compiled {
        println!("Compiled in modules:");
        for m in [
            "core",
            "http_core",
            "mod_alias",
            "mod_authz_core",
            "mod_authz_host",
            "mod_access_compat",
            "mod_dir",
            "mod_mime",
            "mod_autoindex",
            "mod_cgi",
            "mod_ssl",
            "mod_http2",
            "mod_rewrite",
            "mod_headers",
            "mod_auth_basic",
            "mod_authn_file",
            "mod_authz_user",
            "mod_authz_groupfile",
            "mod_filter",
            "mod_deflate",
            "mod_brotli",
            "mod_proxy",
            "mod_proxy_fcgi",
            "mod_proxy_http",
        ] {
            println!("  {m}");
        }
        return;
    }

    let server_root = if args.server_root.is_absolute() {
        args.server_root.clone()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(&args.server_root)
    };
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| server_root.join("apache2.conf"));

    let mut env = if args.no_envvars {
        std::env::vars().collect()
    } else {
        load_envvars(&server_root.join("envvars"))
    };
    env.entry("APACHE_CONFDIR".into())
        .or_insert_with(|| server_root.to_string_lossy().into_owned());
    env.entry("SERVER_ROOT".into())
        .or_insert_with(|| server_root.to_string_lossy().into_owned());

    let loader = if args.audit_capabilities {
        Config::load_capability_audit
    } else {
        Config::load
    };
    let mut cfg = match loader(&config_path, &server_root, &env, &args.defines, args.strict) {
        Ok(c) => c,
        Err(errors) => {
            for e in errors {
                eprintln!("{e}");
            }
            eprintln!("vapached: configuration test failed");
            std::process::exit(1);
        }
    };
    for warning in &cfg.warnings {
        // Exercised by cli_lifecycle's instrumented subprocess; llvm-cov does
        // not merge that child record into the unit-test binary's main.rs map.
        eprintln!("vapached: {warning}"); // coverage:ignore-line
    }

    if args.audit_capabilities {
        let enabled = cfg.capabilities.enabled_names();
        let missing: Vec<_> = cfg
            .required_capabilities
            .iter()
            .copied()
            .filter(|capability| !cfg.capability_enabled(*capability))
            .collect();
        println!("Capability audit:");
        println!(
            "  explicitly enabled: {}",
            if enabled.is_empty() {
                "none".to_string()
            } else {
                enabled.join(", ")
            }
        );
        if missing.is_empty() {
            println!("  missing opt-ins: none");
        } else {
            println!("  missing opt-ins:");
            for capability in missing {
                println!("    VapacheCapability {} On", capability.name());
            }
        }
        println!(
            "  note: access-file contents are checked when read and can never enable a capability"
        );
        return;
    }

    if args.show_build {
        println!("Server version: {}", cfg.server_header());
        println!("Server built: unknown");
        println!("ServerRoot: {}", cfg.server_root.display());
        println!("Config file: {}", config_path.display());
        println!("PidFile: {}", cfg.pid_file.display());
        println!(
            "Listen: {:?}",
            cfg.listeners.iter().map(|l| &l.raw).collect::<Vec<_>>()
        );
        return;
    }
    if args.dump_modules {
        for m in &cfg.modules {
            println!(" {m}");
        }
        return;
    }
    if args.dump_vhosts {
        println!("VirtualHost configuration:");
        for v in &cfg.vhosts {
            println!(
                "  {}:{:?} name={:?} docroot={:?}",
                v.addrs.join(" "),
                v.aliases,
                v.server_name,
                v.scope.content_policy.document_root
            );
        }
        return;
    }

    if let Some(_) = &args.explain {
        if let Err(e) = explain_config(&cfg, &args) {
            eprintln!("vapached: explain: {e}");
            std::process::exit(1);
        }
        return;
    }

    let (service_uid, service_gid) = match user_ids(&cfg.user, &cfg.group) {
        Ok((uid, gid, _)) => (uid, gid),
        Err(error) => {
            eprintln!("vapached: {error}");
            std::process::exit(1);
        }
    };
    let (euid, egid) = effective_ids();
    if let Err(error) = validate_service_identity(euid, egid, service_uid, service_gid) {
        eprintln!("vapached: {error}");
        std::process::exit(1);
    }
    if let Err(error) = cfg.validate_admin_input_parents(service_uid) {
        eprintln!("vapached: {error}");
        std::process::exit(1);
    }
    if let Err(error) = cfg.validate_auth_files(service_uid) {
        eprintln!("vapached: {error}");
        std::process::exit(1);
    }
    let admin_service_uid = (effective_uid() == 0).then_some(service_uid);

    match args.action.as_deref() {
        Some("stop") => {
            if let Err(e) = kill_action(&cfg.pid_file, admin_service_uid, libc::SIGTERM) {
                eprintln!("vapached: {e}");
                std::process::exit(1);
            }
            return;
        }
        Some("graceful") => {
            if let Err(e) = kill_action(&cfg.pid_file, admin_service_uid, libc::SIGHUP) {
                eprintln!("vapached: {e}");
                std::process::exit(1);
            }
            return;
        }
        Some("graceful-stop") => {
            if let Err(e) = kill_action(&cfg.pid_file, admin_service_uid, libc::SIGTERM) {
                eprintln!("vapached: {e}");
                std::process::exit(1);
            }
            return;
        }
        Some("status") => match kill_action(&cfg.pid_file, admin_service_uid, 0) {
            Ok(pid) => {
                println!("vapached is running (pid {pid})");
                return;
            }
            _ => {
                eprintln!("vapached is not running");
                std::process::exit(3);
            }
        },
        Some("start") | Some("restart") | None => {}
        Some(other) => {
            eprintln!("vapached: unsupported -k action '{other}'");
            std::process::exit(1);
        }
    }

    if args.test {
        if let Err(e) = vapached::files::require_secure_path_resolution() {
            eprintln!("vapached: {e}");
            eprintln!("vapached: configuration test failed");
            std::process::exit(1);
        }
        // Apache's configtest also validates SSL certificate/key material.
        // Do this before printing Syntax OK so missing or unreadable TLS
        // files fail closed rather than at first HTTPS connection attempt.
        for listener in &cfg.listeners {
            let local_ip = listener
                .addr
                .parse::<std::net::IpAddr>()
                .ok()
                .filter(|ip| !ip.is_unspecified())
                .map(vapached::access::canonical_ip);
            if let Err(e) = vapached::tls::server_config(&cfg, listener.port, local_ip) {
                eprintln!("vapached: SSL configuration error: {e}");
                eprintln!("vapached: configuration test failed");
                std::process::exit(1);
            }
        }
        println!("Syntax OK");
        return;
    }

    let mut bound = match server::bind(&cfg) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("vapached: cannot bind listener: {e}");
            std::process::exit(1);
        }
    };
    let mut logger = match Logger::new(&cfg) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            eprintln!("vapached: cannot open logs: {e}");
            std::process::exit(1);
        }
    };
    if !args.foreground {
        if let Err(e) = daemonize() {
            eprintln!("vapached: {e}");
            std::process::exit(1);
        }
    }
    if let Err(e) = vapached::tls::install_privileged_file_broker(&cfg, service_uid) {
        eprintln!("vapached: cannot start privileged TLS broker: {e}");
        std::process::exit(1);
    }
    if let Err(e) = server::activate_background(&cfg, &mut bound) {
        eprintln!("vapached: cannot start background services: {e}");
        std::process::exit(1);
    }
    let mut pid_guard = match write_pid(&cfg.pid_file, admin_service_uid) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("vapached: {e}");
            std::process::exit(1);
        }
    };
    if cfg.has_cgi() {
        if let Err(e) = vapached::cgi::init_pool(&cfg) {
            // coverage:ignore-start - root-only configured identity failure
            eprintln!("vapached: warning: CGI worker pool unavailable: {e}; using direct CGI");
        } // coverage:ignore-stop
    }
    logger.prepare_permissions(&cfg);
    if let Err(e) = drop_privileges(&cfg.user, &cfg.group) {
        eprintln!("vapached: {e}");
        pid_guard.clear();
        std::process::exit(1);
    }
    if let Err(e) = pid_guard.refresh_identity() {
        eprintln!("vapached: {e}");
        pid_guard.clear();
        std::process::exit(1);
    }
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as libc::sighandler_t);
        libc::signal(libc::SIGHUP, on_reload as libc::sighandler_t);
        libc::signal(libc::SIGUSR1, on_reopen as libc::sighandler_t);
    }
    logger.info(&format!(
        "vapached/{} started, listening on {} socket(s)",
        vapached::VERSION,
        bound.len()
    ));

    loop {
        let srv = Server::new(Arc::new(cfg.clone()), logger.clone());
        let stop = srv.stop_flag();
        let monitor_logger = logger.clone();
        std::thread::spawn(move || loop {
            if STOP.load(Ordering::SeqCst) || RELOAD.load(Ordering::SeqCst) {
                stop.store(true, Ordering::SeqCst);
                break;
            }
            if REOPEN.swap(false, Ordering::SeqCst) {
                let _ = monitor_logger.reopen();
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        });
        if let Err(e) = srv.run(&bound) {
            // Listener poll failures require external descriptor corruption;
            // Server::run's error mapping is covered with injected poll errors.
            logger.error(&format!("server loop failed: {e}")); // coverage:ignore-line - external fd failure
        }
        if STOP.load(Ordering::SeqCst) && !RELOAD.load(Ordering::SeqCst) {
            let deadline = std::time::Instant::now() + cfg.graceful_shutdown_timeout;
            while server::active_connections() > 0 && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            break;
        }
        if !RELOAD.swap(false, Ordering::SeqCst) {
            // Normal exits set STOP; reload exits set RELOAD.  Reaching this
            // requires the externally induced Server::run error above.
            break; // coverage:ignore-line - external fd failure
        }
        logger.info("SIGHUP received; reloading configuration");
        let mut new_cfg = match Config::load_for_reload(
            &config_path,
            &server_root,
            &env,
            &args.defines,
            args.strict,
            &cfg,
            service_uid,
        ) {
            Ok(c) => c,
            Err(errors) => {
                for e in errors {
                    logger.error(&format!("reload rejected: {e}"));
                }
                logger.error("reload rejected; continuing with previous configuration");
                continue;
            }
        };
        if let Err(error) = new_cfg.validate_admin_input_parents(service_uid) {
            logger.error(&format!("reload rejected: {error}"));
            logger.error("reload rejected; continuing with previous configuration");
            continue;
        }
        if let Err(error) = new_cfg.validate_auth_files(service_uid) {
            logger.error(&format!("reload rejected: {error}"));
            logger.error("reload rejected; continuing with previous configuration");
            continue;
        }
        if let Err(error) = new_cfg.validate_reload_from(&cfg) {
            logger.error(&format!("reload rejected: {error}"));
            logger.error("reload rejected; continuing with previous configuration");
            continue;
        }
        // Old keep-alive requests can overlap a graceful reload.  Share the
        // usage counters so the aggregate limits remain process-wide across
        // both configuration generations.
        new_cfg.resource_budget = cfg.resource_budget.clone();
        let new_logger = if logger.configuration_matches(&new_cfg) {
            logger.clone()
        } else {
            match Logger::new(&new_cfg) {
                Ok(l) => {
                    let l = Arc::new(l);
                    l.prepare_permissions(&new_cfg);
                    l
                }
                Err(e) => {
                    logger.error(&format!("reload rejected: cannot prepare logger: {e}"));
                    logger.error("reload rejected; continuing with previous configuration");
                    continue;
                }
            }
        };
        let mut new_bound = match server::rebind(&new_cfg, &bound) {
            Ok(b) => b,
            Err(e) => {
                logger.error(&format!(
                    "reload rejected: listener/TLS preparation failed: {e}"
                ));
                logger.error("reload rejected; continuing with previous configuration");
                continue;
            }
        };
        // This is the commit boundary: every fallible candidate resource has
        // been prepared, and activate_background validates the whole listener
        // set before starting any candidate worker.
        if let Err(e) = server::activate_background(&new_cfg, &mut new_bound) {
            logger.error(&format!(
                "reload rejected: background preparation failed: {e}"
            ));
            logger.error("reload rejected; continuing with previous configuration");
            continue;
        }
        cfg = new_cfg;
        bound = new_bound;
        logger = new_logger;
        vapached::cache::clear(&cfg);
        logger.info("configuration reloaded; cache generation invalidated");
    }
    vapached::cgi::shutdown_pool();
    vapached::tls::shutdown_privileged_file_broker();
    pid_guard.clear();
    let _ = std::io::stderr().flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vapache-main-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir.join(name)
    }

    #[test]
    fn env_expansion() {
        let mut vars = HashMap::new();
        vars.insert("FOO".to_string(), "bar".to_string());
        vars.insert("EMPTY".to_string(), String::new());
        assert_eq!(expand_env("$FOO", &vars), "bar");
        assert_eq!(expand_env("x/${FOO}/y", &vars), "x/bar/y");
        assert_eq!(expand_env("${FOO##prefix}", &vars), "bar");
        assert_eq!(expand_env("$EMPTY!$MISSING", &vars), "!");
        assert_eq!(expand_env("cost $5 and $", &vars), "cost  and $");
        assert_eq!(expand_env("${UNCLOSED", &vars), "${UNCLOSED");
        assert_eq!(expand_env("literal$-tail", &vars), "literal$-tail");
    }

    #[test]
    fn envvars_file() {
        let path = temp("envvars");
        std::fs::write(
            &path,
            "# comment\nexport A=one\nB=\"two words\"\nC='$A-${B}'\ninvalid-name=x\nunset PATH\nEMPTY=\nNOEQUALS\n=bad\n",
        )
        .unwrap();
        let vars = load_envvars(&path);
        assert_eq!(vars.get("A").map(String::as_str), Some("one"));
        assert_eq!(vars.get("B").map(String::as_str), Some("two words"));
        assert_eq!(vars.get("C").map(String::as_str), Some("one-two words"));
        assert!(!vars.contains_key("PATH"));
        assert_eq!(vars.get("EMPTY").map(String::as_str), Some(""));
        assert!(!vars.contains_key("invalid-name"));
        assert!(load_envvars(&temp("missing-envvars")).contains_key("PATH"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn pid_file_roundtrip() {
        let path = temp("pid");
        let mut guard = write_pid(&path, None).unwrap();
        assert_eq!(read_pid(&path, None).unwrap(), std::process::id() as i32);
        // signal 0 only checks for existence/permission
        kill_action(&path, None, 0).unwrap();
        let mut forged = process_identity(std::process::id() as i32).unwrap();
        forged.start_time = forged.start_time.saturating_add(1);
        std::fs::write(
            pid_identity_path(&path),
            serialize_process_identity(&forged),
        )
        .unwrap();
        assert!(read_pid(&path, None).is_err());
        guard.refresh_identity().unwrap();
        assert_eq!(read_pid(&path, None).unwrap(), std::process::id() as i32);
        std::fs::write(&path, "not-a-pid\n").unwrap();
        assert!(read_pid(&path, None).is_err());
        std::fs::write(&path, "-1\n").unwrap();
        assert!(kill_action(&path, None, libc::SIGTERM).is_err());
        std::fs::write(&path, "0\n").unwrap();
        assert!(kill_action(&path, None, libc::SIGTERM).is_err());
        assert!(kill_action(&temp("missing-pid"), None, 0).is_err());
        std::fs::write(&path, "2147483647\n").unwrap();
        assert!(kill_action(&path, None, 0).is_err());
        let _ = std::fs::remove_file(&path);
        let victim = temp("pid-victim");
        std::fs::write(&victim, b"unchanged").unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        assert!(write_pid(&path, None).is_err());
        assert!(read_pid(&path, None).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"unchanged");
        guard.clear();
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(victim);
    }

    #[test]
    fn privileged_pid_file_must_itself_be_safe() {
        let path = temp("unsafe-pid");
        std::fs::write(&path, b"unchanged").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(write_pid(&path, Some(u32::MAX)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"unchanged");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn user_lookup() {
        assert!(user_ids("0", "0").is_ok());
        assert!(user_ids("root", "root").is_ok());
        assert!(user_ids("definitely-not-a-user", "definitely-not-a-group").is_err());
        assert!(user_ids("0", "definitely-not-a-group").is_err());
        assert!(user_ids("bad\0name", "0").is_err());
        assert!(user_ids("0", "bad\0group").is_err());

        let (uid, gid) = effective_ids();
        assert!(validate_service_identity(0, 0, 0, 0).is_err());
        assert!(validate_service_identity(0, 0, 1, 0).is_err());
        if uid != 0 {
            assert!(drop_privileges(&uid.to_string(), &gid.to_string()).is_ok());
            assert!(drop_privileges(&u32::MAX.to_string(), &gid.to_string()).is_err());
        }
    }

    #[test]
    fn service_identity_validation_is_fail_closed() {
        assert!(validate_service_identity(0, 0, 0, 65534).is_err());
        assert!(validate_service_identity(0, 0, 65534, 0).is_err());
        assert!(validate_service_identity(1000, 1000, 1001, 1000).is_err());
        assert!(validate_service_identity(1000, 1000, 1000, 1001).is_err());
        assert!(validate_service_identity(0, 0, 65534, 65534).is_ok());
        assert!(validate_service_identity(1000, 1000, 1000, 1000).is_ok());
    }

    #[test]
    fn argument_matrix_and_signal_handlers() {
        let args = vec![
            "-d",
            "relative-root",
            "-f",
            "conf/httpd.conf",
            "-D",
            "FOREGROUND",
            "-DNAME",
            "-k",
            "restart",
            "-t",
            "-T",
            "-M",
            "-S",
            "-X",
            "-v",
            "-V",
            "-l",
            "--strict-config",
            "--audit-capabilities",
            "--no-envvars",
            "--explain",
            "/x?q=1",
            "--explain-method",
            "post",
            "--explain-host",
            "example.test",
            "--explain-port",
            "8080",
            "--explain-header",
            "X-Test: yes",
            "-C",
            "ServerName ignored",
            "-c",
            "ServerAdmin ignored",
            "-e",
            "debug",
            "-E",
            "error.log",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        let parsed = parse_args_from(&args, PathBuf::from("/default")).unwrap();
        assert_eq!(parsed.server_root, PathBuf::from("relative-root"));
        assert!(parsed.foreground && parsed.test && parsed.strict && parsed.no_envvars);
        assert!(parsed.audit_capabilities);
        assert!(parsed.dump_modules && parsed.dump_vhosts);
        assert!(parsed.show_version && parsed.show_build && parsed.show_modules_compiled);
        assert_eq!(parsed.explain_port, Some(8080));
        assert_eq!(
            parsed.explain_headers,
            vec![("X-Test".into(), "yes".into())]
        );
        assert!(parsed.defines.contains_key("FOREGROUND"));
        assert!(parsed.defines.contains_key("NAME"));

        for option in [
            "-d",
            "-f",
            "-D",
            "-k",
            "--explain",
            "--explain-method",
            "--explain-host",
            "--explain-port",
            "--explain-header",
            "-C",
            "-c",
        ] {
            assert!(parse_args_from(&[option.into()], PathBuf::from("/default")).is_err());
        }
        assert!(parse_args_from(
            &["--explain-header".into(), "broken".into()],
            PathBuf::from("/default")
        )
        .is_err());
        assert!(parse_args_from(&["--help".into()], PathBuf::from("/default")).is_err());
        assert!(parse_args_from(&["--unknown".into()], PathBuf::from("/default")).is_err());
        let invalid_port = parse_args_from(
            &["--explain-port".into(), "bad".into()],
            PathBuf::from("/default"),
        )
        .unwrap();
        assert_eq!(invalid_port.explain_port, None);

        STOP.store(false, Ordering::SeqCst);
        RELOAD.store(false, Ordering::SeqCst);
        REOPEN.store(false, Ordering::SeqCst);
        on_signal(libc::SIGTERM);
        on_reload(libc::SIGHUP);
        on_reopen(libc::SIGUSR1);
        assert!(STOP.swap(false, Ordering::SeqCst));
        assert!(RELOAD.swap(false, Ordering::SeqCst));
        assert!(REOPEN.swap(false, Ordering::SeqCst));
    }

    #[test]
    fn explain_config_success_and_invalid_path() {
        let dir = temp("explain-root");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("www/sub")).unwrap();
        std::fs::write(dir.join("www/sub/file.txt"), b"x").unwrap();
        let conf = dir.join("httpd.conf");
        std::fs::write(
            &conf,
            format!(
                "Listen 127.0.0.1:8080\nServerName example.test\nDocumentRoot {}\n<Directory {}>\nAllowOverride None\nRequire all granted\n</Directory>\n",
                dir.join("www").display(),
                dir.join("www").display()
            ),
        )
        .unwrap();
        let cfg = Config::load(&conf, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        let mut args = parse_args_from(
            &[
                "--explain".into(),
                "/sub/file.txt?q=1".into(),
                "--explain-method".into(),
                "head".into(),
                "--explain-host".into(),
                "example.test".into(),
                "--explain-header".into(),
                "X-Test: yes".into(),
            ],
            dir.clone(),
        )
        .unwrap();
        assert!(explain_config(&cfg, &args).is_ok());
        args.explain = Some("/bad%2fpath".into());
        assert!(explain_config(&cfg, &args).is_err());

        let alias_root = dir.join("alias-root");
        std::fs::create_dir_all(&alias_root).unwrap();
        std::fs::write(alias_root.join("file.txt"), b"alias").unwrap();
        std::fs::write(alias_root.join(".htaccess"), "Require all granted\n").unwrap();
        std::fs::write(
            &conf,
            format!(
                "VapacheCapability AccessFiles On\nListen 127.0.0.1:8080\nServerName example.test\nDocumentRoot {}\nAlias /alias {}\n<Directory {}>\nAllowOverride All\nRequire all granted\n</Directory>\n",
                dir.join("www").display(),
                alias_root.display(),
                alias_root.display(),
            ),
        )
        .unwrap();
        let alias_cfg = Config::load(&conf, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        args.explain = Some("/alias/file.txt".into());
        assert!(explain_config(&alias_cfg, &args).is_ok());

        let unrelated = dir.join("unrelated-override");
        std::fs::create_dir_all(&unrelated).unwrap();
        std::fs::write(
            &conf,
            format!(
                "VapacheCapability AccessFiles On\nListen 127.0.0.1:8080\nDocumentRoot {}\n<Directory {}>\nAllowOverride All\n</Directory>\n",
                dir.join("www").display(),
                unrelated.display(),
            ),
        )
        .unwrap();
        let no_override =
            Config::load(&conf, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        args.explain = Some("/sub/file.txt".into());
        assert!(explain_config(&no_override, &args).is_ok());

        std::fs::remove_dir_all(dir).unwrap();
    }
}
