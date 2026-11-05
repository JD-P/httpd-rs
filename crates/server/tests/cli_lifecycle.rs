#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_vapached")
}

fn test_dir(name: &str) -> PathBuf {
    let sequence = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "vapache-cli-{name}-{}-{sequence}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(path.join("www")).unwrap();
    path
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn service_ids() -> (u32, u32) {
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    if uid == 0 {
        (65534, 65534)
    } else {
        (uid, gid)
    }
}

fn config_text(root: &Path, port: u16, extra: &str) -> String {
    let (uid, gid) = service_ids();
    format!(
        "VapacheCapability AbsoluteRequestTarget On\n\
         VapacheCapability AccessFiles On\n\
         VapacheCapability AutoIndex On\n\
         VapacheCapability Cgi On\n\
         VapacheCapability FastCgi On\n\
         VapacheCapability LegacyAuthz On\n\
         VapacheCapability RequestTrailers On\n\
         VapacheCapability RewriteProgram On\n\
         VapacheCapability ServerStatus On\n\
         VapacheCapability Trace On\n\
         VapacheCapability UnstableFastCgiPaths On\n\
         VapacheCapability MutableAuthFiles On\n\
         ServerRoot {root}\n\
         Listen 127.0.0.1:{port}\n\
         ServerName localhost\n\
         User {uid}\n\
         Group {gid}\n\
         PidFile {root}/vapached.pid\n\
         ErrorLog {root}/error.log\n\
         DocumentRoot {root}/www\n\
         <Directory {root}/www>\n\
         Require all granted\n\
         </Directory>\n\
         {extra}\n",
        root = root.display(),
    )
}

fn write_config(root: &Path, port: u16, extra: &str) -> PathBuf {
    let path = root.join("httpd.conf");
    fs::write(&path, config_text(root, port, extra)).unwrap();
    path
}

fn command(root: &Path, config: &Path) -> Command {
    let mut command = Command::new(binary());
    command.args(["-d", root.to_str().unwrap(), "-f", config.to_str().unwrap()]);
    command
}

fn output(root: &Path, config: &Path, args: &[&str]) -> Output {
    command(root, config).args(args).output().unwrap()
}

fn spawn_foreground(root: &Path, config: &Path, args: &[&str]) -> Child {
    command(root, config)
        .args(args)
        .arg("-X")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn spawn_foreground_with_inherited_fd(root: &Path, config: &Path, fd: i32) -> Child {
    let sentinel = fs::File::open("/dev/null").unwrap();
    let source = sentinel.as_raw_fd();
    let mut command = command(root, config);
    command
        .arg("-X")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Install the descriptor in the child after std::process has prepared its
    // own descriptor table. Vapache must close it before opening any server
    // resource, regardless of the launcher's CLOEXEC discipline.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(source, fd) < 0 || libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn().unwrap()
}

fn wait_until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for vapached lifecycle transition");
}

fn wait_running(root: &Path, config: &Path, port: u16) {
    wait_until(|| {
        // A bound listener can complete the TCP handshake while startup is
        // still publishing its authenticated PID identity and before the
        // accept loop begins.  Use the control-plane status contract as the
        // readiness marker so lifecycle assertions cannot race that window.
        output(root, config, &["-k", "status"]).status.success()
            && TcpStream::connect(("127.0.0.1", port)).is_ok()
    });
}

fn connect_when_ready(port: u16) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => return stream,
            Err(_) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("timed out connecting to vapached: {error}"),
        }
    }
}

fn read_pid(root: &Path) -> i32 {
    fs::read_to_string(root.join("vapached.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn signal(pid: i32, sig: i32) {
    assert_eq!(unsafe { libc::kill(pid, sig) }, 0);
}

fn http_body(port: u16, path: &str) -> Vec<u8> {
    let mut stream = connect_when_ready(port);
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|split| response[split + 4..].to_vec())
        .unwrap_or_default()
}

fn keepalive_body(stream: &mut TcpStream, path: &str) -> Option<Vec<u8>> {
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"
    )
    .ok()?;
    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        response.extend_from_slice(&chunk[..read]);
        let Some(split) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let headers = String::from_utf8_lossy(&response[..split]);
        let length = headers
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
            })
            .unwrap_or(0);
        if response.len() >= split + 4 + length {
            return Some(response[split + 4..split + 4 + length].to_vec());
        }
    }
}

fn wait_success(mut child: Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "vapached exited with {status}");
            return;
        }
        assert!(Instant::now() < deadline, "vapached did not exit");
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn cli_information_explain_and_startup_failures() {
    let root = test_dir("information");
    fs::write(root.join("www/index.txt"), "ok\n").unwrap();
    let port = free_port();
    let config = write_config(&root, port, "");

    for args in [["--help"].as_slice(), ["--not-a-real-option"].as_slice()] {
        assert!(!output(&root, &config, args).status.success());
    }

    for args in [
        &["-v"][..],
        &["-l"][..],
        &["-V"][..],
        &["-M"][..],
        &["-S"][..],
        &["-t"][..],
        &["--explain", "/index.txt", "--explain-header", "X-Test: yes"][..],
    ] {
        let result = output(&root, &config, args);
        assert!(result.status.success(), "{args:?}: {result:?}");
    }

    let audit = output(&root, &config, &["--audit-capabilities"]);
    assert!(audit.status.success(), "{audit:?}");
    let audit_stdout = String::from_utf8_lossy(&audit.stdout);
    assert!(audit_stdout.contains("explicitly enabled: AbsoluteRequestTarget"));
    assert!(audit_stdout.contains("missing opt-ins: none"));

    let missing_capability = root.join("missing-capability.conf");
    fs::write(&missing_capability, "Listen 127.0.0.1:0\nTraceEnable On\n").unwrap();
    let audit = output(&root, &missing_capability, &["--audit-capabilities"]);
    assert!(audit.status.success(), "{audit:?}");
    assert!(String::from_utf8_lossy(&audit.stdout).contains("VapacheCapability Trace On"));

    assert_eq!(
        output(&root, &config, &["-k", "status"]).status.code(),
        Some(3)
    );
    assert!(!output(&root, &config, &["-k", "stop"]).status.success());
    assert!(!output(&root, &config, &["-k", "graceful"]).status.success());
    assert!(!output(&root, &config, &["-k", "graceful-stop"])
        .status
        .success());
    assert!(!output(&root, &config, &["-k", "unsupported"])
        .status
        .success());
    assert!(!output(&root, &config, &["--explain", "/bad%2fpath"])
        .status
        .success());

    let malformed = root.join("malformed.conf");
    fs::write(&malformed, "Listen not-a-port\n").unwrap();
    assert!(!output(&root, &malformed, &["-t"]).status.success());

    let warning = write_config(
        &root,
        free_port(),
        "RewriteEngine On\nRewriteRule ^/x$ /y [UnsafePrefixStat]",
    );
    let warning_result = output(&root, &warning, &["-t"]);
    assert!(warning_result.status.success());
    assert!(String::from_utf8_lossy(&warning_result.stderr).contains("has no effect"));

    let relative = root.file_name().unwrap().to_str().unwrap();
    let relative_result = Command::new(binary())
        .current_dir(root.parent().unwrap())
        .args([
            "-d",
            relative,
            "-f",
            config.to_str().unwrap(),
            "--no-envvars",
            "-t",
        ])
        .output()
        .unwrap();
    assert!(relative_result.status.success(), "{relative_result:?}");

    let display_config = root.join("display.conf");
    fs::write(
        &display_config,
        config_text(
            &root,
            port,
            &format!(
                "LoadModule sample_module modules/sample.so\n\
                 <VirtualHost *:{port}>\n\
                 ServerName vhost.test\n\
                 DocumentRoot {}\n\
                 </VirtualHost>",
                root.join("www").display()
            ),
        ),
    )
    .unwrap();
    assert!(output(&root, &display_config, &["-M"]).status.success());
    assert!(output(&root, &display_config, &["-S"]).status.success());

    let tls_config = root.join("tls-failure.conf");
    fs::write(
        &tls_config,
        config_text(
            &root,
            free_port(),
            "SSLEngine On\nSSLCertificateFile missing.crt\nSSLCertificateKeyFile missing.key",
        ),
    )
    .unwrap();
    assert!(!output(&root, &tls_config, &["-t"]).status.success());

    let held = TcpListener::bind(("127.0.0.1", free_port())).unwrap();
    let held_port = held.local_addr().unwrap().port();
    let bind_config = write_config(&root, held_port, "");
    assert!(!output(&root, &bind_config, &["-X"]).status.success());
    drop(held);

    let blocker = root.join("blocker");
    fs::write(&blocker, "not a directory").unwrap();
    let log_config = root.join("log-failure.conf");
    fs::write(
        &log_config,
        config_text(
            &root,
            free_port(),
            &format!("ErrorLog {}/child.log", blocker.display()),
        ),
    )
    .unwrap();
    assert!(!output(&root, &log_config, &["-X"]).status.success());

    let pid_config = root.join("pid-failure.conf");
    fs::write(
        &pid_config,
        config_text(
            &root,
            free_port(),
            &format!("PidFile {}/child.pid", blocker.display()),
        ),
    )
    .unwrap();
    assert!(!output(&root, &pid_config, &["-X"]).status.success());

    let cgi = root.join("www/test.cgi");
    fs::write(
        &cgi,
        "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\nok\\n'\n",
    )
    .unwrap();
    fs::set_permissions(&cgi, fs::Permissions::from_mode(0o755)).unwrap();
    let user_config = root.join("missing-user.conf");
    let mut missing_user = config_text(
        &root,
        free_port(),
        &format!(
            "ScriptAlias /cgi-bin/ {}/\nAddHandler cgi-script .cgi\n<Directory {}>\nOptions +ExecCGI\n</Directory>",
            root.join("www").display(),
            root.join("www").display(),
        ),
    );
    missing_user = missing_user.replace(
        &format!("User {}", service_ids().0),
        "User vapache-user-that-does-not-exist",
    );
    fs::write(&user_config, missing_user).unwrap();
    assert!(!output(&root, &user_config, &["-X"]).status.success());

    let root_user_config = root.join("root-user.conf");
    let root_user = config_text(&root, free_port(), "")
        .replace(&format!("User {}", service_ids().0), "User 0")
        .replace(&format!("Group {}", service_ids().1), "Group 0");
    fs::write(&root_user_config, root_user).unwrap();
    assert!(!output(&root, &root_user_config, &["-X"]).status.success());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn foreground_reload_reopen_bind_and_actions() {
    let root = test_dir("foreground");
    fs::write(root.join("www/index.txt"), "ok\n").unwrap();
    let alternate = root.join("alternate");
    fs::create_dir_all(&alternate).unwrap();
    fs::write(alternate.join("index.txt"), "candidate\n").unwrap();
    let port = free_port();
    let config = write_config(&root, port, "");
    const INHERITED_FD: i32 = 198;
    let child = spawn_foreground_with_inherited_fd(&root, &config, INHERITED_FD);
    wait_running(&root, &config, port);
    let pid = read_pid(&root);
    assert!(
        !PathBuf::from(format!("/proc/{pid}/fd/{INHERITED_FD}")).exists(),
        "daemon retained a launcher-supplied descriptor"
    );

    assert!(output(&root, &config, &["-k", "status"]).status.success());
    assert!(!output(&root, &config, &["-X"]).status.success());
    signal(pid, libc::SIGUSR1);

    assert!(output(&root, &config, &["-k", "graceful"]).status.success());
    thread::sleep(Duration::from_millis(150));

    let mut old_generation = connect_when_ready(port);
    old_generation
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    assert_eq!(
        keepalive_body(&mut old_generation, "/index.txt"),
        Some(b"ok\n".to_vec())
    );

    fs::write(&config, "Listen invalid\n").unwrap();
    signal(pid, libc::SIGHUP);
    thread::sleep(Duration::from_millis(150));
    // A rejected candidate stops listener admission only while it is checked;
    // it must not retire connections whose configuration remains current.
    assert_eq!(
        keepalive_body(&mut old_generation, "/index.txt"),
        Some(b"ok\n".to_vec())
    );

    let occupied = TcpListener::bind(("127.0.0.1", free_port())).unwrap();
    fs::write(
        &config,
        config_text(&root, occupied.local_addr().unwrap().port(), ""),
    )
    .unwrap();
    signal(pid, libc::SIGHUP);
    thread::sleep(Duration::from_millis(150));
    drop(occupied);

    let blocker = root.join("reload-log-blocker");
    fs::write(&blocker, "not a directory").unwrap();
    fs::write(
        &config,
        config_text(
            &root,
            port,
            &format!(
                "ErrorLog {}/child.log\nDocumentRoot {}\n<Directory {}>\nRequire all granted\n</Directory>",
                blocker.display(),
                alternate.display(),
                alternate.display(),
            ),
        ),
    )
    .unwrap();
    signal(pid, libc::SIGHUP);
    wait_until(|| {
        fs::read_to_string(root.join("error.log"))
            .is_ok_and(|log| log.contains("reload rejected: cannot prepare logger"))
    });
    assert_eq!(http_body(port, "/index.txt"), b"ok\n");

    fs::write(
        &config,
        config_text(
            &root,
            port,
            &format!(
                "ErrorLog {}/reloaded.log\nDocumentRoot {}\n<Directory {}>\nRequire all granted\n</Directory>",
                root.display(),
                alternate.display(),
                alternate.display(),
            ),
        ),
    )
    .unwrap();
    signal(pid, libc::SIGHUP);
    wait_until(|| http_body(port, "/index.txt") == b"candidate\n");
    // The successful commit retires the transport's immutable generation.
    // The old socket may finish an already-admitted request, but cannot begin
    // another request under the stale DocumentRoot/policy.
    assert_eq!(keepalive_body(&mut old_generation, "/index.txt"), None);
    assert!(output(&root, &config, &["-k", "stop"]).status.success());
    wait_success(child);

    let child = spawn_foreground(&root, &config, &["-k", "start"]);
    wait_running(&root, &config, port);
    assert!(output(&root, &config, &["-k", "graceful-stop"])
        .status
        .success());
    wait_success(child);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn daemon_and_active_graceful_drain() {
    let daemon_root = test_dir("daemon");
    fs::write(daemon_root.join("www/index.txt"), "ok\n").unwrap();
    let daemon_port = free_port();
    let daemon_config = write_config(&daemon_root, daemon_port, "");
    assert!(output(&daemon_root, &daemon_config, &[]).status.success());
    wait_running(&daemon_root, &daemon_config, daemon_port);
    assert!(output(&daemon_root, &daemon_config, &["-k", "status"])
        .status
        .success());
    assert!(output(&daemon_root, &daemon_config, &["-k", "stop"])
        .status
        .success());
    wait_until(|| TcpStream::connect(("127.0.0.1", daemon_port)).is_err());
    let _ = fs::remove_file(daemon_root.join("vapached.pid"));

    let drain_root = test_dir("drain");
    let script = drain_root.join("www/slow.cgi");
    fs::write(
        &script,
        "#!/bin/sh\nsleep 10\nprintf 'Content-Type: text/plain\\r\\n\\r\\nslow\\n'\n",
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let drain_port = free_port();
    let drain_config = write_config(
        &drain_root,
        drain_port,
        "Timeout 60\nGracefulShutdownTimeout 1\nAddHandler cgi-script .cgi\n<Directory /tmp>\nOptions +ExecCGI\n</Directory>",
    );
    let child = spawn_foreground(&drain_root, &drain_config, &[]);
    wait_running(&drain_root, &drain_config, drain_port);
    // The listener is bound before CGI pool setup and signal-handler
    // installation complete.  Do not send SIGTERM in that narrow window.
    thread::sleep(Duration::from_secs(2));
    let mut request = connect_when_ready(drain_port);
    request
        .write_all(b"GET /slow.cgi HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    thread::sleep(Duration::from_millis(200));
    signal(read_pid(&drain_root), libc::SIGTERM);
    wait_success(child);
    drop(request);

    let _ = fs::remove_dir_all(daemon_root);
    let _ = fs::remove_dir_all(drain_root);
}
