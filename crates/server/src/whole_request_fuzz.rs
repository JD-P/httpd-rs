//! Whole-request HTTP/1 versus HTTP/2 differential campaigns.
//!
//! The single-request campaign compares the canonical request, production
//! plan, authorization/terminal route, backend binding, cache classification
//! and response semantics. The stateful campaign additionally schedules
//! reload, access-file and backend-health transitions before admission and
//! between preparation and sink execution. Every owned policy/sink artifact
//! is dropped before the complete resource ledger is checked for zero.

use crate::config::Config;
use crate::http::{Body, Limits, Request, Response};
use crate::request_plan::{CanonicalErrorOrPlan, RequestPlan};
use crate::server::{BodyRouteDecision, PreparedHandler, PreparedRouteDecision};
use std::collections::VecDeque;
use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::FileExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

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
    cancel_before_sink: bool,
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
    Complete {
        status: u16,
        headers: Vec<(String, Vec<u8>)>,
        body: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BackendExchangeSnapshot {
    kind: &'static str,
    method: String,
    target: Vec<u8>,
    fields: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct WholeRequestSnapshot {
    canonical: CanonicalRequestSnapshot,
    plan: PlanSnapshot,
    authorization: AuthorizationSnapshot,
    sink: SinkSnapshot,
    backend: Option<BackendSnapshot>,
    cache: CacheSnapshot,
    backend_exchange: Option<BackendExchangeSnapshot>,
    backend_effect: bool,
    response: ResponseSnapshot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WireProtocol {
    H1,
    H2,
}

#[derive(Debug, PartialEq, Eq)]
enum StatefulOutcomeSnapshot {
    Completed(WholeRequestSnapshot),
    /// The connection was bound to a retired generation. The wire request was
    /// decoded, but no request plan, authorization or sink was admitted.
    Refused(CanonicalRequestSnapshot),
}

#[derive(Debug, PartialEq, Eq)]
struct StatefulStepSnapshot {
    active_generation: usize,
    connection_generation: usize,
    outcome: StatefulOutcomeSnapshot,
}

#[derive(Debug, PartialEq, Eq)]
struct StatefulTrace {
    steps: Vec<StatefulStepSnapshot>,
}

#[derive(Clone, Debug)]
struct StatefulStep {
    logical: LogicalRequest,
    reload_before: bool,
    reconnect_before: bool,
    access_before: Option<bool>,
    health_before: Option<bool>,
    reload_after_prepare: bool,
    access_after_prepare: Option<bool>,
    health_after_prepare: Option<bool>,
    reconnect_after: bool,
}

struct Fixture {
    config: Config,
    root: PathBuf,
    old_config_path: PathBuf,
    next_config_path: PathBuf,
    balancer_members: [String; 2],
    proxy_exchanges: Arc<Mutex<VecDeque<BackendExchangeSnapshot>>>,
    fastcgi_exchanges: Arc<Mutex<VecDeque<BackendExchangeSnapshot>>>,
    stateful_lock: Mutex<()>,
}

fn push_exchange(
    exchanges: &Arc<Mutex<VecDeque<BackendExchangeSnapshot>>>,
    exchange: BackendExchangeSnapshot,
) {
    exchanges
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .push_back(exchange);
}

fn try_pop_exchange(
    exchanges: &Arc<Mutex<VecDeque<BackendExchangeSnapshot>>>,
) -> Option<BackendExchangeSnapshot> {
    exchanges
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .pop_front()
}

fn exchange_mode(exchange: &BackendExchangeSnapshot, name: &str) -> u8 {
    exchange
        .fields
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .and_then(|(_, value)| value.first().copied())
        .map(|byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => byte,
        })
        .unwrap_or(0)
        % 4
}

fn read_proxy_exchange(stream: &mut TcpStream) -> std::io::Result<BackendExchangeSnapshot> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    let mut wire = Vec::new();
    let head_end = loop {
        if wire.len() > 128 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "proxy request head exceeded differential bound",
            ));
        }
        if let Some(end) = wire.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "proxy request ended before its head",
            ));
        }
        wire.extend_from_slice(&chunk[..read]);
    };
    let head = &wire[..head_end - 4];
    let mut lines = head.split(|byte| *byte == b'\n');
    let request_line = lines.next().unwrap_or_default();
    let request_line = request_line.strip_suffix(b"\r").unwrap_or(request_line);
    let mut parts = request_line.splitn(3, |byte| *byte == b' ');
    let method = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let target = parts.next().unwrap_or_default().to_vec();
    let mut fields = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = String::from_utf8_lossy(&line[..colon]).to_ascii_lowercase();
        let value = line[colon + 1..]
            .iter()
            .copied()
            .skip_while(|byte| *byte == b' ' || *byte == b'\t')
            .collect::<Vec<_>>();
        if name == "content-length" {
            content_length = String::from_utf8_lossy(&value).parse().unwrap_or(0);
        }
        fields.push((name, value));
    }
    fields.sort();
    let mut body = wire[head_end..].to_vec();
    while body.len() < content_length {
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);
    Ok(BackendExchangeSnapshot {
        kind: "proxy",
        method,
        target,
        fields,
        body,
    })
}

fn start_proxy_backend(
    exchanges: Arc<Mutex<VecDeque<BackendExchangeSnapshot>>>,
) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind differential proxy backend");
    let port = listener.local_addr().expect("proxy backend address").port();
    let thread = std::thread::spawn(move || {
        for accepted in listener.incoming() {
            let Ok(mut stream) = accepted else {
                continue;
            };
            let Ok(exchange) = read_proxy_exchange(&mut stream) else {
                continue;
            };
            let mode = exchange_mode(&exchange, "x-fuzz");
            push_exchange(&exchanges, exchange);
            let response: &[u8] = match mode {
                0 => b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: public, max-age=60\r\nX-Backend: proxy\r\nContent-Length: 20\r\nConnection: close\r\n\r\nwhole-request proxy\n",
                1 => b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nwhole\r\nF\r\n-request proxy\n\r\n0\r\nX-Trailer: done\r\n\r\n",
                2 => b"HTTP/1.1 204 No Content\r\nX-Backend: proxy\r\nConnection: close\r\n\r\n",
                _ => b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbad!",
            };
            for chunk in response.chunks(3) {
                if stream.write_all(chunk).is_err() {
                    break;
                }
                std::thread::yield_now();
            }
        }
    });
    (port, thread)
}

fn fastcgi_len(bytes: &[u8], position: &mut usize) -> Option<usize> {
    let first = *bytes.get(*position)?;
    *position += 1;
    if first & 0x80 == 0 {
        Some(first as usize)
    } else {
        let tail = bytes.get(*position..position.checked_add(3)?)?;
        *position += 3;
        Some(
            (((first & 0x7f) as usize) << 24)
                | ((tail[0] as usize) << 16)
                | ((tail[1] as usize) << 8)
                | tail[2] as usize,
        )
    }
}

fn parse_fastcgi_params(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut fields = Vec::new();
    let mut position = 0usize;
    while position < bytes.len() {
        let Some(name_len) = fastcgi_len(bytes, &mut position) else {
            break;
        };
        let Some(value_len) = fastcgi_len(bytes, &mut position) else {
            break;
        };
        let Some(end) = position
            .checked_add(name_len)
            .and_then(|p| p.checked_add(value_len))
        else {
            break;
        };
        if end > bytes.len() {
            break;
        }
        let name = String::from_utf8_lossy(&bytes[position..position + name_len]).into_owned();
        position += name_len;
        let value = bytes[position..position + value_len].to_vec();
        position += value_len;
        // This is the one intentional protocol projection: a backend may
        // observe the incoming protocol version, while every security- and
        // application-bearing field must remain byte-identical.
        if name != "SERVER_PROTOCOL" {
            fields.push((name, value));
        }
    }
    fields.sort();
    fields
}

fn fastcgi_record(out: &mut Vec<u8>, kind: u8, content: &[u8]) {
    out.push(1);
    out.push(kind);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.push(0);
    out.push(0);
    out.extend_from_slice(content);
}

fn read_fastcgi_exchange(stream: &mut UnixStream) -> std::io::Result<BackendExchangeSnapshot> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    let mut params = Vec::new();
    let mut body = Vec::new();
    loop {
        let mut header = [0u8; 8];
        stream.read_exact(&mut header)?;
        if header[0] != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid FastCGI version",
            ));
        }
        let kind = header[1];
        let len = u16::from_be_bytes([header[4], header[5]]) as usize;
        let padding = header[6] as usize;
        let mut content = vec![0u8; len.saturating_add(padding)];
        stream.read_exact(&mut content)?;
        content.truncate(len);
        match kind {
            4 => params.extend_from_slice(&content),
            5 if len == 0 => break,
            5 => body.extend_from_slice(&content),
            _ => {}
        }
    }
    let fields = parse_fastcgi_params(&params);
    let value = |name: &str| {
        fields
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.clone())
            .unwrap_or_default()
    };
    Ok(BackendExchangeSnapshot {
        kind: "fastcgi",
        method: String::from_utf8_lossy(&value("REQUEST_METHOD")).into_owned(),
        target: value("REQUEST_URI"),
        fields,
        body,
    })
}

fn start_fastcgi_backend(
    socket: PathBuf,
    exchanges: Arc<Mutex<VecDeque<BackendExchangeSnapshot>>>,
) -> std::thread::JoinHandle<()> {
    let listener = UnixListener::bind(&socket).expect("bind differential FastCGI backend");
    std::thread::spawn(move || {
        for accepted in listener.incoming() {
            let Ok(mut stream) = accepted else {
                continue;
            };
            let Ok(exchange) = read_fastcgi_exchange(&mut stream) else {
                continue;
            };
            let mode = exchange_mode(&exchange, "HTTP_X_FUZZ");
            push_exchange(&exchanges, exchange);
            let mut response = Vec::new();
            let (head, body): (&[u8], &[u8]) = match mode {
                0 => (
                    b"Status: 202 Accepted\r\nContent-Type: text/plain\r\nCache-Control: public, max-age=60\r\nX-Backend: fastcgi\r\n\r\n",
                    b"whole-request fastcgi\n",
                ),
                1 => (b"Status: 204 No Content\r\nX-Backend: fastcgi\r\n\r\n", b""),
                2 => (
                    b"Status: 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n",
                    b"bad!",
                ),
                _ => (
                    b"Status: 404 Not Found\r\nContent-Type: text/plain\r\nX-Backend: fastcgi\r\n\r\n",
                    b"fastcgi missing\n",
                ),
            };
            fastcgi_record(&mut response, 6, head);
            for chunk in body.chunks(4) {
                fastcgi_record(&mut response, 6, chunk);
            }
            fastcgi_record(&mut response, 6, &[]);
            fastcgi_record(&mut response, 3, &[0u8; 8]);
            let _ = stream.write_all(&response);
        }
    })
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        vapache_os::ignore_sigpipe().expect("install whole-request fuzz SIGPIPE disposition");
        let root =
            std::env::temp_dir().join(format!("vapache-whole-request-fuzz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("www/cache")).expect("create cache document root");
        std::fs::create_dir_all(root.join("www/denied")).expect("create denied document root");
        for directory in [
            "errors",
            "external",
            "app",
            "fcgi-dir",
            "proxy-dir",
            "access",
        ] {
            std::fs::create_dir_all(root.join("www").join(directory))
                .expect("create internal-transition fixture directory");
        }
        std::fs::create_dir_all(root.join("cache")).expect("create response cache root");
        let proxy_exchanges = Arc::new(Mutex::new(VecDeque::new()));
        let fastcgi_exchanges = Arc::new(Mutex::new(VecDeque::new()));
        let (proxy_port, _proxy_thread) = start_proxy_backend(proxy_exchanges.clone());
        let (proxy_failover_port, _proxy_failover_thread) =
            start_proxy_backend(proxy_exchanges.clone());
        let balancer_members = [
            format!("http://127.0.0.1:{proxy_port}"),
            format!("http://127.0.0.1:{proxy_failover_port}"),
        ];
        let fastcgi_socket = root.join("whole-request-fcgi.sock");
        let _fastcgi_thread =
            start_fastcgi_backend(fastcgi_socket.clone(), fastcgi_exchanges.clone());
        std::fs::write(root.join("www/public.txt"), b"public representation\n")
            .expect("write public fixture");
        std::fs::write(root.join("www/cache/item.txt"), b"cache representation\n")
            .expect("write cache fixture");
        std::fs::write(
            root.join("www/denied/secret.txt"),
            b"denied representation\n",
        )
        .expect("write denied fixture");
        std::fs::write(
            root.join("www/denied/index.html"),
            b"denied index representation\n",
        )
        .expect("write denied DirectoryIndex fixture");
        std::fs::write(root.join("www/index.html"), b"index representation\n")
            .expect("write index fixture");
        let error_cgi = root.join("www/errors/404.cgi");
        std::fs::write(
            &error_cgi,
            b"#!/bin/sh\nprintf 'Status: 200 OK\\r\\nContent-Type: text/plain\\r\\nX-Backend: cgi-error\\r\\n\\r\\n'\nprintf 'error:%s|%s|%s\\n' \"$REQUEST_METHOD\" \"$QUERY_STRING\" \"$SCRIPT_NAME\"\ncat\n",
        )
        .expect("write dynamic ErrorDocument fixture");
        std::fs::write(root.join("www/fcgi-dir/index.php"), b"<?php echo 'index'; ?>\n")
            .expect("write FastCGI index fixture");
        std::fs::write(root.join("www/proxy-dir/index.txt"), b"proxy index selection\n")
            .expect("write proxy index fixture");
        let cgi_index = root.join("www/app/index.cgi");
        std::fs::write(
            &cgi_index,
            b"#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\nX-Backend: cgi\\r\\n\\r\\nwhole-request CGI\\n'\n",
        )
        .expect("write CGI index fixture");
        let mut permissions = std::fs::metadata(&cgi_index)
            .expect("stat CGI index fixture")
            .permissions();
        use std::os::unix::fs::PermissionsExt as _;
        permissions.set_mode(0o755);
        std::fs::set_permissions(&cgi_index, permissions.clone())
            .expect("make CGI index executable");
        std::fs::set_permissions(&error_cgi, permissions)
            .expect("make ErrorDocument CGI executable");
        let access_cgi = root.join("www/access/guard.cgi");
        std::fs::write(
            &access_cgi,
            b"#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\nX-Backend: cgi-access\\r\\n\\r\\naccess request\\n'\n",
        )
        .expect("write access-file transition CGI fixture");
        let mut access_permissions = std::fs::metadata(&access_cgi)
            .expect("stat access-file transition CGI fixture")
            .permissions();
        access_permissions.set_mode(0o755);
        std::fs::set_permissions(&access_cgi, access_permissions)
            .expect("make access-file transition CGI executable");
        std::fs::write(
            root.join("www/access/.htaccess"),
            b"Require all granted\n",
        )
        .expect("write initial access-file policy");

        let config_path = root.join("httpd.conf");
        let next_config_path = root.join("httpd-next.conf");
        let config_text = format!(
            "ServerRoot \"{}\"\n\
             Listen 127.0.0.1:0\n\
             ServerName localhost\n\
             PidFile \"{}/httpd.pid\"\n\
             ErrorLog \"{}/error.log\"\n\
             DocumentRoot \"{}/www\"\n\
             VapacheCapability Cgi On\n\
             VapacheCapability FastCgi On\n\
             VapacheCapability AccessFiles On\n\
             VapacheCapability UnstableFastCgiPaths On\n\
             DirectoryIndex index.html\n\
             ErrorDocument 404 /errors/404.cgi?source=local\n\
             CacheRoot \"{}/cache\"\n\
             CacheEnable disk /cache\n\
             CacheHeader On\n\
             ProxyPass /proxy http://127.0.0.1:{}/upstream/\n\
             ProxyPass /proxy-dir/index.txt http://127.0.0.1:{}/upstream/index.txt\n\
             <Proxy \"balancer://stateful\">\n\
             BalancerMember http://127.0.0.1:{} hcuri=/health hcfails=1 hcpasses=1\n\
             BalancerMember http://127.0.0.1:{} hcuri=/health hcfails=1 hcpasses=1\n\
             </Proxy>\n\
             ProxyPass /balanced balancer://stateful/\n\
             ProxyPassMatch ^/fcgi-dir/(.*\\.php)$ \"unix:{}|fcgi://localhost{}/www/fcgi-dir/\"\n\
             Redirect 302 /redirect /public.txt\n\
             AddHandler cgi-script .cgi\n\
             RewriteEngine On\n\
             RewriteRule ^/rewrite$ /public.txt [L]\n\
             <Directory \"{}/www\">\n\
             Require all granted\n\
             </Directory>\n\
             <Directory \"{}/www/denied\">\n\
             Require all denied\n\
             </Directory>\n\
             <Directory \"{}/www/app\">\n\
             Options +ExecCGI\n\
             DirectoryIndex index.cgi\n\
             Require all granted\n\
             </Directory>\n\
             <Directory \"{}/www/errors\">\n\
             Options +ExecCGI\n\
             Require all granted\n\
             </Directory>\n\
             <Directory \"{}/www/fcgi-dir\">\n\
             DirectoryIndex index.php\n\
             Require all granted\n\
             </Directory>\n\
             <Directory \"{}/www/proxy-dir\">\n\
             DirectoryIndex index.txt\n\
             Require all granted\n\
             </Directory>\n\
             <Directory \"{}/www/access\">\n\
             AllowOverride AuthConfig\n\
             Options +ExecCGI\n\
             Require all granted\n\
             </Directory>\n\
             <Location /location-denied>\n\
             Require all denied\n\
             </Location>\n\
             <Location /external>\n\
             ErrorDocument 404 https://errors.example.test/not-found\n\
             </Location>\n",
            root.display(),
            root.display(),
            root.display(),
            root.display(),
            root.display(),
            proxy_port,
            proxy_port,
            proxy_port,
            proxy_failover_port,
            fastcgi_socket.display(),
            root.display(),
            root.display(),
            root.display(),
            root.display(),
            root.display(),
            root.display(),
            root.display(),
            root.display(),
        );
        std::fs::write(&config_path, &config_text).expect("write whole-request config");
        std::fs::write(
            &next_config_path,
            format!(
                "{config_text}\n<Location /cache>\nRequire all denied\n</Location>\n"
            ),
        )
        .expect("write reload whole-request config");
        let config = Config::load(
            &config_path,
            &root,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap_or_else(|errors| panic!("whole-request config: {errors:?}"));
        assert!(config.resource_budget.transition_usage_is_zero());
        Fixture {
            config,
            root,
            old_config_path: config_path,
            next_config_path,
            balancer_members,
            proxy_exchanges,
            fastcgi_exchanges,
            stateful_lock: Mutex::new(()),
        }
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
    let (path, denied_route) = match byte(0) % 20 {
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
        11 => ("/".to_string(), false),
        12 => (format!("/missing-local-{token}"), false),
        13 => (format!("/external/missing-{token}"), false),
        14 => ("/app/".to_string(), false),
        15 => ("/fcgi-dir/".to_string(), false),
        16 => ("/proxy-dir/".to_string(), false),
        17 => ("/denied/".to_string(), true),
        18 => ("/access/guard.cgi".to_string(), false),
        _ => (format!("/balanced/{token}"), false),
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
    if byte(6) & 1 != 0 {
        fields.push((
            "content-type".to_string(),
            b"application/octet-stream".to_vec(),
        ));
        fields.push(("content-language".to_string(), b"en-US".to_vec()));
    }
    if byte(6) & 2 != 0 {
        fields.push(("if-match".to_string(), format!("\"{token}\"").into_bytes()));
        fields.push((
            "if-range".to_string(),
            b"Wed, 21 Oct 2015 07:28:00 GMT".to_vec(),
        ));
    }
    if byte(6) & 4 != 0 {
        fields.push(("te".to_string(), b"trailers".to_vec()));
    }
    if byte(6) & 8 != 0 && byte(5) & 4 != 0 {
        fields.push(("expect".to_string(), b"100-continue".to_vec()));
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
        cancel_before_sink: byte(7) & 0x80 != 0,
    }
}

fn encode_h1(logical: &LogicalRequest) -> Vec<u8> {
    let mut wire = Vec::new();
    wire.extend_from_slice(logical.method.as_bytes());
    wire.push(b' ');
    wire.extend_from_slice(logical.target.as_bytes());
    wire.extend_from_slice(b" HTTP/1.1\r\nHost: localhost\r\n");
    // HTTP/1 requires the hop-by-hop Connection token before forwarding TE,
    // while HTTP/2 forbids Connection entirely.  This is a wire projection of
    // the same logical `TE: trailers` field, not an application-visible
    // difference, so canonical snapshots omit Connection below.
    if logical
        .fields
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("te"))
    {
        wire.extend_from_slice(b"Connection: TE\r\n");
    }
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
        .filter(|(name, _)| !name.eq_ignore_ascii_case("connection"))
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
    let body = match response.body {
        Body::Empty => Vec::new(),
        Body::Bytes(body) => body,
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
            body
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
            body
        }
    };
    ResponseSnapshot::Complete {
        status,
        headers,
        body,
    }
}

struct RouteSnapshot {
    authorization: AuthorizationSnapshot,
    sink: SinkSnapshot,
    backend: Option<BackendSnapshot>,
    backend_exchange: Option<BackendExchangeSnapshot>,
    backend_effect: bool,
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

fn prepared_identity(
    handler: &PreparedHandler,
) -> (SinkSnapshot, BackendSnapshot, Option<CacheSnapshot>) {
    match handler {
        PreparedHandler::FinalizeDispatch { handler, cache, .. } => {
            let (sink, backend, nested_cache) = prepared_identity(handler);
            (
                sink,
                backend,
                cache
                    .as_deref()
                    .map(cache_context_snapshot)
                    .or(nested_cache),
            )
        }
        PreparedHandler::FinalizeErrorDocument { handler, .. }
        | PreparedHandler::FinalizeInternalRequest { handler, .. } => prepared_identity(handler),
        PreparedHandler::Proxy {
            authorization,
            target,
            ..
        } => {
            let selected = target.binding_key();
            let authorized = authorization.resource().backend_target.clone();
            (
                SinkSnapshot::Proxy,
                BackendSnapshot {
                    kind: "proxy",
                    selected,
                    authorized,
                    resource: authorization.resource().clone(),
                },
                None,
            )
        }
        PreparedHandler::FastCgi {
            authorization,
            target,
            ..
        } => {
            // URL-space FastCGI does not bind the opened script inode until
            // execution. The prepared IR still carries the exact lexical
            // script identity and pre-binding resource, which are the fields
            // available at this side-effect-free differential boundary.
            let selected = target.script_filename().display().to_string();
            let authorized = authorization.resource().backend_target.clone();
            (
                SinkSnapshot::FastCgi,
                BackendSnapshot {
                    kind: "fastcgi",
                    selected,
                    authorized,
                    resource: authorization.resource().clone(),
                },
                None,
            )
        }
        PreparedHandler::Cgi {
            authorization,
            script_meta,
            ..
        } => {
            use std::os::unix::fs::MetadataExt as _;
            let selected = format!("{}:{}", script_meta.dev(), script_meta.ino());
            (
                SinkSnapshot::Cgi,
                BackendSnapshot {
                    kind: "cgi",
                    selected,
                    authorized: authorization.resource().backend_target.clone(),
                    resource: authorization.resource().clone(),
                },
                None,
            )
        }
    }
}

fn execute_prepared_snapshot(
    fixture: &Fixture,
    cfg: &Config,
    request: &mut Request,
    handler: PreparedHandler,
    cancel_before_sink: bool,
) -> RouteSnapshot {
    let (sink, backend, route_cache) = prepared_identity(&handler);
    if cancel_before_sink {
        request
            .request_scope()
            .expect("decoded request has a cancellation scope")
            .cancel();
    }
    let peer = SocketAddr::new(PEER, 4242);
    let response =
        crate::server::execute_prepared_handler(cfg, request, peer, LOCAL_PORT, true, handler);
    let (backend_exchange, backend_effect) = match sink {
        SinkSnapshot::Proxy => {
            let exchange = try_pop_exchange(&fixture.proxy_exchanges);
            let effect = exchange.is_some();
            (exchange, effect)
        }
        SinkSnapshot::FastCgi => {
            let exchange = try_pop_exchange(&fixture.fastcgi_exchanges);
            let effect = exchange.is_some();
            (exchange, effect)
        }
        SinkSnapshot::Cgi => (
            None,
            response
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("x-backend")),
        ),
        SinkSnapshot::None | SinkSnapshot::StaticFile | SinkSnapshot::Redirect => {
            unreachable!("a prepared handler always owns a dynamic sink")
        }
    };
    assert_eq!(
        backend_effect, !cancel_before_sink,
        "pre-sink cancellation did not suppress the dynamic effect"
    );
    RouteSnapshot {
        authorization: AuthorizationSnapshot::Granted,
        sink,
        backend: Some(backend),
        backend_exchange,
        backend_effect,
        route_cache,
        response: response_snapshot(response),
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
        backend_exchange: None,
        backend_effect: false,
        route_cache: None,
        response: response_snapshot(response),
    }
}

enum ProbedRoute {
    Prepared(PreparedHandler),
    Responded(RouteSnapshot),
}

fn probe_route(cfg: &Config, request: &mut Request) -> ProbedRoute {
    let peer = SocketAddr::new(PEER, 4242);
    if !matches!(request.framing, crate::verified::BodyFraming::None) {
        match crate::server::probe_request_body(cfg, request, peer, LOCAL_IP, LOCAL_PORT, true) {
            BodyRouteDecision::Read { handler, .. } => ProbedRoute::Prepared(handler),
            BodyRouteDecision::Drain(response, _) | BodyRouteDecision::Respond(response, _) => {
                ProbedRoute::Responded(response_route(response))
            }
        }
    } else {
        match crate::server::probe_prepared_handler(cfg, request, peer, LOCAL_IP, LOCAL_PORT, true)
        {
            PreparedRouteDecision::Prepared { handler, .. } => ProbedRoute::Prepared(handler),
            PreparedRouteDecision::Respond(response, _) => {
                ProbedRoute::Responded(response_route(response))
            }
        }
    }
}

fn finish_route(
    fixture: &Fixture,
    cfg: &Config,
    request: &mut Request,
    route: ProbedRoute,
    cancel_before_sink: bool,
) -> RouteSnapshot {
    match route {
        ProbedRoute::Prepared(handler) => {
            execute_prepared_snapshot(fixture, cfg, request, handler, cancel_before_sink)
        }
        ProbedRoute::Responded(route) => route,
    }
}

struct PreparedEvaluation {
    request: Request,
    canonical: CanonicalRequestSnapshot,
    plan: PlanSnapshot,
    cache: CacheSnapshot,
    route: ProbedRoute,
}

fn prepare_evaluation(cfg: &Config, mut request: Request) -> PreparedEvaluation {
    let canonical = canonical_snapshot(&request);
    let (plan, owned_plan) = plan_snapshot(cfg, &request);
    let cache = crate::expr::with_connection(true, LOCAL_PORT, || {
        cache_snapshot(cfg, &request, owned_plan.as_ref())
    });
    let route = probe_route(cfg, &mut request);
    PreparedEvaluation {
        request,
        canonical,
        plan,
        cache,
        route,
    }
}

fn finish_evaluation(
    fixture: &Fixture,
    cfg: &Config,
    prepared: PreparedEvaluation,
    cancel_before_sink: bool,
) -> WholeRequestSnapshot {
    let PreparedEvaluation {
        mut request,
        canonical,
        plan,
        cache,
        route,
    } = prepared;
    let route = finish_route(fixture, cfg, &mut request, route, cancel_before_sink);
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
        backend_exchange: route.backend_exchange,
        backend_effect: route.backend_effect,
        response: route.response,
    }
}

fn evaluate(
    fixture: &Fixture,
    cfg: &Config,
    request: Request,
    cancel_before_sink: bool,
) -> WholeRequestSnapshot {
    let prepared = prepare_evaluation(cfg, request);
    finish_evaluation(fixture, cfg, prepared, cancel_before_sink)
}

fn compare_protocols(data: &[u8]) -> WholeRequestSnapshot {
    let fixture = fixture();
    let _stateful_guard = fixture
        .stateful_lock
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let cfg = &fixture.config;
    let logical = logical_request(data);
    assert!(cfg.resource_budget.transition_usage_is_zero());
    let baseline = cfg.resource_budget.transition_snapshot();

    let h1 = evaluate(
        fixture,
        cfg,
        decode_h1(cfg, &logical),
        logical.cancel_before_sink,
    );
    let h1_warm = matches!(h1.cache, CacheSnapshot::Eligible { .. }).then(|| {
        evaluate(
            fixture,
            cfg,
            decode_h1(cfg, &logical),
            logical.cancel_before_sink,
        )
    });
    crate::cache::clear(cfg);
    assert_eq!(cfg.resource_budget.transition_snapshot(), baseline);
    assert!(cfg.resource_budget.transition_usage_is_zero());

    let decode_h2 = || {
        crate::h2::differential_decode_request(
            cfg,
            logical.method,
            &logical.target,
            &logical.fields,
            &logical.body,
            PEER,
        )
        .unwrap_or_else(|error| panic!("generated HTTP/2 request failed: {error}; {logical:?}"))
    };
    let h2_request = decode_h2();
    let h2 = evaluate(fixture, cfg, h2_request, logical.cancel_before_sink);
    let h2_warm = matches!(h2.cache, CacheSnapshot::Eligible { .. })
        .then(|| evaluate(fixture, cfg, decode_h2(), logical.cancel_before_sink));
    crate::cache::clear(cfg);
    assert_eq!(cfg.resource_budget.transition_snapshot(), baseline);
    assert!(cfg.resource_budget.transition_usage_is_zero());

    assert_eq!(h1, h2, "protocol projections diverged for {logical:?}");
    assert_eq!(
        h1_warm, h2_warm,
        "warm-cache protocol projections diverged for {logical:?}"
    );
    if logical.denied_route {
        assert!(matches!(h1.authorization, AuthorizationSnapshot::Denied(_)));
        assert_eq!(h1.sink, SinkSnapshot::None);
        assert!(h1.backend.is_none());
    }
    if logical.cancel_before_sink {
        assert!(!h1.backend_effect);
        assert!(h1.backend_exchange.is_none());
    }
    h1
}

fn drain_backend_exchanges(fixture: &Fixture) {
    fixture
        .proxy_exchanges
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
    fixture
        .fastcgi_exchanges
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
}

fn replace_access_file(fixture: &Fixture, granted: bool) {
    let directory = fixture.root.join("www/access");
    let next = directory.join(".htaccess.stateful-next");
    std::fs::write(
        &next,
        if granted {
            b"Require all granted\n".as_slice()
        } else {
            b"Require all denied\n".as_slice()
        },
    )
    .expect("write replacement access-file policy");
    std::fs::rename(next, directory.join(".htaccess"))
        .expect("atomically replace access-file policy");
}

fn load_stateful_configs(fixture: &Fixture) -> [Config; 2] {
    replace_access_file(fixture, true);
    let old = Config::load(
        &fixture.old_config_path,
        &fixture.root,
        &Default::default(),
        &Default::default(),
        false,
    )
    .unwrap_or_else(|errors| panic!("stateful old config: {errors:?}"));
    let mut candidate = Config::load(
        &fixture.next_config_path,
        &fixture.root,
        &Default::default(),
        &Default::default(),
        false,
    )
    .unwrap_or_else(|errors| panic!("stateful candidate config: {errors:?}"));
    candidate
        .validate_reload_from(&old)
        .expect("stateful reload candidate must be compatible");
    candidate.resource_budget = old.resource_budget.clone();
    crate::cache::prepare(&old);
    crate::cache::prepare(&candidate);
    crate::cache::clear(&old);
    assert!(old.resource_budget.transition_usage_is_zero());
    [old, candidate]
}

fn parse_stateful_steps(data: &[u8]) -> Vec<StatefulStep> {
    const RECORD: usize = 16;
    let record_count = data.len().div_ceil(RECORD).clamp(2, 6);
    (0..record_count)
        .map(|index| {
            let start = index.saturating_mul(RECORD);
            let end = start.saturating_add(RECORD).min(data.len());
            let mut record = [0u8; RECORD];
            if start < data.len() {
                record[..end - start].copy_from_slice(&data[start..end]);
            }
            let before = record[8];
            let after = record[10];
            StatefulStep {
                logical: logical_request(&record),
                reload_before: before & 0x01 != 0,
                reconnect_before: before & 0x02 != 0,
                access_before: (before & 0x04 != 0).then_some(record[9] & 0x01 != 0),
                health_before: (before & 0x08 != 0).then_some(record[9] & 0x02 != 0),
                reload_after_prepare: after & 0x01 != 0,
                access_after_prepare: (after & 0x02 != 0).then_some(record[11] & 0x01 != 0),
                health_after_prepare: (after & 0x04 != 0).then_some(record[11] & 0x02 != 0),
                reconnect_after: after & 0x08 != 0,
            }
        })
        .collect()
}

struct H1SequenceDecoder {
    stream: Cursor<Vec<u8>>,
    buffered: Vec<u8>,
}

impl H1SequenceDecoder {
    fn new(steps: &[StatefulStep]) -> Self {
        let mut wire = Vec::new();
        for step in steps {
            wire.extend_from_slice(&encode_h1(&step.logical));
        }
        Self {
            stream: Cursor::new(wire),
            buffered: Vec::new(),
        }
    }

    fn decode(&mut self, cfg: &Config) -> Request {
        let mut limits = Limits::default();
        limits.request_line = cfg.limit_request_line;
        limits.fields = cfg.limit_request_fields;
        limits.field_size = cfg.limit_request_field_size;
        limits.body = cfg.limit_request_body;
        limits.resource_budget = cfg.resource_budget.clone();
        limits.max_spool_bytes = cfg.max_spool_bytes;
        limits.max_spool_files = cfg.max_spool_files;
        limits.https = true;
        let context = cfg.resource_budget.context(PEER);
        let mut request = crate::resource::with_resource_context(context.clone(), || {
            crate::http::read_request(&mut self.stream, &mut self.buffered, &limits, |_| {})
        })
        .expect("generated stateful HTTP/1 request must parse")
        .expect("generated stateful HTTP/1 request must not be EOF");
        request
            .headers
            .bind_request_scope(crate::resource::RequestScope::new(context));
        request
    }
}

fn decode_stateful_request(
    protocol: WireProtocol,
    h1: &mut H1SequenceDecoder,
    cfg: &Config,
    logical: &LogicalRequest,
) -> Request {
    match protocol {
        WireProtocol::H1 => h1.decode(cfg),
        WireProtocol::H2 => crate::h2::differential_decode_request(
            cfg,
            logical.method,
            &logical.target,
            &logical.fields,
            &logical.body,
            PEER,
        )
        .unwrap_or_else(|error| {
            panic!("generated stateful HTTP/2 request failed: {error}; {logical:?}")
        }),
    }
}

fn commit_stateful_reload(configs: &[Config; 2], active_generation: &mut usize) {
    if *active_generation != 0 {
        return;
    }
    configs[0].retire_generation();
    crate::cache::clear_reload(&configs[0], &configs[1]);
    *active_generation = 1;
}

fn set_stateful_health(fixture: &Fixture, cfg: &Config, member_zero_healthy: bool) {
    crate::proxy::differential_set_member_health(
        cfg,
        "stateful",
        &fixture.balancer_members[0],
        member_zero_healthy,
    );
    // Keep the alternate viable so an unhealthy primary deterministically
    // exercises failover instead of the no-backend error path.
    crate::proxy::differential_set_member_health(
        cfg,
        "stateful",
        &fixture.balancer_members[1],
        true,
    );
}

fn normalize_resource(resource: &mut crate::access::ResourceKey) {
    // Vhost identity is deliberately a process-local pointer. Independently
    // compiled but semantically equal protocol runs cannot compare it.
    resource.vhost = 0;
}

fn normalize_whole_request(snapshot: &mut WholeRequestSnapshot) {
    if let Some(backend) = snapshot.backend.as_mut() {
        normalize_resource(&mut backend.resource);
    }
    if let CacheSnapshot::Eligible { resource, .. } = &mut snapshot.cache {
        normalize_resource(resource);
    }
}

fn response_has_cache_hit(snapshot: &WholeRequestSnapshot) -> bool {
    let ResponseSnapshot::Complete { headers, .. } = &snapshot.response;
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("x-cache") && value.eq_ignore_ascii_case(b"HIT")
    })
}

fn run_stateful_protocol(
    fixture: &Fixture,
    steps: &[StatefulStep],
    protocol: WireProtocol,
) -> StatefulTrace {
    let configs = load_stateful_configs(fixture);
    let baseline = configs[0].resource_budget.transition_snapshot();
    let mut h1 = H1SequenceDecoder::new(steps);
    let mut active_generation = 0usize;
    let mut connection_generation = 0usize;
    let mut access_granted = true;
    let mut member_zero_healthy = [true, true];
    let mut snapshots = Vec::with_capacity(steps.len());

    for step in steps {
        if step.reload_before {
            commit_stateful_reload(&configs, &mut active_generation);
        }
        if let Some(granted) = step.access_before {
            replace_access_file(fixture, granted);
            access_granted = granted;
        }
        if let Some(healthy) = step.health_before {
            set_stateful_health(fixture, &configs[active_generation], healthy);
            member_zero_healthy[active_generation] = healthy;
        }
        if step.reconnect_before {
            connection_generation = active_generation;
        }

        let cfg = &configs[connection_generation];
        let request = decode_stateful_request(protocol, &mut h1, cfg, &step.logical);
        let refused_canonical = canonical_snapshot(&request);
        let admitted = cfg.admit_generation_work(|| prepare_evaluation(cfg, request));
        assert_eq!(
            admitted.is_some(),
            connection_generation == active_generation,
            "generation admission disagreed with the connection binding"
        );
        let access_granted_at_prepare = access_granted;
        let member_zero_healthy_at_prepare = member_zero_healthy[connection_generation];
        let outcome = if let Some(prepared) = admitted {
            if step.reload_after_prepare {
                commit_stateful_reload(&configs, &mut active_generation);
            }
            if let Some(granted) = step.access_after_prepare {
                replace_access_file(fixture, granted);
                access_granted = granted;
            }
            if let Some(healthy) = step.health_after_prepare {
                set_stateful_health(fixture, &configs[active_generation], healthy);
                member_zero_healthy[active_generation] = healthy;
            }
            let mut completed =
                finish_evaluation(fixture, cfg, prepared, step.logical.cancel_before_sink);
            normalize_whole_request(&mut completed);
            if connection_generation == 1 && completed.canonical.raw_path.starts_with(b"/cache") {
                assert!(matches!(
                    completed.authorization,
                    AuthorizationSnapshot::Denied(_)
                ));
                assert_eq!(completed.sink, SinkSnapshot::None);
                assert!(completed.backend.is_none());
                assert!(!response_has_cache_hit(&completed));
            }
            if matches!(completed.authorization, AuthorizationSnapshot::Denied(_)) {
                assert_eq!(completed.sink, SinkSnapshot::None);
                assert!(completed.backend.is_none());
                assert!(!completed.backend_effect);
            }
            if completed
                .canonical
                .raw_path
                .starts_with(b"/access/guard.cgi")
            {
                assert_eq!(
                    matches!(completed.authorization, AuthorizationSnapshot::Granted),
                    access_granted_at_prepare,
                    "access-file replacement affected the wrong planning epoch"
                );
            }
            if completed.canonical.raw_path.starts_with(b"/balanced/")
                && !member_zero_healthy_at_prepare
                && completed.backend_effect
            {
                let expected = fixture.balancer_members[1]
                    .strip_prefix("http://")
                    .expect("fixture balancer member is HTTP");
                let exchange = completed
                    .backend_exchange
                    .as_ref()
                    .expect("effectful proxy request has an exchange");
                let host = exchange
                    .fields
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("host"))
                    .map(|(_, value)| value.as_slice())
                    .expect("proxy exchange carries Host");
                assert_eq!(host, expected.as_bytes(), "unhealthy member was selected");
            }
            StatefulOutcomeSnapshot::Completed(completed)
        } else {
            StatefulOutcomeSnapshot::Refused(refused_canonical)
        };
        snapshots.push(StatefulStepSnapshot {
            active_generation,
            connection_generation,
            outcome,
        });
        if step.reconnect_after {
            connection_generation = active_generation;
        }
    }

    crate::cache::clear(&configs[0]);
    crate::cache::clear(&configs[1]);
    drain_backend_exchanges(fixture);
    assert_eq!(configs[0].resource_budget.transition_snapshot(), baseline);
    assert!(configs[0].resource_budget.transition_usage_is_zero());
    StatefulTrace { steps: snapshots }
}

fn compare_stateful_steps(steps: &[StatefulStep]) -> StatefulTrace {
    let fixture = fixture();
    let _stateful_guard = fixture
        .stateful_lock
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    drain_backend_exchanges(fixture);
    let h1 = run_stateful_protocol(fixture, steps, WireProtocol::H1);
    replace_access_file(fixture, true);
    drain_backend_exchanges(fixture);
    let h2 = run_stateful_protocol(fixture, steps, WireProtocol::H2);
    replace_access_file(fixture, true);
    assert_eq!(h1, h2, "stateful protocol projections diverged: {steps:#?}");
    h1
}

/// Run a bounded sequence through reload, access-file, health and connection
/// transitions, then require HTTP/1 and HTTP/2 to agree on every outcome.
pub fn run_stateful(data: &[u8]) {
    let steps = parse_stateful_steps(data);
    let _ = compare_stateful_steps(&steps);
}

/// Run one bounded logical request through both complete protocol paths.
pub fn run(data: &[u8]) {
    let _ = compare_protocols(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stateful_step(route: u8) -> StatefulStep {
        let mut request = [0u8; 16];
        request[0] = route;
        StatefulStep {
            logical: logical_request(&request),
            reload_before: false,
            reconnect_before: false,
            access_before: None,
            health_before: None,
            reload_after_prepare: false,
            access_after_prepare: None,
            health_after_prepare: None,
            reconnect_after: false,
        }
    }

    fn completed(step: &StatefulStepSnapshot) -> &WholeRequestSnapshot {
        let StatefulOutcomeSnapshot::Completed(snapshot) = &step.outcome else {
            panic!("expected completed request, got {step:#?}");
        };
        snapshot
    }

    #[test]
    fn dynamic_outcome_machine_requires_every_admission_fact() {
        use vapache_verified::{
            dynamic_outcome_initial, dynamic_outcome_step, DynamicOutcomeEvent as Event,
            DynamicOutcomePhase as Phase,
        };

        let nested = dynamic_outcome_initial(2, 0, 0);
        let nested_once = dynamic_outcome_step(
            nested,
            Event::CompleteInternalProjection,
            false,
            false,
            false,
            false,
        )
        .unwrap();
        assert!(
            dynamic_outcome_step(nested_once, Event::StartBackend, true, true, false, false)
                .is_none()
        );
        let nested_twice = dynamic_outcome_step(
            nested_once,
            Event::CompleteInternalProjection,
            false,
            false,
            false,
            false,
        )
        .unwrap();
        assert!(
            dynamic_outcome_step(nested_twice, Event::StartBackend, true, true, false, false)
                .is_some()
        );

        let initial = dynamic_outcome_initial(1, 1, 1);
        assert!(
            dynamic_outcome_step(initial, Event::StartBackend, false, true, false, false).is_none()
        );
        assert!(
            dynamic_outcome_step(initial, Event::StartBackend, true, true, false, false).is_none()
        );
        let projected = dynamic_outcome_step(
            initial,
            Event::CompleteInternalProjection,
            false,
            false,
            false,
            false,
        )
        .unwrap();
        let backend =
            dynamic_outcome_step(projected, Event::StartBackend, true, true, false, false).unwrap();
        assert_eq!(backend.phase, Phase::Backend);
        assert!(
            dynamic_outcome_step(backend, Event::BackendComplete, false, false, false, false,)
                .is_none()
        );
        let response =
            dynamic_outcome_step(backend, Event::BackendComplete, false, false, true, false)
                .unwrap();
        let error = dynamic_outcome_step(
            response,
            Event::ApplyErrorFinalizer,
            false,
            false,
            false,
            false,
        )
        .unwrap();
        let dispatch = dynamic_outcome_step(
            error,
            Event::BeginDispatchFinalizer,
            false,
            false,
            false,
            false,
        )
        .unwrap();
        assert!(
            dynamic_outcome_step(dispatch, Event::ConsiderCache, false, false, false, false,)
                .is_none()
        );
        let cached =
            dynamic_outcome_step(dispatch, Event::ConsiderCache, false, false, false, true)
                .unwrap();
        let finalized = dynamic_outcome_step(
            cached,
            Event::CompleteDispatchFinalizer,
            false,
            false,
            false,
            false,
        )
        .unwrap();
        let output =
            dynamic_outcome_step(finalized, Event::AdmitOutput, false, false, true, false).unwrap();
        assert_eq!(output.phase, Phase::Output);

        let aborted =
            dynamic_outcome_step(backend, Event::Abort, false, false, false, false).unwrap();
        assert_eq!(aborted.phase, Phase::Aborted);
        for event in [
            Event::StartBackend,
            Event::BackendComplete,
            Event::CompleteInternalProjection,
            Event::ApplyErrorFinalizer,
            Event::BeginDispatchFinalizer,
            Event::ConsiderCache,
            Event::CompleteDispatchFinalizer,
            Event::AdmitOutput,
            Event::Abort,
        ] {
            assert!(dynamic_outcome_step(aborted, event, true, true, true, true).is_none());
        }
    }

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

        let local_error = compare_protocols(b"\x0c\x01\x00\x00\x00\x00\x03\x00local-error");
        assert_eq!(local_error.authorization, AuthorizationSnapshot::Granted);
        assert_eq!(local_error.sink, SinkSnapshot::Cgi);
        assert!(matches!(
            local_error.response,
            ResponseSnapshot::Complete { status: 404, .. }
        ));

        let external_error = compare_protocols(b"\x0d\x01\x00\x00\x00\x00\x03\x00external-error");
        assert_eq!(external_error.authorization, AuthorizationSnapshot::Granted);
        assert_eq!(external_error.sink, SinkSnapshot::Redirect);

        let cgi_index = compare_protocols(b"\x0e\x01\x00\x02\x00\x04\x0b\x00cgi-body");
        assert_eq!(cgi_index.sink, SinkSnapshot::Cgi);
        assert!(matches!(
            cgi_index.backend,
            Some(BackendSnapshot { kind: "cgi", .. })
        ));

        let fastcgi_index = compare_protocols(b"\x0f\x01\x00\x00\x00\x00\x03\x00fastcgi-index");
        assert_eq!(fastcgi_index.sink, SinkSnapshot::FastCgi);

        let proxy_index = compare_protocols(b"\x10\x01\x00\x00\x00\x00\x03\x00proxy-index");
        assert_eq!(proxy_index.sink, SinkSnapshot::Proxy);

        let denied_index = compare_protocols(b"\x11\x01\x00\x00\x00\x00\x03\x00denied-index");
        assert!(matches!(
            denied_index.authorization,
            AuthorizationSnapshot::Denied(_)
        ));
        assert_eq!(denied_index.sink, SinkSnapshot::None);

        for cancelled in [
            b"\x06\x00\x00\x00\x00\x00\x00\x80cancel-proxy".as_slice(),
            b"\x0f\x00\x00\x00\x00\x00\x00\x80cancel-fastcgi".as_slice(),
            b"\x0e\x00\x00\x00\x00\x00\x00\x80cancel-cgi".as_slice(),
        ] {
            let result = compare_protocols(cancelled);
            assert!(!result.backend_effect);
            assert!(result.backend_exchange.is_none());
        }
    }

    #[test]
    fn fixed_multi_request_transition_matrix_agrees() {
        // An old-generation cache entry cannot cross the reload boundary into
        // a candidate whose authorization policy now denies the same URL.
        let warm = stateful_step(3);
        let warm_lookup = stateful_step(3);
        let mut post_reload_lookup = stateful_step(3);
        post_reload_lookup.reload_before = true;
        post_reload_lookup.reconnect_before = true;
        let trace = compare_stateful_steps(&[warm, warm_lookup, post_reload_lookup]);
        assert!(matches!(
            completed(&trace.steps[0]).cache,
            CacheSnapshot::Eligible { .. }
        ));
        assert!(response_has_cache_hit(completed(&trace.steps[1])));
        assert!(matches!(
            completed(&trace.steps[2]).authorization,
            AuthorizationSnapshot::Denied(_)
        ));
        assert!(!response_has_cache_hit(completed(&trace.steps[2])));

        // A request admitted before retirement retains its move-only outcome,
        // while another stream/request on the old connection is refused. A
        // newly established connection binds the candidate generation.
        let mut in_flight = stateful_step(18);
        in_flight.reload_after_prepare = true;
        let stale_connection = stateful_step(0);
        let mut new_connection = stateful_step(0);
        new_connection.reconnect_before = true;
        let trace = compare_stateful_steps(&[in_flight, stale_connection, new_connection]);
        assert_eq!(completed(&trace.steps[0]).sink, SinkSnapshot::Cgi);
        assert!(matches!(
            trace.steps[1].outcome,
            StatefulOutcomeSnapshot::Refused(_)
        ));
        assert_eq!(completed(&trace.steps[2]).sink, SinkSnapshot::StaticFile);

        // Atomic replacement after planning cannot revoke or retarget an
        // already-prepared outcome, but the next lookup observes the inode
        // replacement and its denied policy.
        let mut access_in_flight = stateful_step(18);
        access_in_flight.access_after_prepare = Some(false);
        let denied_fresh_lookup = stateful_step(18);
        let trace = compare_stateful_steps(&[access_in_flight, denied_fresh_lookup]);
        assert_eq!(completed(&trace.steps[0]).sink, SinkSnapshot::Cgi);
        assert!(matches!(
            completed(&trace.steps[1]).authorization,
            AuthorizationSnapshot::Denied(_)
        ));
        assert!(!completed(&trace.steps[1]).backend_effect);

        // Health changes are generation-keyed and affect the next selection,
        // not the concrete backend bound into an in-flight authorization.
        let mut selected_before_failure = stateful_step(19);
        selected_before_failure.health_after_prepare = Some(false);
        let selected_after_failure = stateful_step(19);
        let trace = compare_stateful_steps(&[selected_before_failure, selected_after_failure]);
        let first = completed(&trace.steps[0])
            .backend
            .as_ref()
            .expect("first balanced request has a backend");
        let second = completed(&trace.steps[1])
            .backend
            .as_ref()
            .expect("failover request has a backend");
        assert_ne!(first.selected, second.selected);
        assert_eq!(first.authorized, first.resource.backend_target);
        assert_eq!(second.authorized, second.resource.backend_target);
    }
}
