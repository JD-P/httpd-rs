#![cfg(feature = "fault-injection")]

use httpd_rs::files::Target;
use httpd_rs::http::{read_request, Limits, ReadError};
use std::collections::HashMap;
use std::io;

struct Fragmented<'a> {
    input: &'a [u8],
    offset: usize,
}

impl io::Read for Fragmented<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.offset == self.input.len() {
            return Ok(0);
        }
        output[0] = self.input[self.offset];
        self.offset += 1;
        Ok(1)
    }
}

impl io::Write for Fragmented<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn fragmented(input: &[u8]) -> Fragmented<'_> {
    Fragmented { input, offset: 0 }
}

fn with_request_context<T>(operation: impl FnOnce(&Limits) -> T) -> T {
    let limits = Limits::default();
    let context = limits
        .resource_budget
        .context(std::net::IpAddr::from([192, 0, 2, 1]));
    httpd_rs::resource::with_resource_context(context, || operation(&limits))
}

#[test]
fn injected_header_failures_retry_eintr_and_reject_other_errors() {
    let _fault_guard = httpd_rs::fault::test_guard();
    let wire = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";

    httpd_rs::fault::configure("http.head.read", 0, io::ErrorKind::Interrupted);
    let request = with_request_context(|limits| {
        read_request(
            &mut io::Cursor::new(wire.to_vec()),
            &mut Vec::new(),
            limits,
            |_| {},
        )
    })
    .expect("EINTR is retryable")
    .expect("request after EINTR");
    assert_eq!(request.target, b"/");

    httpd_rs::fault::configure("http.head.read", 0, io::ErrorKind::ConnectionReset);
    let result = with_request_context(|limits| {
        read_request(
            &mut io::Cursor::new(wire.to_vec()),
            &mut Vec::new(),
            limits,
            |_| {},
        )
    });
    assert!(
        matches!(result, Err(ReadError::Io(error)) if error.kind() == io::ErrorKind::ConnectionReset)
    );
    httpd_rs::fault::clear();
}

#[test]
fn injected_secure_open_failure_never_returns_a_file() {
    let _fault_guard = httpd_rs::fault::test_guard();
    let root = std::env::temp_dir().join(format!("httpd-rs-failpoint-open-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("visible.txt"), b"secret").unwrap();

    httpd_rs::fault::configure("fs.open_beneath", 0, io::ErrorKind::PermissionDenied);
    assert!(matches!(
        httpd_rs::files::resolve_target(&root, std::path::Path::new("visible.txt"), true),
        Target::Forbidden | Target::NotFound
    ));
    httpd_rs::fault::clear();

    httpd_rs::fault::configure("fs.open_beneath", 0, io::ErrorKind::Unsupported);
    let error = httpd_rs::files::require_secure_path_resolution().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert!(error.to_string().contains("requires Linux openat2"));
    httpd_rs::fault::clear();
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn injected_configuration_open_failure_is_reported_without_partial_policy() {
    let _fault_guard = httpd_rs::fault::test_guard();
    let root =
        std::env::temp_dir().join(format!("httpd-rs-failpoint-config-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let config = root.join("httpd.conf");
    std::fs::write(&config, "Listen 127.0.0.1:0\n").unwrap();

    httpd_rs::fault::configure("fs.openat2", 0, io::ErrorKind::PermissionDenied);
    let result =
        httpd_rs::config::Config::load(&config, &root, &HashMap::new(), &HashMap::new(), false);
    assert!(result.is_err());
    httpd_rs::fault::clear();
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn injected_fixed_body_read_failure_is_propagated() {
    let _fault_guard = httpd_rs::fault::test_guard();
    let wire = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nbody";
    httpd_rs::fault::configure("http.body.read", 0, io::ErrorKind::ConnectionReset);
    let result = with_request_context(|limits| {
        read_request(&mut fragmented(wire), &mut Vec::new(), limits, |_| {})
    });
    assert!(
        matches!(result, Err(ReadError::Io(error)) if error.kind() == io::ErrorKind::ConnectionReset)
    );
}

#[test]
fn injected_chunk_line_and_data_failures_are_propagated() {
    let _fault_guard = httpd_rs::fault::test_guard();
    let wire = b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n";
    for boundary in ["http.chunk.line", "http.chunk.read"] {
        httpd_rs::fault::configure(boundary, 0, io::ErrorKind::ConnectionReset);
        let result = with_request_context(|limits| {
            read_request(&mut fragmented(wire), &mut Vec::new(), limits, |_| {})
        });
        assert!(
            matches!(result, Err(ReadError::Io(error)) if error.kind() == io::ErrorKind::ConnectionReset),
            "{boundary} did not fail closed"
        );
    }
}
