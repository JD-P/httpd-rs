use httpd_rs::http::{read_request, Limits, ReadError};
use std::io::{self, Read, Write};

fn read_accounted<R: Read + Write>(
    stream: &mut R,
) -> Result<Option<httpd_rs::http::Request>, ReadError> {
    let limits = Limits::default();
    let context = limits
        .resource_budget
        .context(std::net::IpAddr::from([192, 0, 2, 1]));
    httpd_rs::resource::with_resource_context(context, || {
        read_request(stream, &mut Vec::new(), &limits, |_| {})
    })
}

struct FaultyIo<'a> {
    input: &'a [u8],
    offset: usize,
    calls: usize,
    fail_at: usize,
    kind: io::ErrorKind,
    max_chunk: usize,
}

impl Read for FaultyIo<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.calls == self.fail_at {
            self.calls += 1;
            return Err(io::Error::new(self.kind, "injected read failure"));
        }
        self.calls += 1;
        let take = output
            .len()
            .min(self.max_chunk)
            .min(self.input.len().saturating_sub(self.offset));
        output[..take].copy_from_slice(&self.input[self.offset..self.offset + take]);
        self.offset += take;
        Ok(take)
    }
}

impl Write for FaultyIo<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn every_header_read_failure_fails_closed() {
    let wire = b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 8\r\n\r\n12345678";
    for kind in [
        io::ErrorKind::Interrupted,
        io::ErrorKind::WouldBlock,
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::ConnectionReset,
    ] {
        for fail_at in 0..12 {
            let mut stream = FaultyIo {
                input: wire,
                offset: 0,
                calls: 0,
                fail_at,
                kind,
                max_chunk: 7,
            };
            let result = read_accounted(&mut stream);
            if fail_at < stream.calls && kind != io::ErrorKind::Interrupted {
                assert!(
                    matches!(result, Err(ReadError::Io(_))),
                    "injected {kind:?} at read {fail_at} was not propagated"
                );
            }
        }
    }
}

#[test]
fn short_reads_at_every_boundary_preserve_the_request() {
    let wire = b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 8\r\n\r\n12345678";
    for chunk in 1..=wire.len() {
        let mut stream = FaultyIo {
            input: wire,
            offset: 0,
            calls: 0,
            fail_at: usize::MAX,
            kind: io::ErrorKind::Other,
            max_chunk: chunk,
        };
        let request = read_accounted(&mut stream)
            .expect("short reads must not fail")
            .expect("complete request");
        assert_eq!(request.target, b"/upload");
        assert_eq!(request.body, b"12345678");
    }
}
