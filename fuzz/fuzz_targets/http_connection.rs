#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::{self, Read, Write};
use httpd_rs::http::{read_request, Limits, ReadError};

struct Fragmented<'a> {
    input: &'a [u8],
    offset: usize,
    chunk: usize,
}

impl Read for Fragmented<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.offset == self.input.len() {
            return Ok(0);
        }
        let take = output
            .len()
            .min(self.chunk)
            .min(self.input.len() - self.offset);
        output[..take].copy_from_slice(&self.input[self.offset..self.offset + take]);
        self.offset += take;
        Ok(take)
    }
}

impl Write for Fragmented<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn parse_sequence(data: &[u8], chunk: usize, spool_bytes: u64, spool_files: u64) -> Vec<String> {
    let mut input = Fragmented {
        input: data,
        offset: 0,
        chunk: chunk.max(1),
    };
    let mut buffered = Vec::new();
    let mut limits = Limits::default();
    limits.body = 2 * 1024 * 1024;
    limits.max_spool_bytes = spool_bytes;
    limits.max_spool_files = spool_files;
    let mut outcomes = Vec::new();
    for _ in 0..16 {
        let before = (input.offset, buffered.len());
        match read_request(&mut input, &mut buffered, &limits, |_| {}) {
            Ok(Some(request)) => {
                outcomes.push(format!(
                    "ok:{}:{:?}:{}:{}",
                    request.method,
                    request.target,
                    request.body_len(),
                    request.keep_alive
                ));
                assert_ne!(before, (input.offset, buffered.len()));
            }
            Ok(None) => {
                outcomes.push("eof".into());
                break;
            }
            Err(ReadError::Parse(error)) => {
                outcomes.push(format!("parse:{}:{}", error.status(), error.message()));
                break;
            }
            Err(ReadError::Io(error)) => {
                outcomes.push(format!("io:{:?}", error.kind()));
                break;
            }
        }
    }
    assert_eq!(limits.resource_budget.usage(), (0, 0, 0));
    outcomes
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let chunk = usize::from(data[0]).max(1);
    // Vary the aggregate quotas so the same framing corpus explores normal
    // spooling, byte exhaustion and file-slot exhaustion.  A zero file quota
    // is intentional and must still leave the process budget balanced.
    let spool_bytes = u64::from(data[1]) * 4096;
    let spool_files = u64::from(data[2] % 5);
    let wire = &data[3..];
    let whole = parse_sequence(wire, wire.len().max(1), spool_bytes, spool_files);
    let fragmented = parse_sequence(wire, chunk, spool_bytes, spool_files);
    assert_eq!(
        whole, fragmented,
        "HTTP parsing changed with read fragmentation"
    );
});
