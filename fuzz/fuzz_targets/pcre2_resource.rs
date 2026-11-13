#![no_main]

// Resource-policy and limit-monotonicity fuzzer for the in-tree PCRE2
// compatibility engine. The semantic differential intentionally raises its
// work ceiling so that it can reach deep matching behavior; this companion
// keeps production defaults active and mutates every public resource knob.

use libfuzzer_sys::fuzz_target;
use httpd_rs_pcre2::bytes::{Regex, RegexBuilder};
use httpd_rs_pcre2::ErrorKind;

type CaptureSpans = Vec<Option<(usize, usize)>>;

fn word(hi: u8, lo: u8) -> usize {
    usize::from(u16::from_be_bytes([hi, lo]))
}

fn flags(builder: &mut RegexBuilder, control: u8) {
    builder
        .caseless(control & 1 != 0)
        .dotall(control & 2 != 0)
        .multi_line(control & 4 != 0)
        .extended(control & 8 != 0)
        .crlf(control & 16 != 0)
        .utf(control & 32 != 0)
        .ucp(control & 64 != 0);
}

fn capture_outcome(
    regex: &Regex,
    subject: &[u8],
    start: usize,
) -> Result<Option<CaptureSpans>, ErrorKind> {
    let mut locations = regex.capture_locations();
    regex
        .captures_read_at(&mut locations, subject, start)
        .map(|matched| {
            matched.map(|_| {
                (0..locations.len())
                    .map(|index| locations.get(index))
                    .collect()
            })
        })
        .map_err(|error| error.kind())
}

fuzz_target!(|data: &[u8]| {
    let Some((header, payload)) = data.split_at_checked(13) else {
        return;
    };
    let Some(split) = payload.iter().position(|&byte| byte == 0 || byte == b'\n') else {
        return;
    };
    let Ok(pattern) = std::str::from_utf8(&payload[..split]) else {
        return;
    };
    let subject = &payload[split + 1..];
    if pattern.len() > 8 * 1024 || subject.len() > 64 * 1024 {
        return;
    }

    // First, exercise production defaults. LibFuzzer's timeout becomes a
    // backstop for any structural undercharge that admits unexpectedly costly
    // cold or hot searches.
    if let Ok(regex) = Regex::new(pattern) {
        let starts = [
            0,
            subject.len(),
            word(header[1], header[2]) % (subject.len() + 1),
        ];
        for &start in &starts {
            let _ = regex.is_match_at(subject, start);
            let _ = regex.find_at(subject, start);
            let _ = capture_outcome(&regex, subject, start);
        }
    }

    // Compilation admission must be monotone when every compile-time ceiling
    // is raised. This catches limit arithmetic, translated-size, capture and
    // nesting boundary mistakes without treating unsupported syntax as a
    // failure.
    let pattern_low = word(header[1], header[2]) % (pattern.len() + 2);
    let pattern_high = pattern_low.saturating_add(word(header[11], header[12]) + 1);
    let capture_low = usize::from(header[3] % 32) + 1;
    let capture_high = capture_low.saturating_add(usize::from(header[4]) + 1);
    let size_low = word(header[5], header[6])
        .saturating_mul(64)
        .saturating_add(1024);
    let size_high = size_low.saturating_add((usize::from(header[12]) + 1) * 4096);
    let nest_low = u32::from(header[7] % 64) + 1;
    let nest_high = nest_low.saturating_add(u32::from(header[12]) + 1);

    let mut low_builder = RegexBuilder::new();
    flags(&mut low_builder, header[0]);
    low_builder
        .max_pattern_size(pattern_low)
        .capture_limit(capture_low)
        .size_limit(size_low)
        .nest_limit(nest_low);
    let low = low_builder.build(pattern);

    let mut high_builder = RegexBuilder::new();
    flags(&mut high_builder, header[0]);
    high_builder
        .max_pattern_size(pattern_high)
        .capture_limit(capture_high)
        .size_limit(size_high)
        .nest_limit(nest_high);
    let high = high_builder.build(pattern);
    if low.is_ok() {
        assert!(
            high.is_ok(),
            "raising compile limits rejected admitted pattern {pattern:?}: low={:?}, high={:?}",
            low.as_ref().err(),
            high.as_ref().err(),
        );
    }

    // Match admission is likewise monotone. If the tighter subject/work
    // policy completes, the looser policy must complete with identical spans;
    // a ResourceLimit at the tighter boundary is an expected fail-closed
    // result and is left for further mutation around that edge.
    let subject_low = word(header[8], header[9]);
    let subject_high = subject_low.saturating_add(word(header[11], header[12]) + 1);
    let work_low = (word(header[10], header[11]) as u64).saturating_mul(256);
    let work_high = work_low.saturating_add(
        (word(header[11], header[12]) as u64)
            .saturating_add(1)
            .saturating_mul(1024),
    );

    let mut low_match_builder = RegexBuilder::new();
    flags(&mut low_match_builder, header[0]);
    low_match_builder
        .max_pattern_size(8 * 1024)
        .max_subject_size(subject_low)
        .match_limit(work_low)
        .capture_limit(256)
        .size_limit(4 * 1024 * 1024)
        .nest_limit(128);
    let Ok(low_match) = low_match_builder.build(pattern) else {
        return;
    };

    let mut high_match_builder = RegexBuilder::new();
    flags(&mut high_match_builder, header[0]);
    high_match_builder
        .max_pattern_size(8 * 1024)
        .max_subject_size(subject_high)
        .match_limit(work_high)
        .capture_limit(256)
        .size_limit(4 * 1024 * 1024)
        .nest_limit(128);
    let high_match = high_match_builder
        .build(pattern)
        .expect("match-only limit increase must not change compilation");

    let start = word(header[1], header[2]) % (subject.len() + 1);
    let low_outcome = capture_outcome(&low_match, subject, start);
    let high_outcome = capture_outcome(&high_match, subject, start);
    if low_outcome != Err(ErrorKind::ResourceLimit) {
        assert_eq!(
            low_outcome, high_outcome,
            "raising match limits changed result: pattern {pattern:?}, subject_len={}, start={start}",
            subject.len(),
        );
    }
});
