#![no_main]

use libfuzzer_sys::fuzz_target;
use vapached::config_frontend::{logical_lines, logical_lines_with_numbers, parse_line, ConfigLine};

const MAX_SOURCE: usize = 64 * 1024;

/// Independent byte-oriented model of Apache's physical-line continuation.
/// A continuation exists only when `\\` is immediately followed by LF or
/// CRLF, and it removes exactly that one backslash and line ending.
fn reference_lines(text: &str) -> Vec<(usize, String)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut pending: Option<(usize, Vec<u8>)> = None;
    let mut start = 0usize;
    let mut line_no = 1usize;

    while start < bytes.len() {
        let newline = bytes[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|offset| start + offset);
        let end = newline.unwrap_or(bytes.len());
        let mut physical_end = end;
        if newline.is_some() && physical_end > start && bytes[physical_end - 1] == b'\r' {
            physical_end -= 1;
        }
        let continued = newline.is_some() && bytes[start..physical_end].ends_with(b"\\");
        let content_end = physical_end - usize::from(continued);

        match &mut pending {
            Some((_, logical)) => logical.extend_from_slice(&bytes[start..content_end]),
            None => pending = Some((line_no, bytes[start..content_end].to_vec())),
        }
        if !continued {
            let (first, logical) = pending.take().expect("physical line started a logical line");
            out.push((
                first,
                String::from_utf8(logical).expect("source slices preserve UTF-8"),
            ));
        }

        let Some(end) = newline else {
            break;
        };
        start = end + 1;
        line_no += 1;
    }

    if let Some((first, logical)) = pending {
        out.push((
            first,
            String::from_utf8(logical).expect("source slices preserve UTF-8"),
        ));
    }
    out
}

fn parsed_lines(text: &str) -> Vec<Result<ConfigLine, String>> {
    logical_lines(text)
        .into_iter()
        .map(|line| parse_line(line.trim_start()))
        .collect()
}

fn check_source(text: &str) {
    assert_eq!(
        logical_lines_with_numbers(text),
        reference_lines(text),
        "physical-line projection diverged for {text:?}"
    );
}

fn mapped_source(data: &[u8]) -> String {
    const ALPHABET: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \\\r\n\t#<>[](){}^$.*+?-_=:\"'/";
    data.iter()
        .take(MAX_SOURCE)
        .map(|byte| ALPHABET[*byte as usize % ALPHABET.len()] as char)
        .collect()
}

fn continuation_variant(data: &[u8]) -> (String, String) {
    const TEMPLATES: &[&str] = &[
        "SetHandlercgi-script",
        "Requireall granted",
        "<FilesMatch \"^private[.]txt$\">",
        "<LocationMatch \"^/private[.]txt$\">",
        "RewriteRule ^private[.]txt$ - [F]",
        "Options +ExecCGI",
        "#Require all granted",
        "Header set X-Continuation exact",
    ];
    let template = TEMPLATES[data.first().copied().unwrap_or(0) as usize % TEMPLATES.len()];
    let chars: Vec<char> = template.chars().collect();
    // A string with N characters has N + 1 insertion boundaries.  Boundary
    // zero is important: `\\\nSetHandler...` must be the same logical line as
    // the unsplit spelling, not an empty directive followed by another line.
    let split = data.get(1).copied().unwrap_or(0) as usize % (chars.len() + 1);
    let use_crlf = data.get(2).is_some_and(|byte| byte & 1 != 0);
    let mut physical = String::with_capacity(template.len() + 3);
    for (index, ch) in chars.into_iter().enumerate() {
        if index == split {
            physical.push('\\');
            physical.push_str(if use_crlf { "\r\n" } else { "\n" });
        }
        physical.push(ch);
    }
    if split == template.chars().count() {
        physical.push('\\');
        physical.push_str(if use_crlf { "\r\n" } else { "\n" });
    }
    physical.push('\n');
    (format!("{template}\n"), physical)
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_SOURCE {
        return;
    }

    if let Ok(text) = std::str::from_utf8(data) {
        check_source(text);
    }
    check_source(&mapped_source(data));

    // Inserting only a backslash-newline at any character boundary is a
    // semantics-preserving physical encoding. Compare both the logical text
    // and the parsed configuration IR so a future join bug cannot silently
    // turn a guard into a different directive or argument list.
    let (plain, continued) = continuation_variant(data);
    check_source(&continued);
    assert_eq!(logical_lines(&plain), logical_lines(&continued));
    assert_eq!(parsed_lines(&plain), parsed_lines(&continued));
});
