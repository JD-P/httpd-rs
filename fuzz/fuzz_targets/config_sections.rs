#![no_main]

use libfuzzer_sys::fuzz_target;
use httpd_rs::config_frontend::{logical_lines_with_numbers, parse_line, ConfigLine};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut stack = Vec::new();
    for (_, line) in logical_lines_with_numbers(text) {
        match parse_line(line.trim_start()) {
            Ok(ConfigLine::SectionStart { name, .. }) => stack.push(name),
            Ok(ConfigLine::SectionEnd { name }) => {
                if stack.last().is_some_and(|open| open == &name) {
                    stack.pop();
                }
            }
            Ok(ConfigLine::Directive { .. }) | Err(_) => {}
        }
        if stack.len() > 256 {
            break;
        }
    }
});
