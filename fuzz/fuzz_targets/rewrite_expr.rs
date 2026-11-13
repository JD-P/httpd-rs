#![no_main]

use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use httpd_rs::expr::{parse, validate_vars, Context};
use httpd_rs::http::{Headers, Request, Version};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(expression) = parse(text) else {
        return;
    };
    let _ = validate_vars(&expression);
    let request = Request {
        method: "GET".into(),
        target: b"/fuzz?x=1".to_vec(),
        raw_path: b"/fuzz".to_vec(),
        query: b"x=1".to_vec(),
        version: Version::Http11,
        headers: Headers::default(),
        body: Vec::new(),
        body_spool: None,
        keep_alive: true,
        expect_continue: false,
        framing: httpd_rs::verified::BodyFraming::None,
    };
    let env = [("FUZZ".to_string(), b"1".to_vec())];
    let mut context = Context::new(
        &request,
        &env,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Path::new("/tmp"),
        "/fuzz",
    )
    .with_fs_path(Some(Path::new("/tmp/fuzz")));
    let _ = expression.eval(&mut context);
});
