#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::fs;
use std::sync::OnceLock;
use httpd_rs::config::Config;
use httpd_rs::config_frontend::{logical_lines_with_numbers, parse_line, ConfigLine};

fn root() -> &'static std::path::Path {
    static ROOT: OnceLock<std::path::PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        let root = std::env::temp_dir().join(format!("httpd-rs-config-fuzz-{}", std::process::id()));
        fs::create_dir_all(&root).expect("create config fuzz root");
        root
    })
}

fn has_external_reader(data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    logical_lines_with_numbers(text)
        .into_iter()
        .any(|(_, line)| {
            let Ok(ConfigLine::Directive { name, .. }) = parse_line(line.trim_start()) else {
                return false;
            };
            matches!(
                name.to_ascii_lowercase().as_str(),
                "include"
                    | "includeoptional"
                    | "typesconfig"
                    | "authuserfile"
                    | "authgroupfile"
                    | "rewritemap"
                    | "sslcertificatefile"
                    | "sslcertificatekeyfile"
                    | "sslcertificatechainfile"
                    | "sslclientcafile"
                    | "sslcacertificatefile"
            )
        })
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 || has_external_reader(data) {
        return;
    }
    let path = root().join("httpd.conf");
    fs::write(&path, data).expect("write fuzz configuration");
    let strict = data.first().is_some_and(|byte| byte & 1 != 0);
    let _ = Config::load(&path, root(), &HashMap::new(), &HashMap::new(), strict);
});
