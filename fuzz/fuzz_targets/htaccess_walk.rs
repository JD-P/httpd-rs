#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::fs;
use std::sync::OnceLock;
use vapached::config::Config;

fn root() -> &'static std::path::Path {
    static ROOT: OnceLock<std::path::PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        let root =
            std::env::temp_dir().join(format!("vapache-htaccess-fuzz-{}", std::process::id()));
        fs::create_dir_all(root.join("a/b/c")).expect("create access-file fuzz root");
        fs::write(root.join("a/b/c/target.txt"), b"target").expect("write fuzz target");
        root
    })
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 1024 * 1024 {
        return;
    }
    let depth = usize::from(data[0] % 4);
    let dirs = [
        root().to_path_buf(),
        root().join("a"),
        root().join("a/b"),
        root().join("a/b/c"),
    ];
    for dir in &dirs {
        let _ = fs::remove_file(dir.join(".htaccess"));
    }
    fs::write(dirs[depth].join(".htaccess"), &data[1..]).expect("write access file");
    let config = format!(
        "VapacheCapability AccessFiles On\nListen 127.0.0.1:0\nDocumentRoot {}\n<Directory {}>\nAllowOverride All\nRequire all granted\n</Directory>\n",
        root().display(),
        root().display()
    );
    let path = root().join("httpd.conf");
    fs::write(&path, config).expect("write access-file configuration");
    let Ok(cfg) = Config::load(&path, root(), &HashMap::new(), &HashMap::new(), false) else {
        return;
    };
    let target = root().join("a/b/c/target.txt");
    let mut scope = cfg.effective_scope(None, &target, "/a/b/c/target.txt");
    let _ = vapached::htaccess::apply(&cfg, None, &mut scope, &target, "/a/b/c/target.txt");
    let _ = vapached::htaccess::collect_layers(&cfg, None, &target, "/a/b/c/target.txt");
});
