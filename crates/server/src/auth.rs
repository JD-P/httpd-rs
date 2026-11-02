//! HTTP Basic authentication (`mod_auth_basic` + `mod_authn_file`).
//!
//! Only password *verification* is implemented; plaintext passwords are
//! never accepted.  Supported htpasswd encodings are Apache MD5 (`$apr1$`),
//! Unix MD5 (`$1$`), bcrypt (`$2*$`), `{SHA}` and salted `{SSHA}`.
//! Anything else fails closed.

use crate::access::Identity;
use crate::config::Scope;
use crate::http::Request;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use md5::Md5;
use sha1::{Digest, Sha1};
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

const MAX_PASSWORD_FILE: u64 = 4 * 1024 * 1024;
const MAX_AUTH_CACHE_BYTES: usize = 16 * 1024 * 1024;
const MAX_AUTH_CACHE_ENTRIES: usize = 128;
const AUTH_FAILURE_CACHE_TTL: Duration = Duration::from_millis(250);

const CRYPT_ALPHABET: &[u8; 64] =
    b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

thread_local! {
    /// The authenticated identity for the synchronous request dispatch that
    /// is currently running on this worker. Dispatch never yields while this
    /// value is live, including on HTTP/2 worker threads.
    static REQUEST_IDENTITY: RefCell<Option<String>> = const { RefCell::new(None) };
}

pub(crate) fn reset_request_identity() {
    REQUEST_IDENTITY.with(|identity| *identity.borrow_mut() = None);
}

pub(crate) fn take_request_identity() -> Option<String> {
    REQUEST_IDENTITY.with(|identity| identity.borrow_mut().take())
}

/// Verify the request's Basic credentials against `AuthUserFile`.  Returns
/// `None` for missing, malformed, unsupported or non-matching credentials.
pub fn authenticate(scope: &Scope, req: &Request, mutable_auth_files: bool) -> Option<Identity> {
    if !scope
        .authorization
        .auth_type
        .as_deref()
        .map(|t| t.eq_ignore_ascii_case("basic"))
        .unwrap_or(false)
    {
        return None;
    }
    let header = req.header_str("authorization")?.trim();
    let mut parts = header.splitn(2, char::is_whitespace);
    let scheme = parts.next()?;
    let token = parts.next()?.trim();
    if !scheme.eq_ignore_ascii_case("basic") || token.is_empty() {
        return None;
    }
    let decoded = STANDARD
        .decode(token)
        .or_else(|_| STANDARD_NO_PAD.decode(token))
        .ok()?;
    let colon = decoded.iter().position(|b| *b == b':')?;
    let user = std::str::from_utf8(&decoded[..colon]).ok()?;
    let password = &decoded[colon + 1..];
    if user.is_empty()
        || user.chars().any(|c| c.is_control())
        || user.contains(':')
        || password.len() > 4096
    {
        return None;
    }
    let file = scope.authorization.auth_user_file.as_ref()?;
    let stored = lookup_user(file, user, mutable_auth_files)?;
    if !verify_password(password, &stored) {
        return None;
    }
    let groups = match scope.authorization.auth_group_file.as_ref() {
        Some(path) => groups_for(path, user, mutable_auth_files)?,
        None => Vec::new(),
    };
    let identity = Identity {
        user: user.to_string(),
        groups,
    };
    REQUEST_IDENTITY.with(|current| *current.borrow_mut() = Some(identity.user.clone()));
    Some(identity)
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct AuthFileKey {
    path: PathBuf,
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[derive(Default)]
struct AuthFileCache {
    entries: HashMap<AuthFileKey, (Arc<ParsedAuthFile>, usize)>,
    failures: HashMap<(PathBuf, bool, u32), Instant>,
    bytes: usize,
}

struct ParsedAuthFile {
    users: HashMap<String, Option<String>>,
    groups_by_user: HashMap<String, Vec<String>>,
}

fn auth_file_cache() -> &'static Mutex<AuthFileCache> {
    static CACHE: OnceLock<Mutex<AuthFileCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(AuthFileCache::default()))
}

fn auth_key(path: &Path, meta: &std::fs::Metadata) -> AuthFileKey {
    AuthFileKey {
        path: path.to_path_buf(),
        dev: meta.dev(),
        ino: meta.ino(),
        size: meta.len(),
        mtime: meta.mtime(),
        mtime_nsec: meta.mtime_nsec(),
        ctime: meta.ctime(),
        ctime_nsec: meta.ctime_nsec(),
    }
}

fn read_small(path: &Path, mutable: bool) -> Option<Arc<ParsedAuthFile>> {
    let service_uid = crate::files::effective_uid();
    let failure_key = (path.to_path_buf(), mutable, service_uid);
    let now = Instant::now();
    {
        let mut cache = auth_file_cache()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        cache
            .failures
            .retain(|_, failed| now.saturating_duration_since(*failed) < AUTH_FAILURE_CACHE_TTL);
        if cache.failures.contains_key(&failure_key) {
            return None;
        }
    }
    let data = read_small_uncached(path, mutable, service_uid);
    if data.is_none() {
        let mut cache = auth_file_cache()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if cache.failures.len() >= MAX_AUTH_CACHE_ENTRIES {
            if let Some(victim) = cache.failures.keys().next().cloned() {
                cache.failures.remove(&victim);
            }
        }
        cache.failures.insert(failure_key, Instant::now());
    }
    data
}

fn read_small_uncached(
    path: &Path,
    mutable: bool,
    service_uid: u32,
) -> Option<Arc<ParsedAuthFile>> {
    // O_NONBLOCK is security-significant: opening an attacker-selected FIFO
    // must not park a request worker before the regular-file check runs.
    let file = if mutable {
        crate::files::open_admin_path(path, libc::O_RDONLY | libc::O_NONBLOCK, 0).ok()?
    } else {
        crate::files::validate_service_immutable_file(path, service_uid).ok()?
    };
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_PASSWORD_FILE {
        return None;
    }
    let key = auth_key(path, &meta);
    if let Some(data) = auth_file_cache()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .entries
        .get(&key)
        .map(|(data, _)| Arc::clone(data))
    {
        return path_names_key(path, &key).then_some(data);
    }
    let raw = read_bounded(&file)?;
    let (parsed, parsed_weight) = parse_auth_file(&raw)?;
    let data = Arc::new(parsed);
    let after = file.metadata().ok()?;
    if auth_key(path, &after) != key || !path_names_key(path, &key) {
        return None;
    }
    let weight = parsed_weight
        .saturating_add(path.as_os_str().as_encoded_bytes().len())
        .saturating_add(128);
    if weight <= MAX_AUTH_CACHE_BYTES {
        let mut cache = auth_file_cache()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let stale: Vec<AuthFileKey> = cache
            .entries
            .keys()
            .filter(|candidate| candidate.path == path && *candidate != &key)
            .cloned()
            .collect();
        for stale_key in stale {
            if let Some((_, old_weight)) = cache.entries.remove(&stale_key) {
                cache.bytes = cache.bytes.saturating_sub(old_weight);
            }
        }
        while cache.entries.len() >= MAX_AUTH_CACHE_ENTRIES
            || cache.bytes.saturating_add(weight) > MAX_AUTH_CACHE_BYTES
        {
            let Some(victim) = cache.entries.keys().next().cloned() else {
                break;
            };
            if let Some((_, old_weight)) = cache.entries.remove(&victim) {
                cache.bytes = cache.bytes.saturating_sub(old_weight);
            }
        }
        cache.bytes = cache.bytes.saturating_add(weight);
        cache.entries.insert(key, (Arc::clone(&data), weight));
    }
    Some(data)
}

fn path_names_key(path: &Path, key: &AuthFileKey) -> bool {
    let Ok(file) = crate::files::open_admin_path(path, libc::O_RDONLY | libc::O_NONBLOCK, 0) else {
        return false;
    };
    let Ok(meta) = file.metadata() else {
        return false;
    };
    meta.is_file() && meta.dev() == key.dev && meta.ino() == key.ino
}

fn read_bounded(reader: impl Read) -> Option<String> {
    let mut data = Vec::new();
    reader
        .take(MAX_PASSWORD_FILE + 1)
        .read_to_end(&mut data)
        .ok()?;
    if data.len() as u64 > MAX_PASSWORD_FILE {
        return None;
    }
    String::from_utf8(data).ok()
}

fn parse_auth_file(data: &str) -> Option<(ParsedAuthFile, usize)> {
    let mut users: HashMap<String, Option<String>> = HashMap::new();
    let mut groups_by_user: HashMap<String, Vec<String>> = HashMap::new();
    let mut weight = 0usize;
    for line in data.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.to_string();
        let value = value.trim_end_matches('\r').to_string();
        weight = weight
            .checked_add(name.len())?
            .checked_add(value.len())?
            .checked_add(96)?;
        if weight > MAX_AUTH_CACHE_BYTES {
            return None;
        }
        match users.entry(name.clone()) {
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(Some(value.clone()));
            }
            std::collections::hash_map::Entry::Occupied(mut slot) => {
                // Preserve the existing fail-closed duplicate-user behavior.
                slot.insert(None);
            }
        }
        let group = name.trim().to_string();
        for member in value.split_whitespace() {
            weight = weight
                .checked_add(member.len())?
                .checked_add(group.len())?
                .checked_add(64)?;
            if weight > MAX_AUTH_CACHE_BYTES {
                return None;
            }
            groups_by_user
                .entry(member.to_string())
                .or_default()
                .push(group.clone());
        }
    }
    Some((
        ParsedAuthFile {
            users,
            groups_by_user,
        },
        weight,
    ))
}

/// Validate a main-configuration authentication database before serving.
/// Runtime reads repeat every property so later replacement still fails
/// closed, including for paths introduced by an access file.
pub fn validate_auth_file(path: &Path, mutable: bool, service_uid: u32) -> Result<(), String> {
    read_small_uncached(path, mutable, service_uid)
        .map(|_| ())
        .ok_or_else(|| {
            format!(
                "authentication file {} must be bounded strict UTF-8 and, unless MutableAuthFiles is enabled, operator-controlled",
                path.display()
            )
        })
}

fn lookup_user(path: &Path, user: &str, mutable: bool) -> Option<String> {
    let data = read_small(path, mutable)?;
    data.users.get(user)?.clone()
}

fn groups_for(path: &Path, user: &str, mutable: bool) -> Option<Vec<String>> {
    let data = read_small(path, mutable)?;
    Some(data.groups_by_user.get(user).cloned().unwrap_or_default())
}

fn verify_password(password: &[u8], stored: &str) -> bool {
    let stored = stored.trim();
    if let Some(encoded) = stored.strip_prefix("{SHA}") {
        let Ok(expected) = STANDARD
            .decode(encoded)
            .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        else {
            return false;
        };
        if expected.len() != 20 {
            return false;
        }
        return bool::from(Sha1::digest(password).as_slice().ct_eq(expected.as_slice()));
    }
    if let Some(encoded) = stored.strip_prefix("{SSHA}") {
        let Ok(decoded) = STANDARD
            .decode(encoded)
            .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        else {
            return false;
        };
        if decoded.len() < 20 {
            return false;
        }
        let mut h = Sha1::new();
        h.update(password);
        h.update(&decoded[20..]);
        return bool::from(h.finalize().as_slice().ct_eq(&decoded[..20]));
    }
    if stored.starts_with("$apr1$") {
        let Some(_expensive) = crate::resource::try_expensive() else {
            return false;
        };
        return md5_crypt_matches(password, stored, "$apr1$");
    }
    if stored.starts_with("$1$") {
        let Some(_expensive) = crate::resource::try_expensive() else {
            return false;
        };
        return md5_crypt_matches(password, stored, "$1$");
    }
    if stored.starts_with("$2a$")
        || stored.starts_with("$2b$")
        || stored.starts_with("$2x$")
        || stored.starts_with("$2y$")
    {
        let cost = stored
            .split('$')
            .nth(2)
            .and_then(|cost| cost.parse::<u32>().ok())
            .unwrap_or(u32::MAX);
        if !vapache_verified::bcrypt_cost_admit(cost) {
            return false;
        }
        let Some(_expensive) = crate::resource::try_expensive() else {
            return false;
        };
        let Ok(password) = std::str::from_utf8(password) else {
            return false;
        };
        return bcrypt::verify(password, stored).unwrap_or(false);
    }
    false
}

fn md5_crypt_matches(password: &[u8], stored: &str, magic: &str) -> bool {
    let Some(rest) = stored.strip_prefix(magic) else {
        return false;
    };
    let Some((salt, _)) = rest.split_once('$') else {
        return false;
    };
    let salt = salt.as_bytes();
    if salt.len() > 8 {
        return false;
    }
    let computed = md5_crypt(password, salt, magic);
    bool::from(computed.as_bytes().ct_eq(stored.as_bytes()))
}

fn md5_crypt(password: &[u8], salt: &[u8], magic: &str) -> String {
    let mut ctx = Md5::new();
    ctx.update(password);
    ctx.update(salt);
    ctx.update(password);
    let mut digest = ctx.finalize();

    let mut ctx = Md5::new();
    ctx.update(password);
    ctx.update(magic.as_bytes());
    ctx.update(salt);
    let mut left = password.len();
    while left > 0 {
        let n = left.min(16);
        ctx.update(&digest[..n]);
        left -= n;
    }
    let mut i = password.len();
    while i > 0 {
        if i & 1 != 0 {
            ctx.update([0u8]);
        } else {
            ctx.update(&password[..1]);
        }
        i >>= 1;
    }
    digest = ctx.finalize();

    for i in 0..1000 {
        let mut ctx = Md5::new();
        if i & 1 != 0 {
            ctx.update(password);
        } else {
            ctx.update(digest.as_slice());
        }
        if i % 3 != 0 {
            ctx.update(salt);
        }
        if i % 7 != 0 {
            ctx.update(password);
        }
        if i & 1 != 0 {
            ctx.update(digest.as_slice());
        } else {
            ctx.update(password);
        }
        digest = ctx.finalize();
    }

    let mut out = String::with_capacity(magic.len() + salt.len() + 24);
    out.push_str(magic);
    out.push_str(std::str::from_utf8(salt).unwrap_or(""));
    out.push('$');
    b64_from_24(&mut out, digest[0], digest[6], digest[12], 4);
    b64_from_24(&mut out, digest[1], digest[7], digest[13], 4);
    b64_from_24(&mut out, digest[2], digest[8], digest[14], 4);
    b64_from_24(&mut out, digest[3], digest[9], digest[15], 4);
    b64_from_24(&mut out, digest[4], digest[10], digest[5], 4);
    b64_from_24(&mut out, 0, 0, digest[11], 2);
    out
}

fn b64_from_24(out: &mut String, a: u8, b: u8, c: u8, n: usize) {
    let mut w = ((a as u32) << 16) | ((b as u32) << 8) | c as u32;
    for _ in 0..n {
        out.push(CRYPT_ALPHABET[(w & 0x3f) as usize] as char);
        w >>= 6;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{BodyFraming, Headers, Version};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "vapache-auth-{label}-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn request(authorization: Option<Vec<u8>>) -> Request {
        let mut headers = Headers::default();
        if let Some(value) = authorization {
            headers.insert("Authorization", value);
        }
        Request {
            method: "GET".into(),
            target: b"/".to_vec(),
            raw_path: b"/".to_vec(),
            query: Vec::new(),
            version: Version::Http11,
            headers,
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: BodyFraming::None,
        }
    }

    fn basic(value: &[u8]) -> Vec<u8> {
        format!("Basic {}", STANDARD.encode(value)).into_bytes()
    }

    #[test]
    fn authenticate_rejects_malformed_and_unsafe_credentials() {
        let mut scope = Scope::default();
        assert!(authenticate(&scope, &request(None), true).is_none());
        scope.authorization.auth_type = Some("basic".into());
        for header in [
            b"Bearer abc".to_vec(),
            b"Basic ".to_vec(),
            b"Basic %%%".to_vec(),
            basic(b"missing-colon"),
            basic(b"\xff:secret"),
            basic(b":secret"),
            basic(b"bad\nname:secret"),
        ] {
            assert!(authenticate(&scope, &request(Some(header)), true).is_none());
        }
        let mut oversized = b"alice:".to_vec();
        oversized.extend(std::iter::repeat_n(b'x', 4097));
        assert!(authenticate(&scope, &request(Some(basic(&oversized))), true).is_none());
        assert!(authenticate(&scope, &request(Some(basic(b"alice:secret"))), true).is_none());
    }

    #[test]
    fn authenticate_reads_unique_user_and_groups() {
        let users = temp_path("users");
        let groups = temp_path("groups");
        std::fs::write(
            &users,
            "# comment\nmalformed\nalice:$apr1$gqijKP2Z$nBjZURLWP3/zSfPLTfhVM0\r\n",
        )
        .unwrap();
        std::fs::write(&groups, "malformed\n admins: alice bob\nother: bob\n").unwrap();
        let mut scope = Scope::default();
        scope.authorization.auth_type = Some("BASIC".into());
        scope.authorization.auth_user_file = Some(users.clone());
        scope.authorization.auth_group_file = Some(groups.clone());

        let identity = authenticate(&scope, &request(Some(basic(b"alice:secret"))), true).unwrap();
        assert_eq!(identity.user, "alice");
        assert_eq!(identity.groups, ["admins"]);
        assert!(authenticate(&scope, &request(Some(basic(b"alice:wrong"))), true).is_none());
        assert!(authenticate(&scope, &request(Some(basic(b"nobody:secret"))), true).is_none());

        std::fs::write(&groups, b"admins: alice\xff\n").unwrap();
        assert!(authenticate(&scope, &request(Some(basic(b"alice:secret"))), true).is_none());
        std::fs::write(&groups, "admins: alice bob\n").unwrap();

        std::fs::write(
            &users,
            "alice:$apr1$gqijKP2Z$nBjZURLWP3/zSfPLTfhVM0\nalice:duplicate\n",
        )
        .unwrap();
        assert!(authenticate(&scope, &request(Some(basic(b"alice:secret"))), true).is_none());
        std::fs::remove_file(users).unwrap();
        std::fs::remove_file(groups).unwrap();
    }

    #[test]
    fn password_file_and_hash_error_edges_fail_closed() {
        let directory = temp_path("directory");
        std::fs::create_dir(&directory).unwrap();
        assert!(read_small(&directory, true).is_none());
        assert!(groups_for(&directory.join("missing"), "alice", true).is_none());
        std::fs::remove_dir(directory).unwrap();
        assert!(read_bounded(std::io::Cursor::new(vec![
            b'x';
            MAX_PASSWORD_FILE as usize + 1
        ]))
        .is_none());

        assert!(!verify_password(b"x", "{SHA}%%%"));
        assert!(!verify_password(b"x", "{SSHA}%%%"));
        assert!(!verify_password(b"x", "{SSHA}eA=="));
        assert!(!verify_password(
            b"\xff",
            "$2y$05$lFdvgVrS6ROEENEOjKS5h.y4SA05OvKSOFRPC1BcjARNhNt.DQ8jC"
        ));
        assert!(!verify_password(b"x", "$1$x$bad"));
        assert!(!md5_crypt_matches(b"x", "$1$x$bad", "$apr1$"));
        assert!(!md5_crypt_matches(b"x", "$apr1$missing", "$apr1$"));
        assert!(!md5_crypt_matches(b"x", "$apr1$123456789$bad", "$apr1$"));
    }

    #[test]
    fn authentication_files_reject_fifos_and_symlinks_without_blocking() {
        let fifo = temp_path("fifo");
        crate::files::make_test_fifo(&fifo).unwrap();
        let started = Instant::now();
        assert!(read_small(&fifo, true).is_none());
        assert!(started.elapsed() < Duration::from_secs(1));

        let regular = temp_path("symlink-target");
        let linked = temp_path("symlink");
        std::fs::write(&regular, "alice:hash\n").unwrap();
        std::os::unix::fs::symlink(&regular, &linked).unwrap();
        assert!(read_small(&linked, true).is_none());

        std::fs::remove_file(fifo).unwrap();
        std::fs::remove_file(linked).unwrap();
        std::fs::remove_file(regular).unwrap();
    }

    #[test]
    fn authentication_files_are_strict_utf8_and_immutable_by_default() {
        let invalid = temp_path("invalid-utf8");
        std::fs::write(&invalid, b"alice:$apr1$x$\xff\n").unwrap();
        assert!(read_small(&invalid, true).is_none());

        let mutable = temp_path("service-owned");
        std::fs::write(&mutable, "alice:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=\n").unwrap();
        assert!(read_small(&mutable, false).is_none());
        assert!(read_small(&mutable, true).is_some());

        std::fs::remove_file(invalid).unwrap();
        std::fs::remove_file(mutable).unwrap();
    }

    #[test]
    fn apr1_matches_apache_htpasswd() {
        // Generated with `htpasswd -nb alice secret`.
        assert!(verify_password(
            b"secret",
            "$apr1$gqijKP2Z$nBjZURLWP3/zSfPLTfhVM0"
        ));
        assert!(!verify_password(
            b"wrong",
            "$apr1$gqijKP2Z$nBjZURLWP3/zSfPLTfhVM0"
        ));
    }

    #[test]
    fn sha_and_ssha() {
        // echo -n password | openssl dgst -sha1 -binary | base64
        assert!(verify_password(
            b"password",
            "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
        ));
        // Salted SHA variant: 20-byte digest followed by "salt".
        let mut raw = Sha1::digest(b"passwordsalt").to_vec();
        raw.extend_from_slice(b"salt");
        let encoded = STANDARD.encode(raw);
        assert!(verify_password(b"password", &format!("{{SSHA}}{encoded}")));
        assert!(!verify_password(b"nope", &format!("{{SSHA}}{encoded}")));
    }

    #[test]
    fn bcrypt_matches_apache_htpasswd() {
        // Generated with `htpasswd -nbB alice secret`.
        assert!(verify_password(
            b"secret",
            "$2y$05$lFdvgVrS6ROEENEOjKS5h.y4SA05OvKSOFRPC1BcjARNhNt.DQ8jC"
        ));
        assert!(!verify_password(
            b"wrong",
            "$2y$05$lFdvgVrS6ROEENEOjKS5h.y4SA05OvKSOFRPC1BcjARNhNt.DQ8jC"
        ));
        assert!(!verify_password(
            b"secret",
            "$2y$31$lFdvgVrS6ROEENEOjKS5h.y4SA05OvKSOFRPC1BcjARNhNt.DQ8jC"
        ));
    }

    #[test]
    fn unsupported_hashes_fail_closed() {
        assert!(!verify_password(b"password", "password"));
        assert!(!verify_password(b"password", "{PLAIN}password"));
        assert!(!verify_password(b"password", "{CRYPT}xyz"));
    }
}
