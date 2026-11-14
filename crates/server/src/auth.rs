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
    let token = basic_token(req.header("authorization")?)?;
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
    let (known_user, password_matches) =
        authenticate_password(file, user, password, mutable_auth_files)?;
    // A syntactically valid credential always executes exactly one verifier.
    // Missing users select the generation-bound dummy from the parsed file;
    // do not turn this into a short-circuiting boolean expression.
    if !(known_user & password_matches) {
        return None;
    }
    // Group authorization is a separate provider. Preserve its unavailable
    // state instead of treating a missing/unreadable database as an empty
    // membership set: the latter can grant `Require not group ...`.
    let groups = scope
        .authorization
        .auth_group_file
        .as_ref()
        .and_then(|path| groups_for(path, user, mutable_auth_files));
    let identity = Identity {
        user: user.to_string(),
        groups,
    };
    if !req.record_authenticated_identity(&identity.user) {
        return None;
    }
    Some(identity)
}

/// Parse the byte-oriented Apache Basic scheme boundary. HTTP field values
/// may contain UTF-8 obs-text, but Unicode whitespace is data rather than an
/// authentication grammar separator.
fn basic_token(header: &[u8]) -> Option<&[u8]> {
    let mut start = 0usize;
    while start < header.len() && matches!(header[start], b' ' | b'\t') {
        start += 1;
    }
    let mut end = header.len();
    while end > start && matches!(header[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    let scheme_basic =
        end.saturating_sub(start) >= 5 && header[start..start + 5].eq_ignore_ascii_case(b"basic");
    let separator = start
        .checked_add(5)
        .filter(|index| *index < end)
        .is_some_and(|index| matches!(header[index], b' ' | b'\t'));
    let mut token_start = start.saturating_add(5);
    while token_start < end && matches!(header[token_start], b' ' | b'\t') {
        token_start += 1;
    }
    let token_nonempty = token_start < end;
    let token_has_no_ascii_whitespace = token_nonempty
        && header[token_start..end]
            .iter()
            .all(|byte| !byte.is_ascii_whitespace());
    if !httpd_rs_verified::basic_authorization_shape_admit(
        scheme_basic,
        separator,
        token_nonempty,
        token_has_no_ascii_whitespace,
    ) {
        return None;
    }
    Some(&header[token_start..end])
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
    passwords: Option<PasswordDatabase>,
    groups_by_user: HashMap<String, Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PasswordProfile {
    Sha,
    SaltedSha { salt_len: usize },
    Apr1 { salt_len: usize },
    UnixMd5 { salt_len: usize },
    Bcrypt { cost: u32 },
}

#[derive(Clone)]
enum PasswordVerifier {
    Sha([u8; 20]),
    SaltedSha {
        digest: [u8; 20],
        salt: Box<[u8]>,
    },
    Md5Crypt {
        stored: Box<str>,
        salt: Box<[u8]>,
        magic: &'static str,
    },
    Bcrypt {
        stored: Box<str>,
        cost: u32,
    },
}

impl PasswordVerifier {
    fn parse(stored: &str) -> Option<(PasswordProfile, Self)> {
        if let Some(encoded) = stored.strip_prefix("{SHA}") {
            let decoded = STANDARD
                .decode(encoded)
                .or_else(|_| STANDARD_NO_PAD.decode(encoded))
                .ok()?;
            let digest = <[u8; 20]>::try_from(decoded.as_slice()).ok()?;
            return Some((PasswordProfile::Sha, Self::Sha(digest)));
        }
        if let Some(encoded) = stored.strip_prefix("{SSHA}") {
            let decoded = STANDARD
                .decode(encoded)
                .or_else(|_| STANDARD_NO_PAD.decode(encoded))
                .ok()?;
            if decoded.len() < 20 {
                return None;
            }
            let digest = <[u8; 20]>::try_from(&decoded[..20]).ok()?;
            let salt = Box::<[u8]>::from(&decoded[20..]);
            return Some((
                PasswordProfile::SaltedSha {
                    salt_len: salt.len(),
                },
                Self::SaltedSha { digest, salt },
            ));
        }
        for (magic, apr1) in [("$apr1$", true), ("$1$", false)] {
            let Some(rest) = stored.strip_prefix(magic) else {
                continue;
            };
            let (salt, encoded) = rest.split_once('$')?;
            if salt.len() > 8
                || encoded.len() != 22
                || !encoded.bytes().all(|byte| CRYPT_ALPHABET.contains(&byte))
            {
                return None;
            }
            let profile = if apr1 {
                PasswordProfile::Apr1 {
                    salt_len: salt.len(),
                }
            } else {
                PasswordProfile::UnixMd5 {
                    salt_len: salt.len(),
                }
            };
            return Some((
                profile,
                Self::Md5Crypt {
                    stored: stored.into(),
                    salt: salt.as_bytes().into(),
                    magic,
                },
            ));
        }
        if stored.starts_with("$2") {
            // Use the same parser as verification. Merely checking the shape
            // here would admit non-canonical bcrypt base64 that `verify`
            // rejects before doing any work, recreating a timing oracle.
            let parts = stored.parse::<bcrypt::HashParts>().ok()?;
            let cost = parts.get_cost();
            if httpd_rs_verified::bcrypt_cost_admit(cost) {
                return Some((
                    PasswordProfile::Bcrypt { cost },
                    Self::Bcrypt {
                        stored: stored.into(),
                        cost,
                    },
                ));
            }
        }
        None
    }

    fn verify(&self, password: &[u8]) -> bool {
        #[cfg(test)]
        PASSWORD_VERIFY_CALLS.with(|calls| calls.set(calls.get().saturating_add(1)));
        match self {
            Self::Sha(expected) => {
                bool::from(Sha1::digest(password).as_slice().ct_eq(expected.as_slice()))
            }
            Self::SaltedSha { digest, salt } => {
                let mut h = Sha1::new();
                h.update(password);
                h.update(salt);
                bool::from(h.finalize().as_slice().ct_eq(digest.as_slice()))
            }
            Self::Md5Crypt {
                stored,
                salt,
                magic,
            } => {
                let Some(_expensive) = crate::resource::try_expensive() else {
                    return false;
                };
                let computed = md5_crypt(password, salt, magic);
                bool::from(computed.as_bytes().ct_eq(stored.as_bytes()))
            }
            Self::Bcrypt { stored, cost } => {
                let Some(_expensive) = crate::resource::try_bcrypt(*cost) else {
                    return false;
                };
                bcrypt::verify(password, stored.as_ref()).unwrap_or(false)
            }
        }
    }
}

struct PasswordDatabase {
    users: HashMap<String, PasswordVerifier>,
    dummy: PasswordVerifier,
}

impl PasswordDatabase {
    fn parse(users: &HashMap<String, Option<String>>) -> Option<Self> {
        let mut profile = None;
        let mut parsed = HashMap::with_capacity(users.len());
        let mut dummy = None;
        for (user, stored) in users {
            let (candidate_profile, verifier) = PasswordVerifier::parse(stored.as_ref()?)?;
            if profile
                .as_ref()
                .is_some_and(|expected| expected != &candidate_profile)
            {
                return None;
            }
            profile.get_or_insert(candidate_profile);
            dummy.get_or_insert_with(|| verifier.clone());
            parsed.insert(user.clone(), verifier);
        }
        Some(Self {
            users: parsed,
            dummy: dummy?,
        })
    }

    fn select(&self, user: &str) -> (bool, &PasswordVerifier) {
        match self.users.get(user) {
            Some(verifier) => (true, verifier),
            None => (false, &self.dummy),
        }
    }
}

#[cfg(test)]
thread_local! {
    static PASSWORD_VERIFY_CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
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
        if !httpd_rs_verified::shared_map_insert_admit(
            cache.failures.len() as u64,
            MAX_AUTH_CACHE_ENTRIES as u64,
            0,
            0,
            0,
        ) {
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
    let _blocking_io = crate::resource::begin_blocking_io().ok()?;
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
    let after = crate::fault::hit("auth.post_read.metadata")
        .and_then(|()| file.metadata())
        .ok()?;
    if crate::fault::hit("auth.post_read.identity").is_err()
        || auth_key(path, &after) != key
        || !path_names_key(path, &key)
    {
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
        while !httpd_rs_verified::shared_map_insert_admit(
            cache.entries.len() as u64,
            MAX_AUTH_CACHE_ENTRIES as u64,
            cache.bytes as u64,
            weight as u64,
            MAX_AUTH_CACHE_BYTES as u64,
        ) {
            let Some(victim) = cache.entries.keys().next().cloned() else {
                break;
            };
            if let Some((_, old_weight)) = cache.entries.remove(&victim) {
                cache.bytes = cache.bytes.saturating_sub(old_weight);
            }
        }
        if httpd_rs_verified::shared_map_insert_admit(
            cache.entries.len() as u64,
            MAX_AUTH_CACHE_ENTRIES as u64,
            cache.bytes as u64,
            weight as u64,
            MAX_AUTH_CACHE_BYTES as u64,
        ) {
            cache.bytes = cache.bytes.saturating_add(weight);
            cache.entries.insert(key, (Arc::clone(&data), weight));
        }
    }
    Some(data)
}

fn path_names_key(path: &Path, key: &AuthFileKey) -> bool {
    let Ok(file) = crate::files::open_admin_path(path, libc::O_RDONLY | libc::O_NONBLOCK, 0) else {
        return false;
    };
    let Ok(meta) = crate::fault::hit("auth.path.metadata").and_then(|()| file.metadata()) else {
        return false;
    };
    httpd_rs_verified::auth_cache_snapshot_admit(meta.is_file(), auth_key(path, &meta) == *key)
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
    // auth-file := *( empty-line | comment-line | entry-line )
    // comment-line := "#" *UTF8
    // entry-line := name ":" value
    //
    // `name` is non-empty strict UTF-8 with no colon/control byte and no
    // leading or trailing ASCII whitespace. `value` excludes control bytes
    // other than HTAB. Every non-comment line must match `entry-line`.
    let mut users: HashMap<String, Option<String>> = HashMap::new();
    let mut groups_by_user: HashMap<String, Vec<String>> = HashMap::new();
    let mut weight = 0usize;
    for line in data.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return None;
        };
        if name.is_empty()
            || name.trim_matches(|character: char| character.is_ascii_whitespace()) != name
            || name
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b':')
        {
            return None;
        }
        let name = name.to_string();
        let value = value.trim_end_matches('\r').to_string();
        if value
            .bytes()
            .any(|byte| byte.is_ascii_control() && !matches!(byte, b'\t'))
        {
            return None;
        }
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
        let group = name
            .trim_matches(|character: char| character.is_ascii_whitespace())
            .to_string();
        for member in value.split_ascii_whitespace() {
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
    let passwords = PasswordDatabase::parse(&users);
    Some((
        ParsedAuthFile {
            passwords,
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

/// Validate the password-record semantics for a main-configuration
/// `AuthUserFile`. Group files share the bounded file reader but deliberately
/// do not use this password-specific grammar.
pub fn validate_auth_user_file(path: &Path, mutable: bool, service_uid: u32) -> Result<(), String> {
    let data = read_small_uncached(path, mutable, service_uid).ok_or_else(|| {
        format!(
            "authentication file {} must be bounded strict UTF-8 and, unless MutableAuthFiles is enabled, operator-controlled",
            path.display()
        )
    })?;
    data.passwords.as_ref().map(|_| ()).ok_or_else(|| {
        format!(
            "AuthUserFile {} must contain unique, valid password records with one uniform hash scheme, cost, and salt shape",
            path.display()
        )
    })
}

fn authenticate_password(
    path: &Path,
    user: &str,
    password: &[u8],
    mutable: bool,
) -> Option<(bool, bool)> {
    let data = read_small(path, mutable)?;
    let (known_user, verifier) = data.passwords.as_ref()?.select(user);
    Some((known_user, verifier.verify(password)))
}

fn groups_for(path: &Path, user: &str, mutable: bool) -> Option<Vec<String>> {
    let data = read_small(path, mutable)?;
    Some(data.groups_by_user.get(user).cloned().unwrap_or_default())
}

#[cfg(test)]
fn verify_password(password: &[u8], stored: &str) -> bool {
    PasswordVerifier::parse(stored).is_some_and(|(_, verifier)| verifier.verify(password))
}

#[cfg(test)]
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
            "httpd-rs-auth-{label}-{}-{}",
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
            "# comment\nalice:$apr1$gqijKP2Z$nBjZURLWP3/zSfPLTfhVM0\r\n",
        )
        .unwrap();
        std::fs::write(&groups, "admins: alice bob\nother: bob\n").unwrap();
        let mut scope = Scope::default();
        scope.authorization.auth_type = Some("BASIC".into());
        scope.authorization.auth_user_file = Some(users.clone());
        scope.authorization.auth_group_file = Some(groups.clone());

        let identity = authenticate(&scope, &request(Some(basic(b"alice:secret"))), true).unwrap();
        assert_eq!(identity.user, "alice");
        assert_eq!(
            identity.groups.as_deref(),
            Some(["admins".to_string()].as_slice())
        );
        assert!(authenticate(&scope, &request(Some(basic(b"alice:wrong"))), true).is_none());
        assert!(authenticate(&scope, &request(Some(basic(b"nobody:secret"))), true).is_none());

        std::fs::write(&groups, "malformed\nadmins: alice\n").unwrap();
        let identity = authenticate(&scope, &request(Some(basic(b"alice:secret"))), true).unwrap();
        assert!(identity.groups.is_none());

        std::fs::write(&groups, b"admins: alice\xff\n").unwrap();
        let identity = authenticate(&scope, &request(Some(basic(b"alice:secret"))), true).unwrap();
        assert!(identity.groups.is_none());
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
    fn missing_and_present_users_each_execute_one_uniform_verifier() {
        let users = temp_path("uniform-dummy-users");
        std::fs::write(&users, "alice:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=\n").unwrap();
        let mut scope = Scope::default();
        scope.authorization.auth_type = Some("Basic".into());
        scope.authorization.auth_user_file = Some(users.clone());

        PASSWORD_VERIFY_CALLS.with(|calls| calls.set(0));
        assert!(authenticate(&scope, &request(Some(basic(b"nobody:wrong"))), true).is_none());
        assert_eq!(PASSWORD_VERIFY_CALLS.with(std::cell::Cell::get), 1);
        assert!(authenticate(&scope, &request(Some(basic(b"alice:wrong"))), true).is_none());
        assert_eq!(PASSWORD_VERIFY_CALLS.with(std::cell::Cell::get), 2);
        assert!(authenticate(&scope, &request(Some(basic(b"alice:test"))), true).is_some());
        assert_eq!(PASSWORD_VERIFY_CALLS.with(std::cell::Cell::get), 3);

        std::fs::remove_file(users).unwrap();
    }

    #[test]
    fn password_database_requires_valid_unique_uniform_records() {
        let uniform = parse_auth_file(
            "alice:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=\nbob:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n",
        )
        .unwrap()
        .0;
        assert!(uniform.passwords.is_some());

        for invalid in [
            "alice:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=\nbob:{SSHA}cHh4eHh4eHh4eHh4eHh4eHh4eHg=\n",
            "alice:{SHA}%%%\n",
            "alice:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=\nalice:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=\n",
            "alice:$2y$05$lFdvgVrS6ROEENEOjKS5h.y4SA05OvKSOFRPC1BcjARNhNt.DQ8jC\nbob:$2y$06$lFdvgVrS6ROEENEOjKS5h.y4SA05OvKSOFRPC1BcjARNhNt.DQ8jC\n",
            // Alphabet-valid but non-canonical bcrypt base64 must be rejected
            // by the verification backend's parser during configuration.
            "alice:$2y$05$lFdvgVrS6ROEENEOjKS5h.y4SA05OvKSOFRPC1BcjARNhNt.DQ8jD\n",
            "",
        ] {
            assert!(parse_auth_file(invalid).unwrap().0.passwords.is_none());
        }

        // Group-file syntax remains independently valid even though it is not
        // a password database.
        let group = parse_auth_file("admins: alice bob\n").unwrap().0;
        assert!(group.passwords.is_none());
        assert_eq!(group.groups_by_user["alice"], ["admins"]);
    }

    #[test]
    fn group_provider_failure_does_not_erase_valid_user_authentication() {
        let users = temp_path("valid-user-users");
        std::fs::write(&users, "alice:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=\n").unwrap();
        let mut scope = Scope::default();
        scope.authorization.auth_type = Some("Basic".into());
        scope.authorization.auth_user_file = Some(users.clone());
        scope.authorization.auth_group_file = Some(temp_path("missing-group-file"));

        let identity = authenticate(&scope, &request(Some(basic(b"alice:test"))), true).unwrap();
        assert_eq!(identity.user, "alice");
        assert!(identity.groups.is_none());
        std::fs::remove_file(users).unwrap();
    }

    #[test]
    fn password_file_and_hash_error_edges_fail_closed() {
        let directory = temp_path("directory");
        std::fs::create_dir(&directory).unwrap();
        assert!(read_small(&directory, true).is_none());
        // A repeated failure is served from the short negative cache rather
        // than reopening an attacker-selected path on every request.
        assert!(read_small(&directory, true).is_none());
        assert!(groups_for(&directory.join("missing"), "alice", true).is_none());
        std::fs::remove_dir(directory).unwrap();
        assert!(read_bounded(std::io::Cursor::new(vec![
            b'x';
            MAX_PASSWORD_FILE as usize + 1
        ]))
        .is_none());

        assert!(!verify_password(b"x", "{SHA}%%%"));
        assert!(!verify_password(b"x", "{SHA}eA=="));
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
        assert!(!verify_password(
            b"secret",
            "{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=\u{2003}"
        ));

        let missing = temp_path("identity-missing");
        let missing_key = AuthFileKey {
            path: missing.clone(),
            dev: 0,
            ino: 0,
            size: 0,
            mtime: 0,
            mtime_nsec: 0,
            ctime: 0,
            ctime_nsec: 0,
        };
        assert!(!path_names_key(&missing, &missing_key));
    }

    #[test]
    fn basic_scheme_boundary_is_ascii_and_byte_exact() {
        assert_eq!(
            basic_token(b"Basic dXNlcjpwYXNz"),
            Some(&b"dXNlcjpwYXNz"[..])
        );
        assert_eq!(
            basic_token(b"\tBASIC\t\tdXNlcjpwYXNz \t"),
            Some(&b"dXNlcjpwYXNz"[..])
        );
        for malformed in [
            b"Basic\xe2\x80\x83dXNlcjpwYXNz".as_slice(),
            b"\xe2\x80\x83Basic dXNlcjpwYXNz".as_slice(),
            b"Basic dXNl dXNlcg==".as_slice(),
            b"Basic".as_slice(),
        ] {
            assert!(basic_token(malformed).is_none());
        }
    }

    #[test]
    fn authenticated_identity_is_request_owned_and_monotonic() {
        let first = request(None);
        let internal = first.clone();
        let unrelated = request(None);

        assert!(first.record_authenticated_identity("alice"));
        assert!(internal.record_authenticated_identity("alice"));
        assert!(!internal.record_authenticated_identity("mallory"));
        assert_eq!(first.authenticated_identity().as_deref(), Some("alice"));
        assert!(unrelated.authenticated_identity().is_none());
        // Taking an access-log snapshot must not shorten the identity's
        // lifetime before a deferred handler or internal transition runs.
        assert_eq!(internal.authenticated_identity().as_deref(), Some("alice"));
        assert_eq!(first.authenticated_identity().as_deref(), Some("alice"));

        assert!(unrelated.record_authenticated_identity("bob"));
        unrelated.reset_authenticated_identity();
        assert!(unrelated.authenticated_identity().is_none());
    }

    #[test]
    fn cache_identity_includes_the_complete_metadata_snapshot() {
        let path = temp_path("complete-cache-key");
        std::fs::write(&path, "alice:old\n").unwrap();
        let original = auth_key(&path, &std::fs::metadata(&path).unwrap());
        assert!(path_names_key(&path, &original));

        // Same path and inode, different contents/size: the old parsed
        // snapshot must no longer be reusable.
        std::fs::write(&path, "alice:replacement-value\n").unwrap();
        assert!(!path_names_key(&path, &original));
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn injected_post_open_auth_file_races_fail_closed() {
        let _fault_guard = crate::fault::test_guard();
        let path = temp_path("post-open-faults");
        std::fs::write(&path, "alice:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=\n").unwrap();

        crate::fault::configure(
            "auth.post_read.metadata",
            0,
            std::io::ErrorKind::PermissionDenied,
        );
        assert!(read_small_uncached(&path, true, 0).is_none());

        crate::fault::configure(
            "auth.post_read.identity",
            0,
            std::io::ErrorKind::InvalidData,
        );
        assert!(read_small_uncached(&path, true, 0).is_none());

        let metadata = std::fs::metadata(&path).unwrap();
        let key = auth_key(&path, &metadata);
        crate::fault::configure(
            "auth.path.metadata",
            0,
            std::io::ErrorKind::PermissionDenied,
        );
        assert!(!path_names_key(&path, &key));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn password_hashing_fails_closed_when_expensive_work_is_saturated() {
        let budget = Arc::new(crate::resource::ResourceBudget::default());
        let context = budget.context("127.0.0.1".parse().unwrap());
        crate::resource::with_resource_context(context.clone(), || {
            let _leases = (0..crate::resource::MAX_EXPENSIVE_OPS_PER_CLIENT)
                .map(|_| crate::resource::try_expensive_in(&context).unwrap())
                .collect::<Vec<_>>();
            assert!(!verify_password(
                b"secret",
                "$apr1$gqijKP2Z$nBjZURLWP3/zSfPLTfhVM0"
            ));
            assert!(!verify_password(b"secret", "$1$salt$hash"));
            assert!(!verify_password(
                b"secret",
                "$2y$05$lFdvgVrS6ROEENEOjKS5h.y4SA05OvKSOFRPC1BcjARNhNt.DQ8jC"
            ));
        });
    }

    #[test]
    fn auth_group_index_has_a_resident_memory_ceiling() {
        let oversized_name = format!("{}:x", "n".repeat(MAX_AUTH_CACHE_BYTES + 1));
        assert!(parse_auth_file(&oversized_name).is_none());

        // The source is comfortably below the 4 MiB file ceiling, but every
        // indexed membership has independent HashMap/Vec ownership.
        let members = "x ".repeat(300_000);
        assert!(parse_auth_file(&format!("group:{members}")).is_none());
    }

    #[test]
    fn auth_file_caches_evict_at_their_entry_ceiling() {
        let parsed = Arc::new(ParsedAuthFile {
            passwords: None,
            groups_by_user: HashMap::new(),
        });
        {
            let mut cache = auth_file_cache().lock().unwrap();
            cache.entries.clear();
            cache.failures.clear();
            cache.bytes = 0;
            for index in 0..MAX_AUTH_CACHE_ENTRIES {
                cache.entries.insert(
                    AuthFileKey {
                        path: temp_path(&format!("cached-{index}")),
                        dev: 0,
                        ino: index as u64,
                        size: 0,
                        mtime: 0,
                        mtime_nsec: 0,
                        ctime: 0,
                        ctime_nsec: 0,
                    },
                    (Arc::clone(&parsed), 1),
                );
                cache.bytes += 1;
                cache.failures.insert(
                    (temp_path(&format!("failed-{index}")), true, 0),
                    Instant::now(),
                );
            }
        }

        let valid = temp_path("cache-eviction-valid");
        std::fs::write(&valid, "alice:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=\n").unwrap();
        assert!(read_small(&valid, true).is_some());
        let missing = temp_path("cache-eviction-missing");
        assert!(read_small(&missing, true).is_none());

        let mut cache = auth_file_cache().lock().unwrap();
        assert!(cache.entries.len() <= MAX_AUTH_CACHE_ENTRIES);
        assert!(cache.failures.len() <= MAX_AUTH_CACHE_ENTRIES);
        cache.entries.clear();
        cache.failures.clear();
        cache.bytes = 0;
        drop(cache);
        std::fs::remove_file(valid).unwrap();

        // Exercise the defensive recovery for an inconsistent accounting
        // snapshot: the byte counter says eviction is required, but no entry
        // exists to evict. The valid file must still be parsed successfully.
        let accounted = temp_path("cache-accounting-recovery");
        std::fs::write(&accounted, "alice:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=\n").unwrap();
        {
            let mut cache = auth_file_cache().lock().unwrap();
            cache.entries.clear();
            cache.failures.clear();
            cache.bytes = MAX_AUTH_CACHE_BYTES + 1;
        }
        assert!(read_small(&accounted, true).is_some());
        {
            let mut cache = auth_file_cache().lock().unwrap();
            cache.entries.clear();
            cache.failures.clear();
            cache.bytes = 0;
        }
        std::fs::remove_file(accounted).unwrap();
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

    #[test]
    #[ignore = "manual authentication-path benchmark"]
    fn benchmark_basic_authentication_path() {
        let users = temp_path("benchmark-users");
        std::fs::write(&users, "alice:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=\n").unwrap();
        let mut scope = Scope::default();
        scope.authorization.auth_type = Some("Basic".into());
        scope.authorization.auth_user_file = Some(users.clone());
        let header = basic(b"alice:test");
        let iterations = 500_000u32;
        let started = Instant::now();
        for _ in 0..iterations {
            assert!(authenticate(&scope, &request(Some(header.clone())), true).is_some());
        }
        let elapsed = started.elapsed();
        eprintln!(
            "basic_auth_benchmark iterations={iterations} elapsed_s={:.6} ns_per_op={:.1}",
            elapsed.as_secs_f64(),
            elapsed.as_nanos() as f64 / f64::from(iterations)
        );
        std::fs::remove_file(users).unwrap();
    }
}
