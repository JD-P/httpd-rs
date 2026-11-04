//! Shared HTTP cache (`mod_cache` / `mod_cache_disk` subset).
//!
//! The cache stores complete, already-finalized responses.  It is deliberately
//! conservative: only GET/HEAD responses that are independently cacheable are
//! stored, authenticated resources are never served from the public cache, and
//! responses carrying `Set-Cookie`, `Vary: *`, `no-store`, `private` or
//! `no-cache` are rejected.  Cache entries may be persisted as body files
//! under `CacheRoot` when a `disk` cache is enabled.

use crate::access::AccessGrant;
use crate::config::{CacheConfig, Config, Scope, VHost};
use crate::http::{Body, Request, Response};
use crate::util::{parse_http_date, unix_now};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha1::{Digest, Sha1};
use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::SystemTime;

const MAX_ENTRIES: usize = 4096;
/// The on-disk cache has its own hard entry cap; the in-memory key cap alone
/// would still let unique URLs fill the cache filesystem (F44).
const MAX_DISK_ENTRIES: usize = 4096;
/// Bound the number of stored variants for one key before evicting the oldest
/// representation.
const MAX_VARIANTS_PER_KEY: usize = 32;
/// Large representations already have a bounded disk backing file.  Keeping
/// another full copy resident provides little benefit and magnifies RSS.
const MAX_MEMORY_BODY: usize = 64 * 1024;
const MAX_DISK_META_BYTES: u64 = 1024 * 1024;
/// Administrative cache walks must remain bounded even if the configured
/// directory is polluted by another local service or a previous broken
/// release. A normal entry uses two files below a shallow hash hierarchy.
const MAX_DISK_SCAN_RECORDS: usize = MAX_DISK_ENTRIES * 8;
const MAX_DISK_SCAN_DEPTH: usize = 32;
/// Full-strength policy/request digest.  The previous 64-bit fingerprint was
/// collision-prone for an attacker who can vary request headers and force
/// variants of one cache key.  A SHA-256 digest is still compared exactly.
type PolicyFingerprint = [u8; 32];
/// Configuration generation for persisted cache entries.  A reload bumps this
/// value; entries from an older generation are never served, even if their
/// body/meta files survived the reload cleanup.
static CACHE_EPOCH: AtomicU64 = AtomicU64::new(1);

fn current_epoch() -> u64 {
    CACHE_EPOCH.load(Ordering::SeqCst)
}

fn bump_epoch() -> u64 {
    CACHE_EPOCH.fetch_add(1, Ordering::SeqCst) + 1
}
// Authorization is not hop-by-hop, but it is identity-bearing metadata and
// must never be persisted in the shared response cache. Transport-owned and
// Connection-nominated fields are classified by ResponseHeaderSanitizer.
const CACHE_PRIVATE_HEADERS: &[&str] = &["authorization"];

#[derive(Clone)]
struct Entry {
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
    body_len: u64,
    stored: i64,
    expires: i64,
    policy: PolicyFingerprint,
    epoch: u64,
    vary: Vec<(String, Vec<u8>)>,
    // Keeps the process-wide resident-memory reservation alive for exactly as
    // long as this representation remains reachable from the memory cache.
    _resident: Option<Arc<crate::resource::CacheResidentLease>>,
}

#[derive(Default)]
struct MemoryCache {
    entries: HashMap<String, Vec<Arc<Entry>>>,
    bytes: u64,
    eviction: VecDeque<(usize, u64, Weak<Entry>)>,
    locations: HashMap<usize, (u64, String)>,
    next_generation: u64,
}

fn memory_entry_id(entry: &Arc<Entry>) -> usize {
    Arc::as_ptr(entry) as usize
}

fn untrack_memory_entry(cache: &mut MemoryCache, entry: &Arc<Entry>) {
    cache.locations.remove(&memory_entry_id(entry));
}

fn track_memory_entry(cache: &mut MemoryCache, key: &str, entry: &Arc<Entry>) {
    let id = memory_entry_id(entry);
    cache.next_generation = cache.next_generation.wrapping_add(1).max(1);
    let generation = cache.next_generation;
    cache.locations.insert(id, (generation, key.to_string()));
    cache
        .eviction
        .push_back((id, generation, Arc::downgrade(entry)));
    // Hot replacement of one key can leave stale weak records. Compact them
    // occasionally; this work is amortized and bounded independently of key
    // length because queue records do not clone cache keys.
    if cache.eviction.len() > MAX_ENTRIES * 8 {
        let locations = &cache.locations;
        cache.eviction.retain(|(candidate, generation, _)| {
            locations
                .get(candidate)
                .is_some_and(|(current, _)| current == generation)
        });
    }
}

fn entries() -> &'static Mutex<MemoryCache> {
    static CACHE: OnceLock<Mutex<MemoryCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(MemoryCache::default()))
}

fn memory_entry_size(key: &str, entry: &Entry) -> u64 {
    let mut size = key.len() as u64;
    size = size.saturating_add(entry.body.len() as u64);
    for (name, value) in &entry.headers {
        size = size
            .saturating_add(name.len() as u64)
            .saturating_add(value.len() as u64);
    }
    for (name, value) in &entry.vary {
        size = size
            .saturating_add(name.len() as u64)
            .saturating_add(value.len() as u64);
    }
    // Account conservatively for the Entry, Arc, Vec allocations and map
    // bookkeeping without relying on allocator-specific usable sizes.
    size.saturating_add(256)
}

fn evict_oldest_memory(cache: &mut MemoryCache) -> bool {
    while let Some((id, queued_generation, weak)) = cache.eviction.pop_front() {
        let Some((current_generation, key)) = cache.locations.get(&id) else {
            continue;
        };
        if *current_generation != queued_generation {
            continue;
        }
        let key = key.clone();
        cache.locations.remove(&id);
        let Some(entry) = weak.upgrade() else {
            continue;
        };
        let Some(mut list) = cache.entries.remove(&key) else {
            continue;
        };
        let Some(index) = list
            .iter()
            .position(|candidate| Arc::ptr_eq(candidate, &entry))
        else {
            if !list.is_empty() {
                cache.entries.insert(key, list);
            }
            continue;
        };
        let removed = list.remove(index);
        cache.bytes = cache
            .bytes
            .saturating_sub(memory_entry_size(&key, &removed));
        if !list.is_empty() {
            cache.entries.insert(key, list);
        }
        return true;
    }
    // Production insertions never leave empty buckets. Keep malformed test,
    // upgrade, or interrupted state self-healing without putting the normal
    // eviction path back on an O(n) scan.
    if let Some(key) = cache
        .entries
        .iter()
        .find_map(|(key, entries)| entries.is_empty().then(|| key.clone()))
    {
        cache.entries.remove(&key);
        return true;
    }
    false
}

fn insert_memory(cfg: &Config, key: &str, entry: Arc<Entry>) {
    let mut cache = entries().lock().unwrap_or_else(|e| e.into_inner());
    insert_memory_into(cfg, &mut cache, key, entry);
}

fn insert_memory_into(cfg: &Config, cache: &mut MemoryCache, key: &str, entry: Arc<Entry>) {
    if cfg.cache.max_memory_size == 0 || entry.body_len > MAX_MEMORY_BODY as u64 {
        return;
    }
    // Production callers must reserve the shared physical-memory parent
    // before publishing an entry. Tests may construct synthetic entries to
    // exercise eviction independently of the process ledger.
    #[cfg(not(test))]
    if entry._resident.is_none() {
        return;
    }
    let incoming = memory_entry_size(key, &entry);
    if incoming > cfg.cache.max_memory_size {
        return;
    }
    let mut list = cache.entries.remove(key).unwrap_or_default();
    let mut retained = Vec::with_capacity(list.len().saturating_add(1));
    for old in list.drain(..) {
        // This key is temporarily outside `entries` while its variants are
        // filtered. Retire every old queue identity now and assign a fresh
        // generation to retained variants after global eviction completes.
        untrack_memory_entry(cache, &old);
        if old.vary == entry.vary {
            cache.bytes = cache.bytes.saturating_sub(memory_entry_size(key, &old));
        } else {
            retained.push(old);
        }
    }
    while retained.len() >= MAX_VARIANTS_PER_KEY {
        let old = retained.remove(0);
        cache.bytes = cache.bytes.saturating_sub(memory_entry_size(key, &old));
    }
    while (!vapache_verified::cache_memory_admit(cache.bytes, incoming, cfg.cache.max_memory_size)
        || cache.entries.len() >= MAX_ENTRIES)
        && evict_oldest_memory(cache)
    {}
    if vapache_verified::cache_memory_admit(cache.bytes, incoming, cfg.cache.max_memory_size)
        && cache.entries.len() < MAX_ENTRIES
    {
        cache.bytes = cache.bytes.saturating_add(incoming);
        retained.push(entry);
    }
    if !retained.is_empty() {
        for retained_entry in &retained {
            track_memory_entry(cache, key, retained_entry);
        }
        cache.entries.insert(key.to_string(), retained);
    }
}

#[derive(Default)]
struct DiskUsageState {
    total: u64,
    /// stem -> (accounted bytes, modification time, insertion generation)
    stems: HashMap<PathBuf, (u64, SystemTime, u64)>,
    file_counts: HashMap<PathBuf, u64>,
    /// Insertion/scan order with timestamps used to discard stale records.
    /// This makes eviction O(1) amortized instead of sorting the entire cache
    /// on every unique request key.
    eviction: VecDeque<(PathBuf, u64)>,
    next_generation: u64,
    /// Exact key decoded once from the metadata file. `None` denotes corrupt
    /// or legacy metadata and is removed conservatively on invalidation.
    keys: HashMap<PathBuf, Option<Vec<u8>>>,
    /// Shared disk/inode parent permits for every persisted representation.
    leases: HashMap<PathBuf, crate::resource::DiskLease>,
}

fn disk_usage() -> &'static Mutex<HashMap<PathBuf, DiskUsageState>> {
    static USAGE: OnceLock<Mutex<HashMap<PathBuf, DiskUsageState>>> = OnceLock::new();
    USAGE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn ensure_disk_usage(
    root: &Path,
    budget: &std::sync::Arc<crate::resource::ResourceBudget>,
) -> bool {
    let mut roots = disk_usage()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if crate::fault::hit("cache.scan.concurrent").is_err() {
        roots.insert(root.to_path_buf(), DiskUsageState::default());
    }
    if roots.contains_key(root) {
        return true;
    }
    drop(roots);
    // Cold-start scans are bounded, but letting every first request perform
    // the same walk in parallel would multiply that bound by the worker cap.
    // Serialize only index construction; steady-state accounting and file I/O
    // do not use this lock.
    static SCAN: OnceLock<Mutex<()>> = OnceLock::new();
    let Ok(_scan) = SCAN.get_or_init(|| Mutex::new(())).try_lock() else {
        // A cold scan is already in flight. Bypass disk cache rather than
        // parking another request worker behind filesystem latency.
        return false;
    };
    if disk_usage()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .contains_key(root)
    {
        return true;
    }
    let Some(mut scanned) = scan_disk_usage(root) else {
        return false;
    };
    for (stem, (bytes, _, _)) in &scanned.stems {
        let files = scanned.file_counts.get(stem).copied().unwrap_or(1);
        let Ok(lease) = budget.try_disk_at(root, *bytes, files) else {
            return false;
        };
        scanned.leases.insert(stem.clone(), lease);
    }
    disk_usage()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(root.to_path_buf(), scanned);
    true
}

/// Serialize writers and readers of one cache stem without putting unrelated
/// cache keys behind the accounting lock. A fixed set of stripes bounds the
/// lock table itself, while making the body-then-metadata rename sequence
/// atomic from the point of view of `disk_load`.
fn disk_io_locks() -> &'static [Mutex<()>] {
    const STRIPES: usize = 64;
    static LOCKS: OnceLock<Vec<Mutex<()>>> = OnceLock::new();
    LOCKS
        .get_or_init(|| (0..STRIPES).map(|_| Mutex::new(())).collect())
        .as_slice()
}

fn disk_io_lock(stem: &Path) -> &Mutex<()> {
    let mut hasher = DefaultHasher::new();
    stem.hash(&mut hasher);
    &disk_io_locks()[hasher.finish() as usize % disk_io_locks().len()]
}

fn disk_stem(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_string_lossy();
    let base = name
        .strip_suffix(".body.tmp")
        .or_else(|| name.strip_suffix(".meta.tmp"))
        .or_else(|| name.strip_suffix(".body"))
        .or_else(|| name.strip_suffix(".meta"))?;
    Some(path.with_file_name(base))
}

fn disk_stem_files(stem: &Path) -> [PathBuf; 4] {
    [
        stem.with_extension("body"),
        stem.with_extension("meta"),
        stem.with_extension("body.tmp"),
        stem.with_extension("meta.tmp"),
    ]
}

fn record_disk_file(state: &mut DiskUsageState, stem: PathBuf, len: u64, modified: SystemTime) {
    let slot = state.stems.entry(stem.clone()).or_insert((0, modified, 0));
    slot.0 = slot.0.saturating_add(len);
    if modified < slot.1 {
        slot.1 = modified;
    }
    *state.file_counts.entry(stem).or_insert(0) += 1;
}

fn remove_disk_stem_files(stem: &Path) {
    for path in disk_stem_files(stem) {
        let _ = fs::remove_file(path);
    }
}

fn open_cache_regular(path: &Path, limit: u64) -> Option<(File, fs::Metadata)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > limit {
        return None;
    }
    Some((file, meta))
}

fn read_disk_metadata(path: &Path) -> Option<Vec<u8>> {
    let (mut file, meta) = open_cache_regular(path, MAX_DISK_META_BYTES)?;
    let mut data = vec![0u8; meta.len() as usize];
    file.read_exact(&mut data).ok()?;
    Some(data)
}

fn read_disk_metadata_accounted(
    path: &Path,
    resident: &mut crate::resource::ResidentLease,
) -> Option<Vec<u8>> {
    let (mut file, meta) = open_cache_regular(path, MAX_DISK_META_BYTES)?;
    // Decoding retains the raw record while allocating decoded names and
    // values. Charging twice its encoded size conservatively covers both.
    resident.reserve(meta.len().saturating_mul(2)).ok()?;
    let mut data = vec![0u8; meta.len() as usize];
    file.read_exact(&mut data).ok()?;
    Some(data)
}

fn write_cache_temp(path: &Path, data: &[u8]) -> io::Result<()> {
    // A previous crash may leave the predictable temporary name behind.
    // Unlink it, then use create_new so a racing symlink/FIFO is never opened.
    let _ = fs::remove_file(path);
    crate::fault::hit("cache.temp.open")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    crate::fault::hit("cache.temp.write")?;
    file.write_all(data)
}

fn scan_disk_usage(root: &Path) -> Option<DiskUsageState> {
    if crate::fault::hit("cache.scan").is_err() {
        return None;
    }
    let mut state = DiskUsageState::default();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut scanned = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_DISK_SCAN_DEPTH {
            return None;
        }
        let Ok(read) = fs::read_dir(dir) else {
            continue;
        };
        for entry in read.flatten() {
            scanned = scanned.checked_add(1)?;
            if crate::fault::hit("cache.scan.limit").is_err() || scanned > MAX_DISK_SCAN_RECORDS {
                return None;
            }
            let path = entry.path();
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => stack.push((path, depth + 1)),
                Ok(ft) if ft.is_file() => {
                    let Some(stem) = disk_stem(&path) else {
                        continue;
                    };
                    let Ok(meta) = entry.metadata() else {
                        // `read_dir` supplied a regular-file entry but it was
                        // concurrently removed or replaced before metadata.
                        continue; // coverage:ignore-line - filesystem race
                    };
                    let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                    record_disk_file(&mut state, stem.clone(), meta.len(), modified);
                    if path
                        .extension()
                        .is_some_and(|extension| extension == "meta")
                    {
                        let key = read_disk_metadata(&path).and_then(|data| decode_meta_key(&data));
                        state.keys.insert(stem, key);
                    }
                }
                _ => {}
            }
        }
    }
    state.total = state.stems.values().map(|(size, _, _)| *size).sum();
    let mut ordered: Vec<_> = state
        .stems
        .iter()
        .map(|(stem, (_, modified, _))| (stem.clone(), *modified))
        .collect();
    ordered.sort_by_key(|(_, modified)| *modified);
    for (stem, _) in ordered {
        state.next_generation = state.next_generation.saturating_add(1);
        if let Some(entry) = state.stems.get_mut(&stem) {
            entry.2 = state.next_generation;
        }
        state.eviction.push_back((stem, state.next_generation));
    }
    Some(state)
}

fn remove_disk_stem(cfg: &Config, stem: &Path) {
    remove_disk_stem_files(stem);
    let Some(root) = &cfg.cache.root else {
        return;
    };
    let mut roots = disk_usage().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(usage) = roots.get_mut(root) {
        if let Some((size, _, _)) = usage.stems.remove(stem) {
            usage.total = usage.total.saturating_sub(size);
        }
        usage.file_counts.remove(stem);
        usage.leases.remove(stem);
        usage.keys.remove(stem);
    }
}

fn header<'a>(headers: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}

#[cfg(test)]
fn response_header<'a>(resp: &'a Response, name: &str) -> Option<&'a [u8]> {
    resp.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}

#[cfg(test)]
fn response_header_str(resp: &Response, name: &str) -> Option<String> {
    response_header(resp, name).map(|v| String::from_utf8_lossy(v).into_owned())
}

fn prefix_matches(path: &str, prefix: &str) -> bool {
    if prefix.is_empty() || prefix == "/" {
        return true;
    }
    if path == prefix {
        return true;
    }
    if let Some(rest) = path.strip_prefix(prefix) {
        return prefix.ends_with('/') || rest.starts_with('/');
    }
    false
}

pub struct CacheContext {
    pub scope: Scope,
    pub grant: AccessGrant,
    /// Fully qualified cache key binding listener, vhost, URL, mapped target
    /// and policy.  Lookup and store must use this exact key.
    pub key: String,
    pub target: std::path::PathBuf,
    /// Effective cache URL.  For a directory request this is the selected
    /// `DirectoryIndex` URL, so lookup and store authorize the same resource.
    pub path: String,
}

/// Return the cache type selected for this request, if caching is enabled and
/// access control permits serving a cached representation.
/// Compatibility entry point for callers that do not already hold a
/// `RequestPlan`.  Production dispatch/cache integration uses
/// `request_scope_with_plan` so the cache and dispatcher share one identity.
#[allow(clippy::too_many_arguments)]
pub fn request_scope(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    peer: IpAddr,
    path: &str,
    local_port: u16,
    https: bool,
    server_name: &str,
    host: &str,
    local_ip: &str,
) -> Option<CacheContext> {
    let allow_encoded = cfg.encoded_slashes == crate::config::EncodedSlashes::On;
    let plan =
        crate::request_plan::RequestPlan::from_request(cfg, vhost, req, allow_encoded).ok()?;
    request_scope_with_plan(
        cfg,
        vhost,
        req,
        peer,
        &plan,
        path,
        local_port,
        https,
        server_name,
        host,
        local_ip,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn request_scope_with_plan(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    peer: IpAddr,
    plan: &crate::request_plan::RequestPlan,
    path: &str,
    local_port: u16,
    https: bool,
    server_name: &str,
    host: &str,
    local_ip: &str,
) -> Option<CacheContext> {
    if req.method != "GET" && req.method != "HEAD" {
        return None;
    }
    if req.header("range").is_some() {
        return None;
    }
    // Without a cache root nothing can be served from or stored in the cache.
    // Skip the request-scope walk entirely; this is the common case for static
    // document roots that have not opted into mod_cache.
    cfg.cache.root.as_ref()?;
    // F55/I51: a lossy URL conversion can collapse distinct byte paths into
    // one cache identity.  The plan already rejected a non-UTF-8 canonical
    // path; keep the cache decision on that same identity.
    let url_path = plan.url_path().to_string();
    // Most requests are outside every CacheEnable prefix.  Check the
    // inherited scope before resolving directory rules and .htaccess, since
    // that walk is far more expensive than the prefix test itself.
    let base = vhost.map(|v| &v.scope).unwrap_or(&cfg.global);
    // Use the raw request path here so this test is identical to the later
    // `cache_enabled(&scope, path)` check.  In particular, URI normalization
    // drops a trailing slash and would make `/cache/` look outside a
    // `/cache/` CacheEnable prefix.
    let base_enabled = base
        .rewrite_policy
        .cache_enable
        .iter()
        .any(|(_, prefix)| prefix_matches(path, prefix));
    if !base_enabled {
        // CacheEnable is accepted only in server/vhost context. The typed
        // compiler rejects it in every rule-producing section, so there is no
        // conditional rule tree to search for a later enablement.
        return None;
    }
    // Authorizing a document-root path that an Alias never serves would let
    // a cached alias response bypass the alias target's Directory/access-file
    // policy.  The plan already used dispatch's mapping and access layers.
    let root = plan.root().to_path_buf();
    let rel = plan.rel().to_path_buf();
    let script_alias = plan.script_alias();
    let mapped_fs_path = plan.fs_path().to_path_buf();
    let mut scope = plan.effective_scope(cfg, vhost, req, peer);
    // Cache lookup must not bypass rewrite rules.  If any rule would produce
    // an outcome (including F/G/redirects or a target/file change), run the
    // normal dispatcher instead of serving a stale representation.
    let rewrite_ctx = crate::rewrite::Context::for_plan(
        plan,
        &cfg.server_root,
        &req.query,
        peer,
        local_port,
        https,
        server_name,
    );
    if !matches!(
        crate::rewrite::process(&scope, req, &rewrite_ctx),
        crate::rewrite::Outcome::None
    ) {
        return None;
    }
    // A CGI PATH_INFO URL dispatches to the script prefix, not to the
    // nonexistent full path.  Bind cache policy and the cache target to that
    // script so a later `<Files "script.cgi">` deny is part of the scope and
    // fingerprint rather than being bypassed by `/script.cgi/<info>`.
    let mut fs_path = mapped_fs_path;
    let mut cache_url_path = url_path.clone();
    let follow_symlinks = scope
        .effective_options()
        .contains(crate::config::Options::FOLLOW_SYMLINKS);
    let owner_match_only = !follow_symlinks
        && scope
            .effective_options()
            .contains(crate::config::Options::SYMLINKS_IF_OWNER_MATCH);
    let follow = follow_symlinks || owner_match_only;
    let script_target = if cfg.cgi_path_info_possible() {
        crate::cgi::find_script_checked_for_request(&root, &rel, follow, owner_match_only, req)
    } else {
        None
    };
    if let Some(st) = script_target {
        if !st.path_info.is_empty() {
            let script_base = st
                .rel_script
                .file_name()
                .map(|n| n.as_encoded_bytes())
                .unwrap_or(b"");
            if script_alias || crate::cgi::is_cgi(cfg, &scope, script_base, false) {
                let script_url = url_path
                    .strip_suffix(&st.path_info)
                    .unwrap_or(&url_path)
                    .to_string();
                fs_path = root.join(&st.rel_script);
                cache_url_path = script_url.clone();
                let target = crate::request_plan::CanonicalTarget::from_url_path(&script_url)?;
                let script_plan = crate::request_plan::RequestPlan::from_fs_target_for_request(
                    cfg,
                    vhost,
                    target,
                    root.clone(),
                    fs_path.clone(),
                    script_alias,
                    req,
                )
                .ok()?;
                let mut script_scope = script_plan.effective_scope(cfg, vhost, req, peer);
                // The PATH_INFO script target must keep the lexical script
                // URL's execution/list policy as well as its own canonical
                // policy.  The handler map comes from the script URL, not the
                // PATH_INFO spelling.
                let lexical = crate::request_plan::CanonicalTarget::from_url_path(&script_url)?;
                let lexical_plan =
                    crate::request_plan::RequestPlan::resolve_for_request(cfg, vhost, lexical, req)
                        .ok()?;
                let lexical_scope = lexical_plan.effective_scope(cfg, vhost, req, peer);
                script_scope.restrict_with(&lexical_scope);
                script_scope.restrict_policy_with(&scope);
                scope = script_scope;
            }
        }
    }
    // A directory URL is not the representation that dispatch will serve.
    // Resolve `DirectoryIndex` before the cache decision and rebind the cache
    // target, URL and policy to that index.  Without this, a cached directory
    // response outlives a live `<Files "index.html">` deny and a dynamic index
    // can be shared across queries under `CacheIgnoreQueryString` (F52).
    let current_rel = fs_path.strip_prefix(&root).unwrap_or(&rel);
    let mut directory_target = false;
    let mut index_selected = false;
    let mut opened_actual = None;
    match crate::files::resolve_target_checked(&root, current_rel, follow, owner_match_only) {
        crate::files::Target::File { file, .. } => {
            opened_actual = Some(crate::files::fd_path(&file)?);
        }
        crate::files::Target::Directory { file, .. } => {
            directory_target = true;
            if let Some(index) = crate::files::directory_index_target(
                cfg,
                &scope,
                req,
                &file,
                &url_path,
                &req.raw_path,
            ) {
                // The cache identity must preserve the exact index name bytes.
                // Reject a non-UTF-8 index name rather than sharing a lossy key.
                let index_name = std::str::from_utf8(&index.name).ok()?;
                let index_url = format!("{}/{}", url_path.trim_end_matches('/'), index_name);
                let index_fs = crate::files::fd_path(&index.file)?;
                let target = crate::request_plan::CanonicalTarget::from_url_path(&index_url)?;
                let index_plan = crate::request_plan::RequestPlan::from_fs_target_for_request(
                    cfg,
                    vhost,
                    target,
                    root.clone(),
                    index_fs.clone(),
                    script_alias,
                    req,
                )
                .ok()?;
                let mut index_scope = index_plan.effective_scope(cfg, vhost, req, peer);
                // The selected index has its own URL identity; conjoin that
                // lexical scope and the directory URL's non-handler policy.
                let lexical = crate::request_plan::CanonicalTarget::from_url_path(&index_url)?;
                let lexical_plan =
                    crate::request_plan::RequestPlan::resolve_for_request(cfg, vhost, lexical, req)
                        .ok()?;
                let lexical_scope = lexical_plan.effective_scope(cfg, vhost, req, peer);
                index_scope.restrict_with(&lexical_scope);
                index_scope.restrict_policy_with(&scope);
                scope = index_scope;
                fs_path = index_fs;
                cache_url_path = index_url;
                index_selected = true;
            } else {
                opened_actual = Some(crate::files::fd_path(&file)?);
            }
        }
        crate::files::Target::Forbidden => return None,
        crate::files::Target::NotFound => {}
    }
    // The opened/canonical target may differ from the URL-mapped path when a
    // document root, alias target or in-root component is a symlink.  The
    // cache must use the same two-identity meet as dispatch before deciding
    // that a representation is servable (F60/I61).
    if let Some(actual) = opened_actual {
        if actual != fs_path {
            let target = crate::request_plan::CanonicalTarget::from_url_path(&cache_url_path)?;
            let target_plan = crate::request_plan::RequestPlan::from_fs_target_for_request(
                cfg,
                vhost,
                target,
                root.clone(),
                actual.clone(),
                script_alias,
                req,
            )
            .ok()?;
            let mut target_scope = target_plan.effective_scope(cfg, vhost, req, peer);
            target_scope.restrict_with(&scope);
            scope = target_scope;
            fs_path = actual;
        }
    }
    if !vapache_verified::cache_directory_index_bind_admit(
        directory_target,
        index_selected,
        index_selected,
        index_selected,
    ) {
        // All three index arguments are the same local bit.  The verified
        // predicate therefore proves this fail-closed guard unreachable.
        return None; // coverage:ignore-line - verified identical bindings
    }
    if !cache_enabled(&scope, &cache_url_path) {
        return None;
    }
    // A local ErrorDocument is selected only after dispatch fails.  It is an
    // internal subrequest with its own handler/query policy, so a *missing*
    // URL must not be represented by that subrequest's response (F56/I52).
    // Existing targets may still use the cache; `store` additionally refuses
    // any response that actually came from a local error document.
    let local_error_document = scope
        .error_policy
        .documents
        .iter()
        .any(|(_, doc)| matches!(doc, crate::config::ErrorDoc::Local(_)));
    if local_error_document && !fs_path.exists() {
        if !vapache_verified::cache_local_error_document_admit(true, true) {
            return None;
        }
    }
    // `CacheIgnoreQueryString` is safe for static representations, but a
    // query-driven CGI/FastCGI/proxy/server-status/SetHandler response cannot
    // be shared across distinct queries.  Classify every non-default handler,
    // not just the proxy forms known to `match_proxy` (F52/F54/I49/I53).
    let mut proxy_route_match = None;
    if cfg.cache.ignore_query_string && !req.query.is_empty() {
        let name = fs_path
            .file_name()
            .map(|n| n.as_encoded_bytes())
            .unwrap_or(b"");
        let handler = crate::config::effective_handler(&scope, name)
            .map(str::trim)
            .filter(|h| {
                !h.is_empty()
                    && !h.eq_ignore_ascii_case("default-handler")
                    && !h.eq_ignore_ascii_case("none")
            })
            .is_some();
        let fastcgi =
            crate::fastcgi::match_proxy_for_request(&scope, &cache_url_path, &root, req).is_some();
        if req.policy_budget_failed() {
            return None;
        }
        let dynamic_without_proxy =
            script_alias || crate::cgi::is_cgi(cfg, &scope, name, false) || handler || fastcgi;
        let dynamic = if dynamic_without_proxy {
            true
        } else {
            let matched = crate::proxy::matches_route_req(&scope, &cache_url_path, req).ok()?;
            proxy_route_match = Some(matched);
            matched
        };
        if !vapache_verified::cache_dynamic_handler_admit(handler, dynamic) {
            // `dynamic` includes `handler` as a disjunct, so the verified
            // predicate proves that this fail-closed guard cannot reject.
            // coverage:ignore-start - verified implication
            return None;
            // coverage:ignore-stop
        }
        if !vapache_verified::cache_ignore_query_admit(
            cfg.cache.ignore_query_string,
            !req.query.is_empty(),
            dynamic,
        ) {
            return None;
        }
    }
    // Never bypass per-directory access control or a rewrite-set environment
    // requirement by serving a cached object without running dispatch.
    let fingerprint = cache_policy_fingerprint(&scope, req, peer, &fs_path);
    let resource =
        crate::access::ResourceKey::cache_policy(vhost, req, host, &cache_url_path, fingerprint);
    let grant = match crate::access::check_grant(
        &scope,
        req,
        peer,
        None,
        &cache_url_path,
        Some(&fs_path),
        resource,
    ) {
        Ok(grant) => grant,
        Err(_) => return None,
    };
    // AllowMethods and <Proxy> authorization are enforced by the normal
    // dispatcher; do not satisfy the request from cache first.
    if !scope.method_allowed(&req.method) {
        return None;
    }
    let proxy_route_match = match proxy_route_match {
        Some(matched) => matched,
        None => crate::proxy::matches_route_req(&scope, &cache_url_path, req).ok()?,
    };
    if proxy_route_match {
        return None;
    }
    let key = base_key(
        cfg,
        vhost,
        local_ip,
        local_port,
        https,
        host,
        &url_path,
        &cache_url_path,
        &req.query,
        &fs_path,
        fingerprint,
    );
    Some(CacheContext {
        scope,
        grant,
        key,
        target: fs_path,
        path: cache_url_path,
    })
}

fn cache_enabled(scope: &Scope, path: &str) -> bool {
    if scope
        .rewrite_policy
        .cache_disable
        .iter()
        .any(|prefix| prefix_matches(path, prefix))
    {
        return false;
    }
    scope
        .rewrite_policy
        .cache_enable
        .iter()
        .any(|(_, prefix)| prefix_matches(path, prefix))
}

#[allow(clippy::too_many_arguments)]
fn base_key(
    cfg: &Config,
    vhost: Option<&VHost>,
    local_ip: &str,
    local_port: u16,
    https: bool,
    host: &str,
    request_path: &str,
    representation_path: &str,
    query: &[u8],
    target: &std::path::Path,
    policy_fingerprint: PolicyFingerprint,
) -> String {
    // F55/I51: every byte-bearing component is hex encoded, so raw query,
    // path and filesystem-target bytes cannot collide with an empty value or
    // with each other.  `CacheIgnoreQueryString` is an explicit opt-in.
    let query = if cfg.cache.ignore_query_string {
        String::new()
    } else {
        key_component(query)
    };
    let vhost_id = vhost
        .and_then(|v| cfg.vhosts.iter().position(|x| std::ptr::eq(x, v)))
        .map(|i| i.to_string())
        .unwrap_or_else(|| "default".into());
    let policy_fingerprint = key_component(&policy_fingerprint);
    format!(
        "{}\n{host}\n{request_path}\n{representation_path}\n{query}\n{scheme}\n{local_ip}\n{local_port}\n{vhost_id}\n{target}\n{policy_fingerprint}",
        key_component(cfg.server_root.as_os_str().as_bytes()),
        host = key_component(host.as_bytes()),
        request_path = key_component(request_path.as_bytes()),
        representation_path = key_component(representation_path.as_bytes()),
        scheme = if https { "https" } else { "http" },
        target = key_component(target.as_os_str().as_bytes()),
    )
}

/// Lossless ASCII hex for cache-key material.  The verifier proves the
/// encoding length; the runtime never uses a lossy string conversion here.
fn key_component(value: &[u8]) -> String {
    String::from_utf8(vapache_verified::cache_key_hex(value))
        .expect("cache key hex encoding is ASCII")
}

fn rewrite_map_material(map: &crate::config::RewriteMap) -> String {
    match map {
        crate::config::RewriteMap::Txt(entries) => {
            let mut entries: Vec<_> = entries.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            format!("txt:{entries:?}")
        }
        crate::config::RewriteMap::Rnd(entries) => {
            let mut entries: Vec<_> = entries.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            format!("rnd:{entries:?}")
        }
        crate::config::RewriteMap::Prg(program) => {
            format!("prg:{}", program.cache_material())
        }
        crate::config::RewriteMap::Int(function) => format!("int:{function}"),
    }
}

/// Canonical material for every policy object that can affect authorization,
/// target selection or representation.  `Scope` is destructured so adding a
/// policy slice forces this function to make an explicit decision.  Most
/// policy objects have deterministic `Debug` output; rewrite maps contain a
/// `HashMap`, so their entries are canonicalized before hashing.
fn cache_policy_material(scope: &Scope) -> String {
    let Scope {
        conditional_error,
        options,
        override_policy,
        authorization,
        header_policy,
        content_policy,
        mapping_policy,
        error_policy,
        environment_policy,
        rewrite_policy,
        compression_policy,
        proxy_policy,
    } = scope;
    let crate::scope_policy::RewriteCachePolicy {
        rewrite_engine,
        rewrite_maps,
        cache_enable,
        cache_disable,
        rewrite_inherit,
        rewrite_base,
        rewrite_match_base,
        rewrite_rules,
        pending_rewrite_conds,
    } = rewrite_policy;
    let mut rewrite_maps: Vec<String> = rewrite_maps
        .iter()
        .map(|(name, map)| format!("{name}={}", rewrite_map_material(map)))
        .collect();
    rewrite_maps.sort();
    format!(
        "{conditional_error:?}|{options:?}|{override_policy:?}|{authorization:?}|{header_policy:?}|\
         {content_policy:?}|{mapping_policy:?}|{error_policy:?}|\
         {environment_policy:?}|{compression_policy:?}|{proxy_policy:?}|\
         {rewrite_engine:?}|{}|{cache_enable:?}|{cache_disable:?}|\
         {rewrite_inherit:?}|{rewrite_base:?}|{rewrite_match_base:?}|\
         {rewrite_rules:?}|{pending_rewrite_conds:?}",
        rewrite_maps.join(","),
    )
}

/// Security-relevant policy fingerprint for cache isolation.
fn cache_policy_fingerprint(
    scope: &Scope,
    req: &Request,
    peer: IpAddr,
    target: &std::path::Path,
) -> PolicyFingerprint {
    // Length-prefix every field so concatenation cannot make two different
    // material tuples look identical.  Hash the exact bytes with SHA-256; a
    // 64-bit `DefaultHasher` fingerprint was not collision-resistant enough
    // for a value that decides whether two cache entries may be shared.
    let mut material = Vec::new();
    fingerprint_field(&mut material, cache_policy_material(scope).as_bytes());
    fingerprint_field(&mut material, peer.to_string().as_bytes());
    fingerprint_field(&mut material, req.method.as_bytes());
    fingerprint_field(&mut material, target.as_os_str().as_bytes());
    // Configuration expressions (`Require expr`, `SetEnvIf`, rewrite
    // conditions) can read any request header.  The compiled policy text is
    // not enough to identify the branch a request takes, so bind the complete
    // request header set into the policy fingerprint.  This also partitions
    // non-credential tenant/feature headers and cookies even when the response
    // did not name them in `Vary`.
    for (name, value) in req.headers.iter() {
        fingerprint_field(&mut material, name.as_bytes());
        fingerprint_field(&mut material, value);
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, &material);
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(digest.as_ref());
    fingerprint
}

fn fingerprint_field(out: &mut Vec<u8>, field: &[u8]) {
    // Verified four-byte big-endian framing; see
    // `cache_fingerprint_field_injective`.
    out.extend_from_slice(&vapache_verified::cache_fingerprint_field(field));
}

fn request_allows_lookup(cfg: &Config, req: &Request) -> bool {
    if req.header("authorization").is_some() {
        return false;
    }
    if cfg.cache.ignore_cache_control {
        return true;
    }
    if let Some(pragma) = req.header("pragma") {
        if pragma
            .windows(b"no-cache".len())
            .any(|window| window.eq_ignore_ascii_case(b"no-cache"))
        {
            return false;
        }
    }
    let Some(cc) = req.header("cache-control") else {
        return true;
    };
    !cc.split(|byte| *byte == b',').any(|value| {
        let mut value = value;
        while value.first().is_some_and(u8::is_ascii_whitespace) {
            value = &value[1..];
        }
        while value.last().is_some_and(u8::is_ascii_whitespace) {
            value = &value[..value.len() - 1];
        }
        value.eq_ignore_ascii_case(b"no-cache")
            || value.eq_ignore_ascii_case(b"no-store")
            || value.eq_ignore_ascii_case(b"max-age=0")
    })
}

fn combined_header(headers: &[(String, Vec<u8>)], name: &str) -> Option<String> {
    let mut found = false;
    let mut out = String::new();
    for (n, v) in headers {
        if !n.eq_ignore_ascii_case(name) {
            continue;
        }
        found = true;
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(&String::from_utf8_lossy(v));
    }
    found.then_some(out)
}

fn vary_values(req: &Request, headers: &[(String, Vec<u8>)]) -> Option<Vec<(String, Vec<u8>)>> {
    const MAX_VARY_DIMENSIONS: usize = 256;
    // Multiple `Vary` field lines are legal and equivalent to one
    // comma-separated list.  Collapsing to the first line silently dropped
    // later dimensions such as Cookie on a response that also varied by
    // Accept-Encoding.
    let Some(vary) = combined_header(headers, "vary") else {
        return Some(Vec::new());
    };
    let mut out = Vec::new();
    for name in vary.split(',') {
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() || name == "*" || !crate::verified::valid_token(name.as_bytes()) {
            return None;
        }
        if out.iter().any(|(n, _)| n == &name) {
            continue;
        }
        if out.len() >= MAX_VARY_DIMENSIONS {
            return None;
        }
        out.push((name.clone(), req.header(&name).unwrap_or(b"").to_vec()));
    }
    Some(out)
}

fn vary_matches(entry: &Entry, req: &Request) -> bool {
    entry
        .vary
        .iter()
        .all(|(name, expected)| req.header(name).unwrap_or(b"") == expected.as_slice())
}

fn conditional_hit(req: &Request, entry: &Entry, response: &mut Response) -> bool {
    let if_none_match = req.header("if-none-match");
    let if_none_match_matches = if_none_match.is_some_and(|value| {
        crate::verified::cache_if_none_match_matches(
            value,
            header(&entry.headers, "etag").unwrap_or(b""),
        )
    });
    let if_modified_since_matches = if if_none_match.is_none() {
        req.header("if-modified-since").is_some_and(|ims| {
            if let (Some(since), Some(last)) = (
                parse_http_date(ims),
                header(&entry.headers, "last-modified").and_then(parse_http_date),
            ) {
                last <= since
            } else {
                false
            }
        })
    } else {
        false
    };
    let hit = crate::verified::cache_conditional_hit_admit(
        if_none_match.is_some(),
        if_none_match_matches,
        if_modified_since_matches,
    );
    if hit {
        response.status = 304;
        response.body = Body::Empty;
    }
    hit
}

#[allow(clippy::too_many_arguments)]
pub fn lookup(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    host: &str,
    path: &str,
    scope: &Scope,
    peer: IpAddr,
    grant: &AccessGrant,
    cache_key: &str,
    target: &std::path::Path,
) -> Option<Response> {
    let fingerprint = cache_policy_fingerprint(scope, req, peer, target);
    if !grant.require_sink(
        &crate::access::ResourceKey::cache_policy(vhost, req, host, path, fingerprint),
        vapache_verified::TransformSink::Cache,
    ) {
        return None;
    }
    if !request_allows_lookup(cfg, req) {
        return None;
    }
    let key = cache_key.to_string();
    let now = unix_now();
    let cache_context = req
        .resource_context()
        .cloned()
        .unwrap_or_else(|| cfg.resource_budget.context(peer));
    let mut found: Option<Arc<Entry>> = None;
    let mut response_resident = None;
    {
        let mut cache = entries().lock().unwrap_or_else(|e| e.into_inner());
        let mut list = cache.entries.remove(&key).unwrap_or_default();
        let mut retained = Vec::with_capacity(list.len());
        for entry in list.drain(..) {
            if entry.expires <= now {
                cache.bytes = cache.bytes.saturating_sub(memory_entry_size(&key, &entry));
                untrack_memory_entry(&mut cache, &entry);
                continue;
            }
            if found.is_none()
                && vapache_verified::cache_lookup_admit(
                    true,
                    entry.policy == fingerprint,
                    vary_matches(&entry, req),
                    entry.epoch == current_epoch(),
                    entry.expires,
                    now,
                )
            {
                // Arc cloning is constant-size and does not copy the cached
                // representation while the process-wide lock is held.
                found = Some(Arc::clone(&entry));
            }
            retained.push(entry);
        }
        if !retained.is_empty() {
            cache.entries.insert(key.clone(), retained);
        }
    }
    if found.is_none() {
        let mut load_resident = cfg
            .resource_budget
            .try_response_bytes_in(&cache_context)
            .ok()?;
        if let Some(mut loaded) = disk_load_accounted(cfg, &key, &mut load_resident) {
            if !vapache_verified::cache_lookup_admit(
                true,
                loaded.policy == fingerprint,
                vary_matches(&loaded, req),
                loaded.epoch == current_epoch(),
                loaded.expires,
                now,
            ) {
                return None;
            }
            // Cover the response-body clone while the decoded disk entry is
            // still live. The lease is transferred into the Response below.
            load_resident.reserve(loaded.body.len() as u64).ok()?;
            if loaded.body_len <= MAX_MEMORY_BODY as u64 && cfg.cache.max_memory_size > 0 {
                let incoming = memory_entry_size(&key, &loaded);
                if incoming <= cfg.cache.max_memory_size {
                    loaded._resident = cfg
                        .resource_budget
                        .try_cache_resident(&cache_context, cfg.cache.max_memory_size, incoming)
                        .ok()
                        .map(Arc::new);
                }
            }
            let loaded = Arc::new(loaded);
            if loaded._resident.is_some() {
                insert_memory(cfg, &key, Arc::clone(&loaded));
            }
            found = Some(loaded);
            response_resident = Some(load_resident);
        }
    }
    let entry = found?;

    let mut response = Response::new(entry.status);
    response.headers = entry
        .headers
        .iter()
        .map(|(n, v)| (Cow::Owned(n.clone()), v.clone()))
        .collect();
    let age = (now - entry.stored).max(0).to_string();
    response
        .headers
        .retain(|(n, _)| !n.eq_ignore_ascii_case("age"));
    response
        .headers
        .push((Cow::Borrowed("Age"), age.into_bytes()));
    if cfg.cache.header {
        response
            .headers
            .retain(|(n, _)| !n.eq_ignore_ascii_case("x-cache"));
        response
            .headers
            .push((Cow::Borrowed("X-Cache"), b"HIT".to_vec()));
    }
    if cfg.cache.detail_header {
        response
            .headers
            .push((Cow::Borrowed("X-Cache-Detail"), b"fresh cache hit".to_vec()));
    }
    if conditional_hit(req, &entry, &mut response) {
        response
            .headers
            .retain(|(n, _)| !n.eq_ignore_ascii_case("content-length"));
    } else if req.method != "HEAD" {
        // Large cached representations are already persisted as a body file.
        // Serve that file through the file-body path so the plain-TCP writer
        // can use sendfile instead of copying the whole body from user memory.
        const FILE_BODY_THRESHOLD: usize = 64 * 1024;
        let mut served_file = false;
        if entry.body_len > FILE_BODY_THRESHOLD as u64 {
            if let Some(stem) = cache_stem(cfg, cache_key) {
                let path = stem.with_extension("body");
                if let Some((file, meta)) = open_cache_regular(&path, cfg.cache.max_file_size) {
                    if meta.len() == entry.body_len {
                        response.body = Body::File {
                            file,
                            offset: 0,
                            len: meta.len(),
                        };
                        served_file = true;
                    }
                }
            }
        }
        if !served_file {
            if response_resident.is_none() {
                let mut resident = cfg
                    .resource_budget
                    .try_response_bytes_in(&cache_context)
                    .ok()?;
                resident.reserve(entry.body.len() as u64).ok()?;
                response_resident = Some(resident);
            }
            response.body = Body::Bytes(entry.body.clone());
        }
    }
    if let Some(resident) = response_resident {
        response.hold_resident(resident);
    }
    Some(response)
}

fn cache_control_directives(
    headers: &[(String, Vec<u8>)],
) -> Result<Vec<crate::http::CacheControlDirective>, ()> {
    crate::http::parse_cache_control_values(
        headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("cache-control"))
            .map(|(_, value)| value.as_slice()),
    )
}

fn directive_seconds(
    directives: &[crate::http::CacheControlDirective],
    name: &str,
) -> Result<Option<u64>, ()> {
    let mut found = None;
    for directive in directives {
        if directive.name != name {
            continue;
        }
        if found.is_some() {
            return Err(());
        }
        let value = directive.value.as_deref().ok_or(())?;
        if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
            return Err(());
        }
        let value = std::str::from_utf8(value)
            .map_err(|_| ())?
            .parse::<u64>()
            .map_err(|_| ())?;
        found = Some(value);
    }
    Ok(found)
}

fn single_header<'a>(headers: &'a [(String, Vec<u8>)], name: &str) -> Result<Option<&'a [u8]>, ()> {
    let mut values = headers
        .iter()
        .filter(|(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_slice());
    let first = values.next();
    if values.next().is_some() {
        Err(())
    } else {
        Ok(first)
    }
}

fn cache_metadata_singletons_valid(headers: &[(String, Vec<u8>)]) -> bool {
    const SINGLETONS: [&str; 11] = [
        "age",
        "content-disposition",
        "content-location",
        "content-range",
        "content-type",
        "date",
        "etag",
        "expires",
        "last-modified",
        "location",
        "retry-after",
    ];
    SINGLETONS
        .iter()
        .all(|name| single_header(headers, name).is_ok())
        // A reusable complete response cannot carry partial-representation
        // metadata under one of the cacheable full-response statuses.
        && header(headers, "content-range").is_none()
}

fn decimal_seconds(value: &[u8]) -> Option<u64> {
    let value = crate::util::trim_ascii(value);
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(value).ok()?.parse().ok()
}

fn response_current_age(headers: &[(String, Vec<u8>)], now: i64) -> Option<(u64, Option<i64>)> {
    let age_value = match single_header(headers, "age").ok()? {
        Some(value) => decimal_seconds(value)?,
        None => 0,
    };
    let date = match single_header(headers, "date").ok()? {
        Some(value) => Some(parse_http_date(value)?),
        None => None,
    };
    let apparent_age = date
        .map(|date| u64::try_from(now.saturating_sub(date).max(0)).unwrap_or(u64::MAX))
        .unwrap_or(0);
    Some((age_value.max(apparent_age), date))
}

fn bounded_remaining_ttl(
    cfg: &CacheConfig,
    lifetime: u64,
    current_age: u64,
    heuristic: bool,
) -> i64 {
    if cfg.min_expire > cfg.max_expire {
        return 0;
    }
    let remaining = vapache_verified::cache_remaining_freshness(lifetime, current_age);
    if remaining == 0 {
        return 0;
    }
    let remaining = i64::try_from(remaining).unwrap_or(i64::MAX);
    let min = if heuristic {
        i64::try_from(cfg.min_expire).unwrap_or(i64::MAX)
    } else {
        0
    };
    let max = i64::try_from(cfg.max_expire).unwrap_or(i64::MAX);
    vapache_verified::cache_ttl_clamp(remaining, min, max)
}

fn freshness_and_age(
    cfg: &CacheConfig,
    headers: &[(String, Vec<u8>)],
    now: i64,
) -> Option<(i64, u64)> {
    let directives = cache_control_directives(headers).ok()?;
    let s_maxage = directive_seconds(&directives, "s-maxage").ok()?;
    let max_age = directive_seconds(&directives, "max-age").ok()?;
    let (current_age, date) = response_current_age(headers, now)?;
    if let Some(n) = s_maxage.or(max_age) {
        return Some((
            bounded_remaining_ttl(cfg, n, current_age, false),
            current_age,
        ));
    }
    if let Some(expires) = single_header(headers, "expires").ok()? {
        let expires = parse_http_date(expires)?;
        let reference = date.unwrap_or(now);
        let lifetime = u64::try_from(expires.saturating_sub(reference).max(0)).ok()?;
        let ttl = bounded_remaining_ttl(cfg, lifetime, current_age, false);
        if ttl <= 0 {
            return None;
        }
        return Some((ttl, current_age));
    }
    if let Some(last) = single_header(headers, "last-modified").ok()? {
        let last = parse_http_date(last)?;
        let reference = date.unwrap_or(now);
        let representation_age = reference.saturating_sub(last).max(0) as f64;
        let lifetime = (representation_age * cfg.last_modified_factor) as u64;
        if lifetime > 0 {
            return Some((
                bounded_remaining_ttl(cfg, lifetime, current_age, true),
                current_age,
            ));
        }
        // A just-written file has no observable reuse window through the
        // Last-Modified heuristic; CacheDefaultExpire keeps it cacheable.
        return Some((
            bounded_remaining_ttl(cfg, cfg.default_expire, current_age, true),
            current_age,
        ));
    }
    if cfg.ignore_no_last_mod {
        return Some((
            bounded_remaining_ttl(cfg, cfg.default_expire, current_age, true),
            current_age,
        ));
    }
    None
}

fn freshness(cfg: &CacheConfig, headers: &[(String, Vec<u8>)], now: i64) -> Option<i64> {
    freshness_and_age(cfg, headers, now).map(|(ttl, _)| ttl)
}

fn response_body_bytes(
    body: &mut Body,
    resident: &mut crate::resource::ResidentLease,
) -> Option<Vec<u8>> {
    match body {
        Body::Empty => Some(Vec::new()),
        Body::Bytes(bytes) => {
            resident.reserve(bytes.len() as u64).ok()?;
            Some(bytes.clone())
        }
        Body::File { file, offset, len } => {
            let len = usize::try_from(*len).ok()?;
            resident.reserve(len as u64).ok()?;
            let mut file = file.try_clone().ok()?;
            file.seek(SeekFrom::Start(*offset)).ok()?;
            let mut bytes = vec![0; len];
            file.read_exact(&mut bytes).ok()?;
            Some(bytes)
        }
        Body::Stream { .. } => None,
    }
}

pub fn prepare_dir(cfg: &Config, dir: &std::path::Path) {
    let Ok(opened) = crate::files::ensure_admin_dir(dir, 0o755) else {
        return;
    };
    // The daemon drops privileges after binding, so hand the cache directory
    // to the configured account while we are still privileged.
    #[cfg(unix)]
    {
        use std::ffi::CString;
        if unsafe { libc::geteuid() } == 0 {
            let user = CString::new(cfg.user.as_str()).ok(); // coverage:ignore-start - root-only ownership handoff
            let group = CString::new(cfg.group.as_str()).ok();
            let uid = user.as_ref().and_then(|u| unsafe {
                let pw = libc::getpwnam(u.as_ptr());
                (!pw.is_null()).then(|| (*pw).pw_uid)
            });
            let gid = group.as_ref().and_then(|g| unsafe {
                let gr = libc::getgrnam(g.as_ptr());
                (!gr.is_null()).then(|| (*gr).gr_gid)
            });
            unsafe {
                if let Some(uid) = uid {
                    let gid = gid.unwrap_or(u32::MAX);
                    let _ = libc::fchown(opened.as_raw_fd(), uid, gid);
                }
                let _ = libc::fchmod(opened.as_raw_fd(), 0o770); // coverage:ignore-stop
            }
        }
    }
}

pub fn prepare(cfg: &Config) {
    if let Some(root) = &cfg.cache.root {
        prepare_dir(cfg, root);
    }
}

fn cache_stem(cfg: &Config, key: &str) -> Option<std::path::PathBuf> {
    let root = cfg.cache.root.as_ref()?;
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    let name: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Some(root.join(name))
}

fn encode_meta(key: &str, entry: &Entry) -> Vec<u8> {
    let mut out = format!(
        "V7\nK {}\nS {}\nT {}\nE {}\nP {}\nG {}\n",
        STANDARD.encode(key.as_bytes()),
        entry.status,
        entry.stored,
        entry.expires,
        STANDARD.encode(entry.policy),
        entry.epoch
    );
    for (name, value) in &entry.vary {
        out.push_str(&format!(
            "V {} {}\n",
            STANDARD.encode(name.as_bytes()),
            STANDARD.encode(value)
        ));
    }
    for (name, value) in &entry.headers {
        out.push_str(&format!(
            "H {} {}\n",
            STANDARD.encode(name.as_bytes()),
            STANDARD.encode(value)
        ));
    }
    out.into_bytes()
}

fn decode_meta(data: &[u8]) -> Option<Entry> {
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.lines();
    let version = lines.next()?;
    if version != "V1"
        && version != "V2"
        && version != "V3"
        && version != "V4"
        && version != "V5"
        && version != "V6"
        && version != "V7"
    {
        return None;
    }
    let mut status = None;
    let mut stored = None;
    let mut expires = None;
    let mut policy = None;
    // V1 entries predate the configuration-generation field and are never
    // admissible in a live configuration.
    let mut epoch = Some(0u64);
    let mut vary = Vec::new();
    let mut headers = Vec::new();
    for line in lines {
        let mut parts = line.splitn(3, ' ');
        let kind = parts.next()?;
        match kind {
            "S" => status = parts.next()?.parse::<u16>().ok(),
            "T" => stored = parts.next()?.parse::<i64>().ok(),
            "E" => expires = parts.next()?.parse::<i64>().ok(),
            "P" => {
                let raw = STANDARD.decode(parts.next()?).ok()?;
                policy = Some(<[u8; 32]>::try_from(raw.as_slice()).ok()?);
            }
            "G" => epoch = parts.next()?.parse::<u64>().ok(),
            "V" | "H" => {
                let name = STANDARD.decode(parts.next()?).ok()?;
                let value = STANDARD.decode(parts.next().unwrap_or("")).ok()?;
                let name = String::from_utf8(name).ok()?;
                if kind == "V" {
                    vary.push((name, value));
                } else {
                    headers.push((name, value));
                }
            }
            _ => {}
        }
    }
    Some(Entry {
        status: status?,
        headers,
        body: Vec::new(),
        body_len: 0,
        stored: stored?,
        expires: expires?,
        policy: policy?,
        epoch: epoch?,
        vary,
        _resident: None,
    })
}

/// Return the exact cache key carried by current metadata.  Older metadata is
/// deliberately unkeyed: it can be decoded for diagnostics, but it is never
/// served and is removed conservatively by targeted invalidation.
fn decode_meta_key(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.lines();
    // V7 deliberately invalidates representations admitted before every
    // Cache-Control line, qualified private/no-cache directives, malformed
    // Vary metadata and ambiguous singleton fields failed closed.  Older
    // entries can otherwise replay a representation the current admission
    // policy would refuse to store.
    if lines.next()? != "V7" {
        return None;
    }
    for line in lines {
        if let Some(encoded) = line.strip_prefix("K ") {
            return STANDARD.decode(encoded).ok();
        }
    }
    None
}

/// Exercise both metadata decoders on arbitrary and truncated disk records.
#[cfg(feature = "fuzzing")]
pub fn fuzz_decode_metadata(data: &[u8]) {
    let _ = decode_meta(data);
    let _ = decode_meta_key(data);
}

fn disk_store(cfg: &Config, key: &str, entry: &Entry) {
    let Some(stem) = cache_stem(cfg, key) else {
        return;
    };
    let Ok(_io_guard) = disk_io_lock(&stem).try_lock() else {
        // Contention means another reader/writer is already making progress
        // for this stripe. Cache population is optional, so never turn the
        // stripe into a request-worker convoy.
        return;
    };
    // `cache_stem` succeeds exactly when the root exists.
    let root = cfg
        .cache
        .root
        .as_ref()
        .expect("cache root checked by cache_stem");
    if let Some(parent) = stem.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let meta = encode_meta(key, entry);
    let incoming = (entry.body.len() as u64).saturating_add(meta.len() as u64);
    // A single representation larger than the whole disk budget is never
    // written; `CacheMaxFileSize` already bounds the body, while this covers
    // metadata and the total quota.
    if incoming > cfg.cache.max_disk_size {
        return;
    }
    // Establish the initial index without holding the process-wide state lock
    // across the bounded filesystem walk. A racing store may install an
    // equivalent index first; `entry().or_insert` keeps that newer state.
    if !ensure_disk_usage(root, &cfg.resource_budget) {
        return;
    }
    let (generation, victims) = {
        let mut roots = disk_usage().lock().unwrap_or_else(|e| e.into_inner());
        let usage = roots
            .get_mut(root)
            .expect("bounded disk scan inserted cache usage");
        let old_size = usage
            .stems
            .get(&stem)
            .map(|(size, _, _)| *size)
            .unwrap_or(0);
        let old_count = usize::from(old_size > 0);
        let old_files = usage.file_counts.get(&stem).copied().unwrap_or(0);
        let mut projected = vapache_verified::cache_disk_projected(usage.total, old_size, incoming);
        let mut entries = usage
            .stems
            .len()
            .saturating_sub(old_count)
            .saturating_add(1);
        let peak_bytes = old_size.saturating_add(incoming);
        let peak_files = old_files.saturating_add(2);
        let lease = usage.leases.entry(stem.clone()).or_insert_with(|| {
            cfg.resource_budget
                .try_disk_at(root, 0, 0)
                .expect("zero-sized disk lease must be admissible")
        });
        if lease.resize(peak_bytes, peak_files).is_err() {
            return;
        }
        let mut victims = Vec::new();
        while projected > cfg.cache.max_disk_size || entries > MAX_DISK_ENTRIES {
            let Some((victim, queued_generation)) = usage.eviction.pop_front() else {
                break;
            };
            if victim == stem {
                continue;
            }
            let Some((size, _, current_generation)) = usage.stems.get(&victim).copied() else {
                continue;
            };
            if current_generation != queued_generation {
                continue;
            }
            if usage.stems.remove(&victim).is_some() {
                usage.total = usage.total.saturating_sub(size);
                projected = vapache_verified::cache_disk_evict(projected, size);
                entries = entries.saturating_sub(1);
                victims.push((victim.clone(), usage.leases.remove(&victim)));
            }
            usage.file_counts.remove(&victim);
            usage.keys.remove(&victim);
        }
        if projected > cfg.cache.max_disk_size || entries > MAX_DISK_ENTRIES {
            if let Some(lease) = usage.leases.get_mut(&stem) {
                let _ = lease.resize(old_size, old_files);
            }
            if old_size == 0 {
                usage.leases.remove(&stem);
            }
            (None, victims)
        } else {
            usage.next_generation = usage.next_generation.wrapping_add(1).max(1);
            let generation = usage.next_generation;
            let stored = SystemTime::now();
            usage.total = projected;
            usage
                .stems
                .insert(stem.clone(), (incoming, stored, generation));
            usage.file_counts.insert(stem.clone(), 2);
            usage.eviction.push_back((stem.clone(), generation));
            if usage.eviction.len() > MAX_DISK_ENTRIES * 8 {
                let (stems, eviction) = (&usage.stems, &mut usage.eviction);
                eviction.retain(|(candidate, queued_generation)| {
                    stems
                        .get(candidate)
                        .is_some_and(|(_, _, current_generation)| {
                            current_generation == queued_generation
                        })
                });
            }
            usage
                .keys
                .insert(stem.clone(), Some(key.as_bytes().to_vec()));
            (Some(generation), victims)
        }
    };
    // Filesystem I/O happens after releasing the accounting lock. Concurrent
    // stores reserve their bytes first, so the disk quota remains closed.
    for (victim, lease) in victims {
        remove_disk_stem_files(&victim);
        drop(lease);
    }
    let Some(generation) = generation else {
        return;
    };
    let body_path = stem.with_extension("body");
    let meta_path = stem.with_extension("meta");
    let body_tmp = stem.with_extension("body.tmp");
    let meta_tmp = stem.with_extension("meta.tmp");
    if write_cache_temp(&body_tmp, &entry.body).is_err()
        || write_cache_temp(&meta_tmp, &meta).is_err()
    {
        remove_disk_stem_files(&stem);
        release_disk_reservation(root, &stem, generation);
        return;
    }
    if crate::fault::hit("cache.rename.body")
        .and_then(|()| fs::rename(&body_tmp, &body_path))
        .is_err()
        || crate::fault::hit("cache.rename.meta")
            .and_then(|()| fs::rename(&meta_tmp, &meta_path))
            .is_err()
    {
        let _ = fs::remove_file(&body_tmp);
        let _ = fs::remove_file(&meta_tmp);
        let _ = fs::remove_file(&body_path);
        let _ = fs::remove_file(&meta_path);
        release_disk_reservation(root, &stem, generation);
        return;
    }
    let actual = fs::metadata(&body_path)
        .map(|m| m.len())
        .unwrap_or(entry.body.len() as u64)
        .saturating_add(
            fs::metadata(&meta_path)
                .map(|m| m.len())
                .unwrap_or(meta.len() as u64),
        );
    let mut roots = disk_usage().lock().unwrap_or_else(|e| e.into_inner());
    if crate::fault::hit("cache.commit.usage").is_err() {
        roots.remove(root);
    }
    let Some(usage) = roots.get_mut(root) else {
        drop(roots);
        remove_disk_stem_files(&stem);
        return;
    };
    if crate::fault::hit("cache.commit.reservation").is_err() {
        if let Some((reserved, _, _)) = usage.stems.remove(&stem) {
            usage.total = usage.total.saturating_sub(reserved);
        }
        usage.file_counts.remove(&stem);
        usage.keys.remove(&stem);
        usage.leases.remove(&stem);
    }
    let Some((reserved, _, current_generation)) = usage.stems.get_mut(&stem) else {
        drop(roots);
        remove_disk_stem_files(&stem);
        return;
    };
    if crate::fault::hit("cache.commit.generation").is_err() {
        *current_generation = current_generation.wrapping_add(1);
    }
    if *current_generation != generation {
        let reserved = *reserved;
        usage.stems.remove(&stem);
        usage.file_counts.remove(&stem);
        usage.keys.remove(&stem);
        usage.leases.remove(&stem);
        usage.total = usage.total.saturating_sub(reserved);
        drop(roots);
        remove_disk_stem_files(&stem);
        return;
    }
    usage.total = usage.total.saturating_sub(*reserved).saturating_add(actual);
    *reserved = actual;
    if usage
        .leases
        .get_mut(&stem)
        .is_none_or(|lease| lease.resize(actual, 2).is_err())
    {
        usage.stems.remove(&stem);
        usage.file_counts.remove(&stem);
        usage.keys.remove(&stem);
        usage.leases.remove(&stem);
        usage.total = usage.total.saturating_sub(actual);
        drop(roots);
        remove_disk_stem_files(&stem);
    }
}

fn release_disk_reservation(root: &Path, stem: &Path, generation: u64) {
    let mut roots = disk_usage().lock().unwrap_or_else(|e| e.into_inner());
    let Some(usage) = roots.get_mut(root) else {
        return;
    };
    let current = usage.stems.get(stem).copied();
    if let Some((size, _, current_generation)) = current {
        if current_generation == generation {
            usage.stems.remove(stem);
            usage.file_counts.remove(stem);
            usage.keys.remove(stem);
            usage.leases.remove(stem);
            usage.total = usage.total.saturating_sub(size);
        }
    }
}

fn disk_load_accounted(
    cfg: &Config,
    key: &str,
    resident: &mut crate::resource::ResidentLease,
) -> Option<Entry> {
    let stem = cache_stem(cfg, key)?;
    let Ok(_io_guard) = disk_io_lock(&stem).try_lock() else {
        return None;
    };
    let meta = match read_disk_metadata_accounted(&stem.with_extension("meta"), resident) {
        Some(meta) => meta,
        None => {
            remove_disk_stem(cfg, &stem);
            return None;
        }
    };
    let metadata_key = decode_meta_key(&meta);
    let exact_key = metadata_key.as_deref() == Some(key.as_bytes());
    if !vapache_verified::cache_disk_key_admit(metadata_key.is_some(), exact_key) {
        remove_disk_stem(cfg, &stem);
        return None;
    }
    let mut entry = match decode_meta(&meta) {
        Some(entry) => entry,
        None => {
            remove_disk_stem(cfg, &stem);
            return None;
        }
    };
    // A reload changes the generation and expiry makes the representation
    // unusable.  Remove both files instead of leaving them to fill the cache
    // filesystem (F44).
    if entry.epoch != current_epoch() || entry.expires <= unix_now() {
        remove_disk_stem(cfg, &stem);
        return None;
    }
    let (mut body, body_meta) =
        match open_cache_regular(&stem.with_extension("body"), cfg.cache.max_file_size) {
            Some(body) => body,
            None => {
                remove_disk_stem(cfg, &stem);
                return None;
            }
        };
    entry.body_len = body_meta.len();
    if entry.body_len <= MAX_MEMORY_BODY as u64 {
        resident.reserve(entry.body_len).ok()?;
        entry.body.resize(entry.body_len as usize, 0);
        if crate::fault::hit("cache.body.read")
            .and_then(|()| body.read_exact(&mut entry.body))
            .is_err()
        {
            remove_disk_stem(cfg, &stem);
            return None;
        }
    }
    Some(entry)
}

#[cfg(test)]
fn disk_load(cfg: &Config, key: &str) -> Option<Entry> {
    let client = "127.0.0.1".parse().expect("loopback address");
    let mut resident = cfg.resource_budget.try_response_bytes_for(client);
    disk_load_accounted(cfg, key, &mut resident)
}

#[allow(clippy::too_many_arguments)]
pub fn store(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    host: &str,
    path: &str,
    scope: &Scope,
    peer: IpAddr,
    resp: &mut Response,
    grant: &AccessGrant,
    cache_key: &str,
    target: &std::path::Path,
) {
    // A local ErrorDocument marks the response itself ineligible before this
    // boundary. Response-local provenance cannot bleed between async tasks.
    if !resp.shared_cache_eligible() || !crate::http::response_headers_valid(resp) {
        return;
    }
    let fingerprint = cache_policy_fingerprint(scope, req, peer, target);
    if !grant.require_sink(
        &crate::access::ResourceKey::cache_policy(vhost, req, host, path, fingerprint),
        vapache_verified::TransformSink::Cache,
    ) {
        return;
    }
    // Credentialed responses are never placed in the shared cache.  The
    // cache has no identity dimension, so storing one and hoping a later
    // policy check rejects a different identity is not sufficient.
    let credential_free = req.header("authorization").is_none() && req.header("cookie").is_none();
    if !vapache_verified::cache_store_request_admit(
        req.method == "GET",
        req.body_len() == 0,
        credential_free,
    ) {
        return;
    }
    if !vapache_verified::cache_store_status_admit(resp.status) {
        return;
    }
    let Ok(header_sanitizer) = crate::http::ResponseHeaderSanitizer::from_response(resp) else {
        return;
    };
    if header_sanitizer.nominates_framing() || header_sanitizer.nominates_end_to_end() {
        return;
    }
    let response_headers: Vec<(String, Vec<u8>)> = resp
        .headers
        .iter()
        .filter(|(name, _)| !header_sanitizer.is_hop_by_hop(name))
        .map(|(n, v)| (n.to_string(), v.clone()))
        .collect();
    if !cache_metadata_singletons_valid(&response_headers) {
        return;
    }
    let Ok(directives) = cache_control_directives(&response_headers) else {
        return;
    };
    let no_store = directives.iter().any(|d| d.name == "no-store");
    let no_cache = directives.iter().any(|d| d.name == "no-cache");
    let private = directives.iter().any(|d| d.name == "private");
    if !vapache_verified::cache_store_control_admit(
        no_store,
        no_cache,
        private,
        cfg.cache.store_no_store,
        cfg.cache.ignore_cache_control,
        cfg.cache.store_private,
    ) {
        return;
    }
    let set_cookie = header(&response_headers, "set-cookie").is_some();
    let Some(vary) = vary_values(req, &response_headers) else {
        return;
    };
    #[cfg(test)]
    let fallback_context;
    let resource_context = match req.resource_context() {
        Some(context) => context,
        #[cfg(test)]
        None => {
            fallback_context = cfg.resource_budget.context(peer);
            &fallback_context
        }
        #[cfg(not(test))]
        None => return,
    };
    let Ok(mut cache_resident) = cfg.resource_budget.try_response_bytes_in(resource_context) else {
        return;
    };
    let Some(body) = response_body_bytes(&mut resp.body, &mut cache_resident) else {
        return;
    };
    let size_ok = body.len() as u64 <= cfg.cache.max_file_size
        && (body.len() as u64) >= cfg.cache.min_file_size;
    if !vapache_verified::cache_store_shape_admit(set_cookie, false, size_ok) {
        return;
    }
    let now = unix_now();
    let Some((ttl, response_age)) = freshness_and_age(&cfg.cache, &response_headers, now) else {
        return;
    };
    if !vapache_verified::cache_store_ttl_admit(ttl) {
        return;
    }
    let mut headers = Vec::new();
    for (name, value) in &response_headers {
        if CACHE_PRIVATE_HEADERS
            .iter()
            .any(|private| name.eq_ignore_ascii_case(private))
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("age")
            || name.eq_ignore_ascii_case("x-cache")
        {
            continue;
        }
        headers.push((name.clone(), value.clone()));
    }
    let key = cache_key.to_string();
    let body_len = body.len() as u64;
    let mut entry = Entry {
        status: resp.status,
        headers,
        body,
        body_len,
        stored: now.saturating_sub(i64::try_from(response_age).unwrap_or(i64::MAX)),
        expires: vapache_verified::cache_expiry(now, ttl),
        policy: fingerprint,
        epoch: current_epoch(),
        vary,
        _resident: None,
    };
    let cache_context = req
        .resource_context()
        .cloned()
        .unwrap_or_else(|| cfg.resource_budget.context(peer));
    let cache_write_bytes =
        body_len.saturating_add(entry.headers.iter().fold(256u64, |total, (name, value)| {
            total
                .saturating_add(name.len() as u64)
                .saturating_add(value.len() as u64)
        }));
    if cfg
        .resource_budget
        .try_cache_write(&cache_context, cache_write_bytes)
        .is_err()
    {
        return;
    }
    if entry.body_len <= MAX_MEMORY_BODY as u64 {
        let incoming = memory_entry_size(&key, &entry);
        if incoming <= cfg.cache.max_memory_size {
            entry._resident = cfg
                .resource_budget
                .try_cache_resident(&cache_context, cfg.cache.max_memory_size, incoming)
                .ok()
                .map(Arc::new);
        }
    }
    disk_store(cfg, &key, &entry);
    insert_memory(cfg, &key, Arc::new(entry));
    if cfg.cache.header {
        resp.headers
            .retain(|(n, _)| !n.eq_ignore_ascii_case("x-cache"));
        resp.headers
            .push((Cow::Borrowed("X-Cache"), b"MISS".to_vec()));
    }
}

/// Invalidate every cache representation for a new configuration generation.
/// The in-memory map is cleared and the persisted body/meta files are removed.
/// The epoch bump additionally rejects any stale file a concurrent writer could
/// recreate while cleanup is in progress.
pub fn clear(cfg: &Config) {
    bump_epoch();
    *entries().lock().unwrap_or_else(|e| e.into_inner()) = MemoryCache::default();
    invalidate_disk(cfg);
}

pub(crate) fn invalidate_generation_only() {
    bump_epoch();
    *entries().lock().unwrap_or_else(|e| e.into_inner()) = MemoryCache::default();
}

/// Remove every persisted cache file after a configuration-generation change.
fn invalidate_disk(cfg: &Config) {
    let Some(root) = &cfg.cache.root else {
        return;
    };
    let retained_usage = disk_usage()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(root);
    let mut stack = vec![(root.clone(), 0usize)];
    let mut scanned = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_DISK_SCAN_DEPTH {
            break;
        }
        let Ok(read) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.flatten() {
            scanned = scanned.saturating_add(1);
            if scanned > MAX_DISK_SCAN_RECORDS {
                return;
            }
            let path = entry.path();
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => stack.push((path, depth + 1)),
                Ok(ft) if ft.is_file() => {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if name.ends_with(".body")
                        || name.ends_with(".meta")
                        || name.ends_with(".body.tmp")
                        || name.ends_with(".meta.tmp")
                    {
                        let _ = fs::remove_file(&path);
                    }
                }
                _ => {}
            }
        }
    }
    drop(retained_usage);
}

/// Remove only disk entries whose embedded, complete key has the selected
/// canonical request-URI prefix.  Unkeyed legacy/corrupt metadata and orphan
/// temporary/body files are removed conservatively during the same scan.
fn invalidate_disk_prefix(cfg: &Config, prefix: &[u8]) {
    let Some(root) = &cfg.cache.root else {
        return;
    };
    // Build the index at most once per cache generation. Subsequent unsafe
    // requests select matching stems in memory instead of recursively walking
    // and rereading every metadata file.
    if !ensure_disk_usage(root, &cfg.resource_budget) {
        // A bounded scan could not establish which persisted entries are
        // affected. Advance the generation so none of them can be served,
        // and release the bounded in-memory cache as the fail-closed path.
        bump_epoch();
        *entries().lock().unwrap_or_else(|e| e.into_inner()) = MemoryCache::default();
        return;
    }
    let victims = {
        let mut roots = disk_usage().lock().unwrap_or_else(|e| e.into_inner());
        let usage = roots
            .get_mut(root)
            .expect("bounded disk scan inserted cache usage");
        let victim_paths: Vec<PathBuf> = usage
            .stems
            .keys()
            .filter(|stem| {
                let key = usage.keys.get(*stem).and_then(|key| key.as_deref());
                vapache_verified::cache_invalidation_remove_admit(
                    key.is_some(),
                    key.is_some_and(|key| key.starts_with(prefix)),
                )
            })
            .cloned()
            .collect();
        let mut victims = Vec::with_capacity(victim_paths.len());
        for stem in victim_paths {
            if let Some((size, _, _)) = usage.stems.remove(&stem) {
                usage.total = usage.total.saturating_sub(size);
            }
            usage.file_counts.remove(&stem);
            usage.keys.remove(&stem);
            victims.push((stem.clone(), usage.leases.remove(&stem)));
        }
        victims
    };
    for (stem, lease) in victims {
        remove_disk_stem_files(&stem);
        drop(lease);
    }
}

pub fn invalidate(cfg: &Config, host: &str, path: &str) {
    // Keep the prefix in the same lossless encoding as `base_key`; a lossy
    // `display()` prefix no longer matches keys and would leave stale entries
    // after an unsafe method (F55/I51).
    let prefix = format!(
        "{}\n{}\n{}\n",
        key_component(cfg.server_root.as_os_str().as_bytes()),
        key_component(host.as_bytes()),
        key_component(path.as_bytes()),
    );
    let mut cache = entries().lock().unwrap_or_else(|e| e.into_inner());
    let victims: Vec<String> = cache
        .entries
        .keys()
        .filter(|key| key.starts_with(&prefix))
        .cloned()
        .collect();
    for key in victims {
        if let Some(list) = cache.entries.remove(&key) {
            for entry in list {
                cache.bytes = cache.bytes.saturating_sub(memory_entry_size(&key, &entry));
                untrack_memory_entry(&mut cache, &entry);
            }
        }
    }
    drop(cache);
    invalidate_disk_prefix(cfg, prefix.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_request() -> crate::http::Request {
        crate::http::Request {
            method: "GET".into(),
            target: b"/x".to_vec(),
            raw_path: b"/x".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    #[test]
    fn prefix_matching_uses_path_boundaries() {
        assert!(prefix_matches("/cache/a", "/cache"));
        assert!(!prefix_matches("/cachex", "/cache"));
        assert!(prefix_matches("/any", "/"));
        assert!(prefix_matches("/cache/", "/cache/"));
    }

    #[test]
    fn disk_entries_round_trip_for_warm_start() {
        let dir = std::env::temp_dir().join(format!("vapache-cache-meta-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(&conf, "Listen 127.0.0.1:0\n").unwrap();
        let mut cfg = crate::config::Config::load(
            &conf,
            &dir,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap();
        cfg.cache.root = Some(dir.join("cache"));
        let entry = Entry {
            status: 200,
            headers: vec![("content-type".into(), b"text/plain".to_vec())],
            body: b"hello".to_vec(),
            body_len: 5,
            stored: unix_now(),
            expires: unix_now() + 60,
            policy: [7u8; 32],
            epoch: current_epoch(),
            vary: vec![("accept".into(), b"text/plain".to_vec())],
            _resident: None,
        };
        disk_store(&cfg, "host\n/path\n", &entry);
        let loaded = disk_load(&cfg, "host\n/path\n").expect("warm entry");
        assert_eq!(loaded.status, 200);
        assert_eq!(loaded.body, b"hello");
        assert_eq!(loaded.headers, entry.headers);
        assert_eq!(loaded.policy, entry.policy);
        assert_eq!(loaded.vary, entry.vary);
        // A fresh process has no in-memory entry; lookup must load the disk
        // metadata/body pair and serve it as a hit.
        let request = crate::http::Request {
            method: "GET".into(),
            target: b"/path".to_vec(),
            raw_path: b"/path".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        let scope = Scope::default();
        let peer = "127.0.0.1".parse().unwrap();
        let target = std::path::Path::new("/srv/path");
        let fingerprint = cache_policy_fingerprint(&scope, &request, peer, target);
        let entry = Entry {
            policy: fingerprint,
            vary: Vec::new(),
            ..entry
        };
        let key = base_key(
            &cfg,
            None,
            "127.0.0.1",
            80,
            false,
            "warm.test",
            "/path",
            "/path",
            b"",
            target,
            fingerprint,
        );
        let memory_key = format!("{key}memory");
        disk_store(&cfg, &memory_key, &entry);
        cfg.cache.max_memory_size = 1024 * 1024;
        let memory_hit = lookup(
            &cfg,
            None,
            &request,
            "warm.test",
            "/path",
            &scope,
            peer,
            &crate::access::test_grant(),
            &memory_key,
            target,
        )
        .expect("warm memory-admitted hit");
        assert!(matches!(memory_hit.body, crate::http::Body::Bytes(_)));
        assert!(entries()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .entries
            .contains_key(&memory_key));

        disk_store(&cfg, &key, &entry);
        // A disk-only configuration must still serve small warm entries; it
        // simply declines to retain the decoded body in the memory cache.
        cfg.cache.max_memory_size = 0;
        let hit = lookup(
            &cfg,
            None,
            &request,
            "warm.test",
            "/path",
            &scope,
            peer,
            &crate::access::test_grant(),
            &key,
            target,
        )
        .expect("warm hit");
        match hit.body {
            crate::http::Body::Bytes(body) => assert_eq!(body, b"hello"),
            _ => panic!("expected cached bytes"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn large_cache_hit_is_served_from_the_disk_body_file() {
        let (dir, cfg) = disk_test_config("file-body");
        let request = test_request();
        let peer = "127.0.0.1".parse().unwrap();
        let scope = Scope::default();
        let target = std::path::Path::new("/srv/large.bin");
        let mut entry = disk_entry(&vec![b'z'; 128 * 1024], unix_now() + 60);
        entry.policy = cache_policy_fingerprint(&scope, &request, peer, target);
        let key = "host\n/large.bin\n";
        disk_store(&cfg, key, &entry);
        let hit = lookup(
            &cfg,
            None,
            &request,
            "localhost",
            "/large.bin",
            &scope,
            peer,
            &crate::access::test_grant(),
            key,
            target,
        )
        .expect("large cache hit");
        match hit.body {
            Body::File { len, .. } => assert_eq!(len, 128 * 1024),
            _ => panic!("large cached body should use the file-body path"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disk_entries_from_an_older_generation_are_not_served() {
        let dir = std::env::temp_dir().join(format!("vapache-cache-epoch-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(&conf, "Listen 127.0.0.1:0\n").unwrap();
        let mut cfg = crate::config::Config::load(
            &conf,
            &dir,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap();
        cfg.cache.root = Some(dir.join("cache"));
        let entry = Entry {
            status: 200,
            headers: vec![("content-type".into(), b"text/plain".to_vec())],
            body: b"stale".to_vec(),
            body_len: 5,
            stored: unix_now(),
            expires: unix_now() + 60,
            policy: [7u8; 32],
            epoch: current_epoch().saturating_sub(1),
            vary: Vec::new(),
            _resident: None,
        };
        disk_store(&cfg, "old\n/path\n", &entry);
        assert!(disk_load(&cfg, "old\n/path\n").is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_info_cache_target_is_the_actual_script() {
        let dir =
            std::env::temp_dir().join(format!("vapache-cache-pathinfo-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let cgi = dir.join("www").join("cgi");
        fs::create_dir_all(&cgi).unwrap();
        fs::write(cgi.join("wallet.cgi"), "#!/bin/sh\nexit 0\n").unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(
            &conf,
            format!(
                "{}Listen 127.0.0.1:0\n\
DocumentRoot \"{www}\"\n\
CacheRoot \"{cache}\"\n\
CacheEnable disk /\n\
CacheDefaultExpire 60\n\
AddHandler cgi-script .cgi\n\
<Directory \"{www}\">\n\
    Options +ExecCGI\n\
    Require all granted\n\
</Directory>\n",
                crate::config::TEST_CAPABILITIES,
                www = dir.join("www").display(),
                cache = dir.join("cache").display(),
            ),
        )
        .unwrap();
        let cfg = crate::config::Config::load(
            &conf,
            &dir,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap();
        let request = crate::http::Request {
            method: "GET".into(),
            target: b"/cgi/wallet.cgi/foo".to_vec(),
            raw_path: b"/cgi/wallet.cgi/foo".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        let ctx = request_scope(
            &cfg,
            None,
            &request,
            "127.0.0.1".parse().unwrap(),
            "/cgi/wallet.cgi/foo",
            80,
            false,
            "localhost",
            "localhost",
            "127.0.0.1",
        )
        .expect("path-info cache scope");
        assert_eq!(ctx.target, cgi.join("wallet.cgi"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_scope_never_caches_proxy_routes() {
        let dir = std::env::temp_dir().join(format!("vapache-cache-proxy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(dir.join("cache")).unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(
            &conf,
            format!(
                "Listen 127.0.0.1:0\nCacheRoot {}\nCacheEnable /\nProxyPass /app http://127.0.0.1:9000/\n",
                dir.join("cache").display()
            ),
        )
        .unwrap();
        let cfg = crate::config::Config::load(
            &conf,
            &dir,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap();
        let req = crate::http::Request {
            method: "GET".into(),
            target: b"/app/x".to_vec(),
            raw_path: b"/app/x".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        let scope = request_scope(
            &cfg,
            None,
            &req,
            "127.0.0.1".parse().unwrap(),
            "/app/x",
            80,
            false,
            "localhost",
            "localhost",
            "127.0.0.1",
        );
        assert!(scope.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_policy_fingerprint_binds_header_driven_policy_inputs() {
        let dir = std::env::temp_dir().join(format!("vapache-cache-fp-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(&conf, "Listen 127.0.0.1:0\n").unwrap();
        let cfg = crate::config::Config::load(
            &conf,
            &dir,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap();
        let scope = Scope::default();
        let peer = "127.0.0.1".parse().unwrap();
        let target = std::path::Path::new("/srv/tenant.txt");
        let request = |tenant: &str| {
            let mut headers = crate::http::Headers::default();
            headers.insert("x-tenant", tenant.as_bytes().to_vec());
            crate::http::Request {
                method: "GET".into(),
                target: b"/tenant.txt".to_vec(),
                raw_path: b"/tenant.txt".to_vec(),
                query: Vec::new(),
                version: crate::http::Version::Http11,
                headers,
                body: Vec::new(),
                body_spool: None,
                keep_alive: true,
                expect_continue: false,
                framing: crate::verified::BodyFraming::None,
            }
        };
        let alpha = cache_policy_fingerprint(&scope, &request("alpha"), peer, target);
        let beta = cache_policy_fingerprint(&scope, &request("beta"), peer, target);
        assert_ne!(alpha, beta, "tenant header must partition the cache");
        let _ = cfg;
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_policy_fingerprint_binds_every_policy_field() {
        let request = test_request();
        let peer = "127.0.0.1".parse().unwrap();
        let target = std::path::Path::new("/srv/x");
        let fingerprint = |scope: &Scope| cache_policy_fingerprint(scope, &request, peer, target);
        let baseline = fingerprint(&Scope::default());

        let cases: Vec<(&str, fn(&mut Scope))> =
            vec![
                ("options.changes", |s| s.options.push_add(1)),
                ("override.mode", |s| {
                    s.override_policy.set_mode(crate::config::OverrideMode::All)
                }),
                ("override.allow_list", |s| {
                    s.override_policy.set_allow_list(vec!["Require".into()])
                }),
                ("override.nonfatal", |s| {
                    s.override_policy
                        .set_nonfatal(crate::config::NonfatalMode::All)
                }),
                ("authorization.requires", |s| {
                    s.authorization.add_require(
                        crate::config::RequireNode::Provider(crate::config::Require::AllGranted),
                        None,
                    )
                }),
                ("authorization.auth_merging", |s| {
                    s.authorization.auth_merging = Some(crate::config::AuthMerging::And)
                }),
                ("authorization.allow_methods", |s| {
                    s.authorization.allow_methods = Some(crate::config::AllowMethods::Reset)
                }),
                ("authorization.legacy", |s| {
                    s.authorization.legacy = Some(crate::config::LegacyAccess::default())
                }),
                ("authorization.auth_type", |s| {
                    s.authorization.auth_type = Some("basic".into())
                }),
                ("authorization.auth_name", |s| {
                    s.authorization.auth_name = Some("realm".into())
                }),
                ("authorization.auth_user_file", |s| {
                    s.authorization.auth_user_file = Some("/tmp/users".into())
                }),
                ("authorization.auth_group_file", |s| {
                    s.authorization.auth_group_file = Some("/tmp/groups".into())
                }),
                ("header.add_headers", |s| {
                    s.header_policy.add_headers.push(("X-A".into(), "1".into()))
                }),
                ("header.set_headers", |s| {
                    s.header_policy.set_headers.push(("X-A".into(), "1".into()))
                }),
                ("header.unset_headers", |s| {
                    s.header_policy.unset_headers.push("X-A".into())
                }),
                ("header.always_add_headers", |s| {
                    s.header_policy
                        .always_add_headers
                        .push(("X-A".into(), "1".into()))
                }),
                ("header.always_set_headers", |s| {
                    s.header_policy
                        .always_set_headers
                        .push(("X-A".into(), "1".into()))
                }),
                ("header.always_unset_headers", |s| {
                    s.header_policy.always_unset_headers.push("X-A".into())
                }),
                ("header.expires_active", |s| {
                    s.header_policy.expires_active = Some(true)
                }),
                ("header.expires_default", |s| {
                    s.header_policy.expires_default = Some("access plus 1 hour".into())
                }),
                ("header.expires_by_type", |s| {
                    s.header_policy
                        .expires_by_type
                        .push(("text/html".into(), "access plus 1 hour".into()))
                }),
                ("header.cookies", |s| {
                    s.header_policy.cookies.push("session".into())
                }),
                ("header.vary", |s| {
                    s.header_policy.vary.push("Accept".into())
                }),
                ("content.document_root", |s| {
                    s.content_policy.document_root = Some("/srv".into())
                }),
                ("content.directory_index", |s| {
                    s.content_policy.directory_index = Some(vec!["index.html".into()])
                }),
                ("content.index_ignore", |s| {
                    s.content_policy.index_ignore.push("*.secret".into())
                }),
                ("content.default_charset", |s| {
                    s.content_policy.default_charset = Some("utf-8".into())
                }),
                ("content.file_etag", |s| {
                    s.content_policy.file_etag = Some(1)
                }),
                ("content.enable_sendfile", |s| {
                    s.content_policy.enable_sendfile = Some(true)
                }),
                ("content.directory_slash", |s| {
                    s.content_policy.directory_slash = Some(false)
                }),
                ("content.add_types", |s| {
                    s.content_policy
                        .add_types
                        .push(("text/plain".into(), ".txt".into()))
                }),
                ("content.remove_types", |s| {
                    s.content_policy.remove_types.push(".txt".into())
                }),
                ("content.force_type", |s| {
                    s.content_policy.force_type = Some("text/plain".into())
                }),
                ("content.access_file_names", |s| {
                    s.content_policy.access_file_names = Some(vec![".htaccess".into()])
                }),
                ("mapping.aliases", |s| {
                    s.mapping_policy.aliases.push(crate::config::Alias::prefix(
                        "/x".into(),
                        "/srv/x".into(),
                        false,
                    ))
                }),
                ("mapping.redirects", |s| {
                    s.mapping_policy.redirects.push(crate::config::Redirect {
                        from: "/x".into(),
                        to: "/y".into(),
                        status: 302,
                        regex: None,
                    })
                }),
                ("mapping.handlers", |s| {
                    s.mapping_policy
                        .handlers
                        .push(crate::config::Handler::add(".x".into(), "handler".into()))
                }),
                ("mapping.unsupported_filters", |s| {
                    s.mapping_policy.unsupported_filters.push("INCLUDES".into())
                }),
                ("error.documents", |s| {
                    s.error_policy
                        .push(404, crate::config::ErrorDoc::Text("missing".into()))
                }),
                ("environment.set_env", |s| {
                    s.environment_policy
                        .set_env
                        .push(crate::scope_policy::Originated::main((
                            "A".into(),
                            "1".into(),
                        )))
                }),
                ("environment.rewrite_env", |s| {
                    s.environment_policy
                        .rewrite_env
                        .push(crate::scope_policy::Originated::main((
                            "EARLY".into(),
                            b"1".to_vec(),
                        )))
                }),
                ("environment.rewrite_unset_env", |s| {
                    s.environment_policy
                        .rewrite_unset_env
                        .push(crate::scope_policy::Originated::main("EARLY".into()))
                }),
                ("environment.rewrite_late_env", |s| {
                    s.environment_policy.rewrite_late_env.push(
                        crate::scope_policy::Originated::main(("LATE".into(), b"1".to_vec())),
                    )
                }),
                ("environment.rewrite_late_unset_env", |s| {
                    s.environment_policy
                        .rewrite_late_unset_env
                        .push(crate::scope_policy::Originated::main("LATE".into()))
                }),
                ("environment.access_rewrite_env", |s| {
                    s.environment_policy.rewrite_late_env.push(
                        crate::scope_policy::Originated::access(("ACCESS".into(), b"1".to_vec())),
                    )
                }),
                ("environment.access_rewrite_unset_env", |s| {
                    s.environment_policy
                        .rewrite_late_unset_env
                        .push(crate::scope_policy::Originated::access("ACCESS".into()))
                }),
                ("environment.unset_env", |s| {
                    s.environment_policy
                        .unset_env
                        .push(crate::scope_policy::Originated::main("A".into()))
                }),
                ("environment.pass_env", |s| {
                    s.environment_policy
                        .pass_env
                        .push(crate::scope_policy::Originated::main("PATH".into()))
                }),
                ("environment.set_env_if", |s| {
                    s.environment_policy
                        .set_env_if
                        .push(crate::scope_policy::Originated::main(
                            crate::config::parse_env_rule(
                                "SetEnvIf",
                                &["X-Test".into(), "yes".into(), "A=1".into()],
                            )
                            .unwrap(),
                        ))
                }),
                ("environment.access_set_env", |s| {
                    s.environment_policy
                        .set_env
                        .push(crate::scope_policy::Originated::access((
                            "A".into(),
                            "1".into(),
                        )))
                }),
                ("environment.access_unset_env", |s| {
                    s.environment_policy
                        .unset_env
                        .push(crate::scope_policy::Originated::access("A".into()))
                }),
                ("environment.access_pass_env", |s| {
                    s.environment_policy
                        .pass_env
                        .push(crate::scope_policy::Originated::access("PATH".into()))
                }),
                ("environment.access_set_env_if", |s| {
                    s.environment_policy
                        .set_env_if
                        .push(crate::scope_policy::Originated::access(
                            crate::config::parse_env_rule(
                                "SetEnvIf",
                                &["X-Test".into(), "yes".into(), "A=1".into()],
                            )
                            .unwrap(),
                        ))
                }),
                ("rewrite.engine", |s| {
                    s.rewrite_policy.rewrite_engine = Some(true)
                }),
                ("rewrite.maps", |s| {
                    s.rewrite_policy.rewrite_maps.push((
                        "m".into(),
                        crate::config::RewriteMap::Txt(std::collections::HashMap::from([(
                            "a".into(),
                            "b".into(),
                        )])),
                    ))
                }),
                ("rewrite.cache_enable", |s| {
                    s.rewrite_policy
                        .cache_enable
                        .push(("/".into(), "disk".into()))
                }),
                ("rewrite.cache_disable", |s| {
                    s.rewrite_policy.cache_disable.push("/private".into())
                }),
                ("rewrite.inherit", |s| {
                    s.rewrite_policy.rewrite_inherit = Some(true)
                }),
                ("rewrite.base", |s| {
                    s.rewrite_policy.rewrite_base = Some("/base/".into())
                }),
                ("rewrite.match_base", |s| {
                    s.rewrite_policy.rewrite_match_base = Some("/match/".into())
                }),
                ("rewrite.rules", |s| {
                    s.rewrite_policy.rewrite_rules.push(
                        crate::config::parse_rewrite_rule(
                            &["^/x$".into(), "/y".into(), "[L]".into()],
                            "/",
                            false,
                        )
                        .unwrap(),
                    )
                }),
                ("rewrite.pending_conds", |s| {
                    s.rewrite_policy.pending_rewrite_conds.push(
                        crate::config::parse_rewrite_cond(&[
                            "%{REQUEST_URI}".into(),
                            "^/x$".into(),
                        ])
                        .unwrap(),
                    )
                }),
                ("compression.rules", |s| {
                    s.compression_policy.compression_rules.push(
                        crate::config::CompressionRule::Set(vec![
                            crate::config::CompressionKind::Gzip,
                        ]),
                    )
                }),
                ("compression.deflate_level", |s| {
                    s.compression_policy.deflate_level = Some(6)
                }),
                ("compression.brotli_quality", |s| {
                    s.compression_policy.brotli_quality = Some(5)
                }),
                ("compression.deflate_alter_etag", |s| {
                    s.compression_policy.deflate_alter_etag =
                        Some(crate::config::AlterEtag::AddSuffix)
                }),
                ("compression.brotli_alter_etag", |s| {
                    s.compression_policy.brotli_alter_etag = Some(crate::config::AlterEtag::Remove)
                }),
                ("proxy.rules", |s| {
                    s.proxy_policy.proxy_rules.push(crate::config::ProxyRule {
                        pattern: std::sync::Arc::new(regex::bytes::Regex::new("^/x$").unwrap()),
                        backend: "http://127.0.0.1:9000/".into(),
                        route_order: 0,
                    })
                }),
                ("proxy.passes", |s| {
                    s.proxy_policy
                        .proxy_passes
                        .push(crate::config::ProxyPassRule {
                            prefix: "/x".into(),
                            backend: "http://127.0.0.1:9000/".into(),
                            sticky_cookie: None,
                            fail_on_status: Vec::new(),
                            route_order: 0,
                        })
                }),
                ("proxy.reverses", |s| {
                    s.proxy_policy
                        .proxy_reverses
                        .push(crate::config::ProxyReverseRule {
                            front: "/x".into(),
                            backend: "http://127.0.0.1:9000/".into(),
                        })
                }),
                ("proxy.ca_file", |s| {
                    s.proxy_policy.proxy_ca_file = Some("/tmp/ca.pem".into())
                }),
            ];

        for (name, mutate) in cases {
            let mut scope = Scope::default();
            mutate(&mut scope);
            assert_ne!(
                baseline,
                fingerprint(&scope),
                "cache fingerprint does not bind policy field {name}"
            );
        }
    }

    #[test]
    fn cache_policy_material_is_stable_for_rewrite_map_order() {
        let request = test_request();
        let peer = "127.0.0.1".parse().unwrap();
        let target = std::path::Path::new("/srv/x");
        let scope_with = |entries: [(&str, &str); 2]| {
            let mut scope = Scope::default();
            scope.rewrite_policy.rewrite_maps.push((
                "m".into(),
                crate::config::RewriteMap::Txt(
                    entries
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                ),
            ));
            scope
        };
        let a = scope_with([("a", "1"), ("b", "2")]);
        let b = scope_with([("b", "2"), ("a", "1")]);
        assert_eq!(
            cache_policy_fingerprint(&a, &request, peer, target),
            cache_policy_fingerprint(&b, &request, peer, target),
            "rewrite map iteration order must not change the cache fingerprint"
        );
    }

    #[test]
    fn cache_key_binds_every_request_and_listener_input() {
        let dir = std::env::temp_dir().join(format!("vapache-cache-key-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(
            &conf,
            format!(
                "Listen 127.0.0.1:8080\n\
                 ServerName localhost\n\
                 DocumentRoot \"{www}\"\n\
                 <VirtualHost *:8080>\n\
                     ServerName vhost.test\n\
                     DocumentRoot \"{www}\"\n\
                 </VirtualHost>\n",
                www = dir.display()
            ),
        )
        .unwrap();
        let mut cfg = crate::config::Config::load(
            &conf,
            &dir,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap();
        let target = std::path::Path::new("/srv/x");
        let key = |cfg: &Config,
                   vhost: Option<&VHost>,
                   local_ip: &str,
                   local_port: u16,
                   https: bool,
                   host: &str,
                   path: &str,
                   query: &[u8],
                   target: &std::path::Path,
                   fingerprint: PolicyFingerprint| {
            base_key(
                cfg,
                vhost,
                local_ip,
                local_port,
                https,
                host,
                path,
                path,
                query,
                target,
                fingerprint,
            )
        };
        let baseline = key(
            &cfg,
            None,
            "127.0.0.1",
            8080,
            false,
            "example.test",
            "/x",
            b"",
            target,
            [7u8; 32],
        );
        let variants = [
            key(
                &cfg,
                None,
                "127.0.0.2",
                8080,
                false,
                "example.test",
                "/x",
                b"",
                target,
                [7u8; 32],
            ),
            key(
                &cfg,
                None,
                "127.0.0.1",
                8081,
                false,
                "example.test",
                "/x",
                b"",
                target,
                [7u8; 32],
            ),
            key(
                &cfg,
                None,
                "127.0.0.1",
                8080,
                true,
                "example.test",
                "/x",
                b"",
                target,
                [7u8; 32],
            ),
            key(
                &cfg,
                None,
                "127.0.0.1",
                8080,
                false,
                "other.test",
                "/x",
                b"",
                target,
                [7u8; 32],
            ),
            key(
                &cfg,
                None,
                "127.0.0.1",
                8080,
                false,
                "example.test",
                "/y",
                b"",
                target,
                [7u8; 32],
            ),
            key(
                &cfg,
                None,
                "127.0.0.1",
                8080,
                false,
                "example.test",
                "/x",
                b"a=1",
                target,
                [7u8; 32],
            ),
            key(
                &cfg,
                None,
                "127.0.0.1",
                8080,
                false,
                "example.test",
                "/x",
                b"",
                std::path::Path::new("/srv/y"),
                [7u8; 32],
            ),
            key(
                &cfg,
                None,
                "127.0.0.1",
                8080,
                false,
                "example.test",
                "/x",
                b"",
                target,
                [8u8; 32],
            ),
        ];
        for (index, variant) in variants.iter().enumerate() {
            assert_ne!(baseline, *variant, "cache key input {index} is not bound");
        }
        assert_ne!(
            baseline,
            base_key(
                &cfg,
                None,
                "127.0.0.1",
                8080,
                false,
                "example.test",
                "/x",
                "/x/index.html",
                b"",
                target,
                [7u8; 32],
            ),
            "selected representation path is not independently bound"
        );

        let original_root = cfg.server_root.clone();
        cfg.server_root = dir.join("other-root");
        assert_ne!(
            baseline,
            key(
                &cfg,
                None,
                "127.0.0.1",
                8080,
                false,
                "example.test",
                "/x",
                b"",
                target,
                [7u8; 32]
            ),
            "server root is not bound"
        );
        cfg.server_root = original_root;

        let vhost = cfg.vhosts.first().expect("configured vhost");
        assert_ne!(
            baseline,
            key(
                &cfg,
                Some(vhost),
                "127.0.0.1",
                8080,
                false,
                "example.test",
                "/x",
                b"",
                target,
                [7u8; 32]
            ),
            "vhost identity is not bound"
        );

        let request = test_request();
        let peer = "127.0.0.1".parse().unwrap();
        let fingerprint = |req: &crate::http::Request, peer: IpAddr, target: &std::path::Path| {
            cache_policy_fingerprint(&Scope::default(), req, peer, target)
        };
        let baseline_fp = fingerprint(&request, peer, target);
        let mut other = test_request();
        other.method = "HEAD".into();
        assert_ne!(baseline_fp, fingerprint(&other, peer, target), "method");
        other = test_request();
        other
            .headers
            .insert("x-tenant", "alpha".as_bytes().to_vec());
        assert_ne!(baseline_fp, fingerprint(&other, peer, target), "header");
        assert_ne!(
            baseline_fp,
            fingerprint(&request, "127.0.0.2".parse().unwrap(), target),
            "peer"
        );
        assert_ne!(
            baseline_fp,
            fingerprint(&request, peer, std::path::Path::new("/srv/y")),
            "resolved target"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_key_includes_policy_fingerprint() {
        let a = format!("{}\nhost\n/path\n\n{}", "/srv", key_component(&[0u8; 32]));
        let b = format!("{}\nhost\n/path\n\n{}", "/srv", key_component(&[1u8; 32]));
        assert_ne!(a, b);
        // Credentials must never be persisted as cache metadata.
        assert!(CACHE_PRIVATE_HEADERS.contains(&"authorization"));
        assert!(crate::http::ResponseHeaderSanitizer::new().is_hop_by_hop("proxy-authorization"));
    }

    #[test]
    fn ignore_query_string_never_shares_dynamic_cgi_representations() {
        let dir =
            std::env::temp_dir().join(format!("vapache-cache-ignore-query-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let cgi = dir.join("www").join("cgi");
        fs::create_dir_all(&cgi).unwrap();
        fs::write(cgi.join("wallet.cgi"), "#!/bin/sh\nexit 0\n").unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(
            &conf,
            format!(
                "{}Listen 127.0.0.1:0\n\
DocumentRoot \"{www}\"\n\
CacheRoot \"{cache}\"\n\
CacheEnable disk /\n\
CacheIgnoreQueryString On\n\
CacheDefaultExpire 60\n\
AddHandler cgi-script .cgi\n\
<Directory \"{www}\">\n\
    Options +ExecCGI\n\
    Require all granted\n\
</Directory>\n",
                crate::config::TEST_CAPABILITIES,
                www = dir.join("www").display(),
                cache = dir.join("cache").display(),
            ),
        )
        .unwrap();
        let cfg = crate::config::Config::load(
            &conf,
            &dir,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap();
        let request = crate::http::Request {
            method: "GET".into(),
            target: b"/cgi/wallet.cgi?nonce=1".to_vec(),
            raw_path: b"/cgi/wallet.cgi".to_vec(),
            query: b"nonce=1".to_vec(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        assert!(request_scope(
            &cfg,
            None,
            &request,
            "127.0.0.1".parse().unwrap(),
            "/cgi/wallet.cgi",
            80,
            false,
            "localhost",
            "localhost",
            "127.0.0.1",
        )
        .is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_key_is_injective_over_raw_bytes() {
        let dir =
            std::env::temp_dir().join(format!("vapache-cache-key-bytes-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(&conf, "Listen 127.0.0.1:0\n").unwrap();
        let cfg = crate::config::Config::load(
            &conf,
            &dir,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap();
        let key = |query: &[u8], target: &std::path::Path| {
            base_key(
                &cfg,
                None,
                "127.0.0.1",
                80,
                false,
                "example.test",
                "/index.php",
                "/index.php",
                query,
                target,
                [7u8; 32],
            )
        };
        let target = std::path::Path::new("/srv/index.php");
        assert_ne!(key(b"", target), key(b"\xff", target));
        assert_ne!(key(b"?a=\xff", target), key(b"?a=\xfe", target));
        // The UTF-8 replacement bytes of a lossy conversion must not share a
        // key with the raw invalid byte (F55/I51).
        assert_ne!(key(b"\xff", target), key(b"\xef\xbf\xbd", target));
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let invalid_target = std::path::Path::new(OsStr::from_bytes(b"/srv/\xff"));
        assert_ne!(key(b"", target), key(b"", invalid_target));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_rejects_non_utf8_paths() {
        let dir = std::env::temp_dir().join(format!(
            "vapache-cache-non-utf8-path-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let www = dir.join("www");
        fs::create_dir_all(&www).unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(
            &conf,
            format!(
                "Listen 127.0.0.1:0\n\
DocumentRoot \"{www}\"\n\
CacheRoot \"{cache}\"\n\
CacheEnable disk /\n\
<Directory \"{www}\">\n\
    Require all granted\n\
</Directory>\n",
                www = www.display(),
                cache = dir.join("cache").display(),
            ),
        )
        .unwrap();
        let cfg = crate::config::Config::load(
            &conf,
            &dir,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap();
        let request = crate::http::Request {
            method: "GET".into(),
            target: b"/\xff".to_vec(),
            raw_path: b"/\xff".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        assert!(request_scope(
            &cfg,
            None,
            &request,
            "127.0.0.1".parse().unwrap(),
            "/\u{fffd}",
            80,
            false,
            "localhost",
            "localhost",
            "127.0.0.1",
        )
        .is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ignore_query_string_bypasses_set_handler_and_server_status() {
        for handler in ["proxy:unix:/nonexistent|fcgi://localhost", "server-status"] {
            let dir = std::env::temp_dir().join(format!(
                "vapache-cache-handler-{}-{}",
                handler.contains("server-status") as u8,
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            let www = dir.join("www");
            fs::create_dir_all(&www).unwrap();
            fs::write(www.join("direct.php"), "not executed\n").unwrap();
            let conf = dir.join("httpd.conf");
            fs::write(
                &conf,
                format!(
                    "{}Listen 127.0.0.1:0\n\
DocumentRoot \"{www}\"\n\
CacheRoot \"{cache}\"\n\
CacheEnable disk /\n\
CacheIgnoreQueryString On\n\
<FilesMatch \"\\.php$\">\n\
    SetHandler \"{handler}\"\n\
</FilesMatch>\n\
<Directory \"{www}\">\n\
    Require all granted\n\
</Directory>\n",
                    crate::config::TEST_CAPABILITIES,
                    www = www.display(),
                    cache = dir.join("cache").display(),
                ),
            )
            .unwrap();
            let cfg = crate::config::Config::load(
                &conf,
                &dir,
                &Default::default(),
                &Default::default(),
                false,
            )
            .unwrap();
            let request = crate::http::Request {
                method: "GET".into(),
                target: b"/direct.php?token=alpha".to_vec(),
                raw_path: b"/direct.php".to_vec(),
                query: b"token=alpha".to_vec(),
                version: crate::http::Version::Http11,
                headers: crate::http::Headers::default(),
                body: Vec::new(),
                body_spool: None,
                keep_alive: true,
                expect_continue: false,
                framing: crate::verified::BodyFraming::None,
            };
            assert!(
                request_scope(
                    &cfg,
                    None,
                    &request,
                    "127.0.0.1".parse().unwrap(),
                    "/direct.php",
                    80,
                    false,
                    "localhost",
                    "localhost",
                    "127.0.0.1",
                )
                .is_none(),
                "dynamic handler {handler} was treated as static"
            );
            let _ = fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn local_error_document_is_never_cache_scoped() {
        let dir = std::env::temp_dir().join(format!(
            "vapache-cache-error-document-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let www = dir.join("www");
        fs::create_dir_all(&www).unwrap();
        fs::write(www.join("404.html"), "missing\n").unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(
            &conf,
            format!(
                "{}Listen 127.0.0.1:0\n\
DocumentRoot \"{www}\"\n\
CacheRoot \"{cache}\"\n\
CacheEnable disk /\n\
ErrorDocument 404 /404.html\n\
<Directory \"{www}\">\n\
    Require all granted\n\
</Directory>\n",
                crate::config::TEST_CAPABILITIES,
                www = www.display(),
                cache = dir.join("cache").display(),
            ),
        )
        .unwrap();
        let cfg = crate::config::Config::load(
            &conf,
            &dir,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap();
        let request = crate::http::Request {
            method: "GET".into(),
            target: b"/missing".to_vec(),
            raw_path: b"/missing".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        assert!(request_scope(
            &cfg,
            None,
            &request,
            "127.0.0.1".parse().unwrap(),
            "/missing",
            80,
            false,
            "localhost",
            "localhost",
            "127.0.0.1",
        )
        .is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn directory_index_binds_cache_target_and_live_policy() {
        let dir =
            std::env::temp_dir().join(format!("vapache-cache-dir-index-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let www = dir.join("www");
        fs::create_dir_all(www.join("dir")).unwrap();
        fs::write(www.join("dir/index.html"), "index\n").unwrap();
        fs::write(www.join("dir/.htaccess"), "# no deny\n").unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(
            &conf,
            format!(
                "{}Listen 127.0.0.1:0\n\
DocumentRoot \"{www}\"\n\
CacheRoot \"{cache}\"\n\
CacheEnable disk /\n\
DirectoryIndex index.html\n\
<Directory \"{www}\">\n\
    AllowOverride All\n\
    Require all granted\n\
</Directory>\n",
                crate::config::TEST_CAPABILITIES,
                www = www.display(),
                cache = dir.join("cache").display(),
            ),
        )
        .unwrap();
        let cfg = crate::config::Config::load(
            &conf,
            &dir,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap();
        let request = crate::http::Request {
            method: "GET".into(),
            target: b"/dir/".to_vec(),
            raw_path: b"/dir/".to_vec(),
            query: Vec::new(),
            version: crate::http::Version::Http11,
            headers: crate::http::Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        };
        let ctx = request_scope(
            &cfg,
            None,
            &request,
            "127.0.0.1".parse().unwrap(),
            "/dir/",
            80,
            false,
            "localhost",
            "localhost",
            "127.0.0.1",
        )
        .expect("directory index cache scope");
        assert_eq!(ctx.target, www.join("dir/index.html"));
        assert_eq!(ctx.path, "/dir/index.html");

        fs::write(
            www.join("dir/.htaccess"),
            "<Files \"index.html\">\n    Require all denied\n</Files>\n",
        )
        .unwrap();
        assert!(request_scope(
            &cfg,
            None,
            &request,
            "127.0.0.1".parse().unwrap(),
            "/dir/",
            80,
            false,
            "localhost",
            "localhost",
            "127.0.0.1",
        )
        .is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn request_scope_covers_symlink_directory_disable_method_and_dynamic_routes() {
        let dir =
            std::env::temp_dir().join(format!("vapache-cache-scope-matrix-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let www = dir.join("www");
        fs::create_dir_all(www.join("empty")).unwrap();
        fs::create_dir_all(www.join("disabled")).unwrap();
        fs::create_dir_all(www.join("method")).unwrap();
        fs::write(www.join("real.txt"), b"real").unwrap();
        fs::write(www.join("disabled/file.txt"), b"disabled").unwrap();
        fs::write(www.join("method/file.txt"), b"method").unwrap();
        std::os::unix::fs::symlink("real.txt", www.join("alias.txt")).unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(
            &conf,
            format!(
                "Listen 127.0.0.1:0\n\
DocumentRoot \"{www}\"\n\
CacheRoot \"{cache}\"\n\
CacheEnable disk /\n\
CacheDisable /disabled\n\
<Directory \"{www}\">\n\
    Require all granted\n\
    Options -FollowSymLinks +SymLinksIfOwnerMatch\n\
</Directory>\n\
<Directory \"{www}/method\">\n\
    AllowMethods POST\n\
</Directory>\n",
                www = www.display(),
                cache = dir.join("cache").display(),
            ),
        )
        .unwrap();
        let cfg =
            Config::load(&conf, &dir, &Default::default(), &Default::default(), false).unwrap();
        let call = |path: &str| {
            let mut req = test_request();
            req.target = path.as_bytes().to_vec();
            req.raw_path = path.as_bytes().to_vec();
            request_scope(
                &cfg,
                None,
                &req,
                "127.0.0.1".parse().unwrap(),
                path,
                80,
                false,
                "localhost",
                "localhost",
                "127.0.0.1",
            )
        };
        let symlink = call("/alias.txt").expect("same-owner symlink is cacheable");
        assert_eq!(
            symlink.target,
            fs::canonicalize(www.join("real.txt")).unwrap()
        );
        // Cache admission must consume the same owner-match policy as live
        // dispatch.  Otherwise a representation populated while the link was
        // admissible could remain reachable after the link owner changed.
        if crate::files::effective_uid() == 0 {
            let link = www.join("alias.txt");
            rustix::fs::chownat(
                rustix::fs::CWD,
                &link,
                Some(rustix::fs::Uid::from_raw(1)),
                None,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .unwrap();
            assert!(call("/alias.txt").is_none());
        }
        assert!(call("/empty/").is_some());
        assert!(call("/disabled/file.txt").is_none());
        assert!(call("/method/file.txt").is_none());

        let route_config = |name: &str, extra: &str| {
            let conf = dir.join(format!("{name}.conf"));
            fs::write(
                &conf,
                format!(
                    "{}Listen 127.0.0.1:0\n\
DocumentRoot \"{www}\"\n\
CacheRoot \"{cache}\"\n\
CacheEnable disk /\n\
CacheIgnoreQueryString On\n\
<Directory \"{www}\">\nRequire all granted\n</Directory>\n{extra}\n",
                    crate::config::TEST_CAPABILITIES,
                    www = www.display(),
                    cache = dir.join("cache").display(),
                ),
            )
            .unwrap();
            Config::load(&conf, &dir, &Default::default(), &Default::default(), false).unwrap()
        };
        fs::create_dir_all(www.join("fcgi")).unwrap();
        fs::write(www.join("fcgi/test.php"), b"php").unwrap();
        let fastcgi_rule = format!(
            "ProxyPassMatch ^/fcgi/(.*\\.php)$ \"unix:/tmp/vapache-cache-missing.sock|fcgi://localhost{}/\"",
            www.display()
        );
        let fastcgi_cfg = route_config("fastcgi", &fastcgi_rule);
        let mut dynamic = test_request();
        dynamic.target = b"/fcgi/test.php?a=1".to_vec();
        dynamic.raw_path = b"/fcgi/test.php".to_vec();
        dynamic.query = b"a=1".to_vec();
        assert!(request_scope(
            &fastcgi_cfg,
            None,
            &dynamic,
            "127.0.0.1".parse().unwrap(),
            "/fcgi/test.php",
            80,
            false,
            "localhost",
            "localhost",
            "127.0.0.1",
        )
        .is_none());

        let proxy_cfg = route_config("proxy", "ProxyPass /proxy http://127.0.0.1:9000/");
        dynamic.target = b"/proxy/item?a=1".to_vec();
        dynamic.raw_path = b"/proxy/item".to_vec();
        assert!(request_scope(
            &proxy_cfg,
            None,
            &dynamic,
            "127.0.0.1".parse().unwrap(),
            "/proxy/item",
            80,
            false,
            "localhost",
            "localhost",
            "127.0.0.1",
        )
        .is_none());

        let static_cfg = route_config("static-query", "");
        fs::write(www.join("static.txt"), b"static").unwrap();
        let mut static_query = test_request();
        static_query.target = b"/static.txt?a=1".to_vec();
        static_query.raw_path = b"/static.txt".to_vec();
        static_query.query = b"a=1".to_vec();
        assert!(request_scope(
            &static_cfg,
            None,
            &static_query,
            "127.0.0.1".parse().unwrap(),
            "/static.txt",
            80,
            false,
            "localhost",
            "localhost",
            "127.0.0.1",
        )
        .is_some());
        assert!(static_query
            .charge_policy_work(crate::resource::MAX_POLICY_WORK_UNITS)
            .is_err());
        assert!(request_scope(
            &static_cfg,
            None,
            &static_query,
            "127.0.0.1".parse().unwrap(),
            "/static.txt",
            80,
            false,
            "localhost",
            "localhost",
            "127.0.0.1",
        )
        .is_none());
        dynamic.query.clear();
        dynamic.target = b"/proxy/item".to_vec();
        assert!(request_scope(
            &proxy_cfg,
            None,
            &dynamic,
            "127.0.0.1".parse().unwrap(),
            "/proxy/item",
            80,
            false,
            "localhost",
            "localhost",
            "127.0.0.1",
        )
        .is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_control_ttl_is_bounded() {
        let cfg = crate::config::CacheConfig::default();
        let headers = vec![("Cache-Control".into(), b"max-age=999999".to_vec())];
        assert_eq!(freshness(&cfg, &headers, 100), Some(cfg.max_expire as i64));

        let aged = vec![
            ("Cache-Control".into(), b"max-age=100".to_vec()),
            ("Age".into(), b"99".to_vec()),
        ];
        assert_eq!(freshness(&cfg, &aged, 100), Some(1));
        let stale = vec![
            ("Cache-Control".into(), b"max-age=100".to_vec()),
            ("Age".into(), b"100".to_vec()),
        ];
        assert_eq!(freshness(&cfg, &stale, 100), Some(0));
        let apparent = vec![
            ("Cache-Control".into(), b"max-age=100".to_vec()),
            ("Date".into(), crate::util::http_date(10).into_bytes()),
        ];
        assert_eq!(freshness(&cfg, &apparent, 100), Some(10));
        assert!(freshness(
            &cfg,
            &[
                ("Cache-Control".into(), b"max-age=100".to_vec()),
                ("Age".into(), b"not-seconds".to_vec()),
            ],
            100,
        )
        .is_none());

        // CacheMinExpire is a heuristic floor, not permission to revive an
        // explicitly stale response or extend an origin max-age.
        let mut minimum = cfg.clone();
        minimum.min_expire = 60;
        assert_eq!(
            freshness(
                &minimum,
                &[("Cache-Control".into(), b"max-age=1".to_vec())],
                100,
            ),
            Some(1)
        );

        // A reversed configuration pair must disable reuse instead of
        // panicking in `i64::clamp` (verified `cache_ttl_clamp`).
        let mut reversed = crate::config::CacheConfig::default();
        reversed.min_expire = 60;
        reversed.max_expire = 5;
        assert_eq!(freshness(&reversed, &headers, 100), Some(0));
        assert_eq!(vapache_verified::cache_expiry(i64::MAX - 1, 10), i64::MAX);
    }

    #[test]
    fn verified_cache_store_and_accounting_gates_cover_edge_cases() {
        assert!(vapache_verified::cache_store_request_admit(
            true, true, true
        ));
        assert!(!vapache_verified::cache_store_request_admit(
            false, true, true
        ));
        assert!(!vapache_verified::cache_store_request_admit(
            true, false, true
        ));
        assert!(!vapache_verified::cache_store_request_admit(
            true, true, false
        ));

        assert!(vapache_verified::cache_store_status_admit(200));
        assert!(vapache_verified::cache_store_status_admit(404));
        assert!(!vapache_verified::cache_store_status_admit(500));

        assert!(!vapache_verified::cache_store_control_admit(
            true, false, false, false, false, false
        ));
        assert!(vapache_verified::cache_store_control_admit(
            true, false, false, true, false, false
        ));
        assert!(!vapache_verified::cache_store_control_admit(
            false, true, false, false, false, false
        ));

        assert!(vapache_verified::cache_store_shape_admit(
            false, false, true
        ));
        assert!(!vapache_verified::cache_store_shape_admit(
            true, false, true
        ));
        assert!(!vapache_verified::cache_store_shape_admit(
            false, true, true
        ));
        assert!(!vapache_verified::cache_store_shape_admit(
            false, false, false
        ));
        assert!(vapache_verified::cache_store_ttl_admit(1));
        assert!(!vapache_verified::cache_store_ttl_admit(0));

        assert_eq!(vapache_verified::cache_disk_projected(10, 20, 3), 3);
        assert_eq!(vapache_verified::cache_disk_evict(10, 20), 0);
        assert!(vapache_verified::cache_disk_key_admit(true, true));
        assert!(!vapache_verified::cache_disk_key_admit(false, true));
        assert!(!vapache_verified::cache_disk_key_admit(true, false));
        assert!(vapache_verified::cache_invalidation_remove_admit(
            false, false
        ));
        assert!(vapache_verified::cache_invalidation_remove_admit(
            true, true
        ));
        assert!(!vapache_verified::cache_invalidation_remove_admit(
            true, false
        ));
    }

    fn disk_test_config(name: &str) -> (std::path::PathBuf, Config) {
        let dir =
            std::env::temp_dir().join(format!("vapache-cache-quota-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("httpd.conf");
        fs::write(&conf, "Listen 127.0.0.1:0\n").unwrap();
        let mut cfg = crate::config::Config::load(
            &conf,
            &dir,
            &Default::default(),
            &Default::default(),
            false,
        )
        .unwrap();
        cfg.cache.root = Some(dir.join("cache"));
        // Most disk-cache unit tests exercise store/load behavior rather than
        // the deliberately nonblocking cold-start scan. Give each unique
        // fixture an empty index up front so unrelated parallel tests cannot
        // make its first optional store skip on the process-wide scan lock.
        let root = cfg.cache.root.as_ref().unwrap();
        fs::create_dir_all(root).unwrap();
        disk_usage()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(root.clone(), DiskUsageState::default());
        (dir, cfg)
    }

    fn disk_entry(body: &[u8], expires: i64) -> Entry {
        Entry {
            status: 200,
            headers: vec![("content-type".into(), b"text/plain".to_vec())],
            body: body.to_vec(),
            body_len: body.len() as u64,
            stored: unix_now(),
            expires,
            policy: [7u8; 32],
            epoch: current_epoch(),
            vary: Vec::new(),
            _resident: None,
        }
    }

    #[test]
    fn unsafe_method_invalidation_is_canonical_and_targeted() {
        let (dir, mut cfg) = disk_test_config("targeted-invalidation");
        cfg.cache.max_disk_size = 1_000_000;
        prepare(&cfg);
        let root = cfg.cache.root.clone().unwrap();
        // Put crash leftovers in place before the per-generation index is
        // built. The first disk operation accounts them; later invalidations
        // must use that index rather than rescan attacker-amplifiable trees.
        fs::write(root.join("orphan.body.tmp"), b"partial").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("missing-target", root.join("unrelated-link")).unwrap();
        disk_usage()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&root);
        let fingerprint = [7u8; 32];
        let target = Path::new("/srv/index.html");
        let selected_index = base_key(
            &cfg,
            None,
            "127.0.0.1",
            80,
            false,
            "example.test",
            "/dir",
            "/dir/index.html",
            b"",
            target,
            fingerprint,
        );
        let unrelated = base_key(
            &cfg,
            None,
            "127.0.0.1",
            80,
            false,
            "example.test",
            "/other",
            "/other/index.html",
            b"",
            target,
            fingerprint,
        );
        let entry = disk_entry(b"cached", unix_now() + 60);
        disk_store(&cfg, &selected_index, &entry);
        disk_store(&cfg, &unrelated, &entry);
        let selected_stem = cache_stem(&cfg, &selected_index).unwrap();
        let unrelated_stem = cache_stem(&cfg, &unrelated).unwrap();
        entries()
            .lock()
            .unwrap()
            .entries
            .insert(selected_index.clone(), vec![Arc::new(entry.clone())]);
        entries()
            .lock()
            .unwrap()
            .entries
            .insert(unrelated.clone(), vec![Arc::new(entry.clone())]);
        invalidate(&cfg, "example.test", "/dir");

        assert!(!selected_stem.with_extension("meta").exists());
        assert!(!selected_stem.with_extension("body").exists());
        assert!(unrelated_stem.with_extension("meta").exists());
        assert!(unrelated_stem.with_extension("body").exists());
        assert!(!entries()
            .lock()
            .unwrap()
            .entries
            .contains_key(&selected_index));
        assert!(entries().lock().unwrap().entries.contains_key(&unrelated));
        assert!(disk_load(&cfg, &unrelated).is_some());
        assert!(!root.join("orphan.body.tmp").exists());
        #[cfg(unix)]
        assert!(root.join("unrelated-link").is_symlink());

        let mismatched = "metadata-key-mismatch";
        disk_store(&cfg, mismatched, &entry);
        let mismatch_stem = cache_stem(&cfg, mismatched).unwrap();
        fs::write(
            mismatch_stem.with_extension("meta"),
            encode_meta("different-key", &entry),
        )
        .unwrap();
        assert!(disk_load(&cfg, mismatched).is_none());
        assert!(!mismatch_stem.with_extension("body").exists());

        let corrupt = "keyed-corrupt-metadata";
        disk_store(&cfg, corrupt, &entry);
        let corrupt_stem = cache_stem(&cfg, corrupt).unwrap();
        fs::write(
            corrupt_stem.with_extension("meta"),
            format!("V7\nK {}\n", STANDARD.encode(corrupt.as_bytes())),
        )
        .unwrap();
        assert!(disk_load(&cfg, corrupt).is_none());
        assert!(!corrupt_stem.with_extension("body").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disk_cache_enforces_total_quota_and_rejects_oversize_entries() {
        let (dir, mut cfg) = disk_test_config("evict");
        cfg.cache.max_disk_size = 6_000;
        disk_store(
            &cfg,
            "first",
            &disk_entry(&vec![b'a'; 4_000], unix_now() + 60),
        );
        let first = cache_stem(&cfg, "first").unwrap();
        assert!(first.with_extension("body").is_file());
        disk_store(
            &cfg,
            "second",
            &disk_entry(&vec![b'b'; 4_000], unix_now() + 60),
        );
        let second = cache_stem(&cfg, "second").unwrap();
        assert!(second.with_extension("body").is_file());
        assert!(!first.with_extension("body").exists());
        assert!(!first.with_extension("meta").exists());

        // A single entry larger than the total budget is never persisted.
        cfg.cache.max_disk_size = 128;
        disk_store(
            &cfg,
            "oversize",
            &disk_entry(&vec![b'c'; 1_024], unix_now() + 60),
        );
        let oversize = cache_stem(&cfg, "oversize").unwrap();
        assert!(!oversize.with_extension("body").exists());

        cfg.cache.max_disk_size = 20_000;
        for key in ["break-a", "break-b", "break-c"] {
            disk_store(&cfg, key, &disk_entry(&vec![b'd'; 1_000], unix_now() + 60));
        }
        cfg.cache.max_disk_size = 4_000;
        disk_store(
            &cfg,
            "break-new",
            &disk_entry(&vec![b'e'; 1_000], unix_now() + 60),
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn memory_cache_has_an_independent_byte_cap_and_skips_large_bodies() {
        let (dir, mut cfg) = disk_test_config("memory-quota");
        let mut cache = MemoryCache::default();
        cfg.cache.max_memory_size = 1_600;
        let first = Arc::new(disk_entry(&vec![b'a'; 700], unix_now() + 60));
        let second = Arc::new(disk_entry(&vec![b'b'; 700], unix_now() + 60));
        insert_memory_into(&cfg, &mut cache, "first", first);
        insert_memory_into(&cfg, &mut cache, "second", second);
        assert!(cache.bytes <= cfg.cache.max_memory_size);
        assert_eq!(cache.entries.len(), 1, "oldest entry should be evicted");
        assert!(cache.entries.contains_key("second"));

        let large = Arc::new(disk_entry(
            &vec![b'x'; MAX_MEMORY_BODY + 1],
            unix_now() + 60,
        ));
        insert_memory_into(&cfg, &mut cache, "large", large);
        assert!(!cache.entries.contains_key("large"));

        cfg.cache.max_memory_size = 0;
        insert_memory_into(
            &cfg,
            &mut cache,
            "disabled",
            Arc::new(disk_entry(b"x", unix_now() + 60)),
        );
        assert!(!cache.entries.contains_key("disabled"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_same_key_disk_stores_publish_one_complete_entry() {
        let (dir, mut cfg) = disk_test_config("same-key-store");
        cfg.cache.max_disk_size = 1_000_000;
        prepare(&cfg);
        let cfg = Arc::new(cfg);
        let start = Arc::new(std::sync::Barrier::new(8));
        let mut workers = Vec::new();
        for value in 0..8u8 {
            let cfg = cfg.clone();
            let start = start.clone();
            workers.push(std::thread::spawn(move || {
                start.wait();
                disk_store(
                    &cfg,
                    "shared-key",
                    &disk_entry(&vec![value; 4096], unix_now() + 60),
                );
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        let loaded = disk_load(&cfg, "shared-key").expect("complete concurrent store");
        assert_eq!(loaded.body.len(), 4096);
        assert!(loaded.body.iter().all(|byte| *byte == loaded.body[0]));
        let stem = cache_stem(&cfg, "shared-key").unwrap();
        assert!(!stem.with_extension("body.tmp").exists());
        assert!(!stem.with_extension("meta.tmp").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disk_cache_deletes_expired_entries_on_lookup() {
        let (dir, cfg) = disk_test_config("expired");
        disk_store(&cfg, "expired", &disk_entry(b"stale", unix_now() - 1));
        let stem = cache_stem(&cfg, "expired").unwrap();
        assert!(stem.with_extension("body").is_file());
        assert!(disk_load(&cfg, "expired").is_none());
        assert!(!stem.with_extension("body").exists());
        assert!(!stem.with_extension("meta").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_helper_lookup_and_freshness_edges() {
        let (dir, mut cfg) = disk_test_config("helpers");
        let cache_root = cfg.cache.root.clone().unwrap();
        fs::create_dir_all(cache_root.join("nested")).unwrap();
        fs::write(cache_root.join("alpha.body"), b"body").unwrap();
        fs::write(cache_root.join("alpha.meta"), b"meta").unwrap();
        fs::write(cache_root.join("unrelated.txt"), b"ignored").unwrap();
        let old = fs::FileTimes::new().set_modified(SystemTime::UNIX_EPOCH);
        fs::OpenOptions::new()
            .write(true)
            .open(cache_root.join("alpha.meta"))
            .unwrap()
            .set_times(old)
            .unwrap();
        fs::write(cache_root.join("nested/beta.body.tmp"), b"tmp").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("alpha.body", cache_root.join("link")).unwrap();
        let usage = scan_disk_usage(&cache_root).unwrap();
        assert!(usage.total >= 11);
        assert_eq!(usage.stems.len(), 2);
        assert_eq!(usage.file_counts[&cache_root.join("alpha")], 2);
        assert_eq!(usage.file_counts[&cache_root.join("nested/beta")], 1);
        let mut recorded = DiskUsageState::default();
        record_disk_file(
            &mut recorded,
            PathBuf::from("manual"),
            2,
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2),
        );
        record_disk_file(
            &mut recorded,
            PathBuf::from("manual"),
            3,
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1),
        );
        assert_eq!(recorded.stems[Path::new("manual")].0, 5);
        assert_eq!(recorded.file_counts[Path::new("manual")], 2);
        assert_eq!(
            scan_disk_usage(&cache_root.join("missing")).unwrap().total,
            0
        );
        assert!(disk_stem(Path::new("plain")).is_none());
        assert_eq!(disk_stem(Path::new("x.body")).unwrap(), PathBuf::from("x"));
        assert_eq!(disk_stem(Path::new("x.meta")).unwrap(), PathBuf::from("x"));
        assert!(open_cache_regular(&cache_root, MAX_DISK_META_BYTES).is_none());
        let too_large_meta = cache_root.join("too-large.meta");
        fs::write(&too_large_meta, b"xx").unwrap();
        assert!(open_cache_regular(&too_large_meta, 1).is_none());

        let response = Response::bytes(200, "text/plain", b"x".to_vec());
        assert_eq!(
            response_header_str(&response, "content-type").as_deref(),
            Some("text/plain")
        );
        let mut no_root = cfg.clone();
        no_root.cache.root = None;
        remove_disk_stem(&no_root, Path::new("unused"));
        disk_store(&no_root, "no-root", &disk_entry(b"x", unix_now() + 60));

        let mut req = test_request();
        req.headers.insert("authorization", b"Basic eA==".to_vec());
        assert!(!request_allows_lookup(&cfg, &req));
        req.headers = Default::default();
        req.headers.insert("pragma", b"NO-CACHE".to_vec());
        assert!(!request_allows_lookup(&cfg, &req));
        req.headers.insert("cache-control", b"public".to_vec());
        assert!(!request_allows_lookup(&cfg, &req));
        req.headers = Default::default();
        req.headers
            .insert("cache-control", b"private, max-age=0".to_vec());
        assert!(!request_allows_lookup(&cfg, &req));
        req.headers
            .insert("cache-control", b"public, \xff, no-cache".to_vec());
        assert!(!request_allows_lookup(&cfg, &req));
        req.headers = Default::default();
        req.headers
            .insert("pragma", b"extension=\xff, NO-CACHE".to_vec());
        assert!(!request_allows_lookup(&cfg, &req));
        req.headers = Default::default();
        req.headers
            .insert("cache-control", b"public, no-cache   ".to_vec());
        assert!(!request_allows_lookup(&cfg, &req));
        cfg.cache.ignore_cache_control = true;
        assert!(request_allows_lookup(&cfg, &req));
        cfg.cache.ignore_cache_control = false;

        let headers = vec![
            ("Vary".into(), b"Accept-Encoding,,*".to_vec()),
            ("vary".into(), b"Accept-Encoding, Cookie".to_vec()),
        ];
        let mut req = test_request();
        req.headers.insert("accept-encoding", b"gzip".to_vec());
        assert!(vary_values(&req, &headers).is_none());
        let valid = vec![
            ("Vary".into(), b"Accept-Encoding".to_vec()),
            ("vary".into(), b"Cookie".to_vec()),
        ];
        let vary = vary_values(&req, &valid).unwrap();
        assert_eq!(vary.len(), 2);
        let excessive_vary = (0..=256)
            .map(|index| format!("x-{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(vary_values(&req, &[("Vary".into(), excessive_vary.into_bytes())]).is_none());
        assert_eq!(
            combined_header(&headers, "vary")
                .unwrap()
                .matches(',')
                .count(),
            4
        );
        assert!(vary_values(&req, &[]).unwrap().is_empty());
        assert!(!cache_enabled(&Scope::default(), "/x"));
        let mut disabled = Scope::default();
        disabled
            .rewrite_policy
            .cache_enable
            .push(("disk".into(), "/".into()));
        disabled.rewrite_policy.cache_disable.push("/x".into());
        assert!(!cache_enabled(&disabled, "/x"));
        let mut ignored_query_cfg = cfg.clone();
        ignored_query_cfg.cache.ignore_query_string = true;
        assert!(base_key(
            &ignored_query_cfg,
            None,
            "127.0.0.1",
            80,
            false,
            "host",
            "/x",
            "/x",
            b"query",
            Path::new("/tmp/target"),
            [0; 32],
        )
        .contains("\n\nhttp\n"));

        let policy = cache_policy_fingerprint(
            &Scope::default(),
            &req,
            "127.0.0.1".parse().unwrap(),
            Path::new("/tmp/target"),
        );
        let key = "lookup-edges".to_string();
        entries().lock().unwrap().entries.insert(
            key.clone(),
            vec![
                Arc::new(Entry {
                    status: 200,
                    headers: Vec::new(),
                    body: b"expired".to_vec(),
                    body_len: 7,
                    stored: unix_now() - 10,
                    expires: unix_now() - 1,
                    policy,
                    epoch: current_epoch(),
                    vary: Vec::new(),
                    _resident: None,
                }),
                Arc::new(Entry {
                    status: 200,
                    headers: vec![
                        ("etag".into(), b"\"tag\"".to_vec()),
                        ("content-length".into(), b"5".to_vec()),
                    ],
                    body: b"fresh".to_vec(),
                    body_len: 5,
                    stored: unix_now(),
                    expires: unix_now() + 60,
                    policy,
                    epoch: current_epoch(),
                    vary: Vec::new(),
                    _resident: None,
                }),
            ],
        );
        cfg.cache.header = true;
        cfg.cache.detail_header = true;
        let mut conditional = req.clone();
        conditional
            .headers
            .insert("if-none-match", b"W/\"tag\", \"other\"".to_vec());
        let mut memory = entries().lock().unwrap();
        Arc::make_mut(&mut memory.entries.get_mut(&key).unwrap()[1]).policy =
            cache_policy_fingerprint(
                &Scope::default(),
                &conditional,
                "127.0.0.1".parse().unwrap(),
                Path::new("/tmp/target"),
            );
        drop(memory);
        let hit = lookup(
            &cfg,
            None,
            &conditional,
            "host",
            "/x",
            &Scope::default(),
            "127.0.0.1".parse().unwrap(),
            &crate::access::test_grant(),
            &key,
            Path::new("/tmp/target"),
        )
        .unwrap();
        assert_eq!(hit.status, 304);
        assert!(hit
            .headers
            .iter()
            .all(|(n, _)| !n.eq_ignore_ascii_case("content-length")));
        assert!(hit
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("x-cache-detail")));

        let mut memory = entries().lock().unwrap();
        Arc::make_mut(&mut memory.entries.get_mut(&key).unwrap()[0]).policy = policy;
        drop(memory);
        let mut body_hit = lookup(
            &cfg,
            None,
            &req,
            "host",
            "/x",
            &Scope::default(),
            "127.0.0.1".parse().unwrap(),
            &crate::access::test_grant(),
            &key,
            Path::new("/tmp/target"),
        )
        .unwrap();
        assert_eq!(body_hit.body_len(), 5);
        assert!(body_hit.take_resident().unwrap().bytes() >= 5);

        let wrong_resource =
            crate::access::ResourceKey::cache(None, &req, "different-host", "/different-path");
        let wrong_grant =
            crate::access::grant_if_allowed(crate::access::Access::Allowed, wrong_resource)
                .unwrap();
        assert!(lookup(
            &cfg,
            None,
            &req,
            "host",
            "/x",
            &Scope::default(),
            "127.0.0.1".parse().unwrap(),
            &wrong_grant,
            "wrong-grant-lookup",
            Path::new("/tmp/target"),
        )
        .is_none());
        let mut no_cache = req.clone();
        no_cache
            .headers
            .insert("cache-control", b"no-cache".to_vec());
        assert!(lookup(
            &cfg,
            None,
            &no_cache,
            "host",
            "/x",
            &Scope::default(),
            "127.0.0.1".parse().unwrap(),
            &crate::access::test_grant(),
            "no-cache-lookup",
            Path::new("/tmp/target"),
        )
        .is_none());

        let expired_key = "only-expired".to_string();
        entries().lock().unwrap().entries.insert(
            expired_key.clone(),
            vec![Arc::new(Entry {
                policy,
                expires: unix_now() - 1,
                ..disk_entry(b"old", unix_now() - 1)
            })],
        );
        assert!(lookup(
            &cfg,
            None,
            &req,
            "host",
            "/x",
            &Scope::default(),
            "127.0.0.1".parse().unwrap(),
            &crate::access::test_grant(),
            &expired_key,
            Path::new("/tmp/target"),
        )
        .is_none());
        assert!(!entries().lock().unwrap().entries.contains_key(&expired_key));

        let mismatched_key = "disk-policy-mismatch";
        let mismatched = Entry {
            policy: [9; 32],
            ..disk_entry(b"disk", unix_now() + 60)
        };
        disk_store(&cfg, mismatched_key, &mismatched);
        entries().lock().unwrap().entries.remove(mismatched_key);
        assert!(lookup(
            &cfg,
            None,
            &req,
            "host",
            "/x",
            &Scope::default(),
            "127.0.0.1".parse().unwrap(),
            &crate::access::test_grant(),
            mismatched_key,
            Path::new("/tmp/target"),
        )
        .is_none());

        let now = unix_now();
        let expires = vec![(
            "expires".into(),
            crate::util::http_date(now - 1).into_bytes(),
        )];
        assert!(freshness(&cfg.cache, &expires, now).is_none());
        let last = vec![(
            "last-modified".into(),
            crate::util::http_date(now).into_bytes(),
        )];
        assert_eq!(
            freshness(&cfg.cache, &last, now),
            Some(cfg.cache.default_expire.min(cfg.cache.max_expire) as i64)
        );
        let mut no_last = cfg.cache.clone();
        no_last.ignore_no_last_mod = true;
        assert!(freshness(&no_last, &[], now).is_some());

        let budget = Arc::new(crate::resource::ResourceBudget::default());
        let mut resident = budget.try_response_bytes().unwrap();
        let mut empty = Body::Empty;
        assert_eq!(
            response_body_bytes(&mut empty, &mut resident),
            Some(Vec::new())
        );
        let mut bytes = Body::Bytes(b"bytes".to_vec());
        assert_eq!(
            response_body_bytes(&mut bytes, &mut resident),
            Some(b"bytes".to_vec())
        );
        let file_path = dir.join("body-file");
        fs::write(&file_path, b"012345").unwrap();
        let mut file_body = Body::File {
            file: fs::File::open(&file_path).unwrap(),
            offset: 2,
            len: 3,
        };
        assert_eq!(
            response_body_bytes(&mut file_body, &mut resident),
            Some(b"234".to_vec())
        );
        let mut stream = Body::Stream {
            reader: Box::new(&b"stream"[..]),
            len: 6,
        };
        assert!(response_body_bytes(&mut stream, &mut resident).is_none());

        let rnd = crate::config::RewriteMap::Rnd(HashMap::from([
            ("b".into(), vec!["2".into()]),
            ("a".into(), vec!["1".into()]),
        ]));
        assert!(rewrite_map_material(&rnd).starts_with("rnd:"));
        let program = crate::config::RewriteProgram::bind("/bin/true".into(), Vec::new()).unwrap();
        assert!(
            rewrite_map_material(&crate::config::RewriteMap::Prg(program))
                .starts_with("prg:/bin/true|")
        );
        let ims = crate::util::http_date(unix_now()).into_bytes();
        let mut ims_req = test_request();
        ims_req.headers.insert("if-modified-since", ims.clone());
        let ims_entry = Entry {
            headers: vec![("last-modified".into(), ims)],
            ..disk_entry(b"body", unix_now() + 60)
        };
        let mut ims_response = Response::bytes(200, "text/plain", b"body".to_vec());
        assert!(conditional_hit(&ims_req, &ims_entry, &mut ims_response));
        assert_eq!(ims_response.status, 304);

        let mut precedence_req = ims_req.clone();
        precedence_req
            .headers
            .insert("if-none-match", b"\"different\"".to_vec());
        let mut precedence_response = Response::bytes(200, "text/plain", b"body".to_vec());
        assert!(!conditional_hit(
            &precedence_req,
            &ims_entry,
            &mut precedence_response
        ));
        assert_eq!(precedence_response.status, 200);

        let weak_entry = Entry {
            headers: vec![("etag".into(), b"W/\"tag\"".to_vec())],
            ..disk_entry(b"body", unix_now() + 60)
        };
        let mut strong_req = test_request();
        strong_req
            .headers
            .insert("if-none-match", b"\"tag\"".to_vec());
        let mut weak_response = Response::bytes(200, "text/plain", b"body".to_vec());
        assert!(conditional_hit(
            &strong_req,
            &weak_entry,
            &mut weak_response
        ));
        assert_eq!(weak_response.status, 304);

        let comma_entry = Entry {
            headers: vec![("etag".into(), b"\"tag,part\"".to_vec())],
            ..disk_entry(b"body", unix_now() + 60)
        };
        let mut comma_req = test_request();
        comma_req.headers.insert(
            "if-none-match",
            b"\"other\", W/\"tag,part\", \"last\"".to_vec(),
        );
        let mut comma_response = Response::bytes(200, "text/plain", b"body".to_vec());
        assert!(conditional_hit(
            &comma_req,
            &comma_entry,
            &mut comma_response
        ));
        assert_eq!(comma_response.status, 304);

        let mut invalid_list_req = comma_req.clone();
        invalid_list_req
            .headers
            .insert("if-none-match", b"invalid, \"tag,part\"".to_vec());
        let mut invalid_list_response = Response::bytes(200, "text/plain", b"body".to_vec());
        assert!(!conditional_hit(
            &invalid_list_req,
            &comma_entry,
            &mut invalid_list_response
        ));
        for malformed in [
            b"\"tag,part\",".as_slice(),
            b", \"tag,part\"".as_slice(),
            b"\"other\", , \"tag,part\"".as_slice(),
        ] {
            let mut request = test_request();
            request.headers.insert("if-none-match", malformed.to_vec());
            let mut response = Response::bytes(200, "text/plain", b"body".to_vec());
            assert!(!conditional_hit(&request, &comma_entry, &mut response));
        }

        let mut star_req = test_request();
        star_req.headers.insert("if-none-match", b"*".to_vec());
        let mut star_response = Response::bytes(200, "text/plain", b"body".to_vec());
        assert!(conditional_hit(&star_req, &ims_entry, &mut star_response));
        assert_eq!(star_response.status, 304);

        let malformed_entry = Entry {
            headers: vec![("etag".into(), b"tag".to_vec())],
            ..disk_entry(b"body", unix_now() + 60)
        };
        let mut malformed_req = test_request();
        malformed_req
            .headers
            .insert("if-none-match", b"W/tag, \"other".to_vec());
        let mut malformed_response = Response::bytes(200, "text/plain", b"body".to_vec());
        assert!(!conditional_hit(
            &malformed_req,
            &malformed_entry,
            &mut malformed_response
        ));

        let expires_future = vec![(
            "expires".into(),
            crate::util::http_date(unix_now() + 120).into_bytes(),
        )];
        assert!(freshness(&cfg.cache, &expires_future, unix_now()).is_some());
        let last_past = vec![(
            "last-modified".into(),
            crate::util::http_date(unix_now() - 120).into_bytes(),
        )];
        assert!(freshness(&cfg.cache, &last_past, unix_now()).is_some());
        assert!(decode_meta(
            format!(
                "V3\nS 200\nT 1\nE 2\nP {}\nG 1\nX ignored\n",
                STANDARD.encode([0u8; 32])
            )
            .as_bytes()
        )
        .is_some());
        assert!(decode_meta(b"not-a-metadata-version\n").is_none());
        // Historical metadata remains decodable for diagnostics but can
        // never supply the exact current-format key used by disk_load. V7
        // also invalidates V6 entries admitted before response cache-policy
        // metadata was parsed and validated as a complete field set.
        let legacy_v4 = format!(
            "V4\nS 200\nT 1\nE 2\nP {}\nG 1\n",
            STANDARD.encode([0u8; 32])
        );
        assert!(decode_meta(legacy_v4.as_bytes()).is_some());
        assert!(decode_meta_key(b"V4\nK YQ==\n").is_none());
        assert!(decode_meta_key(b"V5\nK YQ==\n").is_none());
        assert!(decode_meta_key(b"V6\nK YQ==\n").is_none());
        assert!(decode_meta_key(b"V7\nS 200\n").is_none());

        let mut invalid_conditional = test_request();
        invalid_conditional
            .headers
            .insert("if-modified-since", b"not-a-date".to_vec());
        let mut conditional_response = Response::new(200);
        assert!(!conditional_hit(
            &invalid_conditional,
            &disk_entry(b"x", unix_now() + 60),
            &mut conditional_response,
        ));

        let legacy_key = "pre-strict-response-cache-policy";
        let legacy_entry = disk_entry(b"SECRET-CONTENT", unix_now() + 60);
        let legacy_stem = cache_stem(&cfg, legacy_key).unwrap();
        fs::create_dir_all(legacy_stem.parent().unwrap()).unwrap();
        let mut legacy_meta = encode_meta(legacy_key, &legacy_entry);
        legacy_meta[..2].copy_from_slice(b"V6");
        fs::write(legacy_stem.with_extension("meta"), legacy_meta).unwrap();
        fs::write(legacy_stem.with_extension("body"), &legacy_entry.body).unwrap();
        assert!(disk_load(&cfg, legacy_key).is_none());
        assert!(!legacy_stem.with_extension("body").exists());
        assert!(!legacy_stem.with_extension("meta").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disk_cache_scan_rejects_excessive_directory_depth() {
        let (dir, cfg) = disk_test_config("bounded-scan-depth");
        let root = cfg.cache.root.as_ref().unwrap();
        let mut nested = root.clone();
        for _ in 0..=MAX_DISK_SCAN_DEPTH {
            nested.push("d");
            fs::create_dir_all(&nested).unwrap();
        }
        fs::write(nested.join("entry.body"), b"body").unwrap();
        assert!(scan_disk_usage(root).is_none());
        disk_usage().lock().unwrap().remove(root);
        assert!(!ensure_disk_usage(root, &cfg.resource_budget));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn contended_disk_cache_stripe_is_a_nonblocking_miss_and_store_skip() {
        let (dir, cfg) = disk_test_config("disk-stripe-contention");
        prepare(&cfg);
        let key = "contended-key";
        let original = disk_entry(b"original", unix_now() + 60);
        disk_store(&cfg, key, &original);
        let stem = cache_stem(&cfg, key).unwrap();
        let guard = disk_io_lock(&stem).lock().unwrap();
        assert!(disk_load(&cfg, key).is_none());
        disk_store(&cfg, key, &disk_entry(b"replacement", unix_now() + 60));
        drop(guard);
        assert_eq!(disk_load(&cfg, key).unwrap().body, b"original");
        disk_usage()
            .lock()
            .unwrap()
            .remove(cfg.cache.root.as_ref().unwrap());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn malformed_memory_eviction_state_is_bounded_and_self_healing() {
        let (dir, mut cfg) = disk_test_config("memory-eviction-state");
        cfg.cache.max_memory_size = u64::MAX;
        let entry = |tag: u8, vary: Vec<(String, Vec<u8>)>| {
            Arc::new(Entry {
                vary,
                ..disk_entry(&[tag], unix_now() + 60)
            })
        };

        // Amortized queue compaction drops stale identities without cloning
        // cache keys or retaining dead Weak references indefinitely.
        let stale = entry(1, Vec::new());
        let mut compact = MemoryCache::default();
        compact.eviction = std::iter::repeat_n(
            (memory_entry_id(&stale), 1, Arc::downgrade(&stale)),
            MAX_ENTRIES * 8 + 1,
        )
        .collect();
        let live = entry(2, Vec::new());
        track_memory_entry(&mut compact, "live", &live);
        assert_eq!(compact.eviction.len(), 1);

        // Every defensive skip in eviction is reachable from a malformed or
        // interrupted snapshot, and each one must terminate without an O(n)
        // fallback scan.
        let target = entry(3, Vec::new());
        let id = memory_entry_id(&target);
        let mut missing_location = MemoryCache::default();
        missing_location
            .eviction
            .push_back((id, 1, Arc::downgrade(&target)));
        assert!(!evict_oldest_memory(&mut missing_location));

        let mut stale_generation = MemoryCache::default();
        stale_generation
            .locations
            .insert(id, (2, "stale-generation".into()));
        stale_generation
            .eviction
            .push_back((id, 1, Arc::downgrade(&target)));
        assert!(!evict_oldest_memory(&mut stale_generation));

        let expired = entry(4, Vec::new());
        let expired_id = memory_entry_id(&expired);
        let expired_weak = Arc::downgrade(&expired);
        drop(expired);
        let mut dead_weak = MemoryCache::default();
        dead_weak.locations.insert(expired_id, (1, "dead".into()));
        dead_weak.eviction.push_back((expired_id, 1, expired_weak));
        assert!(!evict_oldest_memory(&mut dead_weak));

        let mut missing_bucket = MemoryCache::default();
        missing_bucket
            .locations
            .insert(id, (1, "missing-bucket".into()));
        missing_bucket
            .eviction
            .push_back((id, 1, Arc::downgrade(&target)));
        assert!(!evict_oldest_memory(&mut missing_bucket));

        for keep_nonempty in [false, true] {
            let mut wrong_bucket = MemoryCache::default();
            wrong_bucket
                .locations
                .insert(id, (1, "wrong-bucket".into()));
            wrong_bucket
                .eviction
                .push_back((id, 1, Arc::downgrade(&target)));
            wrong_bucket.entries.insert(
                "wrong-bucket".into(),
                keep_nonempty
                    .then(|| vec![entry(5, Vec::new())])
                    .unwrap_or_default(),
            );
            assert!(!evict_oldest_memory(&mut wrong_bucket));
            assert_eq!(
                wrong_bucket.entries.contains_key("wrong-bucket"),
                keep_nonempty
            );
        }

        let mut valid = MemoryCache::default();
        valid.locations.insert(id, (1, "valid".into()));
        valid.eviction.push_back((id, 1, Arc::downgrade(&target)));
        let survivor = entry(9, Vec::new());
        valid
            .entries
            .insert("valid".into(), vec![target.clone(), survivor.clone()]);
        valid.bytes = memory_entry_size("valid", &target)
            .saturating_add(memory_entry_size("valid", &survivor));
        assert!(evict_oldest_memory(&mut valid));
        assert_eq!(valid.entries["valid"].len(), 1);
        assert_eq!(valid.bytes, memory_entry_size("valid", &survivor));

        let oversized = entry(6, Vec::new());
        let mut too_small = cfg.clone();
        too_small.cache.max_memory_size = 1;
        insert_memory_into(&too_small, &mut MemoryCache::default(), "large", oversized);

        let old = entry(7, vec![("accept".into(), b"a".to_vec())]);
        let replacement = entry(8, vec![("accept".into(), b"a".to_vec())]);
        let mut replace = MemoryCache::default();
        replace.bytes = memory_entry_size("replace", &old);
        replace.entries.insert("replace".into(), vec![old]);
        insert_memory_into(&cfg, &mut replace, "replace", replacement);
        assert_eq!(replace.entries["replace"].len(), 1);

        let root = cfg.cache.root.as_ref().unwrap().clone();
        let store_key = "malformed-disk-queue";
        let store_stem = cache_stem(&cfg, store_key).unwrap();
        let missing = root.join("missing-victim");
        let stale_victim = root.join("stale-victim");
        let valid_victim = root.join("valid-victim");
        let mut usage = DiskUsageState {
            total: 2_000_000,
            next_generation: 9,
            ..DiskUsageState::default()
        };
        usage
            .stems
            .insert(stale_victim.clone(), (1, SystemTime::UNIX_EPOCH, 2));
        usage
            .stems
            .insert(valid_victim.clone(), (2_000_000, SystemTime::UNIX_EPOCH, 3));
        usage.eviction.extend([
            (store_stem.clone(), 1),
            (missing.clone(), 1),
            (stale_victim, 1),
            (valid_victim, 3),
        ]);
        usage
            .eviction
            .extend(std::iter::repeat_n((missing, 1), MAX_DISK_ENTRIES * 8 + 1));
        disk_usage().lock().unwrap().insert(root.clone(), usage);
        cfg.cache.max_disk_size = 1_000_000;
        disk_store(&cfg, store_key, &disk_entry(b"queued", unix_now() + 60));
        assert!(disk_load(&cfg, store_key).is_some());

        release_disk_reservation(&dir.join("absent-root"), Path::new("missing"), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disk_corruption_write_failure_and_invalidation_edges() {
        let (dir, mut cfg) = disk_test_config("disk-failures");
        let root = cfg.cache.root.clone().unwrap();
        prepare(&cfg);
        prepare_dir(&cfg, &dir.join("prepared"));
        let blocker = dir.join("blocker");
        fs::write(&blocker, b"file").unwrap();
        prepare_dir(&cfg, &blocker.join("child"));

        assert!(disk_load(&cfg, "absent").is_none());
        let bad_stem = cache_stem(&cfg, "bad-meta").unwrap();
        fs::create_dir_all(bad_stem.parent().unwrap()).unwrap();
        fs::write(bad_stem.with_extension("meta"), b"not metadata").unwrap();
        fs::write(bad_stem.with_extension("body"), b"body").unwrap();
        assert!(disk_load(&cfg, "bad-meta").is_none());
        assert!(!bad_stem.with_extension("body").exists());

        let missing_body = disk_entry(b"gone", unix_now() + 60);
        disk_store(&cfg, "missing-body", &missing_body);
        let missing_stem = cache_stem(&cfg, "missing-body").unwrap();
        fs::remove_file(missing_stem.with_extension("body")).unwrap();
        assert!(disk_load(&cfg, "missing-body").is_none());

        let victim = dir.join("cache-temp-victim");
        fs::write(&victim, b"untouched").unwrap();
        let safe_stem = cache_stem(&cfg, "safe-temp").unwrap();
        std::os::unix::fs::symlink(&victim, safe_stem.with_extension("body.tmp")).unwrap();
        disk_store(&cfg, "safe-temp", &disk_entry(b"cached", unix_now() + 60));
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
        assert!(disk_load(&cfg, "safe-temp").is_some());
        fs::remove_file(safe_stem.with_extension("body")).unwrap();
        std::os::unix::fs::symlink(&victim, safe_stem.with_extension("body")).unwrap();
        assert!(disk_load(&cfg, "safe-temp").is_none());
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");

        let root_file = dir.join("cache-is-a-file");
        fs::write(&root_file, b"x").unwrap();
        cfg.cache.root = Some(root_file.clone());
        cfg.cache.max_disk_size = u64::MAX;
        disk_store(&cfg, "write-fails", &disk_entry(b"x", unix_now() + 60));

        cfg.cache.root = Some(root.clone());
        let rename_stem = cache_stem(&cfg, "rename-fails").unwrap();
        fs::create_dir_all(rename_stem.with_extension("meta")).unwrap();
        disk_store(&cfg, "rename-fails", &disk_entry(b"x", unix_now() + 60));
        assert!(!rename_stem.with_extension("body").exists());
        fs::remove_dir_all(rename_stem.with_extension("meta")).unwrap();

        disk_usage().lock().unwrap().insert(
            root.clone(),
            DiskUsageState {
                total: u64::MAX,
                stems: HashMap::new(),
                keys: HashMap::new(),
                ..DiskUsageState::default()
            },
        );
        cfg.cache.max_disk_size = 1_000;
        disk_store(
            &cfg,
            "accounting-refuses",
            &disk_entry(b"x", unix_now() + 60),
        );

        fs::write(root.join("orphan.body.tmp"), b"x").unwrap();
        fs::write(root.join("keep.txt"), b"x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("keep.txt", root.join("keep-link")).unwrap();
        // `clear()` is the process-global reload transition: it advances the
        // shared generation as well as cleaning this root. Calling it from a
        // parallel unit test invalidates unrelated cache fixtures mid-test.
        // Exercise the filesystem half directly here; reload integration owns
        // the generation transition.
        invalidate_disk(&cfg);
        *entries().lock().unwrap_or_else(|e| e.into_inner()) = MemoryCache::default();
        assert!(!root.join("orphan.body.tmp").exists());
        assert!(root.join("keep.txt").exists());
        assert!(root.join("keep-link").exists());
        let mut no_root = cfg.clone();
        no_root.cache.root = None;
        invalidate_disk(&no_root);
        let mut bad_root = no_root;
        bad_root.cache.root = Some(root_file);
        invalidate_disk(&bad_root);
        invalidate(&bad_root, "host", "/x");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn injected_disk_cache_failures_clean_up_reservations_and_partial_files() {
        let _fault_guard = crate::fault::test_guard();
        let (dir, mut cfg) = disk_test_config("injected-disk-failures");
        cfg.cache.max_disk_size = u64::MAX;
        cfg.cache.max_file_size = 1_000_000;
        prepare(&cfg);
        let root = cfg.cache.root.clone().unwrap();
        disk_usage()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&root);

        crate::fault::configure("cache.scan", 0, io::ErrorKind::PermissionDenied);
        assert!(scan_disk_usage(&root).is_none());
        crate::fault::configure("cache.scan", 0, io::ErrorKind::PermissionDenied);
        assert!(!ensure_disk_usage(&root, &cfg.resource_budget));
        crate::fault::configure("cache.scan", 0, io::ErrorKind::PermissionDenied);
        disk_store(&cfg, "scan-failure", &disk_entry(b"body", unix_now() + 60));
        assert!(!cache_stem(&cfg, "scan-failure")
            .unwrap()
            .with_extension("body")
            .exists());

        crate::fault::configure("cache.scan.concurrent", 0, io::ErrorKind::AlreadyExists);
        assert!(ensure_disk_usage(&root, &cfg.resource_budget));
        disk_usage().lock().unwrap().remove(&root);

        fs::write(root.join("scan-limit-record"), b"x").unwrap();
        crate::fault::configure("cache.scan.limit", 0, io::ErrorKind::OutOfMemory);
        assert!(scan_disk_usage(&root).is_none());
        fs::remove_file(root.join("scan-limit-record")).unwrap();

        for (index, boundary) in [
            "cache.temp.open",
            "cache.temp.write",
            "cache.rename.body",
            "cache.rename.meta",
            "cache.commit.usage",
            "cache.commit.reservation",
            "cache.commit.generation",
        ]
        .into_iter()
        .enumerate()
        {
            let key = format!("fault-{index}");
            let stem = cache_stem(&cfg, &key).unwrap();
            crate::fault::configure(boundary, 0, io::ErrorKind::PermissionDenied);
            disk_store(&cfg, &key, &disk_entry(b"body", unix_now() + 60));
            assert!(!stem.with_extension("body").exists(), "{boundary}");
            assert!(!stem.with_extension("meta").exists(), "{boundary}");
            assert!(!stem.with_extension("body.tmp").exists(), "{boundary}");
            assert!(!stem.with_extension("meta.tmp").exists(), "{boundary}");
        }

        let key = "body-read-fault";
        disk_store(&cfg, key, &disk_entry(b"body", unix_now() + 60));
        let stem = cache_stem(&cfg, key).unwrap();
        crate::fault::configure("cache.body.read", 0, io::ErrorKind::UnexpectedEof);
        assert!(disk_load(&cfg, key).is_none());
        assert!(!stem.with_extension("body").exists());
        assert!(!stem.with_extension("meta").exists());

        disk_usage().lock().unwrap().remove(&root);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn production_store_rejection_and_eviction_edges() {
        let (dir, mut cfg) = disk_test_config("store-edges");
        cfg.cache.root = None;
        cfg.cache.min_file_size = 0;
        cfg.cache.max_file_size = 1_000_000;
        cfg.cache.default_expire = 60;
        cfg.cache.ignore_no_last_mod = true;
        let scope = Scope::default();
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let target = Path::new("/tmp/cache-target");
        let base_req = test_request();
        let good = crate::access::test_grant();
        let call = |cfg: &Config,
                    req: &Request,
                    response: &mut Response,
                    grant: &AccessGrant,
                    key: &str| {
            store(
                cfg, None, req, "host", "/x", &scope, peer, response, grant, key, target,
            )
        };

        let wrong_key = crate::access::ResourceKey::cache(None, &base_req, "other", "/other");
        let wrong_grant =
            crate::access::grant_if_allowed(crate::access::Access::Allowed, wrong_key).unwrap();
        let mut response = Response::bytes(200, "text/plain", b"ok".to_vec());
        response.forbid_shared_cache();
        call(&cfg, &base_req, &mut response, &good, "local-error");
        response = Response::bytes(200, "text/plain", b"ok".to_vec());
        call(&cfg, &base_req, &mut response, &wrong_grant, "wrong-grant");

        for mut req in [
            {
                let mut r = base_req.clone();
                r.method = "POST".into();
                r
            },
            {
                let mut r = base_req.clone();
                r.body = b"x".to_vec();
                r
            },
            {
                let mut r = base_req.clone();
                r.headers.insert("authorization", b"x".to_vec());
                r
            },
            {
                let mut r = base_req.clone();
                r.headers.insert("cookie", b"x=y".to_vec());
                r
            },
        ] {
            let mut response = Response::bytes(200, "text/plain", b"ok".to_vec());
            call(&cfg, &req, &mut response, &good, "bad-request");
            req.headers = Default::default();
        }

        let mut response = Response::bytes(500, "text/plain", b"no".to_vec());
        call(&cfg, &base_req, &mut response, &good, "bad-status");
        for (key, name, value) in [
            ("no-store", "Cache-Control", "no-store"),
            ("no-cache", "Cache-Control", "no-cache"),
            ("private", "Cache-Control", "private"),
            ("cookie", "Set-Cookie", "x=y"),
            ("vary-star", "Vary", "*"),
        ] {
            let mut response = Response::bytes(200, "text/plain", b"ok".to_vec());
            response
                .headers
                .push((Cow::Owned(name.into()), value.as_bytes().to_vec()));
            call(&cfg, &base_req, &mut response, &good, key);
        }
        for (key, headers) in [
            (
                "cache-control-second-line-private",
                vec![
                    (
                        Cow::Borrowed("Cache-Control"),
                        b"public, max-age=60".to_vec(),
                    ),
                    (
                        Cow::Borrowed("Cache-Control"),
                        b"private=\"Set-Cookie\"".to_vec(),
                    ),
                ],
            ),
            (
                "cache-control-second-line-no-store",
                vec![
                    (
                        Cow::Borrowed("Cache-Control"),
                        b"public, max-age=60".to_vec(),
                    ),
                    (Cow::Borrowed("Cache-Control"), b"no-store".to_vec()),
                ],
            ),
            (
                "cache-control-qualified-no-cache",
                vec![(
                    Cow::Borrowed("Cache-Control"),
                    b"no-cache=\"Authorization, Set-Cookie\"".to_vec(),
                )],
            ),
            (
                "cache-control-malformed",
                vec![(
                    Cow::Borrowed("Cache-Control"),
                    b"public, extension=\"unterminated".to_vec(),
                )],
            ),
            (
                "cache-control-duplicate-age",
                vec![
                    (Cow::Borrowed("Cache-Control"), b"max-age=60".to_vec()),
                    (Cow::Borrowed("Cache-Control"), b"max-age=120".to_vec()),
                ],
            ),
            (
                "duplicate-etag",
                vec![
                    (Cow::Borrowed("ETag"), b"\"one\"".to_vec()),
                    (Cow::Borrowed("ETag"), b"\"two\"".to_vec()),
                ],
            ),
            (
                "duplicate-age",
                vec![
                    (Cow::Borrowed("Age"), b"1".to_vec()),
                    (Cow::Borrowed("Age"), b"2".to_vec()),
                ],
            ),
            (
                "malformed-age",
                vec![(Cow::Borrowed("Age"), b"not-seconds".to_vec())],
            ),
            (
                "content-range-on-complete",
                vec![(Cow::Borrowed("Content-Range"), b"bytes 0-1/2".to_vec())],
            ),
            (
                "invalid-vary",
                vec![(Cow::Borrowed("Vary"), b"Accept-Encoding,,Cookie".to_vec())],
            ),
            (
                "connection-nominated-metadata",
                vec![
                    (Cow::Borrowed("Connection"), b"X-Private".to_vec()),
                    (Cow::Borrowed("X-Private"), b"secret selector".to_vec()),
                ],
            ),
        ] {
            let mut response = Response::bytes(200, "text/plain", b"sensitive".to_vec());
            response.headers.extend(headers);
            call(&cfg, &base_req, &mut response, &good, key);
            assert!(
                !entries().lock().unwrap().entries.contains_key(key),
                "hostile backend metadata reached shared cache for {key}"
            );
        }
        let mut provenance_lost = Response::bytes(200, "text/plain", b"sensitive".to_vec());
        provenance_lost.forbid_shared_cache();
        call(
            &cfg,
            &base_req,
            &mut provenance_lost,
            &good,
            "backend-provenance-lost",
        );
        assert!(!entries()
            .lock()
            .unwrap()
            .entries
            .contains_key("backend-provenance-lost"));
        let mut stream = Response::new(200);
        stream.body = Body::Stream {
            reader: Box::new(&b"x"[..]),
            len: 1,
        };
        call(&cfg, &base_req, &mut stream, &good, "stream");
        let mut too_large = Response::bytes(200, "text/plain", b"xx".to_vec());
        let mut tiny_cfg = cfg.clone();
        tiny_cfg.cache.max_file_size = 1;
        call(&tiny_cfg, &base_req, &mut too_large, &good, "too-large");
        let mut no_ttl = Response::bytes(200, "text/plain", b"ok".to_vec());
        let mut no_ttl_cfg = cfg.clone();
        no_ttl_cfg.cache.ignore_no_last_mod = false;
        call(&no_ttl_cfg, &base_req, &mut no_ttl, &good, "no-ttl");
        let mut zero_ttl = Response::bytes(200, "text/plain", b"ok".to_vec());
        zero_ttl
            .headers
            .push((Cow::Borrowed("Cache-Control"), b"max-age=0".to_vec()));
        call(&cfg, &base_req, &mut zero_ttl, &good, "zero-ttl");

        let mut stored = Response::bytes(200, "text/plain", b"ok".to_vec());
        stored.headers.extend([
            (Cow::Borrowed("Connection"), b"close".to_vec()),
            (Cow::Borrowed("Proxy-Connection"), b"keep-alive".to_vec()),
            (Cow::Borrowed("Content-Length"), b"999".to_vec()),
            (Cow::Borrowed("Age"), b"1".to_vec()),
            (Cow::Borrowed("X-Cache"), b"old".to_vec()),
        ]);
        cfg.cache.header = true;
        {
            let mut map = MemoryCache::default();
            for i in 0..=MAX_ENTRIES {
                map.entries.insert(format!("old-{i}"), Vec::new());
            }
            insert_memory_into(
                &cfg,
                &mut map,
                "new-key",
                Arc::new(disk_entry(b"ok", unix_now() + 60)),
            );
            assert!(map.entries.len() <= MAX_ENTRIES);
            assert!(map.entries.contains_key("new-key"));
        }
        call(&cfg, &base_req, &mut stored, &good, "new-key");
        assert!(stored
            .headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("x-cache") && v == b"MISS"));
        {
            let cache = entries().lock().unwrap();
            let cached = cache.entries["new-key"].last().unwrap();
            for removed in [
                "connection",
                "x-hop",
                "proxy-connection",
                "content-length",
                "age",
                "x-cache",
            ] {
                assert!(
                    !cached
                        .headers
                        .iter()
                        .any(|(name, _)| name.eq_ignore_ascii_case(removed)),
                    "cached hop-by-hop/transport field {removed}"
                );
            }
        }
        entries().lock().unwrap().entries.remove("new-key");

        let policy = cache_policy_fingerprint(&scope, &base_req, peer, target);
        let mut variants = MemoryCache::default();
        variants.entries.insert(
            "variants".into(),
            (0..=MAX_VARIANTS_PER_KEY)
                .map(|i| {
                    Arc::new(Entry {
                        status: 200,
                        headers: Vec::new(),
                        body: vec![i as u8],
                        body_len: 1,
                        stored: unix_now(),
                        expires: unix_now() + 60,
                        policy,
                        epoch: current_epoch(),
                        vary: vec![("x-variant".into(), vec![i as u8])],
                        _resident: None,
                    })
                })
                .collect(),
        );
        let variant_entry = Arc::new(Entry {
            status: 200,
            headers: vec![("Vary".into(), b"X-Variant".to_vec())],
            body: b"v".to_vec(),
            body_len: 1,
            stored: unix_now(),
            expires: unix_now() + 60,
            policy,
            epoch: current_epoch(),
            vary: vec![("x-variant".into(), b"new".to_vec())],
            _resident: None,
        });
        insert_memory_into(&cfg, &mut variants, "variants", variant_entry);
        let mut variant_req = base_req.clone();
        variant_req.headers.insert("x-variant", b"new".to_vec());
        let mut variant = Response::bytes(200, "text/plain", b"v".to_vec());
        variant
            .headers
            .push((Cow::Borrowed("Vary"), b"X-Variant".to_vec()));
        call(&cfg, &variant_req, &mut variant, &good, "variants");
        assert_eq!(variants.entries["variants"].len(), MAX_VARIANTS_PER_KEY);
        let _ = fs::remove_dir_all(&dir);
    }
}
