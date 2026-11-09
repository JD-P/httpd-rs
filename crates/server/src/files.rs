//! Static file serving: secure path opening, conditional requests, byte
//! ranges, directory indexes and autoindex, and Apache-compatible errors.
//!
//! Every filesystem access goes through `openat2(root, ..., RESOLVE_BENEATH)`
//! (with `RESOLVE_NO_SYMLINKS` when `Options -FollowSymLinks`).  This makes
//! path traversal impossible even if URI normalization has a bug: the kernel
//! refuses to resolve outside the document root.  `openat2` is a mandatory
//! startup requirement; there is no pathname-based compatibility fallback.

use crate::config::{Config, ErrorDoc, Scope, ServerSignature, VHost, ETAG_ALL};
use crate::http::{reason_phrase, Body, Request, Response};
use crate::scope_policy::{AutoIndexIcon, AutoIndexIconMatch};
use crate::util::{html_escape, http_date, parse_http_date, url_encode_query};
use crate::verified::{parse_byte_range, RangeDecision};
use std::borrow::Cow;
use std::cell::RefCell;
use std::cmp::Ordering as CmpOrdering;
use std::collections::HashMap;
use std::ffi::{CStr, CString, OsString};
use std::fmt::Write as _;
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

fn openat2_file(dir: &File, path: &CStr, how: &OpenHow) -> io::Result<File> {
    const MAX_TRANSIENT_RETRIES: usize = 8;
    for attempt in 0..=MAX_TRANSIENT_RETRIES {
        let injected = crate::fault::hit("fs.openat2").err();
        let file = if injected.is_none() {
            unsafe {
                let fd = libc::syscall(
                    libc::SYS_openat2,
                    dir.as_raw_fd(),
                    path.as_ptr(),
                    how as *const OpenHow,
                    std::mem::size_of::<OpenHow>(),
                );
                (fd >= 0).then(|| File::from_raw_fd(fd as i32))
            }
        } else {
            None
        };
        if let Some(file) = file {
            return Ok(file);
        }
        let error = injected.unwrap_or_else(io::Error::last_os_error);
        let transient = matches!(
            error.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
        ) || matches!(error.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR));
        if !transient || attempt == MAX_TRANSIENT_RETRIES {
            return Err(error);
        }
    }
    unreachable!("bounded secure path retry loop always returns") // coverage:ignore-line
}

pub fn make_admin_dir_root_owned(dir: &File, mode: libc::mode_t) -> io::Result<()> {
    if effective_uid() != 0 {
        return Ok(());
    }
    let failed = unsafe {
        libc::fchown(dir.as_raw_fd(), 0, 0) != 0 || libc::fchmod(dir.as_raw_fd(), mode) != 0
    };
    if failed {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Trust policy captured when an administrative configuration generation is
/// first loaded.  A daemon that starts privileged must continue requiring
/// root-controlled inputs after its request process drops privileges; using
/// the current euid at reload time would silently weaken that boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminFileTrust {
    ProcessOwned,
    RootOwned,
}

impl Default for AdminFileTrust {
    fn default() -> Self {
        Self::ProcessOwned
    }
}

impl AdminFileTrust {
    pub fn for_current_process() -> Self {
        if effective_uid() == 0 {
            Self::RootOwned
        } else {
            Self::ProcessOwned
        }
    }

    fn requires_root(self) -> bool {
        self == Self::RootOwned
    }
}

#[cfg(test)]
pub(crate) fn make_test_fifo(path: &Path) -> io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    if unsafe { libc::mkfifo(path.as_ptr(), 0o600) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Open an absolute or cwd-relative administrative path without following a
/// symlink in any component.  Runtime content paths use `open_beneath`; this
/// variant is for privileged outputs such as logs and OCSP/cache state, where
/// following a service-user-planted parent symlink on the next root startup
/// would cross the privilege boundary.
pub fn open_admin_path(path: &Path, flags: libc::c_int, mode: libc::mode_t) -> io::Result<File> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let rel = absolute
        .strip_prefix("/")
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let rel_c = CString::new(rel.as_os_str().as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let root = File::open("/")?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: mode as u64,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    };
    openat2_file(&root, &rel_c, &how)
}

/// Read a bounded administrative input through the same no-symlink resolver
/// used for privileged outputs.  Configuration, certificate and map files are
/// not allowed to be FIFOs/devices, to grow while being read, or to live in a
/// service-writable tree when the daemon is still privileged.
pub fn read_admin_file(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    read_admin_file_with_trust(path, max_bytes, AdminFileTrust::for_current_process())
}

/// Read an administrative input under an explicitly retained trust policy.
/// In particular, `RootOwned` does not become weaker merely because the
/// caller has already changed its effective uid.
pub fn read_admin_file_with_trust(
    path: &Path,
    max_bytes: u64,
    trust: AdminFileTrust,
) -> io::Result<Vec<u8>> {
    let mut file = open_admin_path(path, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("administrative input must be a regular file no larger than {max_bytes} bytes"),
        ));
    }
    if trust.requires_root() {
        validate_admin_parents(path, u32::MAX)?;
        if before.uid() != 0 || before.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "privileged administrative input is not root-owned and non-writable by group/other",
            ));
        }
    }
    let mut data = Vec::with_capacity(before.len().min(max_bytes) as usize);
    file.by_ref().take(max_bytes + 1).read_to_end(&mut data)?;
    let after = file.metadata()?;
    if crate::fault::hit("fs.admin.post_read.identity").is_err()
        || data.len() as u64 > max_bytes
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.mode() != after.mode()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "administrative input changed while it was being read",
        ));
    }
    Ok(data)
}

/// Read an administrative input while permitting the one symlink shape used
/// by Certbot: a root-owned final link below a root-owned, non-writable tree,
/// pointing to a root-owned regular file in another such tree. Parent
/// symlinks and chained final symlinks remain forbidden.
///
/// General configuration and privileged output paths deliberately continue
/// to use `read_admin_file_with_trust`/`open_admin_path` and never follow a
/// symlink. This exception is only for callers that explicitly opt into
/// certificate-style atomic rotation.
pub fn read_admin_file_following_root_owned_final_symlink(
    path: &Path,
    max_bytes: u64,
    trust: AdminFileTrust,
) -> io::Result<Vec<u8>> {
    let direct_error = match read_admin_file_with_trust(path, max_bytes, trust) {
        Ok(data) => return Ok(data),
        Err(error) => error,
    };
    if trust != AdminFileTrust::RootOwned {
        return Err(direct_error);
    }

    validate_root_owned_admin_parents(path)?;
    // RESOLVE_NO_SYMLINKS plus O_PATH|O_NOFOLLOW returns a descriptor for a
    // final symlink, but still rejects every symlink in its parent path.
    let link = match open_admin_path(path, libc::O_PATH, 0) {
        Ok(link) => link,
        Err(_) => return Err(direct_error),
    };
    let metadata = link.metadata()?;
    if !metadata.file_type().is_symlink() || metadata.uid() != 0 {
        return Err(direct_error);
    }
    let target = read_pinned_symlink(&link)?;
    // The privileged TLS broker deliberately has room for only four file
    // descriptors. Once the target bytes are pinned to this inode, release
    // the link descriptor before walking the independently root-owned target
    // tree so the nested openat2 validation stays within that ceiling.
    drop(link);
    let target = final_admin_symlink_target(path, &target)?;
    validate_root_owned_admin_parents(&target)?;
    read_admin_file_with_trust(&target, max_bytes, AdminFileTrust::RootOwned)
}

fn final_admin_symlink_target(path: &Path, target: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "administrative symlink path is not absolute",
        ));
    }
    let combined = if target.is_absolute() {
        target.to_path_buf()
    } else {
        path.parent()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?
            .join(target)
    };
    let mut normalized = PathBuf::from("/");
    for component in combined.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::Normal(value) => normalized.push(value),
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    return Err(io::Error::from_raw_os_error(libc::EXDEV));
                }
            }
            std::path::Component::Prefix(_) => {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
        }
    }
    Ok(normalized)
}

fn validate_root_owned_admin_parents(path: &Path) -> io::Result<()> {
    validate_admin_parents(path, u32::MAX)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
    let root = File::open("/")?;
    if root.metadata()?.uid() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "administrative symlink tree root is not owned by root",
        ));
    }
    let mut current = PathBuf::from("/");
    for component in parent.components() {
        match component {
            std::path::Component::RootDir => continue,
            std::path::Component::Normal(value) => current.push(value),
            _ => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
        }
        let directory = open_admin_path(&current, libc::O_PATH | libc::O_DIRECTORY, 0)?;
        if directory.metadata()?.uid() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "administrative symlink path component {} is not owned by root",
                    current.display()
                ),
            ));
        }
    }
    Ok(())
}

/// Reject an absolute administrative output whose directory entry could be
/// replaced by the account the daemon later runs as. Group-writable parents
/// are rejected conservatively because NSS supplementary group membership is
/// mutable outside the configuration file.
pub fn validate_admin_parents(path: &Path, service_uid: u32) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "administrative path is not absolute",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "administrative path has no parent",
        )
    })?;
    let mut current = PathBuf::from("/");
    let mut parent_metadata = File::open("/")?.metadata()?;
    for component in parent.components() {
        let std::path::Component::Normal(component) = component else {
            if matches!(component, std::path::Component::RootDir) {
                continue;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid administrative path component",
            ));
        };
        current.push(component);
        let directory = open_admin_path(&current, libc::O_PATH | libc::O_DIRECTORY, 0)?;
        let metadata = directory.metadata()?;
        let parent_mode = parent_metadata.mode();
        // Ownership itself is authority: an owner can chmod a currently
        // read-only directory and then replace its entries.
        let parent_writable = parent_metadata.uid() == service_uid || parent_mode & 0o022 != 0;
        let sticky_protects_entry = parent_mode & libc::S_ISVTX != 0
            && parent_metadata.uid() != service_uid
            && metadata.uid() != service_uid;
        if parent_writable && !sticky_protects_entry {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "administrative path component {} can be replaced by the service account",
                    current.display()
                ),
            ));
        }
        parent_metadata = metadata;
    }
    let mode = parent_metadata.mode();
    if parent_metadata.uid() == service_uid || mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "administrative path parent {} is writable by the service account",
                parent.display()
            ),
        ));
    }
    Ok(())
}

/// Require a regular file and every pathname component to remain outside the
/// service account's mutation authority. This deliberately treats ownership
/// as mutable even when the current owner-write bit is clear, because owners
/// can restore that bit with chmod.
pub fn validate_service_immutable_file(path: &Path, service_uid: u32) -> io::Result<File> {
    validate_admin_parents(path, service_uid)?;
    let file = open_admin_path(path, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "protected input is not a regular file",
        ));
    }
    if !vapache_verified::auth_file_immutable_admit(
        true,
        metadata.uid() == service_uid,
        metadata.mode() & 0o022 != 0,
    ) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "protected input is writable or owned by the service account",
        ));
    }
    Ok(file)
}

/// Open a canonical administrative executable/input that must remain under
/// root's mutation authority. Callers that begin with a symlinked spelling
/// first canonicalize it, retain that original spelling for later binding
/// checks, and register its parents in the configuration trust manifest.
pub(crate) fn validate_root_owned_admin_file(path: &Path) -> io::Result<File> {
    validate_admin_parents(path, u32::MAX)?;
    let file = open_admin_path(path, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "privileged administrative input is not a root-owned, non-writable regular file",
        ));
    }
    Ok(file)
}

/// Create/open every directory component from a retained descriptor.  No
/// pathname fallback is provided: the daemon already requires `openat2`, and
/// weakening privileged output creation would reintroduce the exact rename
/// race that content serving rejects.
pub fn ensure_admin_dir(path: &Path, mode: libc::mode_t) -> io::Result<File> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut current = File::open("/")?;
    for component in absolute.components() {
        use std::path::Component;
        let Component::Normal(name) = component else {
            if matches!(component, Component::RootDir) {
                continue;
            }
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        };
        let name = CString::new(name.as_bytes())
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let open_component = || {
            let how = OpenHow {
                flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
                    as u64,
                mode: 0,
                resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
            };
            openat2_file(&current, &name, &how)
        };
        current = match open_component() {
            Ok(dir) => dir,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let rc = unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), mode) };
                if rc != 0 {
                    let create_error = io::Error::last_os_error();
                    if create_error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(create_error);
                    }
                }
                open_component()?
            }
            Err(error) => return Err(error),
        };
    }
    Ok(current)
}

pub enum Target {
    File { file: File, meta: Metadata },
    Directory { file: File, meta: Metadata },
    NotFound,
    Forbidden,
}

/// A descriptor-bound representation selected by Apache-style MultiViews.
/// The public URL remains extensionless for request metadata, while `name`
/// supplies the selected URL, Files/MIME policy and Content-Location identity.
pub struct MultiView {
    pub name: Vec<u8>,
    pub file: File,
    pub meta: Metadata,
}

pub enum MultiViewsResult {
    Selected(MultiView),
    NotFound,
    NotAcceptable,
    MultipleChoices,
    Overloaded,
}

const MAX_MULTIVIEW_DIRECTORY_ENTRIES: usize = 1024;
pub(crate) const MAX_MULTIVIEW_CANDIDATES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct VariantScore {
    quality: u64,
    media_specificity: u8,
    language_priority: usize,
}

fn quality_value(raw: &str) -> Option<u16> {
    let raw = raw.trim();
    let (whole, fraction) = raw.split_once('.').unwrap_or((raw, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    match whole {
        "0" => {
            let mut value = 0u16;
            for (index, byte) in fraction.bytes().enumerate() {
                value += u16::from(byte - b'0') * [100, 10, 1][index];
            }
            Some(value)
        }
        "1" if fraction.bytes().all(|byte| byte == b'0') => Some(1000),
        _ => None,
    }
}

fn item_quality<'a>(parts: impl Iterator<Item = &'a str>) -> u16 {
    for parameter in parts {
        let Some((name, value)) = parameter.trim().split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("q") {
            return quality_value(value).unwrap_or(0);
        }
    }
    1000
}

fn media_quality(header: Option<&[u8]>, media_type: &str) -> (u16, u8) {
    let Some(header) = header else {
        return (1000, 0);
    };
    let Ok(header) = std::str::from_utf8(header) else {
        return (0, 0);
    };
    let media_type = media_type.split(';').next().unwrap_or("").trim();
    let Some((candidate_type, candidate_subtype)) = media_type.split_once('/') else {
        return (0, 0);
    };
    let mut selected: Option<(u8, u16)> = None;
    for item in header.split(',') {
        let mut parts = item.split(';');
        let range = parts.next().unwrap_or("").trim();
        let Some((kind, subtype)) = range.split_once('/') else {
            continue;
        };
        let specificity = if kind == "*" && subtype == "*" {
            Some(0)
        } else if kind.eq_ignore_ascii_case(candidate_type) && subtype == "*" {
            Some(1)
        } else if kind.eq_ignore_ascii_case(candidate_type)
            && subtype.eq_ignore_ascii_case(candidate_subtype)
        {
            Some(2)
        } else {
            None
        };
        let Some(specificity) = specificity else {
            continue;
        };
        let quality = item_quality(parts);
        if selected
            .map(|(current, _)| specificity >= current)
            .unwrap_or(true)
        {
            selected = Some((specificity, quality));
        }
    }
    selected
        .map(|(specificity, quality)| (quality, specificity))
        .unwrap_or((0, 0))
}

fn language_quality(header: Option<&[u8]>, language: Option<&str>) -> u16 {
    let Some(header) = header else {
        return 1000;
    };
    // A representation with no language metadata is language-independent.
    let Some(language) = language else {
        return 1000;
    };
    let Ok(header) = std::str::from_utf8(header) else {
        return 0;
    };
    let mut best = 0u16;
    for item in header.split(',') {
        let mut parts = item.split(';');
        let range = parts.next().unwrap_or("").trim();
        let matches = range == "*"
            || language.eq_ignore_ascii_case(range)
            || language
                .get(..range.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(range))
                && language.as_bytes().get(range.len()) == Some(&b'-');
        if matches {
            best = best.max(item_quality(parts));
        }
    }
    best
}

fn encoding_quality(header: Option<&[u8]>, encoding: Option<&str>) -> u16 {
    let Some(header) = header else {
        // Do not select a pre-encoded sibling without an explicit client
        // offer. The identity representation remains universally eligible.
        return if encoding.is_none() { 1000 } else { 0 };
    };
    let Ok(header) = std::str::from_utf8(header) else {
        return 0;
    };
    let candidate = encoding.unwrap_or("identity");
    let mut explicit = None;
    let mut wildcard = None;
    for item in header.split(',') {
        let mut parts = item.split(';');
        let name = parts.next().unwrap_or("").trim();
        let quality = item_quality(parts);
        if name.eq_ignore_ascii_case(candidate)
            || (candidate.eq_ignore_ascii_case("x-gzip") && name.eq_ignore_ascii_case("gzip"))
            || (candidate.eq_ignore_ascii_case("gzip") && name.eq_ignore_ascii_case("x-gzip"))
        {
            explicit = Some(quality);
        } else if name == "*" {
            wildcard = Some(quality);
        }
    }
    explicit.unwrap_or_else(|| {
        if encoding.is_none() {
            wildcard.unwrap_or(1000)
        } else {
            wildcard.unwrap_or(0)
        }
    })
}

fn static_negotiation_handler(scope: &Scope, name: &[u8]) -> bool {
    crate::config::effective_handler(scope, name).is_none_or(|handler| {
        handler.trim().is_empty()
            || handler.eq_ignore_ascii_case("default-handler")
            || handler.eq_ignore_ascii_case("none")
    })
}

/// Resolve the default Apache `MultiViewsMatch NegotiatedOnly` shape. The
/// directory scan and candidate set are hard-capped and charged to the
/// request's shared policy-work budget. Every candidate is opened relative to
/// the already-pinned parent descriptor under the active symlink policy.
pub fn multiviews_target(
    cfg: &Config,
    scope: &Scope,
    req: &Request,
    root: &Path,
    rel: &Path,
    follow_symlinks: bool,
    owner_match_only: bool,
) -> MultiViewsResult {
    if !scope
        .effective_options()
        .contains(crate::config::Options::MULTIVIEWS)
    {
        return MultiViewsResult::NotFound;
    }
    let Some(requested_name) = rel.file_name().map(|name| name.as_bytes()) else {
        return MultiViewsResult::NotFound;
    };
    if requested_name.is_empty() || requested_name == b"." || requested_name == b".." {
        return MultiViewsResult::NotFound; // coverage:ignore-line - Path::file_name excludes these terminal components
    }
    let parent_rel = rel.parent().unwrap_or_else(|| Path::new(""));
    let Target::Directory { file: parent, .. } =
        resolve_target_checked(root, parent_rel, follow_symlinks, owner_match_only)
    else {
        return MultiViewsResult::NotFound;
    };
    let Some(_expensive) = crate::resource::try_expensive() else {
        return MultiViewsResult::Overloaded;
    };
    let path = format!("/proc/self/fd/{}", parent.as_raw_fd());
    let Ok(entries) = std::fs::read_dir(path) else {
        return MultiViewsResult::NotFound; // coverage:ignore-line - procfs disappeared after the parent fd was opened
    };
    let mut prefix = requested_name.to_vec();
    prefix.push(b'.');
    let mut scanned = 0usize;
    let mut candidates = 0usize;
    let mut saw_typed_variant = false;
    let mut best: Option<(VariantScore, MultiView)> = None;
    let mut ambiguous = false;
    for entry in entries {
        scanned += 1;
        if scanned > MAX_MULTIVIEW_DIRECTORY_ENTRIES {
            return MultiViewsResult::Overloaded;
        }
        let Ok(entry) = entry else {
            continue; // coverage:ignore-line - filesystem readdir I/O failure
        };
        let name = entry.file_name().as_encoded_bytes().to_vec();
        if req
            .charge_policy_work((name.len() as u64).saturating_add(1))
            .is_err()
        {
            return MultiViewsResult::Overloaded;
        }
        if !name.starts_with(&prefix) || name.len() == prefix.len() {
            continue;
        }
        candidates += 1;
        if candidates > MAX_MULTIVIEW_CANDIDATES {
            return MultiViewsResult::Overloaded;
        }
        let Some(media_type) = mime_type(cfg, scope, &name) else {
            continue;
        };
        if !static_negotiation_handler(scope, &name) {
            continue;
        }
        saw_typed_variant = true;
        let (media, media_specificity) = media_quality(req.header("accept"), &media_type);
        let language = cfg.mime.content_language(&name);
        let language_quality = language_quality(req.header("accept-language"), language);
        let encoding_quality = encoding_quality(
            req.header("accept-encoding"),
            cfg.mime.content_encoding(&name),
        );
        let quality = u64::from(media)
            .saturating_mul(u64::from(language_quality))
            .saturating_mul(u64::from(encoding_quality));
        let acceptable = quality > 0;
        let opened = open_at_with_symlink_policy(&parent, &name, follow_symlinks, owner_match_only);
        let Ok(file) = opened else {
            continue;
        };
        let Ok(meta) = file.metadata() else {
            continue; // coverage:ignore-line - metadata failure on an already-open regular candidate
        };
        if !vapache_verified::multiview_candidate_admit(
            true,
            true,
            true,
            true,
            meta.is_file(),
            true,
            true,
            acceptable,
            scanned <= MAX_MULTIVIEW_DIRECTORY_ENTRIES && candidates <= MAX_MULTIVIEW_CANDIDATES,
        ) {
            continue;
        }
        let language_priority = language
            .and_then(|language| {
                scope
                    .content_policy
                    .language_priority
                    .as_ref()?
                    .iter()
                    .position(|configured| configured.eq_ignore_ascii_case(language))
            })
            .map(|position| usize::MAX - position)
            .unwrap_or(0);
        let score = VariantScore {
            quality,
            media_specificity,
            language_priority,
        };
        match best.as_ref().map(|(best, _)| score.cmp(best)) {
            None | Some(CmpOrdering::Greater) => {
                best = Some((score, MultiView { name, file, meta }));
                ambiguous = false;
            }
            Some(CmpOrdering::Equal) => ambiguous = true,
            Some(CmpOrdering::Less) => {}
        }
    }
    if ambiguous {
        MultiViewsResult::MultipleChoices
    } else if let Some((_, selected)) = best {
        MultiViewsResult::Selected(selected)
    } else if saw_typed_variant {
        MultiViewsResult::NotAcceptable
    } else {
        MultiViewsResult::NotFound
    }
}

/// Directory descriptor for `/proc/self/fd`, opened once.  `readlinkat` on a
/// bare descriptor number avoids re-walking the `/proc/self/fd` prefix for
/// every target.  If procfs is unavailable we fall back to `read_link`.
fn proc_fd_dir() -> Option<&'static File> {
    static DIR: OnceLock<Option<File>> = OnceLock::new();
    DIR.get_or_init(|| File::open("/proc/self/fd").ok())
        .as_ref()
}

/// Render a non-negative descriptor as a NUL-terminated component name.
fn fd_component(fd: libc::c_int, buf: &mut [u8; 24]) -> &CStr {
    let mut pos = buf.len() - 1;
    buf[pos] = 0;
    let mut value = fd as u32;
    loop {
        pos -= 1;
        buf[pos] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    CStr::from_bytes_with_nul(&buf[pos..]).expect("fd component is NUL terminated")
}

/// Read the descriptor's `/proc/self/fd` link into a stack buffer and hand the
/// bytes to `f`.  Keeping the buffer local lets callers compare the resolved
/// path with the lexical target without allocating.
fn with_fd_link<R>(file: &File, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
    let mut buf = [0u8; 4096];
    let fd = file.as_raw_fd();
    let Some(dir) = proc_fd_dir() else {
        let path = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()?;
        let bytes = path.into_os_string().into_vec();
        return Some(f(&bytes));
    };
    let mut component = [0u8; 24];
    let name = fd_component(fd, &mut component);
    let n = unsafe {
        libc::readlinkat(
            dir.as_raw_fd(),
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n < 0 {
        return None;
    }
    let n = n as usize;
    if n == 0 {
        return None;
    }
    if n >= buf.len() {
        // A procfs link can exceed PATH_MAX once the kernel appends a
        // " (deleted)" suffix.  Preserve `read_link`'s growing allocation for
        // that rare case rather than falling back to the lexical path.
        let path = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()?;
        let bytes = path.into_os_string().into_vec();
        return Some(f(&bytes));
    }
    Some(f(&buf[..n]))
}

/// Resolve the absolute path of an already-opened descriptor.  Used to bind
/// authorization to the object actually opened rather than only to the URL
/// path that selected it.
pub fn fd_path(file: &File) -> Option<PathBuf> {
    with_fd_link(file, |bytes| {
        PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec()))
    })
}

/// Resolve an opened descriptor while borrowing `expected` when the kernel
/// reports the same path. Descriptor resolution is part of the authorization
/// boundary: failure must propagate instead of treating a potentially
/// symlinked target as its lexical pathname.
pub fn fd_path_cow<'a>(file: &File, expected: &'a Path) -> Option<Cow<'a, Path>> {
    with_fd_link(file, |bytes| {
        if bytes == expected.as_os_str().as_bytes() {
            Cow::Borrowed(expected)
        } else {
            Cow::Owned(PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())))
        }
    })
}

/// Open `root/rel` without ever escaping `root`.
pub fn resolve_target(root: &Path, rel: &Path, follow_symlinks: bool) -> Target {
    resolve_target_checked(root, rel, follow_symlinks, false)
}

const MAX_SYMLINKS: usize = 40;
const MAX_SYMLINK_BYTES: usize = 64 * 1024;
const MAX_OWNER_PATH_DIRECTORIES: usize = 64;

#[derive(Clone)]
enum OwnedPathComponent {
    Parent,
    Normal(OsString),
}

struct OwnerMatchedTarget {
    file: File,
    meta: Metadata,
    /// Present only for directories.  The full stack is retained so `..` in
    /// a subsequent relative symlink target cannot climb above the root.
    directories: Option<Vec<Arc<File>>>,
}

fn owner_path_components(path: &Path) -> io::Result<Vec<OwnedPathComponent>> {
    use std::path::Component;

    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => components.push(OwnedPathComponent::Parent),
            Component::Normal(name) => {
                components.push(OwnedPathComponent::Normal(name.to_os_string()))
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::from_raw_os_error(libc::EXDEV));
            }
        }
    }
    Ok(components)
}

fn open_component_nofollow(dir: &File, name: &OsString, flags: i32) -> io::Result<File> {
    let name =
        CString::new(name.as_bytes()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    openat2_file(
        dir,
        &name,
        &OpenHow {
            flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            mode: 0,
            // `name` is exactly one component and the parent is already
            // pinned. O_NOFOLLOW must be allowed to return an O_PATH handle
            // to a final symlink so its inode can be inspected.
            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
        },
    )
}

/// Reopen a non-symlink component with usable I/O flags while retaining the
/// identity established by the preceding `O_PATH|O_NOFOLLOW` probe.  Opening
/// the pathname twice without this comparison lets a concurrent rename swap
/// in a different file or directory after the owner-match decision.
fn reopen_pinned_component(
    dir: &File,
    name: &OsString,
    flags: i32,
    pinned: &Metadata,
) -> io::Result<File> {
    let file = open_component_nofollow(dir, name, flags)?;
    let reopened = file.metadata()?;
    if !vapache_verified::owner_component_reopen_admit(
        pinned.dev() == reopened.dev(),
        pinned.ino() == reopened.ino(),
    ) {
        return Err(io::Error::from_raw_os_error(libc::ESTALE));
    }
    Ok(file)
}

/// Read the contents of an already-open `O_PATH|O_NOFOLLOW` symlink.  Linux's
/// empty-path `readlinkat` form binds the bytes to that inode even if its
/// directory entry is concurrently replaced.
fn read_pinned_symlink(file: &File) -> io::Result<PathBuf> {
    let value = rustix::fs::readlinkat(file, "", Vec::with_capacity(256))
        .map_err(io::Error::from)?
        .into_bytes();
    if value.len() >= MAX_SYMLINK_BYTES {
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    Ok(PathBuf::from(OsString::from_vec(value)))
}

fn resolve_owner_components(
    mut directories: Vec<Arc<File>>,
    components: &[OwnedPathComponent],
    final_flags: i32,
    symlinks: &mut usize,
) -> io::Result<OwnerMatchedTarget> {
    if components.is_empty() {
        let file = directories
            .last()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EXDEV))?
            .try_clone()?;
        let meta = file.metadata()?;
        return Ok(OwnerMatchedTarget {
            file,
            meta,
            directories: Some(directories),
        });
    }

    let mut index = 0usize;
    while index < components.len() {
        match &components[index] {
            OwnedPathComponent::Parent => {
                if directories.len() == 1 {
                    return Err(io::Error::from_raw_os_error(libc::EXDEV));
                }
                directories.pop();
                index += 1;
            }
            OwnedPathComponent::Normal(name) => {
                let current = directories
                    .last()
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::EXDEV))?;
                let pinned = open_component_nofollow(current, name, libc::O_PATH)?;
                let pinned_meta = pinned.metadata()?;
                let remaining = &components[index + 1..];

                if pinned_meta.file_type().is_symlink() {
                    *symlinks += 1;
                    if *symlinks > MAX_SYMLINKS {
                        return Err(io::Error::from_raw_os_error(libc::ELOOP));
                    }
                    let target = read_pinned_symlink(&pinned)?;
                    let target_components = owner_path_components(&target)?;
                    let target_flags = if remaining.is_empty() {
                        final_flags
                    } else {
                        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_DIRECTORY | libc::O_NOFOLLOW
                    };
                    let resolved = resolve_owner_components(
                        directories.clone(),
                        &target_components,
                        target_flags,
                        symlinks,
                    )?;
                    if resolved.meta.uid() != pinned_meta.uid() {
                        return Err(io::Error::from_raw_os_error(libc::EACCES));
                    }
                    if remaining.is_empty() {
                        return Ok(resolved);
                    }
                    directories = resolved
                        .directories
                        .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOTDIR))?;
                    index += 1;
                    continue;
                }

                if !remaining.is_empty() {
                    if directories.len() >= MAX_OWNER_PATH_DIRECTORIES {
                        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
                    }
                    let directory = reopen_pinned_component(
                        current,
                        name,
                        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_DIRECTORY,
                        &pinned_meta,
                    )?;
                    directories.push(Arc::new(directory));
                    index += 1;
                    continue;
                }

                let file = reopen_pinned_component(current, name, final_flags, &pinned_meta)?;
                let meta = file.metadata()?;
                let directories = if meta.is_dir() {
                    if directories.len() >= MAX_OWNER_PATH_DIRECTORIES {
                        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
                    }
                    let directory = Arc::new(file);
                    let file = directory.try_clone()?;
                    directories.push(directory);
                    return Ok(OwnerMatchedTarget {
                        file,
                        meta,
                        directories: Some(directories),
                    });
                } else {
                    None
                };
                return Ok(OwnerMatchedTarget {
                    file,
                    meta,
                    directories,
                });
            }
        }
    }

    let file = directories
        .last()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EXDEV))?
        .try_clone()?;
    let meta = file.metadata()?;
    Ok(OwnerMatchedTarget {
        file,
        meta,
        directories: Some(directories),
    })
}

/// Resolve `root/rel` for `SymLinksIfOwnerMatch` without a pathname re-walk.
/// Every traversed directory and symlink is pinned before it is inspected, so
/// the ownership decision applies to the same object returned to the caller.
fn open_owner_matched(root: &Path, rel: &Path, flags: i32) -> io::Result<(File, Metadata)> {
    crate::fault::hit("fs.open_beneath")?;
    let root = root_file(root)?;
    let components = owner_path_components(rel)?;
    let mut symlinks = 0usize;
    let resolved = resolve_owner_components(vec![root], &components, flags, &mut symlinks)?;
    Ok((resolved.file, resolved.meta))
}

pub fn resolve_target_checked(
    root: &Path,
    rel: &Path,
    follow_symlinks: bool,
    owner_match_only: bool,
) -> Target {
    let mut flags = (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK) as u64;
    if rel.as_os_str().is_empty() {
        flags |= libc::O_DIRECTORY as u64;
    }
    let opened = if owner_match_only {
        open_owner_matched(root, rel, flags as i32).map(|(file, meta)| (file, Some(meta)))
    } else if rel.as_os_str().is_empty() {
        File::open(root).map(|file| (file, None))
    } else {
        open_beneath(root, rel, flags, follow_symlinks).map(|file| (file, None))
    };
    let (file, checked_meta) = match opened {
        Ok(opened) => opened,
        Err(e) => {
            return match e.raw_os_error() {
                Some(libc::ENOENT) | Some(libc::ENOTDIR) => Target::NotFound,
                Some(libc::EACCES) | Some(libc::ELOOP) | Some(libc::EXDEV) | Some(libc::EPERM) => {
                    Target::Forbidden
                }
                _ => Target::NotFound,
            }
        }
    };
    // An owned, successfully opened descriptor remains stat-able for its
    // lifetime on Unix; keep the defensive failure closed without requiring
    // an impossible-to-construct test fixture.
    let meta = match checked_meta.map_or_else(|| file.metadata(), Ok) {
        Ok(meta) => meta,
        // coverage:ignore-start - owned descriptor lifetime invariant
        Err(_) => return Target::Forbidden,
        // coverage:ignore-stop
    };
    if meta.is_dir() {
        Target::Directory { file, meta }
    } else if meta.is_file() {
        Target::File { file, meta }
    } else {
        // FIFOs, devices and sockets are never served.
        Target::Forbidden
    }
}

type OpenResult = Result<File, io::Error>;

thread_local! {
    /// Directory descriptors may be reused only within one request.  Keeping
    /// one across requests would pin a keep-alive worker to an old directory
    /// after an atomic `current -> release-N` deployment switch.
    static REQUEST_ROOT_FDS: RefCell<Option<Vec<(PathBuf, Arc<File>)>>> =
        const { RefCell::new(None) };

    /// Per-request metadata memoization.  Dispatch, policy construction and
    /// handler selection repeatedly ask the same question (is this path a
    /// directory, does this access file exist, what is its mtime?).  The cache
    /// is active only inside one outer request and is cleared by a drop guard;
    /// direct library calls outside dispatch always see fresh metadata.
    static REQUEST_METADATA: RefCell<Option<HashMap<PathBuf, Metadata>>> =
        const { RefCell::new(None) };
    static REQUEST_SYMLINK_METADATA: RefCell<Option<HashMap<PathBuf, Metadata>>> =
        const { RefCell::new(None) };
}

pub(crate) struct RequestMetadataGuard;

impl Drop for RequestMetadataGuard {
    fn drop(&mut self) {
        REQUEST_ROOT_FDS.with(|cache| *cache.borrow_mut() = None);
        REQUEST_METADATA.with(|cache| *cache.borrow_mut() = None);
        REQUEST_SYMLINK_METADATA.with(|cache| *cache.borrow_mut() = None);
    }
}

pub(crate) fn request_metadata_scope() -> RequestMetadataGuard {
    REQUEST_ROOT_FDS.with(|cache| *cache.borrow_mut() = Some(Vec::new()));
    REQUEST_METADATA.with(|cache| *cache.borrow_mut() = Some(HashMap::new()));
    REQUEST_SYMLINK_METADATA.with(|cache| *cache.borrow_mut() = Some(HashMap::new()));
    RequestMetadataGuard
}

/// `fs::metadata` with per-request memoization.  Only successful results are
/// cached; an error is re-probed so fail-closed error handling is unchanged.
pub(crate) fn metadata_cached(path: &Path) -> io::Result<Metadata> {
    REQUEST_METADATA.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(map) = cache.as_mut() {
            if let Some(meta) = map.get(path) {
                return Ok(meta.clone());
            }
            let meta = std::fs::metadata(path)?;
            map.insert(path.to_path_buf(), meta.clone());
            return Ok(meta);
        }
        std::fs::metadata(path)
    })
}

/// `fs::symlink_metadata` with per-request memoization, used by `<IfFile>`.
pub(crate) fn symlink_metadata_cached(path: &Path) -> io::Result<Metadata> {
    REQUEST_SYMLINK_METADATA.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(map) = cache.as_mut() {
            if let Some(meta) = map.get(path) {
                return Ok(meta.clone());
            }
            let meta = std::fs::symlink_metadata(path)?;
            map.insert(path.to_path_buf(), meta.clone());
            return Ok(meta);
        }
        std::fs::symlink_metadata(path)
    })
}

pub(crate) fn is_dir_cached(path: &Path) -> bool {
    metadata_cached(path)
        .map(|meta| meta.is_dir())
        .unwrap_or(false)
}

fn root_file(root: &Path) -> io::Result<Arc<File>> {
    // A pathname can be atomically rebound to another directory between
    // requests (the common `current -> release-N` deployment shape).  Caching
    // this descriptor by pathname across requests would keep a connection
    // thread pinned to the old tree after authorization and metadata walks
    // had moved to the new one.  A request-local cache retains a consistent
    // root for multi-step dispatch, then the guard drops it before the next
    // keep-alive request.
    REQUEST_ROOT_FDS.with(|cache| {
        let mut cache = cache.borrow_mut();
        let Some(cache) = cache.as_mut() else {
            return File::open(root).map(Arc::new);
        };
        if let Some((_, file)) = cache.iter().find(|(path, _)| path == root) {
            return Ok(file.clone());
        }
        let file = Arc::new(File::open(root)?);
        if cache.len() >= 16 {
            cache.remove(0);
        }
        cache.push((root.to_path_buf(), file.clone()));
        Ok(file)
    })
}

fn open_beneath(root: &Path, rel: &Path, flags: u64, follow: bool) -> OpenResult {
    crate::fault::hit("fs.open_beneath")?;
    let root_file = root_file(root)?;
    let rel_c = CString::new(rel.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let mut how = OpenHow {
        flags,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
    };
    if !follow {
        how.resolve |= RESOLVE_NO_SYMLINKS;
    }
    openat2_file(&root_file, &rel_c, &how)
}

/// Inspect a rewrite-controlled path through the same retained mapping-root
/// descriptor and kernel containment boundary used by dispatch.  `nofollow`
/// applies only to the final component: intermediate symlinks may resolve
/// within the root, while `RESOLVE_BENEATH` rejects an escape.
pub(crate) fn probe_beneath(
    root: &Path,
    rel: &Path,
    nofollow: bool,
) -> io::Result<(File, Metadata)> {
    if rel.as_os_str().is_empty() {
        if nofollow {
            return Err(io::Error::from_raw_os_error(libc::ELOOP));
        }
        let file = root_file(root)?.try_clone()?;
        let metadata = file.metadata()?;
        return Ok((file, metadata));
    }
    // O_PATH never opens the underlying device/FIFO, so it cannot block.
    // Linux openat2 rejects O_PATH|O_NONBLOCK as an invalid flag set.
    let mut flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
    if nofollow {
        flags |= libc::O_NOFOLLOW as u64;
    }
    let file = open_beneath(root, rel, flags, true)?;
    let metadata = file.metadata()?;
    Ok((file, metadata))
}

/// Open a request-controlled regular-file candidate for bounded reading
/// without re-walking an already-canonicalized pathname. The caller still
/// validates the descriptor type, size and version around the read.
pub(crate) fn open_read_beneath(root: &Path, rel: &Path) -> io::Result<(File, Metadata)> {
    if rel.as_os_str().is_empty() {
        let file = root_file(root)?.try_clone()?;
        let metadata = file.metadata()?;
        return Ok((file, metadata));
    }
    let flags = (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW) as u64;
    let file = open_beneath(root, rel, flags, true)?;
    let metadata = file.metadata()?;
    Ok((file, metadata))
}

/// Refuse to serve when the kernel cannot enforce descriptor-relative path
/// containment.  A canonicalize-then-open fallback has an unavoidable rename
/// race and is not an acceptable security boundary.
pub fn require_secure_path_resolution() -> io::Result<()> {
    let flags = (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY) as u64;
    let root = open_beneath(Path::new("/"), Path::new("."), flags, true).map_err(|error| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "secure path resolution requires Linux openat2 with RESOLVE_BENEATH and RESOLVE_NO_MAGICLINKS: {error}"
            ),
        )
    })?;
    if fd_path(&root).as_deref() != Some(Path::new("/")) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secure resolved-target authorization requires readable /proc/self/fd",
        ));
    }
    Ok(())
}

fn open_at(dir: &File, name: &[u8], follow: bool) -> OpenResult {
    let c = CString::new(name).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let mut how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
    };
    if !follow {
        how.resolve |= RESOLVE_NO_SYMLINKS;
    }
    openat2_file(dir, &c, &how)
}

/// Open one directory child under the effective symlink policy.  In
/// particular, `SymLinksIfOwnerMatch` must not be collapsed to ordinary
/// following for DirectoryIndex/cache probes or autoindex metadata.
fn open_at_with_symlink_policy(
    dir: &File,
    name: &[u8],
    follow_symlinks: bool,
    owner_match_only: bool,
) -> OpenResult {
    if !owner_match_only {
        return open_at(dir, name, follow_symlinks);
    }
    let component = OwnedPathComponent::Normal(OsString::from_vec(name.to_vec()));
    let mut symlinks = 0usize;
    let resolved = resolve_owner_components(
        vec![Arc::new(dir.try_clone()?)],
        &[component],
        libc::O_RDONLY | libc::O_NONBLOCK,
        &mut symlinks,
    )?;
    Ok(resolved.file)
}

pub fn mime_type(cfg: &Config, scope: &Scope, name: &[u8]) -> Option<String> {
    if let Some(ft) = &scope.content_policy.force_type {
        return Some(mime_with_charset(cfg, scope, name, ft.clone()));
    }
    // The overwhelmingly common case is a plain TypesConfig lookup with no
    // per-directory AddType/RemoveType overrides.  Avoid scanning and
    // lowercasing the extension when both override lists are empty.
    if scope.content_policy.remove_types.is_empty() && scope.content_policy.add_types.is_empty() {
        let t = cfg.mime.content_type(name)?;
        return Some(mime_with_charset(cfg, scope, name, t));
    }
    let extensions = crate::config::filename_extension_tokens(name);
    let removed = extensions.iter().any(|ext| {
        scope.content_policy.remove_types.iter().any(|configured| {
            let configured = configured.strip_prefix('.').unwrap_or(configured);
            std::str::from_utf8(ext).is_ok_and(|ext| configured.eq_ignore_ascii_case(ext))
        })
    });
    if removed {
        return None;
    }
    for ext in extensions.iter().rev() {
        let Some(ext) = std::str::from_utf8(ext).ok() else {
            continue;
        };
        for (ty, exts) in scope.content_policy.add_types.iter().rev() {
            if exts.split_ascii_whitespace().any(|configured| {
                configured
                    .strip_prefix('.')
                    .unwrap_or(configured)
                    .eq_ignore_ascii_case(ext)
            }) {
                return Some(mime_with_charset(cfg, scope, name, ty.clone()));
            }
        }
    }
    let t = cfg.mime.content_type(name)?;
    Some(mime_with_charset(cfg, scope, name, t))
}

fn mime_with_charset(cfg: &Config, scope: &Scope, name: &[u8], mut mime: String) -> String {
    // Apache's AddDefaultCharset filter applies to textual media types.  In
    // particular, a RewriteRule [T=application/...], ForceType application/...
    // or binary AddType must not acquire a charset parameter merely because
    // the server has a textual default configured.
    if !mime
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("text/"))
    {
        return mime;
    }
    let charset = cfg
        .mime
        .content_charset(name)
        .or(scope.content_policy.default_charset.as_deref());
    if let Some(charset) = charset {
        if !mime.to_ascii_lowercase().contains("charset=") {
            mime.push_str("; charset=");
            mime.push_str(charset);
        }
    }
    mime
}

fn etag(meta: &Metadata, bits: u32) -> String {
    let mut s = String::with_capacity(48);
    s.push('"');
    if bits & crate::config::ETAG_INODE != 0 {
        let _ = write!(s, "{:x}", meta.ino());
    }
    if bits & crate::config::ETAG_SIZE != 0 {
        let _ = write!(s, "-{:x}", meta.size());
    }
    if bits & crate::config::ETAG_MTIME != 0 {
        let _ = write!(s, "-{:x}", meta.mtime());
    }
    s.push('"');
    s
}

fn header_etag_list_matches(value: &[u8], etag: &str, weak: bool) -> bool {
    let v = std::str::from_utf8(value).unwrap_or("");
    for part in v.split(',') {
        let p = part.trim();
        if p == "*" {
            return true;
        }
        let (pw, pt) = if let Some(rest) = p.strip_prefix("W/") {
            (true, rest)
        } else {
            (false, p)
        };
        let (ew, et) = if let Some(rest) = etag.strip_prefix("W/") {
            (true, rest)
        } else {
            (false, etag)
        };
        if weak {
            if pt == et {
                return true;
            }
        } else if !pw && !ew && pt == et {
            return true;
        }
    }
    false
}

fn current_etag_matches(value: &[u8], etag: Option<&str>, weak: bool) -> bool {
    if std::str::from_utf8(value).is_ok_and(|value| value.split(',').any(|part| part.trim() == "*"))
    {
        return true;
    }
    etag.is_some_and(|etag| header_etag_list_matches(value, etag, weak))
}

fn representation_headers(
    mime: Option<&str>,
    encoding: Option<&str>,
    language: Option<&str>,
    last_mod: &str,
    tag: Option<&str>,
) -> Vec<(Cow<'static, str>, Vec<u8>)> {
    let mut headers = Vec::new();
    if let Some(mime) = mime {
        headers.push(("Content-Type".into(), mime.as_bytes().to_vec()));
    }
    if let Some(encoding) = encoding {
        headers.push(("Content-Encoding".into(), encoding.as_bytes().to_vec()));
    }
    if let Some(language) = language {
        headers.push(("Content-Language".into(), language.as_bytes().to_vec()));
    }
    headers.push(("Last-Modified".into(), last_mod.as_bytes().to_vec()));
    if let Some(tag) = tag {
        headers.push(("ETag".into(), tag.as_bytes().to_vec()));
    }
    headers.push(("Accept-Ranges".into(), b"bytes".to_vec()));
    headers
}

fn not_modified_response(
    scope: &Scope,
    mime: Option<&str>,
    encoding: Option<&str>,
    language: Option<&str>,
    last_mod: &str,
    tag: Option<&str>,
) -> Response {
    let mut response = Response::new(304);
    if let Some(mime) = mime {
        response
            .headers
            .push(("Content-Type".into(), mime.as_bytes().to_vec()));
    }
    if let Some(encoding) = encoding {
        response
            .headers
            .push(("Content-Encoding".into(), encoding.as_bytes().to_vec()));
    }
    if let Some(language) = language {
        response
            .headers
            .push(("Content-Language".into(), language.as_bytes().to_vec()));
    }
    response
        .headers
        .push(("Last-Modified".into(), last_mod.as_bytes().to_vec()));
    if let Some(tag) = tag {
        response
            .headers
            .push(("ETag".into(), tag.as_bytes().to_vec()));
    }
    if scope
        .header_policy
        .apply(&mut response.headers, true)
        .is_err()
    {
        return Response::policy_error();
    }
    response
}

/// RFC 9110 § 13.1.5 permits either one strong entity-tag or one HTTP date.
/// A weak tag (or a list accepted by the other conditional headers) must not
/// authorize a partial response because the bytes may be from a different
/// representation.
fn if_range_matches(value: &[u8], etag: Option<&str>, mtime: i64) -> bool {
    let Ok(value) = std::str::from_utf8(value) else {
        return false;
    };
    let value = value.trim();
    if value.starts_with("W/") {
        return false;
    }
    if value.starts_with('"') {
        return etag.is_some_and(|etag| !etag.starts_with("W/") && value == etag);
    }
    parse_http_date(value.as_bytes()).is_some_and(|time| time == mtime)
}

/// Serve an opened regular file, applying HTTP conditional and range rules.
fn serve_file_inner(
    cfg: &Config,
    scope: &Scope,
    req: &Request,
    file: File,
    meta: &Metadata,
    mime_name: &[u8],
    peer: std::net::IpAddr,
    local_ip: &str,
) -> Response {
    let size = meta.size();
    let mtime = meta.mtime();
    let etag_bits = scope.content_policy.file_etag.unwrap_or(ETAG_ALL);
    let tag = vapache_verified::file_etag_emit_admit(etag_bits).then(|| etag(meta, etag_bits));
    let last_mod = http_date(mtime);
    let mime = mime_type(cfg, scope, mime_name);
    let encoding = cfg.mime.content_encoding(mime_name);
    let language = cfg.mime.content_language(mime_name);
    let headers = representation_headers(
        mime.as_deref(),
        encoding,
        language,
        &last_mod,
        tag.as_deref(),
    );
    let mut representation = Response::new(200);
    representation.headers = headers.clone();
    if scope
        .header_policy
        .apply(&mut representation.headers, true)
        .is_err()
    {
        return Response::policy_error();
    }
    let validator_tag =
        crate::compression::conditional_static_etag(scope, req, &representation, mime_name, size);

    let is_get = req.method == "GET";
    let is_head = req.method == "HEAD";

    // RFC 9110 §13.2.2 evaluation order.
    if let Some(v) = req.header("if-match") {
        if !current_etag_matches(v, validator_tag.as_deref(), false) {
            return error_response(cfg, None, scope, 412, req, "", 0, "", peer, local_ip);
        }
    } else if let Some(v) = req.header("if-unmodified-since") {
        if let Some(t) = parse_http_date(v) {
            if mtime > t {
                return error_response(cfg, None, scope, 412, req, "", 0, "", peer, local_ip);
            }
        }
    }
    if let Some(v) = req.header("if-none-match") {
        if current_etag_matches(v, validator_tag.as_deref(), true) {
            if is_get || is_head {
                return not_modified_response(
                    scope,
                    mime.as_deref(),
                    encoding,
                    language,
                    &last_mod,
                    tag.as_deref(),
                );
            }
            return error_response(cfg, None, scope, 412, req, "", 0, "", peer, local_ip);
        }
    } else if is_get || is_head {
        if let Some(v) = req.header("if-modified-since") {
            if let Some(t) = parse_http_date(v) {
                if mtime <= t {
                    return not_modified_response(
                        scope,
                        mime.as_deref(),
                        encoding,
                        language,
                        &last_mod,
                        tag.as_deref(),
                    );
                }
            }
        }
    }

    let mut status = 200u16;
    let mut start = 0u64;
    let mut len = size;
    let mut content_range: Option<String> = None;

    if (is_get || is_head) && size > 0 {
        if let Some(range) = req.header("range") {
            let use_range = match req.header("if-range") {
                None => true,
                Some(ir) => if_range_matches(ir, tag.as_deref(), mtime),
            };
            if use_range {
                match parse_byte_range(range, size) {
                    RangeDecision::Satisfiable { start: s, end: e } => {
                        status = 206;
                        start = s;
                        len = e - s + 1;
                        content_range = Some(format!("bytes {s}-{e}/{size}"));
                    }
                    RangeDecision::Unsatisfiable => {
                        let mut r =
                            error_response(cfg, None, scope, 416, req, "", 0, "", peer, local_ip);
                        r.headers.push((
                            "Content-Range".into(),
                            format!("bytes */{size}").into_bytes(),
                        ));
                        return r;
                    }
                    RangeDecision::Ignore => {}
                }
            }
        }
    }

    if !(is_get || is_head) {
        // Apache answers unsupported methods on static resources with 405.
        let mut r = error_response(cfg, None, scope, 405, req, "", 0, "", peer, local_ip);
        r.headers
            .push(("Allow".into(), b"GET, HEAD, OPTIONS".to_vec()));
        return r;
    }

    let mut r = Response::new(status);
    r.headers = headers;
    if let Some(cr) = content_range {
        r.headers.push(("Content-Range".into(), cr.into_bytes()));
    }
    if scope.header_policy.apply(&mut r.headers, true).is_err() {
        return Response::policy_error();
    }
    if req.is_head() {
        r.headers
            .push(("Content-Length".into(), len.to_string().into_bytes()));
        r.body = Body::Empty;
    } else {
        r.body = Body::File {
            file,
            offset: start,
            len,
        };
    }
    r
}

pub fn serve_file(
    cfg: &Config,
    scope: &Scope,
    req: &Request,
    file: File,
    meta: &Metadata,
    fs_path: &std::path::Path,
    mime_name: &[u8],
    peer: std::net::IpAddr,
    local_ip: &str,
    grant: &crate::access::AccessGrant,
    resource: &crate::access::ResourceKey,
) -> Response {
    if !grant.require_sink(resource, vapache_verified::TransformSink::StaticFile)
        || resource.fs_path.as_deref() != Some(fs_path)
    {
        return error_response(cfg, None, scope, 500, req, "", 0, "", peer, local_ip);
    }
    let mut r = serve_file_inner(cfg, scope, req, file, meta, mime_name, peer, local_ip);
    crate::compression::finalize_budgeted(scope, req, &mut r, mime_name, &cfg.resource_budget);
    r
}

/// Production static-file entry point.  The caller cannot supply a scope,
/// grant, resource key, selected URL and resolved target independently: all
/// of them come from the same sink-bound authorization artifact.
pub fn serve_authorized_file(
    cfg: &Config,
    req: &Request,
    file: File,
    meta: &Metadata,
    fs_path: &std::path::Path,
    mime_name: &[u8],
    peer: std::net::IpAddr,
    local_ip: &str,
    authorization: &crate::access::AuthorizedOutcome,
) -> Response {
    if !authorization.require_file_sink(vapache_verified::TransformSink::StaticFile, fs_path, meta)
        || fd_path(&file).as_deref() != Some(fs_path)
    {
        return error_response(
            cfg,
            None,
            authorization.scope(),
            500,
            req,
            authorization.identity().public_url_path(),
            0,
            "",
            peer,
            local_ip,
        );
    }
    serve_file(
        cfg,
        authorization.scope(),
        req,
        file,
        meta,
        fs_path,
        mime_name,
        peer,
        local_ip,
        authorization.grant(),
        authorization.resource(),
    )
}

enum DirAction {
    Redirect(Vec<u8>),
    Index(File, Metadata, Vec<u8>),
    List(Vec<(Vec<u8>, bool, u64)>),
    Overloaded,
    Forbidden,
}

const MAX_AUTOINDEX_ENTRIES: usize = 4096;
const MAX_AUTOINDEX_BYTES: usize = 4 * 1024 * 1024;

fn version_name_cmp(left: &[u8], right: &[u8]) -> CmpOrdering {
    let (mut li, mut ri) = (0usize, 0usize);
    while li < left.len() && ri < right.len() {
        if left[li].is_ascii_digit() && right[ri].is_ascii_digit() {
            let (left_start, right_start) = (li, ri);
            while li < left.len() && left[li].is_ascii_digit() {
                li += 1;
            }
            while ri < right.len() && right[ri].is_ascii_digit() {
                ri += 1;
            }
            let left_digits = &left[left_start..li];
            let right_digits = &right[right_start..ri];
            let left_value = left_digits
                .iter()
                .position(|byte| *byte != b'0')
                .map(|index| &left_digits[index..])
                .unwrap_or(&left_digits[left_digits.len()..]);
            let right_value = right_digits
                .iter()
                .position(|byte| *byte != b'0')
                .map(|index| &right_digits[index..])
                .unwrap_or(&right_digits[right_digits.len()..]);
            let order = left_value
                .len()
                .cmp(&right_value.len())
                .then_with(|| left_value.cmp(right_value))
                .then_with(|| left_digits.len().cmp(&right_digits.len()));
            if order != CmpOrdering::Equal {
                return order;
            }
            continue;
        }
        let order = left[li]
            .to_ascii_lowercase()
            .cmp(&right[ri].to_ascii_lowercase());
        if order != CmpOrdering::Equal {
            return order;
        }
        li += 1;
        ri += 1;
    }
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn directory_action(
    cfg: &Config,
    scope: &Scope,
    req: &Request,
    dir: &File,
    url_path: &str,
    raw_path: &[u8],
    follow_symlinks: bool,
    owner_match_only: bool,
) -> DirAction {
    let has_slash = url_path.ends_with('/');
    let slash_enabled = scope.content_policy.directory_slash.unwrap_or(true);
    if !has_slash && slash_enabled {
        let mut loc = raw_path.to_vec();
        loc.push(b'/');
        if !req.query.is_empty() {
            loc.push(b'?');
            loc.extend_from_slice(&url_encode_query(&req.query));
        }
        return DirAction::Redirect(loc);
    }
    for name in cfg.directory_index_for(scope) {
        if req
            .charge_policy_work((name.len() as u64).saturating_add(1))
            .is_err()
        {
            return DirAction::Overloaded;
        }
        if name.contains('/') || name == ".." || name == "." || name.is_empty() {
            continue;
        }
        if let Ok(f) =
            open_at_with_symlink_policy(dir, name.as_bytes(), follow_symlinks, owner_match_only)
        {
            if let Ok(m) = f.metadata() {
                if m.is_file() {
                    return DirAction::Index(f, m, name.into_bytes());
                }
            }
        }
    }
    if scope
        .effective_options()
        .contains(crate::config::Options::INDEXES)
        && vapache_verified::capability_admit(
            cfg.capability_enabled(crate::config::Capability::AutoIndex),
            true,
        )
    {
        let Some(_expensive) = crate::resource::try_expensive() else {
            return DirAction::Overloaded;
        };
        let path = format!("/proc/self/fd/{}", dir.as_raw_fd());
        let mut entries: Vec<(Vec<u8>, bool, u64)> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(path) {
            let mut scanned = 0u64;
            for result in rd {
                // Count every directory record, including unreadable and
                // filtered dot/backup names. Otherwise an upload directory
                // full of hidden entries could evade the rendered-entry cap
                // while still forcing an unbounded readdir walk.
                if !vapache_verified::autoindex_append_admit(
                    scanned,
                    1,
                    MAX_AUTOINDEX_ENTRIES as u64,
                ) {
                    return DirAction::Overloaded;
                }
                scanned += 1;
                let Ok(ent) = result else {
                    continue;
                };
                let name = ent.file_name().as_encoded_bytes().to_vec();
                if name.starts_with(b".") {
                    continue;
                }
                let mut ignored = false;
                for pattern in &scope.content_policy.index_ignore {
                    match crate::glob::fnmatch_budgeted(
                        pattern.as_bytes(),
                        &name,
                        false,
                        req.policy_budget(),
                    ) {
                        Ok(true) => {
                            ignored = true;
                            break;
                        }
                        Ok(false) => {}
                        Err(_) => return DirAction::Overloaded,
                    }
                }
                if ignored {
                    continue;
                }
                if name.ends_with(b"~") || name.starts_with(b"#") {
                    continue;
                }
                if !vapache_verified::autoindex_append_admit(
                    entries.len() as u64,
                    1,
                    MAX_AUTOINDEX_ENTRIES as u64,
                ) {
                    return DirAction::Overloaded;
                }
                // Never follow an autoindex entry with an unconfined pathname
                // stat. The same descriptor-relative symlink policy used by
                // serving decides whether target metadata may be disclosed.
                let meta =
                    open_at_with_symlink_policy(dir, &name, follow_symlinks, owner_match_only)
                        .and_then(|file| file.metadata())
                        .ok();
                let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                let size = meta.as_ref().map(|m| m.size()).unwrap_or(0);
                entries.push((name, is_dir, size));
            }
        }
        let version_sort = scope.content_policy.autoindex.version_sort.unwrap_or(false);
        entries.sort_by(|a, b| {
            b.1.cmp(&a.1).then_with(|| {
                if version_sort {
                    version_name_cmp(&a.0, &b.0)
                } else {
                    a.0.to_ascii_lowercase().cmp(&b.0.to_ascii_lowercase())
                }
            })
        });
        return DirAction::List(entries);
    }
    DirAction::Forbidden
}

/// The configured directory index selected for a directory target, including
/// the opened file descriptor and metadata.  Cache authorization uses this to
/// bind its key/policy fingerprint to the actual index target (F52) before the
/// internal subrequest runs.
pub struct DirectoryIndex {
    pub name: Vec<u8>,
    pub file: File,
    pub meta: Metadata,
}

pub fn directory_index_target(
    cfg: &Config,
    scope: &Scope,
    req: &Request,
    dir: &File,
    url_path: &str,
    raw_path: &[u8],
) -> Option<DirectoryIndex> {
    let options = scope.effective_options();
    let follow_symlinks = options.contains(crate::config::Options::FOLLOW_SYMLINKS);
    let owner_match_only =
        !follow_symlinks && options.contains(crate::config::Options::SYMLINKS_IF_OWNER_MATCH);
    match directory_action(
        cfg,
        scope,
        req,
        dir,
        url_path,
        raw_path,
        follow_symlinks,
        owner_match_only,
    ) {
        DirAction::Index(file, meta, name) => Some(DirectoryIndex { name, file, meta }),
        _ => None,
    }
}

/// Return the configured directory index filename when the directory should
/// serve one.  The caller is expected to perform an internal subrequest so
/// handlers (CGI, FastCGI, filters) run exactly as for a direct request.
pub fn directory_index_name(
    cfg: &Config,
    scope: &Scope,
    req: &Request,
    dir: &File,
    url_path: &str,
    raw_path: &[u8],
) -> Option<Vec<u8>> {
    directory_index_target(cfg, scope, req, dir, url_path, raw_path).map(|target| target.name)
}

/// Serve a directory target (index file, autoindex or redirect).
fn serve_directory_inner(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &Scope,
    req: &Request,
    dir: File,
    url_path: &str,
    raw_path: &[u8],
    host: &str,
    port: u16,
    peer: std::net::IpAddr,
    local_ip: &str,
) -> Response {
    let options = scope.effective_options();
    let follow_symlinks = options.contains(crate::config::Options::FOLLOW_SYMLINKS);
    let owner_match_only =
        !follow_symlinks && options.contains(crate::config::Options::SYMLINKS_IF_OWNER_MATCH);
    match directory_action(
        cfg,
        scope,
        req,
        &dir,
        url_path,
        raw_path,
        follow_symlinks,
        owner_match_only,
    ) {
        DirAction::Redirect(loc) => {
            let canonical_authority = if (!crate::expr::request_is_https() && port == 80)
                || (crate::expr::request_is_https() && port == 443)
            {
                host.to_string()
            } else {
                format!("{host}:{port}")
            };
            let authority = if cfg.use_canonical_name {
                vhost
                    .and_then(|v| v.server_name.as_deref())
                    .or(cfg.server_name.as_deref())
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(str::to_string)
                    .unwrap_or(canonical_authority)
            } else {
                req.header_str("host")
                    .map(str::trim)
                    .filter(|h| !h.is_empty())
                    .map(str::to_string)
                    .unwrap_or(canonical_authority)
            };
            let scheme = if crate::expr::request_is_https() {
                "https"
            } else {
                "http"
            };
            let loc = if loc.starts_with(b"/") {
                let mut absolute = format!("{scheme}://{authority}").into_bytes();
                absolute.extend_from_slice(&loc);
                absolute
            } else {
                loc
            };
            let mut r = Response::new(301);
            r.headers.push(("Location".into(), loc.clone()));
            r.headers.push((
                "Content-Type".into(),
                b"text/html; charset=iso-8859-1".to_vec(),
            ));
            let body = format!(
                "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>301 Moved Permanently</title>\n</head><body>\n<h1>Moved Permanently</h1>\n<p>The document has moved <a href=\"{}\">here</a>.</p>\n</body></html>\n",
                html_escape(&loc)
            );
            r.body = Body::Bytes(body.into_bytes());
            r
        }
        DirAction::Index(_, _, name) => {
            let index_url = format!(
                "{}/{}",
                url_path.trim_end_matches('/'),
                String::from_utf8_lossy(&name)
            );
            crate::server::internal_dispatch(
                cfg,
                req,
                &index_url,
                vapache_verified::InternalRequestKind::DirectoryIndex,
                None,
                vhost,
                host,
                std::net::SocketAddr::new(peer, 0),
                local_ip,
                port,
            )
        }
        DirAction::List(entries) => match authorized_autoindex_entries(
            cfg,
            vhost,
            scope,
            req,
            &dir,
            url_path,
            entries,
            follow_symlinks,
            owner_match_only,
            host,
            port,
            peer,
            local_ip,
        ) {
            Ok(entries) => autoindex(cfg, scope, req, url_path, &entries, host, port),
            Err(response) => response,
        },
        DirAction::Overloaded => Response::bytes(
            503,
            "text/html; charset=UTF-8",
            b"Directory listing capacity is temporarily exhausted\n".to_vec(),
        ),
        DirAction::Forbidden => error_response(
            cfg, vhost, scope, 403, req, url_path, port, host, peer, local_ip,
        ),
    }
}

/// Re-open each bounded directory entry and authorize its exact URL and
/// descriptor-resolved filesystem identity before exposing name/type/size.
/// The initial scan intentionally does no policy work so DirectoryIndex probes
/// and capacity accounting remain bounded; this second pass is the autoindex
/// metadata sink gate.
#[allow(clippy::too_many_arguments)]
fn authorized_autoindex_entries(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &Scope,
    req: &Request,
    dir: &File,
    url_path: &str,
    entries: Vec<(Vec<u8>, bool, u64)>,
    follow_symlinks: bool,
    owner_match_only: bool,
    host: &str,
    port: u16,
    peer: std::net::IpAddr,
    local_ip: &str,
) -> Result<Vec<(Vec<u8>, bool, u64)>, Response> {
    let mut visible = Vec::with_capacity(entries.len());
    for (name, _, _) in entries {
        let Ok(file) = open_at_with_symlink_policy(dir, &name, follow_symlinks, owner_match_only)
        else {
            continue;
        };
        let Ok(meta) = file.metadata() else {
            continue;
        };
        let Some(actual_path) = fd_path(&file) else {
            return Err(Response::policy_error());
        };
        let mut target_url = format!(
            "{}/{}",
            url_path.trim_end_matches('/'),
            crate::util::url_encode_path(&name)
        );
        if meta.is_dir() {
            target_url.push('/');
        }
        if crate::server::autoindex_entry_visible(
            cfg,
            vhost,
            req,
            peer,
            &actual_path,
            &target_url,
            scope,
            port,
            host,
            local_ip,
        )? {
            visible.push((name, meta.is_dir(), meta.size()));
        }
    }
    Ok(visible)
}

pub fn serve_directory(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &Scope,
    req: &Request,
    dir: File,
    meta: &Metadata,
    fs_path: &std::path::Path,
    url_path: &str,
    raw_path: &[u8],
    host: &str,
    port: u16,
    peer: std::net::IpAddr,
    local_ip: &str,
    grant: &crate::access::AccessGrant,
    resource: &crate::access::ResourceKey,
) -> Response {
    if !grant.require_sink(resource, vapache_verified::TransformSink::Directory)
        || resource.fs_path.as_deref() != Some(fs_path)
    {
        return error_response(
            cfg, vhost, scope, 500, req, url_path, port, host, peer, local_ip,
        );
    }
    let mut r = serve_directory_inner(
        cfg, vhost, scope, req, dir, url_path, raw_path, host, port, peer, local_ip,
    );
    if scope
        .header_policy
        .apply(&mut r.headers, r.status < 400)
        .is_err()
    {
        return Response::policy_error();
    }
    crate::compression::finalize_budgeted(
        scope,
        req,
        &mut r,
        url_path.as_bytes(),
        &cfg.resource_budget,
    );
    r
}

/// Production directory entry point paired with [`serve_authorized_file`].
#[allow(clippy::too_many_arguments)]
pub fn serve_authorized_directory(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    dir: File,
    meta: &Metadata,
    fs_path: &std::path::Path,
    url_path: &str,
    raw_path: &[u8],
    host: &str,
    port: u16,
    peer: std::net::IpAddr,
    local_ip: &str,
    authorization: &crate::access::AuthorizedOutcome,
) -> Response {
    if !authorization.require_file_sink(vapache_verified::TransformSink::Directory, fs_path, meta)
        || fd_path(&dir).as_deref() != Some(fs_path)
    {
        return error_response(
            cfg,
            vhost,
            authorization.scope(),
            500,
            req,
            authorization.identity().public_url_path(),
            port,
            host,
            peer,
            local_ip,
        );
    }
    serve_directory(
        cfg,
        vhost,
        authorization.scope(),
        req,
        dir,
        meta,
        fs_path,
        url_path,
        raw_path,
        host,
        port,
        peer,
        local_ip,
        authorization.grant(),
        authorization.resource(),
    )
}

fn autoindex(
    cfg: &Config,
    scope: &Scope,
    req: &Request,
    url_path: &str,
    entries: &[(Vec<u8>, bool, u64)],
    host: &str,
    port: u16,
) -> Response {
    if entries.len() > MAX_AUTOINDEX_ENTRIES {
        return Response::bytes(
            503,
            "text/html; charset=UTF-8",
            b"Directory listing capacity is temporarily exhausted\n".to_vec(),
        );
    }
    // Compute a conservative expansion bound before constructing attacker-
    // influenced names and rows. A byte can expand to at most three bytes in
    // the href and five in HTML text; fixed row/document overhead and the
    // optional signature fit in the margin.
    let estimated = entries.iter().try_fold(
        (64 * 1024usize).saturating_add(url_path.len().saturating_mul(6)),
        |total, (name, is_dir, _)| {
            let icon = autoindex_icon(cfg, scope, name, *is_dir);
            let icon_bytes = icon
                .map(|icon| {
                    icon.url
                        .len()
                        .saturating_mul(5)
                        .saturating_add(icon.alt.len().saturating_mul(5))
                })
                .unwrap_or(0);
            total.checked_add(
                name.len()
                    .saturating_mul(9)
                    .saturating_add(icon_bytes)
                    .saturating_add(192),
            )
        },
    );
    let Some(estimated) =
        estimated.filter(|size| *size <= MAX_AUTOINDEX_BYTES.saturating_add(64 * 1024))
    else {
        return Response::bytes(
            503,
            "text/html; charset=UTF-8",
            b"Directory listing capacity is temporarily exhausted\n".to_vec(),
        );
    };
    #[cfg(test)]
    let fallback_context;
    let resource_context = match req.resource_context() {
        Some(context) => context,
        #[cfg(test)]
        None => {
            fallback_context = cfg
                .resource_budget
                .context(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
            &fallback_context
        }
        #[cfg(not(test))]
        None => {
            return Response::bytes(
                503,
                "text/html; charset=UTF-8",
                b"Directory listing capacity is temporarily exhausted\n".to_vec(),
            );
        }
    };
    let Ok(mut resident) = cfg.resource_budget.try_response_bytes_in(resource_context) else {
        return Response::bytes(
            503,
            "text/html; charset=UTF-8",
            b"Directory listing capacity is temporarily exhausted\n".to_vec(),
        );
    };
    if resident.reserve(estimated as u64).is_err() {
        return Response::bytes(
            503,
            "text/html; charset=UTF-8",
            b"Directory listing capacity is temporarily exhausted\n".to_vec(),
        );
    }
    let title = format!("Index of {}", html_escape(url_path.as_bytes()));
    let mut body = String::new();
    body.push_str(
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n<html>\n <head>\n  <title>",
    );
    body.push_str(&title);
    body.push_str("</title>\n </head>\n <body>\n<h1>");
    body.push_str(&title);
    body.push_str("</h1>\n");
    append_autoindex_named_link(
        &mut body,
        entries,
        scope.content_policy.autoindex.header_name.as_deref(),
        "Header",
    );
    body.push_str("  <table>\n");
    if url_path != "/" {
        body.push_str("   <tr>");
        append_autoindex_icon(&mut body, autoindex_icon(cfg, scope, b"..", true));
        body.push_str("<td><a href=\"../\">Parent Directory</a></td></tr>\n");
    }
    for (name, is_dir, size) in entries {
        let mut href = crate::util::safe_relative_href(name);
        if *is_dir {
            href.push('/');
        }
        let mut row = String::new();
        row.push_str("   <tr>");
        append_autoindex_icon(&mut row, autoindex_icon(cfg, scope, name, *is_dir));
        row.push_str("<td><a href=\"");
        row.push_str(&href);
        row.push_str("\">");
        row.push_str(&html_escape(name));
        if *is_dir {
            row.push('/');
        }
        row.push_str("</a></td><td>");
        if *is_dir {
            row.push_str("-");
        } else {
            row.push_str(&size.to_string());
        }
        row.push_str("</td></tr>\n");
        if !vapache_verified::autoindex_append_admit(
            body.len() as u64,
            row.len() as u64,
            MAX_AUTOINDEX_BYTES as u64,
        ) {
            return Response::bytes(
                503,
                "text/html; charset=UTF-8",
                b"Directory listing capacity is temporarily exhausted\n".to_vec(),
            );
        }
        body.push_str(&row);
    }
    body.push_str("  </table>\n");
    append_autoindex_named_link(
        &mut body,
        entries,
        scope.content_policy.autoindex.readme_name.as_deref(),
        "Readme",
    );
    add_signature(&mut body, cfg, host, port);
    body.push_str(" </body>\n</html>\n");
    let mut response = Response::bytes(200, "text/html; charset=UTF-8", body.into_bytes());
    resident.release(resident.bytes().saturating_sub(response.body_len()));
    response.hold_resident(resident);
    response
}

fn autoindex_icon<'a>(
    cfg: &Config,
    scope: &'a Scope,
    name: &[u8],
    is_dir: bool,
) -> Option<&'a AutoIndexIcon> {
    let media_type = mime_type(cfg, scope, name);
    let media_type = media_type
        .as_deref()
        .and_then(|value| value.split(';').next());
    let encoding = cfg.mime.content_encoding(name);
    for rule in &scope.content_policy.autoindex.icon_rules {
        let matched = rule.patterns.iter().any(|pattern| match rule.kind {
            AutoIndexIconMatch::Name => {
                (pattern == "^^DIRECTORY^^" && is_dir)
                    || (pattern != "^^DIRECTORY^^"
                        && pattern != "^^BLANKICON^^"
                        && if pattern.starts_with('.') {
                            name.len() >= pattern.len()
                                && name[name.len() - pattern.len()..]
                                    .eq_ignore_ascii_case(pattern.as_bytes())
                        } else {
                            name.eq_ignore_ascii_case(pattern.as_bytes())
                        })
            }
            AutoIndexIconMatch::MediaType => media_type.is_some_and(|media_type| {
                if let Some(prefix) = pattern.strip_suffix("/*") {
                    media_type
                        .get(..prefix.len())
                        .is_some_and(|major| major.eq_ignore_ascii_case(prefix))
                        && media_type.as_bytes().get(prefix.len()) == Some(&b'/')
                } else {
                    media_type.eq_ignore_ascii_case(pattern)
                }
            }),
            AutoIndexIconMatch::Encoding => {
                encoding.is_some_and(|encoding| encoding.eq_ignore_ascii_case(pattern))
            }
        });
        if matched {
            return Some(&rule.icon);
        }
    }
    scope.content_policy.autoindex.default_icon.as_ref()
}

fn append_autoindex_icon(body: &mut String, icon: Option<&AutoIndexIcon>) {
    body.push_str("<td>");
    if let Some(icon) = icon {
        body.push_str("<img src=\"");
        body.push_str(&html_escape(icon.url.as_bytes()));
        body.push_str("\" alt=\"[");
        body.push_str(&html_escape(icon.alt.as_bytes()));
        body.push_str("]\"></td>");
    } else {
        body.push_str("</td>");
    }
}

fn append_autoindex_named_link(
    body: &mut String,
    entries: &[(Vec<u8>, bool, u64)],
    configured: Option<&str>,
    label: &str,
) {
    let Some(name) = configured else {
        return;
    };
    if !entries
        .iter()
        .any(|(entry, is_dir, _)| !is_dir && entry.eq_ignore_ascii_case(name.as_bytes()))
    {
        return;
    }
    body.push_str("<p>");
    body.push_str(label);
    body.push_str(": <a href=\"");
    body.push_str(&crate::util::safe_relative_href(name.as_bytes()));
    body.push_str("\">");
    body.push_str(&html_escape(name.as_bytes()));
    body.push_str("</a></p>\n");
}

fn add_signature(body: &mut String, cfg: &Config, host: &str, port: u16) {
    if cfg.server_signature == ServerSignature::Off {
        return;
    }
    body.push_str("<hr>\n<address>");
    body.push_str(&html_escape(cfg.server_header().as_bytes()));
    if cfg.server_signature == ServerSignature::Email {
        body.push_str(" Server at ");
        body.push_str(&html_escape(host.as_bytes()));
        body.push_str(" Port ");
        body.push_str(&port.to_string());
    } else {
        body.push_str(" Server at ");
        body.push_str(&html_escape(host.as_bytes()));
        body.push_str(" Port ");
        body.push_str(&port.to_string());
    }
    body.push_str("</address>\n");
}

fn error_response_inner(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &Scope,
    status: u16,
    req: &Request,
    url_path: &str,
    port: u16,
    host: &str,
    peer: std::net::IpAddr,
    local_ip: &str,
) -> Response {
    if let Some(doc) = scope.error_document(status) {
        match doc {
            ErrorDoc::Text(t) => {
                return Response::bytes(
                    status,
                    "text/html; charset=iso-8859-1",
                    t.as_bytes().to_vec(),
                )
            }
            ErrorDoc::External(url) => {
                let mut r = Response::bytes(
                    302,
                    "text/html; charset=iso-8859-1",
                    format!(
                        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>302 Found</title>\n</head><body>\n<h1>Found</h1>\n<p>The document has moved <a href=\"{}\">here</a>.</p>\n</body></html>\n",
                        html_escape(url.as_bytes())
                    )
                    .into_bytes(),
                );
                r.headers.push(("Location".into(), url.as_bytes().to_vec()));
                return r;
            }
            ErrorDoc::Local(path) => {
                if let Some(r) =
                    serve_error_document(cfg, vhost, req, path, status, peer, local_ip, port, host)
                {
                    return r;
                }
            }
        }
    }
    default_error_response(cfg, status, url_path, port, host)
}

fn default_error_response(
    cfg: &Config,
    status: u16,
    url_path: &str,
    port: u16,
    host: &str,
) -> Response {
    let reason = reason_phrase(status);
    let mut body = String::new();
    body.push_str("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>");
    body.push_str(&format!("{status} {reason}"));
    body.push_str("</title>\n</head><body>\n<h1>");
    body.push_str(reason);
    body.push_str("</h1>\n<p>");
    body.push_str(&error_message(status, url_path));
    body.push_str("</p>\n");
    add_signature(&mut body, cfg, host, port);
    body.push_str("</body></html>\n");
    let mut r = Response::bytes(status, "text/html; charset=iso-8859-1", body.into_bytes());
    r.headers.push((
        "Cache-Control".into(),
        if status >= 400 {
            b"no-store".to_vec()
        } else {
            b"no-cache".to_vec()
        },
    ));
    r
}

pub fn error_response(
    cfg: &Config,
    vhost: Option<&VHost>,
    scope: &Scope,
    status: u16,
    req: &Request,
    url_path: &str,
    port: u16,
    host: &str,
    peer: std::net::IpAddr,
    local_ip: &str,
) -> Response {
    let mut r = error_response_inner(
        cfg, vhost, scope, status, req, url_path, port, host, peer, local_ip,
    );
    if r.has_prepared_handler() {
        let handler = r
            .take_prepared_handler()
            .expect("prepared ErrorDocument response retained its handler");
        return Response::prepared_handler(crate::server::PreparedHandler::FinalizeErrorDocument {
            handler: Box::new(handler),
            scope: scope.clone(),
            status,
            url_path: url_path.to_string(),
            internal_target: match scope.error_document(status) {
                Some(ErrorDoc::Local(path)) => path.clone(),
                _ => unreachable!("a prepared local ErrorDocument retained its target"),
            },
            port,
            host: host.to_string(),
        });
    }
    // Only `Header always` applies to error responses.
    if scope.header_policy.apply(&mut r.headers, false).is_err() {
        return Response::policy_error();
    }
    crate::compression::finalize_budgeted(
        scope,
        req,
        &mut r,
        url_path.as_bytes(),
        &cfg.resource_budget,
    );
    r
}

fn error_message(status: u16, url: &str) -> String {
    let url = html_escape(url.as_bytes());
    match status {
        300 => "The requested resource has multiple available representations.".into(),
        400 => "Your browser sent a request that this server could not understand.".into(),
        401 => "This server could not verify that you are authorized to access the document requested.".into(),
        403 => format!("You don't have permission to access this resource."),
        404 => format!("The requested URL {url} was not found on this server."),
        405 => "The requested method is not allowed for this URL.".into(),
        406 => "No representation of the requested resource is acceptable to this client.".into(),
        408 => "The server closed the network connection because the browser didn't finish the request within the specified time.".into(),
        412 => "The precondition on the request for the URL failed positive evaluation.".into(),
        413 => "The requested resource does not allow request data with the requested method.".into(),
        414 => "The requested URL's length exceeds the capacity limit for this server.".into(),
        416 => "The requested range is not satisfiable.".into(),
        431 => "The server is unwilling to process the request because its header fields are too large.".into(),
        500 => "The server encountered an internal error or misconfiguration and was unable to complete your request.".into(),
        501 => "The server does not support the action requested by the browser.".into(),
        503 => "The server is temporarily unable to service your request due to maintenance downtime or capacity problems.".into(),
        505 => "The server does not support the HTTP protocol version used in the request.".into(),
        _ => "An unexpected error occurred.".into(),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn finalize_prepared_error_document(
    cfg: &Config,
    scope: &Scope,
    status: u16,
    req: &Request,
    url_path: &str,
    port: u16,
    host: &str,
    mut response: Response,
) -> Response {
    if response.status >= 300 {
        response = default_error_response(cfg, status, url_path, port, host);
    } else {
        response.status = status;
    }
    // Provenance must travel with the response across async scheduling and
    // cache-store boundaries. A thread-local marker can be reset by another
    // request and is unnecessary when the response already owns this bit.
    response.forbid_shared_cache();
    if scope
        .header_policy
        .apply(&mut response.headers, false)
        .is_err()
    {
        return Response::policy_error();
    }
    crate::compression::finalize_budgeted(
        scope,
        req,
        &mut response,
        url_path.as_bytes(),
        &cfg.resource_budget,
    );
    response
}

fn serve_error_document(
    cfg: &Config,
    vhost: Option<&VHost>,
    req: &Request,
    path: &str,
    status: u16,
    peer: std::net::IpAddr,
    local_ip: &str,
    local_port: u16,
    server_name: &str,
) -> Option<Response> {
    // Avoid recursion when an error document itself fails. The depth follows
    // the request, so unrelated async tasks cannot affect this decision.
    if req.error_document_depth() >= 1 {
        return None;
    }
    let mut response = crate::server::internal_dispatch(
        cfg,
        req,
        path,
        vapache_verified::InternalRequestKind::ErrorDocument,
        None,
        vhost,
        server_name,
        std::net::SocketAddr::new(peer, 0),
        local_ip,
        local_port,
    );
    if response.status >= 300 {
        return None;
    }
    response.status = status;
    response.forbid_shared_cache();
    Some(response)
}

/// Build a small `text/html` response used for OPTIONS and redirects.
pub fn simple_html(status: u16, message: &str, location: Option<&str>) -> Response {
    let reason = reason_phrase(status);
    let mut r = Response::bytes(
        status,
        "text/html; charset=iso-8859-1",
        format!(
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>{status} {reason}</title>\n</head><body>\n<h1>{reason}</h1>\n<p>{}</p>\n</body></html>\n",
            html_escape(message.as_bytes())
        )
        .into_bytes(),
    );
    if let Some(l) = location {
        r.headers.push(("Location".into(), l.as_bytes().to_vec()));
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Headers, Version};
    use std::collections::HashMap;
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::unix::fs::PermissionsExt;

    fn request(method: &str, path: &[u8]) -> Request {
        Request {
            method: method.into(),
            target: path.to_vec(),
            raw_path: path.to_vec(),
            query: Vec::new(),
            version: Version::Http11,
            headers: Headers::default(),
            body: Vec::new(),
            body_spool: None,
            keep_alive: true,
            expect_continue: false,
            framing: crate::verified::BodyFraming::None,
        }
    }

    fn config(name: &str) -> (PathBuf, Config) {
        let dir = std::env::temp_dir().join(format!("vapache-files-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("httpd.conf");
        std::fs::write(
            &conf,
            format!(
                "{}Listen 127.0.0.1:0\nDocumentRoot {}\n",
                crate::config::TEST_CAPABILITIES,
                dir.display()
            ),
        )
        .unwrap();
        let cfg = Config::load(&conf, &dir, &HashMap::new(), &HashMap::new(), false).unwrap();
        (dir, cfg)
    }

    #[test]
    fn multiviews_selects_only_acceptable_typed_static_variants() {
        let (root, mut cfg) = config("multiview-static");
        std::fs::write(root.join("app.js"), b"selected").unwrap();
        cfg.mime
            .add_type("application/javascript", &["js".to_string()]);
        let mut scope = cfg.global.clone();
        scope.options.push_add(crate::config::Options::MULTIVIEWS);

        let req = request("GET", b"/app");
        let MultiViewsResult::Selected(mut selected) =
            multiviews_target(&cfg, &scope, &req, &root, Path::new("app"), false, false)
        else {
            panic!("typed static representation was not selected");
        };
        assert_eq!(selected.name, b"app.js");
        let mut body = String::new();
        selected.file.read_to_string(&mut body).unwrap();
        assert_eq!(body, "selected");

        let mut unacceptable = request("GET", b"/app");
        unacceptable
            .headers
            .insert("accept", b"text/plain".to_vec());
        assert!(matches!(
            multiviews_target(
                &cfg,
                &scope,
                &unacceptable,
                &root,
                Path::new("app"),
                false,
                false,
            ),
            MultiViewsResult::NotAcceptable
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn multiviews_never_promotes_a_handler_candidate() {
        let (root, mut cfg) = config("multiview-handler");
        std::fs::write(root.join("tool.cgi"), b"not executed").unwrap();
        cfg.mime.add_type("application/x-cgi", &["cgi".to_string()]);
        let mut scope = cfg.global.clone();
        scope.options.push_add(crate::config::Options::MULTIVIEWS);
        scope
            .mapping_policy
            .handlers
            .push(crate::config::Handler::add(
                "cgi".into(),
                "cgi-script".into(),
            ));

        assert!(matches!(
            multiviews_target(
                &cfg,
                &scope,
                &request("GET", b"/tool"),
                &root,
                Path::new("tool"),
                false,
                false,
            ),
            MultiViewsResult::NotFound
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn multiviews_reports_ambiguous_and_bounded_candidate_sets() {
        let (root, mut cfg) = config("multiview-bounds");
        cfg.mime.add_type("text/html", &["html".to_string()]);
        cfg.mime.add_type("text/plain", &["txt".to_string()]);
        let mut scope = cfg.global.clone();
        scope.options.push_add(crate::config::Options::MULTIVIEWS);
        std::fs::write(root.join("page.html"), b"html").unwrap();
        std::fs::write(root.join("page.txt"), b"text").unwrap();
        assert!(matches!(
            multiviews_target(
                &cfg,
                &scope,
                &request("GET", b"/page"),
                &root,
                Path::new("page"),
                false,
                false,
            ),
            MultiViewsResult::MultipleChoices
        ));

        for index in 0..=MAX_MULTIVIEW_CANDIDATES {
            std::fs::write(root.join(format!("many.{index}.txt")), b"candidate").unwrap();
        }
        assert!(matches!(
            multiviews_target(
                &cfg,
                &scope,
                &request("GET", b"/many"),
                &root,
                Path::new("many"),
                false,
                false,
            ),
            MultiViewsResult::Overloaded
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn multiview_quality_parsers_fail_closed() {
        assert_eq!(quality_value("0"), Some(0));
        assert_eq!(quality_value("0.125"), Some(125));
        assert_eq!(quality_value("1.000"), Some(1000));
        assert_eq!(quality_value("1.001"), None);
        assert_eq!(quality_value("0.0000"), None);
        assert_eq!(item_quality(["level=1"].into_iter()), 1000);
        assert_eq!(item_quality(["q=bad"].into_iter()), 0);
        assert_eq!(media_quality(None, "text/html"), (1000, 0));
        assert_eq!(media_quality(Some(b"\xff"), "text/html"), (0, 0));
        assert_eq!(media_quality(Some(b"text/html"), "invalid"), (0, 0));
        assert_eq!(
            media_quality(Some(b"invalid, text/*"), "text/html"),
            (1000, 1)
        );
        assert_eq!(
            media_quality(Some(b"text/*;q=0.4, text/html;q=0.8"), "text/html"),
            (800, 2)
        );
        assert_eq!(language_quality(None, Some("en")), 1000);
        assert_eq!(language_quality(Some(b"en"), None), 1000);
        assert_eq!(language_quality(Some(b"\xff"), Some("en")), 0);
        assert_eq!(encoding_quality(Some(b"*;q=0, gzip;q=1"), None), 0);
        assert_eq!(
            encoding_quality(Some(b"*;q=0, gzip;q=1"), Some("gzip")),
            1000
        );
        assert_eq!(encoding_quality(Some(b"gzip"), Some("br")), 0);
        assert_eq!(encoding_quality(Some(b"\xff"), Some("br")), 0);
        assert_eq!(
            language_quality(Some(b"en;q=0.7, *;q=0.1"), Some("en-US")),
            700
        );
    }

    #[test]
    fn multiviews_admission_edges_are_bounded() {
        let (root, mut cfg) = config("multiview-admission");
        cfg.mime.add_type("text/html", &["html".to_string()]);
        cfg.mime.languages.insert("en".into(), "en".into());
        cfg.mime.languages.insert("fr".into(), "fr".into());
        let mut scope = cfg.global.clone();
        let req = request("GET", b"/page");

        assert!(matches!(
            multiviews_target(&cfg, &scope, &req, &root, Path::new("page"), false, false),
            MultiViewsResult::NotFound
        ));
        scope.options.push_add(crate::config::Options::MULTIVIEWS);
        assert!(matches!(
            multiviews_target(&cfg, &scope, &req, &root, Path::new(""), false, false),
            MultiViewsResult::NotFound
        ));
        assert!(matches!(
            multiviews_target(
                &cfg,
                &scope,
                &req,
                &root,
                Path::new("missing/page"),
                false,
                false,
            ),
            MultiViewsResult::NotFound
        ));

        std::fs::write(root.join("plain.unknown-vapache-type"), b"plain").unwrap();
        assert!(matches!(
            multiviews_target(&cfg, &scope, &req, &root, Path::new("plain"), false, false),
            MultiViewsResult::NotFound
        ));
        std::os::unix::fs::symlink("absent.html", root.join("dangling.html")).unwrap();
        assert!(matches!(
            multiviews_target(
                &cfg,
                &scope,
                &req,
                &root,
                Path::new("dangling"),
                false,
                false,
            ),
            MultiViewsResult::NotAcceptable
        ));

        std::fs::write(root.join("budget.html"), b"budget").unwrap();
        let budgeted = request("GET", b"/budget");
        budgeted
            .charge_policy_work(crate::resource::MAX_POLICY_WORK_UNITS)
            .unwrap();
        assert!(matches!(
            multiviews_target(
                &cfg,
                &scope,
                &budgeted,
                &root,
                Path::new("budget"),
                false,
                false,
            ),
            MultiViewsResult::Overloaded
        ));

        let overloaded =
            crate::resource::with_expensive_client("192.0.2.201".parse().unwrap(), || {
                let leases: Vec<_> = (0..crate::resource::MAX_EXPENSIVE_OPS_PER_CLIENT)
                    .map(|_| crate::resource::try_expensive().unwrap())
                    .collect();
                let result =
                    multiviews_target(&cfg, &scope, &req, &root, Path::new("budget"), false, false);
                drop(leases);
                result
            });
        assert!(matches!(overloaded, MultiViewsResult::Overloaded));

        std::fs::write(root.join("choice.html.en"), b"english").unwrap();
        std::fs::write(root.join("choice.html.fr"), b"french").unwrap();
        scope.content_policy.language_priority = Some(vec!["fr".into(), "en".into()]);
        let mut language = request("GET", b"/choice");
        language
            .headers
            .insert("accept-language", b"en, fr".to_vec());
        let MultiViewsResult::Selected(selected) = multiviews_target(
            &cfg,
            &scope,
            &language,
            &root,
            Path::new("choice"),
            false,
            false,
        ) else {
            panic!("language priority did not select a representation");
        };
        assert_eq!(selected.name, b"choice.html.fr");

        for index in 0..=MAX_MULTIVIEW_DIRECTORY_ENTRIES {
            std::fs::write(root.join(format!("unrelated-{index}")), b"x").unwrap();
        }
        assert!(matches!(
            multiviews_target(
                &cfg,
                &scope,
                &request("GET", b"/absent"),
                &root,
                Path::new("absent"),
                false,
                false,
            ),
            MultiViewsResult::Overloaded
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn root_descriptor_tracks_atomic_symlink_replacement() {
        let (base, _) = config("root-symlink-swap");
        let first_root = base.join("release-1");
        let second_root = base.join("release-2");
        std::fs::create_dir(&first_root).unwrap();
        std::fs::create_dir(&second_root).unwrap();
        std::fs::write(first_root.join("file.txt"), b"first").unwrap();
        std::fs::write(second_root.join("file.txt"), b"second").unwrap();

        let current = base.join("current");
        std::os::unix::fs::symlink(&first_root, &current).unwrap();
        let flags = (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK) as u64;
        let mut body = String::new();
        {
            let _request = request_metadata_scope();
            let mut first = open_beneath(&current, Path::new("file.txt"), flags, true).unwrap();
            first.read_to_string(&mut body).unwrap();
        }
        assert_eq!(body, "first");

        let replacement = base.join("replacement");
        std::os::unix::fs::symlink(&second_root, &replacement).unwrap();
        std::fs::rename(&replacement, &current).unwrap();

        body.clear();
        {
            let _request = request_metadata_scope();
            let mut second = open_beneath(&current, Path::new("file.txt"), flags, true).unwrap();
            second.read_to_string(&mut body).unwrap();
        }
        assert_eq!(body, "second");
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn owner_match_reopen_rejects_non_symlink_substitution() {
        let (root, _) = config("owner-reopen-substitution");
        let selected = root.join("selected.txt");
        std::fs::write(&selected, b"authorized").unwrap();
        let dir = File::open(&root).unwrap();
        let name = OsString::from("selected.txt");
        let pinned = open_component_nofollow(&dir, &name, libc::O_PATH).unwrap();
        let pinned_meta = pinned.metadata().unwrap();

        std::fs::rename(&selected, root.join("authorized.txt")).unwrap();
        std::fs::write(&selected, b"substituted").unwrap();
        let error =
            reopen_pinned_component(&dir, &name, libc::O_RDONLY | libc::O_NONBLOCK, &pinned_meta)
                .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ESTALE));
        assert!(!vapache_verified::owner_component_reopen_admit(true, false));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn resolution_metadata_mime_and_fallback_edges() {
        let (root, mut cfg) = config("resolution");
        std::fs::write(root.join("plain.txt"), b"hello").unwrap();
        std::fs::create_dir(root.join("sub")).unwrap();

        assert!(matches!(
            resolve_target(&root, Path::new("plain.txt"), true),
            Target::File { .. }
        ));
        assert!(matches!(
            resolve_target_checked(&root, Path::new(""), true, false),
            Target::Directory { .. }
        ));
        assert!(matches!(
            resolve_target_checked(&root, Path::new("missing"), true, false),
            Target::NotFound
        ));
        assert!(matches!(
            resolve_target_checked(&root, Path::new("../escape"), true, false),
            Target::Forbidden
        ));

        std::os::unix::fs::symlink("plain.txt", root.join("same-owner-link")).unwrap();
        assert!(matches!(
            resolve_target_checked(&root, Path::new("same-owner-link"), true, true),
            Target::File { .. }
        ));
        std::os::unix::fs::symlink("missing", root.join("dangling")).unwrap();
        assert!(matches!(
            resolve_target_checked(&root, Path::new("dangling"), true, true),
            Target::NotFound
        ));
        std::fs::create_dir(root.join("owner-dir")).unwrap();
        std::fs::write(root.join("owner-dir/nested.txt"), b"nested").unwrap();
        std::os::unix::fs::symlink("owner-dir", root.join("owner-dir-link")).unwrap();
        assert!(matches!(
            resolve_target_checked(&root, Path::new("owner-dir-link/nested.txt"), true, true,),
            Target::File { .. }
        ));
        std::os::unix::fs::symlink("owner-dir/../plain.txt", root.join("parent-link")).unwrap();
        assert!(matches!(
            resolve_target_checked(&root, Path::new("parent-link"), true, true),
            Target::File { .. }
        ));
        std::os::unix::fs::symlink("../../etc/passwd", root.join("owner-escape")).unwrap();
        assert!(matches!(
            resolve_target_checked(&root, Path::new("owner-escape"), true, true),
            Target::Forbidden
        ));
        assert!(matches!(
            resolve_target_checked(
                &root,
                Path::new(std::ffi::OsStr::from_bytes(b"bad\0name")),
                true,
                false,
            ),
            Target::NotFound
        ));
        if effective_uid() == 0 {
            let link = root.join("different-owner-link");
            std::os::unix::fs::symlink("plain.txt", &link).unwrap();
            rustix::fs::chownat(
                rustix::fs::CWD,
                &link,
                Some(rustix::fs::Uid::from_raw(1)),
                None,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .unwrap();
            assert!(matches!(
                resolve_target_checked(&root, Path::new("different-owner-link"), true, true,),
                Target::Forbidden
            ));
        }

        let fifo = root.join("fifo");
        make_test_fifo(&fifo).unwrap();
        assert!(matches!(
            resolve_target_checked(&root, Path::new("fifo"), true, false),
            Target::Forbidden
        ));

        assert!(require_secure_path_resolution().is_ok());
        let invalid_open_flag = 1u64 << 63;
        assert_eq!(
            open_beneath(&root, Path::new("plain.txt"), invalid_open_flag, true)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
        let open_flags = (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK) as u64;
        assert_eq!(
            open_beneath(
                &root,
                Path::new("plain.txt"),
                open_flags | libc::O_DIRECTORY as u64,
                true,
            )
            .unwrap_err()
            .raw_os_error(),
            Some(libc::ENOTDIR)
        );
        let outside_name = format!("vapache-files-outside-{}", std::process::id());
        let outside = root.parent().unwrap().join(&outside_name);
        std::fs::write(&outside, b"outside").unwrap();
        assert_eq!(
            open_beneath(
                &root,
                Path::new("..").join(&outside_name).as_path(),
                open_flags,
                true,
            )
            .unwrap_err()
            .raw_os_error(),
            Some(libc::EXDEV)
        );
        std::fs::remove_file(outside).unwrap();
        assert_eq!(
            open_at(&File::open(&root).unwrap(), b"bad\0name", true)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
        assert_eq!(
            open_at(&File::open(&root).unwrap(), b"plain.txt", false)
                .unwrap()
                .metadata()
                .unwrap()
                .len(),
            5
        );

        let _guard = request_metadata_scope();
        assert!(metadata_cached(&root.join("plain.txt")).is_ok());
        assert!(metadata_cached(&root.join("plain.txt")).is_ok());
        assert!(symlink_metadata_cached(&root.join("same-owner-link")).is_ok());
        assert!(symlink_metadata_cached(&root.join("same-owner-link")).is_ok());
        assert!(is_dir_cached(&root.join("sub")));

        cfg.mime.types.insert("txt".into(), "text/plain".into());
        let mut scope = Scope::default();
        scope.content_policy.default_charset = Some("utf-8".into());
        assert_eq!(
            mime_type(&cfg, &scope, b"plain.txt").as_deref(),
            Some("text/plain; charset=utf-8")
        );
        scope
            .content_policy
            .add_types
            .push(("text/custom".into(), "foo".into()));
        assert_eq!(
            mime_type(&cfg, &scope, b"x.foo").as_deref(),
            Some("text/custom; charset=utf-8")
        );
        scope
            .content_policy
            .add_types
            .push(("application/x-test".into(), "app".into()));
        assert_eq!(
            mime_type(&cfg, &scope, b"x.app").as_deref(),
            Some("application/x-test")
        );
        scope.content_policy.remove_types.push("foo".into());
        assert!(mime_type(&cfg, &scope, b"x.foo").is_none());
        scope.content_policy.remove_types.clear();
        scope
            .content_policy
            .add_types
            .push(("text/cgi-token".into(), "cgi".into()));
        assert_eq!(
            mime_type(&cfg, &scope, b"x.cgi.\xff").as_deref(),
            Some("text/cgi-token; charset=utf-8")
        );
        cfg.mime.charsets.insert("utf8".into(), "UTF-8".into());
        assert_eq!(
            mime_type(&cfg, &scope, b"plain.txt.utf8").as_deref(),
            Some("text/plain; charset=UTF-8")
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn static_metadata_and_autoindex_presentation_are_effectful() {
        let (root, mut cfg) = config("metadata-autoindex");
        let path = root.join("file.txt.en.gz");
        std::fs::write(&path, b"compressed-ish").unwrap();
        cfg.mime.types.insert("txt".into(), "text/plain".into());
        cfg.mime.encodings.insert("gz".into(), "gzip".into());
        cfg.mime.languages.insert("en".into(), "en".into());
        let file = File::open(&path).unwrap();
        let meta = file.metadata().unwrap();
        let response = serve_file_inner(
            &cfg,
            &Scope::default(),
            &request("GET", b"/file.txt.en.gz"),
            file,
            &meta,
            b"file.txt.en.gz",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "127.0.0.1",
        );
        assert!(response.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-encoding") && value == b"gzip"
        }));
        assert!(response.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-language") && value == b"en"
        }));

        let mut scope = Scope::default();
        scope.content_policy.autoindex.version_sort = Some(true);
        scope
            .content_policy
            .autoindex
            .icon_rules
            .push(crate::scope_policy::AutoIndexIconRule {
                icon: crate::scope_policy::AutoIndexIcon {
                    alt: "TXT".into(),
                    url: "/icons/text.gif".into(),
                },
                kind: crate::scope_policy::AutoIndexIconMatch::MediaType,
                patterns: vec!["text/*".into()],
            });
        scope.content_policy.autoindex.header_name = Some("HEADER.html".into());
        scope.content_policy.autoindex.readme_name = Some("README.html".into());
        let entries = vec![
            (b"file10.txt".to_vec(), false, 10),
            (b"file2.txt".to_vec(), false, 2),
            (b"HEADER.html".to_vec(), false, 1),
            (b"README.html".to_vec(), false, 1),
        ];
        let response = autoindex(
            &cfg,
            &scope,
            &request("GET", b"/listing/"),
            "/listing/",
            &entries,
            "example.test",
            80,
        );
        let Body::Bytes(body) = response.body else {
            panic!("autoindex response was not resident")
        };
        let body = String::from_utf8(body).unwrap();
        assert!(body.contains("src=\"/icons/text.gif\""));
        assert!(body.contains("Header: <a href=\"./HEADER.html\""));
        assert!(body.contains("Readme: <a href=\"./README.html\""));
        assert_eq!(version_name_cmp(b"file2", b"file10"), CmpOrdering::Less);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_preconditions_ranges_and_methods() {
        let (root, cfg) = config("preconditions");
        let path = root.join("file.txt");
        std::fs::write(&path, b"abcdef").unwrap();
        let scope = Scope::default();
        let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let make = || {
            let file = File::open(&path).unwrap();
            let meta = file.metadata().unwrap();
            (file, meta)
        };

        let (file, meta) = make();
        let mut req = request("GET", b"/file.txt");
        req.headers.insert("if-match", b"\"wrong\"".to_vec());
        assert_eq!(
            serve_file_inner(
                &cfg,
                &scope,
                &req,
                file,
                &meta,
                b"file.txt",
                peer,
                "127.0.0.1"
            )
            .status,
            412
        );

        let (file, meta) = make();
        let mut req = request("GET", b"/file.txt");
        req.headers.insert(
            "if-unmodified-since",
            crate::util::http_date(meta.mtime() - 10).into_bytes(),
        );
        assert_eq!(
            serve_file_inner(
                &cfg,
                &scope,
                &req,
                file,
                &meta,
                b"file.txt",
                peer,
                "127.0.0.1"
            )
            .status,
            412
        );
        assert!(header_etag_list_matches(b"W/\"abc\"", "\"abc\"", true));
        assert!(header_etag_list_matches(b"\"abc\"", "W/\"abc\"", true));
        assert!(header_etag_list_matches(b"*", "\"abc\"", false));
        assert!(header_etag_list_matches(
            b"\"other\", \"abc\"",
            "\"abc\"",
            false
        ));
        assert!(!header_etag_list_matches(b"\"abc-gzip\"", "\"abc\"", true));
        assert!(!header_etag_list_matches(b"abc", "\"abc\"", true));

        let mut header_scope = Scope::default();
        header_scope
            .header_policy
            .always_set_headers
            .push(("X-Static-Policy".into(), "present".into()));
        let (file, meta) = make();
        let tag = etag(&meta, ETAG_ALL);
        let mut conditional = request("GET", b"/file.txt");
        conditional
            .headers
            .insert("if-none-match", tag.as_bytes().to_vec());
        let not_modified = serve_file_inner(
            &cfg,
            &header_scope,
            &conditional,
            file,
            &meta,
            b"file.txt",
            peer,
            "127.0.0.1",
        );
        assert_eq!(not_modified.status, 304);
        assert!(not_modified.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("x-static-policy") && value == b"present"
        }));

        let mut compressed_scope = Scope::default();
        compressed_scope.compression_policy.compression_rules.push(
            crate::config::CompressionRule::Set(vec![
                crate::config::CompressionKind::Gzip,
                crate::config::CompressionKind::Brotli,
            ]),
        );
        let gzip_tag = format!("{}-gzip\"", tag.trim_end_matches('"'));

        let (file, meta) = make();
        let mut identity = request("GET", b"/file.txt");
        identity
            .headers
            .insert("if-none-match", gzip_tag.as_bytes().to_vec());
        assert_eq!(
            serve_file_inner(
                &cfg,
                &compressed_scope,
                &identity,
                file,
                &meta,
                b"file.txt",
                peer,
                "127.0.0.1",
            )
            .status,
            200
        );

        let (file, meta) = make();
        let mut brotli = request("GET", b"/file.txt");
        brotli.headers.insert("accept-encoding", b"br".to_vec());
        brotli
            .headers
            .insert("if-none-match", gzip_tag.as_bytes().to_vec());
        assert_eq!(
            serve_file_inner(
                &cfg,
                &compressed_scope,
                &brotli,
                file,
                &meta,
                b"file.txt",
                peer,
                "127.0.0.1",
            )
            .status,
            200
        );

        let (file, meta) = make();
        let mut gzip = request("GET", b"/file.txt");
        gzip.headers.insert("accept-encoding", b"gzip".to_vec());
        gzip.headers
            .insert("if-none-match", gzip_tag.as_bytes().to_vec());
        let mut gzip_not_modified = serve_file_inner(
            &cfg,
            &compressed_scope,
            &gzip,
            file,
            &meta,
            b"file.txt",
            peer,
            "127.0.0.1",
        );
        assert_eq!(gzip_not_modified.status, 304);
        crate::compression::finalize(
            &compressed_scope,
            &gzip,
            &mut gzip_not_modified,
            b"file.txt",
        );
        assert!(gzip_not_modified.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("etag") && value == gzip_tag.as_bytes()
        }));

        let mut no_etag_scope = Scope::default();
        no_etag_scope.content_policy.file_etag = Some(0);
        let (file, meta) = make();
        let no_etag = serve_file_inner(
            &cfg,
            &no_etag_scope,
            &request("GET", b"/file.txt"),
            file,
            &meta,
            b"file.txt",
            peer,
            "127.0.0.1",
        );
        assert!(!no_etag
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("etag")));

        let (file, meta) = make();
        let mut wildcard = request("GET", b"/file.txt");
        wildcard.headers.insert("if-none-match", b"*".to_vec());
        assert_eq!(
            serve_file_inner(
                &cfg,
                &no_etag_scope,
                &wildcard,
                file,
                &meta,
                b"file.txt",
                peer,
                "127.0.0.1",
            )
            .status,
            304
        );

        let (file, meta) = make();
        let mut absent = request("GET", b"/file.txt");
        absent.headers.insert("if-none-match", b"\"fake\"".to_vec());
        assert_eq!(
            serve_file_inner(
                &cfg,
                &no_etag_scope,
                &absent,
                file,
                &meta,
                b"file.txt",
                peer,
                "127.0.0.1",
            )
            .status,
            200
        );

        let (file, meta) = make();
        let tag = etag(&meta, ETAG_ALL);
        let mut req = request("POST", b"/file.txt");
        req.headers.insert("if-none-match", tag.as_bytes().to_vec());
        assert_eq!(
            serve_file_inner(
                &cfg,
                &scope,
                &req,
                file,
                &meta,
                b"file.txt",
                peer,
                "127.0.0.1"
            )
            .status,
            412
        );

        let (file, meta) = make();
        let mut req = request("GET", b"/file.txt");
        req.headers.insert("range", b"bytes=1-2".to_vec());
        req.headers
            .insert("if-range", http_date(meta.mtime()).into_bytes());
        assert_eq!(
            serve_file_inner(
                &cfg,
                &scope,
                &req,
                file,
                &meta,
                b"file.txt",
                peer,
                "127.0.0.1"
            )
            .status,
            206
        );

        let (file, meta) = make();
        let tag = etag(&meta, ETAG_ALL);
        let mut req = request("GET", b"/file.txt");
        req.headers.insert("range", b"bytes=1-2".to_vec());
        req.headers.insert("if-range", tag.as_bytes().to_vec());
        assert_eq!(
            serve_file_inner(
                &cfg,
                &scope,
                &req,
                file,
                &meta,
                b"file.txt",
                peer,
                "127.0.0.1"
            )
            .status,
            206
        );

        let (file, meta) = make();
        let mut req = request("GET", b"/file.txt");
        req.headers.insert("range", b"bytes=1-2".to_vec());
        req.headers
            .insert("if-range", format!("W/{tag}").into_bytes());
        assert_eq!(
            serve_file_inner(
                &cfg,
                &scope,
                &req,
                file,
                &meta,
                b"file.txt",
                peer,
                "127.0.0.1"
            )
            .status,
            200
        );

        let (file, meta) = make();
        let mut req = request("GET", b"/file.txt");
        req.headers.insert("range", b"bytes=1-2".to_vec());
        req.headers
            .insert("if-range", format!("{tag}, \"other\"").into_bytes());
        assert_eq!(
            serve_file_inner(
                &cfg,
                &scope,
                &req,
                file,
                &meta,
                b"file.txt",
                peer,
                "127.0.0.1"
            )
            .status,
            200
        );

        let (file, meta) = make();
        let req = request("POST", b"/file.txt");
        let response = serve_file_inner(
            &cfg,
            &scope,
            &req,
            file,
            &meta,
            b"file.txt",
            peer,
            "127.0.0.1",
        );
        assert_eq!(response.status, 405);
        assert!(response
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("allow")));

        let (file, meta) = make();
        let req = request("HEAD", b"/file.txt");
        let response = serve_file_inner(
            &cfg,
            &scope,
            &req,
            file,
            &meta,
            b"file.txt",
            peer,
            "127.0.0.1",
        );
        assert!(matches!(response.body, Body::Empty));

        let (file, meta) = make();
        let req = request("GET", b"/file.txt");
        let response = serve_file(
            &cfg,
            &scope,
            &req,
            file,
            &meta,
            &path,
            b"file.txt",
            peer,
            "127.0.0.1",
            &crate::access::test_grant(),
            &crate::access::ResourceKey::request(
                None,
                &req,
                "/file.txt",
                Some(Path::new("/wrong")),
                None,
            ),
        );
        assert_eq!(response.status, 500);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn directory_error_document_and_message_edges() {
        let (root, mut cfg) = config("directory");
        std::fs::write(root.join("index.html"), b"index").unwrap();
        std::fs::write(root.join("visible"), b"x").unwrap();
        std::fs::write(root.join("ignored~"), b"x").unwrap();
        std::fs::write(root.join("#ignored"), b"x").unwrap();
        let dir = File::open(&root).unwrap();
        let mut req = request("GET", b"/dir");
        req.query = b"raw=\xff&escaped=%FE".to_vec();
        let mut scope = Scope::default();
        match directory_action(&cfg, &scope, &req, &dir, "/dir", b"/dir", true, false) {
            DirAction::Redirect(loc) => {
                assert_eq!(loc, b"/dir/?raw=%FF&escaped=%FE")
            }
            _ => panic!("expected redirect"),
        }

        cfg.directory_index = vec!["../bad".into(), ".".into(), "".into(), "index.html".into()];
        assert!(
            directory_index_target(&cfg, &scope, &request("GET", b"/"), &dir, "/", b"/").is_some()
        );
        assert_eq!(
            directory_index_name(&cfg, &scope, &request("GET", b"/"), &dir, "/", b"/"),
            Some(b"index.html".to_vec())
        );
        cfg.directory_index.clear();
        scope.options.push_add(crate::config::Options::INDEXES);
        scope.content_policy.index_ignore.push("visible".into());
        assert!(matches!(
            directory_action(
                &cfg,
                &scope,
                &request("GET", b"/"),
                &dir,
                "/",
                b"/",
                true,
                false,
            ),
            DirAction::List(_)
        ));

        cfg.directory_index = vec!["index.html".into()];
        let indexed = serve_directory_inner(
            &cfg,
            None,
            &Scope::default(),
            &request("GET", b"/"),
            File::open(&root).unwrap(),
            "/",
            b"/",
            "example.test",
            80,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "127.0.0.1",
        );
        assert_eq!(indexed.status, 200);
        let mut owner_scope = Scope::default();
        owner_scope
            .options
            .push_remove(crate::config::Options::FOLLOW_SYMLINKS);
        owner_scope
            .options
            .push_add(crate::config::Options::SYMLINKS_IF_OWNER_MATCH);
        assert_eq!(
            serve_directory_inner(
                &cfg,
                None,
                &owner_scope,
                &request("GET", b"/"),
                File::open(&root).unwrap(),
                "/",
                b"/",
                "example.test",
                80,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "127.0.0.1",
            )
            .status,
            200
        );

        cfg.server_signature = ServerSignature::Email;
        let listed = autoindex(
            &cfg,
            &scope,
            &request("GET", b"/dir/"),
            "/dir/",
            &[(b"child".to_vec(), true, 0), (b"file".to_vec(), false, 7)],
            "example.test",
            8080,
        );
        assert_eq!(listed.status, 200);
        let too_many = vec![(b"entry".to_vec(), false, 1); MAX_AUTOINDEX_ENTRIES + 1];
        assert_eq!(
            autoindex(
                &cfg,
                &scope,
                &request("GET", b"/dir/"),
                "/dir/",
                &too_many,
                "example.test",
                8080,
            )
            .status,
            503
        );
        let oversized_name = vec![(vec![b'x'; MAX_AUTOINDEX_BYTES / 8], false, 1)];
        assert_eq!(
            autoindex(
                &cfg,
                &scope,
                &request("GET", b"/"),
                "/",
                &oversized_name,
                "example.test",
                80,
            )
            .status,
            503
        );

        let mut text_scope = Scope::default();
        text_scope
            .error_policy
            .push(418, ErrorDoc::Text("teapot".into()));
        assert_eq!(
            error_response_inner(
                &cfg,
                None,
                &text_scope,
                418,
                &request("GET", b"/"),
                "/",
                80,
                "h",
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "127.0.0.1"
            )
            .status,
            418
        );
        text_scope
            .error_policy
            .push(419, ErrorDoc::External("https://example.test/next".into()));
        assert_eq!(
            error_response_inner(
                &cfg,
                None,
                &text_scope,
                419,
                &request("GET", b"/"),
                "/",
                80,
                "h",
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "127.0.0.1"
            )
            .status,
            302
        );

        for status in [408, 413, 414, 505, 599] {
            assert!(!error_message(status, "/x").is_empty());
        }
        let mut recursive = request("GET", b"/");
        assert!(recursive.prepare_error_document_transition());
        assert!(serve_error_document(
            &cfg,
            None,
            &recursive,
            "/missing",
            500,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "127.0.0.1",
            80,
            "h",
        )
        .is_none());
        let local = serve_error_document(
            &cfg,
            None,
            &request("GET", b"/missing"),
            "/index.html",
            404,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "127.0.0.1",
            80,
            "h",
        )
        .expect("existing local error document");
        assert_eq!(local.status, 404);
        assert!(!local.shared_cache_eligible());
        assert_eq!(simple_html(302, "go", Some("/next")).status, 302);

        crate::expr::with_connection(true, 443, || {
            let redirected = serve_directory_inner(
                &cfg,
                None,
                &Scope::default(),
                &request("GET", b"/dir"),
                File::open(&root).unwrap(),
                "/dir",
                b"/dir",
                "example.test",
                443,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "127.0.0.1",
            );
            assert!(redirected
                .headers
                .iter()
                .any(|(n, v)| n.eq_ignore_ascii_case("location") && v.starts_with(b"https://")));
        });

        cfg.use_canonical_name = true;
        cfg.server_name = Some("canonical.example".into());
        let redirected = serve_directory_inner(
            &cfg,
            None,
            &Scope::default(),
            &request("GET", b"relative"),
            File::open(&root).unwrap(),
            "/dir",
            b"relative",
            "fallback.example",
            8080,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "127.0.0.1",
        );
        assert!(redirected
            .headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("location") && v == b"relative/"));

        let req = request("GET", b"/");
        let dir_file = File::open(&root).unwrap();
        let meta = dir_file.metadata().unwrap();
        let invalid = serve_directory(
            &cfg,
            None,
            &Scope::default(),
            &req,
            dir_file,
            &meta,
            &root,
            "/",
            b"/",
            "host",
            80,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "127.0.0.1",
            &crate::access::test_grant(),
            &crate::access::ResourceKey::request(None, &req, "/", Some(Path::new("/wrong")), None),
        );
        assert_eq!(invalid.status, 500);

        let generic_redirect = error_response_inner(
            &cfg,
            None,
            &Scope::default(),
            302,
            &req,
            "/",
            80,
            "host",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "127.0.0.1",
        );
        assert!(generic_redirect
            .headers
            .iter()
            .any(|(n, v)| { n.eq_ignore_ascii_case("cache-control") && v == b"no-cache" }));
        assert!(!error_message(431, "/").is_empty());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn autoindex_scan_limit_counts_filtered_hidden_entries() {
        let (root, cfg) = config("autoindex-hidden-scan-limit");
        for index in 0..=MAX_AUTOINDEX_ENTRIES {
            File::create(root.join(format!(".hidden-{index}"))).unwrap();
        }
        let mut scope = Scope::default();
        scope.options.push_add(crate::config::Options::INDEXES);
        assert!(matches!(
            directory_action(
                &cfg,
                &scope,
                &request("GET", b"/"),
                &File::open(&root).unwrap(),
                "/",
                b"/",
                true,
                false,
            ),
            DirAction::Overloaded
        ));
        let response = serve_directory_inner(
            &cfg,
            None,
            &scope,
            &request("GET", b"/"),
            File::open(&root).unwrap(),
            "/",
            b"/",
            "example.test",
            80,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "127.0.0.1",
        );
        assert_eq!(response.status, 503);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn autoindex_does_not_follow_disallowed_symlink_for_metadata() {
        let (root, cfg) = config("autoindex-symlink-metadata");
        let listed = root.join("listed");
        std::fs::create_dir(&listed).unwrap();
        let secret = root.join("secret.bin");
        std::fs::write(&secret, b"sensitive metadata").unwrap();
        std::os::unix::fs::symlink(&secret, listed.join("outside-link")).unwrap();

        let mut scope = Scope::default();
        scope.options.push_add(crate::config::Options::INDEXES);
        scope
            .options
            .push_remove(crate::config::Options::FOLLOW_SYMLINKS);
        scope
            .options
            .push_remove(crate::config::Options::SYMLINKS_IF_OWNER_MATCH);
        let action = directory_action(
            &cfg,
            &scope,
            &request("GET", b"/listed/"),
            &File::open(&listed).unwrap(),
            "/listed/",
            b"/listed/",
            false,
            false,
        );
        let DirAction::List(entries) = action else {
            panic!("expected autoindex entries");
        };
        let (_, is_dir, size) = entries
            .iter()
            .find(|(name, _, _)| name == b"outside-link")
            .expect("symlink remains name-visible");
        assert!(!is_dir);
        assert_eq!(*size, 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn directory_index_preserves_owner_match_policy() {
        let (root, mut cfg) = config("directory-index-owner-match");
        let listed = root.join("listed");
        std::fs::create_dir(&listed).unwrap();
        std::fs::write(listed.join("target.html"), b"index").unwrap();
        let link = listed.join("index.html");
        std::os::unix::fs::symlink("target.html", &link).unwrap();
        cfg.directory_index = vec!["index.html".into()];

        let mut scope = Scope::default();
        scope
            .options
            .push_remove(crate::config::Options::FOLLOW_SYMLINKS);
        scope
            .options
            .push_add(crate::config::Options::SYMLINKS_IF_OWNER_MATCH);
        let dir = File::open(&listed).unwrap();
        assert!(directory_index_target(
            &cfg,
            &scope,
            &request("GET", b"/listed/"),
            &dir,
            "/listed/",
            b"/listed/",
        )
        .is_some());

        if effective_uid() == 0 {
            rustix::fs::chownat(
                rustix::fs::CWD,
                &link,
                Some(rustix::fs::Uid::from_raw(1)),
                None,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .unwrap();
            assert!(directory_index_target(
                &cfg,
                &scope,
                &request("GET", b"/listed/"),
                &dir,
                "/listed/",
                b"/listed/",
            )
            .is_none());
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn fd_path_cow_borrows_the_lexical_target_and_owns_symlink_targets() {
        let (root, _) = config("fd-path-cow");
        let target = root.join("plain.txt");
        std::fs::write(&target, b"hello").unwrap();

        let file = File::open(&target).unwrap();
        assert_eq!(fd_path(&file).unwrap(), target);
        match fd_path_cow(&file, &target).expect("descriptor path") {
            Cow::Borrowed(path) => assert_eq!(path, target),
            Cow::Owned(path) => panic!("matching target allocated {path:?}"),
        }

        let link = root.join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let linked = File::open(&link).unwrap();
        match fd_path_cow(&linked, &link).expect("symlink target") {
            Cow::Owned(path) => assert_eq!(path, target),
            Cow::Borrowed(path) => panic!("symlink target was not resolved: {path:?}"),
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn administrative_paths_never_follow_parent_or_final_symlinks() {
        let (root, _cfg) = config("admin-path");
        let real = root.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("state"), b"safe").unwrap();
        std::os::unix::fs::symlink(&real, root.join("linked")).unwrap();

        assert!(ensure_admin_dir(&root.join("linked/child"), 0o700).is_err());
        assert!(open_admin_path(&root.join("linked/state"), libc::O_RDONLY, 0).is_err());
        std::os::unix::fs::symlink(real.join("state"), root.join("final-link")).unwrap();
        assert!(open_admin_path(&root.join("final-link"), libc::O_RDONLY, 0).is_err());
        assert_eq!(std::fs::read(real.join("state")).unwrap(), b"safe");
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn injected_openat2_failures_retry_only_transient_errors() {
        let _fault_guard = crate::fault::test_guard();
        let (root, _cfg) = config("openat2-faults");
        let path = root.join("input");
        std::fs::write(&path, b"safe").unwrap();

        crate::fault::configure("fs.openat2", 0, std::io::ErrorKind::Interrupted);
        let mut opened = open_admin_path(&path, libc::O_RDONLY, 0).unwrap();
        let mut contents = Vec::new();
        opened.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, b"safe");

        crate::fault::configure("fs.openat2", 0, std::io::ErrorKind::PermissionDenied);
        let error = open_admin_path(&path, libc::O_RDONLY, 0).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn injected_administrative_file_identity_race_is_rejected() {
        let _fault_guard = crate::fault::test_guard();
        let (root, _cfg) = config("admin-read-race");
        let path = root.join("input");
        std::fs::write(&path, b"safe").unwrap();
        crate::fault::configure(
            "fs.admin.post_read.identity",
            0,
            std::io::ErrorKind::InvalidData,
        );
        let error =
            read_admin_file_with_trust(&path, 64, AdminFileTrust::ProcessOwned).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn administrative_paths_reject_service_writable_parents() {
        let (root, _cfg) = config("admin-parent-mode");
        let service_uid = std::fs::metadata(&root).unwrap().uid();
        assert!(validate_admin_parents(&root.join("state"), service_uid).is_err());
        let mut permissions = std::fs::metadata(&root).unwrap().permissions();
        permissions.set_mode(0o555);
        std::fs::set_permissions(&root, permissions).unwrap();
        assert!(validate_admin_parents(&root.join("state"), service_uid).is_err());
        let mut permissions = std::fs::metadata(&root).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&root, permissions).unwrap();
        let safe = validate_admin_parents(Path::new("/dev/null"), u32::MAX);
        assert!(safe.is_ok(), "{safe:?}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn administrative_inputs_are_bounded_regular_and_no_follow() {
        let (root, _cfg) = config("admin-input");
        let regular = root.join("input");
        std::fs::write(&regular, b"safe").unwrap();
        assert_eq!(read_admin_file(&regular, 4).unwrap(), b"safe");
        assert!(read_admin_file(&regular, 3).is_err());

        let linked = root.join("linked-input");
        std::os::unix::fs::symlink(&regular, &linked).unwrap();
        assert!(read_admin_file(&linked, 4).is_err());

        let fifo = root.join("input-fifo");
        make_test_fifo(&fifo).unwrap();
        assert!(read_admin_file(&fifo, 4).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn final_admin_symlink_targets_are_normalized_without_escaping_root() {
        assert_eq!(
            final_admin_symlink_target(
                Path::new("/etc/letsencrypt/live/example.test/fullchain.pem"),
                Path::new("../../archive/example.test/fullchain1.pem")
            )
            .unwrap(),
            Path::new("/etc/letsencrypt/archive/example.test/fullchain1.pem")
        );
        assert!(final_admin_symlink_target(Path::new("/link"), Path::new("../../escape")).is_err());
    }

    #[test]
    fn root_owned_final_admin_symlink_supports_certbot_rotation_shape() {
        if effective_uid() != 0 {
            return;
        }
        let root = PathBuf::from(format!(
            "/run/vapache-certbot-link-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let archive = root.join("archive/example.test");
        let live = root.join("live/example.test");
        std::fs::create_dir_all(&archive).unwrap();
        std::fs::create_dir_all(&live).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let version = archive.join("fullchain1.pem");
        std::fs::write(&version, b"certificate").unwrap();
        let current = live.join("fullchain.pem");
        std::os::unix::fs::symlink("../../archive/example.test/fullchain1.pem", &current).unwrap();

        assert_eq!(
            read_admin_file_following_root_owned_final_symlink(
                &current,
                64,
                AdminFileTrust::RootOwned
            )
            .unwrap(),
            b"certificate"
        );
        assert!(read_admin_file_with_trust(&current, 64, AdminFileTrust::RootOwned).is_err());

        let chained = archive.join("fullchain2.pem");
        std::os::unix::fs::symlink("fullchain1.pem", &chained).unwrap();
        let chained_current = live.join("chained.pem");
        std::os::unix::fs::symlink(
            "../../archive/example.test/fullchain2.pem",
            &chained_current,
        )
        .unwrap();
        assert!(read_admin_file_following_root_owned_final_symlink(
            &chained_current,
            64,
            AdminFileTrust::RootOwned
        )
        .is_err());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn explicit_root_trust_does_not_follow_the_current_euid() {
        let (root, _cfg) = config("admin-retained-trust");
        let input = root.join("input");
        std::fs::write(&input, b"safe").unwrap();
        assert_eq!(
            read_admin_file_with_trust(&input, 4, AdminFileTrust::ProcessOwned).unwrap(),
            b"safe"
        );
        assert!(read_admin_file_with_trust(&input, 4, AdminFileTrust::RootOwned).is_err());
        let mut mode = std::fs::metadata(&input).unwrap().permissions();
        mode.set_mode(0o666);
        std::fs::set_permissions(&input, mode).unwrap();
        assert!(read_admin_file_with_trust(&input, 4, AdminFileTrust::RootOwned).is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}
