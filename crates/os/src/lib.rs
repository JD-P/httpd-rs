//! Audited Linux process, descriptor, and syscall boundary for httpd-rs.
//!
//! This crate is the only production crate permitted to contain Rust
//! `unsafe` blocks.  Its public API owns successful descriptors immediately,
//! borrows existing descriptors with lifetimes, and does not expose pointers.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

pub type Pid = libc::pid_t;

#[cfg(target_env = "gnu")]
pub type RlimitResource = libc::__rlimit_resource_t;
#[cfg(not(target_env = "gnu"))]
pub type RlimitResource = libc::c_int;

pub const FIRST_NONSTANDARD_FD: u32 = 3;
const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;
const MAX_NSS_BUFFER: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForkResult {
    Parent(Pid),
    Child,
}

#[derive(Clone, Copy, Debug)]
pub struct ChildSetup {
    pub parent_pid: Pid,
    pub duplicate_fd: Option<(RawFd, RawFd)>,
    pub retained_fd: Option<RawFd>,
    pub create_session: bool,
    pub umask: Option<libc::mode_t>,
    pub no_new_privileges: bool,
    pub disable_dumping: bool,
    pub cpu_seconds: Option<u64>,
    pub file_size: Option<u64>,
    pub open_files: Option<u64>,
}

impl ChildSetup {
    pub fn inherited(parent_pid: Pid) -> Self {
        Self {
            parent_pid,
            duplicate_fd: None,
            retained_fd: None,
            create_session: false,
            umask: None,
            no_new_privileges: false,
            disable_dumping: false,
            cpu_seconds: None,
            file_size: None,
            open_files: None,
        }
    }
}

pub fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

pub fn effective_gid() -> u32 {
    rustix::process::getegid().as_raw()
}

pub fn current_pid() -> Pid {
    rustix::process::getpid().as_raw_pid()
}

pub fn parent_pid() -> Pid {
    rustix::process::getppid().map_or(0, rustix::process::Pid::as_raw_pid)
}

pub fn lookup_user_id(name: &CStr) -> io::Result<u32> {
    let mut size = 1024usize;
    loop {
        let mut buffer = vec![0u8; size];
        // SAFETY[OS005]: passwd is a C record whose all-zero state is a valid
        // output buffer; getpwnam_r initializes fields before result is used.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        // SAFETY[OS006]: name is NUL-terminated, entry/result are live output
        // pointers, and buffer advertises its exact writable capacity.
        let rc = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                &mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if rc == 0 {
            return if result.is_null() {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "user does not exist",
                ))
            } else {
                Ok(entry.pw_uid)
            };
        }
        if rc == libc::ERANGE && size < MAX_NSS_BUFFER {
            size = size.saturating_mul(2).min(MAX_NSS_BUFFER);
            continue;
        }
        return Err(io::Error::from_raw_os_error(rc));
    }
}

pub fn lookup_group_id(name: &CStr) -> io::Result<u32> {
    let mut size = 1024usize;
    loop {
        let mut buffer = vec![0u8; size];
        // SAFETY[OS007]: group is a C record whose all-zero state is a valid
        // output buffer; getgrnam_r initializes fields before result is used.
        let mut entry: libc::group = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        // SAFETY[OS008]: name is NUL-terminated, entry/result are live output
        // pointers, and buffer advertises its exact writable capacity.
        let rc = unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                &mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if rc == 0 {
            return if result.is_null() {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "group does not exist",
                ))
            } else {
                Ok(entry.gr_gid)
            };
        }
        if rc == libc::ERANGE && size < MAX_NSS_BUFFER {
            size = size.saturating_mul(2).min(MAX_NSS_BUFFER);
            continue;
        }
        return Err(io::Error::from_raw_os_error(rc));
    }
}

fn close_range(first: u32, flags: u32) -> io::Result<()> {
    // SAFETY[OS009]: close_range takes integer values only; the flag is the
    // Linux CLOSE_RANGE_CLOEXEC bit or zero.
    let result = unsafe { libc::syscall(libc::SYS_close_range, first, u32::MAX, flags) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn close_inherited_descriptors() -> io::Result<()> {
    close_range(FIRST_NONSTANDARD_FD, 0)
}

pub fn cloexec_unrelated_descriptors() -> io::Result<()> {
    close_range(FIRST_NONSTANDARD_FD, CLOSE_RANGE_CLOEXEC)
}

pub fn set_cloexec(fd: BorrowedFd<'_>, enabled: bool) -> io::Result<()> {
    let mut flags = rustix::io::fcntl_getfd(fd).map_err(io::Error::from)?;
    if enabled {
        flags.insert(rustix::io::FdFlags::CLOEXEC);
    } else {
        flags.remove(rustix::io::FdFlags::CLOEXEC);
    }
    rustix::io::fcntl_setfd(fd, flags).map_err(io::Error::from)
}

pub fn set_cloexec_raw(fd: RawFd, enabled: bool) -> io::Result<()> {
    // SAFETY[OS012]: F_GETFD accepts any scalar descriptor and reports EBADF
    // for invalid values without dereferencing process memory.
    let current = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if current < 0 {
        return Err(io::Error::last_os_error());
    }
    let updated = if enabled {
        current | libc::FD_CLOEXEC
    } else {
        current & !libc::FD_CLOEXEC
    };
    // SAFETY[OS088]: fd was validated by F_GETFD and updated derives from its
    // current descriptor flags.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, updated) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn fd_is_open(fd: BorrowedFd<'_>) -> bool {
    rustix::io::fcntl_getfd(fd).is_ok()
}

pub fn raw_fd_is_open(fd: RawFd) -> bool {
    // SAFETY[OS086]: F_GETFD accepts any scalar descriptor number and reports
    // EBADF for invalid values without dereferencing process memory.
    unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
}

pub fn set_nonblocking(fd: BorrowedFd<'_>, enabled: bool) -> io::Result<()> {
    let mut flags = rustix::fs::fcntl_getfl(fd).map_err(io::Error::from)?;
    if enabled {
        flags.insert(rustix::fs::OFlags::NONBLOCK);
    } else {
        flags.remove(rustix::fs::OFlags::NONBLOCK);
    }
    rustix::fs::fcntl_setfl(fd, flags).map_err(io::Error::from)
}

pub fn set_limit(resource: RlimitResource, value: u64) -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    // SAFETY[OS016]: limit is a live rlimit record and resource is supplied
    // from a platform RLIMIT constant.
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn bind_to_parent(parent: Pid) -> io::Result<()> {
    // SAFETY[OS017]: PR_SET_PDEATHSIG consumes scalar arguments only.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if parent_pid() != parent {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }
    Ok(())
}

pub fn no_new_privileges() -> io::Result<()> {
    // SAFETY[OS018]: PR_SET_NO_NEW_PRIVS consumes scalar arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn disable_dumping() -> io::Result<()> {
    set_limit(libc::RLIMIT_CORE, 0)?;
    // SAFETY[OS019]: PR_SET_DUMPABLE consumes scalar arguments only.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn child_exited_unreaped(pid: Pid) -> io::Result<bool> {
    // SAFETY[OS020]: zero is a valid siginfo_t initialization and waitid is
    // given its exact live output pointer.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY[OS021]: info is live for the call and pid names a direct child as
    // required by the caller; WNOWAIT intentionally retains the zombie.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY[OS022]: waitid initialized siginfo_t and the libc accessor reads
    // the si_pid member selected by the wait event representation.
    Ok(unsafe { info.si_pid() } != 0)
}

fn duplicate_fd(source: RawFd, target: RawFd) -> io::Result<()> {
    // SAFETY[OS023]: source is inherited from a live parent descriptor and
    // target is the fixed child descriptor selected by the caller.
    if unsafe { libc::dup2(source, target) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        set_cloexec_raw(target, false)
    }
}

pub fn prepare_inherited_worker_fd(source: RawFd, target: RawFd, parent: Pid) -> io::Result<()> {
    bind_to_parent(parent)?;
    cloexec_unrelated_descriptors()?;
    duplicate_fd(source, target)
}

fn apply_child_setup(setup: ChildSetup) -> io::Result<()> {
    bind_to_parent(setup.parent_pid)?;
    cloexec_unrelated_descriptors()?;
    if let Some((source, target)) = setup.duplicate_fd {
        duplicate_fd(source, target)?;
    }
    if let Some(fd) = setup.retained_fd {
        set_cloexec_raw(fd, false)?;
    }
    if setup.create_session {
        // SAFETY[OS024]: setsid has no pointer arguments or preconditions
        // beyond being called by a process that is not a group leader.
        if unsafe { libc::setsid() } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    if let Some(mask) = setup.umask {
        // SAFETY[OS025]: umask consumes a scalar mode and always succeeds.
        unsafe { libc::umask(mask) };
    }
    if setup.no_new_privileges {
        no_new_privileges()?;
    }
    if setup.disable_dumping {
        disable_dumping()?;
    }
    if let Some(value) = setup.cpu_seconds {
        set_limit(libc::RLIMIT_CPU, value.max(1))?;
    }
    if let Some(value) = setup.file_size {
        set_limit(libc::RLIMIT_FSIZE, value)?;
    }
    if let Some(value) = setup.open_files {
        set_limit(libc::RLIMIT_NOFILE, value)?;
    }
    Ok(())
}

/// Apply a child isolation profile to the current process.
///
/// Production callers normally use [`configure_child`], which installs this
/// fixed operation in `Command::pre_exec`. This entry point exists for
/// isolation probes that already run in a disposable child process.
pub fn setup_current_child(setup: ChildSetup) -> io::Result<()> {
    apply_child_setup(setup)
}

pub fn configure_child(command: &mut Command, setup: ChildSetup) {
    // SAFETY[OS026]: the registered closure performs only scalar syscalls and
    // constructs compact OS errors; it does not allocate, lock, or inspect
    // process-wide Rust state between fork and exec.
    unsafe {
        command.pre_exec(move || apply_child_setup(setup));
    }
}

fn process_thread_count() -> io::Result<usize> {
    Ok(std::fs::read_dir("/proc/self/task")?.count())
}

pub fn fork_single_threaded() -> io::Result<ForkResult> {
    if process_thread_count()? != 1 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "refusing to fork a multithreaded process",
        ));
    }
    // SAFETY[OS027]: /proc confirms this process has one task immediately
    // before the startup-only fork; no httpd-rs thread creation is permitted
    // before this boundary.
    let pid = unsafe { libc::fork() };
    match pid {
        value if value < 0 => Err(io::Error::last_os_error()),
        0 => Ok(ForkResult::Child),
        value => Ok(ForkResult::Parent(value)),
    }
}

pub fn exit_immediately(status: i32) -> ! {
    // SAFETY[OS028]: _exit terminates the calling process without invoking
    // inherited Rust destructors after fork.
    unsafe { libc::_exit(status) }
}

pub fn kill(pid: Pid, signal: i32) -> io::Result<()> {
    // SAFETY[OS029]: kill consumes scalar pid/signal arguments only.
    if unsafe { libc::kill(pid, signal) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn wait(pid: Pid) -> io::Result<i32> {
    let mut status = 0;
    loop {
        // SAFETY[OS030]: status is a live output integer and pid is the child
        // selected by the caller.
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == pid {
            return Ok(status);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub fn fchmod(fd: BorrowedFd<'_>, mode: libc::mode_t) -> io::Result<()> {
    rustix::fs::fchmod(fd, rustix::fs::Mode::from_bits_retain(mode)).map_err(io::Error::from)
}

pub fn fchown(fd: BorrowedFd<'_>, uid: u32, gid: u32) -> io::Result<()> {
    fchown_optional(fd, Some(uid), Some(gid))
}

pub fn fchown_optional(fd: BorrowedFd<'_>, uid: Option<u32>, gid: Option<u32>) -> io::Result<()> {
    if uid == Some(u32::MAX) || gid == Some(u32::MAX) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid identity",
        ));
    }
    rustix::fs::fchown(
        fd,
        uid.map(rustix::process::Uid::from_raw),
        gid.map(rustix::process::Gid::from_raw),
    )
    .map_err(io::Error::from)
}

pub fn mkdirat(dir: BorrowedFd<'_>, name: &CStr, mode: libc::mode_t) -> io::Result<()> {
    rustix::fs::mkdirat(dir, name, rustix::fs::Mode::from_bits_retain(mode))
        .map_err(io::Error::from)
}

pub fn readlinkat_into<'a>(
    dir: BorrowedFd<'_>,
    name: &CStr,
    buffer: &'a mut [u8],
) -> io::Result<&'a [u8]> {
    // SAFETY[OS034]: dir/name are live, and buffer exposes its exact writable
    // pointer and length for the non-NUL-terminating readlinkat result.
    let length = unsafe {
        libc::readlinkat(
            dir.as_raw_fd(),
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    };
    if length < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(&buffer[..length as usize])
    }
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

pub fn openat2(
    dir: BorrowedFd<'_>,
    path: &CStr,
    flags: u64,
    mode: u64,
    resolve: u64,
) -> io::Result<File> {
    let how = OpenHow {
        flags,
        mode,
        resolve,
    };
    // SAFETY[OS035]: dir/path are live, how has the kernel open_how layout,
    // and the exact structure size is passed.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY[OS036]: a successful openat2 return is a fresh descriptor whose
    // ownership is transferred immediately into File.
    Ok(unsafe { File::from_raw_fd(raw as RawFd) })
}

pub fn create_memfd(name: &CStr) -> io::Result<File> {
    // SAFETY[OS037]: name is NUL-terminated and flags are valid memfd flags.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY[OS038]: a successful memfd_create return is a fresh descriptor
    // whose ownership is transferred immediately into File.
    Ok(unsafe { File::from_raw_fd(raw as RawFd) })
}

pub fn seal_file(fd: BorrowedFd<'_>) -> io::Result<()> {
    let seals = rustix::fs::SealFlags::SEAL
        | rustix::fs::SealFlags::SHRINK
        | rustix::fs::SealFlags::GROW
        | rustix::fs::SealFlags::WRITE;
    rustix::fs::fcntl_add_seals(fd, seals).map_err(io::Error::from)
}

pub fn pidfd_open(pid: Pid) -> io::Result<File> {
    // SAFETY[OS040]: pidfd_open consumes scalar arguments and returns a fresh
    // descriptor on success.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY[OS041]: the successful syscall result is uniquely owned and is
    // transferred immediately into File.
    Ok(unsafe { File::from_raw_fd(raw as RawFd) })
}

pub fn pidfd_send_signal(pidfd: BorrowedFd<'_>, signal: i32) -> io::Result<()> {
    // SAFETY[OS042]: pidfd is live, the siginfo pointer is intentionally null,
    // and the flags argument is zero as required by pidfd_send_signal.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn open_cloexec(path: &Path, read: bool, write: bool) -> io::Result<File> {
    OpenOptions::new()
        .read(read)
        .write(write)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)
}

pub fn into_owned_fd(file: File) -> OwnedFd {
    file.into()
}

pub fn bind_tcp_listener(address: SocketAddr, backlog: i32) -> io::Result<TcpListener> {
    let domain = if address.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY[OS043]: socket has scalar arguments and returns a fresh
    // descriptor on success.
    let raw = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY[OS044]: raw is a fresh successful socket descriptor and is
    // transferred immediately into OwnedFd.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let one: libc::c_int = 1;
    // SAFETY[OS045]: fd and one are live, and the supplied length exactly
    // describes the c_int SO_REUSEADDR value.
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&one as *const libc::c_int).cast(),
            std::mem::size_of_val(&one) as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let bind_result = match address {
        SocketAddr::V4(value) => {
            let native = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: value.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(value.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY[OS046]: native is live for the call and the supplied
            // length exactly matches sockaddr_in.
            unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&native as *const libc::sockaddr_in).cast(),
                    std::mem::size_of_val(&native) as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(value) => {
            let native = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: value.port().to_be(),
                sin6_flowinfo: value.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: value.ip().octets(),
                },
                sin6_scope_id: value.scope_id(),
            };
            // SAFETY[OS047]: native is live for the call and the supplied
            // length exactly matches sockaddr_in6.
            unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&native as *const libc::sockaddr_in6).cast(),
                    std::mem::size_of_val(&native) as libc::socklen_t,
                )
            }
        }
    };
    if bind_result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY[OS048]: fd owns a bound stream socket and backlog is clamped to a
    // positive scalar value.
    if unsafe { libc::listen(fd.as_raw_fd(), backlog.max(1)) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(TcpListener::from(fd))
}

pub fn reverse_dns(address: IpAddr) -> io::Result<String> {
    let address = SocketAddr::new(address, 0);
    let mut host = [0i8; libc::NI_MAXHOST as usize];
    let result = match address {
        SocketAddr::V4(value) => {
            let native = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: value.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(value.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY[OS049]: native and host are live for the call and their
            // exact lengths are supplied. Success guarantees host is NUL
            // terminated; overflow is returned as an EAI error.
            unsafe {
                libc::getnameinfo(
                    (&native as *const libc::sockaddr_in).cast(),
                    std::mem::size_of_val(&native) as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
        SocketAddr::V6(value) => {
            let native = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: value.port().to_be(),
                sin6_flowinfo: value.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: value.ip().octets(),
                },
                sin6_scope_id: value.scope_id(),
            };
            // SAFETY[OS050]: native and host are live for the call and their
            // exact lengths are supplied. Success guarantees NUL termination.
            unsafe {
                libc::getnameinfo(
                    (&native as *const libc::sockaddr_in6).cast(),
                    std::mem::size_of_val(&native) as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };
    if result != 0 {
        return Err(io::Error::other(format!(
            "getnameinfo failed with EAI code {result}"
        )));
    }
    // SAFETY[OS051]: successful getnameinfo above guarantees a NUL-terminated
    // string within the fixed host buffer.
    let value = unsafe { CStr::from_ptr(host.as_ptr()) };
    Ok(value.to_string_lossy().into_owned())
}

pub fn connect_unix_timeout(
    path: &Path,
    deadline: Instant,
    mut cancelled: impl FnMut() -> bool,
) -> io::Result<UnixStream> {
    let bytes = path.as_os_str().as_bytes();
    // SAFETY[OS052]: sockaddr_un consists only of integer/byte fields for
    // which the all-zero representation is valid.
    let capacity = unsafe { std::mem::zeroed::<libc::sockaddr_un>() }
        .sun_path
        .len();
    if bytes.is_empty() || bytes.len() >= capacity || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Unix socket path",
        ));
    }
    // SAFETY[OS053]: socket has scalar arguments and returns a fresh
    // descriptor on success.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY[OS054]: raw is a fresh successful socket descriptor and is
    // transferred immediately into OwnedFd.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY[OS055]: zero is a valid sockaddr_un initialization; family and
    // path are populated before the kernel observes it.
    let mut native: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    native.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // SAFETY[OS056]: bytes is strictly shorter than sun_path and the source
    // and destination are distinct live allocations.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            native.sun_path.as_mut_ptr().cast::<u8>(),
            bytes.len(),
        );
    }
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path)
        .saturating_add(bytes.len())
        .saturating_add(1) as libc::socklen_t;
    // SAFETY[OS057]: native remains live and length covers only the family,
    // pathname, and initialized trailing zero.
    let connected = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&native as *const libc::sockaddr_un).cast(),
            length,
        )
    };
    if connected != 0 {
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(code) if code == libc::EINPROGRESS || code == libc::EAGAIN
        ) {
            return Err(error);
        }
        loop {
            if cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "connection cancelled",
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Unix connection deadline exceeded",
                ));
            }
            let wait = remaining.min(Duration::from_millis(100)).as_millis().max(1) as i32;
            let mut poll = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY[OS058]: poll points to one live pollfd matching nfds=1.
            let result = unsafe { libc::poll(&mut poll, 1, wait) };
            if result == 0 {
                continue;
            }
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let mut socket_error: libc::c_int = 0;
            let mut option_length = std::mem::size_of_val(&socket_error) as libc::socklen_t;
            // SAFETY[OS059]: output pointers are live and option_length
            // exactly describes the c_int buffer.
            if unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut socket_error as *mut libc::c_int).cast(),
                    &mut option_length,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if socket_error != 0 {
                return Err(io::Error::from_raw_os_error(socket_error));
            }
            break;
        }
    }
    set_nonblocking(fd.as_fd(), false)?;
    Ok(UnixStream::from(fd))
}

pub fn unix_peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of_val(&credentials) as libc::socklen_t;
    // SAFETY[OS060]: credentials/length are exact live output buffers and the
    // stream owns a connected Unix descriptor.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected SO_PEERCRED size",
        ));
    }
    Ok(credentials.uid)
}

pub fn path_xattr_exists(path: &CStr, name: &CStr) -> io::Result<bool> {
    // SAFETY[OS061]: path/name are live NUL-terminated strings; Linux permits
    // a null output pointer with size zero for this length query.
    let length = unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if length >= 0 {
        return Ok(length > 0);
    }
    let error = io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(code) if code == libc::ENODATA || code == libc::ENOTSUP || code == libc::EOPNOTSUPP
    ) {
        Ok(false)
    } else {
        Err(error)
    }
}

pub fn poll_readable(fd: BorrowedFd<'_>, timeout: Duration) -> io::Result<bool> {
    let milliseconds = timeout.as_millis().min(i32::MAX as u128) as i32;
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY[OS062]: poll points to one live pollfd matching nfds=1.
    let result = unsafe { libc::poll(&mut poll, 1, milliseconds) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result > 0)
    }
}

pub fn poll_readable_raw(fd: RawFd, timeout: Duration) -> io::Result<bool> {
    let milliseconds = timeout.as_millis().min(i32::MAX as u128) as i32;
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY[OS087]: poll points to one live pollfd matching nfds=1; the
    // kernel reports POLLNVAL for an invalid scalar descriptor.
    let result = unsafe { libc::poll(&mut poll, 1, milliseconds) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result > 0)
    }
}

pub fn set_tcp_notsent_lowat(fd: BorrowedFd<'_>, value: u32) -> io::Result<()> {
    // SAFETY[OS063]: fd/value are live and the exact c_uint size is supplied.
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_NOTSENT_LOWAT,
            (&value as *const u32).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    } != 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn clear_supplementary_groups() -> io::Result<()> {
    // SAFETY[OS064]: a zero group count permits a null group pointer.
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn initialize_supplementary_groups(user: &CStr, gid: u32) -> io::Result<()> {
    // SAFETY[OS065]: user is NUL-terminated and gid is a scalar identity.
    if unsafe { libc::initgroups(user.as_ptr(), gid) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn set_res_gid(gid: u32) -> io::Result<()> {
    // SAFETY[OS066]: setresgid consumes scalar identities only.
    if unsafe { libc::setresgid(gid, gid, gid) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn set_res_uid(uid: u32) -> io::Result<()> {
    // SAFETY[OS067]: setresuid consumes scalar identities only.
    if unsafe { libc::setresuid(uid, uid, uid) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn set_umask(mask: libc::mode_t) {
    rustix::process::umask(rustix::fs::Mode::from_bits_retain(mask));
}

pub fn create_session() -> io::Result<Pid> {
    rustix::process::setsid()
        .map(rustix::process::Pid::as_raw_pid)
        .map_err(io::Error::from)
}

pub fn claim_inherited_unix_stream(fd: RawFd) -> io::Result<UnixStream> {
    // Validate the untrusted argv-provided number before constructing any
    // I/O-safety type from it. F_GETFD reports EBADF for a closed descriptor.
    set_cloexec_raw(fd, true)?;
    // SAFETY[OS085]: after exec the validated inherited descriptor has no
    // other Rust owner; ownership is transferred exactly once to UnixStream.
    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

pub fn daemonize() -> io::Result<()> {
    if process_thread_count()? != 1 {
        return Err(io::Error::other(
            "refusing to daemonize after threads started",
        ));
    }
    // SAFETY[OS069]: the process has exactly one task and daemonization occurs
    // before any httpd-rs background service is initialized.
    let first = unsafe { libc::fork() };
    if first < 0 {
        return Err(io::Error::last_os_error());
    }
    if first > 0 {
        std::process::exit(0);
    }
    // SAFETY[OS070]: the first child is not a process-group leader.
    if unsafe { libc::setsid() } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY[OS071]: SIG_IGN is a valid SIGHUP disposition installed during
    // single-threaded daemon setup.
    unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
    // SAFETY[OS072]: the process remains single-threaded between daemon forks.
    let second = unsafe { libc::fork() };
    if second < 0 {
        return Err(io::Error::last_os_error());
    }
    if second > 0 {
        std::process::exit(0);
    }
    set_umask(0o027);
    let null = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/dev/null")?;
    for target in 0..=2 {
        // SAFETY[OS073]: null is live and targets are the three standard
        // descriptors; dup2 atomically replaces each target.
        if unsafe { libc::dup2(null.as_raw_fd(), target) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    std::env::set_current_dir("/")?;
    Ok(())
}

pub fn install_signal_handlers(
    terminate: extern "C" fn(libc::c_int),
    reload: extern "C" fn(libc::c_int),
    reopen: extern "C" fn(libc::c_int),
) {
    // SAFETY[OS074]: each handler has the C signal ABI and performs only
    // lock-free atomic stores; installation occurs before the service loop.
    unsafe {
        libc::signal(libc::SIGTERM, terminate as libc::sighandler_t);
        libc::signal(libc::SIGINT, terminate as libc::sighandler_t);
        libc::signal(libc::SIGHUP, reload as libc::sighandler_t);
        libc::signal(libc::SIGUSR1, reopen as libc::sighandler_t);
    }
}

/// Make pipe/socket peer shutdown an ordinary `EPIPE` I/O result. Rust's
/// executable runtime normally installs this disposition, but embedders such
/// as libFuzzer provide their own `main` and therefore need to request it
/// explicitly before starting worker threads.
pub fn ignore_sigpipe() -> io::Result<()> {
    // SAFETY[OS089]: SIG_IGN is a valid SIGPIPE disposition. Callers install
    // it during single-threaded process initialization before any I/O worker.
    let previous = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    if previous == libc::SIG_ERR {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn move_unix_stream_to_fd(stream: UnixStream, target: RawFd) -> io::Result<UnixStream> {
    let source = stream.into_raw_fd();
    if source == target {
        // SAFETY[OS075]: into_raw_fd transferred the live stream descriptor;
        // ownership is immediately reconstructed without duplication.
        return Ok(unsafe { UnixStream::from_raw_fd(source) });
    }
    // SAFETY[OS076]: source is uniquely owned after into_raw_fd and target is
    // the fixed isolated descriptor chosen by the broker.
    if unsafe { libc::dup2(source, target) } < 0 {
        let error = io::Error::last_os_error();
        // SAFETY[OS077]: source remains uniquely owned on dup2 failure.
        unsafe { libc::close(source) };
        return Err(error);
    }
    // SAFETY[OS078]: successful dup2 created an independent target descriptor;
    // the uniquely owned source descriptor is no longer needed.
    unsafe { libc::close(source) };
    // SAFETY[OS079]: target is now a fresh duplicate owned only by this value.
    Ok(unsafe { UnixStream::from_raw_fd(target) })
}

fn close_standard_descriptors() {
    for fd in 0..=2 {
        // SAFETY[OS080]: each scalar standard descriptor is intentionally
        // closed in the isolated broker child.
        unsafe { libc::close(fd) };
    }
}

/// Install the privileged broker channel on fd 3 and erase every other
/// inherited descriptor. The broker child exits via [`exit_immediately`], so
/// no inherited Rust owner is subsequently dropped.
pub fn isolate_privileged_broker(stream: UnixStream) -> io::Result<UnixStream> {
    let stream = move_unix_stream_to_fd(stream, 3)?;
    close_range(4, 0)?;
    close_standard_descriptors();
    Ok(stream)
}

pub fn set_parent_death_signal(signal: i32, expected_parent: Pid) -> io::Result<()> {
    // SAFETY[OS081]: PR_SET_PDEATHSIG consumes scalar arguments only.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, signal, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if parent_pid() != expected_parent {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }
    Ok(())
}

pub fn harden_privileged_file_broker() -> io::Result<()> {
    restrict_privileged_file_broker_process()?;
    install_broker_seccomp()
}

pub fn restrict_privileged_file_broker_process() -> io::Result<()> {
    set_limit(libc::RLIMIT_CORE, 0)?;
    set_limit(libc::RLIMIT_FSIZE, 0)?;
    set_limit(libc::RLIMIT_NOFILE, 4)?;
    set_limit(libc::RLIMIT_CPU, 60)?;
    set_limit(libc::RLIMIT_AS, 512 * 1024 * 1024)?;
    disable_dumping()?;
    no_new_privileges()
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn install_broker_seccomp() -> io::Result<()> {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc000_00b7;

    fn statement(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
    fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    let allowed = [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_recvfrom,
        libc::SYS_sendto,
        libc::SYS_close,
        libc::SYS_open,
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_readlinkat,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_lseek,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_brk,
        libc::SYS_madvise,
        libc::SYS_fcntl,
        libc::SYS_futex,
        libc::SYS_clock_gettime,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_restart_syscall,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ];
    let mut filter = Vec::with_capacity(5 + allowed.len() * 2);
    filter.push(statement(BPF_LD_W_ABS, 4));
    filter.push(jump(BPF_JMP_JEQ_K, AUDIT_ARCH, 1, 0));
    filter.push(statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
    filter.push(statement(BPF_LD_W_ABS, 0));
    for syscall in allowed {
        filter.push(jump(BPF_JMP_JEQ_K, syscall as u32, 0, 1));
        filter.push(statement(BPF_RET_K, SECCOMP_RET_ALLOW));
    }
    filter.push(statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY[OS082]: program points to the live filter array for the duration
    // of prctl; no_new_privileges was installed before this function.
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &program as *const libc::sock_fprog,
        )
    } != 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn install_broker_seccomp() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the privileged broker has no seccomp profile for this architecture",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;
    use std::sync::{Arc, Barrier};

    #[test]
    fn inherited_descriptor_is_validated_before_ownership_is_claimed() {
        let error = claim_inherited_unix_stream(-1).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
    }

    #[test]
    fn child_setup_retains_only_the_explicit_descriptor_across_exec() {
        let retained = File::open("/dev/null").unwrap();
        let unrelated = File::open("/dev/null").unwrap();
        set_cloexec(unrelated.as_fd(), false).unwrap();
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("test -r /proc/self/fd/$1 && test ! -e /proc/self/fd/$2")
            .arg("httpd-rs-os-test")
            .arg(retained.as_raw_fd().to_string())
            .arg(unrelated.as_raw_fd().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut setup = ChildSetup::inherited(current_pid());
        setup.retained_fd = Some(retained.as_raw_fd());
        configure_child(&mut command, setup);
        assert!(command.status().unwrap().success());
        // The descriptor sweep occurs in the child and cannot mutate the
        // parent's descriptor table.
        assert!(fd_is_open(unrelated.as_fd()));
    }

    #[test]
    fn startup_fork_refuses_a_multithreaded_process() {
        let rendezvous = Arc::new(Barrier::new(2));
        let worker_rendezvous = Arc::clone(&rendezvous);
        let worker = std::thread::spawn(move || {
            worker_rendezvous.wait();
            worker_rendezvous.wait();
        });
        rendezvous.wait();
        let error = fork_single_threaded().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        rendezvous.wait();
        worker.join().unwrap();
    }

    #[test]
    fn listener_ownership_releases_the_port_on_drop() {
        let first = bind_tcp_listener("127.0.0.1:0".parse().unwrap(), 8).unwrap();
        let address = first.local_addr().unwrap();
        drop(first);
        let second = bind_tcp_listener(address, 8).unwrap();
        assert_eq!(second.local_addr().unwrap(), address);
    }
}
