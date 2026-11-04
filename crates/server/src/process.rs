//! Linux process and descriptor-isolation primitives.
//!
//! Keep the raw syscall boundary in one place.  Child `pre_exec` hooks may use
//! these functions because they perform only libc syscalls and construct an
//! `io::Error` on failure; they do not allocate, lock, or consult process-wide
//! Rust state after `fork`.

use std::io;

#[cfg(target_env = "gnu")]
type RlimitResource = libc::__rlimit_resource_t;
#[cfg(not(target_env = "gnu"))]
type RlimitResource = libc::c_int;

pub(crate) const FIRST_NONSTANDARD_FD: u32 = 3;
// linux/close_range.h: apply FD_CLOEXEC instead of closing immediately.  This
// preserves Rust's private exec-error pipe until exec while guaranteeing that
// every unrelated descriptor disappears in the new image.
const CLOSE_RANGE_CLOEXEC_FLAG: u32 = 1 << 2;

fn close_range(first: u32, flags: u32) -> io::Result<()> {
    let result = unsafe { libc::syscall(libc::SYS_close_range, first, u32::MAX, flags) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Close every inherited descriptor other than stdin/stdout/stderr.  Normal
/// daemon startup calls this before it opens configuration, listeners or logs,
/// so only Vapache-owned descriptors can reach the later daemon fork.
pub fn close_inherited_descriptors() -> io::Result<()> {
    close_range(FIRST_NONSTANDARD_FD, 0)
}

/// Make every non-standard descriptor close on the next exec.  Child setup
/// can subsequently clear CLOEXEC on its one explicitly retained descriptor.
pub(crate) fn cloexec_unrelated_descriptors() -> io::Result<()> {
    close_range(FIRST_NONSTANDARD_FD, CLOSE_RANGE_CLOEXEC_FLAG)
}

pub(crate) fn set_cloexec(fd: libc::c_int, enabled: bool) -> io::Result<()> {
    let current = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if current < 0 {
        return Err(io::Error::last_os_error());
    }
    let updated = if enabled {
        current | libc::FD_CLOEXEC
    } else {
        current & !libc::FD_CLOEXEC
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, updated) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn set_limit(resource: RlimitResource, value: u64) -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Arm a child so it cannot survive the parent that owns its protocol state.
/// The post-prctl parent check closes the fork-to-prctl orphan race.
pub(crate) fn bind_to_parent(parent: libc::pid_t) -> io::Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::getppid() } != parent {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }
    Ok(())
}

pub(crate) fn no_new_privileges() -> io::Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn disable_dumping() -> io::Result<()> {
    set_limit(libc::RLIMIT_CORE, 0)?;
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Report whether a direct child has exited without reaping it. Keeping the
/// child as a zombie preserves ownership of its numeric PID/PGID until the
/// caller has signalled and cleaned up any descendants in that process group.
pub(crate) fn child_exited_unreaped(pid: libc::pid_t) -> io::Result<bool> {
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            info.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let info = unsafe { info.assume_init() };
    Ok(unsafe { info.si_pid() } != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn cloexec_sweep_preserves_only_an_explicitly_restored_descriptor() {
        let first = std::fs::File::open("/dev/null").unwrap();
        let second = std::fs::File::open("/dev/null").unwrap();
        // Keep the process-wide descriptor flag mutation inside a disposable
        // child so parallel Rust tests cannot observe it.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let ok = cloexec_unrelated_descriptors().is_ok()
                && set_cloexec(first.as_raw_fd(), true).is_ok()
                && set_cloexec(first.as_raw_fd(), false).is_ok();
            let wrong_parent_rejected = bind_to_parent(unsafe { libc::getppid() } + 1).is_err();
            let invalid_limit_rejected = set_limit(!0 as RlimitResource, 0).is_err();
            let first_flags = unsafe { libc::fcntl(first.as_raw_fd(), libc::F_GETFD) };
            let second_flags = unsafe { libc::fcntl(second.as_raw_fd(), libc::F_GETFD) };
            let isolated = ok
                && wrong_parent_rejected
                && invalid_limit_rejected
                && first_flags & libc::FD_CLOEXEC == 0
                && second_flags & libc::FD_CLOEXEC != 0;
            unsafe { libc::_exit(if isolated { 0 } else { 1 }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn exited_child_can_be_observed_without_reaping_or_releasing_its_pid() {
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe { libc::_exit(0) };
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while !child_exited_unreaped(child).unwrap() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert!(child_exited_unreaped(child).is_err());
    }
}
