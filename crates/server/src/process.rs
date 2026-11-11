//! Safe server-facing process and descriptor-isolation API.
//!
//! Raw syscalls live in `vapache-os`; this module preserves the original
//! domain names used by the server while keeping production code safe Rust.

pub use vapache_os::close_inherited_descriptors;
pub(crate) use vapache_os::{
    bind_to_parent, child_exited_unreaped, disable_dumping, no_new_privileges, set_limit,
};
#[cfg(test)]
pub(crate) use vapache_os::{cloexec_unrelated_descriptors, RlimitResource};

#[cfg(test)]
pub(crate) fn set_cloexec(fd: std::os::fd::RawFd, enabled: bool) -> std::io::Result<()> {
    vapache_os::set_cloexec_raw(fd, enabled)
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
