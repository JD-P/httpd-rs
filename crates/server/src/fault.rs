//! Deterministic, opt-in failure injection at syscall and transport boundaries.
//!
//! The production build compiles every check to an unconditional success.
//! Quality jobs enable `fault-injection` and install a per-process plan before
//! exercising error paths that are otherwise impractical to reproduce.

use std::io;

#[cfg(feature = "fault-injection")]
mod enabled {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    #[derive(Clone, Copy)]
    struct Failure {
        remaining: usize,
        kind: io::ErrorKind,
    }

    fn plan() -> &'static Mutex<HashMap<String, Failure>> {
        static PLAN: OnceLock<Mutex<HashMap<String, Failure>>> = OnceLock::new();
        PLAN.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn test_serial() -> &'static Mutex<()> {
        static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();
        SERIAL.get_or_init(|| Mutex::new(()))
    }

    /// Serialize tests that mutate the process-wide injection plan. Different
    /// boundary names are not enough: `clear` intentionally clears all names.
    pub struct TestGuard {
        _serial: MutexGuard<'static, ()>,
    }

    impl Drop for TestGuard {
        fn drop(&mut self) {
            clear();
        }
    }

    pub fn test_guard() -> TestGuard {
        let serial = test_serial()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        clear();
        TestGuard { _serial: serial }
    }

    /// Fail the named boundary after `after` successful checks.
    pub fn configure(name: &str, after: usize, kind: io::ErrorKind) {
        plan()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(
                name.to_string(),
                Failure {
                    remaining: after,
                    kind,
                },
            );
    }

    pub fn clear() {
        plan()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();
    }

    pub fn hit(name: &str) -> io::Result<()> {
        let mut guard = plan().lock().unwrap_or_else(|poison| poison.into_inner());
        let Some(failure) = guard.get_mut(name) else {
            return Ok(());
        };
        if failure.remaining > 0 {
            failure.remaining -= 1;
            return Ok(());
        }
        let kind = failure.kind;
        guard.remove(name);
        Err(io::Error::new(kind, format!("injected failure at {name}")))
    }
}

#[cfg(feature = "fault-injection")]
pub use enabled::{clear, configure, hit, test_guard, TestGuard};

#[cfg(not(feature = "fault-injection"))]
#[inline]
pub(crate) fn hit(_name: &str) -> io::Result<()> {
    Ok(())
}
