//! Deterministic, opt-in failure injection at syscall and transport boundaries.
//!
//! The production build compiles every check to an unconditional success.
//! Quality jobs enable `fault-injection` and install a per-thread plan before
//! exercising error paths that are otherwise impractical to reproduce.  The
//! thread-local scope is deliberate: Rust runs unrelated unit tests in
//! parallel, and a process-wide failpoint could otherwise perturb a test that
//! merely happens to cross the same production boundary.

use std::io;

#[cfg(feature = "fault-injection")]
mod enabled {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[derive(Clone, Copy)]
    struct Failure {
        remaining: usize,
        kind: io::ErrorKind,
    }

    thread_local! {
        static PLAN: RefCell<HashMap<String, Failure>> = RefCell::new(HashMap::new());
    }

    /// Clear this test thread's injection plan on entry and exit.
    pub struct TestGuard;

    impl Drop for TestGuard {
        fn drop(&mut self) {
            clear();
        }
    }

    pub fn test_guard() -> TestGuard {
        clear();
        TestGuard
    }

    /// Fail the named boundary after `after` successful checks.
    pub fn configure(name: &str, after: usize, kind: io::ErrorKind) {
        PLAN.with(|plan| {
            plan.borrow_mut().insert(
                name.to_string(),
                Failure {
                    remaining: after,
                    kind,
                },
            )
        });
    }

    pub fn clear() {
        PLAN.with(|plan| plan.borrow_mut().clear());
    }

    pub fn hit(name: &str) -> io::Result<()> {
        PLAN.with(|plan| {
            let mut plan = plan.borrow_mut();
            let Some(failure) = plan.get_mut(name) else {
                return Ok(());
            };
            if failure.remaining > 0 {
                failure.remaining -= 1;
                return Ok(());
            }
            let kind = failure.kind;
            plan.remove(name);
            Err(io::Error::new(kind, format!("injected failure at {name}")))
        })
    }
}

#[cfg(feature = "fault-injection")]
pub use enabled::{clear, configure, hit, test_guard, TestGuard};

#[cfg(not(feature = "fault-injection"))]
#[inline]
pub(crate) fn hit(_name: &str) -> io::Result<()> {
    Ok(())
}
