//! Deterministic, opt-in failure injection at syscall and transport boundaries.
//!
//! The production build compiles every check to an unconditional success.
//! Quality jobs enable `fault-injection` and install an explicitly inherited
//! plan before exercising error paths that are otherwise impractical to
//! reproduce. Plans are isolated between parallel tests but follow one
//! request across Tokio tasks, blocking workers, and native helper threads.

use std::io;

#[cfg(feature = "fault-injection")]
mod enabled {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::future::Future;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Copy)]
    struct Failure {
        remaining: usize,
        kind: io::ErrorKind,
    }

    #[derive(Default)]
    struct PlanState {
        named: HashMap<String, Failure>,
        sequence: Option<Failure>,
        trace: Vec<String>,
    }

    /// One explicitly inherited deterministic campaign. The shared state is
    /// deliberate: a request can cross Tokio and blocking-worker threads, but
    /// unrelated parallel tests retain separate thread/task-local plans.
    #[derive(Clone)]
    struct Plan(Arc<Mutex<PlanState>>);

    impl Plan {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(PlanState::default())))
        }

        fn state(&self) -> std::sync::MutexGuard<'_, PlanState> {
            self.0.lock().unwrap_or_else(|error| error.into_inner())
        }
    }

    thread_local! {
        static THREAD_PLAN: RefCell<Option<Plan>> = const { RefCell::new(None) };
    }

    tokio::task_local! {
        static TASK_PLAN: Plan;
    }

    fn active_plan() -> Option<Plan> {
        TASK_PLAN
            .try_with(Clone::clone)
            .ok()
            .or_else(|| THREAD_PLAN.with(|plan| plan.borrow().clone()))
    }

    fn plan() -> Plan {
        if let Some(plan) = active_plan() {
            return plan;
        }
        let plan = Plan::new();
        THREAD_PLAN.with(|slot| *slot.borrow_mut() = Some(plan.clone()));
        plan
    }

    /// Clear this test thread's injection plan on entry and exit.
    pub struct TestGuard {
        previous: Option<Plan>,
    }

    impl Drop for TestGuard {
        fn drop(&mut self) {
            THREAD_PLAN.with(|slot| *slot.borrow_mut() = self.previous.take());
        }
    }

    pub fn test_guard() -> TestGuard {
        let previous = THREAD_PLAN.with(|slot| slot.borrow_mut().replace(Plan::new()));
        TestGuard { previous }
    }

    /// Fail the named boundary after `after` successful checks.
    pub fn configure(name: &str, after: usize, kind: io::ErrorKind) {
        plan().state().named.insert(
            name.to_string(),
            Failure {
                remaining: after,
                kind,
            },
        );
    }

    /// Fail after `after` successful checkpoints, independent of their name.
    /// Running once without this setting yields the exact ordered trace; a
    /// campaign can then rerun the operation for every trace index.
    pub fn configure_sequence(after: usize, kind: io::ErrorKind) {
        let plan = plan();
        let mut state = plan.state();
        state.trace.clear();
        state.sequence = Some(Failure {
            remaining: after,
            kind,
        });
    }

    pub fn clear() {
        let plan = plan();
        let mut state = plan.state();
        state.named.clear();
        state.sequence = None;
        state.trace.clear();
    }

    pub fn clear_trace() {
        plan().state().trace.clear();
    }

    pub fn trace() -> Vec<String> {
        plan().state().trace.clone()
    }

    pub fn hit(name: &str) -> io::Result<()> {
        let Some(plan) = active_plan() else {
            return Ok(());
        };
        let mut state = plan.state();
        state.trace.push(name.to_string());

        if let Some(mut failure) = state.sequence.take() {
            if failure.remaining == 0 {
                return Err(io::Error::new(
                    failure.kind,
                    format!("injected transition failure at {name}"),
                ));
            }
            failure.remaining -= 1;
            state.sequence = Some(failure);
        }

        let Some(failure) = state.named.get_mut(name) else {
            return Ok(());
        };
        if failure.remaining > 0 {
            failure.remaining -= 1;
            return Ok(());
        }
        let kind = failure.kind;
        state.named.remove(name);
        Err(io::Error::new(kind, format!("injected failure at {name}")))
    }

    fn with_plan<T>(inherited: Option<Plan>, operation: impl FnOnce() -> T) -> T {
        let previous =
            THREAD_PLAN.with(|slot| std::mem::replace(&mut *slot.borrow_mut(), inherited));
        struct Restore(Option<Plan>);
        impl Drop for Restore {
            fn drop(&mut self) {
                THREAD_PLAN.with(|slot| *slot.borrow_mut() = self.0.take());
            }
        }
        let _restore = Restore(previous);
        operation()
    }

    pub(crate) fn inherited<F, T>(operation: F) -> impl FnOnce() -> T + Send + 'static
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let inherited = active_plan();
        move || with_plan(inherited, operation)
    }

    pub(crate) fn spawn_blocking<F, T>(operation: F) -> tokio::task::JoinHandle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let inherited = active_plan();
        tokio::task::spawn_blocking(move || with_plan(inherited, operation))
    }

    pub(crate) fn spawn_thread<F, T>(operation: F) -> std::thread::JoinHandle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let inherited = active_plan();
        std::thread::spawn(move || with_plan(inherited, operation))
    }

    pub(crate) fn scope_future<F>(future: F) -> impl Future<Output = F::Output>
    where
        F: Future,
    {
        // Capture before the returned future is handed to `tokio::spawn`.
        // Looking up the plan inside an `async fn` body happens only when the
        // new task is polled, after its caller's thread-local context is gone.
        let inherited = active_plan();
        async move {
            if TASK_PLAN.try_with(|_| ()).is_ok() {
                future.await
            } else if let Some(inherited) = inherited {
                TASK_PLAN.scope(inherited, future).await
            } else {
                future.await
            }
        }
    }
}

#[cfg(feature = "fault-injection")]
pub use enabled::{
    clear, clear_trace, configure, configure_sequence, hit, test_guard, trace, TestGuard,
};

#[cfg(feature = "fault-injection")]
pub(crate) use enabled::{inherited, scope_future, spawn_blocking, spawn_thread};

#[cfg(not(feature = "fault-injection"))]
#[inline]
pub(crate) fn hit(_name: &str) -> io::Result<()> {
    Ok(())
}

#[cfg(not(feature = "fault-injection"))]
pub(crate) fn spawn_blocking<F, T>(operation: F) -> tokio::task::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(operation)
}

#[cfg(not(feature = "fault-injection"))]
pub(crate) fn inherited<F, T>(operation: F) -> F
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    operation
}

#[cfg(not(feature = "fault-injection"))]
pub(crate) fn spawn_thread<F, T>(operation: F) -> std::thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    std::thread::spawn(operation)
}

#[cfg(not(feature = "fault-injection"))]
pub(crate) fn scope_future<F>(future: F) -> F
where
    F: std::future::Future,
{
    future
}

#[cfg(all(test, feature = "fault-injection"))]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plan_follows_every_supported_execution_boundary() {
        let _guard = test_guard();
        hit("root").unwrap();

        spawn_thread(|| hit("native-thread").unwrap())
            .join()
            .unwrap();
        tokio::spawn(scope_future(async {
            hit("tokio-task").unwrap();
            spawn_blocking(|| hit("blocking-worker").unwrap())
                .await
                .unwrap();
        }))
        .await
        .unwrap();

        assert_eq!(
            trace(),
            ["root", "native-thread", "tokio-task", "blocking-worker"]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sequence_failure_is_shared_across_task_and_worker_transitions() {
        let _guard = test_guard();
        configure_sequence(2, io::ErrorKind::ConnectionReset);
        hit("root").unwrap();
        let result = tokio::spawn(scope_future(async {
            hit("task").unwrap();
            spawn_blocking(|| hit("worker")).await.unwrap()
        }))
        .await
        .unwrap();

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(trace(), ["root", "task", "worker"]);
    }
}
