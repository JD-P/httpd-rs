//! One fail-closed regex boundary for every Apache directive surface.
//!
//! The underlying compatibility crate admits a closed, byte-oriented PCRE2
//! subset and executes only its translated IR. Runtime resource errors are a
//! non-match here because directive regexes frequently guard authorization and
//! routing decisions.

use std::cell::RefCell;

const APACHE_REGEX_PATTERN_LIMIT: usize = 8190;
const APACHE_REGEX_AUTOMATA_LIMIT: usize = 256 * 1024;

struct CompileBudget {
    limit: usize,
    used: usize,
    dependency_lease: Option<crate::resource::DependencyWorkspaceLease>,
}

thread_local! {
    static COMPILE_BUDGET: RefCell<Option<CompileBudget>> = const { RefCell::new(None) };
}

struct CompileBudgetScope {
    previous: Option<CompileBudget>,
}

impl Drop for CompileBudgetScope {
    fn drop(&mut self) {
        COMPILE_BUDGET.with(|budget| {
            budget.replace(self.previous.take());
        });
    }
}

#[cfg(test)]
pub(crate) fn with_compile_budget<T>(
    limit: usize,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<(T, usize), String> {
    let (value, used, _) = with_compile_budget_inner(limit, None, operation)?;
    Ok((value, used))
}

pub(crate) fn with_accounted_compile_budget<T>(
    limit: usize,
    dependency_lease: crate::resource::DependencyWorkspaceLease,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<(T, usize, crate::resource::DependencyWorkspaceLease), String> {
    let (value, used, dependency_lease) =
        with_compile_budget_inner(limit, Some(dependency_lease), operation)?;
    Ok((
        value,
        used,
        dependency_lease.expect("accounted compile scope retains its lease"),
    ))
}

fn with_compile_budget_inner<T>(
    limit: usize,
    dependency_lease: Option<crate::resource::DependencyWorkspaceLease>,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<(T, usize, Option<crate::resource::DependencyWorkspaceLease>), String> {
    let previous = COMPILE_BUDGET.with(|budget| {
        budget.replace(Some(CompileBudget {
            limit,
            used: 0,
            dependency_lease,
        }))
    });
    if previous.is_some() {
        COMPILE_BUDGET.with(|budget| {
            budget.replace(previous);
        });
        return Err("nested regex dependency compilation boundary".into());
    }
    let scope = CompileBudgetScope { previous: None };
    let value = operation();
    let current = COMPILE_BUDGET.with(|budget| budget.replace(None));
    drop(scope);
    let current = current.expect("compile budget scope remains installed");
    Ok((value?, current.used, current.dependency_lease))
}

fn reserve_compile_workspace(bytes: usize) -> Result<(), String> {
    COMPILE_BUDGET.with(|budget| {
        let mut budget = budget.borrow_mut();
        let Some(budget) = budget.as_mut() else {
            return Ok(());
        };
        let Some(next) = budget.used.checked_add(bytes) else {
            return Err("aggregate regex dependency workspace overflow".into());
        };
        if next > budget.limit {
            return Err("aggregate regex dependency workspace limit reached".into());
        }
        if let Some(lease) = budget.dependency_lease.as_mut() {
            lease
                .reserve_more(bytes as u64)
                .map_err(|error| error.to_string())?;
        }
        budget.used = next;
        Ok(())
    })
}

fn release_compile_workspace(bytes: usize) {
    COMPILE_BUDGET.with(|budget| {
        if let Some(budget) = budget.borrow_mut().as_mut() {
            budget.used = budget.used.saturating_sub(bytes);
            if let Some(lease) = budget.dependency_lease.as_mut() {
                lease
                    .shrink_to(budget.used as u64)
                    .expect("compile workspace release only shrinks its lease");
            }
        }
    });
}

#[derive(Clone, Debug)]
pub struct Regex {
    inner: httpd_rs_pcre2::bytes::Regex,
}

impl Regex {
    pub fn new(pattern: &str) -> Result<Self, String> {
        Self::compile(pattern, false)
    }

    pub fn compile(pattern: &str, caseless: bool) -> Result<Self, String> {
        let mut builder = httpd_rs_pcre2::bytes::RegexBuilder::new();
        builder
            .caseless(caseless)
            .utf(false)
            .ucp(false)
            .max_pattern_size(APACHE_REGEX_PATTERN_LIMIT)
            .size_limit(APACHE_REGEX_AUTOMATA_LIMIT);
        let workspace = builder
            .dependency_workspace_bound()
            .ok_or_else(|| "regex dependency workspace bound overflow".to_string())?;
        reserve_compile_workspace(workspace)?;
        match builder.build(pattern) {
            Ok(inner) => {
                let retained = inner.dependency_workspace_bound();
                if retained > workspace {
                    release_compile_workspace(workspace);
                    return Err("regex retained workspace exceeds compilation boundary".into());
                }
                release_compile_workspace(workspace - retained);
                Ok(Self { inner })
            }
            Err(error) => {
                release_compile_workspace(workspace);
                Err(error.to_string())
            }
        }
    }

    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    pub fn is_match(&self, subject: &[u8]) -> bool {
        self.inner.is_match(subject).unwrap_or(false)
    }

    pub fn captures<'s>(&self, subject: &'s [u8]) -> Option<httpd_rs_pcre2::bytes::Captures<'s>> {
        self.inner.captures(subject).ok().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::{with_compile_budget, Regex};

    #[test]
    fn directive_boundary_uses_the_closed_pcre_grammar() {
        for pattern in [
            "",
            r"^literal$",
            r"^(?:one|two)+$",
            r"(?i:admin)",
            r"(?<word>[A-Za-z_][A-Za-z0-9_]*)",
            r"\A\Q.*\E\z",
            r"[[:digit:]A-F]+",
        ] {
            assert!(Regex::new(pattern).is_ok(), "rejected {pattern:?}");
        }

        for pattern in [
            r"(?=lookahead)",
            r"(?<=lookbehind)",
            r"(?>atomic)",
            r"(?R)",
            r"(capture)\1",
            r"(*ACCEPT)",
            r"possessive++",
            r"(?u:rust_unicode)",
            r"(?R:rust_crlf)",
            r"\b{start}",
            r"\R",
            r"\R\s",
            r"(?m)^",
            r"\D(?m:^)$",
            r"\y",
            "(?x)(?\r)",
        ] {
            assert!(Regex::new(pattern).is_err(), "admitted {pattern:?}");
        }
    }

    #[test]
    fn pcre_literal_escapes_cannot_become_backend_assertions() {
        let left = Regex::new(r"\<").unwrap();
        let right = Regex::new(r"\>").unwrap();
        assert!(left.is_match(b"<"));
        assert!(!left.is_match(b"word"));
        assert!(right.is_match(b">"));
        assert!(!right.is_match(b"word"));
    }

    #[test]
    fn aggregate_compile_budget_rejects_before_dependency_entry() {
        let error = with_compile_budget(1, || Regex::new("literal")).unwrap_err();
        assert!(error.contains("aggregate regex dependency workspace"));

        let (_, used) = with_compile_budget(8 * 1024 * 1024, || Regex::new("literal")).unwrap();
        assert!(used > 0);
        assert!(Regex::new("after").is_ok());
    }
}
