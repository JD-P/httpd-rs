//! Stack-safe, polynomial shell-pattern matching.
//!
//! The original executable Verus kernels directly implemented the recursive
//! specification.  That established semantic equivalence, but `*` used
//! recursive backtracking: a long star run exhausted the connection stack and
//! a failing match could take exponential time.  These evaluators implement
//! the same recurrences bottom-up.  Runtime callers therefore use O(value)
//! memory, O(pattern * value) work, and no input-dependent call stack.

/// Apache rejects access-file lines longer than 8190 bytes.  Keeping the same
/// ceiling also bounds every configuration-originated shell pattern before it
/// reaches the matcher.
pub const MAX_PATTERN_BYTES: usize = 8190;

/// Request-controlled expression operands get a tighter, per-evaluation work
/// ceiling.  Four million DP cells is large enough for ordinary header/path
/// predicates but rejects the 8 KiB by 8 KiB worker-exhaustion shape.
pub const MAX_EXPR_GLOB_WORK: u64 = 4 * 1024 * 1024;

/// Match the fnmatch dialect used by `<Files>`, `<Location>`, `<Directory>`,
/// `<Proxy>` and `IndexIgnore`.
pub fn fnmatch(pattern: &[u8], value: &[u8], path_mode: bool) -> bool {
    httpd_rs_verified::fnmatch_dp_match(pattern, value, path_mode)
}

/// Request-time form of [`fnmatch`].  The DP algorithm is polynomial, but an
/// 8 KiB pattern multiplied by an attacker-controlled URL (or by every
/// autoindex entry) is still enough to monopolize a worker.  Admit the exact
/// rectangular DP state bound before allocating its rows and debit it from
/// the request-wide policy meter.
pub fn fnmatch_budgeted(
    pattern: &[u8],
    value: &[u8],
    path_mode: bool,
    budget: &crate::resource::RequestPolicyBudget,
) -> Result<bool, &'static str> {
    if !httpd_rs_verified::glob_match_resource_admit(
        pattern.len() as u64,
        value.len() as u64,
        MAX_PATTERN_BYTES as u64,
        crate::resource::MAX_POLICY_WORK_UNITS,
    ) {
        let _ = budget.charge_work(crate::resource::MAX_POLICY_WORK_UNITS.saturating_add(1));
        return Err("shell glob work limit exceeded");
    }
    let work = (pattern.len() as u64 + 1)
        .checked_mul(value.len() as u64 + 1)
        .ok_or("shell glob work limit exceeded")?;
    budget.charge_work(work)?;
    Ok(fnmatch(pattern, value, path_mode))
}

#[derive(Clone, Copy, Debug)]
enum ExprToken {
    Star,
    Any,
    Literal(u8),
}

fn expr_tokens(pattern: &[u8], path_mode: bool) -> Vec<ExprToken> {
    let mut tokens = Vec::with_capacity(pattern.len());
    let mut i = 0usize;
    while i < pattern.len() {
        if pattern[i] == b'*' {
            // Preserve the Apache-expression compatibility rule already
            // captured by expr_glob_spec: in fnmatch mode `*/` is elided.
            if path_mode && i + 1 < pattern.len() && pattern[i + 1] == b'/' {
                i += 2;
            } else {
                tokens.push(ExprToken::Star);
                i += 1;
            }
        } else if pattern[i] == b'?' {
            tokens.push(ExprToken::Any);
            i += 1;
        } else {
            tokens.push(ExprToken::Literal(pattern[i]));
            i += 1;
        }
    }
    tokens
}

/// Match the smaller `ap_expr` glob dialect.  Oversize work is an evaluation
/// error, never a false match: callers must fail the authorization expression
/// closed rather than silently skipping a policy rule.
pub fn expr_match(pattern: &[u8], value: &[u8], path_mode: bool) -> Result<bool, &'static str> {
    if !httpd_rs_verified::glob_match_resource_admit(
        pattern.len() as u64,
        value.len() as u64,
        MAX_PATTERN_BYTES as u64,
        MAX_EXPR_GLOB_WORK,
    ) {
        return Err("expression glob work limit exceeded");
    }
    let tokens = expr_tokens(pattern, path_mode);
    let mut next = vec![false; value.len() + 1];
    next[value.len()] = true;
    let mut current = vec![false; value.len() + 1];
    for token in tokens.iter().rev() {
        current.fill(false);
        match *token {
            ExprToken::Star => {
                current[value.len()] = next[value.len()];
                for j in (0..value.len()).rev() {
                    current[j] = next[j] || (value[j] != b'/' && current[j + 1]);
                }
            }
            ExprToken::Any => {
                for j in 0..value.len() {
                    current[j] = (path_mode || value[j] != b'/') && next[j + 1];
                }
            }
            ExprToken::Literal(byte) => {
                for j in 0..value.len() {
                    current[j] = value[j] == byte && next[j + 1];
                }
            }
        }
        std::mem::swap(&mut current, &mut next);
    }
    Ok(next[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnmatch_preserves_classes_escapes_and_path_mode() {
        assert!(fnmatch(b"[a-c]\\?.txt", b"b?.txt", false));
        assert!(fnmatch(b"[^a].txt", b"b.txt", false));
        assert!(!fnmatch(b"[^a].txt", b"a.txt", false));
        assert!(fnmatch(b"/admin/*", b"/admin/x", true));
        assert!(!fnmatch(b"/admin/*", b"/admin/x/y", true));
        assert!(fnmatch(b"[abc", b"[abc", false));
    }

    #[test]
    fn pathological_star_patterns_are_stack_safe_and_fast() {
        let stars = vec![b'*'; 100_000];
        assert!(fnmatch(&stars, b"name", false));
        let mut pattern = b"*a".repeat(128);
        pattern.push(b'b');
        assert!(!fnmatch(&pattern, &vec![b'a'; 4_000], false));
    }

    #[test]
    fn expression_glob_enforces_work_budget() {
        assert_eq!(expr_match(b"*a*b", b"aaab", false), Ok(true));
        assert!(expr_match(&vec![b'*'; 8_000], &vec![b'a'; 8_000], false).is_err());
    }

    #[test]
    fn request_glob_rejects_the_rectangle_before_allocating_it() {
        let budget = crate::resource::RequestPolicyBudget::default();
        let pattern = vec![b'*'; MAX_PATTERN_BYTES];
        let subject = vec![b'a'; 3_000];
        assert!(fnmatch_budgeted(&pattern, &subject, false, &budget).is_err());
        assert!(budget.failed());

        let budget = crate::resource::RequestPolicyBudget::default();
        assert_eq!(
            fnmatch_budgeted(b"*.html", b"index.html", false, &budget),
            Ok(true)
        );
        assert!(budget.charged_work() > 0);
    }

    #[test]
    fn iterative_kernels_refine_verified_specs_on_small_exhaustive_inputs() {
        fn words(alphabet: &[u8], max: usize) -> Vec<Vec<u8>> {
            let mut out = vec![Vec::new()];
            for _ in 0..max {
                let prior = out.clone();
                for prefix in prior {
                    for byte in alphabet {
                        let mut word = prefix.clone();
                        word.push(*byte);
                        out.push(word);
                    }
                }
            }
            out.sort();
            out.dedup();
            out
        }

        let patterns = words(b"ab*?[]!^\\-", 3);
        let values = words(b"ab/[]", 3);
        for pattern in &patterns {
            for value in &values {
                for path_mode in [false, true] {
                    assert_eq!(
                        fnmatch(pattern, value, path_mode),
                        httpd_rs_verified::fnmatch_match(pattern, value, path_mode),
                        "fnmatch mismatch: pattern={pattern:?} value={value:?} path={path_mode}"
                    );
                }
            }
        }

        let expr_patterns = words(b"ab*?/", 3);
        for pattern in &expr_patterns {
            for value in &values {
                for path_mode in [false, true] {
                    assert_eq!(
                        expr_match(pattern, value, path_mode),
                        Ok(httpd_rs_verified::expr_glob_match(
                            pattern, value, path_mode
                        )),
                        "expr mismatch: pattern={pattern:?} value={value:?} path={path_mode}"
                    );
                }
            }
        }
    }
}
