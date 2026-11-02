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

#[derive(Clone, Copy, Debug)]
enum FnToken {
    Star,
    Any,
    Literal(u8),
    Class {
        body_start: usize,
        body_end: usize,
        negated: bool,
    },
}

fn class_end(pattern: &[u8], mut from: usize) -> Option<usize> {
    while from < pattern.len() {
        if pattern[from] == b']' {
            return Some(from);
        }
        if pattern[from] == b'\\' && from + 1 < pattern.len() {
            from += 2;
        } else {
            from += 1;
        }
    }
    None
}

fn fn_tokens(pattern: &[u8]) -> Vec<FnToken> {
    let mut tokens = Vec::with_capacity(pattern.len());
    let mut i = 0usize;
    while i < pattern.len() {
        match pattern[i] {
            b'*' => {
                tokens.push(FnToken::Star);
                i += 1;
            }
            b'?' => {
                tokens.push(FnToken::Any);
                i += 1;
            }
            b'[' if i + 1 < pattern.len() => {
                let negated = matches!(pattern[i + 1], b'!' | b'^');
                let mut body_start = i + 1 + usize::from(negated);
                // Preserve the existing verified kernel's class grammar: a
                // leading `]` is skipped while finding the real terminator.
                if body_start < pattern.len() && pattern[body_start] == b']' {
                    body_start += 1;
                }
                if let Some(end) = class_end(pattern, body_start) {
                    tokens.push(FnToken::Class {
                        body_start,
                        body_end: end,
                        negated,
                    });
                    i = end + 1;
                } else {
                    tokens.push(FnToken::Literal(b'['));
                    i += 1;
                }
            }
            b'\\' if i + 1 < pattern.len() => {
                tokens.push(FnToken::Literal(pattern[i + 1]));
                i += 2;
            }
            byte => {
                tokens.push(FnToken::Literal(byte));
                i += 1;
            }
        }
    }
    tokens
}

fn class_contains(pattern: &[u8], mut i: usize, end: usize, byte: u8, path_mode: bool) -> bool {
    while i < end {
        if pattern[i] == b'\\' && i + 1 < end {
            if byte == pattern[i + 1] && (!path_mode || byte != b'/') {
                return true;
            }
            i += 2;
        } else if i + 2 < end && pattern[i + 1] == b'-' {
            if (!path_mode || byte != b'/') && pattern[i] <= byte && byte <= pattern[i + 2] {
                return true;
            }
            i += 3;
        } else {
            if byte == pattern[i] && (!path_mode || byte != b'/') {
                return true;
            }
            i += 1;
        }
    }
    false
}

/// Match the fnmatch dialect used by `<Files>`, `<Location>`, `<Directory>`,
/// `<Proxy>` and `IndexIgnore`.
pub fn fnmatch(pattern: &[u8], value: &[u8], path_mode: bool) -> bool {
    let tokens = fn_tokens(pattern);
    let mut next = vec![false; value.len() + 1];
    next[value.len()] = true;
    let mut current = vec![false; value.len() + 1];

    for token in tokens.iter().rev() {
        current.fill(false);
        match *token {
            FnToken::Star => {
                current[value.len()] = next[value.len()];
                for j in (0..value.len()).rev() {
                    current[j] = next[j] || ((!path_mode || value[j] != b'/') && current[j + 1]);
                }
            }
            FnToken::Any => {
                for j in 0..value.len() {
                    current[j] = (!path_mode || value[j] != b'/') && next[j + 1];
                }
            }
            FnToken::Literal(byte) => {
                for j in 0..value.len() {
                    current[j] = value[j] == byte && next[j + 1];
                }
            }
            FnToken::Class {
                body_start,
                body_end,
                negated,
            } => {
                for j in 0..value.len() {
                    let hit = class_contains(pattern, body_start, body_end, value[j], path_mode);
                    current[j] = (!path_mode || value[j] != b'/') && hit != negated && next[j + 1];
                }
            }
        }
        std::mem::swap(&mut current, &mut next);
    }
    next[0]
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
    if !vapache_verified::glob_match_resource_admit(
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
    if !vapache_verified::glob_match_resource_admit(
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
                        vapache_verified::fnmatch_match(pattern, value, path_mode),
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
                        Ok(vapache_verified::expr_glob_match(pattern, value, path_mode)),
                        "expr mismatch: pattern={pattern:?} value={value:?} path={path_mode}"
                    );
                }
            }
        }
    }
}
