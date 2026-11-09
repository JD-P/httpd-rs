//! A memory-safe, non-backtracking PCRE2 compatibility layer for vapache.
//!
//! This crate intentionally mirrors the useful part of the `pcre2::bytes`
//! API.  It compiles the regular subset of the PCRE2 10.46 pattern language
//! to Rust's bounded automata engine.  Constructs that require a recursive
//! backtracking interpreter (backreferences, recursion, look-around,
//! conditionals and backtracking verbs) are rejected at compile time.
//!
//! The matcher is byte oriented by default, just like PCRE2's 8-bit API
//! without `PCRE2_UTF`/`PCRE2_UCP`.  No executable memory or native code is
//! used.  Pattern, subject, capture and pattern×subject work ceilings are
//! checked through the verified vapache resource kernel.

use std::collections::HashMap;
use std::fmt;
use std::ops::Index;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};

use regex_automata::{
    meta::Regex as AutomataRegex, util::primitives::NonMaxUsize, Input, MatchKind, PatternID,
};
use smallvec::SmallVec;

const DEFAULT_PATTERN_LIMIT: usize = 64 * 1024;
const DEFAULT_SUBJECT_LIMIT: usize = 64 * 1024;
const DEFAULT_WORK_LIMIT: u64 = 16 * 1024 * 1024;
const DEFAULT_CAPTURE_LIMIT: usize = 128;
const DEFAULT_SIZE_LIMIT: usize = 2 * 1024 * 1024;
const DEFAULT_NEST_LIMIT: u32 = 64;
const KEEP_PREFIX: &str = "__vapache_pcre2_keep_";
const HOT_TIER_AFTER_SEARCHES: u8 = 1;
// A bounded optional repetition creates both take and skip states in the
// PikeVM active set. Pass 24 measured this path at 4–5x the cost of an exact
// repetition with the same old structural charge. Charge the conservative
// active-set factor even if a later hot search can stay in the lazy DFA.
const PIKE_VM_ACTIVE_SET_FACTOR: u64 = 4;

/// Error category.  Unsupported syntax is distinct from malformed syntax so
/// callers can report a deliberate fail-closed compatibility decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Syntax,
    Unsupported,
    ResourceLimit,
}

/// A PCRE2-compatible compile or match error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    offset: Option<usize>,
}

impl Error {
    fn syntax(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Syntax,
            message: message.into(),
            offset: None,
        }
    }

    fn syntax_at(offset: usize, message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Syntax,
            message: message.into(),
            offset: Some(offset),
        }
    }

    fn unsupported(offset: usize, construct: &str) -> Self {
        Self {
            kind: ErrorKind::Unsupported,
            message: format!("{construct} requires PCRE2 backtracking semantics"),
            offset: Some(offset),
        }
    }

    fn resource(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::ResourceLimit,
            message: message.into(),
            offset: None,
        }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn offset(&self) -> Option<usize> {
        self.offset
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(offset) = self.offset {
            write!(f, "{} at pattern offset {offset}", self.message)
        } else {
            f.write_str(&self.message)
        }
    }
}

impl std::error::Error for Error {}

pub mod bytes {
    use super::*;

    // The common no-explicit-capture case stays inline without making the
    // by-value `Captures` result expensive to move. Patterns with explicit
    // groups retain a bounded heap fallback.
    type CaptureSpans = SmallVec<[Option<(usize, usize)>; 1]>;
    // Four slots cover group zero plus the synthetic group used for `\K`.
    type EngineSlots = SmallVec<[Option<NonMaxUsize>; 4]>;

    /// A byte range in a matched subject.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Match<'s> {
        subject: &'s [u8],
        start: usize,
        end: usize,
    }

    impl<'s> Match<'s> {
        pub fn start(&self) -> usize {
            self.start
        }

        pub fn end(&self) -> usize {
            self.end
        }

        pub fn as_bytes(&self) -> &'s [u8] {
            &self.subject[self.start..self.end]
        }
    }

    #[derive(Clone, Debug)]
    struct Config {
        caseless: bool,
        dotall: bool,
        extended: bool,
        multi_line: bool,
        crlf: bool,
        ucp: bool,
        utf: bool,
        backtracking: bool,
        pattern_limit: usize,
        subject_limit: usize,
        work_limit: u64,
        capture_limit: usize,
        size_limit: usize,
        nest_limit: u32,
    }

    impl Default for Config {
        fn default() -> Self {
            Self {
                caseless: false,
                dotall: false,
                extended: false,
                multi_line: false,
                crlf: false,
                ucp: false,
                utf: false,
                backtracking: false,
                pattern_limit: DEFAULT_PATTERN_LIMIT,
                subject_limit: DEFAULT_SUBJECT_LIMIT,
                work_limit: DEFAULT_WORK_LIMIT,
                capture_limit: DEFAULT_CAPTURE_LIMIT,
                size_limit: DEFAULT_SIZE_LIMIT,
                nest_limit: DEFAULT_NEST_LIMIT,
            }
        }
    }

    /// Builder corresponding to `pcre2::bytes::RegexBuilder`.
    #[derive(Clone, Debug, Default)]
    pub struct RegexBuilder {
        config: Config,
    }

    impl RegexBuilder {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn build(&self, pattern: &str) -> Result<Regex, Error> {
            if !vapache_verified::regex_engine_mode_admit(self.config.backtracking, false) {
                return Err(Error::resource(
                    "the backtracking compatibility engine is not available",
                ));
            }
            if !vapache_verified::regex_compile_resource_admit(
                pattern.len() as u64,
                self.config.pattern_limit as u64,
            ) {
                return Err(Error::resource("pattern exceeds the configured byte limit"));
            }

            let translation = translate(
                pattern,
                self.config.caseless,
                self.config.multi_line,
                self.config.crlf,
                self.config.extended,
            )?;
            if translation.pattern.len() > self.config.pattern_limit.saturating_mul(16) {
                return Err(Error::resource(
                    "translated pattern exceeds the expansion limit",
                ));
            }

            let hir = parse_hir(&translation.pattern, &self.config)?;
            let complexity = hir_complexity(&hir)
                .max(translation.pattern.len() as u64)
                .max(1)
                .saturating_mul(if translation.final_newline_fallback {
                    2
                } else {
                    1
                });

            let cold = build_automata(&hir, self.config.size_limit, false)?;

            let inner_names: Vec<Option<String>> = cold
                .group_info()
                .pattern_names(PatternID::ZERO)
                .map(|name| name.map(ToOwned::to_owned))
                .collect();
            let mut public_to_inner = vec![0];
            let mut keep_groups = Vec::new();
            let mut capture_names = vec![None];
            let mut capture_names_idx = HashMap::new();
            for (index, name) in inner_names.iter().enumerate().skip(1) {
                if name
                    .as_deref()
                    .is_some_and(|name| name.starts_with(&translation.keep_prefix))
                {
                    keep_groups.push(index);
                    continue;
                }
                let public = public_to_inner.len();
                public_to_inner.push(index);
                capture_names.push(name.clone());
                if let Some(name) = name {
                    capture_names_idx.insert(name.clone(), public);
                }
            }
            if public_to_inner.len() > self.config.capture_limit {
                return Err(Error::resource(
                    "capture count exceeds the configured limit",
                ));
            }
            if !vapache_verified::regex_capture_resource_admit(
                public_to_inner.len() as u64,
                self.config.capture_limit as u64,
            ) {
                return Err(Error::resource("capture count exceeds the verified limit"));
            }

            Ok(Regex {
                config: Arc::new(self.config.clone()),
                pattern: pattern.to_owned(),
                translated_pattern: translation.pattern,
                complexity,
                final_newline_fallback: translation.final_newline_fallback,
                multiline_start_anchor: translation.multiline_start_anchor,
                inner: TieredEngine::new(cold, hir, self.config.size_limit),
                public_to_inner: Arc::new(public_to_inner),
                keep_groups: Arc::new(keep_groups),
                capture_names: Arc::new(capture_names),
                capture_names_idx: Arc::new(capture_names_idx),
            })
        }

        pub fn caseless(&mut self, yes: bool) -> &mut Self {
            self.config.caseless = yes;
            self
        }

        pub fn dotall(&mut self, yes: bool) -> &mut Self {
            self.config.dotall = yes;
            self
        }

        pub fn extended(&mut self, yes: bool) -> &mut Self {
            self.config.extended = yes;
            self
        }

        pub fn multi_line(&mut self, yes: bool) -> &mut Self {
            self.config.multi_line = yes;
            self
        }

        pub fn crlf(&mut self, yes: bool) -> &mut Self {
            self.config.crlf = yes;
            self
        }

        pub fn ucp(&mut self, yes: bool) -> &mut Self {
            self.config.ucp = yes;
            self
        }

        pub fn utf(&mut self, yes: bool) -> &mut Self {
            self.config.utf = yes;
            self
        }

        #[deprecated(note = "invalid UTF subjects are handled without undefined behavior")]
        pub fn disable_utf_check(&mut self) -> &mut Self {
            self
        }

        /// Accepted for source compatibility. The Rust automata use bounded
        /// interpreter/DFA tiers and never allocate executable memory.
        pub fn jit(&mut self, _yes: bool) -> &mut Self {
            self
        }

        /// Accepted for source compatibility; see [`Self::jit`].
        pub fn jit_if_available(&mut self, _yes: bool) -> &mut Self {
            self
        }

        /// Accepted for source compatibility. There is no native JIT stack.
        pub fn max_jit_stack_size(&mut self, _bytes: Option<usize>) -> &mut Self {
            self
        }

        /// Backtracking is disabled by default. Enabling it fails compilation
        /// because vapache deliberately ships no recursive fallback engine.
        pub fn backtracking(&mut self, yes: bool) -> &mut Self {
            self.config.backtracking = yes;
            self
        }

        pub fn max_pattern_size(&mut self, bytes: usize) -> &mut Self {
            self.config.pattern_limit = bytes;
            self
        }

        pub fn max_subject_size(&mut self, bytes: usize) -> &mut Self {
            self.config.subject_limit = bytes;
            self
        }

        pub fn match_limit(&mut self, work: u64) -> &mut Self {
            self.config.work_limit = work;
            self
        }

        pub fn capture_limit(&mut self, captures: usize) -> &mut Self {
            self.config.capture_limit = captures;
            self
        }

        pub fn size_limit(&mut self, bytes: usize) -> &mut Self {
            self.config.size_limit = bytes;
            self
        }

        pub fn nest_limit(&mut self, depth: u32) -> &mut Self {
            self.config.nest_limit = depth;
            self
        }
    }

    fn build_automata(
        hir: &regex_syntax::hir::Hir,
        size_limit: usize,
        hybrid: bool,
    ) -> Result<AutomataRegex, Error> {
        AutomataRegex::builder()
            .configure(
                AutomataRegex::config()
                    .match_kind(MatchKind::LeftmostFirst)
                    .utf8_empty(false)
                    .nfa_size_limit(Some(size_limit))
                    .hybrid_cache_capacity(2 * 1024 * 1024)
                    .hybrid(hybrid)
                    .dfa(false)
                    .onepass(false)
                    .backtrack(false),
            )
            .build_from_hir(hir)
            .map_err(|error| Error::syntax(error.to_string()))
    }

    /// A compiled, shareable regular expression.
    #[derive(Clone)]
    pub struct Regex {
        config: Arc<Config>,
        pattern: String,
        translated_pattern: String,
        complexity: u64,
        final_newline_fallback: bool,
        multiline_start_anchor: bool,
        inner: TieredEngine,
        public_to_inner: Arc<Vec<usize>>,
        keep_groups: Arc<Vec<usize>>,
        capture_names: Arc<Vec<Option<String>>>,
        capture_names_idx: Arc<HashMap<String, usize>>,
    }

    /// A bounded Pike VM provides low cold-start latency. After the first
    /// search, a lazy DFA tier is built once and shared by every clone. Both
    /// tiers use the same HIR and Thompson-NFA size ceiling; neither permits
    /// the bounded-backtracking fallback.
    #[derive(Clone)]
    struct TieredEngine(Arc<TieredEngineInner>);

    struct TieredEngineInner {
        cold: AutomataRegex,
        hot: OnceLock<Option<AutomataRegex>>,
        hir: regex_syntax::hir::Hir,
        size_limit: usize,
        searches: AtomicU8,
    }

    impl TieredEngine {
        fn new(cold: AutomataRegex, hir: regex_syntax::hir::Hir, size_limit: usize) -> Self {
            Self(Arc::new(TieredEngineInner {
                cold,
                hot: OnceLock::new(),
                hir,
                size_limit,
                searches: AtomicU8::new(0),
            }))
        }

        fn for_search(&self) -> &AutomataRegex {
            if let Some(hot) = self.0.hot.get() {
                return hot.as_ref().unwrap_or(&self.0.cold);
            }
            let searches = self.0.searches.fetch_add(1, Ordering::Relaxed);
            if searches < HOT_TIER_AFTER_SEARCHES {
                return &self.0.cold;
            }
            self.0
                .hot
                .get_or_init(|| build_automata(&self.0.hir, self.0.size_limit, true).ok())
                .as_ref()
                .unwrap_or(&self.0.cold)
        }
    }

    impl fmt::Debug for Regex {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("Regex").field(&self.pattern).finish()
        }
    }

    impl Regex {
        pub fn new(pattern: &str) -> Result<Self, Error> {
            RegexBuilder::new().build(pattern)
        }

        fn check_subject(&self, subject_len: usize, start: usize) -> Result<(), Error> {
            assert!(start <= subject_len, "start must be <= subject.len()");
            if !vapache_verified::regex_match_resource_admit(
                self.complexity,
                subject_len.saturating_sub(start) as u64,
                self.config.subject_limit as u64,
                self.config.work_limit,
            ) {
                return Err(Error::resource(
                    "subject or deterministic pattern×subject work exceeds the configured limit",
                ));
            }
            Ok(())
        }

        pub fn is_match(&self, subject: &[u8]) -> Result<bool, Error> {
            self.is_match_at(subject, 0)
        }

        pub fn is_match_at(&self, subject: &[u8], start: usize) -> Result<bool, Error> {
            Ok(self.capture_spans(subject, start)?.is_some())
        }

        pub fn find<'s>(&self, subject: &'s [u8]) -> Result<Option<Match<'s>>, Error> {
            self.find_at(subject, 0)
        }

        pub fn find_at<'s>(
            &self,
            subject: &'s [u8],
            start: usize,
        ) -> Result<Option<Match<'s>>, Error> {
            let Some(spans) = self.capture_spans(subject, start)? else {
                return Ok(None);
            };
            Ok(spans[0].map(|(start, end)| Match {
                subject,
                start,
                end,
            }))
        }

        pub fn captures<'s>(&self, subject: &'s [u8]) -> Result<Option<Captures<'s>>, Error> {
            self.captures_at(subject, 0)
        }

        fn captures_at<'s>(
            &self,
            subject: &'s [u8],
            start: usize,
        ) -> Result<Option<Captures<'s>>, Error> {
            Ok(self.capture_spans(subject, start)?.map(|spans| Captures {
                subject,
                spans,
                idx: (!self.capture_names_idx.is_empty())
                    .then(|| Arc::clone(&self.capture_names_idx)),
            }))
        }

        fn capture_spans(
            &self,
            subject: &[u8],
            start: usize,
        ) -> Result<Option<CaptureSpans>, Error> {
            self.check_subject(subject.len(), start)?;
            let engine = self.inner.for_search();
            if self.public_to_inner.len() == 1 && self.keep_groups.is_empty() {
                return Ok(self.group_zero_spans(engine, subject, start));
            }
            let full = Self::engine_captures_at(engine, subject, start);
            let mut trimmed = None;
            if self.final_newline_fallback {
                let trim = if self.config.crlf && subject.ends_with(b"\r\n") {
                    2
                } else if subject.ends_with(b"\n") || (self.config.crlf && subject.ends_with(b"\r"))
                {
                    1
                } else {
                    0
                };
                if trim > 0 && start <= subject.len() - trim {
                    trimmed =
                        Self::engine_captures_at(engine, &subject[..subject.len() - trim], start);
                }
            }
            // PCRE2 exposes both end-of-subject and pre-final-newline anchor
            // positions. Contexts whose greedy priority cannot be represented
            // by this two-pass lowering are rejected during translation.
            let captures = match (full, trimmed) {
                (Some(full), Some(trimmed)) => {
                    let full_match = Self::engine_group(&full, 0).expect("group zero matches");
                    let trimmed_match =
                        Self::engine_group(&trimmed, 0).expect("group zero matches");
                    if trimmed_match.0 < full_match.0
                        || (trimmed_match.0 == full_match.0
                            && trimmed_match.1 < full_match.1
                            && !self.config.dotall)
                    {
                        Some(trimmed)
                    } else {
                        Some(full)
                    }
                }
                (full, trimmed) => full.or(trimmed),
            };
            let Some(captures) = captures else {
                return Ok(None);
            };
            let mut spans = CaptureSpans::with_capacity(self.public_to_inner.len());
            for &inner in self.public_to_inner.iter() {
                spans.push(Self::engine_group(&captures, inner));
            }
            if let Some((_, end)) = spans[0] {
                let keep_start = self
                    .keep_groups
                    .iter()
                    .filter_map(|&group| {
                        Self::engine_group(&captures, group).map(|matched| matched.0)
                    })
                    .max();
                if let Some(keep_start) = keep_start {
                    spans[0] = Some((keep_start, end));
                }
            }
            Ok(Some(spans))
        }

        fn group_zero_spans(
            &self,
            engine: &AutomataRegex,
            subject: &[u8],
            start: usize,
        ) -> Option<CaptureSpans> {
            let full = engine
                .search(&Input::new(subject).span(start..subject.len()))
                .map(|matched| (matched.start(), matched.end()));
            let mut trimmed = None;
            if self.final_newline_fallback {
                let trim = if self.config.crlf && subject.ends_with(b"\r\n") {
                    2
                } else if subject.ends_with(b"\n") || (self.config.crlf && subject.ends_with(b"\r"))
                {
                    1
                } else {
                    0
                };
                if trim > 0 && start <= subject.len() - trim {
                    trimmed = engine
                        .search(
                            &Input::new(&subject[..subject.len() - trim])
                                .span(start..subject.len() - trim),
                        )
                        .map(|matched| (matched.start(), matched.end()));
                }
            }
            let matched = match (full, trimmed) {
                (Some(full), Some(trimmed))
                    if trimmed.0 < full.0
                        || (trimmed.0 == full.0 && trimmed.1 < full.1 && !self.config.dotall) =>
                {
                    trimmed
                }
                (Some(full), _) => full,
                (None, Some(trimmed)) => trimmed,
                (None, None) => return None,
            };
            let mut spans = CaptureSpans::new();
            spans.push(Some(matched));
            Some(spans)
        }

        fn engine_group(slots: &EngineSlots, group: usize) -> Option<(usize, usize)> {
            let slot = group.checked_mul(2)?;
            Some((
                slots.get(slot)?.as_ref()?.get(),
                slots.get(slot + 1)?.as_ref()?.get(),
            ))
        }

        fn engine_captures_at(
            engine: &AutomataRegex,
            subject: &[u8],
            start: usize,
        ) -> Option<EngineSlots> {
            let mut slots = EngineSlots::from_elem(None, engine.group_info().slot_len());
            engine.search_slots(&Input::new(subject).span(start..subject.len()), &mut slots)?;
            Some(slots)
        }

        pub fn find_iter<'r, 's>(&'r self, subject: &'s [u8]) -> Matches<'r, 's> {
            Matches {
                re: self,
                subject,
                last_end: 0,
                last_match: None,
                done: false,
            }
        }

        pub fn captures_iter<'r, 's>(&'r self, subject: &'s [u8]) -> CaptureMatches<'r, 's> {
            CaptureMatches {
                re: self,
                subject,
                last_end: 0,
                last_match: None,
                done: false,
            }
        }

        pub fn captures_read<'s>(
            &self,
            locs: &mut CaptureLocations,
            subject: &'s [u8],
        ) -> Result<Option<Match<'s>>, Error> {
            self.captures_read_at(locs, subject, 0)
        }

        pub fn captures_read_at<'s>(
            &self,
            locs: &mut CaptureLocations,
            subject: &'s [u8],
            start: usize,
        ) -> Result<Option<Match<'s>>, Error> {
            if locs.spans.len() != self.captures_len() {
                return Err(Error::resource(
                    "capture locations belong to a different regex",
                ));
            }
            let Some(spans) = self.capture_spans(subject, start)? else {
                locs.spans.fill(None);
                return Ok(None);
            };
            locs.spans = spans;
            Ok(locs.spans[0].map(|(start, end)| Match {
                subject,
                start,
                end,
            }))
        }

        pub fn as_str(&self) -> &str {
            &self.pattern
        }

        /// The internal regular-language form, useful for audits and
        /// differential-test diagnostics.
        pub fn translated_pattern(&self) -> &str {
            &self.translated_pattern
        }

        pub fn capture_names(&self) -> &[Option<String>] {
            &self.capture_names
        }

        pub fn captures_len(&self) -> usize {
            self.public_to_inner.len()
        }

        pub fn capture_locations(&self) -> CaptureLocations {
            CaptureLocations {
                spans: CaptureSpans::from_elem(None, self.captures_len()),
            }
        }

        fn suppress_terminal_multiline_anchor(
            &self,
            subject: &[u8],
            start: usize,
            end: usize,
        ) -> bool {
            self.multiline_start_anchor
                && start == end
                && end == subject.len()
                && (subject.ends_with(b"\n") || (self.config.crlf && subject.ends_with(b"\r")))
        }
    }

    #[derive(Clone, Debug)]
    pub struct CaptureLocations {
        spans: CaptureSpans,
    }

    impl CaptureLocations {
        pub fn get(&self, i: usize) -> Option<(usize, usize)> {
            self.spans.get(i).copied().flatten()
        }

        pub fn len(&self) -> usize {
            self.spans.len()
        }

        pub fn is_empty(&self) -> bool {
            self.spans.is_empty()
        }
    }

    #[derive(Clone)]
    pub struct Captures<'s> {
        subject: &'s [u8],
        spans: CaptureSpans,
        idx: Option<Arc<HashMap<String, usize>>>,
    }

    impl<'s> Captures<'s> {
        pub fn get(&self, i: usize) -> Option<Match<'s>> {
            self.spans
                .get(i)
                .copied()
                .flatten()
                .map(|(start, end)| Match {
                    subject: self.subject,
                    start,
                    end,
                })
        }

        pub fn name(&self, name: &str) -> Option<Match<'s>> {
            self.idx
                .as_ref()?
                .get(name)
                .and_then(|&index| self.get(index))
        }

        pub fn len(&self) -> usize {
            self.spans.len()
        }

        pub fn is_empty(&self) -> bool {
            self.spans.is_empty()
        }
    }

    impl fmt::Debug for Captures<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_list()
                .entries((0..self.len()).map(|index| self.get(index).map(|m| m.as_bytes())))
                .finish()
        }
    }

    impl Index<usize> for Captures<'_> {
        type Output = [u8];

        fn index(&self, index: usize) -> &Self::Output {
            self.get(index)
                .expect("capture group did not match")
                .as_bytes()
        }
    }

    impl Index<&str> for Captures<'_> {
        type Output = [u8];

        fn index(&self, name: &str) -> &Self::Output {
            self.name(name)
                .expect("capture group did not match")
                .as_bytes()
        }
    }

    pub struct Matches<'r, 's> {
        re: &'r Regex,
        subject: &'s [u8],
        last_end: usize,
        last_match: Option<usize>,
        done: bool,
    }

    impl<'r, 's> Iterator for Matches<'r, 's> {
        type Item = Result<Match<'s>, Error>;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                if self.done || self.last_end > self.subject.len() {
                    self.done = true;
                    return None;
                }
                match self.re.find_at(self.subject, self.last_end) {
                    Ok(Some(matched)) => {
                        if self.re.suppress_terminal_multiline_anchor(
                            self.subject,
                            matched.start(),
                            matched.end(),
                        ) {
                            self.done = true;
                            return None;
                        }
                        if matched.start() == matched.end() {
                            self.last_end = matched.end() + 1;
                            // Match PCRE2's global-search rule: after a
                            // non-empty match, do not emit an empty match at
                            // the exact same ending position.
                            if self.last_match == Some(matched.end()) {
                                continue;
                            }
                        } else {
                            self.last_end = matched.end();
                        }
                        self.last_match = Some(matched.end());
                        return Some(Ok(matched));
                    }
                    Ok(None) => {
                        self.done = true;
                        return None;
                    }
                    Err(error) => {
                        self.done = true;
                        return Some(Err(error));
                    }
                }
            }
        }
    }

    pub struct CaptureMatches<'r, 's> {
        re: &'r Regex,
        subject: &'s [u8],
        last_end: usize,
        last_match: Option<usize>,
        done: bool,
    }

    impl<'r, 's> Iterator for CaptureMatches<'r, 's> {
        type Item = Result<Captures<'s>, Error>;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                if self.done || self.last_end > self.subject.len() {
                    self.done = true;
                    return None;
                }
                match self.re.captures_at(self.subject, self.last_end) {
                    Ok(Some(captures)) => {
                        let matched = captures.get(0).expect("group zero always matches");
                        if self.re.suppress_terminal_multiline_anchor(
                            self.subject,
                            matched.start(),
                            matched.end(),
                        ) {
                            self.done = true;
                            return None;
                        }
                        if matched.start() == matched.end() {
                            self.last_end = matched.end() + 1;
                            if self.last_match == Some(matched.end()) {
                                continue;
                            }
                        } else {
                            self.last_end = matched.end();
                        }
                        self.last_match = Some(matched.end());
                        return Some(Ok(captures));
                    }
                    Ok(None) => {
                        self.done = true;
                        return None;
                    }
                    Err(error) => {
                        self.done = true;
                        return Some(Err(error));
                    }
                }
            }
        }
    }

    struct Translation {
        pattern: String,
        final_newline_fallback: bool,
        multiline_start_anchor: bool,
        keep_prefix: String,
    }

    fn parse_hir(pattern: &str, config: &Config) -> Result<regex_syntax::hir::Hir, Error> {
        let unicode = config.ucp || config.utf;
        let mut builder = regex_syntax::ParserBuilder::new();
        builder
            .utf8(false)
            .unicode(unicode)
            .ignore_whitespace(config.extended)
            .case_insensitive(config.caseless)
            .multi_line(config.multi_line)
            .dot_matches_new_line(config.dotall)
            .crlf(config.crlf)
            .nest_limit(config.nest_limit);
        builder
            .build()
            .parse(pattern)
            .map_err(|error| Error::syntax(error.to_string()))
    }

    fn hir_complexity(hir: &regex_syntax::hir::Hir) -> u64 {
        use regex_syntax::hir::HirKind;
        match hir.kind() {
            HirKind::Empty | HirKind::Class(_) | HirKind::Look(_) => 1,
            HirKind::Literal(literal) => (literal.0.len() as u64).max(1),
            HirKind::Capture(capture) => hir_complexity(&capture.sub).saturating_add(1),
            HirKind::Concat(parts) | HirKind::Alternation(parts) => parts
                .iter()
                .fold(1u64, |sum, part| sum.saturating_add(hir_complexity(part))),
            HirKind::Repetition(repetition) => {
                let min = u64::from(repetition.min);
                let (copies, active_set_factor) = match repetition.max.map(u64::from) {
                    // Exact counted repetitions expand to exactly `max`
                    // copies and have no optional take/skip branch.
                    Some(max) if max == min => (max.max(1), 1),
                    // `{min,max}` has an additional terminal path. In
                    // particular `{0,m}` contributes m+1 active paths, not m.
                    Some(max) => (max.saturating_add(1).max(1), PIKE_VM_ACTIVE_SET_FACTOR),
                    // An unbounded repetition retains one loop/exit path in
                    // addition to its mandatory prefix.
                    None => (min.saturating_add(1).max(1), PIKE_VM_ACTIVE_SET_FACTOR),
                };
                hir_complexity(&repetition.sub)
                    .saturating_mul(copies)
                    .saturating_mul(active_set_factor)
            }
        }
    }

    /// Translate PCRE-only regular constructs while rejecting every construct
    /// whose exact semantics cannot be represented by the automata backend.
    fn translate(
        pattern: &str,
        caseless: bool,
        multi_line: bool,
        crlf: bool,
        extended: bool,
    ) -> Result<Translation, Error> {
        let quantifier_extended = extended || inline_option_may_enable(pattern, b'x');
        let invalid_quantifier = invalid_quantifier_placement(pattern, false, crlf).or_else(|| {
            quantifier_extended
                .then(|| invalid_quantifier_placement(pattern, true, crlf))
                .flatten()
        });
        if let Some(offset) = invalid_quantifier {
            return Err(Error::syntax_at(
                offset,
                "quantifier does not follow a repeatable item",
            ));
        }
        if let Some(offset) = ambiguous_nested_capture_repeat(pattern, crlf) {
            return Err(Error::unsupported(
                offset,
                "quantified capture with ambiguous capture history",
            ));
        }
        let effective_multiline = leading_global_flag(pattern, b'm').unwrap_or(multi_line);
        let effective_extended = leading_global_flag(pattern, b'x').unwrap_or(extended);
        validate_line_constructs(pattern, effective_extended, effective_multiline, crlf)?;

        let bytes = pattern.as_bytes();
        let captures = capture_count(pattern, crlf);
        let keep_prefix = choose_keep_prefix(pattern);
        let absolute_end = contains_escape(pattern, b'z', crlf);
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        let mut keep_count = 0;
        let mut final_newline_fallback = false;
        let mut saw_line_start = false;
        let mut alternation_offset = None;
        let mut effective_caseless = caseless;
        let mut caseless_scopes = Vec::new();
        while i < bytes.len() {
            if bytes[i] >= 0x80 {
                let ch = pattern[i..].chars().next().expect("valid UTF-8 pattern");
                out.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
                i += ch.len_utf8();
                continue;
            }
            match bytes[i] {
                b'[' => {
                    let (class, end) =
                        translate_byte_class_caseless(pattern, i, crlf, effective_caseless)?;
                    out.extend_from_slice(class.as_bytes());
                    i = end;
                }
                b'(' if bytes.get(i + 1) != Some(&b'?') && bytes.get(i + 1) != Some(&b'*') => {
                    caseless_scopes.push(effective_caseless);
                    out.push(b'(');
                    i += 1;
                }
                b'(' if bytes.get(i + 1) == Some(&b'*') => {
                    return Err(Error::unsupported(i, "backtracking control verb"));
                }
                b'(' if bytes.get(i + 1) == Some(&b'?') => {
                    if bytes.get(i + 2) == Some(&b'#') {
                        let Some(relative_end) = bytes[i + 3..].iter().position(|&b| b == b')')
                        else {
                            return Err(Error::syntax("unterminated PCRE comment group"));
                        };
                        i += 4 + relative_end;
                        continue;
                    }
                    if bytes[i..].starts_with(b"(?J)") {
                        return Err(Error::unsupported(i, "duplicate capture names"));
                    }
                    if let Some((end, scoped, updated)) =
                        inline_caseless_option(bytes, i, effective_caseless)
                    {
                        if scoped {
                            caseless_scopes.push(effective_caseless);
                        }
                        effective_caseless = updated;
                        out.extend_from_slice(&bytes[i..end]);
                        i = end;
                        continue;
                    }
                    match bytes.get(i + 2).copied() {
                        Some(b'=') | Some(b'!') | Some(b'>') | Some(b'(') | Some(b'|') => {
                            return Err(Error::unsupported(
                                i,
                                "assertion, atomic, conditional or branch-reset group",
                            ));
                        }
                        Some(b'<') if matches!(bytes.get(i + 3), Some(b'=') | Some(b'!')) => {
                            return Err(Error::unsupported(i, "look-behind assertion"));
                        }
                        Some(b'R') | Some(b'0'..=b'9') | Some(b'&') => {
                            return Err(Error::unsupported(i, "recursive subpattern"));
                        }
                        Some(b'P') if matches!(bytes.get(i + 3), Some(b'=') | Some(b'>')) => {
                            return Err(Error::unsupported(i, "named backreference or recursion"));
                        }
                        Some(b'\'') => {
                            caseless_scopes.push(effective_caseless);
                            let name_start = i + 3;
                            let Some(relative_end) =
                                bytes[name_start..].iter().position(|&b| b == b'\'')
                            else {
                                return Err(Error::syntax("unterminated named capture"));
                            };
                            let name_end = name_start + relative_end;
                            out.extend_from_slice(b"(?P<");
                            out.extend_from_slice(&bytes[name_start..name_end]);
                            out.push(b'>');
                            i = name_end + 1;
                        }
                        _ => {
                            caseless_scopes.push(effective_caseless);
                            out.push(b'(');
                            i += 1;
                        }
                    }
                }
                b')' => {
                    effective_caseless = caseless_scopes
                        .pop()
                        .ok_or_else(|| Error::syntax_at(i, "unmatched closing parenthesis"))?;
                    out.push(b')');
                    i += 1;
                }
                b'^' => {
                    saw_line_start = true;
                    out.push(b'^');
                    i += 1;
                }
                b'|' => {
                    alternation_offset.get_or_insert(i);
                    out.push(b'|');
                    i += 1;
                }
                b'$' => {
                    out.push(b'$');
                    if !effective_multiline && !absolute_end {
                        final_newline_fallback = true;
                    }
                    i += 1;
                }
                b'\\' => {
                    let Some(&escaped) = bytes.get(i + 1) else {
                        return Err(Error::syntax("trailing backslash"));
                    };
                    // Advancing by two bytes would land inside a multi-byte
                    // UTF-8 scalar and make the next string slice panic.
                    // PCRE2's escaped non-ASCII behavior also depends on its
                    // UTF mode, so keep the byte-oriented subset fail closed.
                    if escaped >= 0x80 {
                        return Err(Error::unsupported(i, "non-ASCII escape"));
                    }
                    match escaped {
                        b'Q' => {
                            let start = i + 2;
                            let end = bytes[start..]
                                .windows(2)
                                .position(|pair| pair == b"\\E")
                                .map(|relative| start + relative)
                                .unwrap_or(bytes.len());
                            append_quoted_literal(&mut out, &pattern[start..end]);
                            i = if end < bytes.len() { end + 2 } else { end };
                        }
                        b'K' => {
                            out.extend_from_slice(
                                format!("(?P<{keep_prefix}{keep_count}>)").as_bytes(),
                            );
                            keep_count += 1;
                            i += 2;
                        }
                        b'Z' => {
                            out.extend_from_slice(b"(?-m:$)");
                            if !absolute_end {
                                final_newline_fallback = true;
                            }
                            i += 2;
                        }
                        b'C' => {
                            out.extend_from_slice(b"(?s:.)");
                            i += 2;
                        }
                        b'R' => {
                            out.extend_from_slice(b"(?:\\r\\n|[\\n\\x0B\\f\\r\\x85])");
                            i += 2;
                        }
                        b'N' => {
                            if crlf {
                                out.extend_from_slice(b"[^\\r\\n]");
                            } else {
                                out.extend_from_slice(b"[^\\n]");
                            }
                            i += 2;
                        }
                        b'h' => {
                            out.extend_from_slice(b"[\\x09\\x20\\xA0]");
                            i += 2;
                        }
                        b'v' => {
                            out.extend_from_slice(b"[\\n\\x0B\\f\\r\\x85]");
                            i += 2;
                        }
                        b'H' => {
                            out.extend_from_slice(b"[^\\x09\\x20\\xA0]");
                            i += 2;
                        }
                        b'V' => {
                            out.extend_from_slice(b"[^\\n\\x0B\\f\\r\\x85]");
                            i += 2;
                        }
                        b'a' => {
                            out.extend_from_slice(b"\\x07");
                            i += 2;
                        }
                        b'e' => {
                            out.extend_from_slice(b"\\x1B");
                            i += 2;
                        }
                        b'c' => {
                            let Some(&control) = bytes.get(i + 2) else {
                                return Err(Error::syntax("incomplete control escape"));
                            };
                            if control >= 0x80 {
                                return Err(Error::syntax("control escape must be ASCII"));
                            }
                            push_hex(&mut out, control.to_ascii_uppercase() ^ 0x40);
                            i += 3;
                        }
                        b'x' => {
                            let (value, end) = parse_hex_escape(bytes, i)?;
                            push_hex(&mut out, value);
                            i = end;
                        }
                        b'o' => {
                            let (value, end) = parse_braced_octal(bytes, i)?;
                            push_hex(&mut out, value);
                            i = end;
                        }
                        b'0'..=b'7' => {
                            let (decimal, decimal_end) = decimal_escape(bytes, i + 1);
                            let single_digit = decimal_end == i + 2;
                            if escaped != b'0'
                                && (single_digit || (decimal > 0 && decimal <= captures))
                            {
                                return Err(Error::unsupported(i, "backreference"));
                            }
                            let (value, end) = parse_octal_escape(bytes, i + 1)?;
                            push_hex(&mut out, value);
                            i = end;
                        }
                        b'8' | b'9' | b'g' | b'k' => {
                            return Err(Error::unsupported(i, "backreference"));
                        }
                        b'p' | b'P' | b'X' => {
                            return Err(Error::unsupported(
                                i,
                                "Unicode property or extended grapheme escape",
                            ));
                        }
                        _ => {
                            out.push(b'\\');
                            out.push(escaped);
                            i += 2;
                        }
                    }
                }
                b'+' if matches!(out.last(), Some(b'*' | b'+' | b'?' | b'}')) => {
                    return Err(Error::unsupported(i, "possessive quantifier"));
                }
                b'{' if bytes[i..].starts_with(b"{0}") || bytes[i..].starts_with(b"{0,0}") => {
                    return Err(Error::unsupported(i, "zero-count repetition"));
                }
                byte => {
                    out.push(byte);
                    i += 1;
                }
            }
        }
        if effective_multiline && saw_line_start {
            if let Some(offset) = alternation_offset {
                return Err(Error::unsupported(
                    offset,
                    "multiline start anchor across alternation",
                ));
            }
        }
        let pattern = String::from_utf8(out).expect("translation preserves UTF-8");
        Ok(Translation {
            pattern,
            final_newline_fallback,
            multiline_start_anchor: effective_multiline && saw_line_start,
            keep_prefix,
        })
    }

    /// Return the byte just after an inline option header, whether it opens a
    /// scoped group, and the effective caseless state inside/after it.
    fn inline_caseless_option(
        bytes: &[u8],
        start: usize,
        initial: bool,
    ) -> Option<(usize, bool, bool)> {
        let mut i = start + 2;
        let mut enabled = true;
        let mut caseless = initial;
        while let Some(&byte) = bytes.get(i) {
            match byte {
                b'i' => {
                    caseless = enabled;
                    i += 1;
                }
                b'm' | b's' | b'x' => i += 1,
                b'-' => {
                    enabled = false;
                    i += 1;
                }
                b':' => return Some((i + 1, true, caseless)),
                b')' if i > start + 2 => return Some((i + 1, false, caseless)),
                _ => return None,
            }
        }
        None
    }

    fn append_quoted_literal(out: &mut Vec<u8>, literal: &str) {
        for byte in literal.as_bytes() {
            if byte.is_ascii_whitespace() || *byte == b'#' || *byte >= 0x80 {
                push_hex(out, *byte);
            } else {
                let ch = *byte as char;
                if regex_syntax::is_meta_character(ch) {
                    out.push(b'\\');
                }
                out.push(*byte);
            }
        }
    }

    fn choose_keep_prefix(pattern: &str) -> String {
        for nonce in 0u64.. {
            let candidate = format!("{KEEP_PREFIX}{nonce}_");
            if !pattern.contains(&candidate) {
                return candidate;
            }
        }
        unreachable!("finite pattern cannot contain every generated prefix")
    }

    fn leading_global_flag(pattern: &str, flag: u8) -> Option<bool> {
        let bytes = pattern.as_bytes();
        let mut i = 0;
        let mut result = None;
        while bytes.get(i..i + 2) == Some(b"(?") {
            let start = i + 2;
            let close = bytes[start..].iter().position(|&byte| byte == b')')? + start;
            if bytes[start..close].contains(&b':')
                || !bytes[start..close]
                    .iter()
                    .all(|byte| byte.is_ascii_alphabetic() || *byte == b'-')
            {
                break;
            }
            let mut enabled = true;
            for &byte in &bytes[start..close] {
                if byte == b'-' {
                    enabled = false;
                } else if byte == flag {
                    result = Some(enabled);
                }
            }
            i = close + 1;
        }
        result
    }

    fn inline_option_may_enable(pattern: &str, flag: u8) -> bool {
        let bytes = pattern.as_bytes();
        let mut i = 0;
        while i + 2 < bytes.len() {
            if bytes.get(i..i + 2) != Some(b"(?") {
                i += 1;
                continue;
            }
            let mut cursor = i + 2;
            let mut enabled = true;
            while let Some(&byte) = bytes.get(cursor) {
                match byte {
                    b'-' => enabled = false,
                    b':' | b')' => break,
                    byte if byte.is_ascii_alphabetic() => {
                        if byte == flag && enabled {
                            return true;
                        }
                    }
                    _ => break,
                }
                cursor += 1;
            }
            i += 2;
        }
        false
    }

    fn validate_line_constructs(
        pattern: &str,
        extended: bool,
        effective_multiline: bool,
        crlf: bool,
    ) -> Result<(), Error> {
        let bytes = pattern.as_bytes();
        // A scoped `x` option can hide semantic adjacency inside a group. A
        // conservative whole-pattern scan is preferable to accepting one
        // unrepresentable ACL regex when option scope is ambiguous here.
        let extended_may_apply = extended || inline_option_may_enable(pattern, b'x');
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'[' => {
                    let end = byte_class_end(pattern, i, false)?;
                    i = end;
                }
                b'\\' if bytes.get(i + 1) == Some(&b'Q') => {
                    i = escape_atom_end(bytes, i);
                }
                b'\\' if bytes.get(i + 1) == Some(&b'R') => {
                    let end = i + 2;
                    let mut enclosing_end = end;
                    while bytes.get(enclosing_end) == Some(&b')') {
                        enclosing_end += 1;
                    }
                    if matches!(bytes.get(end), Some(b'*' | b'+' | b'?' | b'{'))
                        || bytes.get(end..end + 2) == Some(b"\\R")
                        || bytes.get(end..end + 2) == Some(b"\\C")
                        || matches!(bytes.get(enclosing_end), Some(b'*' | b'+' | b'?' | b'{'))
                    {
                        return Err(Error::unsupported(i, "atomic CRLF line sequence"));
                    }
                    i = end;
                }
                b'\\' if crlf && bytes.get(i + 1) == Some(&b'B') => {
                    return Err(Error::unsupported(
                        i,
                        "CRLF start-offset non-boundary assertion",
                    ));
                }
                b'\\'
                    if matches!(bytes.get(i + 1), Some(b'S') | Some(b'N'))
                        && matches!(bytes.get(i + 2), Some(b'*') | Some(b'+'))
                        && auto_possessified_line_atom(bytes, i + 3, extended_may_apply) =>
                {
                    return Err(Error::unsupported(
                        i,
                        "PCRE2 auto-possessified line sequence",
                    ));
                }
                b'\\'
                    if bytes.get(i + 1) == Some(&b'N')
                        && bytes.get(i + 2..i + 6) == Some(b"*?\\R") =>
                {
                    return Err(Error::unsupported(
                        i,
                        "PCRE2 auto-possessified line sequence",
                    ));
                }
                b'\\' if bytes.get(i + 1) == Some(&b'Z') => {
                    if !anchor_is_terminal(bytes, i + 2, extended) {
                        return Err(Error::unsupported(i, "non-terminal final-newline anchor"));
                    }
                    i += 2;
                }
                b'\\' => i = escape_atom_end(bytes, i),
                b'$' if crlf && effective_multiline => {
                    return Err(Error::unsupported(i, "CRLF multiline final-newline anchor"));
                }
                b'$' if !effective_multiline => {
                    if !anchor_is_terminal(bytes, i + 1, extended) {
                        return Err(Error::unsupported(i, "non-terminal final-newline anchor"));
                    }
                    let previous = bytes[..i]
                        .iter()
                        .rposition(|byte| !byte.is_ascii_whitespace())
                        .and_then(|index| bytes.get(index));
                    if previous == Some(&b'?') {
                        return Err(Error::unsupported(i, "lazy final-newline anchor priority"));
                    }
                    i += 1;
                }
                _ => i += 1,
            }
        }
        Ok(())
    }

    /// Recognize the next semantic atom after syntax PCRE discards before its
    /// auto-possessification pass.
    fn auto_possessified_line_atom(bytes: &[u8], mut i: usize, extended: bool) -> bool {
        loop {
            if extended {
                while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
                    i += 1;
                }
                if bytes.get(i) == Some(&b'#') {
                    i = bytes[i..]
                        .iter()
                        .position(|&byte| byte == b'\n')
                        .map_or(bytes.len(), |relative| i + relative + 1);
                    continue;
                }
            }
            if bytes.get(i..i + 3) == Some(b"(?#") {
                let Some(relative_end) = bytes[i + 3..].iter().position(|&byte| byte == b')')
                else {
                    return false;
                };
                i += relative_end + 4;
                continue;
            }
            return matches!(bytes.get(i..i + 2), Some(b"\\R" | b"\\v" | b"\\h"));
        }
    }

    fn anchor_is_terminal(bytes: &[u8], mut i: usize, extended: bool) -> bool {
        loop {
            while extended && bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
                i += 1;
            }
            if extended && bytes.get(i) == Some(&b'#') {
                i = bytes[i..]
                    .iter()
                    .position(|&byte| byte == b'\n')
                    .map_or(bytes.len(), |relative| i + relative + 1);
                continue;
            }
            return matches!(bytes.get(i), None | Some(b'|' | b')'));
        }
    }

    fn contains_escape(pattern: &str, wanted: u8, crlf: bool) -> bool {
        let bytes = pattern.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'[' {
                if let Ok(end) = byte_class_end(pattern, i, crlf) {
                    i = end;
                    continue;
                }
            }
            if bytes[i] == b'\\' {
                if bytes.get(i + 1) == Some(&wanted) {
                    return true;
                }
                i = escape_atom_end(bytes, i);
            } else {
                i += 1;
            }
        }
        false
    }

    fn capture_count(pattern: &str, crlf: bool) -> usize {
        let bytes = pattern.as_bytes();
        let mut count = 0;
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'[' {
                if let Ok(end) = byte_class_end(pattern, i, crlf) {
                    i = end;
                    continue;
                }
            }
            if bytes[i] == b'\\' {
                i = escape_atom_end(bytes, i);
                continue;
            }
            if bytes[i] == b'(' {
                let capturing = bytes.get(i + 1) != Some(&b'?')
                    || (bytes.get(i + 2) == Some(&b'<')
                        && !matches!(bytes.get(i + 3), Some(b'=') | Some(b'!')))
                    || bytes.get(i + 2..i + 4) == Some(b"P<")
                    || bytes.get(i + 2) == Some(&b'\'');
                if capturing {
                    count += 1;
                }
            }
            i += 1;
        }
        count
    }

    fn push_hex(out: &mut Vec<u8>, value: u8) {
        out.extend_from_slice(format!("\\x{value:02X}").as_bytes());
    }

    fn decimal_escape(bytes: &[u8], start: usize) -> (usize, usize) {
        let mut end = start;
        let mut value = 0usize;
        while let Some(byte @ b'0'..=b'9') = bytes.get(end).copied() {
            value = value
                .saturating_mul(10)
                .saturating_add(usize::from(byte - b'0'));
            end += 1;
        }
        (value, end)
    }

    fn parse_octal_escape(bytes: &[u8], start: usize) -> Result<(u8, usize), Error> {
        let mut end = start;
        while end < bytes.len() && end < start + 3 && matches!(bytes[end], b'0'..=b'7') {
            end += 1;
        }
        if end == start {
            return Err(Error::syntax_at(start, "invalid octal escape"));
        }
        let value = parse_radix(&bytes[start..end], 8)?;
        Ok((value, end))
    }

    fn parse_hex_escape(bytes: &[u8], slash: usize) -> Result<(u8, usize), Error> {
        let start = slash + 2;
        if bytes.get(start) == Some(&b'{') {
            let close = bytes[start + 1..]
                .iter()
                .position(|&byte| byte == b'}')
                .map(|relative| start + 1 + relative)
                .ok_or_else(|| Error::syntax_at(slash, "unterminated hexadecimal escape"))?;
            let value = parse_radix(&bytes[start + 1..close], 16)?;
            return Ok((value, close + 1));
        }
        let mut end = start;
        while end < bytes.len() && end < start + 2 && bytes[end].is_ascii_hexdigit() {
            end += 1;
        }
        if end == start {
            return Err(Error::syntax_at(slash, "empty hexadecimal escape"));
        }
        Ok((parse_radix(&bytes[start..end], 16)?, end))
    }

    fn parse_braced_octal(bytes: &[u8], slash: usize) -> Result<(u8, usize), Error> {
        let start = slash + 2;
        if bytes.get(start) != Some(&b'{') {
            return Err(Error::syntax_at(slash, "octal escape requires braces"));
        }
        let close = bytes[start + 1..]
            .iter()
            .position(|&byte| byte == b'}')
            .map(|relative| start + 1 + relative)
            .ok_or_else(|| Error::syntax_at(slash, "unterminated octal escape"))?;
        Ok((parse_radix(&bytes[start + 1..close], 8)?, close + 1))
    }

    fn parse_radix(bytes: &[u8], radix: u32) -> Result<u8, Error> {
        let text = std::str::from_utf8(bytes).map_err(|_| Error::syntax("non-ASCII escape"))?;
        let value = u16::from_str_radix(text, radix)
            .map_err(|_| Error::syntax("escape is outside the byte range"))?;
        u8::try_from(value).map_err(|_| Error::syntax("escape is outside the byte range"))
    }

    fn escape_atom_end(bytes: &[u8], slash: usize) -> usize {
        let Some(&escaped) = bytes.get(slash + 1) else {
            return bytes.len();
        };
        match escaped {
            b'Q' => bytes[slash + 2..]
                .windows(2)
                .position(|pair| pair == b"\\E")
                .map_or(bytes.len(), |relative| slash + 4 + relative),
            b'c' => (slash + 3).min(bytes.len()),
            b'x' if bytes.get(slash + 2) == Some(&b'{') => bytes[slash + 3..]
                .iter()
                .position(|&byte| byte == b'}')
                .map_or(bytes.len(), |relative| slash + 4 + relative),
            b'o' if bytes.get(slash + 2) == Some(&b'{') => bytes[slash + 3..]
                .iter()
                .position(|&byte| byte == b'}')
                .map_or(bytes.len(), |relative| slash + 4 + relative),
            b'x' => {
                let mut end = slash + 2;
                while end < bytes.len() && end < slash + 4 && bytes[end].is_ascii_hexdigit() {
                    end += 1;
                }
                end
            }
            b'0'..=b'9' => {
                let mut end = slash + 1;
                while end < bytes.len() && end < slash + 4 && bytes[end].is_ascii_digit() {
                    end += 1;
                }
                end
            }
            _ => (slash + 2).min(bytes.len()),
        }
    }

    type ByteSet = [bool; 256];

    fn translate_byte_class_caseless(
        pattern: &str,
        start: usize,
        crlf: bool,
        caseless: bool,
    ) -> Result<(String, usize), Error> {
        let (set, end) = parse_byte_class(pattern, start, crlf, caseless)?;
        let rendered = render_byte_class(&set);
        if !caseless {
            return Ok((rendered, end));
        }
        let mut scoped = String::with_capacity(rendered.len() + 6);
        scoped.push_str("(?-i:");
        scoped.push_str(&rendered);
        scoped.push(')');
        Ok((scoped, end))
    }

    fn byte_class_end(pattern: &str, start: usize, crlf: bool) -> Result<usize, Error> {
        parse_byte_class(pattern, start, crlf, false).map(|(_, end)| end)
    }

    fn parse_byte_class(
        pattern: &str,
        start: usize,
        crlf: bool,
        caseless: bool,
    ) -> Result<(ByteSet, usize), Error> {
        let bytes = pattern.as_bytes();
        let mut i = start + 1;
        let negated = bytes.get(i) == Some(&b'^');
        if negated {
            i += 1;
        }
        let mut first = true;
        let mut result = [false; 256];
        while i < bytes.len() {
            if bytes[i] == b']' && !first {
                if negated {
                    invert_set(&mut result);
                }
                return Ok((result, i + 1));
            }
            let (mut left, left_single, next) = class_atom(bytes, i, crlf)?;
            first = false;
            if bytes.get(next) == Some(&b'-') && bytes.get(next + 1) != Some(&b']') {
                let (right, right_single, end) = class_atom(bytes, next + 1, crlf)?;
                let (Some(left), Some(right)) = (left_single, right_single) else {
                    let _ = (left, right);
                    return Err(Error::syntax_at(next, "invalid character-class range"));
                };
                if left > right {
                    return Err(Error::syntax_at(
                        next,
                        "range out of order in character class",
                    ));
                }
                let mut range = [false; 256];
                for byte in left..=right {
                    range[usize::from(byte)] = true;
                }
                if caseless {
                    ascii_casefold_set(&mut range);
                }
                union_set(&mut result, &range);
                i = end;
            } else {
                if caseless {
                    ascii_casefold_set(&mut left);
                }
                union_set(&mut result, &left);
                i = next;
            }
        }
        Err(Error::syntax_at(start, "unterminated character class"))
    }

    fn class_atom(
        bytes: &[u8],
        i: usize,
        crlf: bool,
    ) -> Result<(ByteSet, Option<u8>, usize), Error> {
        if bytes.get(i..i + 2) == Some(b"[:") {
            let close = bytes[i + 2..]
                .windows(2)
                .position(|pair| pair == b":]")
                .map(|relative| i + 2 + relative)
                .ok_or_else(|| Error::syntax_at(i, "unterminated POSIX class"))?;
            let mut name = &bytes[i + 2..close];
            let negated = name.first() == Some(&b'^');
            if negated {
                name = &name[1..];
            }
            let mut set =
                posix_set(name).ok_or_else(|| Error::syntax_at(i, "unknown POSIX class"))?;
            if negated {
                invert_set(&mut set);
            }
            return Ok((set, None, close + 2));
        }
        if matches!(bytes.get(i..i + 2), Some(b"[.") | Some(b"[=")) {
            return Err(Error::unsupported(i, "collating character class"));
        }
        if bytes.get(i) == Some(&b'\\') {
            return class_escape(bytes, i, crlf);
        }
        let byte = *bytes
            .get(i)
            .ok_or_else(|| Error::syntax_at(i, "unterminated character class"))?;
        Ok((singleton_set(byte), Some(byte), i + 1))
    }

    fn class_escape(
        bytes: &[u8],
        i: usize,
        crlf: bool,
    ) -> Result<(ByteSet, Option<u8>, usize), Error> {
        let escaped = *bytes
            .get(i + 1)
            .ok_or_else(|| Error::syntax_at(i, "trailing class escape"))?;
        let (set, single, end) = match escaped {
            b'd' => (posix_set(b"digit").unwrap(), None, i + 2),
            b'D' => (complement(posix_set(b"digit").unwrap()), None, i + 2),
            b's' => (posix_set(b"space").unwrap(), None, i + 2),
            b'S' => (complement(posix_set(b"space").unwrap()), None, i + 2),
            b'w' => (posix_set(b"word").unwrap(), None, i + 2),
            b'W' => (complement(posix_set(b"word").unwrap()), None, i + 2),
            b'h' => (bytes_set(&[0x09, 0x20, 0xA0]), None, i + 2),
            b'H' => (complement(bytes_set(&[0x09, 0x20, 0xA0])), None, i + 2),
            b'v' => (bytes_set(&[b'\n', 0x0B, 0x0C, b'\r', 0x85]), None, i + 2),
            b'V' => (
                complement(bytes_set(&[b'\n', 0x0B, 0x0C, b'\r', 0x85])),
                None,
                i + 2,
            ),
            b'b' => (singleton_set(0x08), Some(0x08), i + 2),
            b'a' => (singleton_set(0x07), Some(0x07), i + 2),
            b'e' => (singleton_set(0x1B), Some(0x1B), i + 2),
            b'f' => (singleton_set(0x0C), Some(0x0C), i + 2),
            b'n' => (singleton_set(b'\n'), Some(b'\n'), i + 2),
            b'r' => (singleton_set(b'\r'), Some(b'\r'), i + 2),
            b't' => (singleton_set(b'\t'), Some(b'\t'), i + 2),
            b'x' => {
                let (value, end) = parse_hex_escape(bytes, i)?;
                (singleton_set(value), Some(value), end)
            }
            b'o' => {
                let (value, end) = parse_braced_octal(bytes, i)?;
                (singleton_set(value), Some(value), end)
            }
            b'0'..=b'7' => {
                let (value, end) = parse_octal_escape(bytes, i + 1)?;
                (singleton_set(value), Some(value), end)
            }
            b'N' if crlf => (complement(bytes_set(b"\r\n")), None, i + 2),
            b'N' => (complement(singleton_set(b'\n')), None, i + 2),
            byte if !byte.is_ascii_alphanumeric() => (singleton_set(byte), Some(byte), i + 2),
            _ => return Err(Error::syntax_at(i, "unsupported escape in character class")),
        };
        Ok((set, single, end))
    }

    fn posix_set(name: &[u8]) -> Option<ByteSet> {
        let mut set = [false; 256];
        let ranges: &[(u8, u8)] = match name {
            b"alnum" => &[(b'0', b'9'), (b'A', b'Z'), (b'a', b'z')],
            b"alpha" => &[(b'A', b'Z'), (b'a', b'z')],
            b"ascii" => &[(0x00, 0x7F)],
            b"blank" => &[(0x09, 0x09), (0x20, 0x20)],
            b"cntrl" => &[(0x00, 0x1F), (0x7F, 0x7F)],
            b"digit" => &[(b'0', b'9')],
            b"graph" => &[(0x21, 0x7E)],
            b"lower" => &[(b'a', b'z')],
            b"print" => &[(0x20, 0x7E)],
            b"punct" => &[(0x21, 0x2F), (0x3A, 0x40), (0x5B, 0x60), (0x7B, 0x7E)],
            b"space" => &[(0x09, 0x0D), (0x20, 0x20)],
            b"upper" => &[(b'A', b'Z')],
            b"word" => &[(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')],
            b"xdigit" => &[(b'0', b'9'), (b'A', b'F'), (b'a', b'f')],
            _ => return None,
        };
        for &(start, end) in ranges {
            for byte in start..=end {
                set[usize::from(byte)] = true;
            }
        }
        Some(set)
    }

    fn singleton_set(byte: u8) -> ByteSet {
        let mut set = [false; 256];
        set[usize::from(byte)] = true;
        set
    }

    fn bytes_set(bytes: &[u8]) -> ByteSet {
        let mut set = [false; 256];
        for &byte in bytes {
            set[usize::from(byte)] = true;
        }
        set
    }

    fn union_set(target: &mut ByteSet, source: &ByteSet) {
        for (target, source) in target.iter_mut().zip(source) {
            *target |= *source;
        }
    }

    fn invert_set(set: &mut ByteSet) {
        for member in set {
            *member = !*member;
        }
    }

    fn ascii_casefold_set(set: &mut ByteSet) {
        for offset in 0..26 {
            let upper = usize::from(b'A') + offset;
            let lower = usize::from(b'a') + offset;
            if set[upper] || set[lower] {
                set[upper] = true;
                set[lower] = true;
            }
        }
    }

    fn complement(mut set: ByteSet) -> ByteSet {
        invert_set(&mut set);
        set
    }

    fn render_byte_class(set: &ByteSet) -> String {
        let inverse = complement(*set);
        let positive_len = class_members_len(set);
        let negative_len = class_members_len(&inverse);
        let use_negative = negative_len > 0 && negative_len + 1 < positive_len;
        let members = if use_negative { &inverse } else { set };
        let mut out =
            String::with_capacity(2 + class_members_len(members) + usize::from(use_negative));
        out.push('[');
        if use_negative {
            out.push('^');
        }
        render_class_members(members, &mut out);
        out.push(']');
        out
    }

    fn class_members_len(set: &ByteSet) -> usize {
        let mut len = 0;
        let mut i = 0usize;
        while i < set.len() {
            if !set[i] {
                i += 1;
                continue;
            }
            let start = i;
            while i + 1 < set.len() && set[i + 1] {
                i += 1;
            }
            let end = i;
            if end >= start + 2 {
                len += 9;
            } else {
                len += (end - start + 1) * 4;
            }
            i += 1;
        }
        len
    }

    fn render_class_members(set: &ByteSet, out: &mut String) {
        let mut i = 0usize;
        while i < set.len() {
            if !set[i] {
                i += 1;
                continue;
            }
            let start = i;
            while i + 1 < set.len() && set[i + 1] {
                i += 1;
            }
            let end = i;
            if end >= start + 2 {
                push_hex_string(out, start as u8);
                out.push('-');
                push_hex_string(out, end as u8);
            } else {
                for byte in start..=end {
                    push_hex_string(out, byte as u8);
                }
            }
            i += 1;
        }
    }

    fn push_hex_string(out: &mut String, byte: u8) {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        out.push('\\');
        out.push('x');
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0F)] as char);
    }

    /// PCRE2 diagnoses a quantifier without a preceding repeatable atom.
    /// Rust regex accepts some of these metacharacters as literals.
    fn invalid_quantifier_placement(pattern: &str, extended: bool, crlf: bool) -> Option<usize> {
        let bytes = pattern.as_bytes();
        let mut i = 0;
        let mut repeatable = false;
        while i < bytes.len() {
            if extended && bytes[i].is_ascii_whitespace() {
                i += 1;
                continue;
            }
            if extended && bytes[i] == b'#' {
                i = bytes[i..]
                    .iter()
                    .position(|&byte| byte == b'\n')
                    .map_or(bytes.len(), |relative| i + relative + 1);
                continue;
            }
            match bytes[i] {
                b'[' => {
                    let Ok(end) = byte_class_end(pattern, i, crlf) else {
                        return None;
                    };
                    repeatable = true;
                    i = end;
                }
                b'\\' => {
                    let escaped = *bytes.get(i + 1)?;
                    repeatable = !matches!(escaped, b'A' | b'B' | b'G' | b'K' | b'Z' | b'b' | b'z');
                    i = escape_atom_end(bytes, i);
                }
                b'(' => {
                    if bytes[i..].starts_with(b"(?#") {
                        i = bytes[i + 3..]
                            .iter()
                            .position(|&byte| byte == b')')
                            .map_or(bytes.len(), |relative| i + 4 + relative);
                        continue;
                    }
                    repeatable = false;
                    i += 1;
                    if bytes.get(i) == Some(&b'?') {
                        i += 1;
                        if bytes.get(i) == Some(&b'P') && bytes.get(i + 1) == Some(&b'<') {
                            i += 2;
                            while i < bytes.len() && bytes[i] != b'>' {
                                i += 1;
                            }
                            i = (i + 1).min(bytes.len());
                        } else if bytes.get(i) == Some(&b'<')
                            && !matches!(bytes.get(i + 1), Some(b'=') | Some(b'!'))
                        {
                            i += 1;
                            while i < bytes.len() && bytes[i] != b'>' {
                                i += 1;
                            }
                            i = (i + 1).min(bytes.len());
                        } else if bytes.get(i) == Some(&b'\'') {
                            i += 1;
                            while i < bytes.len() && bytes[i] != b'\'' {
                                i += 1;
                            }
                            i = (i + 1).min(bytes.len());
                        } else if bytes.get(i) == Some(&b':') {
                            i += 1;
                        } else if bytes
                            .get(i)
                            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'-')
                        {
                            while i < bytes.len()
                                && (bytes[i].is_ascii_alphabetic() || bytes[i] == b'-')
                            {
                                i += 1;
                            }
                            if matches!(bytes.get(i), Some(b':') | Some(b')')) {
                                i += 1;
                            }
                        }
                    }
                }
                b')' => {
                    repeatable = true;
                    i += 1;
                }
                b'^' | b'$' | b'|' => {
                    repeatable = false;
                    i += 1;
                }
                b'*' | b'+' | b'?' => {
                    if !repeatable {
                        return Some(i);
                    }
                    i += 1;
                    if matches!(bytes.get(i), Some(b'?') | Some(b'+')) {
                        i += 1;
                    }
                    repeatable = false;
                }
                b'{' if quantifier_end(&bytes[i..]).is_some() => {
                    if !repeatable {
                        return Some(i);
                    }
                    i += quantifier_end(&bytes[i..]).unwrap_or(1);
                    if matches!(bytes.get(i), Some(b'?') | Some(b'+')) {
                        i += 1;
                    }
                    repeatable = false;
                }
                _ => {
                    repeatable = true;
                    i += 1;
                }
            }
        }
        None
    }

    fn quantifier_end(bytes: &[u8]) -> Option<usize> {
        if bytes.first() != Some(&b'{') {
            return None;
        }
        let close = bytes.iter().position(|&byte| byte == b'}')?;
        let body = &bytes[1..close];
        let valid = !body.is_empty()
            && body
                .iter()
                .all(|byte| byte.is_ascii_digit() || *byte == b',')
            && body.iter().filter(|&&byte| byte == b',').count() <= 1
            && body.iter().any(u8::is_ascii_digit);
        valid.then_some(close + 1)
    }

    #[derive(Clone, Copy)]
    struct CaptureFrame {
        capturing: bool,
        variable_repeat: bool,
        alternation: bool,
        zero_width: bool,
    }

    fn ambiguous_nested_capture_repeat(pattern: &str, crlf: bool) -> Option<usize> {
        let bytes = pattern.as_bytes();
        let mut stack: Vec<CaptureFrame> = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'[' {
                if let Ok(end) = byte_class_end(pattern, i, crlf) {
                    i = end;
                    continue;
                }
            }
            if bytes[i] == b'\\' {
                if matches!(
                    bytes.get(i + 1),
                    Some(b'A' | b'B' | b'G' | b'K' | b'Z' | b'b' | b'z')
                ) {
                    for frame in &mut stack {
                        frame.zero_width = true;
                    }
                }
                i = escape_atom_end(bytes, i);
                continue;
            }
            match bytes[i] {
                b'(' => {
                    if bytes.get(i..i + 3) == Some(b"(?#") {
                        i = bytes[i + 3..]
                            .iter()
                            .position(|&byte| byte == b')')
                            .map_or(bytes.len(), |relative| i + 4 + relative);
                        continue;
                    }
                    if let Some(end) = global_option_group_end(bytes, i) {
                        i = end;
                        continue;
                    }
                    let capturing = bytes.get(i + 1) != Some(&b'?')
                        || (bytes.get(i + 2) == Some(&b'<')
                            && !matches!(bytes.get(i + 3), Some(b'=') | Some(b'!')))
                        || bytes.get(i + 2..i + 4) == Some(b"P<")
                        || bytes.get(i + 2) == Some(&b'\'');
                    stack.push(CaptureFrame {
                        capturing,
                        variable_repeat: false,
                        alternation: false,
                        zero_width: false,
                    });
                    i = group_body_start(bytes, i);
                }
                b'|' => {
                    let empty_branch = matches!(bytes.get(i + 1), None | Some(b')' | b'|'))
                        || matches!(bytes.get(i.wrapping_sub(1)), Some(b'(' | b'|'));
                    for frame in &mut stack {
                        frame.alternation = true;
                        frame.zero_width |= empty_branch;
                    }
                    i += 1;
                }
                b'^' | b'$' => {
                    for frame in &mut stack {
                        frame.zero_width = true;
                    }
                    i += 1;
                }
                b'*' | b'+' | b'?' => {
                    for frame in &mut stack {
                        frame.variable_repeat = true;
                    }
                    i += 1;
                }
                b'{' if quantifier_end(&bytes[i..]).is_some() => {
                    let end = quantifier_end(&bytes[i..]).unwrap_or(1);
                    let body = &bytes[i + 1..i + end - 1];
                    if body.contains(&b',') {
                        for frame in &mut stack {
                            frame.variable_repeat = true;
                        }
                    }
                    i += end;
                }
                b')' => {
                    let frame = stack.pop()?;
                    let repeated = matches!(bytes.get(i + 1), Some(b'*' | b'+' | b'?' | b'{'));
                    if frame.capturing
                        && repeated
                        && (frame.variable_repeat || (frame.alternation && frame.zero_width))
                    {
                        return Some(i + 1);
                    }
                    i += 1;
                }
                _ => i += 1,
            }
        }
        None
    }

    fn global_option_group_end(bytes: &[u8], start: usize) -> Option<usize> {
        if bytes.get(start..start + 2) != Some(b"(?") {
            return None;
        }
        let close = bytes[start + 2..].iter().position(|&byte| byte == b')')? + start + 2;
        let flags = &bytes[start + 2..close];
        (!flags.is_empty()
            && flags
                .iter()
                .all(|byte| byte.is_ascii_alphabetic() || *byte == b'-'))
        .then_some(close + 1)
    }

    fn group_body_start(bytes: &[u8], start: usize) -> usize {
        if bytes.get(start..start + 3) == Some(b"(?:") {
            return start + 3;
        }
        if bytes.get(start..start + 4) == Some(b"(?P<") {
            return bytes[start + 4..]
                .iter()
                .position(|&byte| byte == b'>')
                .map_or(start + 2, |relative| start + 5 + relative);
        }
        if bytes.get(start..start + 3) == Some(b"(?<") {
            return bytes[start + 3..]
                .iter()
                .position(|&byte| byte == b'>')
                .map_or(start + 2, |relative| start + 4 + relative);
        }
        if bytes.get(start..start + 3) == Some(b"(?'") {
            return bytes[start + 3..]
                .iter()
                .position(|&byte| byte == b'\'')
                .map_or(start + 2, |relative| start + 4 + relative);
        }
        if bytes.get(start..start + 2) == Some(b"(?") {
            if let Some(relative) = bytes[start + 2..].iter().position(|&byte| byte == b':') {
                return start + 3 + relative;
            }
        }
        start + 1
    }
}

#[cfg(test)]
mod tests {
    use super::bytes::{Regex, RegexBuilder};
    use super::ErrorKind;

    #[test]
    fn pcre_regular_extensions_and_captures() {
        assert!(Regex::new(r"\Qsecret.txt\E\Z")
            .unwrap()
            .is_match(b"secret.txt")
            .unwrap());
        assert!(Regex::new(r"sec(?# ignored)ret")
            .unwrap()
            .is_match(b"secret")
            .unwrap());
        let regex = Regex::new(r"pre\K(?<value>secret)").unwrap();
        let captures = regex.captures(b"presecret").unwrap().unwrap();
        assert_eq!(captures.get(0).unwrap().as_bytes(), b"secret");
        assert_eq!(captures.name("value").unwrap().as_bytes(), b"secret");
        assert_eq!(regex.captures_len(), 2);
    }

    #[test]
    fn backtracking_constructs_fail_closed() {
        for pattern in [r"(a)\1", r"(?=a)a", r"(?>a)", r"a++", r"(?R)"] {
            let error = Regex::new(pattern).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Unsupported, "{pattern}: {error}");
        }
        let mut builder = RegexBuilder::new();
        builder.backtracking(true);
        assert_eq!(
            builder.build("a").unwrap_err().kind(),
            ErrorKind::ResourceLimit
        );
        assert_eq!(Regex::new("^?<wo").unwrap_err().kind(), ErrorKind::Syntax);
    }

    #[test]
    fn fuzzed_escape_edges_fail_closed_without_panicking() {
        let error = Regex::new(r"\ҭend").unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unsupported);
        let error = Regex::new(r"\7<sords+").unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn resource_limits_are_errors_not_partial_matches() {
        let mut builder = RegexBuilder::new();
        builder.max_subject_size(3).match_limit(32);
        let regex = builder.build("a+").unwrap();
        assert!(regex.is_match(b"aaa").unwrap());
        assert_eq!(
            regex.is_match(b"aaaa").unwrap_err().kind(),
            ErrorKind::ResourceLimit
        );
    }

    #[test]
    fn iterators_advance_after_empty_matches() {
        let regex = Regex::new("a*").unwrap();
        let matches: Vec<_> = regex
            .find_iter(b"bb")
            .map(|result| {
                let matched = result.unwrap();
                (matched.start(), matched.end())
            })
            .collect();
        assert_eq!(matches, vec![(0, 0), (1, 1), (2, 2)]);

        let adjacent = Regex::new("a*").unwrap();
        let matches: Vec<_> = adjacent
            .find_iter(b"a")
            .map(|result| {
                let matched = result.unwrap();
                (matched.start(), matched.end())
            })
            .collect();
        assert_eq!(matches, vec![(0, 1)]);
    }
}
