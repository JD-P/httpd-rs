use proptest::prelude::*;
use std::io::{self, Read, Write};
use vapached::config::{Options, Scope};
use vapached::http::{read_request, Limits, ReadError};
use vapached::scope_policy::OptionsPolicy;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn normalized_paths_are_idempotent(tail in prop::collection::vec(any::<u8>(), 0..512)) {
        let mut input = vec![b'/'];
        input.extend(tail);
        if let Some(normalized) = vapached::verified::normalize_uri_path(&input) {
            prop_assert_eq!(vapached::verified::normalize_uri_path(&normalized), Some(normalized));
        }
    }

    #[test]
    fn cache_key_hex_is_injective_and_alphabet_safe(
        left in prop::collection::vec(any::<u8>(), 0..256),
        right in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let encoded_left = vapached::verified::cache_key_hex(&left);
        let encoded_right = vapached::verified::cache_key_hex(&right);
        prop_assert_eq!(encoded_left.len(), left.len() * 2);
        prop_assert!(encoded_left.iter().all(u8::is_ascii_hexdigit));
        if left != right {
            prop_assert_ne!(encoded_left, encoded_right);
        }
    }

    #[test]
    fn conjoining_options_never_grants(url in any::<u32>(), target in any::<u32>()) {
        let result = vapached::verified::options_conjoin(url, target);
        prop_assert_eq!(result & url, result);
        prop_assert_eq!(result & target, result);
        prop_assert_eq!(result, vapached::verified::options_conjoin(target, url));
    }

    #[test]
    fn removing_options_is_monotone(bits in any::<u32>(), mask in any::<u32>()) {
        let result = vapached::verified::options_apply(bits, 2, mask);
        prop_assert_eq!(result & bits, result);
        prop_assert_eq!(result & mask, 0);
    }

    #[test]
    fn aggregate_budget_admission_cannot_overflow(
        used in any::<u64>(), incoming in any::<u64>(), limit in any::<u64>(),
    ) {
        if vapached::verified::resource_budget_admit(used, incoming, limit) {
            prop_assert!(used.checked_add(incoming).is_some_and(|sum| sum <= limit));
        }
    }

    #[test]
    fn autoindex_admission_cannot_overflow(
        used in any::<u64>(), incoming in any::<u64>(), limit in any::<u64>(),
    ) {
        if vapached::verified::autoindex_append_admit(used, incoming, limit) {
            prop_assert!(used.checked_add(incoming).is_some_and(|sum| sum <= limit));
        }
    }

    #[test]
    fn only_successful_unsafe_requests_invalidate(
        unsafe_method in any::<bool>(), status in any::<u16>(),
    ) {
        let admitted = vapached::verified::cache_invalidation_status_admit(unsafe_method, status);
        prop_assert_eq!(admitted, unsafe_method && (200..400).contains(&status));
    }

    #[test]
    fn ambiguous_proxy_retries_require_idempotency(
        request_may_have_started in any::<bool>(), idempotent in any::<bool>(),
    ) {
        prop_assert_eq!(
            vapached::verified::proxy_retry_admit(request_may_have_started, idempotent),
            !request_may_have_started || idempotent
        );
    }

    #[test]
    fn bcrypt_cost_is_limited_to_htpasswd_range(cost in any::<u32>()) {
        prop_assert_eq!(vapached::verified::bcrypt_cost_admit(cost), (4..=17).contains(&cost));
    }

    #[test]
    fn request_body_memory_admission_cannot_overflow(
        used in any::<u64>(), incoming in any::<u64>(), limit in any::<u64>(),
    ) {
        if vapached::verified::request_body_memory_admit(used, incoming, limit) {
            prop_assert!(used.checked_add(incoming).is_some_and(|sum| sum <= limit));
        }
    }

    #[test]
    fn cache_memory_admission_cannot_overflow(
        used in any::<u64>(), incoming in any::<u64>(), limit in any::<u64>(),
    ) {
        if vapached::verified::cache_memory_admit(used, incoming, limit) {
            prop_assert!(used.checked_add(incoming).is_some_and(|sum| sum <= limit));
        }
    }

    #[test]
    fn proxy_operator_gate_never_accepts_an_operator_denial(
        proxy_selected in any::<bool>(), operator_allowed in any::<bool>(),
    ) {
        let admitted =
            vapached::verified::proxy_operator_acl_admit(proxy_selected, operator_allowed);
        prop_assert!(!admitted || !proxy_selected || operator_allowed);
    }

    #[test]
    fn expression_file_read_gate_requires_regular_bounded_input(
        regular in any::<bool>(), size in any::<u64>(), limit in any::<u64>(),
    ) {
        let admitted = vapached::verified::expr_file_read_admit(regular, size, limit);
        prop_assert_eq!(admitted, regular && size <= limit);
    }

    #[test]
    fn capability_disable_is_monotone(requested in any::<bool>()) {
        let disabled = vapached::verified::capability_admit(false, requested);
        let enabled = vapached::verified::capability_admit(true, requested);
        prop_assert!(!requested || !disabled);
        prop_assert!(!disabled || enabled);
        prop_assert!(enabled);
    }

    #[test]
    fn runtime_scope_restriction_refines_verified_options_meet(
        url in any::<u32>(), target in any::<u32>(),
    ) {
        let mut lexical = Scope::default();
        lexical.options = OptionsPolicy::default();
        lexical.options.push_set(url);
        let mut resolved = Scope::default();
        resolved.options = OptionsPolicy::default();
        resolved.options.push_set(target);
        resolved.restrict_policy_with(&lexical);
        prop_assert_eq!(
            resolved.effective_options().0,
            vapached::verified::options_conjoin(url, target)
        );
    }

    #[test]
    fn http_parser_is_independent_of_read_fragmentation(
        wire in prop::collection::vec(any::<u8>(), 0..8192),
        chunk in 1usize..128,
    ) {
        prop_assert_eq!(parse_once(&wire, wire.len().max(1)), parse_once(&wire, chunk));
    }

    #[test]
    fn content_length_consumes_exactly_one_message(
        body in prop::collection::vec(any::<u8>(), 0..4096),
        chunk in 1usize..128,
    ) {
        let mut wire = format!(
            "POST /first HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        wire.extend_from_slice(&body);
        wire.extend_from_slice(
            b"GET /second HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
        );

        let (first, second, remainder) = parse_two(&wire, chunk)?;
        prop_assert_eq!(first.target, b"/first");
        prop_assert_eq!(first.body, body);
        prop_assert_eq!(second.target, b"/second");
        prop_assert!(second.body.is_empty());
        prop_assert!(remainder.is_empty());
    }

    #[test]
    fn chunked_consumes_exactly_one_message(
        body in prop::collection::vec(any::<u8>(), 0..4096),
        chunk in 1usize..128,
    ) {
        let mut wire = b"POST /first HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        if !body.is_empty() {
            wire.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
            wire.extend_from_slice(&body);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        wire.extend_from_slice(
            b"GET /second HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
        );

        let (first, second, remainder) = parse_two(&wire, chunk)?;
        prop_assert_eq!(first.target, b"/first");
        prop_assert_eq!(first.body, body);
        prop_assert_eq!(second.target, b"/second");
        prop_assert!(second.body.is_empty());
        prop_assert!(remainder.is_empty());
    }
}

#[derive(Debug)]
struct Fragmented<'a> {
    input: &'a [u8],
    offset: usize,
    chunk: usize,
}

impl Read for Fragmented<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let take = output
            .len()
            .min(self.chunk)
            .min(self.input.len().saturating_sub(self.offset));
        output[..take].copy_from_slice(&self.input[self.offset..self.offset + take]);
        self.offset += take;
        Ok(take)
    }
}

impl Write for Fragmented<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn parse_once(wire: &[u8], chunk: usize) -> String {
    let mut stream = Fragmented {
        input: wire,
        offset: 0,
        chunk,
    };
    let mut buffered = Vec::new();
    let limits = Limits::default();
    let context = limits
        .resource_budget
        .context(std::net::IpAddr::from([192, 0, 2, 1]));
    let result = vapached::resource::with_resource_context(context, || {
        read_request(&mut stream, &mut buffered, &limits, |_| {})
    });
    match result {
        Ok(Some(request)) => format!(
            "ok:{}:{:?}:{}:{}:{:?}",
            request.method,
            request.target,
            request.body_len(),
            request.keep_alive,
            buffered
        ),
        Ok(None) => "eof".into(),
        Err(ReadError::Parse(error)) => format!("parse:{}:{}", error.status(), error.message()),
        Err(ReadError::Io(error)) => format!("io:{:?}", error.kind()),
    }
}

fn parse_two(
    wire: &[u8],
    chunk: usize,
) -> Result<(vapached::http::Request, vapached::http::Request, Vec<u8>), TestCaseError> {
    let mut stream = Fragmented {
        input: wire,
        offset: 0,
        chunk,
    };
    let mut buffered = Vec::new();
    let limits = Limits::default();
    let context = limits
        .resource_budget
        .context(std::net::IpAddr::from([192, 0, 2, 2]));
    vapached::resource::with_resource_context(context, || {
        let first = read_request(&mut stream, &mut buffered, &limits, |_| {})
            .map_err(|error| TestCaseError::fail(format!("first request: {error:?}")))?
            .ok_or_else(|| TestCaseError::fail("first request: unexpected EOF"))?;
        let second = read_request(&mut stream, &mut buffered, &limits, |_| {})
            .map_err(|error| TestCaseError::fail(format!("second request: {error:?}")))?
            .ok_or_else(|| TestCaseError::fail("second request: unexpected EOF"))?;
        Ok((first, second, buffered))
    })
}

#[test]
fn options_default_remains_follow_symlinks_after_property_setup() {
    assert!(Scope::default()
        .effective_options()
        .contains(Options::FOLLOW_SYMLINKS));
}
