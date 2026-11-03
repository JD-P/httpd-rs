//! `mod_expires` subset: `ExpiresActive`, `ExpiresDefault` and
//! `ExpiresByType`, with Apache's `access plus N units` / `M<seconds>` forms.

use crate::config::Scope;
use crate::http::Response;

fn duration(spec: &str) -> Option<i64> {
    let spec = spec.trim();
    if let Some(rest) = spec.strip_prefix('M') {
        return rest.trim().parse().ok();
    }
    if let Some(rest) = spec.strip_prefix('A') {
        return rest.trim().parse().ok();
    }
    let words: Vec<&str> = spec.split_whitespace().collect();
    let mut i = 0;
    let mut base_mod = false;
    if words
        .get(i)
        .map(|w| w.eq_ignore_ascii_case("access") || w.eq_ignore_ascii_case("now"))
        == Some(true)
    {
        i += 1;
    } else if words.get(i).map(|w| w.eq_ignore_ascii_case("modification")) == Some(true) {
        base_mod = true;
        i += 1;
    } else {
        return None;
    }
    if words.get(i).map(|w| w.eq_ignore_ascii_case("plus")) == Some(true) {
        i += 1;
    }
    let n: i64 = words.get(i)?.parse().ok()?;
    let unit = words.get(i + 1)?.to_ascii_lowercase();
    let seconds = match unit.trim_end_matches('s') {
        "second" => 1,
        "minute" => 60,
        "hour" => 3600,
        "day" => 86_400,
        "week" => 7 * 86_400,
        "month" => 30 * 86_400,
        "year" => 365 * 86_400,
        _ => return None,
    };
    let n = n.checked_mul(seconds)?;
    Some(if base_mod { n | (1 << 62) } else { n })
}

/// Configuration-time grammar check shared by main configuration and
/// access-file compilers. Invalid expiry syntax must not be accepted and then
/// silently omitted when a response is generated.
pub(crate) fn valid_spec(spec: &str) -> bool {
    duration(spec).is_some()
}

fn header<'a>(resp: &'a Response, name: &str) -> Option<&'a [u8]> {
    resp.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}

fn set(resp: &mut Response, name: &'static str, value: Vec<u8>) {
    resp.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
    resp.headers.push((std::borrow::Cow::Borrowed(name), value));
}

pub fn apply(scope: &Scope, resp: &mut Response) {
    if scope.header_policy.expires_active != Some(true) {
        return;
    }
    if resp.status == 204 || resp.status == 205 || (100..200).contains(&resp.status) {
        return;
    }
    let media = header(resp, "content-type").map(|v| {
        String::from_utf8_lossy(v)
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
    });
    let spec = media
        .as_deref()
        .and_then(|m| {
            scope
                .header_policy
                .expires_by_type
                .iter()
                .find(|(t, _)| t == m || t == "*")
                .map(|(_, s)| s.as_str())
        })
        .or(scope.header_policy.expires_default.as_deref());
    let Some(spec) = spec else { return };
    let Some(mut secs) = duration(spec) else {
        return;
    };
    let modification = secs & (1 << 62) != 0;
    if modification {
        secs &= !(1 << 62);
    }
    let base = if modification {
        header(resp, "last-modified")
            .and_then(crate::util::parse_http_date)
            .unwrap_or_else(crate::util::unix_now)
    } else {
        crate::util::unix_now()
    };
    let expires = base.saturating_add(secs);
    set(
        resp,
        "Expires",
        crate::util::http_date(expires).into_bytes(),
    );
    let max_age = secs.max(0);
    if let Some(cc) = header(resp, "cache-control") {
        let text = String::from_utf8_lossy(cc);
        if text
            .split(',')
            .any(|v| v.trim().eq_ignore_ascii_case("no-store"))
        {
            return;
        }
        if !text.to_ascii_lowercase().contains("max-age=") {
            set(
                resp,
                "Cache-Control",
                format!("{text}, max-age={max_age}").into_bytes(),
            );
        }
    } else {
        set(
            resp,
            "Cache-Control",
            format!("max-age={max_age}").into_bytes(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Scope;
    use crate::http::{Body, Response};
    use crate::util::http_date_now;

    #[test]
    fn parses_apache_duration_forms() {
        assert_eq!(duration("access plus 1 day"), Some(86_400));
        assert_eq!(duration("A3600"), Some(3600));
        assert_eq!(duration("M60"), Some(60));
        assert!(duration("bogus").is_none());
        assert_eq!(
            duration("modification plus 2 weeks"),
            Some((1 << 62) | 1_209_600)
        );
        assert_eq!(duration("now 1 month"), Some(2_592_000));
        assert_eq!(duration("access 1 year"), Some(31_536_000));
        assert!(duration("access 1 fortnight").is_none());
        assert!(duration("access nope seconds").is_none());
        assert!(duration("access 9223372036854775807 years").is_none());
    }

    #[test]
    fn applies_type_and_default_rules() {
        let mut scope = Scope::default();
        scope.header_policy.expires_active = Some(true);
        scope.header_policy.expires_default = Some("access plus 1 hour".into());
        scope
            .header_policy
            .expires_by_type
            .push(("text/html".into(), "access plus 1 day".into()));
        let mut r = Response::new(200);
        r.headers.push((
            std::borrow::Cow::Borrowed("Content-Type"),
            b"text/html".to_vec(),
        ));
        r.body = Body::Bytes(b"x".to_vec());
        apply(&scope, &mut r);
        assert!(r.headers.iter().any(|(n, _)| n == "Expires"));
        let cc = r
            .headers
            .iter()
            .find(|(n, _)| n == "Cache-Control")
            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
            .unwrap();
        assert!(cc.contains("max-age=86400"));
        let _ = http_date_now();
    }

    fn active_scope(spec: Option<&str>) -> Scope {
        let mut scope = Scope::default();
        scope.header_policy.expires_active = Some(true);
        scope.header_policy.expires_default = spec.map(str::to_string);
        scope
    }

    #[test]
    fn apply_covers_inactive_status_invalid_and_cache_control_edges() {
        let mut response = Response::new(200);
        apply(&Scope::default(), &mut response);
        assert!(header(&response, "Expires").is_none());

        for status in [101, 204, 205] {
            let mut response = Response::new(status);
            apply(&active_scope(Some("A60")), &mut response);
            assert!(header(&response, "Expires").is_none());
        }

        let mut response = Response::new(200);
        apply(&active_scope(None), &mut response);
        assert!(header(&response, "Expires").is_none());
        apply(&active_scope(Some("invalid")), &mut response);
        assert!(header(&response, "Expires").is_none());

        let mut response = Response::new(200);
        response.headers.push((
            std::borrow::Cow::Borrowed("Last-Modified"),
            http_date_now().into_bytes(),
        ));
        response.headers.push((
            std::borrow::Cow::Borrowed("Cache-Control"),
            b"public".to_vec(),
        ));
        apply(
            &active_scope(Some("modification plus 1 second")),
            &mut response,
        );
        assert!(
            String::from_utf8_lossy(header(&response, "Cache-Control").unwrap())
                .contains("max-age=1")
        );

        let mut response = Response::new(200);
        response.headers.push((
            std::borrow::Cow::Borrowed("Cache-Control"),
            b"private, no-store".to_vec(),
        ));
        apply(&active_scope(Some("A60")), &mut response);
        assert_eq!(
            header(&response, "Cache-Control"),
            Some(&b"private, no-store"[..])
        );

        let mut response = Response::new(200);
        response.headers.push((
            std::borrow::Cow::Borrowed("Cache-Control"),
            b"max-age=7".to_vec(),
        ));
        apply(&active_scope(Some("A60")), &mut response);
        assert_eq!(header(&response, "Cache-Control"), Some(&b"max-age=7"[..]));
    }
}
