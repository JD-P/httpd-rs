//! Closed grammars for security-relevant HTTP field values.
//!
//! These parsers operate on bytes, consume the complete field value, and
//! return typed values.  Callers must not recover a useful prefix from a
//! malformed field: ambiguity at a cache, routing, or representation-selection
//! boundary fails closed.

use crate::util::{days_from_civil, eq_ignore_ascii_case, trim_ascii};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct QValue(u16);

impl QValue {
    pub(crate) const ZERO: Self = Self(0);
    pub(crate) const ONE: Self = Self(1000);

    pub(crate) const fn milli(self) -> u16 {
        self.0
    }
}

/// RFC 9110 qvalue, represented exactly in thousandths.
pub(crate) fn parse_qvalue(raw: &[u8]) -> Option<QValue> {
    let raw = trim_ascii(raw);
    let (whole, fraction) = match raw.iter().position(|byte| *byte == b'.') {
        Some(dot) => (&raw[..dot], Some(&raw[dot + 1..])),
        None => (raw, None),
    };
    let fraction = fraction.unwrap_or_default();
    if fraction.len() > 3 || !fraction.iter().all(u8::is_ascii_digit) {
        return None;
    }
    match whole {
        b"0" => {
            let mut value = 0u16;
            for (index, byte) in fraction.iter().enumerate() {
                value += u16::from(*byte - b'0') * [100, 10, 1][index];
            }
            Some(QValue(value))
        }
        b"1" if fraction.iter().all(|byte| *byte == b'0') => Some(QValue::ONE),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WeightedItem<'a> {
    pub(crate) value: &'a [u8],
    pub(crate) quality: QValue,
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn valid_item_value(value: &[u8]) -> bool {
    !value.is_empty() && value.iter().all(|byte| is_tchar(*byte) || *byte == b'/')
}

fn parse_parameter_value(value: &[u8]) -> Option<&[u8]> {
    if value.first() == Some(&b'"') {
        if value.len() < 2 || value.last() != Some(&b'"') {
            return None;
        }
        let mut escaped = false;
        for byte in &value[1..value.len() - 1] {
            if escaped {
                if !matches!(*byte, b'\t' | b' '..=b'~' | 0x80..=0xff) {
                    return None;
                }
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if !matches!(*byte, b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~' | 0x80..=0xff)
            {
                return None;
            }
        }
        if escaped {
            return None;
        }
        return Some(value);
    }
    (!value.is_empty() && value.iter().all(|byte| is_tchar(*byte))).then_some(value)
}

fn split_quoted(input: &[u8], delimiter: u8) -> Option<Vec<&[u8]>> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in input.iter().copied().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if !quoted && byte == delimiter {
            out.push(&input[start..index]);
            start = index + 1;
        }
    }
    if quoted || escaped {
        return None;
    }
    out.push(&input[start..]);
    Some(out)
}

/// Parse a comma-separated token/range list with RFC parameters and at most
/// one exact `q` parameter per member.
pub(crate) fn parse_weighted_list(value: &[u8]) -> Option<Vec<WeightedItem<'_>>> {
    let members = split_quoted(value, b',')?;
    if members.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(members.len());
    for member in members {
        let parts = split_quoted(member, b';')?;
        let item = trim_ascii(parts.first().copied().unwrap_or_default());
        if !valid_item_value(item) {
            return None;
        }
        let mut quality = QValue::ONE;
        let mut saw_quality = false;
        for parameter in parts.into_iter().skip(1) {
            let parameter = trim_ascii(parameter);
            let equals = parameter.iter().position(|byte| *byte == b'=')?;
            let name = trim_ascii(&parameter[..equals]);
            let parameter_value = trim_ascii(&parameter[equals + 1..]);
            if name.is_empty() || !name.iter().all(|byte| is_tchar(*byte)) {
                return None;
            }
            parse_parameter_value(parameter_value)?;
            if eq_ignore_ascii_case(name, b"q") {
                if saw_quality {
                    return None;
                }
                quality = parse_qvalue(parameter_value)?;
                saw_quality = true;
            }
        }
        out.push(WeightedItem {
            value: item,
            quality,
        });
    }
    Some(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EntityTag<'a> {
    pub(crate) weak: bool,
    opaque: &'a [u8],
}

impl EntityTag<'_> {
    pub(crate) fn weak_eq(self, other: Self) -> bool {
        self.opaque == other.opaque
    }

    pub(crate) fn strong_eq(self, other: Self) -> bool {
        !self.weak && !other.weak && self.opaque == other.opaque
    }
}

pub(crate) fn parse_entity_tag(value: &[u8]) -> Option<EntityTag<'_>> {
    let (weak, value) = if let Some(rest) = value.strip_prefix(b"W/") {
        (true, rest)
    } else {
        (false, value)
    };
    if value.len() < 2 || value.first() != Some(&b'"') || value.last() != Some(&b'"') {
        return None;
    }
    let opaque = &value[1..value.len() - 1];
    if !opaque
        .iter()
        .all(|byte| *byte == 0x21 || matches!(*byte, 0x23..=0x7e | 0x80..=0xff))
    {
        return None;
    }
    Some(EntityTag { weak, opaque })
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EntityTagList<'a> {
    Any,
    Tags(Vec<EntityTag<'a>>),
}

pub(crate) fn parse_entity_tag_list(value: &[u8]) -> Option<EntityTagList<'_>> {
    let value = trim_ascii(value);
    if value == b"*" {
        return Some(EntityTagList::Any);
    }
    let mut tags = Vec::new();
    let mut cursor = 0usize;
    loop {
        while value
            .get(cursor)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            cursor += 1;
        }
        let start = cursor;
        if value.get(cursor..cursor + 2) == Some(b"W/") {
            cursor += 2;
        }
        if value.get(cursor) != Some(&b'"') {
            return None;
        }
        cursor += 1;
        while value.get(cursor).is_some_and(|byte| *byte != b'"') {
            let byte = value[cursor];
            if !(byte == 0x21 || matches!(byte, 0x23..=0x7e | 0x80..=0xff)) {
                return None;
            }
            cursor += 1;
        }
        if value.get(cursor) != Some(&b'"') {
            return None;
        }
        cursor += 1;
        tags.push(parse_entity_tag(&value[start..cursor])?);
        while value
            .get(cursor)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            cursor += 1;
        }
        if cursor == value.len() {
            break;
        }
        if value.get(cursor) != Some(&b',') {
            return None;
        }
        cursor += 1;
    }
    (!tags.is_empty()).then_some(EntityTagList::Tags(tags))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CookiePair<'a> {
    pub(crate) name: &'a [u8],
    pub(crate) value: &'a [u8],
}

fn cookie_octet(byte: u8) -> bool {
    matches!(byte, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e)
}

/// Strict RFC 6265 Cookie grammar. OWS around pairs is tolerated because the
/// HTTP adapters already merge repeated Cookie fields using `; `.
pub(crate) fn parse_cookie(value: &[u8]) -> Option<Vec<CookiePair<'_>>> {
    if value.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for pair in value.split(|byte| *byte == b';') {
        let pair = trim_ascii(pair);
        let equals = pair.iter().position(|byte| *byte == b'=')?;
        let name = &pair[..equals];
        let mut cookie_value = &pair[equals + 1..];
        if name.is_empty() || !name.iter().all(|byte| is_tchar(*byte)) {
            return None;
        }
        if cookie_value.first() == Some(&b'"') {
            if cookie_value.len() < 2 || cookie_value.last() != Some(&b'"') {
                return None;
            }
            cookie_value = &cookie_value[1..cookie_value.len() - 1];
        }
        if !cookie_value.iter().all(|byte| cookie_octet(*byte)) {
            return None;
        }
        out.push(CookiePair {
            name,
            value: cookie_value,
        });
    }
    (!out.is_empty()).then_some(out)
}

fn parse_digits(value: &[u8]) -> Option<u32> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut out = 0u32;
    for byte in value {
        out = out.checked_mul(10)?.checked_add(u32::from(*byte - b'0'))?;
    }
    Some(out)
}

fn month(value: &[u8]) -> Option<u32> {
    [
        b"Jan".as_slice(),
        b"Feb",
        b"Mar",
        b"Apr",
        b"May",
        b"Jun",
        b"Jul",
        b"Aug",
        b"Sep",
        b"Oct",
        b"Nov",
        b"Dec",
    ]
    .iter()
    .position(|candidate| *candidate == value)
    .map(|index| index as u32 + 1)
}

fn leap_year(year: i64) -> bool {
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

fn valid_day(year: i64, month: u32, day: u32) -> bool {
    let limit = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year(year) => 29,
        2 => 28,
        _ => return false,
    };
    (1..=limit).contains(&day)
}

fn hms(value: &[u8]) -> Option<(u32, u32, u32)> {
    if value.len() != 8 || value[2] != b':' || value[5] != b':' {
        return None;
    }
    let hour = parse_digits(&value[..2])?;
    let minute = parse_digits(&value[3..5])?;
    let second = parse_digits(&value[6..])?;
    (hour <= 23 && minute <= 59 && second <= 60).then_some((hour, minute, second))
}

fn weekday_short(value: &[u8]) -> Option<usize> {
    [b"Thu", b"Fri", b"Sat", b"Sun", b"Mon", b"Tue", b"Wed"]
        .iter()
        .position(|candidate| *candidate == value)
}

fn weekday_long(value: &[u8]) -> Option<usize> {
    [
        b"Thursday".as_slice(),
        b"Friday",
        b"Saturday",
        b"Sunday",
        b"Monday",
        b"Tuesday",
        b"Wednesday",
    ]
    .iter()
    .position(|candidate| *candidate == value)
}

fn timestamp(weekday: usize, year: i64, month: u32, day: u32, time: &[u8]) -> Option<i64> {
    if !valid_day(year, month, day) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    if days.rem_euclid(7) as usize != weekday {
        return None;
    }
    let (hour, minute, second) = hms(time)?;
    days.checked_mul(86_400)?
        .checked_add(i64::from(hour * 3600 + minute * 60 + second))
}

/// Parse exactly one of the three HTTP-date productions accepted by RFC 9110.
pub fn parse_http_date(value: &[u8]) -> Option<i64> {
    // IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT
    if value.len() == 29
        && &value[3..5] == b", "
        && value[7] == b' '
        && value[11] == b' '
        && value[16] == b' '
        && value[25] == b' '
        && &value[26..] == b"GMT"
    {
        let weekday = weekday_short(&value[..3])?;
        let day = parse_digits(&value[5..7])?;
        let month = month(&value[8..11])?;
        let year = i64::from(parse_digits(&value[12..16])?);
        return timestamp(weekday, year, month, day, &value[17..25]);
    }

    // RFC 850: Sunday, 06-Nov-94 08:49:37 GMT
    if let Some(comma) = value.iter().position(|byte| *byte == b',') {
        let weekday = weekday_long(&value[..comma])?;
        let rest = value.get(comma + 1..)?;
        if rest.len() == 23
            && rest[0] == b' '
            && rest[3] == b'-'
            && rest[7] == b'-'
            && rest[10] == b' '
            && rest[19] == b' '
            && &rest[20..] == b"GMT"
        {
            let day = parse_digits(&rest[1..3])?;
            let month = month(&rest[4..7])?;
            let year = i64::from(parse_digits(&rest[8..10])?);
            let year = year + if year < 70 { 2000 } else { 1900 };
            return timestamp(weekday, year, month, day, &rest[11..19]);
        }
    }

    // asctime: Sun Nov  6 08:49:37 1994
    if value.len() == 24
        && value[3] == b' '
        && value[7] == b' '
        && value[10] == b' '
        && value[19] == b' '
    {
        let weekday = weekday_short(&value[..3])?;
        let month = month(&value[4..7])?;
        let day = if value[8] == b' ' {
            parse_digits(&value[9..10])?
        } else {
            parse_digits(&value[8..10])?
        };
        let year = i64::from(parse_digits(&value[20..])?);
        return timestamp(weekday, year, month, day, &value[11..19]);
    }
    None
}

pub(crate) fn parse_response_status_line(value: &[u8]) -> Option<u16> {
    crate::verified::proxy_response_status_line_parse(value)
}

#[cfg(feature = "fuzzing")]
pub fn fuzz_http_fields(data: &[u8]) {
    let _ = parse_weighted_list(data);
    let _ = parse_entity_tag(data);
    let _ = parse_entity_tag_list(data);
    let _ = parse_cookie(data);
    let _ = parse_http_date(data);
    let _ = parse_response_status_line(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qvalues_are_exact_and_bounded() {
        assert_eq!(parse_qvalue(b"0.125").map(QValue::milli), Some(125));
        assert_eq!(parse_qvalue(b"1.000").map(QValue::milli), Some(1000));
        for invalid in [b"1.001".as_slice(), b"2", b"NaN", b"1e-3", b"0.0000"] {
            assert_eq!(parse_qvalue(invalid), None, "{invalid:?}");
        }
    }

    #[test]
    fn weighted_lists_reject_partial_or_duplicate_quality() {
        let parsed = parse_weighted_list(b"gzip; level=1; q=0.7, br").unwrap();
        assert_eq!(parsed[0].value, b"gzip");
        assert_eq!(parsed[0].quality.milli(), 700);
        assert_eq!(parsed[1].quality, QValue::ONE);
        for invalid in [
            b"gzip;q=2".as_slice(),
            b"gzip;q=0.5;q=0.4",
            b"gzip;broken",
            b"gzip,,br",
            b"gzip;q=0.5 garbage",
        ] {
            assert!(parse_weighted_list(invalid).is_none(), "{invalid:?}");
        }
    }

    #[test]
    fn entity_tag_lists_honor_quoted_commas_and_reject_bad_members() {
        let EntityTagList::Tags(tags) = parse_entity_tag_list(b"\"a,b\", W/\"c\"").unwrap() else {
            panic!("expected tags");
        };
        assert_eq!(tags.len(), 2);
        let EntityTagList::Tags(tags) = parse_entity_tag_list(b"\"a\\\", \"b\"").unwrap() else {
            panic!("expected tags");
        };
        assert_eq!(tags.len(), 2);
        assert!(parse_entity_tag_list(b"\"ok\", garbage").is_none());
        assert!(parse_entity_tag_list(b"W/ \"bad\"").is_none());
    }

    #[test]
    fn cookies_are_complete_and_byte_strict() {
        let pairs = parse_cookie(b"a=1; route=\"node.2\"").unwrap();
        assert_eq!(pairs[1].name, b"route");
        assert_eq!(pairs[1].value, b"node.2");
        assert!(parse_cookie(b"malformed; route=node.2").is_none());
        assert!(parse_cookie(b"bad=\xff; route=node.2").is_none());
    }

    #[test]
    fn dates_require_exact_real_calendar_values() {
        assert_eq!(
            parse_http_date(b"Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert_eq!(
            parse_http_date(b"Sunday, 06-Nov-94 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert_eq!(
            parse_http_date(b"Sun Nov  6 08:49:37 1994"),
            Some(784_111_777)
        );
        for invalid in [
            b" Sun, 06 Nov 1994 08:49:37 GMT".as_slice(),
            b"Sun, 31 Nov 1994 08:49:37 GMT",
            b"Mon, 06 Nov 1994 08:49:37 GMT",
            b"Sun, 6 Nov 1994 08:49:37 GMT",
            b"Sun, 06 Nov 1994 08:49:37 GMT trailing",
        ] {
            assert_eq!(parse_http_date(invalid), None, "{invalid:?}");
        }
    }
}
