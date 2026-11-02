//! Pure configuration front-end.
//!
//! This module is deliberately free of filesystem access, include expansion,
//! section-context semantics and directive dispatch.  It is the target for
//! the parser-refinement proof: bytes in, a small token/line IR out.  The
//! tokenizer and section-tag scanner consume verified executable state
//! machines.  Main configuration and `.htaccess` then seal the resulting
//! lines into immutable programs with exact section mates before applying any
//! policy effect.  Directive payload parsers remain the next refinement
//! boundary.

/// One logical configuration line after backslash continuation handling, with
/// the source line number where the logical line started.
pub fn logical_lines_with_numbers(text: &str) -> Vec<(usize, String)> {
    let mut logical: Vec<(usize, String)> = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    for (idx, raw_line) in text.lines().enumerate() {
        let lineno = idx + 1;
        let mut line = raw_line.trim_end_matches('\r').to_string();
        let continued = line.trim_end().ends_with('\\');
        if continued {
            line = line.trim_end().trim_end_matches('\\').to_string();
        }
        match &mut pending {
            Some((start, buf)) => {
                buf.push(' ');
                buf.push_str(line.trim_start());
                if !continued {
                    let (s, b) = pending.take().unwrap();
                    logical.push((s, b));
                } else {
                    let _ = start;
                }
            }
            None => {
                if continued {
                    pending = Some((lineno, line));
                } else {
                    logical.push((lineno, line));
                }
            }
        }
    }
    if let Some((s, b)) = pending {
        logical.push((s, b));
    }
    logical
}

/// Logical-line helper used by the `.htaccess` parser.  Comments and blank
/// lines are dropped here because the access-file parser has no source-line
/// diagnostics for skipped lines.
pub fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for raw in text.lines() {
        let line = raw.trim_end_matches('\r');
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if cur.is_empty() && trimmed.is_empty() {
            continue;
        }
        let continuation = line.ends_with('\\');
        if continuation {
            cur.push_str(&line[..line.len() - 1]);
        } else {
            cur.push_str(line);
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// Split one logical line into Apache-style arguments.  Quoted arguments may
/// contain whitespace; backslash escapes the active quote character or, outside
/// quotes, whitespace.  Other backslashes stay literal so regexes such as
/// `"^\.[Hh][Tt]"` survive tokenization.
pub(crate) fn tokenize(s: &str) -> Result<Vec<String>, String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut current: Option<Vec<u8>> = None;
    let mut state = vapache_verified::ConfigLexState::Between;
    let mut i = 0;
    while i < b.len() {
        let next = b.get(i + 1).copied();
        let step = vapache_verified::config_lex_step(state, b[i], next);
        state = step.state;
        match step.action {
            vapache_verified::ConfigLexAction::Skip => {}
            vapache_verified::ConfigLexAction::Begin => {
                debug_assert!(current.is_none());
                current = Some(Vec::new());
            }
            vapache_verified::ConfigLexAction::Push => {
                current
                    .as_mut()
                    .expect("verified lexer pushes only inside a token")
                    .push(b[i]);
            }
            vapache_verified::ConfigLexAction::PushNext => {
                current
                    .as_mut()
                    .expect("verified lexer escapes only inside a token")
                    .push(next.expect("verified two-byte transition requires a next byte"));
            }
            vapache_verified::ConfigLexAction::Finish => {
                finish_token(&mut out, &mut current)?;
            }
            vapache_verified::ConfigLexAction::CloseQuote => {}
            vapache_verified::ConfigLexAction::RejectAfterQuote => {
                return Err("characters after closing quote".into());
            }
        }
        i += usize::from(step.advance);
    }
    match vapache_verified::config_lex_eof(state) {
        vapache_verified::ConfigLexEof::Complete => {}
        vapache_verified::ConfigLexEof::Finish => finish_token(&mut out, &mut current)?,
        vapache_verified::ConfigLexEof::UnterminatedQuote => {
            return Err("unterminated quoted string".into());
        }
    }
    Ok(out)
}

fn finish_token(out: &mut Vec<String>, current: &mut Option<Vec<u8>>) -> Result<(), String> {
    let Some(next_count) = vapache_verified::config_argument_count_step(out.len()) else {
        return Err("too many arguments".into());
    };
    let bytes = current
        .take()
        .expect("verified lexer finishes only after beginning a token");
    let token = String::from_utf8(bytes)
        .map_err(|_| "configuration token is not valid UTF-8".to_string())?;
    out.push(token);
    debug_assert_eq!(out.len(), next_count);
    Ok(())
}

/// Tokenize one logical line, treating section tags as a single leading
/// token (`<Directory`, `</Directory>`) followed by their arguments.
pub(crate) fn tokenize_config(s: &str) -> Result<Vec<String>, String> {
    let t = s.trim();
    if t.starts_with("</") {
        let end = t.find('>').ok_or("unterminated closing section tag")?;
        if !t[end + 1..].trim().is_empty() {
            return Err("characters after closing section tag".into());
        }
        return Ok(vec![t[..=end].to_string()]);
    }
    if t.starts_with('<') {
        let b = t.as_bytes();
        let mut quote = vapache_verified::ConfigTagQuote::Unquoted;
        let mut end = None;
        let mut i = 1;
        while i < b.len() {
            let step = vapache_verified::config_tag_step(quote, b[i], b.get(i + 1).copied());
            quote = step.quote;
            if step.delimiter {
                // Apache permits an unquoted comparison operator in
                // `<IfVersion >= 2.4>`. The closing delimiter is therefore
                // the last unquoted `>`, not necessarily the first one.
                end = Some(i);
            }
            i += usize::from(step.advance);
        }
        let end = end.ok_or("unterminated section tag")?;
        if !t[end + 1..].trim().is_empty() {
            return Err("characters after section tag".into());
        }
        let inner = &t[1..end];
        let mut toks = tokenize(inner)?;
        if toks.is_empty() {
            return Err("empty section tag".into());
        }
        let first = format!("<{}", toks.remove(0));
        let mut out = vec![first];
        out.extend(toks);
        return Ok(out);
    }
    tokenize(t)
}

/// Pure line IR.  This carries no directive semantics and no source file; the
/// caller attaches `SourceLoc` and performs context/include/active evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigLine {
    Directive { name: String, args: Vec<String> },
    SectionStart { name: String, args: Vec<String> },
    SectionEnd { name: String },
}

impl ConfigLine {
    pub fn name(&self) -> &str {
        match self {
            ConfigLine::Directive { name, .. }
            | ConfigLine::SectionStart { name, .. }
            | ConfigLine::SectionEnd { name } => name,
        }
    }
}

/// Parse one logical line into the pure IR.  Syntax errors are returned as
/// strings so the existing compiler can attach file/line diagnostics.
pub fn parse_line(text: &str) -> Result<ConfigLine, String> {
    let tokens = tokenize_config(text)?;
    if tokens.is_empty() {
        return Err("empty configuration line".into());
    }
    let kind =
        vapache_verified::config_line_kind(tokens[0].starts_with("</"), tokens[0].starts_with('<'));
    match kind {
        vapache_verified::ConfigLineKind::SectionEnd => {
            let name = tokens[0]
                .trim_start_matches("</")
                .trim_end_matches('>')
                .trim()
                .to_ascii_lowercase();
            if name.is_empty() {
                return Err("empty closing section name".into());
            }
            Ok(ConfigLine::SectionEnd { name })
        }
        vapache_verified::ConfigLineKind::SectionStart => {
            let name = tokens[0]
                .trim_start_matches('<')
                .trim_end_matches('>')
                .trim()
                .to_ascii_lowercase();
            if name.is_empty() {
                return Err("empty section name".into()); // coverage:ignore-line - tokenizer rejects `<>` first
            }
            Ok(ConfigLine::SectionStart {
                name,
                args: tokens[1..].to_vec(),
            })
        }
        vapache_verified::ConfigLineKind::Directive => Ok(ConfigLine::Directive {
            name: tokens[0].to_ascii_lowercase(),
            args: tokens[1..].to_vec(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizes_quotes_and_escaped_whitespace() {
        assert_eq!(tokenize("a \"b c\" d").unwrap(), vec!["a", "b c", "d"]);
        assert_eq!(tokenize("a\\ b").unwrap(), vec!["a b"]);
        assert_eq!(tokenize("\"^\\.ht\"").unwrap(), vec!["^\\.ht"]);
        assert_eq!(tokenize("\"a \\\"b\\\"\"").unwrap(), vec!["a \"b\""]);
        assert!(tokenize("\"unterminated").is_err());
        assert_eq!(
            tokenize_config("<IfVersion >= 2.4>").unwrap(),
            vec!["<IfVersion", ">=", "2.4"]
        );
        assert_eq!(tokenize("'' \"\"").unwrap(), vec!["", ""]);
        assert_eq!(tokenize("café 'δ value'").unwrap(), vec!["café", "δ value"]);
        assert_eq!(
            tokenize_config(r#"<Directory "a \"> b">"#).unwrap(),
            vec!["<Directory", "a \"> b"]
        );
    }

    #[test]
    fn frontend_error_and_continuation_edges() {
        assert_eq!(
            logical_lines_with_numbers(concat!("one \\", "\n  two \\", "\n three\nfour \\")),
            vec![(1, "one  two  three".into()), (4, "four ".into())]
        );
        assert_eq!(logical_lines("value\\"), vec!["value"]);
        assert!(tokenize("\"closed\"suffix").is_err());
        let too_many = std::iter::repeat_n("x", 257).collect::<Vec<_>>().join(" ");
        assert!(tokenize(&too_many).is_err());
        let maximum = std::iter::repeat_n("x", 256).collect::<Vec<_>>().join(" ");
        assert_eq!(tokenize(&maximum).unwrap().len(), 256);
        assert!(tokenize_config("</Directory> trailing").is_err());
        assert!(tokenize_config("<Directory> trailing").is_err());
        assert!(tokenize_config("<>").is_err());
        assert!(parse_line("</>").is_err());
        assert!(parse_line("").is_err());

        let directive = parse_line("Require all granted").unwrap();
        let start = parse_line("<Directory /srv>").unwrap();
        let end = parse_line("</Directory>").unwrap();
        assert_eq!(directive.name(), "require");
        assert_eq!(start.name(), "directory");
        assert_eq!(end.name(), "directory");
    }

    #[test]
    fn parses_directive_and_section_ir() {
        assert_eq!(
            parse_line("Require all granted").unwrap(),
            ConfigLine::Directive {
                name: "require".into(),
                args: vec!["all".into(), "granted".into()]
            }
        );
        assert_eq!(
            parse_line("<Directory \"/srv/a b\">").unwrap(),
            ConfigLine::SectionStart {
                name: "directory".into(),
                args: vec!["/srv/a b".into()]
            }
        );
        assert_eq!(
            parse_line("</Directory>").unwrap(),
            ConfigLine::SectionEnd {
                name: "directory".into()
            }
        );
        assert!(parse_line("").is_err());
        assert!(parse_line("<Directory").is_err());
    }

    #[test]
    fn logical_lines_keep_config_line_numbers() {
        let lines = logical_lines_with_numbers("# comment\nRequire all \\\n granted\n");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].0, 1);
        assert_eq!(lines[0].1, "# comment");
        assert_eq!(lines[1].0, 2);
        assert_eq!(lines[1].1, "Require all  granted");
    }

    #[test]
    fn logical_lines_skip_htaccess_comments() {
        let lines = logical_lines("# hi\nRequire all \\\n denied\n\nOptions -Indexes\n");
        assert_eq!(lines, vec!["Require all  denied", "Options -Indexes"]);
    }
}
