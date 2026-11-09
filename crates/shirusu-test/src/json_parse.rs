//! 最小 JSON パーサ（shirusu-test の仕様ファイル用）。
//!
//! overview の決定「テストは言語に依存しない JSON 仕様を正規形式に
//! する」に従い、期待ルールは JSON で書く。serde を持ち込まず、
//! 仕様で必要な範囲（オブジェクト/配列/文字列/整数/真偽/null）に
//! 絞った決定的なパーサを自前で持つ。小数は v1 では扱わない
//! （浮動小数点の引数は形式側でもビット列で保持されており、
//! ルールでの数値比較の対象にしない）。

use shirusu_analysis::JsonValue;

/// パースする。エラーは「何バイト目で何が起きたか」を返す。
pub fn parse_json(input: &str) -> Result<JsonValue, String> {
    let mut p = Parser {
        bytes: input.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    let value = p.value()?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(format!("trailing characters at byte {}", p.pos));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos) {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn value(&mut self) -> Result<JsonValue, String> {
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(JsonValue::Str(self.string()?)),
            Some(b't') => self.literal("true", JsonValue::Bool(true)),
            Some(b'f') => self.literal("false", JsonValue::Bool(false)),
            Some(b'n') => self.literal("null", JsonValue::Null),
            Some(b'-') | Some(b'0'..=b'9') => self.number(),
            Some(other) => Err(format!(
                "unexpected character {:?} at byte {}",
                other as char, self.pos
            )),
            None => Err("unexpected end of input".to_string()),
        }
    }

    fn literal(&mut self, text: &str, value: JsonValue) -> Result<JsonValue, String> {
        if self.bytes[self.pos..].starts_with(text.as_bytes()) {
            self.pos += text.len();
            Ok(value)
        } else {
            Err(format!("invalid literal at byte {}", self.pos))
        }
    }

    fn number(&mut self) -> Result<JsonValue, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits_start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.pos == digits_start {
            return Err(format!("invalid number at byte {start}"));
        }
        if matches!(self.peek(), Some(b'.') | Some(b'e') | Some(b'E')) {
            return Err(format!(
                "non-integer numbers are not supported in spec v1 (byte {start})"
            ));
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos]).unwrap();
        if text.starts_with('-') {
            text.parse::<i64>()
                .map(JsonValue::I64)
                .map_err(|_| format!("integer out of range at byte {start}"))
        } else {
            text.parse::<u64>()
                .map(JsonValue::U64)
                .map_err(|_| format!("integer out of range at byte {start}"))
        }
    }

    fn string(&mut self) -> Result<String, String> {
        // 前提: 現在位置が '"'。
        self.pos += 1;
        let mut out = String::new();
        loop {
            let b = self
                .peek()
                .ok_or_else(|| "unterminated string".to_string())?;
            match b {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let esc = self
                        .peek()
                        .ok_or_else(|| "unterminated escape".to_string())?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let cp = self.hex4()?;
                            if (0xD800..0xDC00).contains(&cp) {
                                // サロゲートペア。
                                if self.peek() == Some(b'\\') {
                                    self.pos += 1;
                                    if self.peek() == Some(b'u') {
                                        self.pos += 1;
                                        let lo = self.hex4()?;
                                        if (0xDC00..0xE000).contains(&lo) {
                                            let c =
                                                0x1_0000 + (((cp - 0xD800) << 10) | (lo - 0xDC00));
                                            out.push(char::from_u32(c).unwrap_or('\u{FFFD}'));
                                            continue;
                                        }
                                    }
                                }
                                out.push('\u{FFFD}');
                            } else if (0xDC00..0xE000).contains(&cp) {
                                out.push('\u{FFFD}');
                            } else {
                                out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                            }
                        }
                        _ => return Err(format!("invalid escape at byte {}", self.pos - 1)),
                    }
                }
                0x00..=0x1F => {
                    return Err(format!("unescaped control character at byte {}", self.pos))
                }
                _ => {
                    // UTF-8 の継続バイトも含め、文字単位で取り込む。
                    let s = std::str::from_utf8(&self.bytes[self.pos..])
                        .map_err(|_| format!("invalid UTF-8 at byte {}", self.pos))?;
                    let ch = s.chars().next().unwrap();
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        if self.pos + 4 > self.bytes.len() {
            return Err("truncated \\u escape".to_string());
        }
        let text = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
            .map_err(|_| "invalid \\u escape".to_string())?;
        let value = u32::from_str_radix(text, 16)
            .map_err(|_| format!("invalid \\u escape at byte {}", self.pos))?;
        self.pos += 4;
        Ok(value)
    }

    fn object(&mut self) -> Result<JsonValue, String> {
        self.pos += 1; // '{'
        let mut pairs = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(pairs));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(format!("expected object key at byte {}", self.pos));
            }
            let key = self.string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(format!("expected ':' at byte {}", self.pos));
            }
            self.pos += 1;
            self.skip_ws();
            let value = self.value()?;
            pairs.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(pairs));
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.pos)),
            }
        }
    }

    fn array(&mut self) -> Result<JsonValue, String> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonValue::Array(items));
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.pos)),
            }
        }
    }
}

/// JsonValue のオブジェクトからキーで引く小さなヘルパ。
pub fn get<'a>(value: &'a JsonValue, key: &str) -> Option<&'a JsonValue> {
    match value {
        JsonValue::Object(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

pub fn as_str(value: &JsonValue) -> Option<&str> {
    match value {
        JsonValue::Str(s) => Some(s),
        _ => None,
    }
}

pub fn as_u64(value: &JsonValue) -> Option<u64> {
    match value {
        JsonValue::U64(v) => Some(*v),
        JsonValue::I64(v) if *v >= 0 => Some(*v as u64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_structures() {
        let v = parse_json(r#"{"a":[1,-2,true,null,"x"],"b":{"c":{}}}"#).unwrap();
        assert_eq!(
            v,
            JsonValue::obj(vec![
                (
                    "a",
                    JsonValue::Array(vec![
                        JsonValue::U64(1),
                        JsonValue::I64(-2),
                        JsonValue::Bool(true),
                        JsonValue::Null,
                        JsonValue::Str("x".into()),
                    ]),
                ),
                ("b", JsonValue::obj(vec![("c", JsonValue::obj(vec![]))])),
            ])
        );
    }

    #[test]
    fn parses_escapes_and_surrogates() {
        let v = parse_json(r#""a\nbé\ud83d\ude00""#).unwrap();
        assert_eq!(v, JsonValue::Str("a\nbé😀".into()));
    }

    #[test]
    fn rejects_floats_and_garbage() {
        assert!(parse_json("1.5").is_err());
        assert!(parse_json("[1,]").is_err());
        assert!(parse_json("{} extra").is_err());
        assert!(parse_json("").is_err());
        assert!(parse_json("18446744073709551616").is_err());
    }

    #[test]
    fn hex_u64_max_is_accepted() {
        assert_eq!(
            parse_json("18446744073709551615").unwrap(),
            JsonValue::U64(u64::MAX)
        );
    }
}
