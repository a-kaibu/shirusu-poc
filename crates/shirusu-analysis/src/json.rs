//! 最小の JSON ライタ。serde を持ち込まず、キー順は挿入順で決定的に
//! 出力する（ゴールデンテストで出力を固定できることが要件のため）。
//! 解析 CLI 群（shirusu / shirusu-compare / shirusu-test）の JSON 出力は
//! すべてこのモジュールを経由する。

/// JSON 値。オブジェクトは挿入順を保持する。
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    U64(u64),
    I64(i64),
    Str(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    pub fn obj(pairs: Vec<(&str, JsonValue)>) -> Self {
        JsonValue::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    /// インデント付きで出す（人間向け JSON）。構造は `render` と同一。
    pub fn render_pretty(&self) -> String {
        let mut out = String::new();
        self.write_pretty(&mut out, 0);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            JsonValue::Null => out.push_str("null"),
            JsonValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            JsonValue::U64(v) => out.push_str(&v.to_string()),
            JsonValue::I64(v) => out.push_str(&v.to_string()),
            JsonValue::Str(s) => write_json_string(out, s),
            JsonValue::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            JsonValue::Object(pairs) => {
                out.push('{');
                for (i, (k, v)) in pairs.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_json_string(out, k);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }

    fn write_pretty(&self, out: &mut String, depth: usize) {
        match self {
            JsonValue::Array(items) if !items.is_empty() => {
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    push_indent(out, depth + 1);
                    item.write_pretty(out, depth + 1);
                    if i + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                push_indent(out, depth);
                out.push(']');
            }
            JsonValue::Object(pairs) if !pairs.is_empty() => {
                out.push_str("{\n");
                for (i, (k, v)) in pairs.iter().enumerate() {
                    push_indent(out, depth + 1);
                    write_json_string(out, k);
                    out.push_str(": ");
                    v.write_pretty(out, depth + 1);
                    if i + 1 < pairs.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                push_indent(out, depth);
                out.push('}');
            }
            _ => self.write(out),
        }
    }
}

fn push_indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

/// JSON 文字列リテラルとしてエスケープして書き出す。
pub fn write_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_scalars_and_escapes() {
        assert_eq!(JsonValue::Null.render(), "null");
        assert_eq!(JsonValue::Bool(true).render(), "true");
        assert_eq!(JsonValue::U64(42).render(), "42");
        assert_eq!(JsonValue::I64(-3).render(), "-3");
        assert_eq!(
            JsonValue::Str("a\"b\\c\n".into()).render(),
            "\"a\\\"b\\\\c\\n\""
        );
        assert_eq!(JsonValue::Str("\u{1}é".into()).render(), "\"\\u0001é\"");
    }

    #[test]
    fn object_key_order_is_insertion_order() {
        let v = JsonValue::obj(vec![
            ("b", JsonValue::U64(1)),
            ("a", JsonValue::Array(vec![JsonValue::Bool(false)])),
        ]);
        assert_eq!(v.render(), "{\"b\":1,\"a\":[false]}");
    }

    #[test]
    fn pretty_prints_nested() {
        let v = JsonValue::obj(vec![("x", JsonValue::obj(vec![("y", JsonValue::Null)]))]);
        assert_eq!(v.render_pretty(), "{\n  \"x\": {\n    \"y\": null\n  }\n}");
    }
}
