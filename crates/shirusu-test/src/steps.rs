//! JSON 仕様の `steps`（Probe が実行する呼び出し列）の読み書き。
//!
//! 形式（v1、仕様ファイルの `"steps"` 配列の 1 要素）:
//!
//! ```json
//! {"call": "kernel32!CreateFileW",
//!  "args": {"lpFileName": "probe.txt",
//!           "dwDesiredAccess": 3221225472,
//!           "dwShareMode": 0,
//!           "lpSecurityAttributes": null,
//!           "dwCreationDisposition": 2,
//!           "dwFlagsAndAttributes": 128,
//!           "hTemplateFile": null},
//!  "store": "hFile",
//!  "expect": {"return": "nonzero"}}
//! ```
//!
//! 引数の値の形:
//! - 数値 → 整数（U32/U64/Bool/Handle の引数へ）
//! - 文字列 → 文字列リテラル（WideStr/AnsiStr の引数へ。Bytes の引数へは
//!   UTF-8 バイト列として渡す）
//! - `null` → 0（NULL ポインタ・NULL ハンドル）
//! - 真理値 → 1/0（Bool の引数へ）
//! - `{"buffer": N}` → N バイトの 0 埋めバッファ。`"fill_text"` /
//!   `"fill_bytes"` で先頭の内容を指定できる
//! - `{"out": "u32"}` / `{"out": "u64"}` → out スロットへのポインタ
//! - `{"ref": "name"}` → 先行ステップの `store` に保存された戻り値
//!
//! 期待値（`"expect"`）の形:
//! - `"return": "valid-handle" | "nonzero" | "zero" | <数値>`
//! - `"outputs": {"<引数名>": <数値> | "<16 進文字列>"}`（数値は out
//!   スロット、16 進文字列はバッファ内容との前方一致）

use crate::json_parse::{as_str, as_u64, get};
use crate::runner_exec::{hex_to_bytes, ArgValue, Expect, ExpectedOutput, RetExpect, Step};
use shirusu_analysis::JsonValue;

/// 仕様 JSON の `"steps"` を読む。無ければ空列。
pub fn parse_steps(root: &JsonValue) -> Result<Vec<Step>, String> {
    let Some(steps_json) = get(root, "steps") else {
        return Ok(Vec::new());
    };
    let JsonValue::Array(items) = steps_json else {
        return Err("\"steps\" must be an array".to_string());
    };
    let mut steps = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        steps.push(parse_step(item, i)?);
    }
    Ok(steps)
}

/// 許すキーだけからなることを確かめる。未知のキーは誤字のことが多く、
/// 見過ごすと仕様の意図と実行がずれるため、ここで弾く。
fn check_keys(value: &JsonValue, allowed: &[&str]) -> Result<(), String> {
    let JsonValue::Object(pairs) = value else {
        return Err("expected a JSON object".to_string());
    };
    for (key, _) in pairs {
        if !allowed.contains(&key.as_str()) {
            return Err(format!(
                "unknown key {key:?} (allowed: {})",
                allowed.join(", ")
            ));
        }
    }
    Ok(())
}

fn parse_step(item: &JsonValue, i: usize) -> Result<Step, String> {
    check_keys(item, &["call", "args", "store", "expect"])
        .map_err(|e| format!("steps[{i}]: {e}"))?;
    let call = get(item, "call")
        .and_then(as_str)
        .ok_or_else(|| format!("steps[{i}]: step needs \"call\""))?
        .to_string();
    let mut args = Vec::new();
    if let Some(args_json) = get(item, "args") {
        let JsonValue::Object(pairs) = args_json else {
            return Err(format!("steps[{i}]: \"args\" must be an object"));
        };
        for (name, value) in pairs {
            let parsed =
                parse_arg_value(value).map_err(|e| format!("steps[{i}] arg {name:?}: {e}"))?;
            args.push((name.clone(), parsed));
        }
    }
    let store = match get(item, "store") {
        None => None,
        Some(v) => Some(
            as_str(v)
                .ok_or_else(|| format!("steps[{i}]: \"store\" must be a string"))?
                .to_string(),
        ),
    };
    let expect = match get(item, "expect") {
        None => None,
        Some(v) => Some(parse_expect(v).map_err(|e| format!("steps[{i}]: {e}"))?),
    };
    Ok(Step {
        call,
        args,
        store,
        expect,
    })
}

fn parse_arg_value(value: &JsonValue) -> Result<ArgValue, String> {
    match value {
        JsonValue::U64(n) => Ok(ArgValue::Int(*n)),
        JsonValue::I64(n) if *n >= 0 => Ok(ArgValue::Int(*n as u64)),
        JsonValue::Str(s) => Ok(ArgValue::Text(s.clone())),
        JsonValue::Null => Ok(ArgValue::Null),
        JsonValue::Bool(b) => Ok(ArgValue::Bool(*b)),
        JsonValue::Object(_) => parse_arg_object(value),
        JsonValue::Array(_) => Err("array is not a valid argument value".to_string()),
        JsonValue::I64(_) => Err("negative number is not a valid argument value".to_string()),
    }
}

fn parse_arg_object(value: &JsonValue) -> Result<ArgValue, String> {
    if get(value, "buffer").is_some() {
        check_keys(value, &["buffer", "fill_text", "fill_bytes"])?;
        let size = get(value, "buffer")
            .and_then(as_u64)
            .ok_or_else(|| "\"buffer\" needs a non-negative integer".to_string())?
            as usize;
        let fill_text = get(value, "fill_text").and_then(as_str);
        let fill_bytes = get(value, "fill_bytes");
        if fill_text.is_some() && fill_bytes.is_some() {
            return Err("\"fill_text\" and \"fill_bytes\" are exclusive".to_string());
        }
        let mut fill = Vec::new();
        if let Some(text) = fill_text {
            fill = text.as_bytes().to_vec();
        }
        if let Some(bytes_json) = fill_bytes {
            let JsonValue::Array(items) = bytes_json else {
                return Err("\"fill_bytes\" must be an array of numbers".to_string());
            };
            for item in items {
                let b = as_u64(item)
                    .filter(|n| *n <= 255)
                    .ok_or_else(|| "\"fill_bytes\" entries must be 0..=255".to_string())?;
                fill.push(b as u8);
            }
        }
        return Ok(ArgValue::Buffer { size, fill });
    }
    if let Some(out) = get(value, "out") {
        check_keys(value, &["out"])?;
        return match as_str(out) {
            Some("u32") => Ok(ArgValue::OutU32),
            Some("u64") => Ok(ArgValue::OutU64),
            _ => Err("\"out\" must be \"u32\" or \"u64\"".to_string()),
        };
    }
    if let Some(name) = get(value, "ref") {
        check_keys(value, &["ref"])?;
        let name = as_str(name).ok_or_else(|| "\"ref\" needs a string".to_string())?;
        if name.is_empty() {
            return Err("\"ref\" must not be empty".to_string());
        }
        return Ok(ArgValue::Ref(name.to_string()));
    }
    Err("argument object must have one of \"buffer\", \"out\", \"ref\"".to_string())
}

fn parse_expect(value: &JsonValue) -> Result<Expect, String> {
    check_keys(value, &["return", "outputs"])?;
    let mut expect = Expect::default();
    if let Some(ret) = get(value, "return") {
        expect.ret = Some(match ret {
            JsonValue::Str(s) if s == "valid-handle" => RetExpect::ValidHandle,
            JsonValue::Str(s) if s == "nonzero" => RetExpect::NonZero,
            JsonValue::Str(s) if s == "zero" => RetExpect::Zero,
            JsonValue::U64(n) => RetExpect::Equals(*n),
            JsonValue::I64(n) if *n >= 0 => RetExpect::Equals(*n as u64),
            _ => {
                return Err(
                    "expect.return must be \"valid-handle\", \"nonzero\", \"zero\", or a number"
                        .to_string(),
                );
            }
        });
    }
    if let Some(outputs) = get(value, "outputs") {
        let JsonValue::Object(pairs) = outputs else {
            return Err("expect.outputs must be an object".to_string());
        };
        for (name, val) in pairs {
            let expected = match val {
                JsonValue::U64(n) => ExpectedOutput::U64(*n),
                JsonValue::I64(n) if *n >= 0 => ExpectedOutput::U64(*n as u64),
                JsonValue::Str(s) => {
                    if hex_to_bytes(s).is_none() {
                        return Err(format!("expect.outputs {name:?} hex string is invalid"));
                    }
                    ExpectedOutput::HexPrefix(s.to_ascii_lowercase())
                }
                _ => {
                    return Err(format!(
                        "expect.outputs {name:?} must be a number or a hex string"
                    ));
                }
            };
            expect.outputs.push((name.clone(), expected));
        }
    }
    if expect.ret.is_none() && expect.outputs.is_empty() {
        return Err("expect must not be empty".to_string());
    }
    Ok(expect)
}

/// ステップ列を JSON に戻す（`TestSpec::to_json` 用）。`parse_steps` と
/// 往復できることがテストで保証される。
pub fn steps_to_json(steps: &[Step]) -> JsonValue {
    JsonValue::Array(steps.iter().map(step_to_json).collect())
}

fn step_to_json(step: &Step) -> JsonValue {
    let mut pairs: Vec<(&str, JsonValue)> = vec![("call", JsonValue::Str(step.call.clone()))];
    if !step.args.is_empty() {
        pairs.push((
            "args",
            JsonValue::Object(
                step.args
                    .iter()
                    .map(|(n, v)| (n.clone(), arg_value_to_json(v)))
                    .collect(),
            ),
        ));
    }
    if let Some(store) = &step.store {
        pairs.push(("store", JsonValue::Str(store.clone())));
    }
    if let Some(expect) = &step.expect {
        pairs.push(("expect", expect_to_json(expect)));
    }
    JsonValue::obj(pairs)
}

fn arg_value_to_json(value: &ArgValue) -> JsonValue {
    match value {
        ArgValue::Int(n) => JsonValue::U64(*n),
        ArgValue::Ref(name) => JsonValue::obj(vec![("ref", JsonValue::Str(name.clone()))]),
        ArgValue::Text(s) => JsonValue::Str(s.clone()),
        ArgValue::Null => JsonValue::Null,
        ArgValue::Bool(b) => JsonValue::Bool(*b),
        ArgValue::Buffer { size, fill } => {
            let mut pairs: Vec<(&str, JsonValue)> = vec![("buffer", JsonValue::U64(*size as u64))];
            if !fill.is_empty() {
                pairs.push((
                    "fill_bytes",
                    JsonValue::Array(fill.iter().map(|b| JsonValue::U64(*b as u64)).collect()),
                ));
            }
            JsonValue::obj(pairs)
        }
        ArgValue::OutU32 => JsonValue::obj(vec![("out", JsonValue::Str("u32".into()))]),
        ArgValue::OutU64 => JsonValue::obj(vec![("out", JsonValue::Str("u64".into()))]),
    }
}

fn expect_to_json(expect: &Expect) -> JsonValue {
    let mut pairs: Vec<(&str, JsonValue)> = Vec::new();
    if let Some(ret) = expect.ret {
        pairs.push((
            "return",
            match ret {
                RetExpect::ValidHandle => JsonValue::Str("valid-handle".into()),
                RetExpect::NonZero => JsonValue::Str("nonzero".into()),
                RetExpect::Zero => JsonValue::Str("zero".into()),
                RetExpect::Equals(n) => JsonValue::U64(n),
            },
        ));
    }
    if !expect.outputs.is_empty() {
        pairs.push((
            "outputs",
            JsonValue::Object(
                expect
                    .outputs
                    .iter()
                    .map(|(n, v)| {
                        (
                            n.clone(),
                            match v {
                                ExpectedOutput::U64(n) => JsonValue::U64(*n),
                                ExpectedOutput::HexPrefix(h) => JsonValue::Str(h.clone()),
                            },
                        )
                    })
                    .collect(),
            ),
        ));
    }
    JsonValue::obj(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json_parse::parse_json;
    use crate::runner_exec::plan_steps;

    const SPEC_JSON: &str = r#"{"version":1,"name":"sample","steps":[
        {"call":"kernel32!CreateFileW","args":{"lpFileName":"probe.txt","dwDesiredAccess":3221225472,"dwShareMode":0,"lpSecurityAttributes":null,"dwCreationDisposition":2,"dwFlagsAndAttributes":128,"hTemplateFile":null},"store":"hFile","expect":{"return":"nonzero"}},
        {"call":"kernel32!WriteFile","args":{"hFile":{"ref":"hFile"},"lpBuffer":{"buffer":5,"fill_text":"hello"},"nNumberOfBytesToWrite":5,"lpNumberOfBytesWritten":{"out":"u32"},"lpOverlapped":null},"expect":{"return":"nonzero","outputs":{"lpNumberOfBytesWritten":5}}},
        {"call":"kernel32!CloseHandle","args":{"hObject":{"ref":"hFile"}}}
    ],"rules":[]}"#;

    fn parse_spec_steps(json: &str) -> Result<Vec<Step>, String> {
        parse_steps(&parse_json(json)?)
    }

    #[test]
    fn parses_steps() {
        let steps = parse_spec_steps(SPEC_JSON).unwrap();
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].call, "kernel32!CreateFileW");
        assert_eq!(steps[0].store.as_deref(), Some("hFile"));
        assert_eq!(
            steps[0].expect.as_ref().unwrap().ret,
            Some(RetExpect::NonZero)
        );
        assert_eq!(steps[1].args[0].1, ArgValue::Ref("hFile".to_string()));
        assert_eq!(
            steps[1].args[1].1,
            ArgValue::Buffer {
                size: 5,
                fill: b"hello".to_vec()
            }
        );
        assert_eq!(steps[1].args[3].1, ArgValue::OutU32);
        assert_eq!(
            steps[1].expect.as_ref().unwrap().outputs,
            vec![("lpNumberOfBytesWritten".to_string(), ExpectedOutput::U64(5))]
        );
        // 計画まで通ること（Runner と生成 exe の共通の入口）。
        assert_eq!(plan_steps(&steps).unwrap().len(), 3);
    }

    #[test]
    fn steps_roundtrip_through_json() {
        let steps = parse_spec_steps(SPEC_JSON).unwrap();
        let rendered = steps_to_json(&steps);
        let reparsed = parse_steps(&JsonValue::obj(vec![("steps", rendered)])).unwrap();
        assert_eq!(reparsed, steps);
    }

    #[test]
    fn rejects_bad_steps() {
        // steps が配列でない。
        assert!(parse_steps(&parse_json(r#"{"steps":{}}"#).unwrap()).is_err());
        // call が無い。
        assert!(parse_spec_steps(r#"{"steps":[{"args":{}}]}"#).is_err());
        // 未知のキー。
        assert!(parse_spec_steps(
            r#"{"steps":[{"call":"kernel32!Sleep","args":{"dwMilliseconds":0},"zzz":1}]}"#
        )
        .is_err());
        // args がオブジェクトでない。
        assert!(parse_spec_steps(r#"{"steps":[{"call":"kernel32!Sleep","args":[]}]}"#).is_err());
        // buffer の fill が両方。
        assert!(parse_spec_steps(r#"{"steps":[{"call":"kernel32!ReadFile","args":{"hFile":0,"lpBuffer":{"buffer":4,"fill_text":"ab","fill_bytes":[1]},"nNumberOfBytesToRead":4,"lpNumberOfBytesRead":{"out":"u32"},"lpOverlapped":null}}]}"#).is_err());
        // out の値が不正。
        assert!(parse_spec_steps(r#"{"steps":[{"call":"kernel32!ReadFile","args":{"hFile":0,"lpBuffer":{"buffer":4},"nNumberOfBytesToRead":4,"lpNumberOfBytesRead":{"out":"u16"},"lpOverlapped":null}}]}"#).is_err());
        // ref が空。
        assert!(parse_spec_steps(
            r#"{"steps":[{"call":"kernel32!CloseHandle","args":{"hObject":{"ref":""}}}]}"#
        )
        .is_err());
        // 引数の値が配列。
        assert!(parse_spec_steps(
            r#"{"steps":[{"call":"kernel32!Sleep","args":{"dwMilliseconds":[1]}}]}"#
        )
        .is_err());
        // 負の数。
        assert!(parse_spec_steps(
            r#"{"steps":[{"call":"kernel32!Sleep","args":{"dwMilliseconds":-1}}]}"#
        )
        .is_err());
        // expect が空。
        assert!(parse_spec_steps(
            r#"{"steps":[{"call":"kernel32!Sleep","args":{"dwMilliseconds":0},"expect":{}}]}"#
        )
        .is_err());
        // expect.return が不正。
        assert!(parse_spec_steps(r#"{"steps":[{"call":"kernel32!Sleep","args":{"dwMilliseconds":0},"expect":{"return":"maybe"}}]}"#).is_err());
        // expect.outputs の 16 進文字列が不正。
        assert!(parse_spec_steps(r#"{"steps":[{"call":"kernel32!ReadFile","args":{"hFile":0,"lpBuffer":{"buffer":4},"nNumberOfBytesToRead":4,"lpNumberOfBytesRead":{"out":"u32"},"lpOverlapped":null},"expect":{"outputs":{"lpBuffer":"zz"}}}]}"#).is_err());
        // 引数オブジェクトの形が不正。
        assert!(parse_spec_steps(
            r#"{"steps":[{"call":"kernel32!Sleep","args":{"dwMilliseconds":{"zzz":1}}}]}"#
        )
        .is_err());
    }
}
