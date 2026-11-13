//! Versioned, handwritten semantic additions to WinMD. These contracts describe
//! Trace fields, bounded capture operations and LastError validity. Raw memory
//! access remains behind the audited MemoryReader primitives.
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Contracts {
    version: u32,
    max_buffer_bytes: u32,
    max_string_units: u32,
    api: Vec<Api>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Api {
    id: u32,
    module: String,
    function: String,
    level: u8,
    note: String,
    last_error: String,
    enter_arguments: Vec<String>,
    leave_arguments: Vec<String>,
    enter: Vec<Field>,
    leave: Vec<Field>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Field {
    name: String,
    ty: String,
    kind: String,
    capture: CaptureOp,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum CaptureOp {
    Scalar {
        arg: usize,
    },
    Utf16 {
        arg: usize,
    },
    InputBuffer {
        address: usize,
        length: usize,
    },
    OutputCount {
        address: usize,
        asynchronous: usize,
    },
    OutputBuffer {
        address: usize,
        capacity: usize,
        count_field: usize,
        success: usize,
        asynchronous: usize,
    },
    LastError {
        arg: usize,
        returns: usize,
    },
    LastErrorWithInput {
        arg: usize,
        returns: usize,
        input: usize,
        meaningful_values: Vec<u32>,
    },
}

/// Emit the first four stable ApiDefs. Reject unknown vocabulary instead of
/// interpolating untrusted expressions into generated Rust source.
pub fn emit_file_io_contracts(source: &str) -> Result<String, String> {
    let contracts: Contracts = toml::from_str(source).map_err(|e| e.to_string())?;
    if contracts.version != 3 || contracts.api.len() != 4 {
        return Err("expected version 3 and exactly four file I/O contracts".into());
    }
    if !(1..=1_048_576).contains(&contracts.max_buffer_bytes)
        || !(1..=1_048_576).contains(&contracts.max_string_units)
    {
        return Err("capture limits must be between 1 and 1048576".into());
    }
    let names = ["CreateFileW", "ReadFile", "WriteFile", "CloseHandle"];
    let mut out = String::from("// Generated from file-io-contracts.toml; do not edit.\nconst FILE_IO_API_TABLE: &[ApiDef] = &[\n");
    for (i, api) in contracts.api.iter().enumerate() {
        if api.id != i as u32 + 1 || api.function != names[i] || api.module != "kernel32.dll" {
            return Err("file I/O API identities and order are immutable".into());
        }
        if !(1..=2).contains(&api.level) || api.note.is_empty() {
            return Err(format!("{}: invalid observation level/note", api.function));
        }
        if !matches!(
            api.last_error.as_str(),
            "DependsOnInputs" | "WhenReturnIsFalse"
        ) {
            return Err(format!("{}: unsupported LastError rule", api.function));
        }
        capture_function(api, false)?;
        capture_function(api, true)?;
        out.push_str(&format!("    ApiDef {{\n        api_id: {},\n        module: {:?},\n        function: {:?},\n        level: {},\n        level_note: {:?},\n", api.id, api.module, api.function, api.level, api.note));
        for (phase, timing, fields) in [
            ("enter", "Before", &api.enter),
            ("leave", "After", &api.leave),
        ] {
            if fields.is_empty() {
                return Err(format!("{}: empty {phase}", api.function));
            }
            let mut seen = HashSet::new();
            out.push_str(&format!("        {phase}_fields: &[\n"));
            for f in fields {
                if f.name.is_empty()
                    || !seen.insert(&f.name)
                    || !matches!(f.ty.as_str(), "U64" | "U32" | "I32" | "Str16" | "Bytes")
                    || !matches!(
                        f.kind.as_str(),
                        "Scalar" | "Pointer" | "Handle" | "CreatedObject"
                    )
                {
                    return Err(format!(
                        "{}: invalid/duplicate {phase} field {}",
                        api.function, f.name
                    ));
                }
                if f.kind != "Scalar" && f.ty != "U64" {
                    return Err(format!("{}: object/pointer fields must use U64", f.name));
                }
                out.push_str(&format!(
                    "            ({:?}, Ty::{}, ValueKind::{}, CaptureTiming::{timing}),\n",
                    f.name, f.ty, f.kind
                ));
            }
            out.push_str("        ],\n");
        }
        let ret = &api.leave[0];
        let error = api.leave.last().unwrap();
        if ret.name != "return"
            || ret.ty != if i == 0 { "U64" } else { "I32" }
            || error.name != "last_error"
            || error.ty != "U32"
            || error.kind != "Scalar"
            || api.last_error
                != if i == 0 {
                    "DependsOnInputs"
                } else {
                    "WhenReturnIsFalse"
                }
        {
            return Err(format!(
                "{}: incompatible return/LastError contract",
                api.function
            ));
        }
        out.push_str(&format!(
            "        last_error_meaning: LastErrorMeaning::{},\n    }},\n",
            api.last_error
        ));
    }
    out.push_str("];\n");
    Ok(out)
}

/// Generate bounded capture calls from the same ordered fields as the Schema.
/// This accepts a finite operation vocabulary, never Rust source expressions.
pub fn emit_file_io_capture(source: &str) -> Result<String, String> {
    emit_file_io_contracts(source)?;
    let contracts: Contracts = toml::from_str(source).map_err(|e| e.to_string())?;
    let mut out = String::from("// Generated from file-io-contracts.toml; do not edit.\n");
    out.push_str(&format!(
        "pub const MAX_BUFFER_BYTES: usize = {};\npub const MAX_STRING_UNITS: usize = {};\n",
        contracts.max_buffer_bytes, contracts.max_string_units
    ));
    for api in &contracts.api {
        out.push_str(&capture_function(api, false)?);
        out.push_str(&capture_function(api, true)?);
    }
    Ok(out)
}

fn capture_function(api: &Api, leave: bool) -> Result<String, String> {
    let (stem, enter_types, leave_types): (&str, &[&str], &[&str]) = match api.id {
        1 => (
            "create_file_w",
            &["u64", "u32", "u32", "u64", "u32", "u32", "u64"],
            &["u64", "u32", "u32"],
        ),
        2 => (
            "read_file",
            &["u64", "u64", "u32", "u64"],
            &["i32", "u64", "u32", "u64", "bool", "u32"],
        ),
        3 => (
            "write_file",
            &["u64", "u64", "u32", "u64"],
            &["i32", "u64", "bool", "u32"],
        ),
        4 => ("close_handle", &["u64"], &["i32", "u32"]),
        _ => return Err("unsupported capture API".into()),
    };
    let (phase, args, fields, expected) = if leave {
        ("leave", &api.leave_arguments, &api.leave, leave_types)
    } else {
        ("enter", &api.enter_arguments, &api.enter, enter_types)
    };
    if args.iter().map(String::as_str).ne(expected.iter().copied()) {
        return Err(format!(
            "{} {phase}: incompatible capture arguments",
            api.function
        ));
    }
    let arg_is = |index: usize, ty: &str| args.get(index).is_some_and(|a| a == ty);
    let return_is = |index: usize| {
        api.leave
            .first()
            .is_some_and(|f| matches!(f.capture, CaptureOp::Scalar { arg } if arg == index))
    };
    let needs_memory = fields.iter().any(|f| {
        matches!(
            f.capture,
            CaptureOp::Utf16 { .. }
                | CaptureOp::InputBuffer { .. }
                | CaptureOp::OutputCount { .. }
                | CaptureOp::OutputBuffer { .. }
        )
    });
    let expected_memory = matches!((api.id, leave), (1, false) | (2, true) | (3, _));
    if needs_memory != expected_memory {
        return Err(format!(
            "{} {phase}: incompatible memory reader binding",
            api.function
        ));
    }
    let mut params = Vec::new();
    if needs_memory {
        params.push("mem: &dyn MemoryReader".to_string());
    }
    params.extend(args.iter().enumerate().map(|(i, ty)| format!("a{i}: {ty}")));
    let mut out = format!("#[allow(clippy::too_many_arguments)]\npub fn {stem}_{phase}({}) -> Vec<CapturedValue> {{\n", params.join(", "));
    for (i, field) in fields.iter().enumerate() {
        let bad = || {
            format!(
                "{} {phase} {}: invalid capture binding/type/timing",
                api.function, field.name
            )
        };
        let expression = match field.capture {
            CaptureOp::Scalar { arg } => {
                let (ty, function) = match field.ty.as_str() {
                    "U64" => ("u64", "u64v"),
                    "U32" => ("u32", "u32v"),
                    "I32" => ("i32", "i32v"),
                    _ => return Err(bad()),
                };
                if !arg_is(arg, ty) {
                    return Err(bad());
                }
                format!("{function}(a{arg})")
            }
            CaptureOp::Utf16 { arg } => {
                if leave || field.ty != "Str16" || !arg_is(arg, "u64") {
                    return Err(bad());
                }
                format!("read_utf16_string(mem, a{arg})")
            }
            CaptureOp::InputBuffer { address, length } => {
                if leave || field.ty != "Bytes" || !arg_is(address, "u64") || !arg_is(length, "u32")
                {
                    return Err(bad());
                }
                format!("read_buffer(mem, a{address}, a{length} as usize)")
            }
            CaptureOp::OutputCount {
                address,
                asynchronous,
            } => {
                if !leave
                    || field.ty != "U32"
                    || !arg_is(address, "u64")
                    || !arg_is(asynchronous, "bool")
                {
                    return Err(bad());
                }
                format!("read_io_count(mem, a{address}, a{asynchronous})")
            }
            CaptureOp::OutputBuffer {
                address,
                capacity,
                count_field,
                success,
                asynchronous,
            } => {
                if !leave
                    || field.ty != "Bytes"
                    || !arg_is(address, "u64")
                    || !arg_is(capacity, "u32")
                    || !arg_is(success, "i32")
                    || !return_is(success)
                    || !arg_is(asynchronous, "bool")
                    || count_field >= i
                    || !matches!(fields[count_field].capture, CaptureOp::OutputCount { asynchronous: a, .. } if a == asynchronous)
                {
                    return Err(bad());
                }
                format!("read_io_output(mem, a{success}, a{address}, a{capacity}, &v{count_field}, a{asynchronous})")
            }
            CaptureOp::LastErrorWithInput {
                arg,
                returns,
                input,
                ref meaningful_values,
            } => {
                if api.id != 1
                    || !leave
                    || api.last_error != "DependsOnInputs"
                    || field.name != "last_error"
                    || field.ty != "U32"
                    || !arg_is(arg, "u32")
                    || !arg_is(returns, "u64")
                    || !return_is(returns)
                    || input != 2
                    || !arg_is(input, "u32")
                    || meaningful_values.is_empty()
                    || meaningful_values.len() > 5
                    || meaningful_values.iter().any(|n| !(1..=5).contains(n))
                    || meaningful_values
                        .iter()
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        != meaningful_values.len()
                {
                    return Err(bad());
                }
                let values = meaningful_values
                    .iter()
                    .map(|v| format!("{v}u32"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("last_error_value(if [{values}].contains(&a{input}) {{ LastErrorMeaning::Always }} else {{ LastErrorMeaning::WhenReturnIsInvalidHandle }}, a{returns}, a{arg})")
            }
            CaptureOp::LastError { arg, returns } => {
                if !leave
                    || api.last_error == "DependsOnInputs"
                    || field.name != "last_error"
                    || field.ty != "U32"
                    || !arg_is(arg, "u32")
                    || !return_is(returns)
                {
                    return Err(bad());
                }
                let ret = if arg_is(returns, "u64") {
                    format!("a{returns}")
                } else {
                    format!("a{returns} as u64")
                };
                format!("last_error_value(crate::api::HANDWRITTEN_API_TABLE[{}].last_error_meaning, {ret}, a{arg})", api.id - 1)
            }
        };
        if leave
            && field.name == "last_error"
            && !matches!(
                field.capture,
                CaptureOp::LastError { .. } | CaptureOp::LastErrorWithInput { .. }
            )
        {
            return Err(bad());
        }
        out.push_str(&format!("    let v{i} = {expression};\n"));
    }
    out.push_str(&format!(
        "    vec![{}]\n}}\n",
        (0..fields.len())
            .map(|i| format!("v{i}"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    Ok(out)
}

/// Boundary seeds consumed by the memory-safety regression tests.
pub fn emit_file_io_boundaries(source: &str) -> Result<String, String> {
    emit_file_io_contracts(source)?;
    let contracts: Contracts = toml::from_str(source).map_err(|e| e.to_string())?;
    let n = contracts.max_buffer_bytes;
    Ok(format!("// Generated from file-io-contracts.toml; do not edit.\nconst BUFFER_LENGTHS: [u32; 5] = [0, 1, {n}, {}, u32::MAX];\n", n + 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    const SOURCE: &str = include_str!("../file-io-contracts.toml");
    #[test]
    fn checked_in_contracts_are_current() {
        assert_eq!(
            emit_file_io_contracts(SOURCE).unwrap(),
            include_str!("../../shirusu-api-catalog/src/api_file_io_generated.inc").replace("\r\n", "\n")
        );
        assert_eq!(
            emit_file_io_capture(SOURCE).unwrap(),
            include_str!("../../shirusu-hook/src/capture_file_io_generated.inc")
                .replace("\r\n", "\n")
        );
    }
    #[test]
    fn checked_in_boundaries_are_current() {
        assert_eq!(
            emit_file_io_boundaries(SOURCE).unwrap(),
            include_str!("../../shirusu-hook/tests/file_io_boundaries_generated.inc")
                .replace("\r\n", "\n")
        );
    }
    #[test]
    fn reject_ambiguous_or_incompatible_contracts() {
        for bad in [
            SOURCE.replacen("version = 3", "version = 2", 1),
            SOURCE.replacen("id = 1", "id = 2", 1),
            SOURCE.replacen("max_buffer_bytes = 4096", "max_buffer_bytes = 0", 1),
            SOURCE.replacen("max_string_units = 1024", "max_string_units = 1048577", 1),
            SOURCE.replacen("ty = \"U64\"", "ty = \"Usize\"", 1),
            SOURCE.replacen("kind = \"Pointer\"", "kind = \"Unknown\"", 1),
            SOURCE.replacen("DependsOnInputs", "WhenReturnIsFalse", 1),
            SOURCE.replacen("input = 2", "input = 1", 1),
            SOURCE.replacen(
                "meaningful_values = [2, 4]",
                "meaningful_values = [2, 2]",
                1,
            ),
            SOURCE.replacen("meaningful_values = [2, 4]", "meaningful_values = []", 1),
            SOURCE.replacen("meaningful_values = [2, 4]", "meaningful_values = [6]", 1),
            SOURCE.replacen("name = \"dwShareMode\"", "name = \"dwDesiredAccess\"", 1),
            SOURCE.replacen("op = \"utf16\", arg = 0", "op = \"utf16\", arg = 999", 1),
            SOURCE.replacen("capacity = 2", "capacity = 1", 1),
            SOURCE.replacen("count_field = 1", "count_field = 2", 1),
            SOURCE.replacen("op = \"input_buffer\"", "op = \"output_count\"", 1),
            format!("unknown = true\n{SOURCE}"),
        ] {
            assert!(emit_file_io_contracts(&bad).is_err());
        }
    }
}
