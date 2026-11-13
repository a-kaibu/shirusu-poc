//! Versioned, handwritten semantic additions to WinMD. These contracts describe
//! Trace fields and LastError validity; memory traversal remains audited capture code.
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Contracts {
    version: u32,
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
    enter: Vec<Field>,
    leave: Vec<Field>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Field {
    name: String,
    ty: String,
    kind: String,
}

/// Emit the first four stable ApiDefs. Reject unknown vocabulary instead of
/// interpolating untrusted expressions into generated Rust source.
pub fn emit_file_io_contracts(source: &str) -> Result<String, String> {
    let contracts: Contracts = toml::from_str(source).map_err(|e| e.to_string())?;
    if contracts.version != 1 || contracts.api.len() != 4 {
        return Err("expected version 1 and exactly four file I/O contracts".into());
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
            "WhenReturnIsInvalidHandle" | "WhenReturnIsFalse"
        ) {
            return Err(format!("{}: unsupported LastError rule", api.function));
        }
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
                    "WhenReturnIsInvalidHandle"
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

#[cfg(test)]
mod tests {
    use super::*;
    const SOURCE: &str = include_str!("../file-io-contracts.toml");
    #[test]
    fn checked_in_contracts_are_current() {
        assert_eq!(
            emit_file_io_contracts(SOURCE).unwrap(),
            include_str!("../../shirusu-hook/src/api_file_io_generated.inc")
        );
    }
    #[test]
    fn reject_ambiguous_or_incompatible_contracts() {
        for bad in [
            SOURCE.replacen("version = 1", "version = 2", 1),
            SOURCE.replacen("id = 1", "id = 2", 1),
            SOURCE.replacen("ty = \"U64\"", "ty = \"Usize\"", 1),
            SOURCE.replacen("kind = \"Pointer\"", "kind = \"Unknown\"", 1),
            SOURCE.replacen("WhenReturnIsInvalidHandle", "WhenReturnIsFalse", 1),
            SOURCE.replacen("name = \"dwShareMode\"", "name = \"dwDesiredAccess\"", 1),
            format!("unknown = true\n{SOURCE}"),
        ] {
            assert!(emit_file_io_contracts(&bad).is_err());
        }
    }
}
