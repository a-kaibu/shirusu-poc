//! `win32-metadata-gen`: Win32 Metadata から shirusu-hook の L1 生成表
//! （`api_generated.inc`）と汎用 Detour（`engine_generated.inc`）を出す
//! 開発時ツール（L03）。
//!
//! 使い方（リポジトリルートから）:
//! ```text
//! cargo run -p shirusu-metadata-gen -- --winmd target/winmd/Windows.Win32.winmd
//! cargo run -p shirusu-metadata-gen -- --winmd <path> --check   # 差分があれば終了 1
//! ```
//! winmd が無い場合は `bash scripts/ci/fetch-winmd.sh` で取得する
//! （`Microsoft.Windows.SDK.Win32Metadata` の NuGet 版を固定）。
//! 既定値: `--config crates/shirusu-metadata-gen/apis.toml`、
//! `--out-dir crates/shirusu-hook/src`、
//! `--winmd` は環境変数 `SHIRUSU_WINMD` か
//! `target/winmd/Windows.Win32.winmd`。

use shirusu_metadata_gen::{emit_api_inc, emit_engine_inc, generate, load_config};
use windows_metadata::reader::TypeIndex;

const API_INC: &str = "api_generated.inc";
const ENGINE_INC: &str = "engine_generated.inc";

fn usage() -> ! {
    eprintln!(
        "usage: win32-metadata-gen [--winmd <path>] [--config <path>] [--out-dir <dir>] [--check]"
    );
    std::process::exit(2);
}

fn main() {
    let mut winmd: Option<String> = None;
    let mut config_path = "crates/shirusu-metadata-gen/apis.toml".to_string();
    let mut out_dir = "crates/shirusu-hook/src".to_string();
    let mut check = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--winmd" => winmd = Some(args.next().unwrap_or_else(|| usage())),
            "--config" => config_path = args.next().unwrap_or_else(|| usage()),
            "--out-dir" => out_dir = args.next().unwrap_or_else(|| usage()),
            "--check" => check = true,
            _ => usage(),
        }
    }
    let winmd = winmd
        .or_else(|| std::env::var("SHIRUSU_WINMD").ok())
        .unwrap_or_else(|| "target/winmd/Windows.Win32.winmd".to_string());
    if let Err(e) = run(&winmd, &config_path, &out_dir, check) {
        eprintln!("win32-metadata-gen: {e}");
        std::process::exit(1);
    }
}

fn run(winmd: &str, config_path: &str, out_dir: &str, check: bool) -> Result<(), String> {
    let config = load_config(config_path)?;
    let index = TypeIndex::read(winmd)
        .ok_or_else(|| format!("{winmd} を読めない（fetch-winmd.sh で取得する）"))?;
    let generated = generate(&index, &config)?;
    let api_inc = emit_api_inc(&generated, &config.winmd_version);
    let engine_inc = emit_engine_inc(&generated, &config.winmd_version);
    let api_path = format!("{out_dir}/{API_INC}");
    let engine_path = format!("{out_dir}/{ENGINE_INC}");
    if check {
        let mut mismatch = false;
        for (path, want) in [(&api_path, &api_inc), (&engine_path, &engine_inc)] {
            match std::fs::read_to_string(path) {
                Ok(have) if have == *want => println!("ok: {path} は最新"),
                Ok(_) => {
                    println!("DIFF: {path} が生成結果と異なる（再生成する）");
                    mismatch = true;
                }
                Err(_) => {
                    println!("DIFF: {path} が無い（生成する）");
                    mismatch = true;
                }
            }
        }
        if mismatch {
            return Err(
                "生成物が最新ではない。win32-metadata-gen（--check なし）で再生成する".into(),
            );
        }
    } else {
        std::fs::write(&api_path, &api_inc).map_err(|e| format!("{api_path} を書けない: {e}"))?;
        std::fs::write(&engine_path, &engine_inc)
            .map_err(|e| format!("{engine_path} を書けない: {e}"))?;
        println!("wrote {api_path}");
        println!("wrote {engine_path}");
    }
    let emitted = generated.emitted();
    println!(
        "generated {} APIs (ids {}..={}) from {} (winmd {})",
        emitted.len(),
        config.first_api_id,
        config.first_api_id + emitted.len() as u32 - 1,
        winmd,
        config.winmd_version
    );
    for (module, function, reason) in generated.skipped() {
        println!("skip: {module}!{function}: {reason}");
    }
    for skip in &generated.intentional_skips {
        println!(
            "skip (intentional): {}!{}: {}",
            skip.module, skip.function, skip.reason
        );
    }
    Ok(())
}
