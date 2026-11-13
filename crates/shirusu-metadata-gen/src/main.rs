//! `win32-metadata-gen`: Win32 Metadata から shirusu-api-catalog の L1 生成表
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
//! `--out-dir crates/shirusu-hook/src`（`engine_generated.inc`）、
//! `--api-out-dir crates/shirusu-api-catalog/src`（`api_generated.inc`・
//! `api_broad_generated.inc`・`api_traits_generated.inc`。省略時に
//! `--out-dir` を指定していればその値）、
//! `--winmd` は環境変数 `SHIRUSU_WINMD` か
//! `target/winmd/Windows.Win32.winmd`。

use shirusu_metadata_gen::{
    broad_list_path, emit_api_inc, emit_api_inventory, emit_broad_api_inc, emit_com_catalog,
    emit_engine_inc, emit_traits_inc, generate, load_config, refresh_broad_list,
};
use windows_metadata::reader::TypeIndex;

const API_INC: &str = "api_generated.inc";
const ENGINE_INC: &str = "engine_generated.inc";
const BROAD_INC: &str = "api_broad_generated.inc";
const TRAITS_INC: &str = "api_traits_generated.inc";

fn usage() -> ! {
    eprintln!(
        "usage: win32-metadata-gen [--winmd <path>] [--config <path>] [--out-dir <dir>] [--api-out-dir <dir>] [--com-catalog <path>] [--inventory <tsv-path>] [--refresh-broad] [--check]\n       win32-metadata-gen --file-io-contracts [--check]"
    );
    std::process::exit(2);
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--file-io-contracts") {
        if let Err(e) = file_io_contracts_run() {
            eprintln!("win32-metadata-gen: {e}");
            std::process::exit(1);
        }
        return;
    }
    let mut winmd: Option<String> = None;
    let mut config_path = "crates/shirusu-metadata-gen/apis.toml".to_string();
    let mut out_dir: Option<String> = None;
    let mut api_out_dir: Option<String> = None;
    let mut check = false;
    let mut catalog: Option<String> = None;
    let mut inventory: Option<String> = None;
    let mut refresh = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--winmd" => winmd = Some(args.next().unwrap_or_else(|| usage())),
            "--config" => config_path = args.next().unwrap_or_else(|| usage()),
            "--out-dir" => out_dir = Some(args.next().unwrap_or_else(|| usage())),
            "--api-out-dir" => api_out_dir = Some(args.next().unwrap_or_else(|| usage())),
            "--check" => check = true,
            "--com-catalog" => catalog = Some(args.next().unwrap_or_else(|| usage())),
            "--inventory" => inventory = Some(args.next().unwrap_or_else(|| usage())),
            "--refresh-broad" => refresh = true,
            _ => usage(),
        }
    }
    if inventory.is_some() && catalog.is_some() {
        usage();
    }
    let winmd = winmd
        .or_else(|| std::env::var("SHIRUSU_WINMD").ok())
        .unwrap_or_else(|| "target/winmd/Windows.Win32.winmd".to_string());
    let result = if refresh {
        if inventory.is_some() || catalog.is_some() {
            usage();
        }
        refresh_run(&winmd, &config_path, check)
    } else if let Some(path) = inventory {
        inventory_run(&winmd, &config_path, &path, check)
    } else {
        // API 表は API Catalog、Detour は Hook に置く。--out-dir だけを
        // 指定した場合は両方をその場所に出す（一時ディレクトリでの検査用）。
        let api_out_dir = api_out_dir
            .or_else(|| out_dir.clone())
            .unwrap_or_else(|| "crates/shirusu-api-catalog/src".to_string());
        let out_dir = out_dir.unwrap_or_else(|| "crates/shirusu-hook/src".to_string());
        run(
            &winmd,
            &config_path,
            &out_dir,
            &api_out_dir,
            check,
            catalog.as_deref(),
        )
    };
    if let Err(e) = result {
        eprintln!("win32-metadata-gen: {e}");
        std::process::exit(1);
    }
}

fn refresh_run(winmd: &str, config_path: &str, check: bool) -> Result<(), String> {
    let config = load_config(config_path)?;
    let broad = config.broad.as_ref().ok_or("apis.toml に [broad] が無い")?;
    let index = TypeIndex::read(winmd).ok_or_else(|| format!("cannot read WinMD: {winmd}"))?;
    let content = refresh_broad_list(&index, &config)?;
    let path = broad_list_path(config_path, broad);
    if check {
        if !matches!(std::fs::read_to_string(&path), Ok(have) if have == content) {
            return Err(format!("broad list {} is stale", path.display()));
        }
        return Ok(());
    }
    std::fs::write(&path, &content).map_err(|e| format!("{}: {e}", path.display()))?;
    println!(
        "wrote {} ({} APIs)",
        path.display(),
        content.lines().count().saturating_sub(1)
    );
    Ok(())
}

fn inventory_run(winmd: &str, config_path: &str, path: &str, check: bool) -> Result<(), String> {
    let config = load_config(config_path)?;
    let index = TypeIndex::read(winmd).ok_or_else(|| format!("cannot read WinMD: {winmd}"))?;
    let content = emit_api_inventory(&index, &config);
    if check {
        if !matches!(std::fs::read_to_string(path), Ok(have) if have == content) {
            return Err(format!("API inventory {path} is stale"));
        }
        Ok(())
    } else {
        std::fs::write(path, content).map_err(|e| format!("{path}: {e}"))
    }
}

fn run(
    winmd: &str,
    config_path: &str,
    out_dir: &str,
    api_out_dir: &str,
    check: bool,
    catalog: Option<&str>,
) -> Result<(), String> {
    let config = load_config(config_path)?;
    let index = TypeIndex::read(winmd)
        .ok_or_else(|| format!("{winmd} を読めない（fetch-winmd.sh で取得する）"))?;
    if let Some(path) = catalog {
        let content = emit_com_catalog(&index, &config.winmd_version)?;
        if check {
            if !matches!(std::fs::read_to_string(path), Ok(have) if have == content) {
                return Err(format!("COM catalog {path} is stale"));
            }
        } else {
            std::fs::write(path, content).map_err(|e| e.to_string())?;
        }
    }
    let generated = generate(&index, &config)?;
    let outputs = [
        (
            format!("{api_out_dir}/{API_INC}"),
            emit_api_inc(&generated, &config.winmd_version),
        ),
        (
            format!("{api_out_dir}/{BROAD_INC}"),
            emit_broad_api_inc(&generated, &config.winmd_version),
        ),
        (
            format!("{out_dir}/{ENGINE_INC}"),
            emit_engine_inc(&generated, &config.winmd_version),
        ),
        (
            format!("{api_out_dir}/{TRAITS_INC}"),
            emit_traits_inc(&generated, &config.winmd_version),
        ),
    ];
    if check {
        let mut mismatch = false;
        for (path, want) in &outputs {
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
        for (path, content) in &outputs {
            std::fs::write(path, content).map_err(|e| format!("{path} を書けない: {e}"))?;
            println!("wrote {path}");
        }
    }
    let emitted = generated.emitted();
    println!(
        "generated {} APIs (ids {}..={}) from {} (winmd {})",
        emitted.len(),
        config.first_api_id,
        emitted.last().map(|a| a.api_id).unwrap_or(0),
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

fn file_io_contracts_run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(2).collect();
    if !(args.is_empty() || args == ["--check"]) {
        return Err("usage: win32-metadata-gen --file-io-contracts [--check]".into());
    }
    let source = std::fs::read_to_string("crates/shirusu-metadata-gen/file-io-contracts.toml")
        .map_err(|e| e.to_string())?;
    let generated = shirusu_metadata_gen::contracts::emit_file_io_contracts(&source)?;
    let capture = shirusu_metadata_gen::contracts::emit_file_io_capture(&source)?;
    let boundaries = shirusu_metadata_gen::contracts::emit_file_io_boundaries(&source)?;
    for (path, content) in [
        (
            "crates/shirusu-hook/tests/file_io_boundaries_generated.inc",
            boundaries,
        ),
        (
            "crates/shirusu-api-catalog/src/api_file_io_generated.inc",
            generated,
        ),
        (
            "crates/shirusu-hook/src/capture_file_io_generated.inc",
            capture,
        ),
    ] {
        if args.is_empty() {
            std::fs::write(path, content).map_err(|e| e.to_string())?;
        } else if std::fs::read_to_string(path)
            .map(|s| s.replace("\r\n", "\n"))
            .ok()
            .as_deref()
            != Some(&content)
        {
            return Err(format!("{path} is stale"));
        }
    }
    Ok(())
}
