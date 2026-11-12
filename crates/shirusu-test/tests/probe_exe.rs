//! Probe exe 生成の統合テスト（コード生成＋実ビルド）。
//!
//! 実ビルドは x86_64-pc-windows-gnu 対象＋mingw リンカが揃った環境での
//! み行い、揃わない環境では飛ばして成功とする（CI の Linux ジョブ等）。
//! msvc 対象と i686 のビルドは Windows ジョブ（`scripts/ci/probe-l20.ps1`）
//! で確かめる。

use shirusu_test::{build_probe_exe, TestSpec};
use std::path::PathBuf;
use std::process::Command;

fn sample_spec() -> TestSpec {
    let path = format!(
        "{}/tests/data/probe-sample.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(path).unwrap();
    TestSpec::parse(&text).unwrap()
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_shirusu-test")
}

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("shirusu-test-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// x64 Windows（gnu）向けのビルド道具が揃っているか。
fn gnu_toolchain_available() -> bool {
    let target_ok = Command::new("rustc")
        .args([
            "--print",
            "target-libdir",
            "--target",
            "x86_64-pc-windows-gnu",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let mingw_ok = Command::new("x86_64-w64-mingw32-gcc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    target_ok && mingw_ok
}

/// PE ファイルの基本構造を確かめる。MZ・PE 署名・マシン種別。
fn assert_pe_x64(bytes: &[u8]) {
    assert!(bytes.len() > 64, "exe too small");
    assert_eq!(&bytes[..2], b"MZ", "missing MZ magic");
    let e_lfanew = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    assert!(bytes.len() > e_lfanew + 6, "exe truncated before PE header");
    assert_eq!(
        &bytes[e_lfanew..e_lfanew + 4],
        b"PE\0\0",
        "missing PE signature"
    );
    let machine = u16::from_le_bytes(bytes[e_lfanew + 4..e_lfanew + 6].try_into().unwrap());
    assert_eq!(
        machine, 0x8664,
        "expected x86-64 machine type, got {machine:#x}"
    );
}

#[test]
fn builds_real_x64_exe_when_toolchain_available() {
    if !gnu_toolchain_available() {
        println!("skipped: x86_64-pc-windows-gnu target or mingw linker is missing");
        return;
    }
    let dir = tmp_dir("probe-exe-build");
    let out = dir.join("probe-sample.exe");
    let spec = sample_spec();
    let built = build_probe_exe(&spec, "x86_64-pc-windows-gnu", &out).unwrap();
    assert_eq!(built, out);
    let bytes = std::fs::read(&out).unwrap();
    assert_pe_x64(&bytes);
    // 仕様の呼び出し名とファイル名が exe に埋め込まれていること。
    assert!(bytes.windows(11).any(|w| w == b"CreateFileW"));
    assert!(bytes.windows(16).any(|w| w == b"probe-sample.txt"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_probe_exe_builds_and_keeps_source() {
    if !gnu_toolchain_available() {
        println!("skipped: x86_64-pc-windows-gnu target or mingw linker is missing");
        return;
    }
    let dir = tmp_dir("probe-exe-cli");
    let out = dir.join("probe.exe");
    let source = dir.join("main.rs");
    let spec_path = format!(
        "{}/tests/data/probe-sample.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let status = Command::new(bin())
        .args([
            "probe-exe",
            &spec_path,
            "--target",
            "x86_64-pc-windows-gnu",
            "--out",
            out.to_str().unwrap(),
            "--keep-source",
            source.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let bytes = std::fs::read(&out).unwrap();
    assert_pe_x64(&bytes);
    let kept = std::fs::read_to_string(&source).unwrap();
    assert!(kept.contains("fn run_embedded"));
    assert!(kept.contains("CreateFileW"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(not(windows))]
#[test]
fn generated_exe_runs_on_host_with_clear_error() {
    // 生成物がホスト向けにもビルドでき、計画まで進んで「Windows が
    // 必要」と明言して終わること。生成コードの実行経路を Linux で
    // 確かめられる唯一の方法。Windows での実実行は CI で確かめる。
    use shirusu_test::generate_probe_main_rs;
    let dir = tmp_dir("probe-exe-host");
    let main_rs = dir.join("main.rs");
    let exe = dir.join("probe-host");
    let source = generate_probe_main_rs(&sample_spec()).unwrap();
    std::fs::write(&main_rs, &source).unwrap();
    let build = Command::new("rustc")
        .args([
            "--edition",
            "2021",
            "-O",
            main_rs.to_str().unwrap(),
            "-o",
            exe.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    let run = Command::new(&exe).output().unwrap();
    assert_eq!(run.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(stdout.contains("\"spec\":\"probe-sample\""));
    assert!(stdout.contains("requires Windows"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_probe_exe_rejects_non_windows_target() {
    let dir = tmp_dir("probe-exe-bad-target");
    let out = dir.join("probe.exe");
    let spec_path = format!(
        "{}/tests/data/probe-sample.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let status = Command::new(bin())
        .args([
            "probe-exe",
            &spec_path,
            "--target",
            "x86_64-unknown-linux-gnu",
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    // ビルドの失敗は終了コード 1。
    assert_eq!(status.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_probe_exe_needs_target_and_out() {
    let spec_path = format!(
        "{}/tests/data/probe-sample.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let no_target = Command::new(bin())
        .args(["probe-exe", &spec_path, "--out", "x.exe"])
        .output()
        .unwrap();
    assert_eq!(no_target.status.code(), Some(2));
    let no_out = Command::new(bin())
        .args(["probe-exe", &spec_path, "--target", "x86_64-pc-windows-gnu"])
        .output()
        .unwrap();
    assert_eq!(no_out.status.code(), Some(2));
}
