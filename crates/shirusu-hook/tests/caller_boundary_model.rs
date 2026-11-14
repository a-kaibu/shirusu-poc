//! 呼び出し境界（L23）の判定部品のモデルベース検査。
//!
//! - `CallerCache`: 任意の登録・アンロード列のあと、任意のアドレスの分類が
//!   素朴なモデル（重なる古い範囲を捨てて新しい範囲を足す一覧の線形探索）と
//!   一致し、内部の範囲は base の昇順で重ならない。
//! - `classify_caller_image`: Windows 配置の判定は大小文字・区切り文字に
//!   依存せず、名前の一部一致（`System32x` など）では Windows にしない。
//!   実行基盤は配置に関係なく Runtime、対象 EXE は Application。

use proptest::prelude::*;
use shirusu_hook::caller::{
    classify_address, classify_caller_image, should_suppress_caller, should_suppress_target,
    windows_dir_from_kernel32, windows_image_prefixes, CallerCache, ModuleRange,
};
use shirusu_trace::module::ModuleClass;

#[derive(Debug, Clone)]
enum Op {
    Insert { base: u64, len: u64, class: u8 },
    Unload { base: u64, len: u64 },
}

fn class(n: u8) -> ModuleClass {
    match n % 3 {
        0 => ModuleClass::Windows,
        1 => ModuleClass::Runtime,
        _ => ModuleClass::Application,
    }
}

fn op() -> impl Strategy<Value = Op> {
    // 小さなアドレス空間に詰めて、重なり・隣接・空範囲を頻繁に起こす。
    prop_oneof![
        3 => (0u64..64, 0u64..12, any::<u8>())
            .prop_map(|(base, len, class)| Op::Insert { base, len, class }),
        1 => (0u64..64, 0u64..16).prop_map(|(base, len)| Op::Unload { base, len }),
    ]
}

fn model_classify(model: &[ModuleRange], addr: u64) -> Option<ModuleClass> {
    model
        .iter()
        .find(|r| r.base <= addr && addr < r.end)
        .map(|r| r.class)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn caller_cache_matches_a_naive_model(ops in proptest::collection::vec(op(), 0..40)) {
        let mut cache = CallerCache::with_capacity(4);
        let mut model: Vec<ModuleRange> = Vec::new();
        for op in &ops {
            match *op {
                Op::Insert { base, len, class: c } => {
                    let r = ModuleRange { base, end: base + len, class: class(c) };
                    cache.insert(r);
                    if len > 0 {
                        model.retain(|m| m.end <= r.base || m.base >= r.end);
                        model.push(r);
                    }
                }
                Op::Unload { base, len } => {
                    cache.remove_overlapping(base, base + len);
                    model.retain(|m| m.end <= base || m.base >= base + len);
                }
            }
            prop_assert_eq!(cache.len(), model.len());
            prop_assert_eq!(cache.is_empty(), model.is_empty());
        }
        for addr in 0..80u64 {
            prop_assert_eq!(cache.classify(addr as usize), model_classify(&model, addr), "addr {}", addr);
        }
        // 同じ一覧を base 昇順に並べれば classify_address も同じ答えを返す。
        let mut sorted = model.clone();
        sorted.sort_by_key(|r| r.base);
        for w in sorted.windows(2) {
            prop_assert!(w[0].end <= w[1].base, "overlap {:?}", w);
        }
        for addr in 0..80u64 {
            prop_assert_eq!(classify_address(&sorted, addr as usize), model_classify(&model, addr));
        }
    }

    #[test]
    fn windows_placement_ignores_case_and_separators(
        windows in "[A-Za-z]:\\\\[A-Za-z]{1,8}",
        sub in prop_oneof![Just("System32"), Just("SysWOW64"), Just("WinSxS")],
        file in "[a-z]{1,8}\\.dll",
        upper in any::<bool>(),
        slash in any::<bool>(),
    ) {
        prop_assume!(!shirusu_trace::module::is_runtime_module(&file));
        let prefixes = windows_image_prefixes(&format!("{windows}\\"));
        let mut path = format!("{windows}\\{sub}\\{file}");
        if upper {
            path = path.to_uppercase();
        }
        if slash {
            path = path.replace('\\', "/");
        }
        prop_assert_eq!(classify_caller_image(&path, false, &prefixes), ModuleClass::Windows);
        // 対象 EXE 自身なら配置に関係なく Application。
        prop_assert_eq!(classify_caller_image(&path, true, &prefixes), ModuleClass::Application);
        // 名前の一部一致は Windows にしない。
        for near in [
            format!("{windows}\\{sub}x\\{file}"),
            format!("{windows}x\\{sub}\\{file}"),
            format!("{windows}\\{file}"),
            format!("D:\\copy{windows}\\{sub}\\{file}").replace(':', ""),
        ] {
            prop_assert_eq!(
                classify_caller_image(&near, false, &prefixes),
                ModuleClass::Application,
                "{}",
                near
            );
        }
    }
}

#[test]
fn runtime_modules_are_runtime_anywhere() {
    let prefixes = windows_image_prefixes("\\device\\harddiskvolume3\\windows");
    for path in [
        "\\device\\harddiskvolume3\\windows\\system32\\ucrtbase.dll",
        "C:\\app\\VCRUNTIME140.dll",
        "C:/app/vcruntime140_1.dll",
    ] {
        assert_eq!(
            classify_caller_image(path, false, &prefixes),
            ModuleClass::Runtime,
            "{path}"
        );
        assert_eq!(
            classify_caller_image(path, true, &prefixes),
            ModuleClass::Runtime
        );
    }
}

#[test]
fn windows_dir_is_derived_only_from_a_system_kernel32() {
    assert_eq!(
        windows_dir_from_kernel32("C:\\Windows\\System32\\KERNEL32.DLL").as_deref(),
        Some("C:\\Windows")
    );
    assert_eq!(
        windows_dir_from_kernel32("C:/Windows/SysWOW64/kernel32.dll").as_deref(),
        Some("C:\\Windows")
    );
    for bad in [
        "C:\\Windows\\System32\\kernelbase.dll",
        "C:\\Windows\\Temp\\kernel32.dll",
        "kernel32.dll",
        "\\System32\\kernel32.dll",
        "",
    ] {
        assert_eq!(windows_dir_from_kernel32(bad), None, "{bad}");
    }
}

#[test]
fn suppression_is_fail_open_and_mode_dependent() {
    use ModuleClass::*;
    for c in [
        None,
        Some(Application),
        Some(Runtime),
        Some(Unknown),
        Some(Windows),
    ] {
        assert!(
            !should_suppress_caller(c, true),
            "detailed mode records everything"
        );
        assert_eq!(should_suppress_caller(c, false), c == Some(Windows));
        assert!(!should_suppress_target(c, true));
        assert_eq!(should_suppress_target(c, false), c == Some(Runtime));
    }
}
