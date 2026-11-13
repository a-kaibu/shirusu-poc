#![no_main]
use libfuzzer_sys::fuzz_target;
use shirusu_hook::pe;

// 任意バイト列を PE のファイルイメージ / メモリイメージの両方として解析する。
// 相手 (ディスク上の DLL・自プロセスのモジュール) を完全には信用しない前提で、
// panic せず、返した位置がすべてイメージ内に収まることを確かめる。
fn check_image(image: &[u8]) {
    let thunk = match pe::is_pe64(image) {
        Some(true) => 8,
        Some(false) => 4,
        None => {
            assert!(pe::parse_imports(image).is_empty());
            assert!(pe::find_export(image, "ShirusuInit").is_none());
            assert!(pe::machine(image).is_none());
            return;
        }
    };
    assert!(pe::machine(image).is_some());
    for site in pe::parse_imports(image) {
        // IAT スロット (thunk 幅) 全体がイメージ内にある。フック計画はここへ書く。
        assert!(site.iat_rva as usize + thunk <= image.len());
        // 名前と序数はどちらか一方だけ。
        assert!(site.func_name.is_none() || site.ordinal.is_none());
        assert!(site.dll_name.len() <= 512 * 3);
    }
    for name in ["ShirusuInit", "", "A"] {
        if let Some(rva) = pe::find_export(image, name) {
            assert!(rva != 0 && (rva as usize) < image.len());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // メモリイメージ配置 (Agent 側: ロード済みモジュール)
    check_image(data);
    // ファイルイメージ配置 (Host 側: Agent DLL ファイル)
    if let Some(image) = pe::map_file_to_image(data) {
        assert_eq!(Some(image.len() as u32), pe::size_of_image(data));
        // ヘッダーが写像先に収まる限り、ビット幅の判定は写像の前後で変わらない。
        if pe::is_pe64(&image).is_some() {
            assert_eq!(pe::is_pe64(&image), pe::is_pe64(data));
        }
        check_image(&image);
    }
});
