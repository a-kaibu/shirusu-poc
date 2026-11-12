//! Host → Agent DLL の初期化受け渡し（Bootstrap）。
//!
//! Host レコーダは対象プロセスへ Agent DLL を注入した後、この構造体を
//! 対象プロセスのメモリへ書き込み、DLL の `shirusu_agent_init` を
//! リモートスレッドで呼ぶ。DLL 側は値をコピーして初期化に使い、
//! 構造体自体は初期化が戻った時点で解放してよい（ハンドル値は
//! DLL 側で複製済みの実体を指し続ける）。
//!
//! ハンドル値は全て「対象プロセス内で有効な値」を u64 で運ぶ
//! （同一ビットネス間の受け渡しが前提。GOAL の Phase 3 スコープ）。
//! レイアウトは #[repr(C)] で固定し、version で将来の変更を検出する。

use shirusu_transport::RingConfig;

/// `shirusu_agent_shutdown` の戻り値（Host と DLL の共有定義。
/// レビュー第5回 #6）。Host はこの値で「完全に止まったか」を
/// 区別し、Trace の Event Integrity へ写す。
/// 完全停止: 記録無効化 → 進行中 Detour の完了 → IAT 復元まで済んだ。
pub const SHUTDOWN_OK: u32 = 0;
/// 終了手順は実行されたが、進行中 Detour が完了待ち上限内に
/// 終わらなかった（IAT は復元済み。書き込み途中のイベントが
/// 不完全なまま残りうる）。
pub const SHUTDOWN_INCOMPLETE: u32 = 1;
/// アクティブなセッションが無かった（未初期化、または終了済み）。
pub const SHUTDOWN_NOT_INITIALIZED: u32 = 2;

/// v2: 初期化結果の書き戻し欄 (result_hooked_count /
/// result_missing_count) を追加した。
/// v3: 末尾に result_unrestored_count を追加した (既存フィールドの
/// オフセットは不変)。設置失敗時にロールバックも失敗して対象へ
/// 残存した IAT スロットの数 (レビュー第5回 #8)。
/// v4: 末尾に order_global を追加した (L11 `--order=global`)。
/// 0 = 無効、0 以外 = 有効。Agent は有効な場合のみ観測点で
/// 全スレッド共通の番号を採番する。
/// v5: 末尾に record_runtime_apis を追加した (L23)。0 = Runtime 独自の
/// API を記録しない（既定）、0 以外 = 記録する。Host が
/// `CaptureSessionConfig::record_runtime_apis` から設定する。
/// v6: 末尾に com_options と result_com_factory_count を追加した (L02)。
/// com_options は bit0 = 診断用の追加 QueryInterface を有効にするか
/// （既定は 0 = 無効）。result_com_factory_count は DLL が設置した
/// COM Factory 関数の Detour の数（0〜2。CoCreateInstance /
/// CoGetClassObject）。
/// v7: 末尾に result_winrt_activation_count を追加した (L14)。
/// DLL が設置した WinRT アクティベーション関数の Detour の数
/// （0〜2。RoActivateInstance / RoGetActivationFactory）。
/// v8: 末尾に detailed_mode と result_internal_hook_count を追加した
/// (L15)。detailed_mode は 0 = 無効（既定。内部 API を記録しない）、
/// 0 以外 = 有効（詳細調査モード）。result_internal_hook_count は DLL
/// が設置した内部 API (Nt*) の Inline Hook の数（0〜7）。
/// v9: 末尾に result_callback_hook_count を追加した (L16)。
/// DLL が設置したコールバック検出フックの数（0〜4。RegisterClassExW/A /
/// SetWindowLongPtrW/A）。
pub const BOOTSTRAP_VERSION: u32 = 9;
pub const MAX_BOOTSTRAP_RINGS: usize = 32;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentBootstrap {
    pub version: u32,
    pub ring_count: u32,
    pub session_id: u64,
    /// RingConfig の descriptor 容量（Descriptor 数）。
    pub descriptor_capacity: u64,
    /// RingConfig の payload 容量（バイト数）。
    pub payload_capacity: u64,
    /// data_ready イベント（auto-reset）の対象プロセス内ハンドル値。0 = 無し。
    pub data_ready_handle: u64,
    /// 初期化完了イベント（手動リセット）の対象プロセス内ハンドル値。0 = 無し。
    pub init_done_handle: u64,
    /// Host プロセスの対象プロセス内ハンドル値（生存確認用）。0 = 無し。
    pub host_process_handle: u64,
    /// Ring ごとの File Mapping ハンドル値（対象プロセス内）。
    pub mapping_handles: [u64; MAX_BOOTSTRAP_RINGS],
    /// Ring ごとの space_available イベント（auto-reset）のハンドル値。
    pub space_handles: [u64; MAX_BOOTSTRAP_RINGS],
    /// 初期化結果（DLL が init_done を立てる前に書き戻す。Host は
    /// 初期化成功後に読み戻す）: メインモジュールへ実際に設置できた
    /// フック対象 API の数。対象 API を 1 つもインポートしていない
    /// 正常なアプリでは 0 になる (レビュー #4 の #8)。
    pub result_hooked_count: u32,
    /// 初期化結果: メインモジュールがインポートしておらず、フック
    /// できなかった対象 API の数 (Capture Coverage の欠落)。
    pub result_missing_count: u32,
    /// 初期化結果 (v3): フック設置が途中で失敗し、ロールバックでも
    /// 復元できなかった IAT スロットの数。通常は 0。0 でない場合、
    /// 対象プロセスには Detour が残存しており、Host は初期化失敗の
    /// 詳細として扱わなければならない (レビュー第5回 #8)。
    pub result_unrestored_count: u32,
    /// `--order=global` (v4, L11): 0 = 無効、0 以外 = 有効。
    /// Host が `CaptureSessionConfig::order_global` から設定する。
    pub order_global: u32,
    /// Runtime 独自の API も記録するか (v5, L23): 0 = 記録しない
    /// （既定）、0 以外 = 記録する。Host が
    /// `CaptureSessionConfig::record_runtime_apis` から設定する。
    pub record_runtime_apis: u32,
    /// COM オプション (v6, L02): bit0 = 診断用の追加 QueryInterface
    /// を有効にするか（既定は 0 = 無効。標準では Interceptor 自身は
    /// QueryInterface を呼ばない）。Host が
    /// `CaptureSessionConfig::diagnostic_query_interface` から設定する。
    pub com_options: u32,
    /// 初期化結果 (v6, L02): DLL が設置した COM Factory 関数の
    /// Detour の数（0〜2）。Host は読み戻して Coverage へ写す。
    pub result_com_factory_count: u32,
    /// 初期化結果 (v7, L14): DLL が設置した WinRT アクティベーション
    /// 関数の Detour の数（0〜2）。Host は読み戻して Coverage へ写す。
    pub result_winrt_activation_count: u32,
    /// 詳細調査モード (v8, L15): 0 = 無効（既定。内部 API を記録しない）、
    /// 0 以外 = 有効。Host が `CaptureSessionConfig::record_mode` の
    /// `Detailed` から設定する。
    pub detailed_mode: u32,
    /// 初期化結果 (v8, L15): DLL が設置した内部 API (Nt*) の Inline
    /// Hook の数（0〜7）。Host は読み戻して Coverage へ写す。
    pub result_internal_hook_count: u32,
    /// 初期化結果 (v9, L16): DLL が設置したコールバック検出フックの
    /// 数（0〜4）。Host は読み戻して Coverage へ写す。
    pub result_callback_hook_count: u32,
}

impl Default for AgentBootstrap {
    fn default() -> Self {
        Self {
            version: BOOTSTRAP_VERSION,
            ring_count: 0,
            session_id: 0,
            descriptor_capacity: 0,
            payload_capacity: 0,
            data_ready_handle: 0,
            init_done_handle: 0,
            host_process_handle: 0,
            mapping_handles: [0; MAX_BOOTSTRAP_RINGS],
            space_handles: [0; MAX_BOOTSTRAP_RINGS],
            result_hooked_count: 0,
            result_missing_count: 0,
            result_unrestored_count: 0,
            order_global: 0,
            record_runtime_apis: 0,
            com_options: 0,
            result_com_factory_count: 0,
            result_winrt_activation_count: 0,
            detailed_mode: 0,
            result_internal_hook_count: 0,
            result_callback_hook_count: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapError {
    BadVersion(u32),
    NoRings,
    TooManyRings(u32),
    BadRingConfig,
    MissingMappingHandle(u32),
}

impl AgentBootstrap {
    /// Host 側の組み立て。`rings` は (mapping, space_available) の
    /// ハンドル値ペア（対象プロセス内で有効な値）。
    pub fn new(session_id: u64, config: RingConfig, rings: &[(u64, u64)]) -> Self {
        let mut b = Self {
            session_id,
            descriptor_capacity: config.descriptor_capacity as u64,
            payload_capacity: config.payload_capacity as u64,
            ring_count: rings.len().min(MAX_BOOTSTRAP_RINGS) as u32,
            ..Self::default()
        };
        for (i, (m, s)) in rings.iter().take(MAX_BOOTSTRAP_RINGS).enumerate() {
            b.mapping_handles[i] = *m;
            b.space_handles[i] = *s;
        }
        b
    }

    /// DLL 側の検証。受け取った値を信用せず、初期化に使う前に確認する。
    pub fn validate(&self) -> Result<RingConfig, BootstrapError> {
        if self.version != BOOTSTRAP_VERSION {
            return Err(BootstrapError::BadVersion(self.version));
        }
        if self.ring_count == 0 {
            return Err(BootstrapError::NoRings);
        }
        if self.ring_count as usize > MAX_BOOTSTRAP_RINGS {
            return Err(BootstrapError::TooManyRings(self.ring_count));
        }
        for i in 0..self.ring_count as usize {
            if self.mapping_handles[i] == 0 {
                return Err(BootstrapError::MissingMappingHandle(i as u32));
            }
        }
        let (d, p) = (self.descriptor_capacity, self.payload_capacity);
        if d == 0 || p == 0 || d > (1 << 24) || p > (1 << 32) {
            return Err(BootstrapError::BadRingConfig);
        }
        Ok(RingConfig::new(d as usize, p as usize))
    }

    pub fn ring_mapping_handle(&self, index: usize) -> u64 {
        self.mapping_handles[index]
    }
    pub fn ring_space_handle(&self, index: usize) -> u64 {
        self.space_handles[index]
    }
    /// DLL 側が初期化結果を書き戻すためのポインタ経由の記録。
    ///
    /// # Safety
    /// `bootstrap` は Host が確保した書き込み可能な Bootstrap 領域を
    /// 指し、初期化が終わるまで有効であること。
    pub unsafe fn write_hook_outcome(bootstrap: *mut AgentBootstrap, hooked: u32, missing: u32) {
        // SAFETY: 呼び出し側の契約に従う。
        unsafe {
            (*bootstrap).result_hooked_count = hooked;
            (*bootstrap).result_missing_count = missing;
        }
    }
    /// Host 側: 初期化成功後に読み戻した結果。(設置数, 欠落数)。
    pub fn hook_outcome(&self) -> (u32, u32) {
        (self.result_hooked_count, self.result_missing_count)
    }
    /// DLL 側が設置失敗の詳細を書き戻すためのポインタ経由の記録。
    ///
    /// # Safety
    /// [`AgentBootstrap::write_hook_outcome`] と同じ前提。
    pub unsafe fn write_install_failure(bootstrap: *mut AgentBootstrap, unrestored: u32) {
        // SAFETY: 呼び出し側の契約に従う。
        unsafe {
            (*bootstrap).result_unrestored_count = unrestored;
        }
    }
    /// Host 側: 読み戻した復元失敗スロット数。
    pub fn unrestored_count(&self) -> u32 {
        self.result_unrestored_count
    }
    /// DLL 側が COM Factory 関数の設置数を書き戻すためのポインタ経由の記録。
    ///
    /// # Safety
    /// [`AgentBootstrap::write_hook_outcome`] と同じ前提。
    pub unsafe fn write_com_factory_count(bootstrap: *mut AgentBootstrap, count: u32) {
        // SAFETY: 呼び出し側の契約に従う。
        unsafe {
            (*bootstrap).result_com_factory_count = count;
        }
    }
    /// Host 側: 読み戻した COM Factory 関数の設置数。
    pub fn com_factory_count(&self) -> u32 {
        self.result_com_factory_count
    }
    /// DLL 側が WinRT アクティベーション関数の設置数を書き戻すための
    /// ポインタ経由の記録。
    ///
    /// # Safety
    /// [`AgentBootstrap::write_hook_outcome`] と同じ前提。
    pub unsafe fn write_winrt_activation_count(bootstrap: *mut AgentBootstrap, count: u32) {
        // SAFETY: 呼び出し側の契約に従う。
        unsafe {
            (*bootstrap).result_winrt_activation_count = count;
        }
    }
    /// Host 側: 読み戻した WinRT アクティベーション関数の設置数。
    pub fn winrt_activation_count(&self) -> u32 {
        self.result_winrt_activation_count
    }
    /// DLL 側が内部 API (Nt*) の設置数を書き戻すためのポインタ経由の記録。
    ///
    /// # Safety
    /// [`AgentBootstrap::write_hook_outcome`] と同じ前提。
    pub unsafe fn write_internal_hook_count(bootstrap: *mut AgentBootstrap, count: u32) {
        // SAFETY: 呼び出し側の契約に従う。
        unsafe {
            (*bootstrap).result_internal_hook_count = count;
        }
    }
    /// Host 側: 読み戻した内部 API (Nt*) の設置数。
    pub fn internal_hook_count(&self) -> u32 {
        self.result_internal_hook_count
    }
    /// DLL 側がコールバック検出フックの設置数を書き戻すためのポインタ経由の記録。
    ///
    /// # Safety
    /// [`AgentBootstrap::write_hook_outcome`] と同じ前提。
    pub unsafe fn write_callback_hook_count(bootstrap: *mut AgentBootstrap, count: u32) {
        // SAFETY: 呼び出し側の契約に従う。
        unsafe {
            (*bootstrap).result_callback_hook_count = count;
        }
    }
    /// Host 側: 読み戻したコールバック検出フックの設置数。
    pub fn callback_hook_count(&self) -> u32 {
        self.result_callback_hook_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_new_validate() {
        let cfg = RingConfig::new(64, 4096);
        let b = AgentBootstrap::new(42, cfg, &[(111, 222), (333, 444)]);
        assert_eq!(b.ring_count, 2);
        assert_eq!(b.validate(), Ok(cfg));
        assert_eq!(b.ring_mapping_handle(1), 333);
        assert_eq!(b.ring_space_handle(0), 222);
    }

    #[test]
    fn validate_rejects_bad_inputs() {
        let cfg = RingConfig::new(64, 4096);
        let mut b = AgentBootstrap::new(1, cfg, &[(1, 2)]);
        b.version = 99;
        assert_eq!(b.validate(), Err(BootstrapError::BadVersion(99)));
        let mut b = AgentBootstrap::new(1, cfg, &[]);
        assert_eq!(b.validate(), Err(BootstrapError::NoRings));
        b.ring_count = 1; // ハンドル未設定
        assert_eq!(b.validate(), Err(BootstrapError::MissingMappingHandle(0)));
        let mut b = AgentBootstrap::new(1, cfg, &[(1, 2)]);
        b.payload_capacity = 0;
        assert_eq!(b.validate(), Err(BootstrapError::BadRingConfig));
        let mut b = AgentBootstrap::new(1, cfg, &[(1, 2)]);
        b.ring_count = (MAX_BOOTSTRAP_RINGS + 1) as u32;
        assert_eq!(
            b.validate(),
            Err(BootstrapError::TooManyRings(b.ring_count))
        );
    }

    #[test]
    fn layout_is_fixed_size() {
        // repr(C) の固定レイアウトであること（プロセス間受け渡しの前提）
        assert_eq!(
            std::mem::size_of::<AgentBootstrap>(),
            // フィールド合計 616 (8 バイト整列)。
            // v5 で末尾に record_runtime_apis (u32) を追加したため、
            // v4 の 584 から 592 になった。v6 で末尾に com_options (u32)
            // と result_com_factory_count (u32) を追加したため 600。
            // v7 で末尾に result_winrt_activation_count (u32) を追加したが、
            // 8 個目の u32 が v6 の末尾パディング 4 バイト分に収まるため、
            // サイズは 600 のまま。v8 で末尾に detailed_mode (u32) と
            // result_internal_hook_count (u32) を追加したため 608。
            // v9 で末尾に result_callback_hook_count (u32) を追加したため
            // 612 になるが、8 バイト整列のパディングでサイズは 616。
            4 + 4
                + 8 * 6
                + 8 * (MAX_BOOTSTRAP_RINGS * 2)
                + 4
                + 4
                + 4
                + 4
                + 4
                + 4
                + 4
                + 4
                + 4
                + 4
                + 4
                + 4
        );
    }

    #[test]
    fn detailed_mode_defaults_to_disabled() {
        // L15: v8 の detailed_mode は既定 0（無効）で、validate は通る。
        // 内部フックの設置数も既定 0。
        let cfg = RingConfig::new(64, 4096);
        let b = AgentBootstrap::new(1, cfg, &[(1, 2)]);
        assert_eq!(b.version, BOOTSTRAP_VERSION);
        assert_eq!(b.detailed_mode, 0);
        assert_eq!(b.internal_hook_count(), 0);
        b.validate().expect("default bootstrap validates");
    }

    #[test]
    fn order_global_defaults_to_disabled() {
        // L11: v4 の order_global は既定 0（無効）で、validate は通る。
        let cfg = RingConfig::new(64, 4096);
        let b = AgentBootstrap::new(1, cfg, &[(1, 2)]);
        assert_eq!(b.version, BOOTSTRAP_VERSION);
        assert_eq!(b.order_global, 0);
        assert!(b.validate().is_ok());
        let mut b = AgentBootstrap::new(1, cfg, &[(1, 2)]);
        b.order_global = 1;
        assert!(b.validate().is_ok());
    }

    #[test]
    fn record_runtime_apis_defaults_to_disabled() {
        // L23: v5 の record_runtime_apis は既定 0（記録しない）で、
        // validate は通る。
        let cfg = RingConfig::new(64, 4096);
        let b = AgentBootstrap::new(1, cfg, &[(1, 2)]);
        assert_eq!(b.version, BOOTSTRAP_VERSION);
        assert_eq!(b.record_runtime_apis, 0);
        assert!(b.validate().is_ok());
        let mut b = AgentBootstrap::new(1, cfg, &[(1, 2)]);
        b.record_runtime_apis = 1;
        assert!(b.validate().is_ok());
    }

    #[test]
    fn com_options_default_to_disabled_and_factory_count_roundtrip() {
        // L02: v6 の com_options は既定 0（診断用 QI は無効）で、
        // validate は通る。Factory 設置数の書き戻しと読み戻し。
        let cfg = RingConfig::new(64, 4096);
        let b = AgentBootstrap::new(1, cfg, &[(1, 2)]);
        assert_eq!(b.version, BOOTSTRAP_VERSION);
        assert_eq!(b.com_options, 0);
        assert_eq!(b.com_factory_count(), 0);
        assert!(b.validate().is_ok());
        let mut b = AgentBootstrap::new(1, cfg, &[(1, 2)]);
        b.com_options = 1;
        assert!(b.validate().is_ok());
        unsafe { AgentBootstrap::write_com_factory_count(&mut b, 2) };
        assert_eq!(b.com_factory_count(), 2);
    }

    #[test]
    fn winrt_activation_count_roundtrip() {
        // L14: v7 の result_winrt_activation_count は既定 0 で、
        // 書き戻しと読み戻しができる。
        let cfg = RingConfig::new(64, 4096);
        let b = AgentBootstrap::new(1, cfg, &[(1, 2)]);
        assert_eq!(b.version, BOOTSTRAP_VERSION);
        assert_eq!(b.winrt_activation_count(), 0);
        assert!(b.validate().is_ok());
        let mut b = AgentBootstrap::new(1, cfg, &[(1, 2)]);
        unsafe { AgentBootstrap::write_winrt_activation_count(&mut b, 2) };
        assert_eq!(b.winrt_activation_count(), 2);
    }

    #[test]
    fn callback_hook_count_roundtrip() {
        // L16: v9 の result_callback_hook_count は既定 0 で、
        // 書き戻しと読み戻しができる。
        let cfg = RingConfig::new(64, 4096);
        let b = AgentBootstrap::new(1, cfg, &[(1, 2)]);
        assert_eq!(b.version, BOOTSTRAP_VERSION);
        assert_eq!(b.callback_hook_count(), 0);
        assert!(b.validate().is_ok());
        let mut b = AgentBootstrap::new(1, cfg, &[(1, 2)]);
        unsafe { AgentBootstrap::write_callback_hook_count(&mut b, 4) };
        assert_eq!(b.callback_hook_count(), 4);
    }

    #[test]
    fn install_failure_writeback_roundtrip() {
        // DLL 側の書き戻しと Host 側の読み戻し (レビュー第5回 #8)。
        let mut b = AgentBootstrap::default();
        assert_eq!(b.unrestored_count(), 0);
        unsafe { AgentBootstrap::write_install_failure(&mut b, 2) };
        assert_eq!(b.unrestored_count(), 2);
    }

    #[test]
    fn hook_outcome_writeback_roundtrip() {
        // DLL 側の書き戻しと Host 側の読み戻し (レビュー #4 の #8)。
        let mut b = AgentBootstrap::default();
        assert_eq!(b.hook_outcome(), (0, 0));
        unsafe { AgentBootstrap::write_hook_outcome(&mut b, 0, 4) };
        assert_eq!(b.hook_outcome(), (0, 4));
        unsafe { AgentBootstrap::write_hook_outcome(&mut b, 3, 1) };
        assert_eq!(b.hook_outcome(), (3, 1));
    }
}
