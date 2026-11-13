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
/// v10: bounded per-API IAT and Inline installation evidence.
/// v11: freeze evidence capacity independently of API_COUNT.
/// v12: distinguish COM method return kinds from factory HRESULT payloads.
/// v13: 8,192 evidence slots for the IAT-only broad tier (IDs up to
/// MAX_API_ID); Inline reasons are 1-byte codes of [`INLINE_REASONS`].
/// v14: Hook evidence leaves the fixed structure. Host passes the address and
/// capacity of a separate record area ([`HookEvidenceRecord`]); Agent writes
/// one record per reported API and the record count. The structure size no
/// longer depends on the number of APIs.
/// v15: API Catalog Fingerprint の照合欄と Capture Policy（Agent 側で
/// 記録する API の選択）を v14 の末尾に追加した。
pub const BOOTSTRAP_VERSION: u32 = 15;
/// Initialization published hooks but could not complete installation. Only
/// this failure status authorizes Host to retry this attempt's shutdown.
pub const INIT_HOOK_FAILED: u32 = 3;
/// Agent DLL の API Catalog Fingerprint が Host のものと一致しない。
/// フックを設置する前に拒否するため、Host は後片付けなしで失敗にしてよい。
pub const INIT_CATALOG_MISMATCH: u32 = 7;
/// Capture Policy の API 一覧を読めない、または不正な値を含む。
pub const INIT_BAD_CAPTURE_POLICY: u32 = 8;

/// Capture Policy: 全 API を記録する（`full` / `profile` / `detailed`）。
pub const CAPTURE_POLICY_ALL: u32 = 0;
/// Capture Policy: `capture_api_ids` に並べた API だけを記録する
/// （`filtered`）。範囲外の API は Agent が素通しにし、観測しない。
pub const CAPTURE_POLICY_SELECTED: u32 = 1;
/// Capture Policy の API 一覧の上限（対象プロセスから読む量の上限）。
pub const MAX_CAPTURE_API_IDS: u32 = 1 << 16;
/// `result_evidence_ready`: Agent wrote every record it had.
pub const EVIDENCE_COMPLETE: u32 = 1;
/// `result_evidence_ready`: the record area was too small or absent; Host must
/// treat all installation evidence as unknown rather than a partial claim.
pub const EVIDENCE_TRUNCATED: u32 = 2;

/// IAT evidence codes of [`HookEvidenceRecord::iat`]. Code `n` names
/// `IAT_REASONS[n]`; 0 means unknown. Append only.
pub const IAT_REASONS: &[&str] = &[
    "unknown",
    "installed",
    "not-imported-in-main-module",
    "not-attempted-internal-api",
    "noncanonical-import-preserved",
    "partially-installed-noncanonical-import-preserved",
];
pub const IAT_INSTALLED: u8 = 1;
pub const IAT_NOT_IMPORTED: u8 = 2;
pub const IAT_INTERNAL: u8 = 3;
pub const IAT_PRESERVED: u8 = 4;
pub const IAT_PARTIAL_PRESERVED: u8 = 5;

/// One API's installation result, written by Agent into the record area that
/// Host allocated and named in [`AgentBootstrap::evidence_address`]. The
/// record carries codes only; names, levels and reason strings come from the
/// API table, so the format does not change when APIs are added.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HookEvidenceRecord {
    pub api_id: u32,
    /// Code of [`IAT_REASONS`].
    pub iat: u8,
    /// Code of [`INLINE_REASONS`] (1-based; 0 = not written).
    pub inline: u8,
    pub reserved: u16,
}
/// Inline evidence codes. Code `n` (1-based) names `INLINE_REASONS[n - 1]`;
/// 0 means not written. Append only: a code keeps its meaning across builds.
/// A reason outside this table is reported as `unknown`, never truncated
/// into a different claim.
pub const INLINE_REASONS: &[&str] = &[
    "unknown",
    "installed",
    "installed-restoration-pending",
    "detailed-mode-disabled",
    "not-exported",
    "read-failed",
    "already-hooked",
    "too-short",
    "decode-failed",
    "unrelocatable",
    "invalid-bitness",
    "alloc-failed",
    "flush-failed",
    "near-relay-unavailable",
    "protect-failed",
    "retained-trampoline-limit",
    "target-changed",
    "thread-context-unavailable",
    "thread-in-target",
    "thread-set-changed",
    "thread-suspend-failed",
    "trampoline-too-large",
    "not-attempted-iat-only-scope",
    "installed-without-caller-boundary",
];

/// Code of an Inline reason for [`HookEvidenceRecord::inline`].
pub fn inline_reason_code(reason: &str) -> u8 {
    let index = INLINE_REASONS
        .iter()
        .position(|r| *r == reason)
        .unwrap_or(0);
    (index + 1) as u8
}
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
    /// 0 = not written, [`EVIDENCE_COMPLETE`] or [`EVIDENCE_TRUNCATED`].
    pub result_evidence_ready: u32,
    /// Target-process address of the Host-allocated record area. 0 = none.
    pub evidence_address: u64,
    /// Number of [`HookEvidenceRecord`] slots at `evidence_address`.
    pub evidence_capacity: u32,
    /// Number of records Agent wrote (at most `evidence_capacity`).
    pub result_evidence_count: u32,
    /// Capture Policy (v15): [`CAPTURE_POLICY_ALL`] または
    /// [`CAPTURE_POLICY_SELECTED`]。Agent が記録する API の範囲を決める
    /// （Trace の保存形式を決める Trace Output Policy とは別）。
    pub capture_policy: u32,
    /// `capture_api_ids` の要素数（0 なら API 表の API を 1 つも記録しない）。
    pub capture_api_count: u32,
    /// Capture Policy の API 一覧（対象プロセス内の `u32` 配列のアドレス）。
    /// `CAPTURE_POLICY_SELECTED` のときだけ使う。
    pub capture_api_ids: u64,
    /// 初期化結果 (v15): Agent が実際に記録対象とした API 表の API 数。
    pub result_capture_api_count: u32,
    /// 予約（0）。後続の配列を 8 バイト境界に揃え、暗黙の詰め物を作らない。
    pub reserved_v15: u32,
    /// Host が期待する API Catalog Fingerprint (v15)。Agent は自分の
    /// Fingerprint と比べ、一致しなければフックを設置せずに
    /// [`INIT_CATALOG_MISMATCH`] を返す。
    pub api_catalog_fingerprint: [u8; 32],
    /// 初期化結果 (v15): Agent 自身の API Catalog Fingerprint。照合の
    /// 成否に関係なく書き戻す（不一致の報告に使う）。
    pub result_api_catalog_fingerprint: [u8; 32],
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
            capture_policy: CAPTURE_POLICY_ALL,
            capture_api_ids: 0,
            capture_api_count: 0,
            result_capture_api_count: 0,
            api_catalog_fingerprint: [0; 32],
            result_evidence_ready: 0,
            evidence_address: 0,
            evidence_capacity: 0,
            result_evidence_count: 0,
            reserved_v15: 0,
            result_api_catalog_fingerprint: [0; 32],
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
    BadCapturePolicy,
}

impl AgentBootstrap {
    /// Agent side: copy `records` into the Host-named record area and publish
    /// the count. A missing or too small area marks the report truncated, so
    /// Host never takes a partial list for the complete one.
    ///
    /// # Safety
    /// `bootstrap` must be writable, and a nonzero `evidence_address` must
    /// name `evidence_capacity` writable records in this process (Host's
    /// allocation contract, valid until initialization returns).
    pub unsafe fn write_hook_evidence(
        bootstrap: *mut AgentBootstrap,
        records: &[HookEvidenceRecord],
    ) {
        // SAFETY: caller contract.
        unsafe {
            let address = usize::try_from((*bootstrap).evidence_address).unwrap_or(0);
            let capacity = (*bootstrap).evidence_capacity as usize;
            if address == 0 || records.len() > capacity {
                (*bootstrap).result_evidence_count = 0;
                (*bootstrap).result_evidence_ready = EVIDENCE_TRUNCATED;
                return;
            }
            std::ptr::copy_nonoverlapping(
                records.as_ptr(),
                address as *mut HookEvidenceRecord,
                records.len(),
            );
            (*bootstrap).result_evidence_count = records.len() as u32;
            (*bootstrap).result_evidence_ready = EVIDENCE_COMPLETE;
        }
    }

    /// Number of records Host should read back, validated against the
    /// capacity Host itself allocated (`host_capacity`). None = unknown.
    pub fn evidence_record_count(&self, host_capacity: u32) -> Option<usize> {
        (self.version == BOOTSTRAP_VERSION
            && self.result_evidence_ready == EVIDENCE_COMPLETE
            && self.result_evidence_count <= host_capacity)
            .then_some(self.result_evidence_count as usize)
    }

    /// Validate records read from the record area before producing portable
    /// Trace evidence. Unknown API IDs, duplicate IDs and unknown codes reject
    /// the whole report. APIs without a record have no evidence (unknown).
    pub fn hook_evidence(
        records: &[HookEvidenceRecord],
    ) -> Option<Vec<shirusu_trace::proto::HookEvidence>> {
        let mut seen = std::collections::HashSet::with_capacity(records.len());
        let mut evidence = Vec::with_capacity(records.len() * 2);
        for record in records {
            let api = crate::api::api_by_id(record.api_id)?;
            if !seen.insert(record.api_id) || record.reserved != 0 {
                return None;
            }
            let iat_reason = *IAT_REASONS.get(record.iat as usize)?;
            // A broad-tier API absent from the main module's imports has no
            // installation fact beyond its scope; Agent normally omits it.
            if crate::api::is_iat_only_api(api.api_id) && record.iat == IAT_NOT_IMPORTED {
                continue;
            }
            let code = record.inline as usize;
            let inline_reason = *INLINE_REASONS.get(code.checked_sub(1)?)?;
            for (method, reason, scope) in [
                ("iat", iat_reason, "main-module-at-initialization"),
                (
                    "inline",
                    inline_reason,
                    "resolved-exports-at-initialization",
                ),
            ] {
                evidence.push(shirusu_trace::proto::HookEvidence {
                    api_id: api.api_id,
                    module: api.module.into(),
                    function: api.function.into(),
                    method: method.into(),
                    outcome: if matches!(
                        reason,
                        "partially-installed-noncanonical-import-preserved"
                            | "installed-restoration-pending"
                            | "installed-without-caller-boundary"
                    ) {
                        "partial"
                    } else if reason == "installed" {
                        "installed"
                    } else if reason == "unknown" {
                        "unknown"
                    } else {
                        "not-installed"
                    }
                    .into(),
                    reason: reason.into(),
                    scope: scope.into(),
                    semantic_level: api.level.into(),
                    semantic_detail: api.level_note.into(),
                });
            }
        }
        Some(evidence)
    }

    /// Host 側の組み立て。`rings` は (mapping, space_available) の
    /// ハンドル値ペア（対象プロセス内で有効な値）。
    pub fn new(session_id: u64, config: RingConfig, rings: &[(u64, u64)]) -> Self {
        let mut b = Self {
            api_catalog_fingerprint: shirusu_api_catalog::fingerprint::catalog_fingerprint(),
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
        for (i, handle) in self
            .mapping_handles
            .iter()
            .take(self.ring_count as usize)
            .enumerate()
        {
            if *handle == 0 {
                return Err(BootstrapError::MissingMappingHandle(i as u32));
            }
        }
        match self.capture_policy {
            CAPTURE_POLICY_ALL if self.capture_api_count == 0 && self.capture_api_ids == 0 => {}
            CAPTURE_POLICY_SELECTED
                if self.capture_api_count <= MAX_CAPTURE_API_IDS
                    && (self.capture_api_count == 0 || self.capture_api_ids != 0) => {}
            _ => return Err(BootstrapError::BadCapturePolicy),
        }
        let (d, p) = (self.descriptor_capacity, self.payload_capacity);
        if d < 2 || p < 16 || d > (1 << 24) || p > (1 << 32) {
            return Err(BootstrapError::BadRingConfig);
        }
        let d = usize::try_from(d).map_err(|_| BootstrapError::BadRingConfig)?;
        let p = usize::try_from(p).map_err(|_| BootstrapError::BadRingConfig)?;
        let len = d
            .checked_mul(64)
            .and_then(|n| n.checked_add(shirusu_transport::layout::CONTROL_SIZE))
            .and_then(|n| n.checked_add(p))
            .ok_or(BootstrapError::BadRingConfig)?;
        if len > isize::MAX as usize {
            return Err(BootstrapError::BadRingConfig);
        }
        Ok(RingConfig::new(d, p))
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
    fn invalid_small_capacities_return_error_without_panicking() {
        for (d, p) in [(1, 4096), (64, 1), (64, 15)] {
            let mut b = AgentBootstrap::new(1, RingConfig::new(64, 4096), &[(1, 2)]);
            b.descriptor_capacity = d;
            b.payload_capacity = p;
            assert_eq!(b.validate(), Err(BootstrapError::BadRingConfig));
        }
    }

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

    fn record(api_id: u32, iat: u8, inline: &str) -> HookEvidenceRecord {
        HookEvidenceRecord {
            api_id,
            iat,
            inline: inline_reason_code(inline),
            reserved: 0,
        }
    }

    #[test]
    fn hook_evidence_rejects_incomplete_or_malformed_reports() {
        let mut b = AgentBootstrap::default();
        assert!(b.evidence_record_count(16).is_none(), "not written");
        b.result_evidence_ready = EVIDENCE_TRUNCATED;
        assert!(b.evidence_record_count(16).is_none());
        b.result_evidence_ready = EVIDENCE_COMPLETE;
        b.result_evidence_count = 17;
        assert!(b.evidence_record_count(16).is_none(), "over Host capacity");
        b.result_evidence_count = 16;
        assert_eq!(b.evidence_record_count(16), Some(16));

        let mut records: Vec<_> = crate::api::api_table()
            .map(|api| record(api.api_id, IAT_NOT_IMPORTED, "installed"))
            .collect();
        let evidence = AgentBootstrap::hook_evidence(&records).unwrap();
        // Non-imported broad-tier APIs are summarized away.
        assert_eq!(
            evidence.len(),
            (crate::api::API_COUNT - crate::api::BROAD_API_TABLE.len()) * 2
        );
        assert!(evidence
            .iter()
            .filter(|h| h.method == "inline")
            .all(|h| h.outcome == "installed"));
        for (value, outcome, reason) in [
            (
                IAT_PRESERVED,
                "not-installed",
                "noncanonical-import-preserved",
            ),
            (
                IAT_PARTIAL_PRESERVED,
                "partial",
                "partially-installed-noncanonical-import-preserved",
            ),
        ] {
            records[0].iat = value;
            let report = AgentBootstrap::hook_evidence(&records).unwrap();
            let iat = report
                .iter()
                .find(|h| h.api_id == 1 && h.method == "iat")
                .unwrap();
            assert_eq!(iat.outcome, outcome);
            assert_eq!(iat.reason, reason);
        }
        records[0].inline = inline_reason_code("installed-restoration-pending");
        let report = AgentBootstrap::hook_evidence(&records).unwrap();
        let inline = report
            .iter()
            .find(|h| h.api_id == 1 && h.method == "inline")
            .unwrap();
        assert_eq!(inline.outcome, "partial");
        assert_eq!(inline.reason, "installed-restoration-pending");
        // L23: recorded, but without the caller boundary of the standard mode.
        records[0].inline = inline_reason_code("installed-without-caller-boundary");
        let report = AgentBootstrap::hook_evidence(&records).unwrap();
        let inline = report
            .iter()
            .find(|h| h.api_id == 1 && h.method == "inline")
            .unwrap();
        assert_eq!(inline.outcome, "partial");
        assert_eq!(inline.reason, "installed-without-caller-boundary");
        records[0].inline = inline_reason_code("installed-restoration-pending");
        let reject = |mutate: &dyn Fn(&mut Vec<HookEvidenceRecord>)| {
            let mut bad = records.clone();
            mutate(&mut bad);
            AgentBootstrap::hook_evidence(&bad).is_none()
        };
        assert!(reject(&|r| r[0].inline = 0xff));
        assert!(reject(&|r| r[0].inline = 0));
        assert!(reject(&|r| r[0].iat = 255));
        assert!(reject(&|r| r[0].reserved = 1));
        assert!(reject(&|r| r[0].api_id = 0));
        assert!(reject(&|r| r[0].api_id = u32::MAX));
        assert!(reject(&|r| {
            let first = r[0];
            r.push(first)
        }));
        // A subset is valid: APIs without a record simply have no evidence.
        let subset = AgentBootstrap::hook_evidence(&records[..1]).unwrap();
        assert_eq!(subset.len(), 2);
        assert!(AgentBootstrap::hook_evidence(&[]).unwrap().is_empty());
    }

    #[test]
    fn write_hook_evidence_never_overflows_the_host_area() {
        let records = [
            record(1, IAT_INSTALLED, "installed"),
            record(2, IAT_NOT_IMPORTED, "too-short"),
        ];
        let mut area = [HookEvidenceRecord::default(); 3];
        let mut b = AgentBootstrap {
            evidence_address: area.as_mut_ptr() as usize as u64,
            evidence_capacity: 2,
            ..AgentBootstrap::default()
        };
        // SAFETY: `area` holds 3 >= capacity records.
        unsafe { AgentBootstrap::write_hook_evidence(&mut b, &records) };
        assert_eq!(b.result_evidence_ready, EVIDENCE_COMPLETE);
        assert_eq!(b.evidence_record_count(2), Some(2));
        assert_eq!(&area[..2], &records);
        assert_eq!(area[2], HookEvidenceRecord::default());

        // Too many records: nothing is claimed, nothing is written past capacity.
        let mut small = [HookEvidenceRecord::default(); 1];
        b.evidence_address = small.as_mut_ptr() as usize as u64;
        b.evidence_capacity = 1;
        // SAFETY: capacity 1 matches `small`; the call must not write 2.
        unsafe { AgentBootstrap::write_hook_evidence(&mut b, &records) };
        assert_eq!(b.result_evidence_ready, EVIDENCE_TRUNCATED);
        assert!(b.evidence_record_count(1).is_none());
        assert_eq!(small[0], HookEvidenceRecord::default());

        b.evidence_address = 0;
        // SAFETY: a zero address is never dereferenced.
        unsafe { AgentBootstrap::write_hook_evidence(&mut b, &[]) };
        assert_eq!(b.result_evidence_ready, EVIDENCE_TRUNCATED);
    }

    #[test]
    fn inline_reason_codes_round_trip_and_never_invent_claims() {
        assert!(INLINE_REASONS.len() < u8::MAX as usize);
        let unique: std::collections::HashSet<_> = INLINE_REASONS.iter().collect();
        assert_eq!(unique.len(), INLINE_REASONS.len());
        for (index, reason) in INLINE_REASONS.iter().enumerate() {
            assert_eq!(inline_reason_code(reason) as usize, index + 1);
        }
        assert_eq!(
            INLINE_REASONS[inline_reason_code("future-reason") as usize - 1],
            "unknown"
        );
        assert_eq!(IAT_REASONS[IAT_INSTALLED as usize], "installed");
        assert_eq!(
            IAT_REASONS[IAT_PARTIAL_PRESERVED as usize],
            "partially-installed-noncanonical-import-preserved"
        );
        // Every broad-tier API reports its scope instead of an Inline result.
        let broad = crate::api::BROAD_API_TABLE[0].api_id;
        let records: Vec<_> = crate::api::api_table()
            .map(|api| {
                if crate::api::is_iat_only_api(api.api_id) {
                    let iat = if api.api_id == broad {
                        IAT_INSTALLED
                    } else {
                        IAT_NOT_IMPORTED
                    };
                    record(api.api_id, iat, "not-attempted-iat-only-scope")
                } else {
                    record(api.api_id, IAT_NOT_IMPORTED, "installed")
                }
            })
            .collect();
        let evidence = AgentBootstrap::hook_evidence(&records).unwrap();
        assert_eq!(
            evidence
                .iter()
                .filter(|h| crate::api::is_iat_only_api(h.api_id))
                .count(),
            2,
            "only the imported broad API is listed"
        );
        let of = |method: &str| {
            evidence
                .iter()
                .find(|h| h.api_id == broad && h.method == method)
                .unwrap()
                .clone()
        };
        assert_eq!(of("iat").outcome, "installed");
        assert_eq!(of("inline").outcome, "not-installed");
        assert_eq!(of("inline").reason, "not-attempted-iat-only-scope");
        assert_eq!(of("inline").semantic_detail, crate::api::BROAD_LEVEL_NOTE);
    }

    #[test]
    fn layout_is_fixed_size_and_independent_of_api_count() {
        assert_eq!(std::mem::size_of::<AgentBootstrap>(), 720);
        assert_eq!(
            std::mem::offset_of!(AgentBootstrap, result_evidence_ready),
            612
        );
        assert_eq!(std::mem::offset_of!(AgentBootstrap, evidence_address), 616);
        // v15 の欄は v14 の末尾 (632) に置き、暗黙のパディングを作らない
        // （Host は構造体をバイト列として書き込むため、未初期化の詰め物を渡さない）。
        assert_eq!(std::mem::offset_of!(AgentBootstrap, capture_policy), 632);
        assert_eq!(std::mem::offset_of!(AgentBootstrap, capture_api_count), 636);
        assert_eq!(std::mem::offset_of!(AgentBootstrap, capture_api_ids), 640);
        assert_eq!(
            std::mem::offset_of!(AgentBootstrap, result_capture_api_count),
            648
        );
        assert_eq!(
            std::mem::offset_of!(AgentBootstrap, api_catalog_fingerprint),
            656
        );
        assert_eq!(
            std::mem::offset_of!(AgentBootstrap, result_api_catalog_fingerprint),
            688
        );
        assert_eq!(std::mem::size_of::<HookEvidenceRecord>(), 8);
        assert_eq!(std::mem::align_of::<HookEvidenceRecord>(), 4);
    }

    #[test]
    fn new_carries_the_host_catalog_fingerprint_and_full_capture() {
        let b = AgentBootstrap::new(1, RingConfig::new(64, 4096), &[(1, 2)]);
        assert_eq!(
            b.api_catalog_fingerprint,
            shirusu_api_catalog::fingerprint::catalog_fingerprint()
        );
        assert_eq!(b.capture_policy, CAPTURE_POLICY_ALL);
        assert!(b.validate().is_ok());
    }

    #[test]
    fn validate_rejects_inconsistent_capture_policies() {
        let base = AgentBootstrap::new(1, RingConfig::new(64, 4096), &[(1, 2)]);
        let mut b = base;
        b.capture_api_count = 1;
        assert_eq!(b.validate(), Err(BootstrapError::BadCapturePolicy));
        let mut b = base;
        b.capture_policy = 9;
        assert_eq!(b.validate(), Err(BootstrapError::BadCapturePolicy));
        let mut b = base;
        b.capture_policy = CAPTURE_POLICY_SELECTED;
        b.capture_api_count = 2;
        assert_eq!(b.validate(), Err(BootstrapError::BadCapturePolicy));
        b.capture_api_ids = 0x1000;
        assert!(b.validate().is_ok());
        b.capture_api_count = MAX_CAPTURE_API_IDS + 1;
        assert_eq!(b.validate(), Err(BootstrapError::BadCapturePolicy));
        // 空の選択は「API 表の API を記録しない」として有効。
        let mut b = base;
        b.capture_policy = CAPTURE_POLICY_SELECTED;
        assert!(b.validate().is_ok());
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
