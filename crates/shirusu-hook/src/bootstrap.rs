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

pub const BOOTSTRAP_VERSION: u32 = 1;
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
            4 + 4 + 8 * 6 + 8 * (MAX_BOOTSTRAP_RINGS * 2)
        );
    }
}
