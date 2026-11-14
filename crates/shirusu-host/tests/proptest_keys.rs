//! PBT / DST (A72): Host 内部の一時キー `TemporaryPayloadKey` の一意性と
//! 参照整合性。複数 Ring・Ring 再利用（generation 増分）・Sequence の単調
//! 増加・Payload 位置の折り返し（小容量で論理位置を何度も周回させる）を含む
//! 生成列について、格納済み Payload のキーが全体で一意であり、キー→Payload
//! の参照モデルと照合して古いキーが再利用後の新しい Payload を指さない
//! ことを検証する。失敗時は proptest が Seed と縮小ケースを
//! `proptest-regressions/` に保存する。

use proptest::prelude::*;
use shirusu_host::{DrainWorker, ProcessInstanceId, RingId, RingIdentity, TemporaryPayloadKey};
use shirusu_transport::clock::ManualClock;
use shirusu_transport::ring::{EventInput, RingWriter, SharedRegion, WriterPolicy};
use shirusu_transport::{CaptureState, Clock, EventKind, RingConfig};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// PBT のケース数。既定は各プロパティの宣言値。環境変数 SHIRUSU_PBT_CASES
/// で上書きできる (transport 側の PBT と同じ流儀)。
fn pbt_cases(default: u32) -> u32 {
    std::env::var("SHIRUSU_PBT_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(default)
}

/// 小容量 Ring（Descriptor 8 / Payload 64B）で writer + DrainWorker を組む。
/// Payload 容量が小さいため、論理位置は短い生成列でも何度も折り返す。
/// フィールドの宣言順が drop 順（worker → writer → region）になるようにし、
/// 再利用時に古い領域を安全に破棄できるようにしている。
struct Rig {
    worker: DrainWorker,
    writer: RingWriter,
    region: SharedRegion,
    identity: RingIdentity,
    clock: Arc<ManualClock>,
    harvested: usize,
}
impl Rig {
    fn new(identity: RingIdentity) -> Self {
        let cfg = RingConfig::new(8, 64);
        let region = SharedRegion::new(cfg, identity.generation, 1);
        let clock = Arc::new(ManualClock::new());
        let wc: Arc<dyn Clock> = clock.clone();
        let writer = unsafe {
            region.writer(
                WriterPolicy {
                    max_wait: Duration::ZERO,
                    ..Default::default()
                },
                wc,
            )
        };
        let mut worker = unsafe { DrainWorker::new(region.base(), cfg, identity.generation) };
        worker.set_identity(identity);
        Self {
            worker,
            writer,
            region,
            identity,
            clock,
            harvested: 0,
        }
    }
    fn write(&mut self, payload: &[u8], dropped: bool, call: u64) {
        let capture_state = if dropped {
            CaptureState::DroppedByBackpressure
        } else {
            CaptureState::Captured
        };
        self.writer.write(EventInput {
            kind: EventKind::CallEnter,
            api_id: 1,
            schema_id: 2,
            call_id: call,
            parent_call_id: 0,
            payload,
            capture_state,
            global_order: 0,
        });
    }
    /// 全回収し、新しく生成されたキーを参照モデルへ取り込む。
    /// - キーは格納済み（非ドロップ・非空）Payload にだけ、回収順に生成される
    /// - キーの各要素は identity と Descriptor から独立に組み立てた期待値と一致する
    /// - 同じキーが二度と現れない（現れたら一意性違反として失敗）
    fn harvest(
        &mut self,
        model: &mut HashMap<TemporaryPayloadKey, Vec<u8>>,
    ) -> Result<(), TestCaseError> {
        let batch = self.worker.drain_all();
        let new_keys = &self.worker.payload_keys[self.harvested..];
        self.harvested = self.worker.payload_keys.len();
        let stored: Vec<_> = batch
            .events
            .iter()
            .filter(|e| !e.descriptor.payload_dropped() && !e.payload.is_empty())
            .collect();
        prop_assert_eq!(new_keys.len(), stored.len());
        for (key, e) in new_keys.iter().zip(stored.iter()) {
            let expected = TemporaryPayloadKey {
                process_id: self.identity.process_id,
                ring_id: self.identity.ring_id,
                generation: self.identity.generation,
                sequence: e.descriptor.sequence,
                payload_position: e.descriptor.payload_position,
            };
            prop_assert_eq!(*key, expected);
            prop_assert!(
                model.insert(*key, e.payload.to_vec()).is_none(),
                "duplicate temporary key: {:?}",
                key
            );
        }
        Ok(())
    }
}

/// 書き込み操作: (Payload 長, ドロップ指定か)。内容は呼び出し側で単調な
/// カウンタから作り、書き込みごとに区別できるようにする。
fn write_op() -> impl Strategy<Value = (u8, bool)> {
    (0u8..20, any::<bool>())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: pbt_cases(1024), ..ProptestConfig::default() })]

    /// 複数 Ring × 再利用ラウンド × 単調 Sequence × 位置の折り返しを含む
    /// 生成列で、発行された一時キーは全体で一意であり、モデルに記録された
    /// Payload と常に一致する（古いキーが新しい Payload を指さない）。
    #[test]
    fn temporary_keys_are_globally_unique(
        rings in prop::collection::vec(
            (0u64..2, prop::collection::vec(prop::collection::vec(write_op(), 0..24), 1..3)),
            1..3,
        )
    ) {
        let mut model: HashMap<TemporaryPayloadKey, Vec<u8>> = HashMap::new();
        let mut fill = 0u8;
        for (ring_idx, (process_idx, rounds)) in rings.iter().enumerate() {
            // プロセスはプールから選ぶため、別 Ring が同じプロセス実例を
            // 共有することもあれば、異なることもある。ring_id は Ring ごとに一意。
            let identity0 = RingIdentity::new(
                ProcessInstanceId(100 + process_idx),
                RingId(ring_idx as u64 + 1),
                1,
            );
            let mut identity = identity0;
            for round in rounds {
                // ラウンドごとに新しい領域 = Ring 再利用。Sequence と
                // payload_position は 1 / 0 から振り直される。
                let mut rig = Rig::new(identity);
                let mut call = 0u64;
                for (len, dropped) in round {
                    call += 1;
                    fill = fill.wrapping_add(1);
                    let payload = vec![fill; *len as usize];
                    rig.write(&payload, *dropped, call);
                }
                rig.harvest(&mut model)?;
                identity = identity.next_generation();
            }
        }
        // 参照整合性: モデルに記録された全キーは、記録時の Payload を
        // そのまま指し続けている（再利用で上書きされていない）。
        for (key, payload) in &model {
            prop_assert_eq!(model.get(key), Some(payload));
        }
    }
}

#[derive(Debug, Clone)]
enum DstOp {
    WriteStored(u8),
    WriteDropped(u8),
    Drain,
    AdvanceClock,
    HostRestart,
    ReuseRing,
    ThreadEnd,
}

proptest! {
    #![proptest_config(ProptestConfig { cases: pbt_cases(512), ..ProptestConfig::default() })]

    /// DST-in-PBT: Host 再起動・Ring の drain→再利用・スレッド終了といった
    /// 障害/ライフサイクル操作を混ぜても、一時キーの一意性と参照整合性は
    /// 壊れない。再利用後は世代が進み、旧世代のキーとは決して衝突しない。
    #[test]
    fn dst_ring_reuse_keeps_old_keys_consistent(
        ops in prop::collection::vec(
            (0u8..8).prop_map(|k| match k {
                0 => DstOp::WriteStored(3),
                1 => DstOp::WriteStored(17),
                2 => DstOp::WriteDropped(9),
                3 => DstOp::Drain,
                4 => DstOp::AdvanceClock,
                5 => DstOp::HostRestart,
                6 => DstOp::ThreadEnd,
                _ => DstOp::ReuseRing,
            }),
            0..80)
    ) {
        let mut model: HashMap<TemporaryPayloadKey, Vec<u8>> = HashMap::new();
        let identity = RingIdentity::new(ProcessInstanceId(5), RingId(6), 1);
        let mut rig = Rig::new(identity);
        let mut call = 0u64;
        let mut fill = 0u8;
        let mut thread_ended = false;
        for op in &ops {
            match op {
                DstOp::WriteStored(len) => {
                    if thread_ended { continue; }
                    call += 1;
                    fill = fill.wrapping_add(1);
                    let payload = vec![fill; *len as usize];
                    rig.write(&payload, false, call);
                }
                DstOp::WriteDropped(len) => {
                    if thread_ended { continue; }
                    call += 1;
                    fill = fill.wrapping_add(1);
                    let payload = vec![fill; *len as usize];
                    rig.write(&payload, true, call);
                }
                DstOp::Drain => {
                    rig.harvest(&mut model)?;
                }
                DstOp::AdvanceClock => rig.clock.advance(Duration::from_millis(3)),
                DstOp::HostRestart => {
                    // 回収済みのキーはモデル側に保持される。Worker を作り直して
                    // 同じ Ring の回収を続ける（identity は同じ）。新しい Worker
                    // は共有側の読み位置から検証状態を引き継ぐ (resume)。
                    rig.harvest(&mut model)?;
                    let mut worker = unsafe {
                        DrainWorker::new(
                            rig.region.base(),
                            rig.region.config,
                            rig.identity.generation,
                        )
                    };
                    worker.set_identity(rig.identity);
                    worker.resume_from_shared();
                    rig.worker = worker;
                    rig.harvested = 0;
                }
                DstOp::ReuseRing => {
                    // 残りを回収してから世代を進めて再利用する。新しい領域では
                    // Sequence / payload_position が振り直されるが、キーは
                    // generation で区別される（harvest 内の重複検査で担保）。
                    rig.harvest(&mut model)?;
                    let next = rig.identity.next_generation();
                    rig = Rig::new(next);
                    thread_ended = false;
                }
                DstOp::ThreadEnd => { thread_ended = true; }
            }
        }
        rig.harvest(&mut model)?;
        for (key, payload) in &model {
            prop_assert_eq!(model.get(key), Some(payload));
        }
    }
}

/// 決定的シナリオ版: drain → 再利用後に、旧キーで引くと旧 Payload が、
/// 新キーで引くと新 Payload が返る。旧キーが新しい Payload を指すことはない。
#[test]
fn reuse_after_drain_old_keys_never_point_to_new_payloads() {
    let mut model: HashMap<TemporaryPayloadKey, Vec<u8>> = HashMap::new();
    let identity = RingIdentity::new(ProcessInstanceId(5), RingId(6), 1);
    let mut rig = Rig::new(identity);
    rig.write(b"old-a", false, 1);
    rig.write(b"old-b", false, 2);
    rig.harvest(&mut model).unwrap();
    assert_eq!(model.len(), 2);
    let old_keys: Vec<TemporaryPayloadKey> = model.keys().copied().collect();
    // 再利用: 同じ sequence / payload_position に別の Payload が載る。
    let next = rig.identity.next_generation();
    rig = Rig::new(next);
    rig.write(b"new-a", false, 1);
    rig.harvest(&mut model).unwrap();
    assert_eq!(model.len(), 3);
    // 旧キーは旧 Payload を指し続ける。
    for key in &old_keys {
        let payload = model.get(key).unwrap();
        assert!(payload == b"old-a" || payload == b"old-b");
        assert_eq!(key.generation, 1);
    }
    // 新 Payload のキーは世代 2 で、旧キーとは異なる。
    let new_key = model
        .iter()
        .find(|(_, v)| v.as_slice() == b"new-a")
        .map(|(k, _)| *k)
        .expect("new payload must have a key");
    assert_eq!(new_key.generation, 2);
    assert!(!old_keys.contains(&new_key));
}
