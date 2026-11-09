//! R3 回帰 (レビュー指摘): SlotPool::host_reclaim が FREE を公開してから
//! Generation を進めていたため、公開直後に claim した新しい Producer が
//! 旧 Generation を読む競合があった。同じ (index, generation) の handle が
//! 二重に払い出されると、古い handle と新しい handle を世代ガードで
//! 区別できなくなる。
//!
//! このテストは 1 Slot を複数スレッドで claim→detach→confirm→reclaim
//! し続け、払い出された (index, generation) が一度も重複しないことを見る。
//! 失敗したスレッドが Slot を握ったまま死ぬと残りが空き待ちで固まるため、
//! 停止フラグで全スレッドが抜けられるようにしてある (固まること自体が
//! 失敗の現れだが、テストとしては表明で終わらせる)。
//! 競合の決定的な再現は loom モデル (shirusu-loom-tests の
//! loom_slot_reclaim_publishes_generation_before_free) が担い、こちらは
//! 実装そのものに対するストレスとして併用する。

use shirusu_transport::slot::SlotPool;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[test]
fn concurrent_reclaim_claim_never_reissues_generation() {
    let pool = Arc::new(SlotPool::new(1));
    let issued = Arc::new(Mutex::new(HashSet::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut hs = Vec::new();
    for t in 0..4u64 {
        let pool = Arc::clone(&pool);
        let issued = Arc::clone(&issued);
        let stop = Arc::clone(&stop);
        hs.push(std::thread::spawn(move || {
            for _ in 0..3000 {
                let h = loop {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    if let Some(h) = pool.claim(100 + t) {
                        break h;
                    }
                    std::thread::yield_now();
                };
                {
                    let mut set = issued.lock().unwrap();
                    if !set.insert((h.index, h.generation)) {
                        stop.store(true, Ordering::Relaxed);
                        panic!(
                            "generation {} for slot {} issued twice",
                            h.generation, h.index
                        );
                    }
                }
                if !pool.begin_detach(&h)
                    || !pool.host_confirm_ended_and_drained(&h, true, true)
                    || !pool.host_reclaim(&h)
                {
                    stop.store(true, Ordering::Relaxed);
                    panic!("lifecycle step failed for handle {h:?}");
                }
            }
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
}
