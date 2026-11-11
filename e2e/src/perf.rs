//! 性能目標の判定ロジック (L10)。純粋関数だけを置く。測定値そのものは
//! `e2e/src/bin/shirusu-perf-bench.rs` が出し、ここは基準値・倍率・
//! 損益分岐の計算と判定だけを担う。ベンチ本体の数値が変わっても、判定の
//! 意味はここで固定する。
//!
//! 根拠 (overview「記録モードと性能目標」節):
//! - 代表的な GUI ワークロードで実行時間の増加を 3 倍以内、高負荷の
//!   ケースで 5 倍以内を開発中の評価基準とする。保証値ではない。
//! - API 一件あたりの追加遅延、記録スループット、バッファ使用率も別に測る。
//!   短い API (`GetLastError` 的) と数ミリ秒かかる I/O では Hook の相対的な
//!   負荷が大きく異なるため、倍率だけでは判断できない。
//! - `full` は間引かないモードだが記録を保証するモードではない。欠落したら
//!   Trace は `incomplete` 扱いになる。

use shirusu_transport::layout::usage_percent;

/// GUI ワークロードの実行時間増加の上限（開発中の評価基準。保証値ではない）。
pub const GUI_RATIO_LIMIT: f64 = 3.0;
/// 高負荷ケースの実行時間増加の上限（同上）。
pub const HIGH_LOAD_RATIO_LIMIT: f64 = 5.0;

/// 測定するワークロードの種類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadKind {
    /// 代表的な GUI ワークロード。倍率の上限は 3 倍。
    GuiMix,
    /// 高負荷のケース。倍率の上限は 5 倍。
    HighLoad,
}

impl WorkloadKind {
    /// このワークロードに適用する倍率上限。
    pub fn ratio_limit(self) -> f64 {
        match self {
            WorkloadKind::GuiMix => GUI_RATIO_LIMIT,
            WorkloadKind::HighLoad => HIGH_LOAD_RATIO_LIMIT,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            WorkloadKind::GuiMix => "gui-mix",
            WorkloadKind::HighLoad => "high-load",
        }
    }
}

/// ワークロードの呼び出しクラス 1 件。`share` は呼び出し全体に占める割合
/// （全クラスの合計は 1.0）。`api_cost_ns` は API 本体のモデル化コスト
/// （Linux では実 Windows API を呼べないため、校正済みスピンで置き換える。
/// ベンチが校正値を報告する）。`payload_bytes` は記録する Payload の大きさ。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CallClass {
    pub share: f64,
    pub api_cost_ns: u64,
    pub payload_bytes: usize,
}

/// 決定的な合成ワークロードの仕様。呼び出しクラスの列で定義する。
#[derive(Debug, Clone, PartialEq)]
pub struct WorkloadSpec {
    pub kind: WorkloadKind,
    pub classes: Vec<CallClass>,
}

impl WorkloadSpec {
    /// 1 呼び出しあたりの API 本体コストの加重平均 (ns)。
    pub fn expected_api_cost_ns_per_call(&self) -> f64 {
        self.classes
            .iter()
            .map(|c| c.share * c.api_cost_ns as f64)
            .sum()
    }

    /// 1 呼び出しあたりの記録イベント数。enter + leave の 2 件。
    pub fn events_per_call(&self) -> u64 {
        2
    }
}

/// 代表的な GUI ワークロード (L10): 短い呼び出し 80%・中程度のファイル I/O
/// 15%・長い I/O 5%。短い呼び出しは `GetLastError` 的な 100ns 級、長い
/// I/O は 500µs 級をモデル化する。
pub fn gui_mix_spec() -> WorkloadSpec {
    WorkloadSpec {
        kind: WorkloadKind::GuiMix,
        classes: vec![
            CallClass {
                share: 0.80,
                api_cost_ns: 100,
                payload_bytes: 0,
            },
            CallClass {
                share: 0.15,
                api_cost_ns: 10_000,
                payload_bytes: 512,
            },
            CallClass {
                share: 0.05,
                api_cost_ns: 500_000,
                payload_bytes: 4096,
            },
        ],
    }
}

/// 高負荷のケース (L10): 短い呼び出し 50%・中程度の I/O 30%・長い I/O 20%。
/// GUI ワークロードより I/O の割合と Payload が大きい。
pub fn high_load_spec() -> WorkloadSpec {
    WorkloadSpec {
        kind: WorkloadKind::HighLoad,
        classes: vec![
            CallClass {
                share: 0.50,
                api_cost_ns: 100,
                payload_bytes: 0,
            },
            CallClass {
                share: 0.30,
                api_cost_ns: 10_000,
                payload_bytes: 4096,
            },
            CallClass {
                share: 0.20,
                api_cost_ns: 1_000_000,
                payload_bytes: 16384,
            },
        ],
    }
}

/// 実行時間の増加倍率 = 記録あり時間 ÷ 記録なし時間。baseline が 0 の場合は
/// 無限大（記録なし時間が測れない＝倍率を定義できない）。
pub fn execution_ratio(recorded_ns: u64, baseline_ns: u64) -> f64 {
    if baseline_ns == 0 {
        return f64::INFINITY;
    }
    recorded_ns as f64 / baseline_ns as f64
}

/// 倍率が上限以下かどうか。上限ちょうどは満たす。
pub fn meets_criterion(ratio: f64, limit: f64) -> bool {
    ratio <= limit
}

/// 1 呼び出しあたりの記録コストから、倍率が上限とちょうど等しくなる API 本体
/// コスト（損益分岐）を返す。ratio = (api + record) / api = limit より
/// api = record / (limit - 1)。limit <= 1 の場合はいかなる API コストでも
/// 上限を満たせないので無限大。
pub fn break_even_api_cost_ns(record_ns_per_call: u64, limit: f64) -> f64 {
    if limit <= 1.0 {
        return f64::INFINITY;
    }
    record_ns_per_call as f64 / (limit - 1.0)
}

/// バッファ使用率の観測結果。ピーク値だけを保持する（L10 の「バッファ使用率」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferUsage {
    pub descriptor_used_peak: u64,
    pub descriptor_capacity: u64,
    pub payload_used_peak: u64,
    pub payload_capacity: u64,
}

impl BufferUsage {
    /// Descriptor Ring のピーク使用率 (%)。
    pub fn descriptor_percent(&self) -> u64 {
        usage_percent(self.descriptor_used_peak, self.descriptor_capacity)
    }

    /// Payload Ring のピーク使用率 (%)。
    pub fn payload_percent(&self) -> u64 {
        usage_percent(self.payload_used_peak, self.payload_capacity)
    }

    /// どちらかの Ring がピーク時に満杯だったかどうか。満杯は欠落の可能性を
    /// 意味する（`full` でも記録は保証されない。欠落したら incomplete）。
    pub fn hit_full(&self) -> bool {
        self.descriptor_used_peak >= self.descriptor_capacity
            || self.payload_used_peak >= self.payload_capacity
    }
}

/// ワークロード 1 件の判定結果。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PerfVerdict {
    pub workload: WorkloadKind,
    pub ratio: f64,
    pub limit: f64,
    pub meets: bool,
}

/// 倍率から判定を作る。
pub fn evaluate(workload: WorkloadKind, ratio: f64) -> PerfVerdict {
    let limit = workload.ratio_limit();
    PerfVerdict {
        workload,
        ratio,
        limit,
        meets: meets_criterion(ratio, limit),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratio_equal_times_is_one() {
        assert_eq!(execution_ratio(1000, 1000), 1.0);
    }

    #[test]
    fn ratio_three_times() {
        assert_eq!(execution_ratio(3000, 1000), 3.0);
    }

    #[test]
    fn ratio_zero_baseline_is_infinite() {
        assert!(execution_ratio(1000, 0).is_infinite());
    }

    #[test]
    fn ratio_zero_recorded_is_zero() {
        assert_eq!(execution_ratio(0, 1000), 0.0);
    }

    #[test]
    fn criterion_boundary_is_inclusive() {
        assert!(meets_criterion(3.0, 3.0));
        assert!(meets_criterion(2.9, 3.0));
        assert!(!meets_criterion(3.1, 3.0));
    }

    #[test]
    fn break_even_for_three_times() {
        // 記録 400ns/呼び出しなら、API 本体 200ns でちょうど 3 倍。
        assert_eq!(break_even_api_cost_ns(400, 3.0), 200.0);
    }

    #[test]
    fn break_even_for_five_times() {
        // 同じく 5 倍の損益分岐は 100ns。
        assert_eq!(break_even_api_cost_ns(400, 5.0), 100.0);
    }

    #[test]
    fn break_even_limit_one_or_less_is_infinite() {
        assert!(break_even_api_cost_ns(400, 1.0).is_infinite());
        assert!(break_even_api_cost_ns(400, 0.5).is_infinite());
    }

    #[test]
    fn break_even_zero_record_cost_is_zero() {
        assert_eq!(break_even_api_cost_ns(0, 3.0), 0.0);
    }

    #[test]
    fn workload_limits_come_from_spec() {
        assert_eq!(WorkloadKind::GuiMix.ratio_limit(), GUI_RATIO_LIMIT);
        assert_eq!(WorkloadKind::GuiMix.ratio_limit(), 3.0);
        assert_eq!(WorkloadKind::HighLoad.ratio_limit(), HIGH_LOAD_RATIO_LIMIT);
        assert_eq!(WorkloadKind::HighLoad.ratio_limit(), 5.0);
    }

    #[test]
    fn gui_mix_expected_api_cost() {
        // 0.80*100 + 0.15*10_000 + 0.05*500_000 = 80 + 1_500 + 25_000。
        assert_eq!(gui_mix_spec().expected_api_cost_ns_per_call(), 26_580.0);
        assert_eq!(gui_mix_spec().events_per_call(), 2);
    }

    #[test]
    fn high_load_expected_api_cost() {
        // 0.50*100 + 0.30*10_000 + 0.20*1_000_000 = 50 + 3_000 + 200_000。
        assert_eq!(high_load_spec().expected_api_cost_ns_per_call(), 203_050.0);
        assert_eq!(high_load_spec().events_per_call(), 2);
    }

    #[test]
    fn buffer_usage_percents() {
        let u = BufferUsage {
            descriptor_used_peak: 2048,
            descriptor_capacity: 4096,
            payload_used_peak: 0,
            payload_capacity: 1024 * 1024,
        };
        assert_eq!(u.descriptor_percent(), 50);
        assert_eq!(u.payload_percent(), 0);
        assert!(!u.hit_full());
    }

    #[test]
    fn buffer_usage_full_when_peak_reaches_capacity() {
        let u = BufferUsage {
            descriptor_used_peak: 4096,
            descriptor_capacity: 4096,
            payload_used_peak: 0,
            payload_capacity: 1024 * 1024,
        };
        assert!(u.hit_full());
        assert_eq!(u.descriptor_percent(), 100);
    }

    #[test]
    fn evaluate_gui_mix_pass_and_fail() {
        let pass = evaluate(WorkloadKind::GuiMix, 1.02);
        assert!(pass.meets);
        assert_eq!(pass.limit, 3.0);
        let fail = evaluate(WorkloadKind::GuiMix, 3.5);
        assert!(!fail.meets);
    }

    #[test]
    fn evaluate_high_load_uses_five_times_limit() {
        let v = evaluate(WorkloadKind::HighLoad, 4.5);
        assert!(v.meets);
        assert_eq!(v.limit, 5.0);
    }
}
