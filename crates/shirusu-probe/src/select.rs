//! 候補が「関与する呼び出し」を、正規化済み Trace の側で特定する。
//!
//! トリミングとブリーフ生成の共通の入力になる。特定の根拠は候補が
//! 持つ証跡（根拠イベントと関与オブジェクト）であり、不存在の側
//! （MissingCall の右側など）では空になるのが正しい。

use shirusu_compare::{Candidate, NormTrace};
use std::collections::BTreeSet;

/// 候補の根拠イベントから、その側の呼び出しを 1 件特定する。
/// thread は正準スレッド序数、sequence は呼び出しの先頭イベントの
/// sequence（diff の EventEvidence の作り方と対になっている）。
pub fn locate_call(norm: &NormTrace, ev: &shirusu_compare::diff::EventEvidence) -> Option<usize> {
    norm.calls
        .iter()
        .position(|c| c.thread == ev.thread && c.first_sequence == ev.sequence && c.api == ev.api)
}

/// 片側について、候補が関与する呼び出しのインデックス列（昇順）。
///
/// - 関与オブジェクトがある場合：そのオブジェクトに関与する全
///   呼び出し（生成・操作・Close）。加えて、同一生成 API で序数が
///   先行するオブジェクトの生成呼び出しも含める（トリム後も
///   オブジェクトの序数＝同一性がずれないようにするため）。
/// - 根拠イベントがある場合：その呼び出し自身。
pub fn involved_calls(norm: &NormTrace, cand: &Candidate, side: &'static str) -> Vec<usize> {
    let mut set: BTreeSet<usize> = BTreeSet::new();
    if let Some(key) = &cand.object {
        if let Some(idxs) = norm.object_calls.get(key) {
            set.extend(idxs.iter().copied());
        }
        for info in &norm.objects {
            if info.key.creator_api == key.creator_api && info.key.ordinal < key.ordinal {
                if let Some(idx) = norm
                    .calls
                    .iter()
                    .position(|c| c.created.as_ref() == Some(&info.key))
                {
                    set.insert(idx);
                }
            }
        }
    }
    let ev = if side == "left" {
        cand.left_event.as_ref()
    } else {
        cand.right_event.as_ref()
    };
    if let Some(ev) = ev {
        if let Some(idx) = locate_call(norm, ev) {
            set.insert(idx);
        }
    }
    set.into_iter().collect()
}
