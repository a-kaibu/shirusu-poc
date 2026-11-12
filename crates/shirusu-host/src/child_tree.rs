//! 子プロセス追跡（L05）のプラットフォーム非依存の核。
//!
//! 起動した対象のプロセスツリーだけを対象に、プロセス一覧の
//! スナップショット `(pid, ppid)` から新しく現れた子プロセスを発見する。
//! 返すのは PID の連鎖に基づく候補であり、プロセスの同一性までは
//! 保証しない。注入側の TreeCapture が祖先のハンドルを保持し、
//! 作成時刻と親 PID を再確認する。一度知った PID は二度と返さず、
//! 同一性を確認できない候補は Capture Coverage に残す。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// プロセス一覧の 1 行（pid と親 pid）。列挙自体は
/// transport-win の `enumerate_processes` が担う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessEntry {
    pub pid: u32,
    pub ppid: u32,
}

/// 起動した対象をルートとするプロセスツリーの追跡器。
/// スナップショットを受け取るたび、ルートの子孫でまだ知らない
/// pid を返す。知った pid は覚え、二度と返さない。
#[derive(Debug)]
pub struct ChildTracker {
    root_pid: u32,
    known: HashSet<u32>,
}

impl ChildTracker {
    pub fn new(root_pid: u32) -> Self {
        Self {
            root_pid,
            known: [root_pid].into_iter().collect(),
        }
    }

    pub fn root_pid(&self) -> u32 {
        self.root_pid
    }

    /// 知っている pid の数（ルートを含む）。
    pub fn known_count(&self) -> usize {
        self.known.len()
    }

    /// スナップショットから、ルートの子孫でまだ知らない pid を返す
    /// （pid の昇順で決定的）。見つけた pid は知ったものとして覚える。
    ///
    /// 判定は ppid の連鎖をルート（または既知の pid）まで辿ることで行う。
    /// 既知の pid を中間のリンクとして使うため、親が既に終了して
    /// スナップショットに無くても孫は見つかる。ppid の循環は visited
    /// 集合で止める。スナップショットに無い pid へのリンクは辿れない
    /// （その子孫は「来歴不明」として次回以降のスナップショット待ちに
    /// なるが、親が既知なら見つかるため実運用では稀である）。
    pub fn update(&mut self, snapshot: &[ProcessEntry]) -> Vec<u32> {
        // ppid -> 子 pid 群。スナップショットに無い ppid へのリンクは
        // 張れないが、既知の pid はリンクとして使える（下の BFS の
        // 初期集合に含める）。
        let mut by_parent: HashMap<u32, Vec<u32>> = HashMap::new();
        for e in snapshot {
            by_parent.entry(e.ppid).or_default().push(e.pid);
        }
        let mut reached: HashSet<u32> = HashSet::new();
        let mut frontier: Vec<u32> = vec![self.root_pid];
        // 既知の pid は全て到達済みとして扱う（終了した親を経由する
        // 孫の発見のため）。ただし返値の対象にはしない。
        for pid in &self.known {
            reached.insert(*pid);
            frontier.push(*pid);
        }
        let mut found: Vec<u32> = Vec::new();
        while let Some(pid) = frontier.pop() {
            if let Some(children) = by_parent.get(&pid) {
                for &child in children {
                    if reached.insert(child) {
                        frontier.push(child);
                        if !self.known.contains(&child) {
                            found.push(child);
                        }
                    }
                }
            }
        }
        found.sort_unstable();
        for pid in &found {
            self.known.insert(*pid);
        }
        found
    }
}

/// 子プロセスの Trace ファイル名をルートの Trace ファイル名から作る。
/// `<stem>.child-<pid><ext>`（拡張子が無ければ `<stem>.child-<pid>`）。
/// 子はルートとは別の Trace ファイルに記録する（1 プロセス 1 Trace の
/// 前提を保つため。子孫の来歴はファイル名の pid で辿れる）。
pub fn child_trace_path(root_trace: &Path, pid: u32) -> PathBuf {
    let stem = root_trace
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = match root_trace.extension() {
        Some(ext) => format!("{stem}.child-{pid}.{}", ext.to_string_lossy()),
        None => format!("{stem}.child-{pid}"),
    };
    root_trace.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(pid: u32, ppid: u32) -> ProcessEntry {
        ProcessEntry { pid, ppid }
    }

    #[test]
    fn empty_snapshot_finds_nothing() {
        let mut t = ChildTracker::new(100);
        assert!(t.update(&[]).is_empty());
        assert_eq!(t.known_count(), 1);
    }

    #[test]
    fn direct_child_and_grandchild_are_discovered() {
        let mut t = ChildTracker::new(100);
        let found = t.update(&[e(100, 0), e(101, 100), e(102, 101), e(103, 102)]);
        assert_eq!(found, vec![101, 102, 103]);
        assert_eq!(t.known_count(), 4);
    }

    #[test]
    fn unrelated_processes_are_never_returned() {
        let mut t = ChildTracker::new(100);
        // 200 は別ツリーのルート、201 はその子。どちらも返さない。
        let found = t.update(&[e(100, 0), e(200, 1), e(201, 200)]);
        assert!(found.is_empty());
        assert_eq!(t.known_count(), 1);
    }

    #[test]
    fn second_update_returns_only_new_children() {
        let mut t = ChildTracker::new(100);
        assert_eq!(t.update(&[e(100, 0), e(101, 100)]), vec![101]);
        assert_eq!(t.update(&[e(100, 0), e(101, 100), e(102, 100)]), vec![102]);
        assert!(t.update(&[e(100, 0), e(101, 100), e(102, 100)]).is_empty());
    }

    #[test]
    fn root_itself_is_never_returned() {
        let mut t = ChildTracker::new(100);
        assert!(t.update(&[e(100, 0)]).is_empty());
    }

    #[test]
    fn ppid_cycle_among_unrelated_processes_does_not_loop() {
        let mut t = ChildTracker::new(100);
        // 200 と 201 が互いを親として指す循環。ルートには繋がらない。
        let found = t.update(&[e(100, 0), e(200, 201), e(201, 200)]);
        assert!(found.is_empty());
    }

    #[test]
    fn grandchild_found_after_intermediate_exited() {
        // 中間の子 101 が既に終了してスナップショットに無くても、
        // 101 は知っている pid なので孫 102 はルートの子孫と分かる。
        let mut t = ChildTracker::new(100);
        assert_eq!(t.update(&[e(100, 0), e(101, 100)]), vec![101]);
        let found = t.update(&[e(102, 101)]);
        assert_eq!(found, vec![102]);
    }

    #[test]
    fn pid_reuse_is_not_reported_twice() {
        // 一度知った pid は、別ツリーのプロセスに再利用されても
        // 返さない（誤注入を避ける保守側の決定）。
        let mut t = ChildTracker::new(100);
        assert_eq!(t.update(&[e(100, 0), e(101, 100)]), vec![101]);
        let found = t.update(&[e(101, 999)]);
        assert!(found.is_empty());
    }

    #[test]
    fn results_are_sorted_by_pid() {
        let mut t = ChildTracker::new(100);
        let found = t.update(&[e(105, 100), e(103, 100), e(104, 100)]);
        assert_eq!(found, vec![103, 104, 105]);
    }

    #[test]
    fn child_trace_path_keeps_extension() {
        assert_eq!(
            child_trace_path(Path::new("/tmp/app.trace"), 1234),
            PathBuf::from("/tmp/app.child-1234.trace")
        );
    }

    #[test]
    fn child_trace_path_without_extension() {
        assert_eq!(
            child_trace_path(Path::new("app"), 42),
            PathBuf::from("app.child-42")
        );
    }
}
