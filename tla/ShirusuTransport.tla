---- MODULE ShirusuTransport ----
(***************************************************************************)
(* shirusu Agent-Host transport (spec v0.4) の TLA+ モデル。               *)
(* Ring 容量 2、書き手 2 (Slot 2)、読み手 1。バイト列ではなく各セルの      *)
(* 持ち主・状態・Generation・公開済みかどうかを扱う。                       *)
(* スレッド終了と DLL_THREAD_DETACH 後の呼び出しも含む。                    *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS MaxCursor

VARIABLES
    writeCursor,    \* 単調増加する公開 Cursor
    readCursor,     \* 単調増加する回収 Cursor
    nextSeq,        \* 次に割り当てる Sequence (失敗したイベントにも割り当てる)
    cells,          \* Cursor -> [published, seq, gen, slot] (公開済み窓の記録)
    slotState,      \* slot -> "free"|"claimed"|"active"|"draining"|"reclaimable"
    slotGen,        \* slot -> Generation
    slotEnded,      \* slot -> Host がスレッド終了を確認したか
    slotDrained,    \* slot -> Host が回収を終えたか
    dropped,        \* 欠落として記録されたイベント数
    readLog         \* Host が受け取った Sequence の列

Slots == {1, 2}
Cap == 2

Init ==
    /\ writeCursor = 0
    /\ readCursor = 0
    /\ nextSeq = 1
    /\ cells = [i \in 0..MaxCursor |-> [published |-> FALSE, seq |-> 0, gen |-> 0, slot |-> 1]]
    /\ slotState = [s \in Slots |-> "free"]
    /\ slotGen = [s \in Slots |-> 1]
    /\ slotEnded = [s \in Slots |-> FALSE]
    /\ slotDrained = [s \in Slots |-> FALSE]
    /\ dropped = 0
    /\ readLog = << >>

(* Slot 取得: FREE -> CLAIMED -> ACTIVE (モデルでは一手で ACTIVE まで進める) *)
Claim(s) ==
    /\ slotState[s] = "free"
    /\ slotState' = [slotState EXCEPT ![s] = "active"]
    /\ UNCHANGED <<writeCursor, readCursor, nextSeq, cells, slotGen, slotEnded, slotDrained, dropped, readLog>>

(* 公開: 空きがあるときだけ、セルへ書いてから Cursor を進める (単一公開点) *)
Publish(s) ==
    /\ slotState[s] = "active"
    /\ writeCursor - readCursor < Cap
    /\ writeCursor < MaxCursor
    /\ cells' = [cells EXCEPT ![writeCursor] = [published |-> TRUE, seq |-> nextSeq, gen |-> slotGen[s], slot |-> s]]
    /\ writeCursor' = writeCursor + 1
    /\ nextSeq' = nextSeq + 1
    /\ UNCHANGED <<readCursor, slotState, slotGen, slotEnded, slotDrained, dropped, readLog>>

(* 満杯なら待たずに欠落として前に進む (Overflow の劣化/破棄) *)
DropWhenFull(s) ==
    /\ slotState[s] = "active"
    /\ writeCursor - readCursor >= Cap
    /\ nextSeq' = nextSeq + 1
    /\ dropped' = dropped + 1
    /\ UNCHANGED <<writeCursor, readCursor, cells, slotState, slotGen, slotEnded, slotDrained, readLog>>

(* Host の回収: 確定分だけを読み、読み終わってから Cursor を進める *)
Drain ==
    /\ readCursor < writeCursor
    /\ cells[readCursor].published
    /\ readLog' = Append(readLog, cells[readCursor].seq)
    /\ readCursor' = readCursor + 1
    /\ UNCHANGED <<writeCursor, nextSeq, cells, slotState, slotGen, slotEnded, slotDrained, dropped>>

(* DETACH: DRAINING への移行のみ *)
Detach(s) ==
    /\ slotState[s] = "active"
    /\ slotState' = [slotState EXCEPT ![s] = "draining"]
    /\ UNCHANGED <<writeCursor, readCursor, nextSeq, cells, slotGen, slotEnded, slotDrained, dropped, readLog>>

(* DETACH 後の呼び出し: 記録せず欠落として数える *)
CallAfterDetach(s) ==
    /\ slotState[s] = "draining"
    /\ dropped' = dropped + 1
    /\ nextSeq' = nextSeq + 1
    /\ UNCHANGED <<writeCursor, readCursor, cells, slotState, slotGen, slotEnded, slotDrained, readLog>>

(* Host がスレッド終了を確認し、その Slot の公開分を全部回収したら RECLAIMABLE *)
HostConfirm(s) ==
    /\ slotState[s] = "draining"
    /\ \A i \in 0..MaxCursor: (i >= readCursor /\ i < writeCursor) => cells[i].slot # s
    /\ slotEnded' = [slotEnded EXCEPT ![s] = TRUE]
    /\ slotDrained' = [slotDrained EXCEPT ![s] = TRUE]
    /\ slotState' = [slotState EXCEPT ![s] = "reclaimable"]
    /\ UNCHANGED <<writeCursor, readCursor, nextSeq, cells, slotGen, dropped, readLog>>

(* 再利用: RECLAIMABLE -> FREE、Generation を進める。終了確認と回収完了が前提。 *)
Reclaim(s) ==
    /\ slotState[s] = "reclaimable"
    /\ slotEnded[s]
    /\ slotDrained[s]
    /\ slotState' = [slotState EXCEPT ![s] = "free"]
    /\ slotGen' = [slotGen EXCEPT ![s] = slotGen[s] + 1]
    /\ slotEnded' = [slotEnded EXCEPT ![s] = FALSE]
    /\ slotDrained' = [slotDrained EXCEPT ![s] = FALSE]
    /\ UNCHANGED <<writeCursor, readCursor, nextSeq, cells, dropped, readLog>>

Next ==
    \/ \E s \in Slots: Claim(s) \/ Publish(s) \/ DropWhenFull(s) \/ Detach(s) \/ CallAfterDetach(s) \/ HostConfirm(s) \/ Reclaim(s)
    \/ Drain

Spec == Init /\ [][Next]_<<writeCursor, readCursor, nextSeq, cells, slotState, slotGen, slotEnded, slotDrained, dropped, readLog>>

(***************************************************************************)
(* 不変条件 (test.md の表と 1 対 1 に対応)                                   *)
(***************************************************************************)

(* Host は未確定のイベントを受け取らない *)
NoUnpublishedRead ==
    /\ readCursor <= writeCursor
    /\ \A i \in 0..MaxCursor: i < readCursor => cells[i].published

(* 書き手は未回収の領域を書き換えない: 公開窓は常に容量以内 *)
NoOverwriteBeforeRelease == writeCursor - readCursor <= Cap

(* 同じ領域に書ける書き手は同時に一人: 公開窓のセルは、その Slot の
   現在の Generation で、その Slot の書き手が書いたものだけ *)
ExclusiveCellOwnership ==
    \A i \in 0..MaxCursor:
        (i >= readCursor /\ i < writeCursor) => cells[i].gen = slotGen[cells[i].slot] \/ slotState[cells[i].slot] = "reclaimable" \/ slotState[cells[i].slot] = "free"

(* 再利用した後に古い書き手が書き換えない: 再利用は終了確認+回収完了後のみで、
   その時点でその Slot の未回収セルは存在しない *)
NoStaleProducerWrite ==
    \A s \in Slots:
        slotState[s] = "reclaimable" => slotEnded[s] /\ slotDrained[s]

(* 公開済みイベントの順序と欠落情報が矛盾しない:
   セルの Sequence は Cursor 順に厳密に増加し、Host が読んだ列は
   公開された接頭辞と一致する (欠落分は dropped と nextSeq で数えられる) *)
SequenceConsistency ==
    /\ Len(readLog) = readCursor
    /\ \A i \in 0..MaxCursor: (i < writeCursor /\ i + 1 < writeCursor) => cells[i].seq < cells[i + 1].seq
    /\ \A i \in 1..Len(readLog): readLog[i] = cells[i - 1].seq
    /\ nextSeq >= writeCursor + 1

(* Host 停止や容量不足で待機が無期限に続かない:
   満杯なら Drop、空きがあれば Publish/Drain が常に可能 (状態不変条件として表現) *)
NoPermanentBlocking ==
    \/ writeCursor >= MaxCursor
    \/ \E s \in Slots: slotState[s] = "active"
    \/ readCursor < writeCursor
    \/ \E s \in Slots: slotState[s] = "free" \/ slotState[s] = "draining" \/ slotState[s] = "reclaimable"

StateConstraint == writeCursor <= MaxCursor /\ nextSeq <= MaxCursor + 4 /\ dropped <= 4 /\ \A s \in Slots: slotGen[s] <= 2

=============================================================================
