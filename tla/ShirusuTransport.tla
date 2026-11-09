---- MODULE ShirusuTransport ----
(***************************************************************************)
(* shirusu Agent-Host transport (spec v0.4) の TLA+ モデル。               *)
(* Ring 容量 2、書き手 2 (Slot 2)、読み手 1。バイト列ではなく各セルの      *)
(* 持ち主・状態・Generation・公開済みかどうかを扱う。                       *)
(* スレッド終了と DLL_THREAD_DETACH 後の呼び出しも含む。                    *)
(*                                                                         *)
(* Slot 再利用は実装の原子操作列に合わせて段階に分けてある                  *)
(* (レビュー第2回・項目6): Generation 加算と終了フラグのクリアは            *)
(* RECLAIMING の間に済ませ、FREE の公開は最後の別操作にする。               *)
(* 旧順序 (FREE 公開 → Generation 更新) は変種モデル                         *)
(* ShirusuTransportBuggy.tla が表現し、TLC が不変条件違反として             *)
(* 検出できることを確認してある (docs/verification.md 参照)。               *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS MaxCursor

VARIABLES
    writeCursor,    \* 単調増加する公開 Cursor
    readCursor,     \* 単調増加する回収 Cursor
    nextSeq,        \* 次に割り当てる Sequence (失敗したイベントにも割り当てる)
    cells,          \* Cursor -> [published, seq, gen, slot] (公開済み窓の記録)
    slotState,      \* slot -> "free"|"claimed"|"active"|"draining"|"reclaimable"|"reclaiming"
    slotGen,        \* slot -> Generation
    slotClaimGen,   \* slot -> 取得者が Claim の瞬間に観測した Generation
    slotEnded,      \* slot -> Host がスレッド終了を確認したか
    slotDrained,    \* slot -> Host が回収を終えたか
    dropped,        \* 欠落として記録されたイベント数
    readLog         \* Host が受け取った Sequence の列

Slots == {1, 2}
Cap == 2
vars == <<writeCursor, readCursor, nextSeq, cells, slotState, slotGen, slotClaimGen, slotEnded, slotDrained, dropped, readLog>>

Init ==
    /\ writeCursor = 0
    /\ readCursor = 0
    /\ nextSeq = 1
    /\ cells = [i \in 0..MaxCursor |-> [published |-> FALSE, seq |-> 0, gen |-> 0, slot |-> 1]]
    /\ slotState = [s \in Slots |-> "free"]
    /\ slotGen = [s \in Slots |-> 1]
    /\ slotClaimGen = [s \in Slots |-> 0]
    /\ slotEnded = [s \in Slots |-> FALSE]
    /\ slotDrained = [s \in Slots |-> FALSE]
    /\ dropped = 0
    /\ readLog = << >>

(* Slot 取得: FREE -> CLAIMED -> ACTIVE (モデルでは一手で ACTIVE まで進める)。
   取得は FREE が公開されているときにだけ可能で、その瞬間に観測した
   Generation を slotClaimGen に記録する (実装の SlotHandle に対応)。 *)
Claim(s) ==
    /\ slotState[s] = "free"
    /\ slotState' = [slotState EXCEPT ![s] = "active"]
    /\ slotClaimGen' = [slotClaimGen EXCEPT ![s] = slotGen[s]]
    /\ UNCHANGED <<writeCursor, readCursor, nextSeq, cells, slotGen, slotEnded, slotDrained, dropped, readLog>>

(* 公開: 空きがあるときだけ、セルへ書いてから Cursor を進める (単一公開点) *)
Publish(s) ==
    /\ slotState[s] = "active"
    /\ writeCursor - readCursor < Cap
    /\ writeCursor < MaxCursor
    /\ cells' = [cells EXCEPT ![writeCursor] = [published |-> TRUE, seq |-> nextSeq, gen |-> slotGen[s], slot |-> s]]
    /\ writeCursor' = writeCursor + 1
    /\ nextSeq' = nextSeq + 1
    /\ UNCHANGED <<readCursor, slotState, slotGen, slotClaimGen, slotEnded, slotDrained, dropped, readLog>>

(* 満杯なら待たずに欠落として前に進む (Overflow の劣化/破棄) *)
DropWhenFull(s) ==
    /\ slotState[s] = "active"
    /\ writeCursor - readCursor >= Cap
    /\ nextSeq' = nextSeq + 1
    /\ dropped' = dropped + 1
    /\ UNCHANGED <<writeCursor, readCursor, cells, slotState, slotGen, slotClaimGen, slotEnded, slotDrained, readLog>>

(* Host の回収: 確定分だけを読み、読み終わってから Cursor を進める *)
Drain ==
    /\ readCursor < writeCursor
    /\ cells[readCursor].published
    /\ readLog' = Append(readLog, cells[readCursor].seq)
    /\ readCursor' = readCursor + 1
    /\ UNCHANGED <<writeCursor, nextSeq, cells, slotState, slotGen, slotClaimGen, slotEnded, slotDrained, dropped>>

(* DETACH: DRAINING への移行のみ *)
Detach(s) ==
    /\ slotState[s] = "active"
    /\ slotState' = [slotState EXCEPT ![s] = "draining"]
    /\ UNCHANGED <<writeCursor, readCursor, nextSeq, cells, slotGen, slotClaimGen, slotEnded, slotDrained, dropped, readLog>>

(* DETACH 後の呼び出し: 記録せず欠落として数える *)
CallAfterDetach(s) ==
    /\ slotState[s] = "draining"
    /\ dropped' = dropped + 1
    /\ nextSeq' = nextSeq + 1
    /\ UNCHANGED <<writeCursor, readCursor, cells, slotState, slotGen, slotClaimGen, slotEnded, slotDrained, readLog>>

(* Host がスレッド終了を確認し、その Slot の公開分を全部回収したら RECLAIMABLE *)
HostConfirm(s) ==
    /\ slotState[s] = "draining"
    /\ \A i \in 0..MaxCursor: (i >= readCursor /\ i < writeCursor) => cells[i].slot # s
    /\ slotEnded' = [slotEnded EXCEPT ![s] = TRUE]
    /\ slotDrained' = [slotDrained EXCEPT ![s] = TRUE]
    /\ slotState' = [slotState EXCEPT ![s] = "reclaimable"]
    /\ UNCHANGED <<writeCursor, readCursor, nextSeq, cells, slotGen, slotClaimGen, dropped, readLog>>

(* 再利用の第 1 段階: RECLAIMABLE -> RECLAIMING。Generation を進め、終了
   フラグを落とす。まだ FREE は公開していないので、この間に取得者は
   入ってこられない (実装の SLOT_RECLAIMING 中間状態に対応)。 *)
ReclaimBegin(s) ==
    /\ slotState[s] = "reclaimable"
    /\ slotEnded[s]
    /\ slotDrained[s]
    /\ slotGen' = [slotGen EXCEPT ![s] = slotGen[s] + 1]
    /\ slotEnded' = [slotEnded EXCEPT ![s] = FALSE]
    /\ slotDrained' = [slotDrained EXCEPT ![s] = FALSE]
    /\ slotState' = [slotState EXCEPT ![s] = "reclaiming"]
    /\ UNCHANGED <<writeCursor, readCursor, nextSeq, cells, slotClaimGen, dropped, readLog>>

(* 再利用の第 2 段階: FREE を公開する。公開された時点で、取得者は新しい
   Generation と初期化済みの状態だけを観測する。 *)
PublishFree(s) ==
    /\ slotState[s] = "reclaiming"
    /\ slotState' = [slotState EXCEPT ![s] = "free"]
    /\ UNCHANGED <<writeCursor, readCursor, nextSeq, cells, slotGen, slotClaimGen, slotEnded, slotDrained, dropped, readLog>>

Next ==
    \/ \E s \in Slots: Claim(s) \/ Publish(s) \/ DropWhenFull(s) \/ Detach(s) \/ CallAfterDetach(s) \/ HostConfirm(s) \/ ReclaimBegin(s) \/ PublishFree(s)
    \/ Drain

Spec == Init /\ [][Next]_vars

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
        (i >= readCursor /\ i < writeCursor) => cells[i].gen = slotGen[cells[i].slot] \/ slotState[cells[i].slot] = "reclaimable" \/ slotState[cells[i].slot] = "reclaiming" \/ slotState[cells[i].slot] = "free"

(* 再利用した後に古い書き手が書き換えない: 再利用は終了確認+回収完了後のみで、
   その時点でその Slot の未回収セルは存在しない *)
NoStaleProducerWrite ==
    \A s \in Slots:
        slotState[s] = "reclaimable" => slotEnded[s] /\ slotDrained[s]

(* 取得者が観測した Generation は、その Slot の現在の Generation と
   一致し続ける。FREE 公開より前に Generation を更新する正しい順序では
   常に成り立つ。旧順序 (FREE 公開 → Generation 更新) では、公開直後に
   取得した書き手が古い Generation を観測し、その後 Generation が進む
   ため破れる。変種モデル ShirusuTransportBuggy で検出を確認済み。 *)
ClaimedGenerationIsCurrent ==
    \A s \in Slots:
        slotState[s] = "active" => slotClaimGen[s] = slotGen[s]

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
    \/ \E s \in Slots: slotState[s] = "free" \/ slotState[s] = "draining" \/ slotState[s] = "reclaimable" \/ slotState[s] = "reclaiming"

StateConstraint == writeCursor <= MaxCursor /\ nextSeq <= MaxCursor + 4 /\ dropped <= 4 /\ \A s \in Slots: slotGen[s] <= 2

=============================================================================
