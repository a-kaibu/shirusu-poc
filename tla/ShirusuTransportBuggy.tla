---- MODULE ShirusuTransportBuggy ----
(***************************************************************************)
(* 変種モデル (レビュー第2回・項目6 の証跡用): Slot 再利用の順序が旧実装    *)
(* (修正前) の順序になっている点だけが ShirusuTransport.tla と異なる。     *)
(*                                                                         *)
(*   旧順序: (1) RECLAIMABLE -> FREE を先に公開する                         *)
(*           (2) その後に Generation を進め、終了フラグを落とす             *)
(*                                                                         *)
(* この間に別の書き手が Claim すると、古い Generation を観測したまま       *)
(* Generation が進み、ClaimedGenerationIsCurrent が破れる。TLC がこの      *)
(* 違反を検出することが、「モデルがこの競合を表現できる」証跡になる。       *)
(* 本モデルの TLC 実行は「違反を検出すること」が期待結果であり、            *)
(* scripts/ci/tla.sh は検出できなければ失敗として扱う。                    *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS MaxCursor

VARIABLES
    writeCursor,
    readCursor,
    nextSeq,
    cells,
    slotState,      \* slot -> "free"|"claimed"|"active"|"draining"|"reclaimable"
    slotGen,        \* slot -> Generation
    slotClaimGen,   \* slot -> 取得者が Claim の瞬間に観測した Generation
    slotGenPending, \* slot -> FREE 公開後に Generation 更新が残っているか
    slotEnded,
    slotDrained,
    dropped,
    readLog

Slots == {1, 2}
Cap == 2
vars == <<writeCursor, readCursor, nextSeq, cells, slotState, slotGen, slotClaimGen, slotGenPending, slotEnded, slotDrained, dropped, readLog>>

Init ==
    /\ writeCursor = 0
    /\ readCursor = 0
    /\ nextSeq = 1
    /\ cells = [i \in 0..MaxCursor |-> [published |-> FALSE, seq |-> 0, gen |-> 0, slot |-> 1]]
    /\ slotState = [s \in Slots |-> "free"]
    /\ slotGen = [s \in Slots |-> 1]
    /\ slotClaimGen = [s \in Slots |-> 0]
    /\ slotGenPending = [s \in Slots |-> FALSE]
    /\ slotEnded = [s \in Slots |-> FALSE]
    /\ slotDrained = [s \in Slots |-> FALSE]
    /\ dropped = 0
    /\ readLog = << >>

Claim(s) ==
    /\ slotState[s] = "free"
    /\ slotState' = [slotState EXCEPT ![s] = "active"]
    /\ slotClaimGen' = [slotClaimGen EXCEPT ![s] = slotGen[s]]
    /\ UNCHANGED <<writeCursor, readCursor, nextSeq, cells, slotGen, slotGenPending, slotEnded, slotDrained, dropped, readLog>>

Publish(s) ==
    /\ slotState[s] = "active"
    /\ writeCursor - readCursor < Cap
    /\ writeCursor < MaxCursor
    /\ cells' = [cells EXCEPT ![writeCursor] = [published |-> TRUE, seq |-> nextSeq, gen |-> slotGen[s], slot |-> s]]
    /\ writeCursor' = writeCursor + 1
    /\ nextSeq' = nextSeq + 1
    /\ UNCHANGED <<readCursor, slotState, slotGen, slotClaimGen, slotGenPending, slotEnded, slotDrained, dropped, readLog>>

DropWhenFull(s) ==
    /\ slotState[s] = "active"
    /\ writeCursor - readCursor >= Cap
    /\ nextSeq' = nextSeq + 1
    /\ dropped' = dropped + 1
    /\ UNCHANGED <<writeCursor, readCursor, cells, slotState, slotGen, slotClaimGen, slotGenPending, slotEnded, slotDrained, readLog>>

Drain ==
    /\ readCursor < writeCursor
    /\ cells[readCursor].published
    /\ readLog' = Append(readLog, cells[readCursor].seq)
    /\ readCursor' = readCursor + 1
    /\ UNCHANGED <<writeCursor, nextSeq, cells, slotState, slotGen, slotClaimGen, slotGenPending, slotEnded, slotDrained, dropped>>

Detach(s) ==
    /\ slotState[s] = "active"
    /\ slotState' = [slotState EXCEPT ![s] = "draining"]
    /\ UNCHANGED <<writeCursor, readCursor, nextSeq, cells, slotGen, slotClaimGen, slotGenPending, slotEnded, slotDrained, dropped, readLog>>

CallAfterDetach(s) ==
    /\ slotState[s] = "draining"
    /\ dropped' = dropped + 1
    /\ nextSeq' = nextSeq + 1
    /\ UNCHANGED <<writeCursor, readCursor, cells, slotState, slotGen, slotClaimGen, slotGenPending, slotEnded, slotDrained, readLog>>

HostConfirm(s) ==
    /\ slotState[s] = "draining"
    /\ \A i \in 0..MaxCursor: (i >= readCursor /\ i < writeCursor) => cells[i].slot # s
    /\ slotEnded' = [slotEnded EXCEPT ![s] = TRUE]
    /\ slotDrained' = [slotDrained EXCEPT ![s] = TRUE]
    /\ slotState' = [slotState EXCEPT ![s] = "reclaimable"]
    /\ UNCHANGED <<writeCursor, readCursor, nextSeq, cells, slotGen, slotClaimGen, slotGenPending, dropped, readLog>>

(* 旧順序の第 1 段階 (欠陥): Generation を進める前に FREE を公開する。 *)
PublishFreeBuggy(s) ==
    /\ slotState[s] = "reclaimable"
    /\ slotEnded[s]
    /\ slotDrained[s]
    /\ slotState' = [slotState EXCEPT ![s] = "free"]
    /\ slotGenPending' = [slotGenPending EXCEPT ![s] = TRUE]
    /\ UNCHANGED <<writeCursor, readCursor, nextSeq, cells, slotGen, slotClaimGen, slotEnded, slotDrained, dropped, readLog>>

(* 旧順序の第 2 段階 (欠陥): FREE 公開後に Generation を進める。この間に
   Claim した書き手がいても無条件に進むため、取得済みの Slot の
   Generation が後から変わってしまう。 *)
UpdateGenerationBuggy(s) ==
    /\ slotGenPending[s]
    /\ slotGen' = [slotGen EXCEPT ![s] = slotGen[s] + 1]
    /\ slotEnded' = [slotEnded EXCEPT ![s] = FALSE]
    /\ slotDrained' = [slotDrained EXCEPT ![s] = FALSE]
    /\ slotGenPending' = [slotGenPending EXCEPT ![s] = FALSE]
    /\ UNCHANGED <<writeCursor, readCursor, nextSeq, cells, slotState, slotClaimGen, dropped, readLog>>

Next ==
    \/ \E s \in Slots: Claim(s) \/ Publish(s) \/ DropWhenFull(s) \/ Detach(s) \/ CallAfterDetach(s) \/ HostConfirm(s) \/ PublishFreeBuggy(s) \/ UpdateGenerationBuggy(s)
    \/ Drain

Spec == Init /\ [][Next]_vars

NoUnpublishedRead ==
    /\ readCursor <= writeCursor
    /\ \A i \in 0..MaxCursor: i < readCursor => cells[i].published

NoOverwriteBeforeRelease == writeCursor - readCursor <= Cap

ExclusiveCellOwnership ==
    \A i \in 0..MaxCursor:
        (i >= readCursor /\ i < writeCursor) => cells[i].gen = slotGen[cells[i].slot] \/ slotState[cells[i].slot] = "reclaimable" \/ slotState[cells[i].slot] = "free"

NoStaleProducerWrite ==
    \A s \in Slots:
        slotState[s] = "reclaimable" => slotEnded[s] /\ slotDrained[s]

(* この不変条件が旧順序で破れることの実証が本モデルの目的。 *)
ClaimedGenerationIsCurrent ==
    \A s \in Slots:
        slotState[s] = "active" => slotClaimGen[s] = slotGen[s]

SequenceConsistency ==
    /\ Len(readLog) = readCursor
    /\ \A i \in 0..MaxCursor: (i < writeCursor /\ i + 1 < writeCursor) => cells[i].seq < cells[i + 1].seq
    /\ \A i \in 1..Len(readLog): readLog[i] = cells[i - 1].seq
    /\ nextSeq >= writeCursor + 1

NoPermanentBlocking ==
    \/ writeCursor >= MaxCursor
    \/ \E s \in Slots: slotState[s] = "active"
    \/ readCursor < writeCursor
    \/ \E s \in Slots: slotState[s] = "free" \/ slotState[s] = "draining" \/ slotState[s] = "reclaimable"

StateConstraint == writeCursor <= MaxCursor /\ nextSeq <= MaxCursor + 4 /\ dropped <= 4 /\ \A s \in Slots: slotGen[s] <= 2

=============================================================================
