--------------------------- MODULE NotifyLiveness ---------------------------
(***************************************************************************)
(* data_ready 通知の進行性 (Liveness)。                                      *)
(*                                                                         *)
(* 実装の通知経路 (shirusu-transport::notify, ring.rs の publish):          *)
(*  - 書き手は公開後に PublishNotifyTracker で通知要否を決める。通知は      *)
(*    「使用率が閾値を下から上へ越えた」か「Host 待機フラグが立っている」  *)
(*    ときだけで、通常経路にフェンスはない。                                *)
(*  - data_ready は auto-reset Event。Host は「空を確認 → 待機」の二段で    *)
(*    眠り、その間に公開された通知は Event に残る。                         *)
(*  - Host は待機に期限 (ReCheckPolicy, 既定 2ms) を付け、期限が来たら      *)
(*    通知の有無にかかわらず再確認する。                                    *)
(*                                                                         *)
(* 検査する性質:                                                            *)
(*  - Drained: 公開されたイベントは、書き手が止まっても必ずいつか回収される *)
(*    (閾値未満で通知が出ない公開や、空確認と待機の間に入った公開を含む)。 *)
(*  - TypeOK / Bounded: Cursor は後退せず、占有量は容量を超えない。         *)
(*                                                                         *)
(* UseTimeout = FALSE の変種では Drained が破れることを tla.sh で必須にする *)
(* (期限付き待機が進行性を担っている証跡)。HostSetsWaiting は実装どおり     *)
(* FALSE (2026-11-13 時点で Host は OFF_HOST_WAITING を立てていない)。      *)
(***************************************************************************)
EXTENDS Naturals
CONSTANTS Cap, Threshold, MaxEvents, UseTimeout, HostSetsWaiting

VARIABLES w, r, dropped, above, event, waitingFlag, host
vars == <<w, r, dropped, above, event, waitingFlag, host>>

Used == w - r
AtLeast(u) == u >= Threshold

TypeOK == /\ w \in 0..MaxEvents /\ r \in 0..w /\ dropped \in 0..MaxEvents
          /\ above \in BOOLEAN /\ event \in BOOLEAN /\ waitingFlag \in BOOLEAN
          /\ host \in {"running", "checked", "waiting"}
Bounded == Used <= Cap

Init == /\ w = 0 /\ r = 0 /\ dropped = 0 /\ above = FALSE
        /\ event = FALSE /\ waitingFlag = FALSE /\ host = "running"

\* 書き手: 空きがあれば公開し、PublishNotifyTracker::after_publish と同じ規則で通知する。
Publish == /\ w + dropped < MaxEvents /\ Used < Cap
           /\ LET before == Used
                  after == Used + 1
                  wasAbove == before > 0 /\ AtLeast(before)
                  armed == above /\ wasAbove
                  crossed == AtLeast(after) /\ ~armed /\ ~wasAbove
              IN /\ w' = w + 1
                 /\ above' = AtLeast(after)
                 /\ event' = (event \/ crossed \/ waitingFlag)
           /\ UNCHANGED <<r, dropped, waitingFlag, host>>

\* 満杯: BOUNDED_WAIT の後に欠落として前へ進む (待ち続けない)。
Drop == /\ w + dropped < MaxEvents /\ Used = Cap
        /\ dropped' = dropped + 1
        /\ UNCHANGED <<w, r, above, event, waitingFlag, host>>

\* Host: 確定分を全部回収する。
Drain == /\ host = "running" /\ Used > 0
         /\ r' = w
         /\ UNCHANGED <<w, dropped, above, event, waitingFlag, host>>

\* Host: 空を確認して待機に入る準備 (ここと Block の間に公開が割り込める)。
Check == /\ host = "running" /\ Used = 0
         /\ host' = "checked"
         /\ waitingFlag' = HostSetsWaiting
         /\ UNCHANGED <<w, r, dropped, above, event>>

Block == /\ host = "checked" /\ host' = "waiting"
         /\ UNCHANGED <<w, r, dropped, above, event, waitingFlag>>

\* 起床: 通知 (auto-reset で消費) か、期限切れによる再確認。
Wake == /\ host = "waiting" /\ (event \/ UseTimeout)
        /\ host' = "running" /\ event' = FALSE /\ waitingFlag' = FALSE
        /\ UNCHANGED <<w, r, dropped, above>>

Producer == Publish \/ Drop
Consumer == Drain \/ Check \/ Block \/ Wake
Next == Producer \/ Consumer

\* 書き手には公平性を課さない (いつ止まってもよい)。Host のスケジュールだけ公平。
Spec == Init /\ [][Next]_vars /\ WF_vars(Drain) /\ WF_vars(Check) /\ WF_vars(Block) /\ WF_vars(Wake)

Drained == \A n \in 1..MaxEvents : (w >= n) ~> (r >= n)
CursorsMonotone == [][w' >= w /\ r' >= r]_vars
=============================================================================
