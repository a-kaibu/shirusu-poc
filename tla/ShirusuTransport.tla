---- MODULE ShirusuTransport ----
(***************************************************************************)
(* shirusu Agent-Host transport (spec v0.5) の TLA+ モデル。               *)
(*                                                                         *)
(* v0.5 の Ring はスレッドごとに 1 本 (書き手 1、読み手 1) で、Descriptor  *)
(* Ring と Payload Ring の 2 領域を持つ。Ring どうしは共有する状態を持た    *)
(* ないので、モデルは Slot 1 本を世代をまたいで扱う (Slots は定数)。       *)
(*                                                                         *)
(* v0.4 のモデル (共有 Ring 1 本、セルの持ち主) から次を入れ直した         *)
(* (レビュー 2026-11-14 V10):                                              *)
(* - Payload Ring: 書き手は Payload の領域を確保して書き、Descriptor を書き *)
(*   て write_cursor で両方を公開する。Payload の書き込み位置は公開より先に *)
(*   進む。                                                                 *)
(* - コピーして解放してから検証: Host は公開済みの Descriptor と、それが    *)
(*   参照する Payload を自分の側へコピーしてから領域を書き手へ返す。検証と  *)
(*   受け入れは後から、コピーだけを読んで行う。                            *)
(* - DETACH なしの終了: 書き手はどの時点でも (Payload を書いて未公開の間も) *)
(*   強制終了しうる。再利用の判定は公開済み Descriptor を読み終えたことだけ *)
(*   で行い、Payload の書き込み位置は見ない。                              *)
(* - NoPermanentBlocking (恒真式だった) を、書き手が Host を待たずに常に   *)
(*   前へ進めること (WriterNeverBlocks、ENABLED を含む状態述語) と、公平性 *)
(*   の下での進行性 (EverythingPublishedIsAccepted、DeadSlotIsReclaimed)   *)
(*   に置き換えた。                                                        *)
(*                                                                         *)
(* 変種 (どれも scripts/ci/tla.sh が反例を必須とする):                     *)
(* - FreeBeforeGen: 旧順序 (FREE 公開 → Generation 更新)。                 *)
(*   ClaimedGenerationIsCurrent が破れる (旧 ShirusuTransportBuggy.tla)。   *)
(* - ValidateShared: 解放した後に共有メモリの Payload を読んで検証する。    *)
(*   書き手が解放済みの領域を書き換えるので AcceptedIsPublished が破れる。 *)
(* - ReclaimByPayload: Payload の書き込み位置まで回収したことを再利用の    *)
(*   条件にする。Payload を書いた後で強制終了した Slot が永久に再利用され *)
(*   ず DeadSlotIsReclaimed が破れる。                                     *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS
    Slots,            \* モデルでは {1} (Ring は互いに独立)
    DescCap,          \* Descriptor Ring の件数
    PayCap,           \* Payload Ring の単位数
    MaxSize,          \* 1 イベントの Payload の最大単位数 (<= PayCap)
    MaxEvents,        \* 1 世代で書き手が試みる呼び出しの数
    MaxGen,           \* 再利用する世代の上限 (これを超えた Slot は退役)
    FreeBeforeGen,    \* 変種: FREE を Generation 更新より先に公開する
    ValidateShared,   \* 変種: 解放後に共有メモリを読んで検証する
    ReclaimByPayload  \* 変種: Payload の書き込み位置で再利用を判定する

VARIABLES
    state,      \* s -> "free"|"active"|"draining"|"reclaiming"|"retired"
    alive,      \* s -> Slot を持つスレッドが実行中か
    phase,      \* s -> "idle"|"written" (Payload と Descriptor を書いて未公開)
    pending,    \* s -> 書いて未公開のイベント [seq, pstart, plen]
    gen,        \* s -> Generation
    claimGen,   \* s -> 取得者が Claim の瞬間に観測した Generation
    needBump,   \* s -> FreeBeforeGen で Generation 更新が残っている
    nextSeq,    \* s -> 次に割り当てる Sequence (欠落したイベントにも割り当てる)
    dropped,    \* s -> 欠落として数えたイベント数
    wc, rc,     \* s -> write_cursor / read_cursor (Descriptor、世代内で単調)
    pw, pr,     \* s -> Payload の書き込み位置 (書き手だけが知る) / 解放位置
    ringDesc,   \* s -> 共有メモリの Descriptor セル [seq, pstart, plen]
    ringPay,    \* s -> 共有メモリの Payload 単位 (書いたイベントの seq)
    curPub,     \* s -> この世代で公開したイベント (位置順、証跡用)
    pubHist,    \* s -> 全世代で公開したイベント [gen, seq] (証跡用)
    queue,      \* s -> Host がコピー済みで未検証のイベント
    accepted    \* s -> Host が検証して受け入れたイベント [gen, seq, intact]

vars == <<state, alive, phase, pending, gen, claimGen, needBump, nextSeq, dropped,
          wc, rc, pw, pr, ringDesc, ringPay, curPub, pubHist, queue, accepted>>

NoDesc == [seq |-> 0, pstart |-> 0, plen |-> 0]
EmptyDesc == [i \in 0..DescCap - 1 |-> NoDesc]
EmptyPay == [j \in 0..PayCap - 1 |-> 0]

Init ==
    /\ state = [s \in Slots |-> "free"]
    /\ alive = [s \in Slots |-> FALSE]
    /\ phase = [s \in Slots |-> "idle"]
    /\ pending = [s \in Slots |-> NoDesc]
    /\ gen = [s \in Slots |-> 1]
    /\ claimGen = [s \in Slots |-> 0]
    /\ needBump = [s \in Slots |-> FALSE]
    /\ nextSeq = [s \in Slots |-> 1]
    /\ dropped = [s \in Slots |-> 0]
    /\ wc = [s \in Slots |-> 0]
    /\ rc = [s \in Slots |-> 0]
    /\ pw = [s \in Slots |-> 0]
    /\ pr = [s \in Slots |-> 0]
    /\ ringDesc = [s \in Slots |-> EmptyDesc]
    /\ ringPay = [s \in Slots |-> EmptyPay]
    /\ curPub = [s \in Slots |-> << >>]
    /\ pubHist = [s \in Slots |-> << >>]
    /\ queue = [s \in Slots |-> << >>]
    /\ accepted = [s \in Slots |-> << >>]

Writing(s) == state[s] \in {"active", "draining"}

(***************************************************************************)
(* 書き手 (Agent)                                                           *)
(***************************************************************************)

(* Slot 取得: FREE が公開されているときだけ。観測した Generation を残す。 *)
Claim(s) ==
    /\ state[s] = "free"
    /\ ~alive[s]
    /\ state' = [state EXCEPT ![s] = "active"]
    /\ alive' = [alive EXCEPT ![s] = TRUE]
    /\ claimGen' = [claimGen EXCEPT ![s] = gen[s]]
    /\ UNCHANGED <<phase, pending, gen, needBump, nextSeq, dropped, wc, rc, pw, pr,
                   ringDesc, ringPay, curPub, pubHist, queue, accepted>>

HasRoom(s, size) ==
    /\ wc[s] - rc[s] < DescCap
    /\ pw[s] + size - pr[s] <= PayCap

(* 空きを read_cursor と解放位置で確かめ、Payload (終端をまたぐなら分けて)
   と Descriptor を書く。まだ公開しない。 *)
Write(s, size) ==
    /\ state[s] = "active"
    /\ alive[s]
    /\ phase[s] = "idle"
    /\ nextSeq[s] <= MaxEvents
    /\ HasRoom(s, size)
    /\ ringPay' = [ringPay EXCEPT ![s] =
           [j \in 0..PayCap - 1 |->
               IF \E k \in 0..size - 1: (pw[s] + k) % PayCap = j
               THEN nextSeq[s] ELSE ringPay[s][j]]]
    /\ ringDesc' = [ringDesc EXCEPT ![s][wc[s] % DescCap] =
           [seq |-> nextSeq[s], pstart |-> pw[s], plen |-> size]]
    /\ pending' = [pending EXCEPT ![s] = [seq |-> nextSeq[s], pstart |-> pw[s], plen |-> size]]
    /\ pw' = [pw EXCEPT ![s] = pw[s] + size]
    /\ nextSeq' = [nextSeq EXCEPT ![s] = nextSeq[s] + 1]
    /\ phase' = [phase EXCEPT ![s] = "written"]
    /\ UNCHANGED <<state, alive, gen, claimGen, needBump, dropped, wc, rc, pr,
                   curPub, pubHist, queue, accepted>>

(* 単一の公開点: write_cursor を進める (Descriptor と Payload を同時に公開)。 *)
Publish(s) ==
    /\ alive[s]
    /\ phase[s] = "written"
    /\ wc' = [wc EXCEPT ![s] = wc[s] + 1]
    /\ phase' = [phase EXCEPT ![s] = "idle"]
    /\ curPub' = [curPub EXCEPT ![s] = Append(curPub[s], pending[s])]
    /\ pubHist' = [pubHist EXCEPT ![s] = Append(pubHist[s], [gen |-> gen[s], seq |-> pending[s].seq])]
    /\ UNCHANGED <<state, alive, pending, gen, claimGen, needBump, nextSeq, dropped,
                   rc, pw, pr, ringDesc, ringPay, queue, accepted>>

(* 満杯なら (上限付きの待機の後) 欠落として前に進む。Host は待たない。 *)
DropWhenFull(s, size) ==
    /\ state[s] = "active"
    /\ alive[s]
    /\ phase[s] = "idle"
    /\ nextSeq[s] <= MaxEvents
    /\ ~HasRoom(s, size)
    /\ nextSeq' = [nextSeq EXCEPT ![s] = nextSeq[s] + 1]
    /\ dropped' = [dropped EXCEPT ![s] = dropped[s] + 1]
    /\ UNCHANGED <<state, alive, phase, pending, gen, claimGen, needBump, wc, rc, pw, pr,
                   ringDesc, ringPay, curPub, pubHist, queue, accepted>>

(* DLL_THREAD_DETACH: DRAINING への移行の合図だけ。 *)
Detach(s) ==
    /\ state[s] = "active"
    /\ alive[s]
    /\ phase[s] = "idle"
    /\ state' = [state EXCEPT ![s] = "draining"]
    /\ UNCHANGED <<alive, phase, pending, gen, claimGen, needBump, nextSeq, dropped,
                   wc, rc, pw, pr, ringDesc, ringPay, curPub, pubHist, queue, accepted>>

(* DETACH 後の呼び出しは記録せず欠落として数える。 *)
CallAfterDetach(s) ==
    /\ state[s] = "draining"
    /\ alive[s]
    /\ nextSeq[s] <= MaxEvents
    /\ nextSeq' = [nextSeq EXCEPT ![s] = nextSeq[s] + 1]
    /\ dropped' = [dropped EXCEPT ![s] = dropped[s] + 1]
    /\ UNCHANGED <<state, alive, phase, pending, gen, claimGen, needBump, wc, rc, pw, pr,
                   ringDesc, ringPay, curPub, pubHist, queue, accepted>>

(* 通常の終了 (DETACH の後) と、DETACH なしの強制終了 (どの時点でも、
   書いて未公開のイベントがあっても)。終了したスレッドは二度と書かない。 *)
Exit(s) ==
    /\ state[s] = "draining"
    /\ alive[s]
    /\ phase[s] = "idle"
    /\ alive' = [alive EXCEPT ![s] = FALSE]
    /\ UNCHANGED <<state, phase, pending, gen, claimGen, needBump, nextSeq, dropped,
                   wc, rc, pw, pr, ringDesc, ringPay, curPub, pubHist, queue, accepted>>

Terminate(s) ==
    /\ Writing(s)
    /\ alive[s]
    /\ alive' = [alive EXCEPT ![s] = FALSE]
    /\ UNCHANGED <<state, phase, pending, gen, claimGen, needBump, nextSeq, dropped,
                   wc, rc, pw, pr, ringDesc, ringPay, curPub, pubHist, queue, accepted>>

(***************************************************************************)
(* 読み手 (Host)                                                            *)
(***************************************************************************)

PayloadOf(s, d) == [k \in 1..d.plen |-> ringPay[s][(d.pstart + k - 1) % PayCap]]

(* 回収: 公開済みの Descriptor と、それが参照する Payload をコピーしてから、
   コピーした範囲だけを解放する。Payload は最後にコピーした Descriptor の
   終端までしか解放しない (その先は未公開のイベントのものかもしれない)。 *)
Collect(s) ==
    /\ Writing(s)
    /\ rc[s] < wc[s]
    /\ LET n == wc[s] - rc[s]
           d(k) == ringDesc[s][(rc[s] + k - 1) % DescCap]
           copied == [k \in 1..n |->
                        [gen |-> gen[s], seq |-> d(k).seq, pstart |-> d(k).pstart,
                         plen |-> d(k).plen,
                         payload |-> IF ValidateShared THEN << >> ELSE PayloadOf(s, d(k))]]
       IN /\ queue' = [queue EXCEPT ![s] = queue[s] \o copied]
          /\ rc' = [rc EXCEPT ![s] = wc[s]]
          /\ pr' = [pr EXCEPT ![s] = d(n).pstart + d(n).plen]
    /\ UNCHANGED <<state, alive, phase, pending, gen, claimGen, needBump, nextSeq, dropped,
                   wc, pw, ringDesc, ringPay, curPub, pubHist, accepted>>

(* 検証と受け入れ: 解放の後、どれだけ遅れてもよい。Host 自身のコピーだけを
   読む (変種 ValidateShared は共有メモリを読み直す)。Payload の中身が
   そのイベントのものであれば intact。 *)
Validate(s) ==
    /\ queue[s] # << >>
    /\ LET e == Head(queue[s])
           payload == IF ValidateShared THEN PayloadOf(s, e) ELSE e.payload
       IN accepted' = [accepted EXCEPT ![s] = Append(accepted[s],
              [gen |-> e.gen, seq |-> e.seq,
               intact |-> \A k \in 1..e.plen: payload[k] = e.seq])]
    /\ queue' = [queue EXCEPT ![s] = Tail(queue[s])]
    /\ UNCHANGED <<state, alive, phase, pending, gen, claimGen, needBump, nextSeq, dropped,
                   wc, rc, pw, pr, ringDesc, ringPay, curPub, pubHist>>

(* 再利用の判定: スレッドの終了を (DETACH の有無によらず) 確認し、公開済み
   の Descriptor をすべてコピーし終えたこと。未検証のコピーが残っていても
   よい (検証はコピーだけを読む)。書いて未公開の Payload があるので
   Payload の書き込み位置は見ない (変種 ReclaimByPayload は見る)。 *)
Drained(s) == IF ReclaimByPayload THEN rc[s] = wc[s] /\ pr[s] = pw[s] ELSE rc[s] = wc[s]

ResetRing(s) ==
    /\ phase' = [phase EXCEPT ![s] = "idle"]
    /\ pending' = [pending EXCEPT ![s] = NoDesc]
    /\ nextSeq' = [nextSeq EXCEPT ![s] = 1]
    /\ dropped' = [dropped EXCEPT ![s] = 0]
    /\ wc' = [wc EXCEPT ![s] = 0]
    /\ rc' = [rc EXCEPT ![s] = 0]
    /\ pw' = [pw EXCEPT ![s] = 0]
    /\ pr' = [pr EXCEPT ![s] = 0]
    /\ ringDesc' = [ringDesc EXCEPT ![s] = EmptyDesc]
    /\ ringPay' = [ringPay EXCEPT ![s] = EmptyPay]
    /\ curPub' = [curPub EXCEPT ![s] = << >>]

(* 再利用の第 1 段階: RECLAIMING の間に Control をゼロに戻し Generation を
   進める。FREE はまだ公開しない。変種 FreeBeforeGen は FREE を先に公開し、
   Generation の更新 (BumpGen) を後に残す。 *)
ReclaimBegin(s) ==
    /\ Writing(s)
    /\ ~alive[s]
    /\ Drained(s)
    /\ ResetRing(s)
    /\ IF gen[s] >= MaxGen
       THEN /\ state' = [state EXCEPT ![s] = "retired"]
            /\ UNCHANGED <<gen, needBump>>
       ELSE IF FreeBeforeGen
       THEN /\ state' = [state EXCEPT ![s] = "free"]
            /\ needBump' = [needBump EXCEPT ![s] = TRUE]
            /\ UNCHANGED gen
       ELSE /\ state' = [state EXCEPT ![s] = "reclaiming"]
            /\ gen' = [gen EXCEPT ![s] = gen[s] + 1]
            /\ UNCHANGED needBump
    /\ UNCHANGED <<alive, claimGen, pubHist, queue, accepted>>

BumpGen(s) ==
    /\ needBump[s]
    /\ gen' = [gen EXCEPT ![s] = gen[s] + 1]
    /\ needBump' = [needBump EXCEPT ![s] = FALSE]
    /\ UNCHANGED <<state, alive, phase, pending, claimGen, nextSeq, dropped, wc, rc, pw, pr,
                   ringDesc, ringPay, curPub, pubHist, queue, accepted>>

(* 再利用の第 2 段階: FREE を公開する。 *)
PublishFree(s) ==
    /\ state[s] = "reclaiming"
    /\ state' = [state EXCEPT ![s] = "free"]
    /\ UNCHANGED <<alive, phase, pending, gen, claimGen, needBump, nextSeq, dropped,
                   wc, rc, pw, pr, ringDesc, ringPay, curPub, pubHist, queue, accepted>>

WriterStep(s) ==
    \/ Claim(s) \/ Publish(s) \/ Detach(s) \/ CallAfterDetach(s) \/ Exit(s) \/ Terminate(s)
    \/ \E size \in 0..MaxSize: Write(s, size) \/ DropWhenFull(s, size)

HostStep(s) == Collect(s) \/ Validate(s) \/ ReclaimBegin(s) \/ BumpGen(s) \/ PublishFree(s)

Next == \E s \in Slots: WriterStep(s) \/ HostStep(s)

(* 書き手には公平性を課さない (止まっても強制終了してもよい)。Host の手順
   だけが、可能であり続ければいずれ実行される。 *)
Fairness == \A s \in Slots:
    /\ WF_vars(Collect(s))
    /\ WF_vars(Validate(s))
    /\ WF_vars(ReclaimBegin(s))
    /\ WF_vars(BumpGen(s))
    /\ WF_vars(PublishFree(s))

Spec == Init /\ [][Next]_vars /\ Fairness

(***************************************************************************)
(* 不変条件                                                                 *)
(***************************************************************************)

TypeOK ==
    \A s \in Slots:
        /\ state[s] \in {"free", "active", "draining", "reclaiming", "retired"}
        /\ phase[s] \in {"idle", "written"}
        /\ rc[s] <= wc[s] /\ pr[s] <= pw[s]

(* 書き手は未回収の領域を書き換えない: 公開窓は両方の容量以内で、未回収の
   Descriptor と Payload は公開したときの内容のまま。 *)
NoOverwriteBeforeRelease ==
    \A s \in Slots:
        /\ wc[s] - rc[s] <= DescCap
        /\ pw[s] - pr[s] <= PayCap
        /\ \A i \in rc[s]..wc[s] - 1:
               LET d == ringDesc[s][i % DescCap]
               IN /\ d = curPub[s][i + 1]
                  /\ \A k \in 1..d.plen: PayloadOf(s, d)[k] = d.seq

(* Host が受け入れたイベントは、書き手が公開したイベントの先頭からの並びに
   一致し、中身は公開したときのもの (解放後の書き換えに影響されない)。
   未公開のイベント (強制終了で書きかけのもの) は受け入れない。 *)
AcceptedIsPublished ==
    \A s \in Slots:
        /\ Len(accepted[s]) + Len(queue[s]) <= Len(pubHist[s])
        /\ \A k \in 1..Len(accepted[s]):
               /\ accepted[s][k].gen = pubHist[s][k].gen
               /\ accepted[s][k].seq = pubHist[s][k].seq
               /\ accepted[s][k].intact

(* 取得者が観測した Generation は、取得中ずっと現在の Generation と一致する。 *)
ClaimedGenerationIsCurrent ==
    \A s \in Slots: state[s] = "active" => claimGen[s] = gen[s]

(* 再利用中・空き・退役の Slot を持つスレッドは生きていない (古い書き手が
   再利用後の Ring に書くことはない)。 *)
NoStaleProducerWrite ==
    \A s \in Slots: state[s] \in {"free", "reclaiming", "retired"} => ~alive[s]

(* 書き手は Host を待たない: 生きている書き手は、Host が止まっていても
   常に次の呼び出しを記録するか欠落として数えて前に進める。 *)
WriterNeverBlocks ==
    \A s \in Slots:
        (alive[s] /\ Writing(s) /\ nextSeq[s] <= MaxEvents) =>
            \/ ENABLED Publish(s)
            \/ ENABLED CallAfterDetach(s)
            \/ \A size \in 0..MaxSize: ENABLED (Write(s, size) \/ DropWhenFull(s, size))

(***************************************************************************)
(* 進行性 (Host の公平性の下で)                                             *)
(***************************************************************************)

(* 公開されたイベントはいずれすべて受け入れられる。 *)
EverythingPublishedIsAccepted ==
    \A s \in Slots: <>[](Len(accepted[s]) = Len(pubHist[s]))

(* 終了したスレッドの Slot は、DETACH の有無や書きかけのイベントによらず、
   いずれ再利用 (または世代の上限で退役) に進む。 *)
DeadSlotIsReclaimed ==
    \A s \in Slots:
        (Writing(s) /\ ~alive[s]) ~> (state[s] \in {"free", "reclaiming", "retired"})

=============================================================================
