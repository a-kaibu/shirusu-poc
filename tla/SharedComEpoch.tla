--------------------------- MODULE SharedComEpoch ---------------------------
(***************************************************************************)
(* 共有 vtable フック (shirusu-hook::shared_com) の Module Epoch 手順。      *)
(*                                                                         *)
(* 1 つの index を、管理側が予約 → 公開 → 回収 → 別モジュールで再利用する *)
(* 流れと、各モジュールのアンロード通知 (ローダーロック内のコールバック)    *)
(* が任意に遅れて走る流れを、実装の原子操作の単位で交互実行する。           *)
(*  - install:  e := (MODULE_EPOCHS | 1) + 1; MODULES := m; MODULE_EPOCHS := e *)
(*  - callback: e := load EPOCH; m := load MODULES; if e#0 /\ m=base:        *)
(*              CAS(EPOCH, e, e|1)                                          *)
(*  - reclaim:  MODULES := 0 (epoch はそのまま)                              *)
(* 通知はそのモジュールの公開後にしか始まらない (install 中のアンロードは   *)
(* 呼び出し契約で除外)。                                                    *)
(*                                                                         *)
(* loom ではなく TLA+ で検査する理由: loom 0.7 は変更順序を部分順序で持つため *)
(* 「CAS と別スレッドの通常 store」の競合で C11 では起こり得ない結果         *)
(* (CAS が上書き済みの値を読んで成功する) を生成し、この手順の性質を偽陽性で *)
(* 落とす (2026-11-13 に最小リトマスで確認)。ここでは逐次一貫の交互実行で    *)
(* 手順そのものの論理を網羅する。メモリ順序は検査しない。                   *)
(*                                                                         *)
(* BlindStore = TRUE の変種 (CAS をやめ、読んだ値 | 1 を書く) では           *)
(* NoStaleRetire が破れることを tla.sh で必須にする。                        *)
(***************************************************************************)
EXTENDS Naturals
CONSTANTS Modules, BlindStore

VARIABLES mod, ep, mpc, next, tmp, cur, published, cpc, cep, cmod, owner
vars == <<mod, ep, mpc, next, tmp, cur, published, cpc, cep, cmod, owner>>

Odd(x) == x % 2 = 1
Retire(x) == IF Odd(x) THEN x ELSE x + 1
NextEpoch(x) == Retire(x) + 1
N == Modules

Init == /\ mod = 0 /\ ep = 0 /\ mpc = "free" /\ next = 1 /\ tmp = 0 /\ cur = 0
        /\ published = [m \in 1..N |-> FALSE]
        /\ cpc = [m \in 1..N |-> "idle"] /\ cep = [m \in 1..N |-> 0]
        /\ cmod = [m \in 1..N |-> 0]
        /\ owner = 0   \* ゴースト: 現在の奇数 epoch を書いたコールバックのモジュール

Begin == /\ mpc = "free" /\ next <= N /\ mpc' = "ld"
         /\ UNCHANGED <<mod, ep, next, tmp, cur, published, cpc, cep, cmod, owner>>
LoadEpoch == /\ mpc = "ld" /\ tmp' = NextEpoch(ep) /\ mpc' = "st_mod"
             /\ UNCHANGED <<mod, ep, next, cur, published, cpc, cep, cmod, owner>>
StoreModule == /\ mpc = "st_mod" /\ mod' = next /\ mpc' = "st_ep"
               /\ UNCHANGED <<ep, next, tmp, cur, published, cpc, cep, cmod, owner>>
StoreEpoch == /\ mpc = "st_ep" /\ ep' = tmp /\ owner' = 0
              /\ cur' = next /\ published' = [published EXCEPT ![next] = TRUE]
              /\ mpc' = "live"
              /\ UNCHANGED <<mod, next, tmp, cpc, cep, cmod>>
Reclaim == /\ mpc = "live" /\ mod' = 0 /\ cur' = 0 /\ next' = next + 1 /\ mpc' = "free"
           /\ UNCHANGED <<ep, tmp, published, cpc, cep, cmod, owner>>
Manager == Begin \/ LoadEpoch \/ StoreModule \/ StoreEpoch \/ Reclaim

CbStart(m) == /\ cpc[m] = "idle" /\ published[m] /\ cpc' = [cpc EXCEPT ![m] = "ld_ep"]
              /\ UNCHANGED <<mod, ep, mpc, next, tmp, cur, published, cep, cmod, owner>>
CbLoadEpoch(m) == /\ cpc[m] = "ld_ep" /\ cep' = [cep EXCEPT ![m] = ep]
                  /\ cpc' = [cpc EXCEPT ![m] = "ld_mod"]
                  /\ UNCHANGED <<mod, ep, mpc, next, tmp, cur, published, cmod, owner>>
CbLoadModule(m) == /\ cpc[m] = "ld_mod" /\ cmod' = [cmod EXCEPT ![m] = mod]
                   /\ cpc' = [cpc EXCEPT ![m] = "cas"]
                   /\ UNCHANGED <<mod, ep, mpc, next, tmp, cur, published, cep, owner>>
CbRetire(m) == /\ cpc[m] = "cas" /\ cpc' = [cpc EXCEPT ![m] = "done"]
               /\ IF cep[m] # 0 /\ cmod[m] = m /\ (BlindStore \/ ep = cep[m])
                     THEN /\ ep' = Retire(cep[m])
                          /\ owner' = IF ep' # ep THEN m ELSE owner
                     ELSE UNCHANGED <<ep, owner>>
               /\ UNCHANGED <<mod, mpc, next, tmp, cur, published, cep, cmod>>
Callback(m) == CbStart(m) \/ CbLoadEpoch(m) \/ CbLoadModule(m) \/ CbRetire(m)

Next == Manager \/ \E m \in 1..N : Callback(m)
Spec == Init /\ [][Next]_vars

\* 生きた予約が退役しているなら、退役させたのはそのモジュール自身の通知。
NoStaleRetire == (mpc = "live" /\ Odd(ep)) => owner = cur
\* 公開後に始まった自モジュールの通知が完了していれば、予約は必ず退役済み
\* (アンロードの観測は失われない)。
UnloadObserved == \A m \in 1..N : (cpc[m] = "done" /\ cur = m /\ mpc = "live") => Odd(ep)
\* epoch は単調に増え、新しい予約は旧予約のどの値 (退役済みを含む) とも異なる偶数。
FreshEpoch == (mpc \in {"st_mod", "st_ep"}) => (tmp > ep /\ ~Odd(tmp))
EpochMonotone == [][ep' >= ep]_vars
=============================================================================
