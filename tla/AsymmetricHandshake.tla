------------------------- MODULE AsymmetricHandshake -------------------------
(* Asymmetric Dekker handshakes of the recording fast path (review P0/P1):

   - WriterCell (crates/shirusu-agent/src/writer_cell.rs): the owner thread
     sets owner_busy, issues only a compiler fence, and loads remote. A remote
     user sets remote, runs the heavy fence (FlushProcessWriteBuffers + SeqCst
     fence) and waits until owner_busy is false.
   - Hazard slots (crates/shirusu-hook/src/hazard.rs): an entering thread
     stores its hazard, compiler fence, and re-checks the gate (revision or
     recording flag). The reclaimer closes the gate, heavy fence, then scans
     hazards before it frees the runtime.

   Memory model. The light side's compiler fence emits no instruction, so its
   store may still sit in the store buffer when its following load executes
   (store->load reordering, the only reordering x86/x64 TSO allows and the one
   the handshake must tolerate). Each light-side thread therefore has a FIFO
   store buffer that commits nondeterministically; its loads see its own
   newest buffered store first. The heavy fence is modeled as what
   FlushProcessWriteBuffers guarantees: when it returns, every processor
   running a thread of the process has executed a full barrier, so every
   store issued before that point is visible (the buffer is drained). Heavy
   side stores are followed by a full fence and go straight to memory.
   On ARM64 the same argument holds for the barrier the IPI forces at a point
   of the owner's program order; the model covers only store->load
   reordering, which is the reordering the handshake depends on.

   Forced termination (TerminateThread). A light-side thread may be terminated
   at any step and runs no further step (no Drop). Its already issued stores
   still commit. The kernel reports termination only after the thread stopped
   running, so "terminated" is observable once it is dead and its buffer is
   empty. CheckLiveness models ThreadLiveness::has_terminated: the waiting
   side gives up only on proven termination, never on a timeout.

   Variants (each must be refuted by TLC, see scripts/ci/tla.sh):
   - HeavyFence = FALSE: the remote side's flush is missing.
   - TakeoverOnTimeout = TRUE: the waiting side proceeds after a timeout.
   - CheckLiveness = FALSE: the waiting side ignores termination (old code).
*)
EXTENDS Naturals, Sequences

CONSTANTS HeavyFence, TakeoverOnTimeout, CheckLiveness, AllowTerminate,
          Rounds, MaxBuf

VARIABLES mem, obuf, tbuf, opc, rpc, tpc, cpc, rounds,
          poisoned, abandoned, freed, odead, tdead

vars == <<mem, obuf, tbuf, opc, rpc, tpc, cpc, rounds,
          poisoned, abandoned, freed, odead, tdead>>

Vars == {"busy", "remote", "hz", "gate"}

\* TSO load: the thread's newest buffered store to v, else memory.
Read(buf, v) ==
  LET idx == {i \in 1..Len(buf) : buf[i].var = v}
  IN IF idx = {} THEN mem[v]
     ELSE buf[CHOOSE i \in idx : \A j \in idx : j <= i].val

RECURSIVE ApplyAll(_, _)
ApplyAll(m, buf) ==
  IF buf = <<>> THEN m
  ELSE ApplyAll([m EXCEPT ![Head(buf).var] = Head(buf).val], Tail(buf))

St(v, b) == [var |-> v, val |-> b]

OwnerTerminated == odead /\ obuf = <<>>
HazardOwnerTerminated == tdead /\ tbuf = <<>>

Init ==
  /\ mem = [v \in Vars |-> IF v = "gate" THEN TRUE ELSE FALSE]
  /\ obuf = <<>> /\ tbuf = <<>>
  /\ opc = "idle" /\ rpc = "idle" /\ tpc = "idle" /\ cpc = "idle"
  /\ rounds = 0
  /\ poisoned = FALSE /\ abandoned = FALSE /\ freed = FALSE
  /\ odead = FALSE /\ tdead = FALSE

-----------------------------------------------------------------------------
(* WriterCell owner: try_owner / OwnerGuard::drop. "inside" is the use of
   the writer. A backed-off owner takes the exclusive path, modeled as
   waiting until the remote user is done. *)
OSetBusy ==
  /\ ~odead /\ opc = "idle" /\ Len(obuf) < MaxBuf
  /\ obuf' = Append(obuf, St("busy", TRUE)) /\ opc' = "check"
  /\ UNCHANGED <<mem, tbuf, rpc, tpc, cpc, rounds, poisoned, abandoned, freed, odead, tdead>>
OCheck ==
  /\ ~odead /\ opc = "check"
  /\ opc' = IF Read(obuf, "remote") THEN "backoff" ELSE "inside"
  /\ UNCHANGED <<mem, obuf, tbuf, rpc, tpc, cpc, rounds, poisoned, abandoned, freed, odead, tdead>>
OBackoff ==
  /\ ~odead /\ opc = "backoff" /\ Len(obuf) < MaxBuf
  /\ obuf' = Append(obuf, St("busy", FALSE)) /\ opc' = "blocked"
  /\ UNCHANGED <<mem, tbuf, rpc, tpc, cpc, rounds, poisoned, abandoned, freed, odead, tdead>>
OBlocked ==
  /\ ~odead /\ opc = "blocked" /\ ~Read(obuf, "remote")
  /\ opc' = "idle"
  /\ UNCHANGED <<mem, obuf, tbuf, rpc, tpc, cpc, rounds, poisoned, abandoned, freed, odead, tdead>>
OUse ==
  /\ ~odead /\ opc = "inside"
  /\ opc' = "leave"
  /\ UNCHANGED <<mem, obuf, tbuf, rpc, tpc, cpc, rounds, poisoned, abandoned, freed, odead, tdead>>
OLeave ==
  /\ ~odead /\ opc = "leave" /\ Len(obuf) < MaxBuf
  /\ obuf' = Append(obuf, St("busy", FALSE)) /\ opc' = "idle"
  /\ UNCHANGED <<mem, tbuf, rpc, tpc, cpc, rounds, poisoned, abandoned, freed, odead, tdead>>
OCommit ==
  /\ obuf # <<>>
  /\ mem' = [mem EXCEPT ![Head(obuf).var] = Head(obuf).val] /\ obuf' = Tail(obuf)
  /\ UNCHANGED <<tbuf, opc, rpc, tpc, cpc, rounds, poisoned, abandoned, freed, odead, tdead>>
\* TerminateThread at any step. Cut off while using the writer: poisoned.
OTerminate ==
  /\ AllowTerminate /\ ~odead
  /\ odead' = TRUE /\ opc' = "dead" /\ poisoned' = (opc \in {"inside", "leave"})
  /\ UNCHANGED <<mem, obuf, tbuf, rpc, tpc, cpc, rounds, abandoned, freed, tdead>>

(* WriterCell::exclusive. *)
RStart ==
  /\ rpc = "idle" /\ rounds < Rounds
  /\ mem' = [mem EXCEPT !["remote"] = TRUE] /\ rpc' = "fence"
  /\ UNCHANGED <<obuf, tbuf, opc, tpc, cpc, rounds, poisoned, abandoned, freed, odead, tdead>>
RFence ==
  /\ rpc = "fence"
  /\ IF HeavyFence THEN mem' = ApplyAll(mem, obuf) /\ obuf' = <<>>
                   ELSE UNCHANGED <<mem, obuf>>
  /\ rpc' = "wait"
  /\ UNCHANGED <<tbuf, opc, tpc, cpc, rounds, poisoned, abandoned, freed, odead, tdead>>
RWait ==
  /\ rpc = "wait"
  /\ \/ ~mem["busy"] /\ rpc' = "inside" /\ UNCHANGED abandoned
     \/ mem["busy"] /\ CheckLiveness /\ OwnerTerminated
        /\ rpc' = "abandoned" /\ abandoned' = TRUE
     \/ mem["busy"] /\ TakeoverOnTimeout /\ rpc' = "inside" /\ UNCHANGED abandoned
  /\ UNCHANGED <<mem, obuf, tbuf, opc, tpc, cpc, rounds, poisoned, freed, odead, tdead>>
RUse ==
  /\ rpc = "inside" /\ rpc' = "clear"
  /\ UNCHANGED <<mem, obuf, tbuf, opc, tpc, cpc, rounds, poisoned, abandoned, freed, odead, tdead>>
RClear ==
  /\ rpc = "clear"
  /\ mem' = [mem EXCEPT !["remote"] = FALSE] /\ rpc' = "idle" /\ rounds' = rounds + 1
  /\ UNCHANGED <<obuf, tbuf, opc, tpc, cpc, poisoned, abandoned, freed, odead, tdead>>

-----------------------------------------------------------------------------
(* Hazard slot: RuntimeSlot::cached_hazard ("use" dereferences the runtime). *)
TPublish ==
  /\ ~tdead /\ tpc = "idle" /\ Len(tbuf) < MaxBuf
  /\ tbuf' = Append(tbuf, St("hz", TRUE)) /\ tpc' = "check"
  /\ UNCHANGED <<mem, obuf, opc, rpc, cpc, rounds, poisoned, abandoned, freed, odead, tdead>>
TCheck ==
  /\ ~tdead /\ tpc = "check"
  /\ tpc' = IF Read(tbuf, "gate") THEN "use" ELSE "withdraw"
  /\ UNCHANGED <<mem, obuf, tbuf, opc, rpc, cpc, rounds, poisoned, abandoned, freed, odead, tdead>>
TUse ==
  /\ ~tdead /\ tpc = "use" /\ tpc' = "clear"
  /\ UNCHANGED <<mem, obuf, tbuf, opc, rpc, cpc, rounds, poisoned, abandoned, freed, odead, tdead>>
TClear ==
  /\ ~tdead /\ tpc \in {"clear", "withdraw"} /\ Len(tbuf) < MaxBuf
  /\ tbuf' = Append(tbuf, St("hz", FALSE))
  /\ tpc' = IF tpc = "clear" THEN "idle" ELSE "done"
  /\ UNCHANGED <<mem, obuf, opc, rpc, cpc, rounds, poisoned, abandoned, freed, odead, tdead>>
TCommit ==
  /\ tbuf # <<>>
  /\ mem' = [mem EXCEPT ![Head(tbuf).var] = Head(tbuf).val] /\ tbuf' = Tail(tbuf)
  /\ UNCHANGED <<obuf, opc, rpc, tpc, cpc, rounds, poisoned, abandoned, freed, odead, tdead>>
TTerminate ==
  /\ AllowTerminate /\ ~tdead
  /\ tdead' = TRUE /\ tpc' = "dead"
  /\ UNCHANGED <<mem, obuf, tbuf, opc, rpc, cpc, rounds, poisoned, abandoned, freed, odead>>

(* Reclaimer: RuntimeSlot::reclaim / wait_in_flight_drained. A hazard whose
   owner is proven terminated is withdrawn (hazard::reap_if_terminated). *)
CClose ==
  /\ cpc = "idle"
  /\ mem' = [mem EXCEPT !["gate"] = FALSE] /\ cpc' = "fence"
  /\ UNCHANGED <<obuf, tbuf, opc, rpc, tpc, rounds, poisoned, abandoned, freed, odead, tdead>>
CFence ==
  /\ cpc = "fence"
  /\ IF HeavyFence THEN mem' = ApplyAll(mem, tbuf) /\ tbuf' = <<>>
                   ELSE UNCHANGED <<mem, tbuf>>
  /\ cpc' = "scan"
  /\ UNCHANGED <<obuf, opc, rpc, tpc, rounds, poisoned, abandoned, freed, odead, tdead>>
\* Re-scans pay no fence (count_published); only hazards already visible or
\* committed later are seen.
CScan ==
  /\ cpc = "scan"
  /\ \/ ~mem["hz"]
     \/ mem["hz"] /\ CheckLiveness /\ HazardOwnerTerminated
     \/ mem["hz"] /\ TakeoverOnTimeout
  /\ cpc' = "freed" /\ freed' = TRUE
  /\ UNCHANGED <<mem, obuf, tbuf, opc, rpc, tpc, rounds, poisoned, abandoned, odead, tdead>>

-----------------------------------------------------------------------------
OwnerSteps == OSetBusy \/ OCheck \/ OBackoff \/ OBlocked \/ OUse \/ OLeave
RemoteSteps == RStart \/ RFence \/ RWait \/ RUse \/ RClear
HazardSteps == TPublish \/ TCheck \/ TUse \/ TClear
ReclaimSteps == CClose \/ CFence \/ CScan

Next == OwnerSteps \/ OCommit \/ OTerminate \/ RemoteSteps
        \/ HazardSteps \/ TCommit \/ TTerminate \/ ReclaimSteps

Spec == Init /\ [][Next]_vars
        /\ WF_vars(OwnerSteps) /\ WF_vars(OCommit) /\ WF_vars(RemoteSteps)
        /\ WF_vars(HazardSteps) /\ WF_vars(TCommit) /\ WF_vars(ReclaimSteps)

-----------------------------------------------------------------------------
TypeOK ==
  /\ mem \in [Vars -> BOOLEAN]
  /\ Len(obuf) <= MaxBuf /\ Len(tbuf) <= MaxBuf
  /\ rounds \in 0..Rounds

\* The owner and a remote user never use the writer at the same time.
MutualExclusion == ~(opc \in {"inside", "leave"} /\ rpc = "inside")
\* A writer cut off mid-use is never used again.
NoPoisonedUse == rpc = "inside" => ~poisoned
\* An abandoned cell keeps the fast path closed (remote stays set).
AbandonedStaysClosed == abandoned => (mem["remote"] /\ rpc = "abandoned")
\* A runtime is never freed while a thread dereferences it.
HazardSafe == ~(freed /\ tpc = "use")

\* Waiting never lasts forever, even when the owner was terminated.
RemoteProgress == (rpc = "wait") ~> (rpc \in {"inside", "abandoned"})
ReclaimProgress == (cpc = "scan") ~> (cpc = "freed")
==============================================================================
