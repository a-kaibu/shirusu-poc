---------------------- MODULE OverlappedLifecycle ----------------------
EXTENDS Naturals
CONSTANT RegisterBeforeLaunch
VARIABLES phase, pending, consumed, lost
vars == <<phase, pending, consumed, lost>>
Init == /\ phase = "new" /\ pending = 0 /\ consumed = FALSE /\ lost = FALSE
Register == /\ phase = "new" /\ RegisterBeforeLaunch
            /\ pending' = 1 /\ phase' = "registered"
            /\ UNCHANGED <<consumed,lost>>
Launch == /\ phase = IF RegisterBeforeLaunch THEN "registered" ELSE "new"
          /\ phase' = "launched" /\ UNCHANGED <<pending,consumed,lost>>
Complete == /\ phase = "launched" /\ ~consumed
            /\ lost' = (pending # 1) /\ pending' = 2 /\ consumed' = TRUE
            /\ UNCHANGED phase
Return == /\ phase = "launched" /\ phase' = "returned"
          /\ pending' = IF RegisterBeforeLaunch THEN pending ELSE 1
          /\ UNCHANGED <<consumed,lost>>
CancelOld == /\ phase = "returned" /\ phase' = "done"
             /\ pending' = IF pending = 1 THEN 0 ELSE pending
             /\ UNCHANGED <<consumed,lost>>
Next == Register \/ Launch \/ Complete \/ Return \/ CancelOld
NoLostCompletion == ~lost
NoEraseReusedOperation == consumed => pending = 2
Spec == Init /\ [][Next]_vars
=============================================================================
