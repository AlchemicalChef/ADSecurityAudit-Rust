---------------------------- MODULE KRBTGTRotation ----------------------------
(****************************************************************************)
(* TLA+ Formal Specification: KRBTGT Password Rotation State Machine       *)
(*                                                                          *)
(* Models the two-phase KRBTGT password rotation required for Active       *)
(* Directory security. The KRBTGT account is special - its password hash   *)
(* is used to encrypt Kerberos tickets. Rotating it requires two phases    *)
(* with a mandatory wait period to ensure all domain controllers have      *)
(* replicated and old tickets have expired.                                 *)
(*                                                                          *)
(* Based on: src-tauri/src/krbtgt.rs (RotationStatus struct)               *)
(****************************************************************************)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    MIN_WAIT_SECONDS,   \* Minimum wait between phases (10 hours = 36000)
    MAX_WAIT_SECONDS,   \* Maximum recommended wait (24 hours = 86400)
    MAX_TIME,           \* Model checking bound for time
    DOMAINS             \* Set of domain identifiers

VARIABLES
    rotationPhase,      \* Function: domain -> phase state
    phase1Time,         \* Function: domain -> timestamp of phase 1 completion (-1 if not done)
    phase2Time,         \* Function: domain -> timestamp of phase 2 completion (-1 if not done)
    currentTime,        \* Global time counter (seconds since start)
    rotationError       \* Function: domain -> error state (TRUE if failed)

vars == <<rotationPhase, phase1Time, phase2Time, currentTime, rotationError>>

(****************************************************************************)
(* Type Definitions                                                         *)
(****************************************************************************)

PhaseState == {"NotStarted", "Phase1InProgress", "Phase1Complete",
               "Phase2InProgress", "Phase2Complete", "Failed"}

TypeInvariant ==
    /\ rotationPhase \in [DOMAINS -> PhaseState]
    /\ phase1Time \in [DOMAINS -> Int]
    /\ phase2Time \in [DOMAINS -> Int]
    /\ currentTime \in Nat
    /\ rotationError \in [DOMAINS -> BOOLEAN]

(****************************************************************************)
(* Initial State                                                            *)
(****************************************************************************)

Init ==
    /\ rotationPhase = [d \in DOMAINS |-> "NotStarted"]
    /\ phase1Time = [d \in DOMAINS |-> -1]
    /\ phase2Time = [d \in DOMAINS |-> -1]
    /\ currentTime = 0
    /\ rotationError = [d \in DOMAINS |-> FALSE]

(****************************************************************************)
(* Actions                                                                  *)
(****************************************************************************)

\* Start phase 1 rotation for a domain
StartPhase1(domain) ==
    /\ domain \in DOMAINS
    /\ rotationPhase[domain] = "NotStarted"
    /\ rotationError[domain] = FALSE
    /\ rotationPhase' = [rotationPhase EXCEPT ![domain] = "Phase1InProgress"]
    /\ UNCHANGED <<phase1Time, phase2Time, currentTime, rotationError>>

\* Complete phase 1 (simulates successful LDAP password change)
CompletePhase1(domain) ==
    /\ domain \in DOMAINS
    /\ rotationPhase[domain] = "Phase1InProgress"
    /\ rotationPhase' = [rotationPhase EXCEPT ![domain] = "Phase1Complete"]
    /\ phase1Time' = [phase1Time EXCEPT ![domain] = currentTime]
    /\ UNCHANGED <<phase2Time, currentTime, rotationError>>

\* Fail phase 1 (LDAP error, connectivity issue, etc.)
FailPhase1(domain) ==
    /\ domain \in DOMAINS
    /\ rotationPhase[domain] = "Phase1InProgress"
    /\ rotationPhase' = [rotationPhase EXCEPT ![domain] = "Failed"]
    /\ rotationError' = [rotationError EXCEPT ![domain] = TRUE]
    /\ UNCHANGED <<phase1Time, phase2Time, currentTime>>

\* Start phase 2 - ONLY if phase 1 complete AND minimum wait elapsed
StartPhase2(domain) ==
    /\ domain \in DOMAINS
    /\ rotationPhase[domain] = "Phase1Complete"
    /\ phase1Time[domain] >= 0
    /\ currentTime >= phase1Time[domain] + MIN_WAIT_SECONDS
    /\ rotationPhase' = [rotationPhase EXCEPT ![domain] = "Phase2InProgress"]
    /\ UNCHANGED <<phase1Time, phase2Time, currentTime, rotationError>>

\* Attempt phase 2 too early (models the bug we want to catch)
\* This action exists to verify the invariant catches premature attempts
AttemptPrematurePhase2(domain) ==
    /\ domain \in DOMAINS
    /\ rotationPhase[domain] = "Phase1Complete"
    /\ phase1Time[domain] >= 0
    /\ currentTime < phase1Time[domain] + MIN_WAIT_SECONDS
    \* This should NOT happen in correct implementation
    /\ rotationPhase' = [rotationPhase EXCEPT ![domain] = "Phase2InProgress"]
    /\ UNCHANGED <<phase1Time, phase2Time, currentTime, rotationError>>

\* Complete phase 2 (full rotation complete)
CompletePhase2(domain) ==
    /\ domain \in DOMAINS
    /\ rotationPhase[domain] = "Phase2InProgress"
    /\ rotationPhase' = [rotationPhase EXCEPT ![domain] = "Phase2Complete"]
    /\ phase2Time' = [phase2Time EXCEPT ![domain] = currentTime]
    /\ UNCHANGED <<phase1Time, currentTime, rotationError>>

\* Fail phase 2
FailPhase2(domain) ==
    /\ domain \in DOMAINS
    /\ rotationPhase[domain] = "Phase2InProgress"
    /\ rotationPhase' = [rotationPhase EXCEPT ![domain] = "Failed"]
    /\ rotationError' = [rotationError EXCEPT ![domain] = TRUE]
    /\ UNCHANGED <<phase1Time, phase2Time, currentTime>>

\* Time advances (models real-time progression)
Tick ==
    /\ currentTime < MAX_TIME
    /\ currentTime' = currentTime + 1
    /\ UNCHANGED <<rotationPhase, phase1Time, phase2Time, rotationError>>

\* Reset a failed rotation to try again
ResetRotation(domain) ==
    /\ domain \in DOMAINS
    /\ rotationPhase[domain] = "Failed"
    /\ rotationPhase' = [rotationPhase EXCEPT ![domain] = "NotStarted"]
    /\ phase1Time' = [phase1Time EXCEPT ![domain] = -1]
    /\ phase2Time' = [phase2Time EXCEPT ![domain] = -1]
    /\ rotationError' = [rotationError EXCEPT ![domain] = FALSE]
    /\ UNCHANGED currentTime

(****************************************************************************)
(* Next State Relation                                                      *)
(****************************************************************************)

Next ==
    \/ \E d \in DOMAINS :
        \/ StartPhase1(d)
        \/ CompletePhase1(d)
        \/ FailPhase1(d)
        \/ StartPhase2(d)
        \/ CompletePhase2(d)
        \/ FailPhase2(d)
        \/ ResetRotation(d)
    \/ Tick

\* Fairness: time always eventually advances, phases eventually complete or fail
Fairness ==
    /\ WF_vars(Tick)
    /\ \A d \in DOMAINS :
        /\ WF_vars(CompletePhase1(d))
        /\ WF_vars(CompletePhase2(d))

Spec == Init /\ [][Next]_vars /\ Fairness

(****************************************************************************)
(* Safety Invariants                                                        *)
(****************************************************************************)

\* INV2: Phase 2 completion requires phase 1 complete + minimum wait
Phase2RequiresPhase1AndWait ==
    \A d \in DOMAINS :
        rotationPhase[d] = "Phase2Complete" =>
            /\ phase1Time[d] >= 0
            /\ phase2Time[d] >= phase1Time[d] + MIN_WAIT_SECONDS

\* Phase 2 cannot start without phase 1 complete
Phase2RequiresPhase1 ==
    \A d \in DOMAINS :
        rotationPhase[d] \in {"Phase2InProgress", "Phase2Complete"} =>
            phase1Time[d] >= 0

\* Timestamps are monotonic (phase 2 always after phase 1)
TimestampMonotonicity ==
    \A d \in DOMAINS :
        (phase1Time[d] >= 0 /\ phase2Time[d] >= 0) =>
            phase2Time[d] >= phase1Time[d]

\* No rotation in progress for failed domain
FailedMeansNoProgress ==
    \A d \in DOMAINS :
        rotationPhase[d] = "Failed" =>
            rotationError[d] = TRUE

\* Phase states are valid
ValidPhaseProgression ==
    \A d \in DOMAINS :
        \/ rotationPhase[d] = "NotStarted"
        \/ rotationPhase[d] = "Phase1InProgress"
        \/ (rotationPhase[d] = "Phase1Complete" /\ phase1Time[d] >= 0)
        \/ rotationPhase[d] = "Phase2InProgress"
        \/ (rotationPhase[d] = "Phase2Complete" /\ phase2Time[d] >= 0)
        \/ rotationPhase[d] = "Failed"

(****************************************************************************)
(* Liveness Properties                                                      *)
(****************************************************************************)

\* Every started rotation eventually completes or fails
RotationTerminates ==
    \A d \in DOMAINS :
        rotationPhase[d] = "Phase1InProgress" ~>
            rotationPhase[d] \in {"Phase2Complete", "Failed"}

\* If phase 1 completes and time advances enough, phase 2 is possible
Phase2EventuallyPossible ==
    \A d \in DOMAINS :
        (rotationPhase[d] = "Phase1Complete" /\
         currentTime >= phase1Time[d] + MIN_WAIT_SECONDS) ~>
            rotationPhase[d] \in {"Phase2InProgress", "Phase2Complete", "Failed"}

(****************************************************************************)
(* Model Checking Configuration                                             *)
(****************************************************************************)

\* Symmetry reduction for domains
Symmetry == Permutations(DOMAINS)

\* State constraint to limit state space
StateConstraint ==
    /\ currentTime <= MAX_TIME
    /\ \A d \in DOMAINS : phase1Time[d] <= MAX_TIME
    /\ \A d \in DOMAINS : phase2Time[d] <= MAX_TIME

=============================================================================
