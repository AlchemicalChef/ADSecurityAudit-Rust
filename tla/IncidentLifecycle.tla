--------------------------- MODULE IncidentLifecycle --------------------------
(****************************************************************************)
(* TLA+ Formal Specification: Incident Status Lifecycle State Machine      *)
(*                                                                          *)
(* Models the ADSecurityScanner's incident management system with focus    *)
(* on the status progression workflow. Key verification target: ensuring   *)
(* forward-only status transitions (incidents cannot regress to earlier    *)
(* states once progressed).                                                 *)
(*                                                                          *)
(* Note: Current implementation may NOT enforce forward-only transitions.  *)
(* This specification documents the intended behavior and can detect       *)
(* violations in the actual code.                                           *)
(*                                                                          *)
(* Based on:                                                                 *)
(*   - src-tauri/src/incident.rs (IncidentStatus enum)                     *)
(*   - src-tauri/src/main.rs (incident management commands)                *)
(****************************************************************************)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    MAX_INCIDENTS,      \* Maximum incidents to model
    INCIDENT_IDS        \* Set of incident identifiers

VARIABLES
    incidents,          \* Set of active incident IDs
    incidentStatus,     \* Function: incident -> status
    incidentLock,       \* Function: incident -> lock state (models RwLock)
    statusHistory,      \* Function: incident -> sequence of past statuses
    concurrentOps       \* Set of concurrent operations in progress

vars == <<incidents, incidentStatus, incidentLock, statusHistory, concurrentOps>>

(****************************************************************************)
(* Type Definitions                                                         *)
(****************************************************************************)

\* Status enum matching Rust implementation
Status == {"Open", "Investigating", "Contained", "Resolved", "Closed"}

\* Status ordinal for comparison (forward-only check)
StatusOrdinal(s) ==
    CASE s = "Open" -> 0
      [] s = "Investigating" -> 1
      [] s = "Contained" -> 2
      [] s = "Resolved" -> 3
      [] s = "Closed" -> 4

\* Lock states for RwLock modeling
LockState == {"Unlocked", "ReadLocked", "WriteLocked"}

\* Operation types
OpType == {"StatusChange", "Read", "Update"}

OperationRecord == [incidentId: INCIDENT_IDS, opType: OpType]

TypeInvariant ==
    /\ incidents \subseteq INCIDENT_IDS
    /\ incidentStatus \in [INCIDENT_IDS -> Status]
    /\ incidentLock \in [INCIDENT_IDS -> LockState]
    /\ \A i \in incidents : statusHistory[i] \in Seq(Status)
    /\ concurrentOps \subseteq OperationRecord

(****************************************************************************)
(* Valid Transitions                                                        *)
(****************************************************************************)

\* Define which transitions are valid (forward-only with some skips allowed)
ValidTransition(from, to) ==
    \/ (from = "Open" /\ to \in {"Investigating", "Closed"})
    \/ (from = "Investigating" /\ to \in {"Contained", "Resolved", "Closed"})
    \/ (from = "Contained" /\ to \in {"Resolved", "Closed"})
    \/ (from = "Resolved" /\ to = "Closed")
    \* Closed is terminal - no transitions out

\* Check if transition is forward (higher ordinal)
IsForwardTransition(from, to) ==
    StatusOrdinal(to) > StatusOrdinal(from)

\* Check if transition is backward (lower ordinal) - INVALID
IsBackwardTransition(from, to) ==
    StatusOrdinal(to) < StatusOrdinal(from)

(****************************************************************************)
(* Initial State                                                            *)
(****************************************************************************)

Init ==
    /\ incidents = {}
    /\ incidentStatus = [i \in INCIDENT_IDS |-> "Open"]
    /\ incidentLock = [i \in INCIDENT_IDS |-> "Unlocked"]
    /\ statusHistory = [i \in INCIDENT_IDS |-> << >>]
    /\ concurrentOps = {}

(****************************************************************************)
(* Incident Creation and Deletion                                           *)
(****************************************************************************)

\* Create a new incident (always starts as Open)
CreateIncident(id) ==
    /\ id \in INCIDENT_IDS
    /\ id \notin incidents
    /\ Cardinality(incidents) < MAX_INCIDENTS
    /\ incidents' = incidents \cup {id}
    /\ incidentStatus' = [incidentStatus EXCEPT ![id] = "Open"]
    /\ statusHistory' = [statusHistory EXCEPT ![id] = <<"Open">>]
    /\ UNCHANGED <<incidentLock, concurrentOps>>

\* Archive/delete a closed incident
ArchiveIncident(id) ==
    /\ id \in incidents
    /\ incidentStatus[id] = "Closed"
    /\ incidentLock[id] = "Unlocked"
    /\ incidents' = incidents \ {id}
    /\ UNCHANGED <<incidentStatus, incidentLock, statusHistory, concurrentOps>>

(****************************************************************************)
(* Lock Management (RwLock Modeling)                                        *)
(****************************************************************************)

\* Acquire read lock
AcquireReadLock(id) ==
    /\ id \in incidents
    /\ incidentLock[id] = "Unlocked"
    /\ incidentLock' = [incidentLock EXCEPT ![id] = "ReadLocked"]
    /\ concurrentOps' = concurrentOps \cup {[incidentId |-> id, opType |-> "Read"]}
    /\ UNCHANGED <<incidents, incidentStatus, statusHistory>>

\* Release read lock
ReleaseReadLock(id) ==
    /\ id \in incidents
    /\ incidentLock[id] = "ReadLocked"
    /\ [incidentId |-> id, opType |-> "Read"] \in concurrentOps
    /\ incidentLock' = [incidentLock EXCEPT ![id] = "Unlocked"]
    /\ concurrentOps' = concurrentOps \ {[incidentId |-> id, opType |-> "Read"]}
    /\ UNCHANGED <<incidents, incidentStatus, statusHistory>>

\* Acquire write lock (for status changes)
AcquireWriteLock(id) ==
    /\ id \in incidents
    /\ incidentLock[id] = "Unlocked"
    /\ incidentLock' = [incidentLock EXCEPT ![id] = "WriteLocked"]
    /\ concurrentOps' = concurrentOps \cup {[incidentId |-> id, opType |-> "StatusChange"]}
    /\ UNCHANGED <<incidents, incidentStatus, statusHistory>>

\* Release write lock
ReleaseWriteLock(id) ==
    /\ id \in incidents
    /\ incidentLock[id] = "WriteLocked"
    /\ [incidentId |-> id, opType |-> "StatusChange"] \in concurrentOps
    /\ incidentLock' = [incidentLock EXCEPT ![id] = "Unlocked"]
    /\ concurrentOps' = concurrentOps \ {[incidentId |-> id, opType |-> "StatusChange"]}
    /\ UNCHANGED <<incidents, incidentStatus, statusHistory>>

(****************************************************************************)
(* Status Transition Actions - CORRECT Implementation                       *)
(****************************************************************************)

\* Change status with proper validation (forward-only)
ChangeStatusSafe(id, newStatus) ==
    /\ id \in incidents
    /\ incidentLock[id] = "WriteLocked"
    /\ newStatus \in Status
    /\ ValidTransition(incidentStatus[id], newStatus)
    /\ incidentStatus' = [incidentStatus EXCEPT ![id] = newStatus]
    /\ statusHistory' = [statusHistory EXCEPT ![id] = Append(@, newStatus)]
    /\ UNCHANGED <<incidents, incidentLock, concurrentOps>>

(****************************************************************************)
(* Status Transition Actions - BUGGY Implementation (for detection)        *)
(****************************************************************************)

\* Change status WITHOUT validation (allows backward transitions)
\* This models the potential bug where forward-only is not enforced
ChangeStatusUnsafe(id, newStatus) ==
    /\ id \in incidents
    /\ incidentLock[id] = "WriteLocked"
    /\ newStatus \in Status
    /\ newStatus /= incidentStatus[id]  \* Only check: different status
    \* NO ValidTransition check - this is the bug!
    /\ incidentStatus' = [incidentStatus EXCEPT ![id] = newStatus]
    /\ statusHistory' = [statusHistory EXCEPT ![id] = Append(@, newStatus)]
    /\ UNCHANGED <<incidents, incidentLock, concurrentOps>>

(****************************************************************************)
(* Specific Status Transitions (Named Actions)                              *)
(****************************************************************************)

\* Start investigating an open incident
StartInvestigation(id) ==
    /\ id \in incidents
    /\ incidentLock[id] = "WriteLocked"
    /\ incidentStatus[id] = "Open"
    /\ incidentStatus' = [incidentStatus EXCEPT ![id] = "Investigating"]
    /\ statusHistory' = [statusHistory EXCEPT ![id] = Append(@, "Investigating")]
    /\ UNCHANGED <<incidents, incidentLock, concurrentOps>>

\* Mark incident as contained
MarkContained(id) ==
    /\ id \in incidents
    /\ incidentLock[id] = "WriteLocked"
    /\ incidentStatus[id] = "Investigating"
    /\ incidentStatus' = [incidentStatus EXCEPT ![id] = "Contained"]
    /\ statusHistory' = [statusHistory EXCEPT ![id] = Append(@, "Contained")]
    /\ UNCHANGED <<incidents, incidentLock, concurrentOps>>

\* Mark incident as resolved
MarkResolved(id) ==
    /\ id \in incidents
    /\ incidentLock[id] = "WriteLocked"
    /\ incidentStatus[id] \in {"Investigating", "Contained"}
    /\ incidentStatus' = [incidentStatus EXCEPT ![id] = "Resolved"]
    /\ statusHistory' = [statusHistory EXCEPT ![id] = Append(@, "Resolved")]
    /\ UNCHANGED <<incidents, incidentLock, concurrentOps>>

\* Close an incident (terminal state)
CloseIncident(id) ==
    /\ id \in incidents
    /\ incidentLock[id] = "WriteLocked"
    /\ incidentStatus[id] \in {"Open", "Investigating", "Contained", "Resolved"}
    /\ incidentStatus' = [incidentStatus EXCEPT ![id] = "Closed"]
    /\ statusHistory' = [statusHistory EXCEPT ![id] = Append(@, "Closed")]
    /\ UNCHANGED <<incidents, incidentLock, concurrentOps>>

(****************************************************************************)
(* Next State Relation                                                      *)
(****************************************************************************)

\* Safe implementation (validates transitions)
NextSafe ==
    \E id \in INCIDENT_IDS :
        \/ CreateIncident(id)
        \/ ArchiveIncident(id)
        \/ AcquireReadLock(id)
        \/ ReleaseReadLock(id)
        \/ AcquireWriteLock(id)
        \/ ReleaseWriteLock(id)
        \/ StartInvestigation(id)
        \/ MarkContained(id)
        \/ MarkResolved(id)
        \/ CloseIncident(id)

\* Unsafe implementation (allows any status change)
NextUnsafe ==
    \E id \in INCIDENT_IDS :
        \/ CreateIncident(id)
        \/ ArchiveIncident(id)
        \/ AcquireReadLock(id)
        \/ ReleaseReadLock(id)
        \/ AcquireWriteLock(id)
        \/ ReleaseWriteLock(id)
        \/ \E s \in Status : ChangeStatusUnsafe(id, s)

\* Default: use unsafe to detect the bug
Next == NextUnsafe

Spec == Init /\ [][Next]_vars

(****************************************************************************)
(* Safety Invariants                                                        *)
(****************************************************************************)

\* MAIN INVARIANT: Status transitions are forward-only
\* This will be VIOLATED if ChangeStatusUnsafe allows backward transitions
ForwardOnlyStatus ==
    \A id \in incidents :
        LET history == statusHistory[id]
        IN \A i \in 1..(Len(history)-1) :
            StatusOrdinal(history[i+1]) >= StatusOrdinal(history[i])

\* Alternative: check that each transition is valid
AllTransitionsValid ==
    \A id \in incidents :
        LET history == statusHistory[id]
        IN \A i \in 1..(Len(history)-1) :
            ValidTransition(history[i], history[i+1])

\* Closed incidents cannot change status
ClosedIsFinal ==
    \A id \in incidents :
        LET history == statusHistory[id]
        IN \A i \in 1..Len(history) :
            (history[i] = "Closed") => (i = Len(history))

\* New incidents always start as Open
IncidentsStartOpen ==
    \A id \in incidents :
        Len(statusHistory[id]) > 0 =>
            Head(statusHistory[id]) = "Open"

\* Write lock required for status changes
WriteProtection ==
    \A id \in incidents :
        [incidentId |-> id, opType |-> "StatusChange"] \in concurrentOps =>
            incidentLock[id] = "WriteLocked"

\* No concurrent write operations on same incident
NoConcurrentWrites ==
    \A id \in incidents :
        Cardinality({op \in concurrentOps :
            op.incidentId = id /\ op.opType = "StatusChange"}) <= 1

(****************************************************************************)
(* Liveness Properties                                                      *)
(****************************************************************************)

\* All incidents eventually close
AllIncidentsClose ==
    \A id \in incidents :
        <>(incidentStatus[id] = "Closed")

\* Locks are eventually released
LocksReleased ==
    \A id \in incidents :
        (incidentLock[id] /= "Unlocked") ~> (incidentLock[id] = "Unlocked")

(****************************************************************************)
(* Bug Detection                                                            *)
(****************************************************************************)

\* Detect backward transition (regression)
BackwardTransitionDetected ==
    \E id \in incidents :
        LET history == statusHistory[id]
        IN \E i \in 1..(Len(history)-1) :
            StatusOrdinal(history[i+1]) < StatusOrdinal(history[i])

\* This should be FALSE in correct implementation
\* If TRUE, the invariant ForwardOnlyStatus is violated
HasStatusRegression ==
    \E id \in incidents :
        LET history == statusHistory[id]
        IN Len(history) >= 2 /\
           \E i \in 1..(Len(history)-1) :
               IsBackwardTransition(history[i], history[i+1])

(****************************************************************************)
(* State Space Constraints                                                  *)
(****************************************************************************)

StateConstraint ==
    /\ Cardinality(incidents) <= MAX_INCIDENTS
    /\ \A id \in incidents : Len(statusHistory[id]) <= 10
    /\ Cardinality(concurrentOps) <= MAX_INCIDENTS * 2

=============================================================================
