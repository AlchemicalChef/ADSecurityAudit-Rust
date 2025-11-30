----------------------------- MODULE ConnectionPool -----------------------------
(****************************************************************************)
(* TLA+ Formal Specification: Connection Pool with Semaphore Bounds        *)
(*                                                                          *)
(* Models the ADSecurityScanner's LDAP connection pooling system with      *)
(* semaphore-based concurrency control and RAII resource management.       *)
(*                                                                          *)
(* Key focus: Verifying that connection limits are never exceeded and      *)
(* that all acquired connections are properly released.                     *)
(*                                                                          *)
(* Based on: src-tauri/src/connection_pool.rs                              *)
(****************************************************************************)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    MAX_CONNECTIONS,    \* Maximum connections (semaphore permits)
    IDLE_TIMEOUT,       \* Connection idle timeout in time units
    MAX_TIME,           \* Model checking time bound
    CONNECTIONS,        \* Set of connection identifiers
    TASKS               \* Set of task identifiers (requesters)

VARIABLES
    availablePermits,   \* Current semaphore permit count
    connectionStates,   \* Function: conn -> {Idle, InUse, Expired, Closed}
    connectionOwner,    \* Function: conn -> task or "none"
    lastUsed,           \* Function: conn -> timestamp of last use
    createdAt,          \* Function: conn -> creation timestamp
    currentTime,        \* Global time counter
    waitingTasks,       \* Set of tasks waiting for a connection
    poolStats           \* Statistics record

vars == <<availablePermits, connectionStates, connectionOwner, lastUsed,
          createdAt, currentTime, waitingTasks, poolStats>>

(****************************************************************************)
(* Type Definitions                                                         *)
(****************************************************************************)

ConnectionState == {"Idle", "InUse", "Expired", "Closed"}

NullableTask == TASKS \cup {"none"}

PoolStatsRecord == [
    total_created: Nat,
    total_released: Nat,
    peak_active: Nat,
    current_active: Nat
]

TypeInvariant ==
    /\ availablePermits \in 0..MAX_CONNECTIONS
    /\ connectionStates \in [CONNECTIONS -> ConnectionState]
    /\ connectionOwner \in [CONNECTIONS -> NullableTask]
    /\ lastUsed \in [CONNECTIONS -> Int]
    /\ createdAt \in [CONNECTIONS -> Int]
    /\ currentTime \in Nat
    /\ waitingTasks \subseteq TASKS

(****************************************************************************)
(* Helper Functions                                                         *)
(****************************************************************************)

\* Count connections in a specific state
ConnectionsInState(state) ==
    Cardinality({c \in CONNECTIONS : connectionStates[c] = state})

\* Check if a connection is expired
IsExpired(conn) ==
    /\ connectionStates[conn] \in {"Idle", "InUse"}
    /\ currentTime - lastUsed[conn] > IDLE_TIMEOUT

\* Get all active (in-use) connections
ActiveConnections ==
    {c \in CONNECTIONS : connectionStates[c] = "InUse"}

\* Get all idle connections
IdleConnections ==
    {c \in CONNECTIONS : connectionStates[c] = "Idle"}

(****************************************************************************)
(* Initial State                                                            *)
(****************************************************************************)

Init ==
    /\ availablePermits = MAX_CONNECTIONS
    /\ connectionStates = [c \in CONNECTIONS |-> "Closed"]
    /\ connectionOwner = [c \in CONNECTIONS |-> "none"]
    /\ lastUsed = [c \in CONNECTIONS |-> -1]
    /\ createdAt = [c \in CONNECTIONS |-> -1]
    /\ currentTime = 0
    /\ waitingTasks = {}
    /\ poolStats = [
        total_created |-> 0,
        total_released |-> 0,
        peak_active |-> 0,
        current_active |-> 0
       ]

(****************************************************************************)
(* Connection Lifecycle Actions                                             *)
(****************************************************************************)

\* Create a new connection (requires permit)
CreateConnection(conn, task) ==
    /\ conn \in CONNECTIONS
    /\ task \in TASKS
    /\ connectionStates[conn] = "Closed"
    /\ availablePermits > 0
    /\ availablePermits' = availablePermits - 1
    /\ connectionStates' = [connectionStates EXCEPT ![conn] = "InUse"]
    /\ connectionOwner' = [connectionOwner EXCEPT ![conn] = task]
    /\ lastUsed' = [lastUsed EXCEPT ![conn] = currentTime]
    /\ createdAt' = [createdAt EXCEPT ![conn] = currentTime]
    /\ poolStats' = [poolStats EXCEPT
        !.total_created = @ + 1,
        !.current_active = @ + 1,
        !.peak_active = IF @ + 1 > poolStats.peak_active
                        THEN @ + 1
                        ELSE poolStats.peak_active]
    /\ UNCHANGED <<currentTime, waitingTasks>>

\* Acquire an existing idle connection
AcquireConnection(conn, task) ==
    /\ conn \in CONNECTIONS
    /\ task \in TASKS
    /\ connectionStates[conn] = "Idle"
    /\ ~IsExpired(conn)
    /\ availablePermits > 0
    /\ availablePermits' = availablePermits - 1
    /\ connectionStates' = [connectionStates EXCEPT ![conn] = "InUse"]
    /\ connectionOwner' = [connectionOwner EXCEPT ![conn] = task]
    /\ lastUsed' = [lastUsed EXCEPT ![conn] = currentTime]
    /\ poolStats' = [poolStats EXCEPT !.current_active = @ + 1]
    /\ UNCHANGED <<createdAt, currentTime, waitingTasks>>

\* Release a connection back to the pool
ReleaseConnection(conn) ==
    /\ conn \in CONNECTIONS
    /\ connectionStates[conn] = "InUse"
    /\ connectionOwner[conn] /= "none"
    /\ availablePermits' = availablePermits + 1
    /\ connectionStates' = [connectionStates EXCEPT ![conn] = "Idle"]
    /\ connectionOwner' = [connectionOwner EXCEPT ![conn] = "none"]
    /\ lastUsed' = [lastUsed EXCEPT ![conn] = currentTime]
    /\ poolStats' = [poolStats EXCEPT
        !.total_released = @ + 1,
        !.current_active = @ - 1]
    /\ UNCHANGED <<createdAt, currentTime, waitingTasks>>

\* Close an expired or unused connection
CloseConnection(conn) ==
    /\ conn \in CONNECTIONS
    /\ connectionStates[conn] \in {"Idle", "Expired"}
    /\ connectionOwner[conn] = "none"
    /\ connectionStates' = [connectionStates EXCEPT ![conn] = "Closed"]
    /\ UNCHANGED <<availablePermits, connectionOwner, lastUsed, createdAt,
                   currentTime, waitingTasks, poolStats>>

\* Mark a connection as expired (cleanup thread)
ExpireConnection(conn) ==
    /\ conn \in CONNECTIONS
    /\ connectionStates[conn] = "Idle"
    /\ IsExpired(conn)
    /\ connectionStates' = [connectionStates EXCEPT ![conn] = "Expired"]
    /\ UNCHANGED <<availablePermits, connectionOwner, lastUsed, createdAt,
                   currentTime, waitingTasks, poolStats>>

(****************************************************************************)
(* Task Actions                                                             *)
(****************************************************************************)

\* Task starts waiting for a connection
TaskStartsWaiting(task) ==
    /\ task \in TASKS
    /\ task \notin waitingTasks
    /\ availablePermits = 0  \* No permits available
    /\ waitingTasks' = waitingTasks \cup {task}
    /\ UNCHANGED <<availablePermits, connectionStates, connectionOwner,
                   lastUsed, createdAt, currentTime, poolStats>>

\* Task stops waiting (timeout or connection available)
TaskStopsWaiting(task) ==
    /\ task \in waitingTasks
    /\ waitingTasks' = waitingTasks \ {task}
    /\ UNCHANGED <<availablePermits, connectionStates, connectionOwner,
                   lastUsed, createdAt, currentTime, poolStats>>

(****************************************************************************)
(* Time and Cleanup Actions                                                 *)
(****************************************************************************)

\* Time advances
Tick ==
    /\ currentTime < MAX_TIME
    /\ currentTime' = currentTime + 1
    /\ UNCHANGED <<availablePermits, connectionStates, connectionOwner,
                   lastUsed, createdAt, waitingTasks, poolStats>>

\* Cleanup expired connections (periodic maintenance)
CleanupExpired ==
    /\ \E conn \in CONNECTIONS :
        /\ connectionStates[conn] = "Expired"
        /\ connectionStates' = [connectionStates EXCEPT ![conn] = "Closed"]
    /\ UNCHANGED <<availablePermits, connectionOwner, lastUsed, createdAt,
                   currentTime, waitingTasks, poolStats>>

(****************************************************************************)
(* Next State Relation                                                      *)
(****************************************************************************)

Next ==
    \/ \E c \in CONNECTIONS, t \in TASKS :
        \/ CreateConnection(c, t)
        \/ AcquireConnection(c, t)
    \/ \E c \in CONNECTIONS :
        \/ ReleaseConnection(c)
        \/ CloseConnection(c)
        \/ ExpireConnection(c)
    \/ \E t \in TASKS :
        \/ TaskStartsWaiting(t)
        \/ TaskStopsWaiting(t)
    \/ Tick
    \/ CleanupExpired

\* Fairness: connections are eventually released
Fairness ==
    /\ WF_vars(Tick)
    /\ \A c \in CONNECTIONS : WF_vars(ReleaseConnection(c))

Spec == Init /\ [][Next]_vars /\ Fairness

(****************************************************************************)
(* Safety Invariants                                                        *)
(****************************************************************************)

\* INV1: Semaphore permits never exceed max_connections
SemaphoreInvariant ==
    availablePermits <= MAX_CONNECTIONS

\* INV2: Active connections cannot exceed permits used
ActiveConnectionsBound ==
    Cardinality(ActiveConnections) <= MAX_CONNECTIONS - availablePermits

\* INV3: No connection used by multiple tasks
ExclusiveConnectionAccess ==
    \A c1, c2 \in CONNECTIONS :
        (c1 /= c2 /\ connectionStates[c1] = "InUse" /\
         connectionStates[c2] = "InUse") =>
            connectionOwner[c1] /= connectionOwner[c2]

\* INV4: Expired connections are not in use
ExpiredNotInUse ==
    \A c \in CONNECTIONS :
        connectionStates[c] = "Expired" =>
            connectionOwner[c] = "none"

\* INV5: InUse connections must have an owner
InUseHasOwner ==
    \A c \in CONNECTIONS :
        connectionStates[c] = "InUse" =>
            connectionOwner[c] /= "none"

\* INV6: Idle connections have no owner
IdleNoOwner ==
    \A c \in CONNECTIONS :
        connectionStates[c] = "Idle" =>
            connectionOwner[c] = "none"

\* INV7: Total permits + active = max
PermitConservation ==
    availablePermits + Cardinality(ActiveConnections) <= MAX_CONNECTIONS

\* INV8: Statistics are consistent
StatsConsistency ==
    /\ poolStats.current_active = Cardinality(ActiveConnections)
    /\ poolStats.peak_active >= poolStats.current_active
    /\ poolStats.total_released <= poolStats.total_created

\* INV9: Created timestamp <= last used timestamp
TimestampOrdering ==
    \A c \in CONNECTIONS :
        (connectionStates[c] /= "Closed") =>
            createdAt[c] <= lastUsed[c]

(****************************************************************************)
(* Liveness Properties                                                      *)
(****************************************************************************)

\* Every acquired connection is eventually released
ConnectionsEventuallyReleased ==
    \A c \in CONNECTIONS :
        (connectionStates[c] = "InUse") ~>
            (connectionStates[c] \in {"Idle", "Closed"})

\* Waiting tasks eventually get a connection or timeout
WaitingTasksProgress ==
    \A t \in waitingTasks :
        <>(t \notin waitingTasks)

\* Expired connections are eventually cleaned up
ExpiredEventuallyCleaned ==
    \A c \in CONNECTIONS :
        (connectionStates[c] = "Expired") ~>
            (connectionStates[c] = "Closed")

(****************************************************************************)
(* State Space Constraints                                                  *)
(****************************************************************************)

StateConstraint ==
    /\ currentTime <= MAX_TIME
    /\ poolStats.total_created <= MAX_CONNECTIONS * 2

=============================================================================
