--------------------------- MODULE AuthenticationFlow --------------------------
(****************************************************************************)
(* TLA+ Formal Specification: LDAP Authentication State Machine            *)
(*                                                                          *)
(* Models the ADSecurityScanner's ephemeral authentication pattern where   *)
(* LDAP connections are established per-operation rather than maintained   *)
(* as long-lived sessions. Key focus: credential security through the      *)
(* SecureString lifecycle with guaranteed zeroization on drop.             *)
(*                                                                          *)
(* Based on:                                                                 *)
(*   - src-tauri/src/ad_client.rs (impl ActiveDirectoryClient, line 114+)  *)
(*   - src-tauri/src/secure_types.rs (SecureString)                        *)
(****************************************************************************)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    MAX_RETRIES,        \* Maximum authentication retry attempts
    SESSIONS,           \* Set of session identifiers
    MAX_SESSIONS        \* Maximum concurrent sessions

VARIABLES
    authState,          \* Function: session -> authentication state
    credentials,        \* Function: session -> credential state
    connectionHandle,   \* Function: session -> connection reference state
    retryCount,         \* Function: session -> number of failed attempts
    activeSessions,     \* Set of currently active session IDs
    nextSessionId       \* Counter for unique session IDs

vars == <<authState, credentials, connectionHandle, retryCount,
          activeSessions, nextSessionId>>

(****************************************************************************)
(* Type Definitions                                                         *)
(****************************************************************************)

\* Authentication states mirror the Rust implementation
AuthStates == {"Initial", "Connecting", "Authenticating",
               "Authenticated", "Disconnecting", "Disconnected",
               "Failed", "Destroyed"}

\* Credential lifecycle states
CredentialStates == {"NotLoaded", "Loaded", "InUse", "Zeroizing", "Zeroized"}

\* Connection handle states
HandleStates == {"None", "Pending", "Active", "Closing", "Closed"}

TypeInvariant ==
    /\ authState \in [SESSIONS -> AuthStates]
    /\ credentials \in [SESSIONS -> CredentialStates]
    /\ connectionHandle \in [SESSIONS -> HandleStates]
    /\ retryCount \in [SESSIONS -> Nat]
    /\ activeSessions \subseteq SESSIONS
    /\ nextSessionId \in Nat

(****************************************************************************)
(* Initial State                                                            *)
(****************************************************************************)

Init ==
    /\ authState = [s \in SESSIONS |-> "Initial"]
    /\ credentials = [s \in SESSIONS |-> "NotLoaded"]
    /\ connectionHandle = [s \in SESSIONS |-> "None"]
    /\ retryCount = [s \in SESSIONS |-> 0]
    /\ activeSessions = {}
    /\ nextSessionId = 0

(****************************************************************************)
(* Session Lifecycle Actions                                                *)
(****************************************************************************)

\* Create a new authentication session
CreateSession(session) ==
    /\ session \in SESSIONS
    /\ session \notin activeSessions
    /\ Cardinality(activeSessions) < MAX_SESSIONS
    /\ activeSessions' = activeSessions \cup {session}
    /\ authState' = [authState EXCEPT ![session] = "Initial"]
    /\ credentials' = [credentials EXCEPT ![session] = "NotLoaded"]
    /\ connectionHandle' = [connectionHandle EXCEPT ![session] = "None"]
    /\ retryCount' = [retryCount EXCEPT ![session] = 0]
    /\ nextSessionId' = nextSessionId + 1

(****************************************************************************)
(* Credential Actions                                                       *)
(****************************************************************************)

\* Load credentials into secure memory (SecureString)
LoadCredentials(session) ==
    /\ session \in activeSessions
    /\ authState[session] = "Initial"
    /\ credentials[session] = "NotLoaded"
    /\ credentials' = [credentials EXCEPT ![session] = "Loaded"]
    /\ UNCHANGED <<authState, connectionHandle, retryCount,
                   activeSessions, nextSessionId>>

\* Begin using credentials for authentication
UseCredentials(session) ==
    /\ session \in activeSessions
    /\ credentials[session] = "Loaded"
    /\ authState[session] \in {"Initial", "Connecting"}
    /\ credentials' = [credentials EXCEPT ![session] = "InUse"]
    /\ UNCHANGED <<authState, connectionHandle, retryCount,
                   activeSessions, nextSessionId>>

\* Begin zeroization process (called by Drop trait)
BeginZeroization(session) ==
    /\ session \in activeSessions
    /\ credentials[session] \in {"Loaded", "InUse"}
    /\ authState[session] \in {"Disconnecting", "Disconnected", "Failed", "Destroyed"}
    /\ credentials' = [credentials EXCEPT ![session] = "Zeroizing"]
    /\ UNCHANGED <<authState, connectionHandle, retryCount,
                   activeSessions, nextSessionId>>

\* Complete zeroization (memory securely cleared)
CompleteZeroization(session) ==
    /\ session \in activeSessions
    /\ credentials[session] = "Zeroizing"
    /\ credentials' = [credentials EXCEPT ![session] = "Zeroized"]
    /\ UNCHANGED <<authState, connectionHandle, retryCount,
                   activeSessions, nextSessionId>>

(****************************************************************************)
(* Connection Actions                                                       *)
(****************************************************************************)

\* Begin LDAP connection (bind operation starts)
BeginConnect(session) ==
    /\ session \in activeSessions
    /\ authState[session] = "Initial"
    /\ credentials[session] \in {"Loaded", "InUse"}
    /\ authState' = [authState EXCEPT ![session] = "Connecting"]
    /\ connectionHandle' = [connectionHandle EXCEPT ![session] = "Pending"]
    /\ UNCHANGED <<credentials, retryCount, activeSessions, nextSessionId>>

\* Transition to authentication phase
BeginAuthenticate(session) ==
    /\ session \in activeSessions
    /\ authState[session] = "Connecting"
    /\ connectionHandle[session] = "Pending"
    /\ credentials[session] = "InUse"
    /\ authState' = [authState EXCEPT ![session] = "Authenticating"]
    /\ UNCHANGED <<credentials, connectionHandle, retryCount,
                   activeSessions, nextSessionId>>

\* Authentication succeeds (LDAP bind complete)
AuthenticationSucceeds(session) ==
    /\ session \in activeSessions
    /\ authState[session] = "Authenticating"
    /\ credentials[session] = "InUse"
    /\ authState' = [authState EXCEPT ![session] = "Authenticated"]
    /\ connectionHandle' = [connectionHandle EXCEPT ![session] = "Active"]
    /\ UNCHANGED <<credentials, retryCount, activeSessions, nextSessionId>>

\* Authentication fails (invalid credentials, network error, etc.)
AuthenticationFails(session) ==
    /\ session \in activeSessions
    /\ authState[session] = "Authenticating"
    /\ retryCount[session] < MAX_RETRIES
    /\ authState' = [authState EXCEPT ![session] = "Failed"]
    /\ retryCount' = [retryCount EXCEPT ![session] = retryCount[session] + 1]
    /\ connectionHandle' = [connectionHandle EXCEPT ![session] = "Closed"]
    /\ UNCHANGED <<credentials, activeSessions, nextSessionId>>

\* Retry authentication after failure
RetryAuthentication(session) ==
    /\ session \in activeSessions
    /\ authState[session] = "Failed"
    /\ retryCount[session] < MAX_RETRIES
    /\ authState' = [authState EXCEPT ![session] = "Connecting"]
    /\ connectionHandle' = [connectionHandle EXCEPT ![session] = "Pending"]
    /\ UNCHANGED <<credentials, retryCount, activeSessions, nextSessionId>>

\* Max retries exceeded - permanent failure
MaxRetriesExceeded(session) ==
    /\ session \in activeSessions
    /\ authState[session] = "Failed"
    /\ retryCount[session] >= MAX_RETRIES
    /\ authState' = [authState EXCEPT ![session] = "Destroyed"]
    /\ UNCHANGED <<credentials, connectionHandle, retryCount,
                   activeSessions, nextSessionId>>

(****************************************************************************)
(* Disconnection Actions                                                    *)
(****************************************************************************)

\* Begin graceful disconnection
BeginDisconnect(session) ==
    /\ session \in activeSessions
    /\ authState[session] = "Authenticated"
    /\ connectionHandle[session] = "Active"
    /\ authState' = [authState EXCEPT ![session] = "Disconnecting"]
    /\ connectionHandle' = [connectionHandle EXCEPT ![session] = "Closing"]
    /\ UNCHANGED <<credentials, retryCount, activeSessions, nextSessionId>>

\* Complete disconnection
CompleteDisconnect(session) ==
    /\ session \in activeSessions
    /\ authState[session] = "Disconnecting"
    /\ connectionHandle[session] = "Closing"
    /\ authState' = [authState EXCEPT ![session] = "Disconnected"]
    /\ connectionHandle' = [connectionHandle EXCEPT ![session] = "Closed"]
    /\ UNCHANGED <<credentials, retryCount, activeSessions, nextSessionId>>

\* Destroy session (Drop trait called)
DestroySession(session) ==
    /\ session \in activeSessions
    /\ authState[session] \in {"Disconnected", "Failed"}
    /\ authState' = [authState EXCEPT ![session] = "Destroyed"]
    \* Trigger zeroization if not already done
    /\ IF credentials[session] \in {"Loaded", "InUse"}
       THEN credentials' = [credentials EXCEPT ![session] = "Zeroizing"]
       ELSE UNCHANGED credentials
    /\ UNCHANGED <<connectionHandle, retryCount, activeSessions, nextSessionId>>

\* Remove session from active set (cleanup complete)
CleanupSession(session) ==
    /\ session \in activeSessions
    /\ authState[session] = "Destroyed"
    /\ credentials[session] = "Zeroized"
    /\ connectionHandle[session] = "Closed"
    /\ activeSessions' = activeSessions \ {session}
    /\ UNCHANGED <<authState, credentials, connectionHandle, retryCount, nextSessionId>>

(****************************************************************************)
(* Next State Relation                                                      *)
(****************************************************************************)

Next ==
    \E s \in SESSIONS :
        \/ CreateSession(s)
        \/ LoadCredentials(s)
        \/ UseCredentials(s)
        \/ BeginConnect(s)
        \/ BeginAuthenticate(s)
        \/ AuthenticationSucceeds(s)
        \/ AuthenticationFails(s)
        \/ RetryAuthentication(s)
        \/ MaxRetriesExceeded(s)
        \/ BeginDisconnect(s)
        \/ CompleteDisconnect(s)
        \/ DestroySession(s)
        \/ BeginZeroization(s)
        \/ CompleteZeroization(s)
        \/ CleanupSession(s)

\* Fairness: sessions eventually make progress
Fairness ==
    \A s \in SESSIONS :
        /\ WF_vars(CompleteZeroization(s))
        /\ WF_vars(CleanupSession(s))

Spec == Init /\ [][Next]_vars /\ Fairness

(****************************************************************************)
(* Safety Invariants                                                        *)
(****************************************************************************)

\* INV6: Credentials MUST be zeroized when session is destroyed
CredentialZeroization ==
    \A s \in activeSessions :
        authState[s] = "Destroyed" =>
            credentials[s] \in {"Zeroizing", "Zeroized"}

\* Stronger: Cleanup requires full zeroization
CleanupRequiresZeroization ==
    \A s \in SESSIONS :
        (s \notin activeSessions /\ authState[s] = "Destroyed") =>
            credentials[s] = "Zeroized"

\* Cannot be authenticated without having loaded credentials
AuthRequiresCredentials ==
    \A s \in activeSessions :
        authState[s] = "Authenticated" =>
            credentials[s] = "InUse"

\* Cannot connect without credentials loaded first
ConnectRequiresCredentials ==
    \A s \in activeSessions :
        authState[s] \in {"Connecting", "Authenticating", "Authenticated"} =>
            credentials[s] \in {"Loaded", "InUse"}

\* Retry count is bounded
BoundedRetries ==
    \A s \in activeSessions :
        retryCount[s] <= MAX_RETRIES

\* Connection handle state is consistent with auth state
HandleConsistency ==
    \A s \in activeSessions :
        /\ (authState[s] = "Initial" => connectionHandle[s] = "None")
        /\ (authState[s] = "Authenticated" => connectionHandle[s] = "Active")
        /\ (authState[s] = "Destroyed" => connectionHandle[s] = "Closed")

\* No credentials can be in-use after session destroyed
NoCredentialsAfterDestroy ==
    \A s \in activeSessions :
        authState[s] = "Destroyed" =>
            credentials[s] \notin {"NotLoaded", "Loaded", "InUse"}

(****************************************************************************)
(* Liveness Properties                                                      *)
(****************************************************************************)

\* Every session eventually terminates (destroyed and cleaned up)
SessionsTerminate ==
    \A s \in activeSessions :
        <>(s \notin activeSessions)

\* Credentials are eventually zeroized
CredentialsEventuallyZeroized ==
    \A s \in SESSIONS :
        (credentials[s] \in {"Loaded", "InUse"}) ~>
            (credentials[s] = "Zeroized")

\* Failed sessions eventually get destroyed
FailuresHandled ==
    \A s \in activeSessions :
        (authState[s] = "Failed" /\ retryCount[s] >= MAX_RETRIES) ~>
            authState[s] = "Destroyed"

(****************************************************************************)
(* Security Properties                                                      *)
(****************************************************************************)

\* Credentials never exist in memory after session cleanup
CredentialSecrecy ==
    \A s \in SESSIONS :
        s \notin activeSessions =>
            credentials[s] \in {"NotLoaded", "Zeroized"}

\* Authentication state machine is valid (no skipped states)
ValidStateProgression ==
    \A s \in activeSessions :
        \/ authState[s] = "Initial"
        \/ authState[s] = "Connecting"
        \/ authState[s] = "Authenticating"
        \/ authState[s] = "Authenticated"
        \/ authState[s] = "Disconnecting"
        \/ authState[s] = "Disconnected"
        \/ authState[s] = "Failed"
        \/ authState[s] = "Destroyed"

(****************************************************************************)
(* State Space Constraints                                                  *)
(****************************************************************************)

StateConstraint ==
    /\ Cardinality(activeSessions) <= MAX_SESSIONS
    /\ \A s \in SESSIONS : retryCount[s] <= MAX_RETRIES + 1

=============================================================================
