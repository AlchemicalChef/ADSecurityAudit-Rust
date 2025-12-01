--------------------------- MODULE DomainManagement ---------------------------
(****************************************************************************)
(* TLA+ Formal Specification: Multi-Domain Management with Race Detection  *)
(*                                                                          *)
(* Models the ADSecurityScanner's multi-domain/forest management system.   *)
(* Key focus: Detecting the race condition (BUG-5) where domain switching  *)
(* can occur during an active audit, causing the audit to report results   *)
(* for the wrong domain context.                                            *)
(*                                                                          *)
(* Based on:                                                                 *)
(*   - src-tauri/src/forest_manager.rs (ForestManager)                      *)
(*   - src-tauri/src/main.rs (switch_domain, line 1161)                    *)
(****************************************************************************)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    DOMAINS,            \* Set of domain identifiers (e.g., {"corp.local", "dev.local"})
    MAX_AUDITS          \* Maximum concurrent audits to model

VARIABLES
    configuredDomains,  \* Set of domains that have been configured
    domainStates,       \* Function: domain -> connection state
    activeDomain,       \* Currently active domain (or "none")
    auditsInProgress,   \* Set of {[domain |-> d, auditId |-> id]} active audits
    auditContext,       \* Function: auditId -> domain that was active when audit started
    nextAuditId,        \* Counter for unique audit IDs
    pendingSwitch       \* Domain waiting to become active (models async switch)

vars == <<configuredDomains, domainStates, activeDomain, auditsInProgress,
          auditContext, nextAuditId, pendingSwitch>>

(****************************************************************************)
(* Type Definitions                                                         *)
(****************************************************************************)

ConnectionState == {"Disconnected", "Connecting", "Connected", "Error"}

NullableDomain == DOMAINS \cup {"none"}

AuditRecord == [domain: DOMAINS, auditId: Nat]

TypeInvariant ==
    /\ configuredDomains \subseteq DOMAINS
    /\ domainStates \in [DOMAINS -> ConnectionState]
    /\ activeDomain \in NullableDomain
    /\ auditsInProgress \subseteq [domain: DOMAINS, auditId: Nat]
    /\ nextAuditId \in Nat
    /\ pendingSwitch \in NullableDomain

(****************************************************************************)
(* Helper Functions                                                         *)
(****************************************************************************)

\* Count domains in a specific state
DomainsInState(state) ==
    Cardinality({d \in configuredDomains : domainStates[d] = state})

\* Check if any audit is in progress for a domain
HasActiveAudit(domain) ==
    \E audit \in auditsInProgress : audit.domain = domain

\* Get audit IDs for a domain
AuditIdsForDomain(domain) ==
    {audit.auditId : audit \in {a \in auditsInProgress : a.domain = domain}}

(****************************************************************************)
(* Initial State                                                            *)
(****************************************************************************)

Init ==
    /\ configuredDomains = {}
    /\ domainStates = [d \in DOMAINS |-> "Disconnected"]
    /\ activeDomain = "none"
    /\ auditsInProgress = {}
    /\ auditContext = [id \in {} |-> "none"]
    /\ nextAuditId = 0
    /\ pendingSwitch = "none"

(****************************************************************************)
(* Domain Configuration Actions                                             *)
(****************************************************************************)

\* Add a new domain configuration
AddDomain(domain) ==
    /\ domain \in DOMAINS
    /\ domain \notin configuredDomains
    /\ configuredDomains' = configuredDomains \cup {domain}
    /\ UNCHANGED <<domainStates, activeDomain, auditsInProgress,
                   auditContext, nextAuditId, pendingSwitch>>

\* Remove a domain configuration (only if disconnected and no active audits)
RemoveDomain(domain) ==
    /\ domain \in configuredDomains
    /\ domainStates[domain] = "Disconnected"
    /\ ~HasActiveAudit(domain)
    /\ domain /= activeDomain
    /\ configuredDomains' = configuredDomains \ {domain}
    /\ UNCHANGED <<domainStates, activeDomain, auditsInProgress,
                   auditContext, nextAuditId, pendingSwitch>>

(****************************************************************************)
(* Connection Actions                                                       *)
(****************************************************************************)

\* Begin connecting to a domain
ConnectDomain(domain) ==
    /\ domain \in configuredDomains
    /\ domainStates[domain] = "Disconnected"
    /\ domainStates' = [domainStates EXCEPT ![domain] = "Connecting"]
    /\ UNCHANGED <<configuredDomains, activeDomain, auditsInProgress,
                   auditContext, nextAuditId, pendingSwitch>>

\* Connection succeeds
ConnectionSucceeds(domain) ==
    /\ domain \in configuredDomains
    /\ domainStates[domain] = "Connecting"
    /\ domainStates' = [domainStates EXCEPT ![domain] = "Connected"]
    /\ UNCHANGED <<configuredDomains, activeDomain, auditsInProgress,
                   auditContext, nextAuditId, pendingSwitch>>

\* Connection fails
ConnectionFails(domain) ==
    /\ domain \in configuredDomains
    /\ domainStates[domain] = "Connecting"
    /\ domainStates' = [domainStates EXCEPT ![domain] = "Error"]
    /\ UNCHANGED <<configuredDomains, activeDomain, auditsInProgress,
                   auditContext, nextAuditId, pendingSwitch>>

\* Disconnect from a domain
DisconnectDomain(domain) ==
    /\ domain \in configuredDomains
    /\ domainStates[domain] \in {"Connected", "Error"}
    /\ ~HasActiveAudit(domain)
    /\ domainStates' = [domainStates EXCEPT ![domain] = "Disconnected"]
    \* If disconnecting active domain, clear it
    /\ activeDomain' = IF activeDomain = domain THEN "none" ELSE activeDomain
    /\ UNCHANGED <<configuredDomains, auditsInProgress, auditContext,
                   nextAuditId, pendingSwitch>>

(****************************************************************************)
(* Domain Activation Actions (Race Condition Source)                        *)
(****************************************************************************)

\* Set a domain as active (INV1: only one active at a time)
\* This is the CORRECT implementation
SetActiveDomainSafe(domain) ==
    /\ domain \in configuredDomains
    /\ domainStates[domain] = "Connected"
    \* Safety check: no audits in progress on OTHER domains
    /\ \A audit \in auditsInProgress : audit.domain = domain
    /\ activeDomain' = domain
    /\ UNCHANGED <<configuredDomains, domainStates, auditsInProgress,
                   auditContext, nextAuditId, pendingSwitch>>

\* Set a domain as active WITHOUT checking audits (BUG-5 behavior)
\* This models the actual buggy implementation
SetActiveDomainUnsafe(domain) ==
    /\ domain \in configuredDomains
    /\ domainStates[domain] = "Connected"
    \* NO check for audits in progress - this is the bug!
    /\ activeDomain' = domain
    /\ UNCHANGED <<configuredDomains, domainStates, auditsInProgress,
                   auditContext, nextAuditId, pendingSwitch>>

\* Model async domain switch (two-phase)
RequestDomainSwitch(domain) ==
    /\ domain \in configuredDomains
    /\ domainStates[domain] = "Connected"
    /\ pendingSwitch = "none"
    /\ pendingSwitch' = domain
    /\ UNCHANGED <<configuredDomains, domainStates, activeDomain,
                   auditsInProgress, auditContext, nextAuditId>>

\* Complete async domain switch
CompleteDomainSwitch ==
    /\ pendingSwitch /= "none"
    /\ domainStates[pendingSwitch] = "Connected"
    /\ activeDomain' = pendingSwitch
    /\ pendingSwitch' = "none"
    /\ UNCHANGED <<configuredDomains, domainStates, auditsInProgress,
                   auditContext, nextAuditId>>

(****************************************************************************)
(* Audit Actions (Race Condition Target)                                    *)
(****************************************************************************)

\* Start an audit on the currently active domain
StartAudit ==
    /\ activeDomain /= "none"
    /\ Cardinality(auditsInProgress) < MAX_AUDITS
    /\ domainStates[activeDomain] = "Connected"
    /\ LET newAudit == [domain |-> activeDomain, auditId |-> nextAuditId]
       IN /\ auditsInProgress' = auditsInProgress \cup {newAudit}
          \* Record which domain was active when audit started
          /\ auditContext' = auditContext @@ (nextAuditId :> activeDomain)
    /\ nextAuditId' = nextAuditId + 1
    /\ UNCHANGED <<configuredDomains, domainStates, activeDomain, pendingSwitch>>

\* Complete an audit
CompleteAudit(auditId) ==
    /\ \E audit \in auditsInProgress : audit.auditId = auditId
    /\ LET audit == CHOOSE a \in auditsInProgress : a.auditId = auditId
       IN auditsInProgress' = auditsInProgress \ {audit}
    \* Remove from context (simplified - TLA+ doesn't have map deletion easily)
    /\ UNCHANGED <<configuredDomains, domainStates, activeDomain,
                   auditContext, nextAuditId, pendingSwitch>>

(****************************************************************************)
(* Next State Relation                                                      *)
(****************************************************************************)

Next ==
    \/ \E d \in DOMAINS :
        \/ AddDomain(d)
        \/ RemoveDomain(d)
        \/ ConnectDomain(d)
        \/ ConnectionSucceeds(d)
        \/ ConnectionFails(d)
        \/ DisconnectDomain(d)
        \/ SetActiveDomainUnsafe(d)  \* Models the buggy behavior
        \/ RequestDomainSwitch(d)
    \/ CompleteDomainSwitch
    \/ StartAudit
    \/ \E id \in 0..nextAuditId : CompleteAudit(id)

Spec == Init /\ [][Next]_vars

(****************************************************************************)
(* Safety Invariants                                                        *)
(****************************************************************************)

\* INV1: At most one domain can be active at any time
SingleActiveDomain ==
    \/ activeDomain = "none"
    \/ activeDomain \in configuredDomains

\* Active domain must be in connected state
ActiveMustBeConnected ==
    activeDomain /= "none" => domainStates[activeDomain] = "Connected"

\* Cannot have audits on unconfigured domains
AuditsOnlyOnConfigured ==
    \A audit \in auditsInProgress : audit.domain \in configuredDomains

\* Cannot have audits on disconnected domains
\* BUG FIX: Audits should only run on Connected domains (not Connecting)
AuditsOnlyOnConnected ==
    \A audit \in auditsInProgress :
        domainStates[audit.domain] = "Connected"

\* BUG-5 DETECTION: Audit context should match active domain
\* This invariant will be VIOLATED when the race condition occurs
AuditDomainConsistency ==
    \A audit \in auditsInProgress :
        audit.domain = activeDomain

\* Stronger version: audit should complete on same domain it started
AuditContextPreserved ==
    \A audit \in auditsInProgress :
        auditContext[audit.auditId] = activeDomain

(****************************************************************************)
(* Liveness Properties                                                      *)
(****************************************************************************)

\* Every started audit eventually completes
AuditsComplete ==
    \A audit \in auditsInProgress :
        <>(audit \notin auditsInProgress)

\* If a domain is requested for switch, it eventually becomes active
SwitchEventuallyCompletes ==
    pendingSwitch /= "none" ~> activeDomain = pendingSwitch

(****************************************************************************)
(* State Space Constraints                                                  *)
(****************************************************************************)

StateConstraint ==
    /\ nextAuditId <= MAX_AUDITS + 2
    /\ Cardinality(auditsInProgress) <= MAX_AUDITS
    /\ Cardinality(configuredDomains) <= Cardinality(DOMAINS)

(****************************************************************************)
(* Bug Detection Traces                                                     *)
(****************************************************************************)

\* This formula describes the exact race condition scenario:
\* 1. Domain A is active
\* 2. Audit starts on domain A
\* 3. Domain switches to B while audit in progress
\* 4. Audit completes, but results may be mixed/wrong
RaceConditionTrace ==
    /\ Cardinality(auditsInProgress) > 0
    /\ \E audit \in auditsInProgress :
        audit.domain /= activeDomain

=============================================================================
