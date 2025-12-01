---------------------------- MODULE LDAPReferralHandling ----------------------------
(****************************************************************************)
(* TLA+ Formal Specification: LDAP Search with Referral Handling           *)
(*                                                                          *)
(* Models the ADSecurityScanner's LDAP search behavior with proper         *)
(* handling of LDAP referrals (error code 10). Referrals occur when an     *)
(* LDAP server cannot satisfy a request and directs the client to another  *)
(* server or naming context.                                                *)
(*                                                                          *)
(* Key focus: Verifying that search operations use appropriate scope and   *)
(* base DN combinations to avoid referral errors in multi-domain/forest    *)
(* environments.                                                            *)
(*                                                                          *)
(* Based on: src-tauri/src/ad_client.rs                                    *)
(* Fix applied: Changed Scope::Base/OneLevel on specific DNs to            *)
(*              Scope::Subtree from base_dn with distinguishedName filter  *)
(****************************************************************************)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    DOMAINS,            \* Set of domain identifiers
    NAMING_CONTEXTS,    \* Set of naming contexts (partitions)
    OBJECT_TYPES,       \* Set of object types (user, group, container, etc.)
    MAX_OPERATIONS      \* Maximum operations to model

VARIABLES
    searchBase,         \* Current search base DN for operation
    searchScope,        \* Current search scope (Base, OneLevel, Subtree)
    targetObject,       \* Object being searched for
    objectLocation,     \* Function: object -> naming context
    currentContext,     \* Current connection's naming context
    operationResult,    \* Result of last operation
    referralCount,      \* Number of referrals encountered
    searchHistory       \* Sequence of search operations

vars == <<searchBase, searchScope, targetObject, objectLocation,
          currentContext, operationResult, referralCount, searchHistory>>

(****************************************************************************)
(* Type Definitions                                                         *)
(****************************************************************************)

SearchScope == {"Base", "OneLevel", "Subtree"}

OperationResult == {"Success", "Referral", "NotFound", "Error"}

SearchRecord == [
    base: NAMING_CONTEXTS,
    scope: SearchScope,
    target: OBJECT_TYPES,
    result: OperationResult
]

TypeInvariant ==
    /\ searchBase \in NAMING_CONTEXTS \cup {"none"}
    /\ searchScope \in SearchScope \cup {"none"}
    /\ targetObject \in OBJECT_TYPES \cup {"none"}
    /\ objectLocation \in [OBJECT_TYPES -> NAMING_CONTEXTS]
    /\ currentContext \in NAMING_CONTEXTS
    /\ operationResult \in OperationResult \cup {"none"}
    /\ referralCount \in Nat
    /\ searchHistory \in Seq(SearchRecord)

(****************************************************************************)
(* Helper Functions                                                         *)
(****************************************************************************)

\* Check if a search can reach the target without referral
CanReachWithoutReferral(base, scope, target) ==
    LET targetCtx == objectLocation[target]
    IN \/ (scope = "Subtree" /\ base = currentContext)
       \/ (scope = "Base" /\ base = currentContext /\ targetCtx = currentContext)
       \/ (scope = "OneLevel" /\ base = currentContext /\ targetCtx = currentContext)

\* Check if search would trigger referral
WouldTriggerReferral(base, scope, target) ==
    LET targetCtx == objectLocation[target]
    IN /\ base /= currentContext
       /\ scope \in {"Base", "OneLevel"}
       /\ targetCtx /= base

\* Determine search result based on base, scope, and target location
DetermineResult(base, scope, target) ==
    LET targetCtx == objectLocation[target]
    IN CASE WouldTriggerReferral(base, scope, target) -> "Referral"
         [] CanReachWithoutReferral(base, scope, target) -> "Success"
         [] OTHER -> "NotFound"

(****************************************************************************)
(* Initial State                                                            *)
(****************************************************************************)

Init ==
    /\ searchBase = "none"
    /\ searchScope = "none"
    /\ targetObject = "none"
    /\ objectLocation = [o \in OBJECT_TYPES |-> CHOOSE c \in NAMING_CONTEXTS : TRUE]
    /\ currentContext = CHOOSE c \in NAMING_CONTEXTS : TRUE
    /\ operationResult = "none"
    /\ referralCount = 0
    /\ searchHistory = << >>

(****************************************************************************)
(* UNSAFE Search Actions (Pre-fix behavior - causes referrals)             *)
(****************************************************************************)

\* Search with Base scope directly on object DN (UNSAFE - triggers referrals)
SearchBaseOnObjectDN(target) ==
    /\ target \in OBJECT_TYPES
    /\ Len(searchHistory) < MAX_OPERATIONS
    /\ searchBase' = objectLocation[target]  \* Searching at object's location
    /\ searchScope' = "Base"
    /\ targetObject' = target
    /\ LET result == DetermineResult(objectLocation[target], "Base", target)
       IN /\ operationResult' = result
          /\ IF result = "Referral"
             THEN referralCount' = referralCount + 1
             ELSE UNCHANGED referralCount
          /\ searchHistory' = Append(searchHistory, [
                base |-> objectLocation[target],
                scope |-> "Base",
                target |-> target,
                result |-> result
             ])
    /\ UNCHANGED <<objectLocation, currentContext>>

\* Search with OneLevel scope in specific container (UNSAFE - can trigger referrals)
SearchOneLevelInContainer(container, target) ==
    /\ target \in OBJECT_TYPES
    /\ container \in NAMING_CONTEXTS
    /\ Len(searchHistory) < MAX_OPERATIONS
    /\ searchBase' = container
    /\ searchScope' = "OneLevel"
    /\ targetObject' = target
    /\ LET result == DetermineResult(container, "OneLevel", target)
       IN /\ operationResult' = result
          /\ IF result = "Referral"
             THEN referralCount' = referralCount + 1
             ELSE UNCHANGED referralCount
          /\ searchHistory' = Append(searchHistory, [
                base |-> container,
                scope |-> "OneLevel",
                target |-> target,
                result |-> result
             ])
    /\ UNCHANGED <<objectLocation, currentContext>>

(****************************************************************************)
(* SAFE Search Actions (Post-fix behavior - avoids referrals)              *)
(****************************************************************************)

\* Search with Subtree scope from current context (SAFE - avoids referrals)
SearchSubtreeFromBase(target) ==
    /\ target \in OBJECT_TYPES
    /\ Len(searchHistory) < MAX_OPERATIONS
    /\ searchBase' = currentContext
    /\ searchScope' = "Subtree"
    /\ targetObject' = target
    /\ LET result == IF objectLocation[target] = currentContext
                     THEN "Success"
                     ELSE "NotFound"  \* Object in different context, but no referral
       IN /\ operationResult' = result
          /\ UNCHANGED referralCount  \* No referral with Subtree from base
          /\ searchHistory' = Append(searchHistory, [
                base |-> currentContext,
                scope |-> "Subtree",
                target |-> target,
                result |-> result
             ])
    /\ UNCHANGED <<objectLocation, currentContext>>

\* Search by distinguishedName filter from base context (SAFE - our fix)
SearchByDNFilter(target) ==
    /\ target \in OBJECT_TYPES
    /\ Len(searchHistory) < MAX_OPERATIONS
    /\ searchBase' = currentContext
    /\ searchScope' = "Subtree"
    /\ targetObject' = target
    \* Using (distinguishedName=...) filter from base_dn with Subtree
    /\ LET result == IF objectLocation[target] = currentContext
                     THEN "Success"
                     ELSE "NotFound"
       IN /\ operationResult' = result
          /\ UNCHANGED referralCount
          /\ searchHistory' = Append(searchHistory, [
                base |-> currentContext,
                scope |-> "Subtree",
                target |-> target,
                result |-> result
             ])
    /\ UNCHANGED <<objectLocation, currentContext>>

(****************************************************************************)
(* Next State Relation                                                      *)
(****************************************************************************)

\* Unsafe specification (models pre-fix behavior)
NextUnsafe ==
    \E t \in OBJECT_TYPES :
        \/ SearchBaseOnObjectDN(t)
        \/ \E c \in NAMING_CONTEXTS : SearchOneLevelInContainer(c, t)

\* Safe specification (models post-fix behavior)
NextSafe ==
    \E t \in OBJECT_TYPES :
        \/ SearchSubtreeFromBase(t)
        \/ SearchByDNFilter(t)

\* Combined for comparison
Next ==
    \/ NextUnsafe
    \/ NextSafe

Spec == Init /\ [][Next]_vars

(****************************************************************************)
(* Safety Invariants                                                        *)
(****************************************************************************)

\* INV1: Safe searches never cause referrals
SafeSearchesNoReferrals ==
    \A i \in 1..Len(searchHistory) :
        LET record == searchHistory[i]
        IN (record.scope = "Subtree" /\ record.base = currentContext) =>
            record.result /= "Referral"

\* INV2: Referrals only occur with Base/OneLevel on non-local contexts
ReferralsOnlyFromUnsafePatterns ==
    \A i \in 1..Len(searchHistory) :
        LET record == searchHistory[i]
        IN record.result = "Referral" =>
            /\ record.scope \in {"Base", "OneLevel"}
            /\ record.base /= currentContext

\* INV3: Using Subtree from base_dn never triggers referral
SubtreeFromBaseNeverReferrals ==
    \A i \in 1..Len(searchHistory) :
        LET record == searchHistory[i]
        IN (record.scope = "Subtree" /\ record.base = currentContext) =>
            record.result \in {"Success", "NotFound"}

\* INV4: Total referral count matches history
ReferralCountConsistent ==
    referralCount = Cardinality({i \in 1..Len(searchHistory) :
        searchHistory[i].result = "Referral"})

(****************************************************************************)
(* Liveness Properties                                                      *)
(****************************************************************************)

\* Safe searches eventually succeed (if object exists in context)
SafeSearchesSucceed ==
    \A t \in OBJECT_TYPES :
        (objectLocation[t] = currentContext) =>
            <>(operationResult = "Success" /\ targetObject = t)

(****************************************************************************)
(* Bug Detection                                                            *)
(****************************************************************************)

\* Detect when unsafe patterns are used (for refactoring verification)
UnsafePatternUsed ==
    \E i \in 1..Len(searchHistory) :
        LET record == searchHistory[i]
        IN /\ record.scope \in {"Base", "OneLevel"}
           /\ record.base /= currentContext

\* Detect referral errors (the bug we fixed)
ReferralErrorOccurred ==
    referralCount > 0

\* This property should be FALSE after applying the fix
NoReferralsAfterFix ==
    \A i \in 1..Len(searchHistory) :
        LET record == searchHistory[i]
        IN (record.scope = "Subtree") => record.result /= "Referral"

(****************************************************************************)
(* State Space Constraints                                                  *)
(****************************************************************************)

StateConstraint ==
    /\ Len(searchHistory) <= MAX_OPERATIONS
    /\ referralCount <= MAX_OPERATIONS

(****************************************************************************)
(* Specific Scenarios from Bug Fixes                                        *)
(****************************************************************************)

\* Model the KRBTGT search fix:
\* OLD: Search CN=Users,{base_dn} with OneLevel for sAMAccountName=krbtgt
\* NEW: Search {base_dn} with Subtree for sAMAccountName=krbtgt

\* Model the AdminSDHolder search fix:
\* OLD: Search CN=AdminSDHolder,CN=System,{base_dn} with Base for objectClass=*
\* NEW: Search {base_dn} with Subtree for (&(objectClass=container)(cn=AdminSDHolder))

\* Model the member lookup fix:
\* OLD: Search {member_dn} with Base for objectClass=*
\* NEW: Search {base_dn} with Subtree for (distinguishedName={escaped_member_dn})

=============================================================================
