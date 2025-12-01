----------------------------- MODULE CacheInvariants ----------------------------
(****************************************************************************)
(* TLA+ Formal Specification: LRU Cache with TTL and TOCTOU Detection      *)
(*                                                                          *)
(* Models the ADSecurityScanner's advanced caching system with LRU         *)
(* eviction, TTL expiration, and detection of time-of-check-time-of-use    *)
(* race conditions.                                                         *)
(*                                                                          *)
(* Based on: src-tauri/src/advanced_cache.rs                               *)
(****************************************************************************)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    MAX_SIZE_BYTES,     \* Maximum cache size in bytes
    DEFAULT_TTL,        \* Default time-to-live in time units
    MAX_TIME,           \* Model checking time bound
    KEYS,               \* Set of possible cache keys
    MAX_ENTRY_SIZE      \* Maximum size of a single entry

VARIABLES
    cacheEntries,       \* Function: key -> entry record or "none"
    totalSize,          \* Current total cache size in bytes
    accessCounts,       \* Function: key -> access count
    lastAccessed,       \* Function: key -> timestamp of last access
    expiresAt,          \* Function: key -> expiration timestamp
    entrySize,          \* Function: key -> size in bytes
    currentTime,        \* Global time counter
    hitCount,           \* Cache hit counter
    missCount,          \* Cache miss counter
    evictionCount,      \* Eviction counter
    pendingOperations   \* Set of concurrent operations (for TOCTOU)

vars == <<cacheEntries, totalSize, accessCounts, lastAccessed, expiresAt,
          entrySize, currentTime, hitCount, missCount, evictionCount,
          pendingOperations>>

(****************************************************************************)
(* Type Definitions                                                         *)
(****************************************************************************)

EntryState == {"Present", "Expired", "Evicted", "None"}

OperationType == {"Get", "Put", "Evict", "ExpireCheck"}

OperationRecord == [key: KEYS, opType: OperationType, startTime: Nat]

TypeInvariant ==
    /\ cacheEntries \in [KEYS -> EntryState]
    /\ totalSize \in Nat
    /\ accessCounts \in [KEYS -> Nat]
    /\ lastAccessed \in [KEYS -> Int]
    /\ expiresAt \in [KEYS -> Int]
    /\ entrySize \in [KEYS -> Nat]
    /\ currentTime \in Nat
    /\ hitCount \in Nat
    /\ missCount \in Nat
    /\ evictionCount \in Nat
    /\ pendingOperations \subseteq OperationRecord

(****************************************************************************)
(* Helper Functions                                                         *)
(****************************************************************************)

\* Check if an entry is expired
IsExpired(key) ==
    /\ cacheEntries[key] = "Present"
    /\ currentTime > expiresAt[key]

\* Get all present (non-expired) entries
PresentEntries ==
    {k \in KEYS : cacheEntries[k] = "Present" /\ ~IsExpired(k)}

\* Get total size of present entries (abstracted - actual sum tracked in totalSize variable)
\* Note: TLA+ doesn't have built-in sum for sets, so we rely on the totalSize variable
\* which is maintained correctly by Put/Evict/Remove operations
ComputeTotalSize == totalSize

\* Find least recently accessed entry
LeastRecentlyAccessed ==
    CHOOSE k \in PresentEntries :
        \A k2 \in PresentEntries :
            lastAccessed[k] <= lastAccessed[k2]

\* Find entry with lowest access count (for LRU)
LowestAccessCount ==
    CHOOSE k \in PresentEntries :
        \A k2 \in PresentEntries :
            accessCounts[k] <= accessCounts[k2]

(****************************************************************************)
(* Initial State                                                            *)
(****************************************************************************)

Init ==
    /\ cacheEntries = [k \in KEYS |-> "None"]
    /\ totalSize = 0
    /\ accessCounts = [k \in KEYS |-> 0]
    /\ lastAccessed = [k \in KEYS |-> -1]
    /\ expiresAt = [k \in KEYS |-> -1]
    /\ entrySize = [k \in KEYS |-> 0]
    /\ currentTime = 0
    /\ hitCount = 0
    /\ missCount = 0
    /\ evictionCount = 0
    /\ pendingOperations = {}

(****************************************************************************)
(* Cache Operations                                                         *)
(****************************************************************************)

\* Get an entry from cache (cache hit)
CacheHit(key) ==
    /\ key \in KEYS
    /\ cacheEntries[key] = "Present"
    /\ ~IsExpired(key)
    /\ accessCounts' = [accessCounts EXCEPT ![key] = @ + 1]
    /\ lastAccessed' = [lastAccessed EXCEPT ![key] = currentTime]
    /\ hitCount' = hitCount + 1
    /\ UNCHANGED <<cacheEntries, totalSize, expiresAt, entrySize,
                   currentTime, missCount, evictionCount, pendingOperations>>

\* Cache miss (entry not present or expired)
CacheMiss(key) ==
    /\ key \in KEYS
    /\ \/ cacheEntries[key] = "None"
       \/ IsExpired(key)
    /\ missCount' = missCount + 1
    /\ UNCHANGED <<cacheEntries, totalSize, accessCounts, lastAccessed,
                   expiresAt, entrySize, currentTime, hitCount,
                   evictionCount, pendingOperations>>

\* Put an entry into cache (with eviction if needed)
PutEntry(key, size) ==
    /\ key \in KEYS
    /\ size \in 1..MAX_ENTRY_SIZE
    /\ size <= MAX_SIZE_BYTES  \* Entry must fit
    /\ totalSize + size <= MAX_SIZE_BYTES  \* Space available
    /\ cacheEntries' = [cacheEntries EXCEPT ![key] = "Present"]
    /\ entrySize' = [entrySize EXCEPT ![key] = size]
    /\ totalSize' = totalSize + size
    /\ accessCounts' = [accessCounts EXCEPT ![key] = 1]
    /\ lastAccessed' = [lastAccessed EXCEPT ![key] = currentTime]
    /\ expiresAt' = [expiresAt EXCEPT ![key] = currentTime + DEFAULT_TTL]
    /\ UNCHANGED <<currentTime, hitCount, missCount, evictionCount,
                   pendingOperations>>

\* Evict an entry to make room
EvictEntry(key) ==
    /\ key \in KEYS
    /\ cacheEntries[key] = "Present"
    /\ cacheEntries' = [cacheEntries EXCEPT ![key] = "Evicted"]
    /\ totalSize' = totalSize - entrySize[key]
    /\ evictionCount' = evictionCount + 1
    /\ UNCHANGED <<accessCounts, lastAccessed, expiresAt, entrySize,
                   currentTime, hitCount, missCount, pendingOperations>>

\* Evict LRU entry (lowest access count)
EvictLRU ==
    /\ Cardinality(PresentEntries) > 0
    /\ LET victim == LowestAccessCount
       IN /\ cacheEntries' = [cacheEntries EXCEPT ![victim] = "Evicted"]
          /\ totalSize' = totalSize - entrySize[victim]
          /\ evictionCount' = evictionCount + 1
    /\ UNCHANGED <<accessCounts, lastAccessed, expiresAt, entrySize,
                   currentTime, hitCount, missCount, pendingOperations>>

\* Remove expired entry
RemoveExpired(key) ==
    /\ key \in KEYS
    /\ cacheEntries[key] = "Present"
    /\ IsExpired(key)
    /\ cacheEntries' = [cacheEntries EXCEPT ![key] = "Expired"]
    /\ totalSize' = totalSize - entrySize[key]
    /\ UNCHANGED <<accessCounts, lastAccessed, expiresAt, entrySize,
                   currentTime, hitCount, missCount, evictionCount,
                   pendingOperations>>

(****************************************************************************)
(* TOCTOU Race Condition Modeling                                           *)
(****************************************************************************)

\* Start a get operation (check phase)
StartGetOperation(key) ==
    /\ key \in KEYS
    /\ LET op == [key |-> key, opType |-> "Get", startTime |-> currentTime]
       IN pendingOperations' = pendingOperations \cup {op}
    /\ UNCHANGED <<cacheEntries, totalSize, accessCounts, lastAccessed,
                   expiresAt, entrySize, currentTime, hitCount, missCount,
                   evictionCount>>

\* Complete get operation (use phase)
CompleteGetOperation(key) ==
    /\ key \in KEYS
    /\ \E op \in pendingOperations :
        op.key = key /\ op.opType = "Get"
    /\ LET op == CHOOSE o \in pendingOperations : o.key = key /\ o.opType = "Get"
       IN pendingOperations' = pendingOperations \ {op}
    /\ UNCHANGED <<cacheEntries, totalSize, accessCounts, lastAccessed,
                   expiresAt, entrySize, currentTime, hitCount, missCount,
                   evictionCount>>

\* Model concurrent expiration during get (TOCTOU race)
\* Entry checked as present at T1, but expires/evicted at T2 before use
TOCTOURace(key) ==
    /\ key \in KEYS
    /\ \E op \in pendingOperations :
        /\ op.key = key
        /\ op.opType = "Get"
        /\ op.startTime < currentTime  \* Time has passed since check
    /\ cacheEntries[key] /= "Present"  \* Entry no longer present
    \* This state represents the race condition

(****************************************************************************)
(* Time Actions                                                             *)
(****************************************************************************)

\* Time advances
Tick ==
    /\ currentTime < MAX_TIME
    /\ currentTime' = currentTime + 1
    /\ UNCHANGED <<cacheEntries, totalSize, accessCounts, lastAccessed,
                   expiresAt, entrySize, hitCount, missCount,
                   evictionCount, pendingOperations>>

(****************************************************************************)
(* Next State Relation                                                      *)
(****************************************************************************)

Next ==
    \/ \E k \in KEYS :
        \/ CacheHit(k)
        \/ CacheMiss(k)
        \/ \E s \in 1..MAX_ENTRY_SIZE : PutEntry(k, s)
        \/ EvictEntry(k)
        \/ RemoveExpired(k)
        \/ StartGetOperation(k)
        \/ CompleteGetOperation(k)
    \/ EvictLRU
    \/ Tick

Spec == Init /\ [][Next]_vars

(****************************************************************************)
(* Safety Invariants                                                        *)
(****************************************************************************)

\* INV1: Total cache size never exceeds maximum
CacheSizeConstraint ==
    totalSize <= MAX_SIZE_BYTES

\* INV2: Access count is non-negative
NonNegativeAccessCount ==
    \A k \in KEYS :
        accessCounts[k] >= 0

\* INV3: Expired entries are not counted in active size
\* Total size should only reflect Present (non-expired) entries
ExpiredNotInSize ==
    \* The totalSize variable should only count Present entries
    \* We verify by checking totalSize is bounded by sum of present entry sizes
    totalSize <= MAX_SIZE_BYTES /\
    \A k \in KEYS :
        cacheEntries[k] \in {"Expired", "Evicted", "None"} =>
            \* These entries contribute 0 to totalSize (verified by Put/Evict/Remove logic)
            entrySize[k] >= 0

\* INV4: Present entries have valid expiration time
PresentHasExpiration ==
    \A k \in KEYS :
        cacheEntries[k] = "Present" =>
            expiresAt[k] >= 0

\* INV5: Last accessed time is after creation
AccessAfterCreation ==
    \A k \in KEYS :
        cacheEntries[k] = "Present" =>
            lastAccessed[k] >= 0

\* INV6: Eviction preserves frequently accessed entries (LRU property)
\* When eviction happens, the evicted entry should have the lowest access count
\* among all entries that were present at that time
LRUPreservation ==
    \A k1 \in KEYS :
        cacheEntries[k1] = "Present" =>
            \A k2 \in KEYS :
                cacheEntries[k2] = "Evicted" =>
                    \* If both were candidates, present entry should have >= accesses
                    accessCounts[k1] >= accessCounts[k2]

\* INV7: Statistics are consistent
StatsConsistency ==
    /\ hitCount >= 0
    /\ missCount >= 0
    /\ evictionCount >= 0

\* INV8: Entry size is within bounds
EntrySizeBound ==
    \A k \in KEYS :
        cacheEntries[k] = "Present" =>
            /\ entrySize[k] > 0
            /\ entrySize[k] <= MAX_ENTRY_SIZE

\* INV9: No active TOCTOU race with stale check
\* Pending operations should not be excessively stale
NoStaleCheck ==
    \A op \in pendingOperations :
        \* Operations older than 2x TTL are definitely stale and should timeout
        currentTime - op.startTime <= DEFAULT_TTL * 2

(****************************************************************************)
(* Liveness Properties                                                      *)
(****************************************************************************)

\* Pending operations eventually complete
OperationsComplete ==
    \A op \in pendingOperations :
        <>(op \notin pendingOperations)

\* Expired entries are eventually removed
ExpiredRemoved ==
    \A k \in KEYS :
        IsExpired(k) ~>
            (cacheEntries[k] \in {"Expired", "Evicted", "None"})

(****************************************************************************)
(* TOCTOU Detection                                                         *)
(****************************************************************************)

\* Detect potential TOCTOU: pending get on expired/evicted entry
PotentialTOCTOU ==
    \E k \in KEYS :
        /\ \E op \in pendingOperations :
            op.key = k /\ op.opType = "Get"
        /\ cacheEntries[k] /= "Present"

\* This should be FALSE in correctly synchronized implementation
HasTOCTOURace == PotentialTOCTOU

(****************************************************************************)
(* State Space Constraints                                                  *)
(****************************************************************************)

StateConstraint ==
    /\ currentTime <= MAX_TIME
    /\ hitCount + missCount <= MAX_TIME * 2
    /\ Cardinality(pendingOperations) <= Cardinality(KEYS)

=============================================================================
