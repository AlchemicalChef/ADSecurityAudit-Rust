# TLA+ Formal Specifications for ADSecurityScanner

## Overview

This directory contains TLA+ formal specifications for verifying critical properties of the ADSecurityScanner Active Directory security auditing tool. These specifications model state machines, concurrency patterns, and security invariants to detect potential bugs and verify correctness.

## Modules

### 1. KRBTGTRotation.tla
**Purpose:** Models the two-phase KRBTGT password rotation state machine.

**Key Invariants:**
- `Phase2RequiresPhase1AndWait` - Second rotation requires first complete + 10-hour wait
- `TimestampMonotonicity` - Phase 2 timestamp always after phase 1
- `RotationTerminates` - Every rotation eventually completes or fails

**Bug Detection:** Catches attempts to perform phase 2 rotation before the minimum wait period.

### 2. DomainManagement.tla
**Purpose:** Models multi-domain lifecycle and detects the BUG-5 race condition.

**Key Invariants:**
- `SingleActiveDomain` - At most one domain active at any time
- `AuditDomainConsistency` - Audit runs on the domain that was active when started

**Bug Detection (BUG-5):**
The specification includes `SetActiveDomainUnsafe` which models the current buggy behavior where domain switching can occur during an active audit. Enabling the `AuditDomainConsistency` invariant will produce a counterexample showing the race condition.

### 3. AuthenticationFlow.tla
**Purpose:** Models the ephemeral LDAP authentication pattern with credential security.

**Key Invariants:**
- `CredentialZeroization` - Credentials are zeroized when session is destroyed
- `AuthRequiresCredentials` - Cannot be authenticated without credentials
- `BoundedRetries` - Retry count never exceeds maximum

**Security Verification:** Ensures SecureString lifecycle with guaranteed memory zeroization.

### 4. IncidentLifecycle.tla
**Purpose:** Models incident status progression with forward-only enforcement.

**Key Invariants:**
- `ForwardOnlyStatus` - Status can only progress forward (Open → Investigating → ... → Closed)
- `ClosedIsFinal` - No transitions out of Closed state
- `WriteProtection` - Status changes require write lock

**Bug Detection:** The specification includes `ChangeStatusUnsafe` which allows arbitrary status changes. If the actual code doesn't enforce forward-only transitions, the `ForwardOnlyStatus` invariant will be violated.

## Running TLC Model Checker

### Prerequisites

1. Install TLA+ Toolbox: https://github.com/tlaplus/tlaplus/releases
2. Or use command-line TLC: `java -jar tla2tools.jar`

### Using TLA+ Toolbox

1. Open TLA+ Toolbox
2. Create a new spec: File → Open Spec → Add New Spec
3. Point to one of the `.tla` files
4. Create a model: TLC Model Checker → New Model
5. Configure the model using values from the corresponding `.cfg` file
6. Run the model checker

### Using Command-Line TLC

```bash
# Check KRBTGTRotation
java -jar tla2tools.jar -config KRBTGTRotation.cfg KRBTGTRotation.tla

# Check DomainManagement
java -jar tla2tools.jar -config DomainManagement.cfg DomainManagement.tla

# Check AuthenticationFlow
java -jar tla2tools.jar -config AuthenticationFlow.cfg AuthenticationFlow.tla

# Check IncidentLifecycle
java -jar tla2tools.jar -config IncidentLifecycle.cfg IncidentLifecycle.tla
```

## Expected Bug Detection Results

| Module | Invariant | Expected Result | Bug ID |
|--------|-----------|-----------------|--------|
| DomainManagement | `AuditDomainConsistency` | VIOLATED | BUG-5 |
| IncidentLifecycle | `ForwardOnlyStatus` | VIOLATED | New finding |
| KRBTGTRotation | `Phase2RequiresPhase1AndWait` | SATISFIED | N/A |
| AuthenticationFlow | `CredentialZeroization` | SATISFIED | N/A |

## Mapping to Source Code

| TLA+ Module | Rust Source Files |
|-------------|-------------------|
| KRBTGTRotation | `src-tauri/src/krbtgt.rs` |
| DomainManagement | `src-tauri/src/forest_manager.rs`, `src-tauri/src/main.rs` |
| AuthenticationFlow | `src-tauri/src/ad_client.rs`, `src-tauri/src/secure_types.rs` |
| IncidentLifecycle | `src-tauri/src/incident.rs`, `src-tauri/src/main.rs` |

## Configuration Tuning

The `.cfg` files use small constant values for tractable model checking. For more thorough verification:

```
\* More domains
DOMAINS = {d1, d2, d3}

\* Longer time horizon
MAX_TIME = 50

\* More incidents
MAX_INCIDENTS = 5
```

Note: Increasing these values exponentially increases state space. Use judiciously.

## Symmetry Reduction

The KRBTGTRotation module uses symmetry reduction (`Symmetry == Permutations(DOMAINS)`) to reduce state space when domains are interchangeable. This can provide significant speedup for larger domain sets.

## Interpreting Counterexamples

When TLC finds an invariant violation, it produces a counterexample trace. For example, a BUG-5 violation trace would look like:

```
State 1: configuredDomains = {corp, dev}, activeDomain = "corp"
State 2: StartAudit on "corp" (auditContext[0] = "corp")
State 3: SetActiveDomainUnsafe("dev") - domain switches to "dev"
State 4: Audit continues but activeDomain = "dev" != audit.domain = "corp"
         INVARIANT AuditDomainConsistency VIOLATED
```

This trace exactly describes the race condition in the implementation.

## Contributing

When modifying the specifications:

1. Ensure all existing invariants still pass
2. Add new invariants for any new properties
3. Document any new actions or state variables
4. Update this README with any significant changes

## License

Same as the main ADSecurityScanner project (MIT).
