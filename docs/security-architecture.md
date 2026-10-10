# Zyguor Agent Execution Gateway — Security Architecture

## 1. Overview

The Zyguor Agent Execution Gateway is a Rust-based mediation layer between an AI agent and execution capabilities.

The gateway does not allow an agent to directly invoke sensitive system actions. Instead, each request passes through policy evaluation, scope validation, security checks, audit logging, and, when required, human approval.

The design follows three core principles:

- **Fail closed**
- **Least privilege**
- **Separate capability from authority**

An AI agent may request an operation, but the gateway determines whether that operation is allowed, blocked, or held for human review.

---

## 2. High-Level Architecture

```text
AI Agent / MCP Client
        |
        v
Structured Execution Request
        |
        v
+-----------------------------+
| Zyguor Agent Execution      |
| Gateway                     |
+-----------------------------+
        |
        +--> Input Validation
        |
        +--> Policy Engine
        |      |
        |      +--> Allow
        |      +--> Review
        |      +--> Block
        |
        +--> Scope / Security Validation
        |
        +--> Audit Logging
        |
        +--> Execution Capability
                |
                +--> Filesystem
                +--> Git Status
                +--> Cargo Test
                +--> HTTP
                +--> Wasm Sandbox
```

Review-required operations are stored in durable pending-review state until an authorized administrator approves or rejects them.

---

## 3. Core Components

### 3.1 Policy Engine

The policy engine maps normalized operations to one of three decisions:

- `Allow`
- `Review`
- `Block`

The policy configuration itself is constrained so sensitive capabilities cannot be configured to bypass mandatory human review.

Examples:

- file writes require review,
- Cargo test execution requires review,
- HTTP POST requires review.

Capabilities that do not support a reviewed execution path cannot be configured to require review.

This prevents configuration from creating unsupported or unsafe policy states.

---

## 4. Structured Execution Requests

The gateway operates on structured request types rather than unrestricted shell commands.

Supported operation categories include:

- arithmetic/addition,
- read file,
- write file,
- Git status,
- Cargo test,
- HTTP GET,
- HTTP POST.

Each operation has structured arguments and operation-specific validation.

This reduces ambiguity and prevents raw shell execution from becoming the default execution interface.

---

## 5. Request Lifecycle

### 5.1 Allowed Request

```text
Request
   |
   v
Parse + normalize
   |
   v
Policy = Allow
   |
   v
Scope/security validation
   |
   v
Pre-execution audit
   |
   v
Execute
   |
   v
Completion audit
   |
   v
Return result
```

### 5.2 Review-Required Request

```text
Request
   |
   v
Parse + normalize
   |
   v
Policy = Review
   |
   v
Capture security state
   |
   v
Persist PendingReview
   |
   v
Return HELD_FOR_REVIEW
```

The original operation does not execute at this stage.

---

## 6. Human Approval Flow

The administrative control plane supports:

- `APPROVE <request-id>`
- `REJECT <request-id>`
- `ACK_CLAIMED <request-id>`

Approval does not automatically trust the security state captured at review time.

The gateway performs revalidation immediately before execution.

```text
APPROVE
   |
   v
Locate pending request
   |
   v
Revalidate request security state
   |
   v
Claim request
   |
   v
Persist approval / pre-execution audit
   |
   v
Execute
   |
   v
Persist completion audit
   |
   v
Consume claimed request
```

This protects against state changes between review and execution.

---

## 7. Pending Review State

Pending-review state is durable across restarts.

The store maintains two logical collections:

- pending reviews,
- claimed reviews.

A request becomes claimed before a reviewed side effect executes.

This distinction is important because a crash can occur after an operation begins but before cleanup completes.

---

## 8. Crash-Safe Persistence

Pending-review persistence uses an atomic replace model.

Simplified flow:

```text
Serialize state
     |
     v
Create private temporary file
     |
     v
Write contents
     |
     v
fsync temporary file
     |
     v
renameat() to final state file
     |
     v
fsync parent directory
```

The successful rename is treated as the persistence commit point.

Persistence failures are classified as:

- **BeforeCommit**
- **AfterCommit / DurabilityUncertain**

Before-commit failures allow in-memory rollback.

After-commit failures do not roll memory backward because the new state may already exist on disk.

---

## 9. Operational-State Path Anchoring

Pending-review and audit state must reside outside the agent workspace.

Operational paths are validated at startup.

The gateway records the validated parent directory identity using:

- device ID,
- inode ID.

The parent directory is then opened and its actual identity is checked against the validated identity.

If the identity changed between validation and opening, startup fails closed.

Once verified, the directory file descriptor is retained.

This prevents later parent-path replacement from redirecting operational state.

---

## 10. FD-Relative Pending-State Operations

Pending-review persistence does not repeatedly resolve the parent pathname.

Instead, it uses the retained trusted directory file descriptor.

Relevant operations use:

- `openat`
- `renameat`
- `unlinkat`

The final state filename is resolved relative to the trusted directory handle.

This prevents parent directory replacement from redirecting state writes.

---

## 11. Pending-State File Safety

The pending-review state loader:

- opens relative to the retained directory,
- rejects symbolic links,
- verifies the opened object is a regular file,
- avoids blocking on malicious special files,
- fails closed on invalid persisted state.

The state file is therefore validated after opening, not only by pathname inspection.

---

## 12. Audit Architecture

Audit events are stored as JSON Lines.

Security-relevant phases include:

- approval,
- rejection,
- pre-execution,
- completion,
- reconciliation.

Execution outcomes include:

- success,
- failed,
- not executed,
- unknown.

Audit records include a stable request identity so multiple phases of the same operation can be correlated.

---

## 13. Anchored Audit Storage

Production audit persistence uses an `AnchoredAuditLog`.

At startup:

1. the audit path is validated,
2. parent device/inode identity is captured,
3. the parent directory is opened,
4. the opened directory identity is verified,
5. the directory file descriptor is retained.

Audit file access then uses `openat` relative to that trusted directory.

The audit target:

- must not be followed through a symlink,
- must be a regular file,
- is restricted to owner-only permissions.

---

## 14. Audit Durability

For newly created audit files, the gateway:

1. creates the file,
2. applies restrictive permissions,
3. synchronizes the file,
4. synchronizes the parent directory,
5. writes the audit record,
6. synchronizes the file again.

Audit writes are serialized with a shared mutex so concurrent gateway/admin activity does not interleave JSONL records.

---

## 15. Filesystem Capability Boundary

Agent file operations are constrained to the configured workspace.

The gateway rejects:

- absolute paths,
- parent traversal,
- invalid path scope,
- symlink escape,
- symlinked parents,
- unsafe final targets.

Filesystem operations use opened handles and anchored validation where appropriate.

---

## 16. Read Security

Secure reads verify that:

- the path remains inside the workspace,
- parent components do not escape through symlinks,
- the final target is not a symlink,
- the opened object is a regular file,
- configured read-size limits are respected.

---

## 17. Write Security

Write operations require human review.

At review time, the gateway captures write-target state.

Target state may represent:

- a missing target,
- an existing file with a content hash.

Before approved execution, the target is revalidated.

Execution is rejected if the target was:

- created after review,
- removed after review,
- modified after review,
- replaced by an unsafe filesystem object.

Writes are performed using secure filesystem operations rather than trusting the original pathname state.

---

## 18. Cargo Test Security

Cargo test execution requires human review.

At review time, the gateway captures a workspace fingerprint.

Before execution, the workspace is revalidated.

If relevant Cargo inputs changed after review, approval is rejected.

Execution runs against a controlled workspace snapshot.

Cargo execution also enforces:

- execution timeout,
- stdout capture limit,
- stderr capture limit,
- descendant process-group cleanup.

Configuration values are subject to hard upper bounds.

---

## 19. Git Status Security

Git status is treated as a bounded read-style capability.

The gateway limits the maximum number of status entries processed.

Git metadata that resolves outside the permitted workspace is rejected.

---

## 20. HTTP Security Model

Outbound HTTP access is explicitly constrained.

The gateway enforces:

- HTTPS only,
- approved host allowlist,
- no embedded credentials,
- no IP-literal destinations,
- no localhost,
- default HTTPS port restrictions,
- redirect disabling,
- proxy disabling,
- DNS resolution checks,
- unsafe-address rejection.

---

## 21. SSRF Protection

Resolved outbound addresses are checked before execution.

Rejected categories include:

- loopback,
- private address space,
- link-local,
- multicast,
- unspecified,
- IPv4 shared address space,
- benchmarking ranges,
- other unsafe destination classes.

This prevents an allowlisted hostname from becoming a route to internal infrastructure through unsafe DNS resolution.

---

## 22. HTTP Request and Response Bounds

HTTP configuration has both defaults and hard maximum values.

The gateway bounds:

- timeout,
- request body size,
- response body size.

Oversized request bodies are rejected.

Response bodies are bounded and may be truncated.

---

## 23. HTTP POST Review

HTTP POST is treated as an external write operation.

It requires human review.

The exact request information is retained for approval and revalidated before execution.

Approval cannot silently redirect the reviewed request to a different destination.

---

## 24. Wasm Sandbox

The gateway uses Wasmtime for sandboxed computation.

Production sandbox execution enables:

- fuel consumption,
- memory limits,
- epoch interruption.

These form independent resource-control mechanisms.

---

## 25. Wasm Fuel Limit

Every production sandbox store receives a configured fuel allocation.

When fuel is exhausted, Wasmtime traps execution.

The gateway converts the failure into a controlled execution failure rather than allowing unbounded CPU consumption.

---

## 26. Wasm Memory Limit

A Wasmtime `StoreLimits` limiter is attached to the store.

The limiter enforces a configured maximum memory size.

Memory growth beyond the configured maximum traps instead of silently exceeding the resource boundary.

---

## 27. Wasm Execution Timeout

Epoch interruption is enabled.

The store is configured with an epoch deadline.

A timer thread waits for the configured timeout.

If execution does not complete in time, the timer advances the Wasmtime engine epoch, causing execution to trap.

Successful execution cancels the timer path, and the timer thread is joined.

---

## 28. Configuration Safety

Gateway configuration is parsed with unknown-field rejection.

Numeric resource settings must be:

- greater than zero,
- no greater than predefined hard upper bounds.

Bounded settings include:

- HTTP timeout,
- HTTP request body size,
- HTTP response body size,
- Cargo timeout,
- Cargo stdout size,
- Cargo stderr size,
- Wasm fuel,
- Wasm memory,
- Wasm timeout.

This prevents configuration from disabling practical resource controls through extreme values.

---

## 29. Admin Control Plane

The admin control plane is exposed through a local Unix-domain socket.

The socket is created with owner-only permissions.

If the configured socket path already exists, startup refuses to overwrite it.

This avoids silently replacing an existing filesystem object.

---

## 30. Admin Peer Authentication

Filesystem permissions are supplemented by operating-system peer credential verification.

On supported Unix platforms, the gateway obtains the peer UID from the accepted Unix socket connection.

The peer UID must match the gateway process's effective UID.

Connections from a different user are rejected before admin commands are processed.

---

## 31. Admin Input Validation

Admin commands are read through a bounded reader.

Commands exceeding the configured maximum length are rejected.

Parsing validates:

- supported command name,
- request ID presence,
- UUID format,
- unexpected extra arguments.

Malformed commands do not consume pending request state.

---

## 32. Admin Socket Lifecycle

The gateway uses an admin socket path guard.

The guard records the socket's filesystem identity.

When cleaning up, the gateway removes the socket only if the current filesystem object:

- is still a Unix socket,
- has the expected device identity,
- has the expected inode identity.

This prevents shutdown cleanup from deleting a replacement object.

---

## 33. Restart Reconciliation

A claimed operation may survive a process restart.

The gateway does not assume that such an operation did or did not complete.

It therefore marks the situation as operationally uncertain.

Surviving claimed requests:

- are not automatically retried,
- generate a startup security warning,
- require operator reconciliation.

---

## 34. ACK_CLAIMED

`ACK_CLAIMED` is used to reconcile a claimed request without replaying it.

The flow is:

```text
Locate claimed request
        |
        v
Write reconciliation audit
        |
        v
Consume claimed state
        |
        v
Return acknowledgement
```

The original operation is never re-executed during acknowledgement.

---

## 35. Reconciliation Durability

If consumption fails before the persistence commit point, the claimed request remains available.

If the disk update committed but parent-directory durability is uncertain, the gateway reports a dedicated durability-uncertain result rather than pretending the acknowledgement was completely durable.

---

## 36. Audit-Before-Execution Principle

For reviewed operations, pre-execution auditing happens before the side effect.

If the pre-execution audit fails, execution is prevented and claimed state is restored where safe.

This prevents a sensitive action from proceeding without the required audit trail.

---

## 37. Completion Audit Failures

A completion audit failure is not treated as though execution never happened.

The gateway preserves the execution outcome and reports the audit failure separately.

This is important because retrying an already executed operation could create duplicate side effects.

---

## 38. Concurrency

Pending-review state is protected by a mutex.

Audit persistence uses a separate shared audit lock.

Locks are held only around the state or resource they protect, reducing unnecessary coupling between unrelated operations.

---

## 39. Error Handling

Production code favors explicit error propagation.

Security-sensitive failures return controlled errors instead of relying on panic-driven recovery.

Examples include:

- persistence errors,
- audit failures,
- invalid filesystem state,
- network validation failures,
- sandbox failures,
- admin authentication failures.

---

## 40. Fail-Closed Startup

Startup fails when required security assumptions cannot be established.

Examples include:

- invalid workspace configuration,
- unsafe operational-state path,
- changed operational parent identity,
- malformed persisted review state,
- invalid gateway configuration,
- unsafe existing operational state,
- invalid admin socket setup.

---

## 41. Main Security Boundaries

```text
               Untrusted
              AI / Client
                   |
                   v
          +------------------+
          | Request Parsing  |
          +------------------+
                   |
                   v
          +------------------+
          | Policy Engine    |
          +------------------+
                   |
        +----------+-----------+
        |                      |
      Allow                  Review
        |                      |
        v                      v
Security Validation      Pending Review Store
        |                      |
        v                      v
Execution              Admin Approval
        |                      |
        +-----------+----------+
                    |
                    v
              Audit System
                    |
                    v
            Anchored State
```

---

## 42. Security Verification

The current release-candidate baseline contains:

**291 automated tests**

covering policy enforcement, approval integrity, persistence, audit durability, filesystem safety, SSRF prevention, sandbox resource limits, restart reconciliation, and admin control-plane security.

---

## 43. Design Principle

The gateway is designed around a simple security rule:

> Requests are untrusted until policy, scope, state, and authority all agree that execution is permitted.

Human approval is one layer of authority.

It does not replace technical security validation.

Likewise, technical validation does not replace authorization.

Both must succeed before sensitive operations execute.