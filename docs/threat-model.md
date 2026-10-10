# Zyguor Agent Execution Gateway — Threat Model

## 1. Purpose

The Zyguor Agent Execution Gateway is a policy-controlled execution layer designed to sit between AI agents and sensitive system capabilities.

Its purpose is to prevent an AI agent from directly performing high-impact actions without policy evaluation, validation, audit logging, and, where required, explicit human approval.

The gateway follows a fail-closed security model.

Operations are classified as:

- **Allow** — may execute automatically after validation.
- **Review** — must be held for explicit human approval.
- **Block** — must not execute.

The gateway does not treat successful policy evaluation alone as permission to bypass execution-time security checks.

---

## 2. Security Objectives

The gateway is designed to provide the following security properties:

1. Prevent unauthorized or out-of-scope agent actions.
2. Require human approval for high-impact operations.
3. Prevent approved requests from being modified between review and execution.
4. Restrict filesystem access to the configured workspace.
5. Prevent symlink and path-traversal escapes.
6. Restrict outbound HTTP destinations.
7. Mitigate SSRF and DNS-rebinding attacks.
8. Limit resource consumption by sandboxed Wasm execution.
9. Bound configurable timeouts, memory limits, output sizes, and request sizes.
10. Maintain durable security audit records.
11. Preserve pending approval state across process restarts.
12. Prevent uncertain operations from being automatically re-executed after crashes.
13. Protect operational state from pathname redirection and symlink attacks.
14. Restrict the local administrative control plane to the gateway owner.
15. Fail closed when critical security state cannot be validated or persisted.

---

## 3. Protected Assets

The primary assets protected by the gateway are:

### 3.1 Agent Workspace

Files and source code available to the AI agent.

The gateway prevents operations from escaping the configured workspace through:

- absolute paths,
- `..` traversal,
- symlinked parents,
- symlinked final components,
- changed targets after approval.

### 3.2 Pending Review State

Requests waiting for human approval and requests already claimed for execution.

This state is security-sensitive because modifying it could:

- introduce unauthorized operations,
- replay previously approved actions,
- alter reviewed parameters,
- remove evidence of pending actions.

### 3.3 Audit Log

The audit log records security-relevant decisions and execution outcomes.

Audit records include information such as:

- request identity,
- policy decision,
- policy reason,
- execution phase,
- execution outcome,
- timestamps.

### 3.4 Administrative Control Plane

The local Unix-domain admin socket controls:

- `APPROVE`
- `REJECT`
- `ACK_CLAIMED`

Compromise of this interface could allow an attacker to authorize privileged operations.

### 3.5 Outbound Network Access

HTTP capabilities must not become a mechanism for reaching:

- localhost,
- private networks,
- link-local networks,
- metadata services,
- arbitrary IP literals,
- unapproved destinations.

### 3.6 Execution Resources

CPU time, memory, subprocess output, HTTP bodies, and execution duration must remain bounded.

---

## 4. Trust Boundaries

The architecture contains several important trust boundaries.

### Boundary A — AI Agent → Gateway

Agent input is considered untrusted.

The agent cannot directly execute protected operations.

Every structured request passes through:

1. parsing,
2. normalization,
3. policy evaluation,
4. scope validation,
5. security validation,
6. execution or human-review routing.

### Boundary B — Gateway → Workspace

The workspace is treated as the only permitted filesystem scope for agent file operations.

Operational gateway state must reside outside this workspace.

### Boundary C — Gateway → External Network

Outbound HTTP is restricted by:

- HTTPS-only enforcement,
- hostname allowlisting,
- rejection of credentials in URLs,
- rejection of IP literals,
- rejection of localhost,
- port restrictions,
- DNS resolution validation,
- unsafe-address filtering,
- redirect disabling,
- proxy disabling.

### Boundary D — Gateway → Human Administrator

Review-required operations cross a human authorization boundary.

The administrator may approve, reject, or reconcile previously claimed requests through the local admin control plane.

### Boundary E — Gateway → Operational State

Audit logs and pending-review state are security-sensitive operational files.

Their parent directories are validated and anchored with retained directory file descriptors.

---

## 5. Threat Actors

The threat model considers the following attacker categories.

### 5.1 Malicious or Compromised AI Agent

An agent may attempt to:

- perform unauthorized actions,
- alter protected files,
- escape filesystem scope,
- access internal network services,
- exploit approval workflows,
- consume excessive resources.

### 5.2 Prompt-Injection or Indirect-Instruction Attacker

External content processed by an AI system may attempt to influence the agent into requesting unsafe operations.

The gateway assumes agent intent cannot be trusted solely because it originated from an AI system.

### 5.3 Local Unprivileged User

A local user may attempt to:

- access the admin socket,
- replace operational-state paths,
- redirect audit files,
- alter pending-review files,
- exploit filesystem races.

### 5.4 Remote Network Attacker

A remote service may attempt to:

- redirect HTTP requests,
- manipulate DNS results,
- trigger oversized responses,
- cause network resource exhaustion.

---

## 6. Key Threats and Mitigations

### 6.1 Unauthorized Agent Execution

**Threat**

An AI agent attempts to perform a dangerous action without human authorization.

**Mitigation**

Operations are mapped to policy decisions.

Sensitive operations such as file writes, Cargo execution, and HTTP POST requests cannot be configured to bypass required review.

---

### 6.2 Approval-Time Request Modification

**Threat**

A request is reviewed and then its target or environment changes before execution.

**Mitigation**

Approved operations are revalidated immediately before execution.

Examples include:

- write-target state revalidation,
- workspace fingerprint verification for Cargo tests,
- HTTP destination revalidation.

---

### 6.3 Filesystem Escape

**Threat**

An agent attempts to access files outside the configured workspace.

Possible techniques include:

- absolute paths,
- parent traversal,
- symlinked directories,
- symlinked final targets.

**Mitigation**

Filesystem operations use anchored and validated access.

Path traversal and symlink escape attempts are rejected.

Secure reads and writes verify the final opened filesystem object.

---

### 6.4 Symlink Race / TOCTOU

**Threat**

An attacker replaces a validated filesystem path between validation and use.

**Mitigation**

Critical operations use opened directory handles and FD-relative filesystem operations.

Pending-review persistence uses:

- `openat`
- `renameat`
- `unlinkat`

Operational parent directory device and inode identity are captured during validation and rechecked after opening.

---

### 6.5 Operational-State Redirection

**Threat**

An attacker replaces the operational-state directory after startup and attempts to redirect pending-review or audit writes.

**Mitigation**

The gateway retains trusted parent-directory file descriptors.

Later filesystem operations use those handles instead of repeatedly resolving the parent pathname.

Parent replacement therefore does not redirect writes to the replacement directory.

---

### 6.6 Audit Log Symlink Attack

**Threat**

An attacker attempts to replace the audit file with a symlink to another file.

**Mitigation**

Audit files are opened relative to an anchored parent directory with no-follow protection.

The opened target must be a regular file.

Audit file permissions are enforced as owner-only.

---

### 6.7 Audit Record Interleaving

**Threat**

Concurrent gateway and administrative operations write overlapping or corrupted JSON audit records.

**Mitigation**

Audit writes are serialized through a shared process-wide mutex.

Each audit entry is persisted as one JSONL record.

---

### 6.8 Audit Durability Failure

**Threat**

The system reports a security event as completed although its audit record was not durably written.

**Mitigation**

Security-sensitive execution ordering requires audit persistence before certain actions proceed.

Audit files are synchronized to storage.

New audit-file creation includes parent-directory synchronization.

---

### 6.9 Pending-Review Crash Inconsistency

**Threat**

A process crash occurs while updating approval state.

**Mitigation**

Pending state is written to a temporary file, synchronized, atomically renamed, and followed by parent-directory synchronization.

Persistence failures are classified as:

- failure before commit,
- durability uncertain after commit.

Memory rollback occurs only when the commit did not happen.

---

### 6.10 Duplicate Execution After Restart

**Threat**

The gateway crashes after an operation may have executed but before state cleanup completes.

Automatically retrying the request could repeat a destructive action.

**Mitigation**

Claimed requests surviving a restart are not automatically re-executed.

They require operator reconciliation.

`ACK_CLAIMED` records a reconciliation audit event and consumes the claimed state without executing the original operation.

---

### 6.11 SSRF

**Threat**

An agent attempts to use outbound HTTP capabilities to reach internal or sensitive services.

**Mitigation**

The gateway:

- permits HTTPS only,
- rejects embedded credentials,
- rejects IP literals,
- rejects localhost,
- limits ports,
- validates DNS resolutions,
- rejects unsafe IPv4 and IPv6 ranges,
- disables redirects,
- disables proxy inheritance,
- restricts requests to approved hosts.

---

### 6.12 DNS Rebinding

**Threat**

A hostname initially resolves to a public IP but later resolves to an unsafe internal address.

**Mitigation**

Resolved outbound addresses are security-validated before execution.

Unsafe loopback, private, link-local, multicast, unspecified, shared-address-space and other restricted destinations are rejected.

---

### 6.13 HTTP Resource Exhaustion

**Threat**

An attacker causes extremely large requests, responses, or long network waits.

**Mitigation**

The gateway enforces maximum configuration values for:

- HTTP timeout,
- request body size,
- response body size.

Response bodies are bounded and may be truncated.

---

### 6.14 Cargo-Test Resource Exhaustion

**Threat**

A reviewed Cargo test produces unlimited output or runs indefinitely.

**Mitigation**

Cargo execution has bounded:

- execution timeout,
- stdout capture,
- stderr capture.

Timeout handling terminates the spawned process group.

---

### 6.15 Wasm Infinite Loop

**Threat**

Sandboxed Wasm executes indefinitely.

**Mitigation**

Wasmtime fuel consumption is enabled and bounded.

Epoch interruption provides an independent execution-time limit.

---

### 6.16 Wasm Memory Exhaustion

**Threat**

Sandboxed Wasm attempts excessive memory growth.

**Mitigation**

Wasmtime `StoreLimits` enforce a configured memory ceiling.

Growth beyond the limit traps.

Gateway configuration also places an upper bound on the configurable sandbox memory limit.

---

### 6.17 Administrative Socket Access

**Threat**

Another local user attempts to approve or reject agent requests.

**Mitigation**

The Unix-domain admin socket is created with owner-only permissions.

Additionally, every accepted connection is checked using OS peer credentials.

The peer UID must match the gateway process's effective UID.

---

### 6.18 Admin Socket Path Replacement

**Threat**

An attacker replaces the socket path while the gateway is running so cleanup removes an unrelated object.

**Mitigation**

The socket guard records filesystem identity.

Cleanup removes the path only when the current object is still the same owned Unix socket.

---

### 6.19 Oversized Administrative Commands

**Threat**

A local client sends extremely large administrative input.

**Mitigation**

Administrative input is read through a bounded reader.

Commands exceeding the configured maximum are rejected before request state is consumed.

---

### 6.20 Invalid Administrative Commands

**Threat**

Malformed commands, unexpected parameters, or invalid request identifiers attempt to manipulate state.

**Mitigation**

The admin command parser validates:

- command name,
- argument count,
- UUID format,
- unexpected trailing input.

Unknown pending requests are rejected.

---

## 7. Security-Sensitive Execution Ordering

For reviewed operations, ordering is important.

A simplified approval flow is:

```text
Pending request
      |
      v
Inspect request
      |
      v
Revalidate security state
      |
      v
Claim request
      |
      v
Persist pre-execution audit
      |
      v
Execute operation
      |
      v
Persist completion audit
      |
      v
Consume claimed state
```

If pre-execution auditing fails, execution does not proceed.

If execution begins, the gateway preserves enough state to avoid unsafe automatic replay.

---

## 8. Fail-Closed Conditions

The gateway intentionally refuses to continue when critical security assumptions cannot be verified.

Examples include:

- invalid operational-state paths,
- changed operational parent identity,
- symlinked state files,
- malformed persisted state,
- invalid policy configuration,
- unsafe HTTP destinations,
- failed approval revalidation,
- inaccessible audit storage,
- failed admin peer authentication,
- unsupported reconciliation state.

---

## 9. Explicit Non-Goals

The current gateway is not intended to provide:

- operating-system kernel isolation equivalent to a virtual machine,
- protection from a fully compromised gateway process,
- protection from the same privileged operating-system account deliberately modifying its own files,
- distributed multi-host consensus,
- cryptographic audit-log signing,
- hardware-backed key protection,
- protection from malicious kernel or hypervisor behavior.

The gateway currently focuses on policy enforcement, execution mediation, filesystem isolation, durable state, network restrictions, sandbox resource controls, and human approval workflows.

---

## 10. Residual Risks

Despite the implemented controls, some risk remains.

### 10.1 Same-User Local Compromise

A malicious process running under the same OS user may have broader access to the user's environment.

Unix peer UID verification distinguishes different users but not necessarily different processes owned by the same user.

### 10.2 Audit Tampering by Privileged Actors

Audit logs have filesystem protections and anchored access, but they are not yet cryptographically tamper-evident.

Hash chaining or signing could be introduced in a future release.

### 10.3 Denial of Service

Resource limits reduce denial-of-service risk but cannot completely prevent resource pressure on the host system.

### 10.4 Application-Level HTTP Risk

Destination validation prevents many SSRF classes, but an approved external service may still return malicious or misleading application data.

### 10.5 Human Approval Error

Human review reduces automated risk but cannot guarantee that every approved action is safe.

The gateway therefore revalidates technical security conditions even after human approval.

---

## 11. Security Assumptions

The gateway assumes:

- the host operating system is trusted,
- Wasmtime behaves according to its documented security model,
- the configured workspace root is legitimate,
- operational-state directories are controlled by the gateway owner,
- the gateway binary itself has not been maliciously modified,
- system calls used for filesystem and peer-credential verification behave correctly,
- administrators understand that approval authorizes an actual side effect.

---

## 12. Verification

The gateway maintains an automated regression suite covering security-sensitive behavior.

At the current release-candidate checkpoint:

**291 automated tests pass.**

Coverage includes areas such as:

- policy decisions,
- approval workflows,
- filesystem traversal,
- symlink rejection,
- atomic writes,
- write-target integrity,
- SSRF controls,
- DNS validation,
- HTTP body limits,
- Cargo execution limits,
- Wasm fuel exhaustion,
- Wasm memory limits,
- epoch interruption,
- pending-review durability,
- restart reconciliation,
- audit durability,
- audit concurrency,
- operational-state anchoring,
- admin socket ownership,
- admin input limits,
- peer UID verification.

---

## 13. Future Security Enhancements

Potential future improvements include:

- cryptographic audit hash chaining,
- signed audit checkpoints,
- stronger process-level admin authentication,
- configurable administrator identities,
- additional Wasm capabilities under explicit policy,
- external secret-management integration,
- formalized security event export,
- structured observability and metrics,
- additional fuzzing and property-based testing,
- platform-specific hardening beyond macOS/Linux.

---

## 14. Security Principle

The core security principle of the Zyguor Agent Execution Gateway is:

> An AI agent may request an action, but the gateway decides whether that action is allowed to happen.

Capability does not imply authority.

Execution requires policy, scope, validation, auditability, and, where necessary, explicit human approval.