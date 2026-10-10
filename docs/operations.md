# Zyguor Agent Execution Gateway — Operations Guide

## 1. Purpose

This guide explains how to deploy, start, operate, review, reconcile, and troubleshoot the Zyguor Agent Execution Gateway.

The gateway is security-sensitive infrastructure. Operational choices such as workspace location, state-file location, admin socket placement, file permissions, and restart handling directly affect security.

---

## 2. Pre-Deployment Checklist

Before starting the gateway, confirm:

- Rust build completed successfully.
- All automated tests pass.
- `cargo clippy --all-targets --all-features -- -D warnings` is clean.
- Gateway configuration has been reviewed.
- Workspace root exists.
- Pending-review state parent directory exists.
- Audit-log parent directory exists.
- Operational state is outside the workspace.
- Admin socket path does not already exist.
- Operational directories are owned by the gateway OS user.
- Untrusted users cannot modify operational-state directories.

---

## 3. Recommended Filesystem Layout

Example:

```text
/opt/zyguor/
    gateway-binary

/opt/agents/project/
    application workspace

/var/lib/zyguor/
    pending-reviews.json

/var/log/zyguor/
    audit.jsonl

/run/user/<uid>/
    zyguor-admin.sock
```

The exact layout depends on the operating system and deployment model.

The key requirement is separation between:

- agent workspace,
- pending-review state,
- audit state,
- admin control plane.

---

## 4. Environment Variables

The gateway requires:

```text
ZYGUOR_WORKSPACE_ROOT
ZYGUOR_ADMIN_SOCKET
ZYGUOR_PENDING_REVIEW_STATE_PATH
ZYGUOR_AUDIT_LOG_PATH
```

Optional:

```text
ZYGUOR_CONFIG_PATH
```

Example:

```bash
export ZYGUOR_WORKSPACE_ROOT="/opt/agents/project"
export ZYGUOR_ADMIN_SOCKET="/tmp/zyguor-admin.sock"
export ZYGUOR_PENDING_REVIEW_STATE_PATH="/var/lib/zyguor/pending-reviews.json"
export ZYGUOR_AUDIT_LOG_PATH="/var/log/zyguor/audit.jsonl"
export ZYGUOR_CONFIG_PATH="/etc/zyguor/gateway.toml"
```

---

## 5. Workspace Preparation

Create or identify the workspace that the agent is permitted to access.

Example:

```bash
mkdir -p /opt/agents/project
```

The gateway constrains filesystem capabilities to this workspace.

Do not store gateway operational state inside the workspace.

---

## 6. Pending Review State Directory

Create the operational state directory before startup.

Example:

```bash
mkdir -p /var/lib/zyguor
```

Recommended permissions should restrict access to the gateway owner.

Example conceptual permission model:

```text
owner: read/write/execute
group: none
other: none
```

The gateway validates the state path and anchors the parent directory during startup.

---

## 7. Audit Directory

Create the audit directory before startup.

Example:

```bash
mkdir -p /var/log/zyguor
```

The audit file itself may be created by the gateway.

The gateway enforces owner-only permissions on the audit file.

Parent-directory permissions remain an administrator responsibility.

---

## 8. Admin Socket Directory

The admin socket should be placed in a directory controlled by the gateway user.

Examples:

```text
/tmp/zyguor-admin.sock
```

or a dedicated runtime directory.

The gateway refuses to overwrite an existing socket path.

Before starting the gateway, verify that the configured path does not already exist unexpectedly.

---

## 9. Starting the Gateway

After configuring the environment:

```bash
cargo run
```

or execute the compiled binary directly.

Example:

```bash
./target/release/zyguor-agent-execution-gateway
```

Startup performs security validation before serving requests.

---

## 10. Startup Validation

During startup, the gateway verifies:

- required environment variables,
- gateway configuration,
- workspace initialization,
- operational-state paths,
- operational parent identity,
- pending-review state integrity,
- audit storage setup,
- admin socket creation.

Startup fails closed if critical validation fails.

---

## 11. Existing Pending Reviews

If the pending-review state file already exists, the gateway loads it at startup.

The final target:

- must not be a symlink,
- must be a regular file.

The parent directory identity must match the identity validated during startup.

Malformed or unsupported persisted state causes startup failure.

---

## 12. Claimed Requests After Restart

A claimed request means the gateway had already moved a reviewed operation into the execution lifecycle.

If claimed requests survive a restart, the gateway does not automatically retry them.

A security warning is emitted.

Example conceptual warning:

```text
SECURITY WARNING:
claimed review(s) survived restart and require operator reconciliation
```

This is intentional.

The gateway cannot safely assume whether the previous side effect occurred.

---

## 13. Why Claimed Requests Are Not Automatically Retried

Consider a reviewed write:

```text
approval
→ pre-execution audit
→ write begins
→ process crashes
```

After restart, the gateway may not know whether the write:

- never happened,
- partially happened,
- fully happened.

Automatically replaying the operation could create duplicate or destructive side effects.

Therefore claimed requests require operator reconciliation.

---

# 14. Admin Control Plane

The local admin interface supports three commands.

```text
APPROVE <request-id>
REJECT <request-id>
ACK_CLAIMED <request-id>
```

Commands are sent through the configured Unix-domain socket.

---

## 15. Admin Authentication

Admin socket security has two layers.

### Filesystem Permissions

The socket is created with owner-only permissions.

### Peer Credential Verification

The gateway verifies the UID of the connected Unix socket peer.

The peer UID must match the gateway process's effective UID.

Connections from another local user are rejected before command processing.

---

## 16. Approving a Request

Command:

```text
APPROVE <request-id>
```

Approval does not bypass security validation.

Before execution, the gateway revalidates relevant state.

Depending on the capability, this may include:

- write-target integrity,
- workspace fingerprint,
- HTTP destination policy,
- current configuration.

If revalidation fails, the operation does not execute.

---

## 17. Rejecting a Request

Command:

```text
REJECT <request-id>
```

The gateway removes the pending request through the durable review-state mechanism and records the rejection audit event.

A rejected request cannot later be approved using the same consumed pending state.

---

## 18. Acknowledging a Claimed Request

Command:

```text
ACK_CLAIMED <request-id>
```

This command is used for restart reconciliation.

It does not re-execute the original operation.

Flow:

```text
locate claimed request
→ write reconciliation audit
→ consume claimed state
→ return acknowledgement
```

Use this only after an operator has investigated the uncertain operation.

---

## 19. Reconciliation Procedure

When a claimed request survives restart:

1. Identify the request ID.
2. Review the audit log.
3. Inspect the actual system state.
4. Determine whether the original operation occurred.
5. Correct system state manually if necessary.
6. Use `ACK_CLAIMED` only when the uncertainty has been operationally resolved.

Do not treat `ACK_CLAIMED` as an execution retry.

---

## 20. Approval Failure

An approval may fail because:

- the pending request no longer exists,
- write target changed,
- workspace changed,
- HTTP destination is no longer permitted,
- audit persistence failed,
- state persistence failed,
- operation became otherwise invalid.

A failed approval should be investigated rather than blindly retried.

---

## 21. Audit Log Format

Audit records are stored as JSON Lines.

Each line represents one security-relevant event.

Fields include information such as:

```text
request_id
timestamp_unix
message
phase
decision
reason
execution_outcome
```

Audit phases include:

```text
Approval
Rejection
PreExecution
Completion
Reconciliation
```

---

## 22. Reading Audit Logs

A simple local inspection:

```bash
tail -n 50 /var/log/zyguor/audit.jsonl
```

Pretty-printing individual JSON records may be done using standard JSON tools.

Audit logs should be treated as security-sensitive operational data.

---

## 23. Audit Concurrency

Gateway execution and admin operations may both produce audit events.

The gateway serializes audit writes with a shared lock.

This prevents concurrent JSONL writes from corrupting record boundaries.

---

## 24. Audit File Permissions

Audit files are secured to owner-only mode by the gateway.

Administrators should periodically verify:

- ownership,
- parent-directory permissions,
- storage availability.

---

## 25. Audit Storage Failure

If the gateway cannot persist a required pre-execution audit event, the protected operation does not proceed.

This is fail-closed behavior.

Completion audit failure is handled differently because the operation may already have happened.

The gateway therefore preserves and reports the execution outcome rather than pretending the side effect never occurred.

---

## 26. Pending-State Persistence

Pending-review state uses an atomic temporary-file and rename strategy.

The high-level sequence is:

```text
serialize
→ create private temp file
→ write
→ fsync temp
→ rename
→ fsync parent directory
```

The rename is treated as the commit boundary.

---

## 27. Persistence Durability Messages

Persistence errors may indicate:

### Before Commit

The state replacement did not commit.

The gateway can safely preserve or restore prior in-memory state.

### Durability Uncertain

The replacement occurred, but final directory durability could not be confirmed.

Operators should treat the disk state as potentially committed.

---

## 28. HTTP Operations

HTTP GET may execute automatically when policy allows.

HTTP POST requires human review.

Outbound HTTP is restricted by:

- HTTPS-only policy,
- hostname allowlist,
- DNS validation,
- unsafe IP rejection,
- redirect disabling,
- proxy disabling,
- request/response limits.

---

## 29. HTTP Troubleshooting

If an HTTP request is rejected, check:

- host exists in `allowed_hosts`,
- URL uses HTTPS,
- URL has no embedded credentials,
- URL does not use an IP literal,
- hostname does not resolve to restricted addresses,
- configured request size is within limits,
- configured timeout is valid.

Do not weaken SSRF controls to resolve connectivity issues without understanding the security impact.

---

## 30. Cargo Test Operations

Cargo test execution requires review.

Before approval execution, the workspace is revalidated using a fingerprint.

If relevant Cargo inputs changed after review, execution is rejected.

---

## 31. Cargo Test Timeout

Cargo execution has a bounded timeout.

If exceeded, the gateway terminates the Cargo process group.

Captured stdout and stderr are also bounded.

This prevents runaway subprocess output or indefinitely running tests.

---

## 32. Wasm Sandbox Operations

Sandbox execution is protected by three independent mechanisms:

- fuel,
- memory limit,
- epoch timeout.

If any limit is exceeded, execution fails cleanly.

---

## 33. Wasm Fuel Failure

Fuel exhaustion indicates that execution consumed more Wasm instructions than permitted.

This should be treated as a resource-control event rather than a gateway crash.

---

## 34. Wasm Timeout

If execution exceeds the configured timeout, the timer advances the Wasmtime epoch.

The sandbox traps and returns a controlled failure.

---

## 35. Wasm Memory Failure

If Wasm attempts memory growth beyond the configured store limit, Wasmtime traps the operation.

The host process remains responsible for broader operating-system resource management.

---

# 36. Troubleshooting Startup Failures

## Workspace Configuration Missing

Possible message:

```text
ZYGUOR_WORKSPACE_ROOT must be configured
```

Action:

Set the required environment variable.

---

## Admin Socket Already Exists

Possible message:

```text
admin socket path already exists
```

Action:

Investigate the existing object.

Do not automatically delete it unless you are certain it is stale and belongs to the gateway.

---

## Operational State Inside Workspace

Possible message:

```text
pending review state file must be outside the agent workspace
```

or equivalent audit error.

Action:

Move operational state to a dedicated directory outside the agent workspace.

---

## Parent Identity Changed

Possible message:

```text
parent directory changed after validation
```

Action:

Treat this as a security-sensitive startup failure.

Investigate whether the operational directory was replaced, remounted, renamed, or modified during startup.

---

## Symlink State File

Possible message:

```text
pending review state file must not be a symbolic link
```

Action:

Replace the symlink-based configuration with a direct regular-file target in the validated operational directory.

---

## Invalid Configuration

Possible message:

```text
failed to resolve gateway configuration
```

Action:

Review:

- TOML syntax,
- unknown fields,
- policy constraints,
- zero numeric values,
- values above hard maximums.

---

# 37. Admin Command Troubleshooting

## Invalid Request ID

The request ID must be a valid UUID.

---

## Unknown Request

Possible message:

```text
pending review request not found
```

The request may have already been:

- consumed,
- rejected,
- executed,
- reconciled.

---

## Oversized Command

Admin commands longer than the configured maximum are rejected before review state is consumed.

This protects the control plane from unbounded input.

---

## Peer Authentication Failure

Possible message:

```text
admin connection rejected: peer user does not match gateway owner
```

Ensure the admin client is running under the same operating-system user as the gateway process.

---

# 38. Shutdown

The gateway owns its admin socket while running.

The socket guard removes the path only when the filesystem object still matches the socket created by the gateway.

If the socket path was replaced, the replacement object is left untouched.

---

# 39. Restart Procedure

Recommended restart workflow:

1. Stop the gateway cleanly when possible.
2. Preserve pending-review state.
3. Preserve audit logs.
4. Restart using the same trusted operational directories.
5. Observe startup warnings.
6. Investigate any surviving claimed requests.
7. Reconcile them before continuing high-impact operations.

---

# 40. Backup

Operational backups may include:

- pending-review state,
- audit logs,
- gateway configuration.

Backups should preserve confidentiality and integrity.

Do not place backups inside the agent workspace.

---

# 41. Audit Rotation

The current gateway writes to the configured audit file.

If external rotation is used:

- coordinate rotation with gateway operation,
- preserve file ownership and permissions,
- avoid replacing trusted parent directories,
- test rotation procedures before production use.

Future versions may provide first-class rotation support.

---

# 42. Monitoring Recommendations

Operators should monitor for:

- repeated blocked operations,
- repeated approval failures,
- SSRF validation failures,
- unexpected admin connection failures,
- surviving claimed requests,
- audit persistence failures,
- state durability warnings,
- repeated Wasm resource-limit failures,
- repeated Cargo timeouts.

---

# 43. Incident Response

If suspicious behavior is detected:

1. Stop accepting new sensitive approvals.
2. Preserve audit logs.
3. Preserve pending-review state.
4. Record relevant request IDs.
5. Inspect workspace changes.
6. Review outbound HTTP activity.
7. Review claimed requests.
8. Investigate local admin socket access.
9. Restart only after trust in operational state is restored.

---

# 44. Secure Upgrade Procedure

Before upgrading:

1. Commit or preserve source changes.
2. Run the complete test suite.
3. Run Clippy with warnings denied.
4. Preserve operational state.
5. Preserve audit logs.
6. Review configuration compatibility.
7. Build the new version.
8. Restart.
9. Inspect startup reconciliation warnings.

---

# 45. Current Release-Candidate Verification

At the current release-candidate checkpoint:

```text
291 automated tests passed
0 failed
```

The release-hardening suite also passes:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
git diff --check
```

---

# 46. Operational Security Principle

The gateway should be operated with the assumption that agent requests can be unsafe even when they appear reasonable.

Human approval should be deliberate.

Operational-state warnings should be investigated.

Security validation should not be bypassed merely to make an operation succeed.