# Zyguor Agent Execution Gateway

A policy-controlled execution gateway for AI agents, built in Rust.

The Zyguor Agent Execution Gateway sits between an AI agent and sensitive execution capabilities. Instead of allowing an agent to directly perform filesystem, network, build, or other side-effecting actions, the gateway evaluates each request against policy and security controls first.

The core model is:

```text
AI Agent
   |
   v
Execution Request
   |
   v
+---------------------------+
| Zyguor Agent Execution    |
| Gateway                   |
+---------------------------+
   |
   +--> ALLOW  ------> Validate ------> Execute
   |
   +--> REVIEW ------> Human approval
   |                       |
   |                       v
   |                  Revalidate
   |                       |
   |                       v
   |                    Execute
   |
   +--> BLOCK  ------> Reject
```

The gateway follows a fail-closed model and is designed around one principle:

> An AI agent may request an action, but the gateway decides whether that action is allowed to happen.

---

## Why This Exists

AI agents are increasingly capable of interacting with:

- local files,
- source-code repositories,
- APIs,
- build systems,
- automation workflows,
- external services.

Capability alone should not imply authority.

An agent that can generate an action should not automatically have permission to execute that action.

The Zyguor Agent Execution Gateway introduces a security boundary between agent intent and real-world execution.

---

## Core Security Model

Every supported operation is classified as one of:

| Decision | Meaning |
|---|---|
| **Allow** | Operation may execute after validation |
| **Review** | Operation requires explicit human approval |
| **Block** | Operation must not execute |

Sensitive operations cannot silently bypass mandatory review through configuration.

---

## Supported Capabilities

Current capability categories include:

- arithmetic execution,
- file reads,
- file writes,
- Git status inspection,
- Cargo test execution,
- HTTP GET,
- HTTP POST,
- Wasm sandbox execution.

The gateway uses structured capabilities rather than exposing unrestricted shell execution as its default execution model.

---

# Security Features

## Human Approval for High-Impact Actions

Operations with persistent or external side effects require review.

Current mandatory-review operations include:

```text
write_file
run_cargo_test
http_post
```

They may be configured as:

```text
review
block
```

but not unrestricted `allow`.

---

## Approval-Time Revalidation

Human approval does not disable technical security checks.

Before an approved operation executes, the gateway revalidates relevant state.

Examples include:

- file-write target state,
- Cargo workspace state,
- HTTP destination security.

This protects against changes occurring between review and execution.

---

## Write-Target Integrity

For reviewed file writes, the gateway records the target state during review.

The state distinguishes between:

- a missing file,
- an existing file with a recorded content hash.

Before execution, the target is checked again.

Approval fails if the target was unexpectedly:

- created,
- deleted,
- changed,
- replaced.

---

## Filesystem Containment

Filesystem access is restricted to the configured agent workspace.

Controls include:

- absolute-path rejection,
- parent traversal rejection,
- symlink-parent rejection,
- final symlink rejection,
- regular-file validation,
- anchored filesystem operations.

The gateway is designed to prevent an agent from escaping its permitted workspace through pathname manipulation.

---

## TOCTOU and Symlink Hardening

Security-sensitive filesystem operations do not rely solely on pathname validation.

Where appropriate, the gateway uses opened directory handles and file-descriptor-relative operations such as:

```text
openat
renameat
unlinkat
```

This reduces exposure to time-of-check/time-of-use path replacement attacks.

---

## Operational-State Isolation

Gateway operational state must remain outside the agent workspace.

This includes:

- pending-review state,
- audit logs.

At startup, the gateway validates and records operational parent-directory identity.

It then retains trusted directory file descriptors for subsequent operations.

Replacing a parent pathname after startup therefore does not redirect the gateway's trusted operational-state writes.

---

# Durable Human Review

## Pending Reviews

Operations requiring approval are persisted in durable pending-review state.

A request can exist as:

```text
Pending
Claimed
```

A request becomes `Claimed` before an approved side effect enters execution.

---

## Crash-Safe Persistence

Pending state uses an atomic persistence model:

```text
serialize
   |
   v
create private temporary file
   |
   v
write
   |
   v
fsync
   |
   v
atomic rename
   |
   v
fsync parent directory
```

Persistence failures are distinguished between:

- failure before commit,
- durability uncertainty after commit.

This prevents in-memory state from being incorrectly rolled backward after a disk commit may already have occurred.

---

## Restart-Safe Claimed Requests

If the gateway crashes while an approved operation is claimed, the gateway does **not** automatically execute that request again after restart.

That would risk duplicate side effects.

Instead, surviving claimed requests require operator reconciliation.

---

## Reconciliation

The administrative command:

```text
ACK_CLAIMED <request-id>
```

acknowledges an uncertain claimed request after operator investigation.

It does **not** replay the original operation.

The reconciliation audit record is persisted before the claimed state is consumed.

---

# Audit Architecture

Security-sensitive activity is recorded as JSON Lines.

Audit records cover phases such as:

- approval,
- rejection,
- pre-execution,
- completion,
- reconciliation.

Execution outcomes distinguish conditions such as:

- success,
- failure,
- not executed,
- unknown.

---

## Audit-Before-Execution

For reviewed operations, required pre-execution auditing occurs before the protected side effect.

If that audit cannot be persisted:

```text
the operation does not execute
```

This is a core fail-closed property.

---

## Audit Durability

Audit storage includes:

- owner-only file permissions,
- no-follow file opening,
- regular-file validation,
- anchored parent directory access,
- file synchronization,
- parent-directory synchronization for newly created files.

Concurrent audit writers are serialized using a shared lock so JSONL records do not interleave.

---

# HTTP Security

Outbound HTTP is constrained to reduce SSRF and destination-redirection risk.

Controls include:

- HTTPS only,
- hostname allowlist,
- rejection of embedded URL credentials,
- rejection of IP literals,
- rejection of localhost,
- restricted port behavior,
- DNS resolution validation,
- unsafe-address filtering,
- redirects disabled,
- proxy inheritance disabled,
- bounded request bodies,
- bounded response bodies,
- bounded timeouts.

---

## DNS and SSRF Protection

Resolved addresses are checked before use.

Restricted address classes include relevant:

- loopback,
- private,
- link-local,
- multicast,
- unspecified,
- shared address space,
- other unsafe destination ranges.

An allowlisted hostname therefore does not automatically imply that every address it resolves to is trusted.

---

# Wasm Sandbox

Sandboxed execution uses Wasmtime.

Production sandbox execution enables three independent resource controls:

```text
Fuel
Memory limit
Epoch timeout
```

---

## Fuel

Execution receives a configured fuel budget.

When the budget is exhausted, Wasmtime traps execution.

---

## Memory

Wasmtime store limits enforce a configured memory ceiling.

Memory growth beyond the limit traps.

---

## Timeout

Epoch interruption provides an independent execution deadline.

If execution exceeds the configured time, the gateway advances the Wasmtime epoch and execution traps.

---

# Cargo Test Execution

Cargo test execution is review-gated.

Before approved execution, the gateway revalidates the workspace state.

Resource controls include:

- execution timeout,
- bounded stdout,
- bounded stderr,
- process-group termination on timeout.

This prevents indefinite or unbounded reviewed build execution.

---

# Admin Control Plane

Human-review operations are controlled through a local Unix-domain admin socket.

Supported commands are:

```text
APPROVE <request-id>
REJECT <request-id>
ACK_CLAIMED <request-id>
```

---

## Admin Socket Security

The admin control plane uses multiple protections:

- owner-only socket permissions,
- refusal to overwrite an existing socket path,
- bounded command length,
- strict command parsing,
- UUID validation,
- socket filesystem identity tracking,
- operating-system peer credential verification.

The UID of an accepted peer must match the gateway process's effective UID.

---

# Configuration Safety

Resource settings are bounded by hard maximum values.

Current limits include:

| Setting | Default | Hard Maximum |
|---|---:|---:|
| HTTP timeout | 10 s | 60 s |
| HTTP request body | 64 KiB | 1 MiB |
| HTTP response body | 256 KiB | 4 MiB |
| Cargo timeout | 60 s | 600 s |
| Cargo stdout | 64 KiB | 1 MiB |
| Cargo stderr | 64 KiB | 1 MiB |
| Wasm fuel | 10,000 | 10,000,000 |
| Wasm memory | 2 MiB | 64 MiB |
| Wasm timeout | 250 ms | 5 s |

Zero-valued resource settings and values above the hard maximums are rejected.

Unknown TOML configuration fields are also rejected.

See:

```text
docs/configuration.md
```

for the full configuration reference.

---

# Trust Boundaries

The architecture contains several explicit trust boundaries.

```text
Untrusted AI Agent
        |
        v
+----------------------+
| Request Validation   |
+----------------------+
        |
        v
+----------------------+
| Policy Engine        |
+----------------------+
        |
   +----+----+
   |         |
 Allow     Review
   |         |
   |         v
   |    Human Admin
   |         |
   +----+----+
        |
        v
+----------------------+
| Security Validation  |
+----------------------+
        |
        v
+----------------------+
| Execution Capability |
+----------------------+
        |
        v
+----------------------+
| Durable Audit        |
+----------------------+
```

The AI agent itself is treated as untrusted input.

---

# Fail-Closed Behavior

The gateway refuses to continue when critical security assumptions cannot be established.

Examples include:

- invalid configuration,
- unsafe operational-state paths,
- changed operational parent identity,
- malformed persisted state,
- symlinked operational files,
- unsafe HTTP destinations,
- failed approval revalidation,
- required audit persistence failure,
- failed admin peer authentication.

---

# Building

Requirements:

- Rust toolchain compatible with the project,
- Cargo,
- supported Unix environment for the current admin control-plane implementation.

Build:

```bash
cargo build
```

Optimized build:

```bash
cargo build --release
```

---

# Quality Gates

Before release:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
git diff --check
```

Current release-candidate test baseline:

```text
291 passed
0 failed
```

---

# Documentation

Detailed documentation is available under `docs/`.

### Threat Model

```text
docs/threat-model.md
```

Documents:

- protected assets,
- threat actors,
- trust boundaries,
- mitigations,
- residual risks,
- security assumptions.

### Security Architecture

```text
docs/security-architecture.md
```

Documents the internal security design and execution lifecycle.

### Configuration Reference

```text
docs/configuration.md
```

Documents policy options, defaults, resource bounds, and operational paths.

### Operations Guide

```text
docs/operations.md
```

Covers deployment, restart handling, reconciliation, troubleshooting, audit handling, and admin operation.

### Release Checklist

```text
docs/release-checklist.md
```

Defines the engineering and security gates required before publishing a release.

---

# Current Status

The project is currently at a **release-candidate hardening stage**.

The current engineering baseline includes:

- 291 passing automated tests,
- clean formatting checks,
- clean Clippy with warnings denied,
- operational-state path anchoring,
- durable approval state,
- restart-safe reconciliation,
- audit durability,
- filesystem containment,
- approval-time state revalidation,
- outbound HTTP/SSRF controls,
- Wasm resource controls,
- bounded configuration,
- authenticated local admin control plane.

A public release should only be tagged after the final release checklist and release-binary smoke test are completed.

---

# Known Limitations

The current design intentionally does not claim protection against every host compromise scenario.

Current limitations include:

- processes running under the same OS user remain within the same broad local trust domain,
- audit logs are not yet cryptographically signed or hash-chained,
- Wasm isolation is not equivalent to hardware virtualization,
- human approval can still contain judgment error,
- host-level denial-of-service cannot be eliminated entirely,
- a compromised operating-system kernel is outside the security boundary,
- a deliberately compromised gateway process is outside the security boundary.

These limitations are documented explicitly rather than hidden behind broad security claims.

---

# Security Philosophy

The Zyguor Agent Execution Gateway is based on five principles:

```text
Policy before execution
Validation before trust
Audit before sensitive side effects
Human approval where authority is required
Fail closed when security state is uncertain
```

AI systems can generate actions at machine speed.

Execution authority should still remain controlled, bounded, reviewable, and auditable.

---

## Zyguor

**Secure. Smart. Scalable.**

The Agent Execution Gateway is part of Zyguor's work toward safer infrastructure for AI agents and agentic systems.