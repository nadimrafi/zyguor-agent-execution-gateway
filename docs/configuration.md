# Zyguor Agent Execution Gateway — Configuration Reference

## 1. Overview

The Zyguor Agent Execution Gateway is configured through environment variables and an optional TOML configuration file.

Configuration is intentionally restrictive.

Unknown TOML fields are rejected, sensitive policies cannot be weakened beyond supported security rules, and numeric resource settings are subject to both minimum and maximum bounds.

The gateway fails closed when configuration is invalid.

---

## 2. Required Environment Variables

### `ZYGUOR_WORKSPACE_ROOT`

Absolute or resolvable path to the workspace the gateway is allowed to operate within.

Example:

```text
ZYGUOR_WORKSPACE_ROOT=/Users/example/projects/my-agent-workspace
```

Agent filesystem capabilities are constrained to this workspace.

Operational gateway state must not be stored inside this directory.

---

### `ZYGUOR_ADMIN_SOCKET`

Path to the local Unix-domain administrative socket.

Example:

```text
ZYGUOR_ADMIN_SOCKET=/tmp/zyguor-admin.sock
```

The admin socket is used for commands such as:

```text
APPROVE <request-id>
REJECT <request-id>
ACK_CLAIMED <request-id>
```

The socket is created with owner-only permissions.

The gateway also verifies the UID of connecting peers.

---

### `ZYGUOR_PENDING_REVIEW_STATE_PATH`

Absolute path to the durable pending-review state file.

Example:

```text
ZYGUOR_PENDING_REVIEW_STATE_PATH=/var/lib/zyguor/pending-reviews.json
```

Requirements:

- must be an absolute path,
- must have an existing parent directory,
- must reside outside the agent workspace,
- final target must not be a symlink,
- existing target must be a regular file.

The parent directory identity is verified and anchored at startup.

---

### `ZYGUOR_AUDIT_LOG_PATH`

Absolute path to the audit JSONL file.

Example:

```text
ZYGUOR_AUDIT_LOG_PATH=/var/log/zyguor/audit.jsonl
```

Requirements:

- must be an absolute path,
- must have an existing parent directory,
- must reside outside the agent workspace,
- final target must not be a symlink,
- existing target must be a regular file.

The audit parent directory is verified and anchored at startup.

---

## 3. Optional Environment Variable

### `ZYGUOR_CONFIG_PATH`

Optional path to the TOML gateway configuration file.

Example:

```text
ZYGUOR_CONFIG_PATH=/etc/zyguor/gateway.toml
```

If omitted, built-in safe defaults are used.

If provided, the configuration file must parse successfully and pass all validation rules before the gateway starts.

---

## 4. Configuration File Structure

A configuration file may contain these sections:

```toml
[http]

[policy]

[cargo_test]

[sandbox]
```

Unknown configuration fields are rejected.

This helps prevent misspelled or unsupported options from being silently ignored.

---

# 5. HTTP Configuration

Example:

```toml
[http]
allowed_hosts = ["api.example.com"]
timeout_seconds = 10
max_request_body_bytes = 65536
max_response_body_bytes = 262144
```

---

## `allowed_hosts`

Type:

```text
array of strings
```

Default:

```text
["api.example.com"]
```

An empty allowlist is valid and effectively disables outbound HTTP access.

Each entry must be a hostname.

The gateway rejects:

- empty hostnames,
- IP literals,
- localhost,
- malformed hosts,
- duplicate hosts ignoring case,
- full URLs where only a hostname is expected.

Examples of valid entries:

```toml
allowed_hosts = [
    "api.example.com",
    "service.example.org"
]
```

Invalid examples:

```text
127.0.0.1
localhost
https://api.example.com
```

---

## `timeout_seconds`

Default:

```text
10 seconds
```

Valid range:

```text
1–60 seconds
```

Hard maximum:

```text
60 seconds
```

Values above the hard maximum are rejected.

---

## `max_request_body_bytes`

Default:

```text
65,536 bytes
64 KiB
```

Valid range:

```text
1–1,048,576 bytes
```

Hard maximum:

```text
1 MiB
```

This bounds outbound HTTP request bodies.

---

## `max_response_body_bytes`

Default:

```text
262,144 bytes
256 KiB
```

Valid range:

```text
1–4,194,304 bytes
```

Hard maximum:

```text
4 MiB
```

HTTP responses exceeding the configured limit are bounded or truncated according to execution behavior.

---

# 6. Policy Configuration

Example:

```toml
[policy]
add = "allow"
read_file = "allow"
write_file = "review"
git_status = "allow"
run_cargo_test = "review"
http_get = "allow"
http_post = "review"
```

Supported policy values are:

```text
allow
review
block
```

Values are parsed case-insensitively after trimming whitespace.

---

## Default Policy

| Capability | Default |
|---|---|
| add | Allow |
| read_file | Allow |
| write_file | Review |
| git_status | Allow |
| run_cargo_test | Review |
| http_get | Allow |
| http_post | Review |

---

## Mandatory Review Rules

The following capabilities cannot be configured as `allow`:

```text
write_file
run_cargo_test
http_post
```

These operations require human review because they can create external or persistent side effects.

Valid values for these capabilities are therefore:

```text
review
block
```

---

## Unsupported Review Rules

The following capabilities cannot be configured as `review` because the gateway does not provide a reviewed execution path for them:

```text
add
read_file
git_status
http_get
```

These capabilities must be either:

```text
allow
block
```

---

# 7. Cargo Test Configuration

Example:

```toml
[cargo_test]
timeout_seconds = 60
max_stdout_bytes = 65536
max_stderr_bytes = 65536
```

Cargo test execution requires human approval.

---

## `timeout_seconds`

Default:

```text
60 seconds
```

Valid range:

```text
1–600 seconds
```

Hard maximum:

```text
600 seconds
10 minutes
```

The gateway terminates timed-out Cargo execution, including the associated process group.

---

## `max_stdout_bytes`

Default:

```text
65,536 bytes
64 KiB
```

Valid range:

```text
1–1,048,576 bytes
```

Hard maximum:

```text
1 MiB
```

This prevents unlimited stdout capture.

---

## `max_stderr_bytes`

Default:

```text
65,536 bytes
64 KiB
```

Valid range:

```text
1–1,048,576 bytes
```

Hard maximum:

```text
1 MiB
```

This prevents unlimited stderr capture.

---

# 8. Wasm Sandbox Configuration

Example:

```toml
[sandbox]
fuel_limit = 10000
memory_limit_bytes = 2097152
timeout_milliseconds = 250
```

---

## `fuel_limit`

Default:

```text
10,000
```

Valid range:

```text
1–10,000,000
```

Hard maximum:

```text
10,000,000
```

Wasmtime fuel consumption is enabled.

Execution traps when configured fuel is exhausted.

---

## `memory_limit_bytes`

Default:

```text
2,097,152 bytes
2 MiB
```

Valid range:

```text
1–67,108,864 bytes
```

Hard maximum:

```text
64 MiB
```

Wasmtime store limits enforce this maximum.

Memory growth beyond the configured limit traps.

---

## `timeout_milliseconds`

Default:

```text
250 milliseconds
```

Valid range:

```text
1–5,000 milliseconds
```

Hard maximum:

```text
5 seconds
```

The timeout is enforced independently through Wasmtime epoch interruption.

---

# 9. Default Configuration Summary

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
| Wasm timeout | 250 ms | 5,000 ms |

---

# 10. Example Secure Configuration

```toml
[http]
allowed_hosts = [
    "api.example.com"
]
timeout_seconds = 10
max_request_body_bytes = 65536
max_response_body_bytes = 262144

[policy]
add = "allow"
read_file = "allow"
write_file = "review"
git_status = "allow"
run_cargo_test = "review"
http_get = "allow"
http_post = "review"

[cargo_test]
timeout_seconds = 60
max_stdout_bytes = 65536
max_stderr_bytes = 65536

[sandbox]
fuel_limit = 10000
memory_limit_bytes = 2097152
timeout_milliseconds = 250
```

This configuration closely matches the built-in defaults.

---

# 11. Example Restrictive Configuration

The gateway can be configured to disable network writes and filesystem writes while still permitting safe read-style operations.

```toml
[http]
allowed_hosts = []

[policy]
add = "allow"
read_file = "allow"
write_file = "block"
git_status = "allow"
run_cargo_test = "block"
http_get = "block"
http_post = "block"
```

This can be useful for environments where the gateway should operate primarily as an inspection or analysis tool.

---

# 12. Invalid Configuration Examples

## Zero Timeout

```toml
[http]
timeout_seconds = 0
```

Rejected because timeouts must be greater than zero.

---

## Excessive HTTP Timeout

```toml
[http]
timeout_seconds = 120
```

Rejected because the hard maximum is 60 seconds.

---

## Excessive Wasm Memory

```toml
[sandbox]
memory_limit_bytes = 134217728
```

Rejected because the hard maximum is 64 MiB.

---

## Bypassing Required Review

```toml
[policy]
write_file = "allow"
```

Rejected because file writes require human review.

---

## Unsupported Review Policy

```toml
[policy]
http_get = "review"
```

Rejected because reviewed HTTP GET execution is not supported.

---

## Unknown Field

```toml
[http]
timeout_seconds = 10
disable_security = true
```

Rejected because unknown configuration fields are denied.

---

# 13. Operational State Separation

The following files are not normal application workspace files:

- pending-review state,
- audit logs.

They must be stored outside `ZYGUOR_WORKSPACE_ROOT`.

Recommended conceptual layout:

```text
agent workspace
/opt/agents/project/

gateway operational state
/var/lib/zyguor/
    pending-reviews.json

gateway audit
/var/log/zyguor/
    audit.jsonl
```

The exact directories depend on deployment environment and operating-system permissions.

---

# 14. File Permissions

Operational state should be accessible only to the OS account running the gateway.

Audit files are secured to owner-only permissions by the gateway.

Administrators should also ensure parent directories are not writable by untrusted users.

---

# 15. Admin Socket Placement

The admin Unix socket should be placed in a directory controlled by the gateway owner.

Example:

```text
/tmp/zyguor-admin.sock
```

or a dedicated runtime directory.

The gateway:

- refuses to overwrite an existing path,
- creates the socket with owner-only permissions,
- verifies connecting peer UID,
- guards socket cleanup by filesystem identity.

---

# 16. Configuration Changes and Pending Reviews

Changing gateway configuration does not automatically grant previously reviewed requests permission to execute.

When a pending operation is approved, relevant security conditions are revalidated against the current runtime configuration and state.

This is particularly important for:

- HTTP destinations,
- workspace state,
- write targets,
- Cargo execution.

---

# 17. Recommended Production Practice

For production-style deployment:

1. Use the built-in defaults unless a larger limit is genuinely required.
2. Keep HTTP allowlists minimal.
3. Prefer `block` over `allow` for unused capabilities.
4. Keep review-required capabilities as `review` or `block`.
5. Store operational state outside the agent workspace.
6. Restrict operational parent-directory permissions.
7. Protect the admin socket directory.
8. Review audit logs regularly.
9. Investigate surviving claimed requests before using `ACK_CLAIMED`.
10. Treat configuration changes as security-sensitive changes.

---

# 18. Security Principle

Configuration may make the gateway more restrictive.

It must not be able to silently disable core security invariants.

For that reason, certain review requirements and hard resource ceilings are enforced directly by the gateway rather than being optional configuration choices.