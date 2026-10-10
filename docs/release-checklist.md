# Zyguor Agent Execution Gateway — Release Checklist

## 1. Purpose

This checklist defines the minimum verification required before publishing a Zyguor Agent Execution Gateway release.

The goal is to ensure that code quality, security controls, operational safety, documentation, and repository state have all been reviewed before a release is considered ready.

---

# 2. Source Control

Confirm the repository is in the expected state.

```bash id="qmhszk"
git status --short
```

Expected:

```text id="22mkfx"
no unexpected modified or untracked files
```

Confirm the current branch:

```bash id="8d63xq"
git branch --show-current
```

Confirm recent commits:

```bash id="qvd8r5"
git log --oneline -5
```

Confirm the local branch is synchronized with the intended remote branch.

---

# 3. Formatting

Run:

```bash id="bub3df"
cargo fmt --check
```

Release requirement:

```text id="wi0lfy"
PASS
```

There must be no unformatted Rust source files.

---

# 4. Automated Test Suite

Run:

```bash id="js63gb"
cargo test
```

Current release-candidate baseline:

```text id="qgx3sw"
291 passed
0 failed
```

Any test failure blocks release.

---

# 5. Clippy

Run:

```bash id="mb7p31"
cargo clippy --all-targets --all-features -- -D warnings
```

Release requirement:

```text id="aq8wvh"
0 warnings
0 errors
```

Warnings are treated as release-blocking failures.

---

# 6. Diff Integrity

Run:

```bash id="wxoxaw"
git diff --check
```

Expected:

```text id="8oh0wa"
no output
```

This confirms that the working diff contains no whitespace errors.

If reviewing staged release changes, also run:

```bash id="vdmz7j"
git diff --cached --check
```

---

# 7. Configuration Validation

Verify the release retains hard upper bounds for:

- HTTP timeout,
- HTTP request body,
- HTTP response body,
- Cargo timeout,
- Cargo stdout,
- Cargo stderr,
- Wasm fuel,
- Wasm memory,
- Wasm timeout.

Verify values above the maximum are rejected.

Verify zero-valued resource settings are rejected.

---

# 8. Policy Validation

Verify the following capabilities cannot bypass mandatory review:

```text id="pxz1t3"
write_file
run_cargo_test
http_post
```

They must remain limited to:

```text id="qzz1wl"
review
block
```

Verify unsupported review policies remain rejected for operations without a reviewed execution path.

---

# 9. Filesystem Security

Confirm regression coverage exists for:

- workspace traversal rejection,
- absolute-path rejection,
- symlink-parent rejection,
- final symlink rejection,
- regular-file validation,
- anchored filesystem access,
- write-target integrity,
- changed write target after approval,
- secure read handling.

Any regression in workspace containment blocks release.

---

# 10. Operational State Security

Verify:

- pending-review state resides outside the agent workspace,
- audit state resides outside the agent workspace,
- final state targets cannot be symlinks,
- existing state targets must be regular files,
- validated parent device/inode identity is checked,
- trusted parent directory file descriptors are retained.

---

# 11. Pending Review Durability

Verify pending-review persistence still uses:

```text id="7c3qpd"
temporary file
→ write
→ fsync
→ atomic rename
→ parent-directory fsync
```

Verify persistence errors remain classified into:

```text id="9k5ars"
BeforeCommit
AfterCommit / DurabilityUncertain
```

Before-commit failures must not leave memory incorrectly advanced.

Post-commit uncertainty must not incorrectly roll memory backward.

---

# 12. Claimed Review Safety

Verify claimed requests survive restart without automatic replay.

A claimed request after restart must require operator reconciliation.

The gateway must not automatically re-execute an uncertain operation.

---

# 13. ACK_CLAIMED Safety

Verify:

```text id="oa87r9"
ACK_CLAIMED
```

does not execute the original operation.

Required order:

```text id="t82jmy"
locate claimed request
→ persist reconciliation audit
→ consume claimed state
```

If reconciliation auditing fails, claimed state must not be incorrectly consumed.

---

# 14. Audit Integrity

Verify:

- audit writes remain serialized,
- JSONL record boundaries remain intact,
- audit file is owner-only,
- final audit target cannot be followed through a symlink,
- opened target must be a regular file,
- trusted parent directory remains anchored,
- newly created audit state is durably synchronized.

---

# 15. Audit-Before-Execution

For reviewed side effects, verify required pre-execution audit persistence occurs before execution.

If required pre-execution auditing fails:

```text id="tnzkfv"
operation must not execute
```

This is release-critical behavior.

---

# 16. Completion Audit Semantics

Verify that failure to write a completion audit does not cause the gateway to pretend the original operation never executed.

Execution outcome and audit failure must remain distinguishable.

This prevents unsafe duplicate retries.

---

# 17. HTTP Security

Verify outbound HTTP continues to enforce:

- HTTPS only,
- host allowlist,
- no URL credentials,
- no IP literals,
- no localhost,
- approved port behavior,
- redirect disabling,
- proxy disabling,
- DNS resolution validation,
- unsafe IP filtering.

---

# 18. SSRF Regression

Verify regression tests reject restricted address categories including relevant:

- loopback,
- private,
- link-local,
- multicast,
- unspecified,
- shared IPv4 space,
- other explicitly restricted ranges.

HTTP security regressions block release.

---

# 19. HTTP POST Approval

Verify HTTP POST:

- requires human review,
- preserves reviewed request information,
- revalidates the destination before approved execution,
- cannot silently redirect to a different destination.

---

# 20. Cargo Test Security

Verify Cargo test execution:

- requires review,
- captures review-time workspace state,
- revalidates workspace state before execution,
- rejects changed relevant inputs,
- enforces timeout,
- bounds stdout,
- bounds stderr,
- terminates timed-out process groups.

---

# 21. Git Status Resource Bound

Verify Git status retains its configured maximum processed-entry bound.

Large repositories must not result in unlimited status accumulation.

---

# 22. Wasm Sandbox

Verify production Wasm execution retains:

- fuel consumption,
- memory limits,
- epoch interruption.

All three mechanisms are release-critical resource controls.

---

# 23. Wasm Fuel Regression

Verify the production `SandboxExecutor` fails cleanly when configured fuel is insufficient.

Fuel exhaustion must not crash the gateway process.

---

# 24. Wasm Memory Regression

Verify Wasm memory growth beyond the configured limit traps.

---

# 25. Wasm Timeout Regression

Verify runaway execution is interrupted by epoch timeout.

The gateway must return controlled failure instead of hanging indefinitely.

---

# 26. Admin Socket Creation

Verify:

- gateway refuses to overwrite an existing admin socket path,
- socket is created with owner-only permissions,
- startup reports socket creation failures clearly.

---

# 27. Admin Peer Authentication

Verify every accepted admin connection is authenticated using operating-system peer credentials.

The peer UID must match the gateway process effective UID.

A mismatched UID must be rejected before command processing.

---

# 28. Admin Input Bounds

Verify oversized admin commands are rejected.

Oversized input must not consume or alter pending-review state.

---

# 29. Admin Parser Validation

Verify rejection of:

- empty commands,
- unknown commands,
- missing request IDs,
- malformed UUIDs,
- unexpected extra arguments.

---

# 30. Admin Socket Cleanup

Verify shutdown cleanup removes the admin socket only when the filesystem object still matches the original socket identity.

A replacement object must not be deleted.

---

# 31. Restart Test

Perform or verify automated coverage for:

```text id="3d8omz"
pending reviews survive restart
claimed reviews remain claimed
claimed reviews are not replayed
operator reconciliation remains required
```

---

# 32. Fail-Closed Startup

Verify startup refuses unsafe states including:

- invalid configuration,
- malformed persisted review state,
- operational state inside workspace,
- state-file symlink,
- invalid file type,
- changed parent identity,
- unsafe admin socket configuration.

---

# 33. Error Handling

Review production code for accidental use of panic-driven shortcuts in security-sensitive paths.

Avoid production use of:

```text id="50roal"
unwrap()
expect()
panic!()
```

where recoverable errors can be propagated explicitly.

Test code may use different conventions where appropriate.

---

# 34. Dependency Review

Review:

```bash id="f442ro"
cargo tree
```

Confirm expected major dependencies are present and no accidental dependency changes were introduced.

Review `Cargo.lock` changes whenever dependencies change.

---

# 35. Build Verification

Run:

```bash id="nzboyw"
cargo build --release
```

Release requirement:

```text id="jnzfby"
successful optimized build
```

---

# 36. Release Binary Smoke Test

Start the release binary in a safe test environment.

Verify:

- configuration loads,
- operational state initializes,
- admin socket initializes,
- MCP server starts,
- safe request succeeds,
- blocked request remains blocked,
- reviewed request is held,
- approval workflow functions.

Do not perform destructive testing against production data.

---

# 37. Documentation Verification

Confirm the following documents exist and match current behavior:

```text id="s8n52m"
README.md
docs/threat-model.md
docs/security-architecture.md
docs/configuration.md
docs/operations.md
docs/release-checklist.md
```

Documentation must not describe controls that are absent from the implementation.

---

# 38. Security Documentation Consistency

Cross-check terminology between:

- source code,
- threat model,
- security architecture,
- configuration reference,
- operations guide,
- README.

In particular verify consistent use of:

```text id="4yif8q"
Allow
Review
Block
Pending
Claimed
Reconciliation
DurabilityUncertain
```

---

# 39. Secrets Review

Search the repository for accidentally committed credentials or secrets.

Examples include:

- API keys,
- tokens,
- passwords,
- private keys,
- internal credentials.

Do not commit operational secrets.

---

# 40. Operational Artifact Review

Confirm runtime artifacts are ignored.

Current examples include:

```text id="7kd32n"
target/
zyguor-audit*.jsonl
```

Audit files must not be accidentally committed to the repository.

---

# 41. Repository Status Before Release Commit

Run:

```bash id="j8f86u"
git status
```

Ensure all intended release files are accounted for.

Review:

```bash id="7qw3sx"
git diff --stat
git diff
```

or staged equivalents before committing.

---

# 42. Release Commit

Use a clear release-preparation commit message.

Example:

```text id="9xkski"
Prepare Agent Execution Gateway release documentation
```

The exact message should reflect the changes being committed.

---

# 43. Push Verification

Push the intended branch:

```bash id="wmmdb4"
git push origin master
```

Verify remote output confirms the expected commit range.

---

# 44. Tagging

Only tag a release after all release gates pass.

Example future pattern:

```text id="7mp3ec"
v0.1.0
```

Do not create a release tag merely because development appears complete.

The tag should represent a verified release candidate or published release.

---

# 45. Release Notes

Release notes should summarize:

- purpose of the gateway,
- supported capabilities,
- security model,
- human-review workflow,
- filesystem protections,
- network protections,
- durable review state,
- audit architecture,
- Wasm sandbox controls,
- admin control-plane security,
- known limitations.

Avoid unsupported performance or security claims.

---

# 46. Known Limitations

Before release, ensure documented limitations remain explicit.

Examples include:

- same-UID local processes remain within the same OS trust domain,
- audit logs are not yet cryptographically signed,
- Wasm sandboxing is not equivalent to VM isolation,
- human approval can still contain judgment error,
- denial-of-service risk can be reduced but not eliminated,
- host OS compromise is outside the gateway's protection boundary.

---

# 47. Release Security Gate

A release must not proceed when any of the following is true:

- automated tests fail,
- Clippy produces warnings,
- release build fails,
- policy review can be bypassed,
- filesystem containment is broken,
- audit-before-execution fails,
- claimed requests can replay automatically,
- SSRF controls regress,
- sandbox limits are disabled,
- admin peer authentication fails,
- operational state can be redirected through untrusted paths.

---

# 48. Current Release-Candidate Baseline

Current verified engineering baseline:

```text id="2mzz2c"
291 automated tests passed
0 failed

cargo fmt --check: PASS

cargo clippy --all-targets --all-features -- -D warnings:
PASS

git diff --check:
PASS
```

Security hardening commits include operational-state anchoring and resource/admin control-plane hardening.

---

# 49. Final Release Decision

Before release, answer all of the following:

```text id="qw4f2g"
[ ] Are all tests passing?
[ ] Is Clippy clean?
[ ] Is formatting clean?
[ ] Does the optimized build succeed?
[ ] Is the working tree understood?
[ ] Are mandatory review controls intact?
[ ] Are audit guarantees intact?
[ ] Are persistence guarantees intact?
[ ] Are SSRF controls intact?
[ ] Are sandbox limits intact?
[ ] Is admin authentication intact?
[ ] Are operational paths safely configured?
[ ] Is documentation current?
[ ] Are known limitations documented?
[ ] Has the release binary been smoke-tested?
```

If any security-critical answer is **No**, the release should remain blocked.

---

# 50. Release Principle

The release criterion is not simply:

> Does the gateway run?

The correct question is:

> Does the gateway still enforce the security properties it was designed to guarantee?

Functionality, policy enforcement, auditability, durability, and safe failure behavior must all remain intact before release.