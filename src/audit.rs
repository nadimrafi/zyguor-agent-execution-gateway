use crate::policy::{PolicyDecision, PolicyReason};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum AuditPhase {
    Approval,
    Rejection,
    PreExecution,
    Completion,
    Reconciliation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ExecutionOutcome {
    Success,
    Failed,
    NotExecuted,
    Unknown,
}

#[derive(Debug, serde::Serialize)]
pub struct AuditRecord<'a> {
    pub request_id: Uuid,
    pub timestamp_unix: u64,
    pub message: &'a str,
    pub phase: AuditPhase,
    pub decision: PolicyDecision,
    pub reason: PolicyReason,
    pub execution_outcome: ExecutionOutcome,
}

impl<'a> AuditRecord<'a> {
    pub fn new(
        request_id: Uuid,
        message: &'a str,
        decision: PolicyDecision,
        reason: PolicyReason,
        phase: AuditPhase,
        execution_outcome: ExecutionOutcome,
    ) -> Result<Self, std::time::SystemTimeError> {
        let timestamp_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        Ok(Self {
            request_id,
            timestamp_unix,
            message,
            decision,
            reason,
            execution_outcome,
            phase,
        })
    }
}

pub fn write_audit<W: Write>(writer: &mut W, record: &AuditRecord<'_>) -> Result<(), String> {
    let json = serde_json::to_string(record)
        .map_err(|error| format!("failed to serialize audit record: {error}"))?;

    writeln!(writer, "{json}").map_err(|error| format!("failed to write audit record: {error}"))?;

    Ok(())
}

pub fn persist_audit(audit_path: &std::path::Path, record: &AuditRecord<'_>) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }

    let mut file = options.open(audit_path).map_err(|error| {
        format!(
            "failed to open audit log '{}': {error}",
            audit_path.display()
        )
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect opened audit log: {error}"))?;

    if !metadata.is_file() {
        return Err("audit log must be a regular file".to_owned());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let permissions = std::fs::Permissions::from_mode(0o600);

        file.set_permissions(permissions)
            .map_err(|error| format!("failed to secure audit log permissions: {error}"))?;
    }

    write_audit(&mut file, record)?;

    file.sync_data()
        .map_err(|error| format!("failed to sync audit log: {error}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AuditPhase, AuditRecord, ExecutionOutcome, persist_audit, write_audit};
    use crate::policy::{PolicyDecision, PolicyReason};
    use uuid::Uuid;

    #[test]
    fn writes_one_json_record_per_line() -> Result<(), String> {
        let request_id = Uuid::new_v4();
        let record = AuditRecord::new(
            request_id,
            "read project status",
            PolicyDecision::Allow,
            PolicyReason::Safe,
            AuditPhase::Completion,
            ExecutionOutcome::Success,
        )
        .map_err(|error| format!("failed to create test audit record: {error}"))?;

        let mut output = Vec::new();

        write_audit(&mut output, &record)?;
        write_audit(&mut output, &record)?;

        let text = String::from_utf8(output)
            .map_err(|error| format!("audit output was not UTF-8: {error}"))?;

        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(lines.len(), 2);

        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn persist_audit_rejects_symlink_target() -> Result<(), String> {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
            "zyguor-audit-symlink-test-{}",
            uuid::Uuid::new_v4()
        ));

        std::fs::create_dir_all(&base)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let real_file = base.join("real-audit.jsonl");
        let audit_path = base.join("audit.jsonl");

        std::fs::write(&real_file, "original\n")
            .map_err(|error| format!("failed to create real audit file: {error}"))?;

        symlink(&real_file, &audit_path)
            .map_err(|error| format!("failed to create audit symlink: {error}"))?;

        let record = AuditRecord::new(
            Uuid::new_v4(),
            "test symlink protection",
            PolicyDecision::Allow,
            PolicyReason::Safe,
            AuditPhase::Completion,
            ExecutionOutcome::Success,
        )
        .map_err(|error| format!("failed to create audit record: {error}"))?;

        let result = persist_audit(&audit_path, &record);

        assert!(result.is_err());

        let original = std::fs::read_to_string(&real_file)
            .map_err(|error| format!("failed to read real audit file: {error}"))?;

        assert_eq!(original, "original\n");

        std::fs::remove_dir_all(&base)
            .map_err(|error| format!("failed to remove test directory: {error}"))?;

        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn persist_audit_creates_private_file() -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt;

        let base = std::env::temp_dir().join(format!(
            "zyguor-audit-permissions-test-{}",
            uuid::Uuid::new_v4()
        ));

        std::fs::create_dir_all(&base)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let audit_path = base.join("audit.jsonl");

        let record = AuditRecord::new(
            Uuid::new_v4(),
            "test private audit permissions",
            PolicyDecision::Allow,
            PolicyReason::Safe,
            AuditPhase::Completion,
            ExecutionOutcome::Success,
        )
        .map_err(|error| format!("failed to create audit record: {error}"))?;

        persist_audit(&audit_path, &record)?;

        let metadata = std::fs::metadata(&audit_path)
            .map_err(|error| format!("failed to inspect audit log: {error}"))?;

        let mode = metadata.permissions().mode() & 0o777;

        assert_eq!(
            mode & 0o077,
            0,
            "audit log must not grant group or other permissions: mode {mode:o}"
        );

        std::fs::remove_dir_all(&base)
            .map_err(|error| format!("failed to remove test directory: {error}"))?;

        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn persist_audit_tightens_existing_file_permissions() -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt;

        let base = std::env::temp_dir().join(format!(
            "zyguor-audit-existing-permissions-test-{}",
            uuid::Uuid::new_v4()
        ));

        std::fs::create_dir_all(&base)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let audit_path = base.join("audit.jsonl");

        std::fs::write(&audit_path, "")
            .map_err(|error| format!("failed to create audit file: {error}"))?;

        std::fs::set_permissions(&audit_path, std::fs::Permissions::from_mode(0o644))
            .map_err(|error| format!("failed to set test permissions: {error}"))?;

        let record = AuditRecord::new(
            Uuid::new_v4(),
            "test existing audit permissions",
            PolicyDecision::Allow,
            PolicyReason::Safe,
            AuditPhase::Completion,
            ExecutionOutcome::Success,
        )
        .map_err(|error| format!("failed to create audit record: {error}"))?;

        persist_audit(&audit_path, &record)?;

        let metadata = std::fs::metadata(&audit_path)
            .map_err(|error| format!("failed to inspect audit log: {error}"))?;

        let mode = metadata.permissions().mode() & 0o777;

        assert_eq!(mode, 0o600);

        std::fs::remove_dir_all(&base)
            .map_err(|error| format!("failed to remove test directory: {error}"))?;

        Ok(())
    }
}
