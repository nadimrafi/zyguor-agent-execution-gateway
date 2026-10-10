use crate::policy::{PolicyDecision, PolicyReason};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[cfg(unix)]
use std::os::{
    fd::{AsRawFd, FromRawFd},
    unix::{
        ffi::OsStrExt,
        fs::{OpenOptionsExt, PermissionsExt},
    },
};

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
pub trait AuditSink: Send + Sync {
    fn persist_record(&self, record: &AuditRecord<'_>) -> Result<(), String>;
}

impl AuditSink for Path {
    fn persist_record(&self, record: &AuditRecord<'_>) -> Result<(), String> {
        persist_audit(self, record)
    }
}

impl AuditSink for PathBuf {
    fn persist_record(&self, record: &AuditRecord<'_>) -> Result<(), String> {
        persist_audit(self.as_path(), record)
    }
}
#[cfg(unix)]
#[derive(Debug)]
pub struct AnchoredAuditLog {
    path: PathBuf,
    parent_directory: File,
}

#[cfg(unix)]
impl AnchoredAuditLog {
    pub fn from_validated_path(
        path: &Path,
        expected_parent_device: u64,
        expected_parent_inode: u64,
    ) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt;

        let parent = path
            .parent()
            .ok_or_else(|| "audit log path must have a parent directory".to_owned())?;

        let file_name = path
            .file_name()
            .ok_or_else(|| "audit log path must include a file name".to_owned())?;

        let canonical_parent = std::fs::canonicalize(parent).map_err(|error| {
            format!(
                "failed to resolve audit log parent directory '{}': {error}",
                parent.display()
            )
        })?;

        let mut options = OpenOptions::new();
        options.read(true);
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);

        let parent_directory = options.open(&canonical_parent).map_err(|error| {
            format!(
                "failed to open audit log parent directory '{}': {error}",
                canonical_parent.display()
            )
        })?;

        let metadata = parent_directory
            .metadata()
            .map_err(|error| format!("failed to inspect audit log parent directory: {error}"))?;

        if !metadata.is_dir() {
            return Err("audit log parent must be a directory".to_owned());
        }

        let actual_device = metadata.dev();
        let actual_inode = metadata.ino();

        if actual_device != expected_parent_device || actual_inode != expected_parent_inode {
            return Err(format!(
                "audit log parent directory changed after validation: \
                 expected device {expected_parent_device} inode {expected_parent_inode}, \
                 found device {actual_device} inode {actual_inode}"
            ));
        }

        Ok(Self {
            path: canonical_parent.join(file_name),
            parent_directory,
        })
    }

    pub fn persist(&self, record: &AuditRecord<'_>) -> Result<(), String> {
        persist_audit_with_parent(&self.path, &self.parent_directory, record)
    }
}
#[cfg(unix)]
impl AuditSink for AnchoredAuditLog {
    fn persist_record(&self, record: &AuditRecord<'_>) -> Result<(), String> {
        self.persist(record)
    }
}
#[cfg(unix)]
fn persist_audit_with_parent(
    audit_path: &Path,
    parent_directory: &File,
    record: &AuditRecord<'_>,
) -> Result<(), String> {
    let file_name = audit_path
        .file_name()
        .ok_or_else(|| "audit log path must include a file name".to_owned())?;

    let file_name_c = CString::new(file_name.as_bytes())
        .map_err(|_| "audit log file name contains an invalid NUL byte".to_owned())?;

    let create_fd = unsafe {
        libc::openat(
            parent_directory.as_raw_fd(),
            file_name_c.as_ptr(),
            libc::O_WRONLY
                | libc::O_APPEND
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };

    let (mut file, newly_created) = if create_fd >= 0 {
        (unsafe { File::from_raw_fd(create_fd) }, true)
    } else {
        let create_error = std::io::Error::last_os_error();

        if create_error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(format!(
                "failed to create audit log '{}': {create_error}",
                audit_path.display()
            ));
        }

        let existing_fd = unsafe {
            libc::openat(
                parent_directory.as_raw_fd(),
                file_name_c.as_ptr(),
                libc::O_WRONLY
                    | libc::O_APPEND
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
            )
        };

        if existing_fd < 0 {
            let error = std::io::Error::last_os_error();

            return Err(format!(
                "failed to open existing audit log '{}': {error}",
                audit_path.display()
            ));
        }

        (unsafe { File::from_raw_fd(existing_fd) }, false)
    };

    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect opened audit log: {error}"))?;

    if !metadata.is_file() {
        return Err("audit log must be a regular file".to_owned());
    }

    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("failed to secure audit log permissions: {error}"))?;

    if newly_created {
        file.sync_all()
            .map_err(|error| format!("failed to sync newly created audit log: {error}"))?;

        parent_directory
            .sync_all()
            .map_err(|error| format!("failed to sync audit log parent directory: {error}"))?;
    }

    write_audit(&mut file, record)?;

    file.sync_all()
        .map_err(|error| format!("failed to sync audit log: {error}"))?;

    if newly_created {
        parent_directory
            .sync_all()
            .map_err(|error| format!("failed to sync audit log parent directory: {error}"))?;
    }

    Ok(())
}

pub fn persist_audit(audit_path: &Path, record: &AuditRecord<'_>) -> Result<(), String> {
    let parent = audit_path
        .parent()
        .ok_or_else(|| "audit log path must have a parent directory".to_owned())?;

    let canonical_parent = std::fs::canonicalize(parent).map_err(|error| {
        format!(
            "failed to resolve audit log parent directory '{}': {error}",
            parent.display()
        )
    })?;

    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);

    let parent_directory = options.open(&canonical_parent).map_err(|error| {
        format!(
            "failed to open audit log parent directory '{}': {error}",
            canonical_parent.display()
        )
    })?;

    let metadata = parent_directory
        .metadata()
        .map_err(|error| format!("failed to inspect audit log parent directory: {error}"))?;

    if !metadata.is_dir() {
        return Err("audit log parent must be a directory".to_owned());
    }

    #[cfg(unix)]
    {
        persist_audit_with_parent(audit_path, &parent_directory, record)
    }

    #[cfg(not(unix))]
    {
        let _ = record;
        Err("audit persistence requires Unix filesystem support".to_owned())
    }
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
    #[test]
    fn persist_audit_creates_then_appends_records() -> Result<(), String> {
        let base = std::env::temp_dir().join(format!(
            "zyguor-audit-create-append-test-{}",
            uuid::Uuid::new_v4()
        ));

        std::fs::create_dir_all(&base)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let audit_path = base.join("audit.jsonl");

        let first_request_id = Uuid::new_v4();
        let second_request_id = Uuid::new_v4();

        let first_request_id_text = first_request_id.to_string();
        let second_request_id_text = second_request_id.to_string();

        let first = AuditRecord::new(
            first_request_id,
            "first durable audit record",
            PolicyDecision::Allow,
            PolicyReason::Safe,
            AuditPhase::Completion,
            ExecutionOutcome::Success,
        )
        .map_err(|error| format!("failed to create first audit record: {error}"))?;

        let second = AuditRecord::new(
            second_request_id,
            "second durable audit record",
            PolicyDecision::Allow,
            PolicyReason::Safe,
            AuditPhase::Completion,
            ExecutionOutcome::Success,
        )
        .map_err(|error| format!("failed to create second audit record: {error}"))?;

        persist_audit(&audit_path, &first)?;
        persist_audit(&audit_path, &second)?;

        let contents = std::fs::read_to_string(&audit_path)
            .map_err(|error| format!("failed to read audit log: {error}"))?;

        let lines: Vec<&str> = contents.lines().collect();

        assert_eq!(lines.len(), 2);

        let first_value: serde_json::Value = serde_json::from_str(lines[0])
            .map_err(|error| format!("first audit line was invalid JSON: {error}"))?;

        let second_value: serde_json::Value = serde_json::from_str(lines[1])
            .map_err(|error| format!("second audit line was invalid JSON: {error}"))?;

        assert_eq!(
            first_value
                .get("request_id")
                .and_then(serde_json::Value::as_str),
            Some(first_request_id_text.as_str())
        );

        assert_eq!(
            second_value
                .get("request_id")
                .and_then(serde_json::Value::as_str),
            Some(second_request_id_text.as_str())
        );

        std::fs::remove_dir_all(&base)
            .map_err(|error| format!("failed to remove test directory: {error}"))?;

        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn anchored_audit_log_rejects_replaced_parent_directory() -> Result<(), String> {
        use super::AnchoredAuditLog;
        use std::os::unix::fs::MetadataExt;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-anchored-audit-parent-replacement-test-{}",
            uuid::Uuid::new_v4()
        ));

        let audit_dir = test_root.join("audit-state");
        let moved_trusted_dir = test_root.join("trusted-audit-state-moved");

        std::fs::create_dir_all(&audit_dir)
            .map_err(|error| format!("failed to create audit directory: {error}"))?;

        let metadata = std::fs::metadata(&audit_dir)
            .map_err(|error| format!("failed to inspect audit directory: {error}"))?;

        let expected_device = metadata.dev();
        let expected_inode = metadata.ino();

        let audit_path = audit_dir.join("audit.jsonl");

        std::fs::rename(&audit_dir, &moved_trusted_dir)
            .map_err(|error| format!("failed to move trusted audit directory: {error}"))?;

        std::fs::create_dir_all(&audit_dir)
            .map_err(|error| format!("failed to create replacement audit directory: {error}"))?;

        let result =
            AnchoredAuditLog::from_validated_path(&audit_path, expected_device, expected_inode);

        std::fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to remove test directory: {error}"))?;

        let error = result.expect_err("replaced audit parent directory should be rejected");

        assert!(
            error.starts_with("audit log parent directory changed after validation:"),
            "unexpected error: {error}"
        );

        Ok(())
    }
}
