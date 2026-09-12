use crate::policy::{PolicyDecision, PolicyReason};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ExecutionOutcome {
    Success,
    Failed,
    NotExecuted,
}

#[derive(Debug, serde::Serialize)]
pub struct AuditRecord<'a> {
    pub request_id: Uuid,
    pub timestamp_unix: u64,
    pub message: &'a str,
    pub decision: PolicyDecision,
    pub reason: PolicyReason,
    pub execution_outcome: ExecutionOutcome,
}

impl<'a> AuditRecord<'a> {
    pub fn new(
        message: &'a str,
        decision: PolicyDecision,
        reason: PolicyReason,
        execution_outcome: ExecutionOutcome,
    ) -> Result<Self, std::time::SystemTimeError> {
        let timestamp_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let request_id = Uuid::new_v4();

        Ok(Self {
            request_id,
            timestamp_unix,
            message,
            decision,
            reason,
            execution_outcome,
        })
    }
}

pub fn write_audit<W: Write>(writer: &mut W, record: &AuditRecord<'_>) -> Result<(), String> {
    let json = serde_json::to_string(record)
        .map_err(|error| format!("failed to serialize audit record: {error}"))?;

    writeln!(writer, "{json}").map_err(|error| format!("failed to write audit record: {error}"))?;

    Ok(())
}

pub fn persist_audit(record: &AuditRecord<'_>) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("zyguor-audit.jsonl")
        .map_err(|error| format!("failed to open audit log: {error}"))?;

    write_audit(&mut file, record)
}

#[cfg(test)]
mod tests {
    use super::{AuditRecord, ExecutionOutcome, write_audit};
    use crate::policy::{PolicyDecision, PolicyReason};

    #[test]
    fn writes_one_json_record_per_line() -> Result<(), String> {
        let record = AuditRecord::new(
            "read project status",
            PolicyDecision::Allow,
            PolicyReason::Safe,
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
}
