use crate::policy::PolicyDecision;
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize)]
pub struct AuditRecord<'a> {
    pub timestamp_unix: u64,
    pub message: &'a str,
    pub decision: PolicyDecision,
}

impl<'a> AuditRecord<'a> {
    pub fn new(
        message: &'a str,
        decision: PolicyDecision,
    ) -> Result<Self, std::time::SystemTimeError> {
        let timestamp_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        Ok(Self {
            timestamp_unix,
            message,
            decision,
        })
    }
}
