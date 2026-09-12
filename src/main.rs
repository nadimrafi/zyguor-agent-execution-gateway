mod audit;
mod policy;

use audit::{AuditRecord, persist_audit};

use policy::evaluate_message;

use rmcp::{
    ServiceExt, handler::server::wrapper::Parameters, schemars, tool, tool_router, transport::stdio,
};

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct EchoParams {
    message: String,
}
#[derive(Debug, serde::Serialize)]
struct GatewayResponse<'a> {
    request_id: uuid::Uuid,
    status: &'a str,
    decision: policy::PolicyDecision,
    reason: policy::PolicyReason,
    executed: bool,
    message: Option<&'a str>,
}

#[derive(Clone)]
struct ZyguorGateway;

const MAX_MESSAGE_LENGTH: usize = 4096;

fn validate_message(message: &str) -> Result<(), String> {
    if message.trim().is_empty() {
        return Err("message cannot be empty".to_owned());
    }

    if message.len() > MAX_MESSAGE_LENGTH {
        return Err(format!(
            "message exceeds maximum length of {MAX_MESSAGE_LENGTH} bytes"
        ));
    }

    Ok(())
}

fn execute_message_with_audit<F>(message: &str, audit_writer: F) -> Result<String, String>
where
    F: FnOnce(&AuditRecord<'_>) -> Result<(), String>,
{
    validate_message(message)?;

    let evaluation = evaluate_message(message);

    let audit_record = AuditRecord::new(message, evaluation.decision, evaluation.reason)
        .map_err(|error| format!("failed to create audit record: {error}"))?;

    audit_writer(&audit_record)?;

    let response = match evaluation.decision {
        policy::PolicyDecision::Allow => GatewayResponse {
            request_id: audit_record.request_id,
            status: "executed",
            decision: evaluation.decision,
            reason: evaluation.reason,
            executed: true,
            message: Some(message),
        },

        policy::PolicyDecision::Review => GatewayResponse {
            request_id: audit_record.request_id,
            status: "held_for_review",
            decision: evaluation.decision,
            reason: evaluation.reason,
            executed: false,
            message: None,
        },

        policy::PolicyDecision::Block => GatewayResponse {
            request_id: audit_record.request_id,
            status: "blocked",
            decision: evaluation.decision,
            reason: evaluation.reason,
            executed: false,
            message: None,
        },
    };

    serde_json::to_string(&response)
        .map_err(|error| format!("failed to serialize gateway response: {error}"))
}

fn execute_message(message: &str) -> Result<String, String> {
    execute_message_with_audit(message, persist_audit)
}

#[tool_router(server_handler)]
impl ZyguorGateway {
    #[tool(description = "Evaluates a message through Zyguor policy controls")]
    fn echo(&self, Parameters(params): Parameters<EchoParams>) -> String {
        match execute_message(&params.message) {
            Ok(result) => result,
            Err(error) => format!("GATEWAY_ERROR: {error}"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = ZyguorGateway.serve(stdio()).await?;

    service.waiting().await?;

    Ok(())
}

#[cfg(test)]
mod gateway_tests {
    use super::{MAX_MESSAGE_LENGTH, execute_message_with_audit};

    fn no_op_audit(_: &crate::audit::AuditRecord<'_>) -> Result<(), String> {
        Ok(())
    }

    #[test]
    fn allow_executes_message() -> Result<(), String> {
        let result = execute_message_with_audit("read the project status", no_op_audit)?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["status"], "executed");
        assert_eq!(json["decision"], "Allow");
        assert_eq!(json["reason"], "Safe");
        assert_eq!(json["executed"], true);
        assert_eq!(json["message"], "read the project status");

        Ok(())
    }

    #[test]
    fn review_does_not_execute_message() -> Result<(), String> {
        let result = execute_message_with_audit("write a new configuration", no_op_audit)?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["status"], "held_for_review");
        assert_eq!(json["decision"], "Review");
        assert_eq!(json["reason"], "Write");
        assert_eq!(json["executed"], false);
        assert!(json["message"].is_null());

        Ok(())
    }

    #[test]
    fn block_does_not_execute_message() -> Result<(), String> {
        let result = execute_message_with_audit("delete the production database", no_op_audit)?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["status"], "blocked");
        assert_eq!(json["decision"], "Block");
        assert_eq!(json["reason"], "Destructive");
        assert_eq!(json["executed"], false);
        assert!(json["message"].is_null());

        Ok(())
    }
    #[test]
    fn rejects_empty_message() {
        let result = execute_message_with_audit("", no_op_audit);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_whitespace_only_message() {
        let result = execute_message_with_audit("   ", no_op_audit);

        assert!(result.is_err());
    }

    #[test]
    fn accepts_message_at_maximum_length() -> Result<(), String> {
        let message = "a".repeat(MAX_MESSAGE_LENGTH);

        let result = execute_message_with_audit(&message, no_op_audit)?;

        assert!(result.contains("\"executed\":true"));

        Ok(())
    }

    #[test]
    fn rejects_message_over_maximum_length() {
        let message = "a".repeat(MAX_MESSAGE_LENGTH + 1);

        let result = execute_message_with_audit(&message, no_op_audit);

        assert!(result.is_err());
    }
}
