mod audit;
mod policy;
mod sandbox;
use audit::{AuditRecord, ExecutionOutcome, persist_audit};
use policy::evaluate_message;
use sandbox::{ExecutionRequest, SandboxConfig, SandboxExecutor, SandboxOperation};

#[cfg(test)]
use sandbox::run_infinite_loop_with_fuel;

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
    execution_outcome: ExecutionOutcome,
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

fn execute_message_with_audit<F, S>(
    message: &str,
    audit_writer: F,
    sandbox_runner: S,
) -> Result<String, String>
where
    F: FnOnce(&AuditRecord<'_>) -> Result<(), String>,
    S: FnOnce() -> Result<i32, String>,
{
    validate_message(message)?;

    let evaluation = evaluate_message(message);

    let (status, executed, response_message, execution_outcome) = match evaluation.decision {
        policy::PolicyDecision::Allow => match sandbox_runner() {
            Ok(_) => ("executed", true, Some(message), ExecutionOutcome::Success),

            Err(_) => ("execution_failed", false, None, ExecutionOutcome::Failed),
        },

        policy::PolicyDecision::Review => (
            "held_for_review",
            false,
            None,
            ExecutionOutcome::NotExecuted,
        ),

        policy::PolicyDecision::Block => ("blocked", false, None, ExecutionOutcome::NotExecuted),
    };

    let audit_record = AuditRecord::new(
        message,
        evaluation.decision,
        evaluation.reason,
        execution_outcome,
    )
    .map_err(|error| format!("failed to create audit record: {error}"))?;

    audit_writer(&audit_record)?;

    let response = GatewayResponse {
        request_id: audit_record.request_id,
        status,
        decision: evaluation.decision,
        reason: evaluation.reason,
        executed,
        message: response_message,
        execution_outcome,
    };

    serde_json::to_string(&response)
        .map_err(|error| format!("failed to serialize gateway response: {error}"))
}

fn execute_message(message: &str) -> Result<String, String> {
    let executor = SandboxExecutor::new(SandboxConfig::default());

    execute_message_with_audit(message, persist_audit, || {
        executor.execute(ExecutionRequest {
            operation: SandboxOperation::Add,
            left: 2,
            right: 3,
        })
    })
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

    use super::{MAX_MESSAGE_LENGTH, execute_message_with_audit, run_infinite_loop_with_fuel};

    fn no_op_audit(_: &crate::audit::AuditRecord<'_>) -> Result<(), String> {
        Ok(())
    }

    fn sandbox_success() -> Result<i32, String> {
        Ok(5)
    }
    fn sandbox_real_fuel_failure() -> Result<i32, String> {
        run_infinite_loop_with_fuel(1_000)?;
        Ok(0)
    }

    fn sandbox_failure() -> Result<i32, String> {
        Err("simulated sandbox failure".to_owned())
    }
    fn capture_failed_audit(record: &crate::audit::AuditRecord<'_>) -> Result<(), String> {
        assert_eq!(record.decision, crate::policy::PolicyDecision::Allow);
        assert_eq!(
            record.execution_outcome,
            crate::audit::ExecutionOutcome::Failed
        );

        Ok(())
    }

    #[test]
    fn allow_executes_message() -> Result<(), String> {
        let result =
            execute_message_with_audit("read the project status", no_op_audit, sandbox_success)?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["status"], "executed");
        assert_eq!(json["decision"], "Allow");
        assert_eq!(json["reason"], "Safe");
        assert_eq!(json["executed"], true);
        assert_eq!(json["execution_outcome"], "Success");
        assert_eq!(json["message"], "read the project status");

        Ok(())
    }

    #[test]
    fn review_does_not_execute_message() -> Result<(), String> {
        let result =
            execute_message_with_audit("write a new configuration", no_op_audit, sandbox_success)?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["status"], "held_for_review");
        assert_eq!(json["decision"], "Review");
        assert_eq!(json["reason"], "Write");
        assert_eq!(json["executed"], false);
        assert_eq!(json["execution_outcome"], "NotExecuted");
        assert!(json["message"].is_null());

        Ok(())
    }

    #[test]
    fn block_does_not_execute_message() -> Result<(), String> {
        let result = execute_message_with_audit(
            "delete the production database",
            no_op_audit,
            sandbox_success,
        )?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["status"], "blocked");
        assert_eq!(json["decision"], "Block");
        assert_eq!(json["reason"], "Destructive");
        assert_eq!(json["executed"], false);
        assert_eq!(json["execution_outcome"], "NotExecuted");
        assert!(json["message"].is_null());

        Ok(())
    }

    #[test]
    fn allow_reports_sandbox_failure() -> Result<(), String> {
        let result =
            execute_message_with_audit("read the project status", no_op_audit, sandbox_failure)?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["status"], "execution_failed");
        assert_eq!(json["decision"], "Allow");
        assert_eq!(json["reason"], "Safe");
        assert_eq!(json["executed"], false);
        assert_eq!(json["execution_outcome"], "Failed");
        assert!(json["message"].is_null());

        Ok(())
    }

    #[test]
    fn rejects_empty_message() {
        let result = execute_message_with_audit("", no_op_audit, sandbox_success);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_whitespace_only_message() {
        let result = execute_message_with_audit("   ", no_op_audit, sandbox_success);

        assert!(result.is_err());
    }
    fn sandbox_must_not_run() -> Result<i32, String> {
        Err("sandbox was called unexpectedly".to_owned())
    }

    #[test]
    fn accepts_message_at_maximum_length() -> Result<(), String> {
        let message = "a".repeat(MAX_MESSAGE_LENGTH);

        let result = execute_message_with_audit(&message, no_op_audit, sandbox_success)?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["executed"], true);
        assert_eq!(json["execution_outcome"], "Success");

        Ok(())
    }
    #[test]
    fn review_never_calls_sandbox() -> Result<(), String> {
        let result = execute_message_with_audit(
            "write a new configuration",
            no_op_audit,
            sandbox_must_not_run,
        )?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["decision"], "Review");
        assert_eq!(json["execution_outcome"], "NotExecuted");

        Ok(())
    }

    #[test]
    fn block_never_calls_sandbox() -> Result<(), String> {
        let result = execute_message_with_audit(
            "delete the production database",
            no_op_audit,
            sandbox_must_not_run,
        )?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["decision"], "Block");
        assert_eq!(json["execution_outcome"], "NotExecuted");

        Ok(())
    }

    #[test]
    fn real_wasmtime_resource_failure_is_reported() -> Result<(), String> {
        let result = execute_message_with_audit(
            "read the project status",
            no_op_audit,
            sandbox_real_fuel_failure,
        )?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["status"], "execution_failed");
        assert_eq!(json["decision"], "Allow");
        assert_eq!(json["reason"], "Safe");
        assert_eq!(json["executed"], false);
        assert_eq!(json["execution_outcome"], "Failed");
        assert!(json["message"].is_null());

        Ok(())
    }
    #[test]
    fn real_wasmtime_failure_is_recorded_in_audit() -> Result<(), String> {
        let result = execute_message_with_audit(
            "read the project status",
            capture_failed_audit,
            sandbox_real_fuel_failure,
        )?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["status"], "execution_failed");
        assert_eq!(json["execution_outcome"], "Failed");
        assert_eq!(json["executed"], false);

        Ok(())
    }

    #[test]
    fn rejects_message_over_maximum_length() {
        let message = "a".repeat(MAX_MESSAGE_LENGTH + 1);

        let result = execute_message_with_audit(&message, no_op_audit, sandbox_success);

        assert!(result.is_err());
    }
}
