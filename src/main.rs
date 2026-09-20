mod audit;
mod execution;
mod policy;
mod sandbox;
use audit::{AuditPhase, AuditRecord, ExecutionOutcome, persist_audit};
use execution::{AddArguments, ExecutionRequest, ReadFileArguments};
use policy::{PolicyDecision, PolicyEvaluation, PolicyOperation, evaluate_operation};
use sandbox::{SandboxConfig, SandboxExecutor};

#[cfg(test)]
use sandbox::run_infinite_loop_with_fuel;

use rmcp::{
    ServiceExt, handler::server::wrapper::Parameters, schemars, tool, tool_router, transport::stdio,
};

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ExecutionArgumentsParams {
    left: Option<i32>,
    right: Option<i32>,
    path: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ExecuteParams {
    operation: String,
    arguments: ExecutionArgumentsParams,
    context: ExecutionContextParams,
}
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ExecutionContextParams {
    purpose: String,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
struct ExecutionResult {
    value: i32,
}

#[derive(Debug, serde::Serialize)]
struct GatewayResponse<'a> {
    request_id: uuid::Uuid,
    status: &'a str,
    decision: policy::PolicyDecision,
    reason: policy::PolicyReason,
    executed: bool,
    result: Option<ExecutionResult>,
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
    evaluation: PolicyEvaluation,
    mut audit_writer: F,
    sandbox_runner: S,
) -> Result<String, String>
where
    F: FnMut(&AuditRecord<'_>) -> Result<(), String>,
    S: FnOnce() -> Result<i32, String>,
{
    validate_message(message)?;

    let request_id = uuid::Uuid::new_v4();

    let (status, executed, result, execution_outcome) = match evaluation.decision {
        PolicyDecision::Allow => {
            let pre_execution_record = AuditRecord::new(
                request_id,
                message,
                evaluation.decision,
                evaluation.reason,
                AuditPhase::PreExecution,
                ExecutionOutcome::NotExecuted,
            )
            .map_err(|error| format!("failed to create pre-execution audit record: {error}"))?;

            audit_writer(&pre_execution_record)
                .map_err(|error| format!("failed to persist pre-execution audit: {error}"))?;

            match sandbox_runner() {
                Ok(value) => (
                    "executed",
                    true,
                    Some(ExecutionResult { value }),
                    ExecutionOutcome::Success,
                ),
                Err(_) => ("execution_failed", false, None, ExecutionOutcome::Failed),
            }
        }
        PolicyDecision::Review => (
            "held_for_review",
            false,
            None,
            ExecutionOutcome::NotExecuted,
        ),
        PolicyDecision::Block => ("blocked", false, None, ExecutionOutcome::NotExecuted),
    };

    let audit_record = AuditRecord::new(
        request_id,
        message,
        evaluation.decision,
        evaluation.reason,
        AuditPhase::Completion,
        execution_outcome,
    )
    .map_err(|error| format!("failed to create audit record: {error}"))?;

    let completion_audit_failed = audit_writer(&audit_record).is_err();

    let status = if completion_audit_failed {
        match execution_outcome {
            ExecutionOutcome::Success => "execution_completed_audit_failed",
            ExecutionOutcome::Failed => "execution_failed_audit_failed",
            ExecutionOutcome::NotExecuted => status,
        }
    } else {
        status
    };

    let response = GatewayResponse {
        request_id: audit_record.request_id,
        status,
        decision: evaluation.decision,
        reason: evaluation.reason,
        executed,
        result,
        execution_outcome,
    };

    serde_json::to_string(&response)
        .map_err(|error| format!("failed to serialize gateway response: {error}"))
}

fn build_execution_request(params: &ExecuteParams) -> Result<ExecutionRequest, String> {
    match params.operation.trim().to_ascii_lowercase().as_str() {
        "add" => {
            let left = params
                .arguments
                .left
                .ok_or_else(|| "add requires arguments.left".to_owned())?;

            let right = params
                .arguments
                .right
                .ok_or_else(|| "add requires arguments.right".to_owned())?;

            Ok(ExecutionRequest::Add(AddArguments { left, right }))
        }
        "read_file" => {
            let path = params
                .arguments
                .path
                .as_ref()
                .ok_or_else(|| "read_file requires arguments.path".to_owned())?;

            if path.trim().is_empty() {
                return Err("read_file path cannot be empty".to_owned());
            }

            Ok(ExecutionRequest::ReadFile(ReadFileArguments {
                path: path.clone(),
            }))
        }
        other => Err(format!("unsupported operation: {other}")),
    }
}
fn policy_operation_for(request: &ExecutionRequest) -> PolicyOperation {
    match request {
        ExecutionRequest::Add(_) => PolicyOperation::Add,
        ExecutionRequest::ReadFile(_) => PolicyOperation::ReadFile,
    }
}

fn execute_request(params: &ExecuteParams) -> Result<String, String> {
    let request = build_execution_request(params)?;
    let policy_operation = policy_operation_for(&request);
    let evaluation = evaluate_operation(policy_operation);
    let executor = SandboxExecutor::new(SandboxConfig::default());

    execute_message_with_audit(
        &params.context.purpose,
        evaluation,
        persist_audit,
        || match request {
            ExecutionRequest::Add(arguments) => executor.execute_add(arguments),
            ExecutionRequest::ReadFile(arguments) => Err(format!(
                "read_file execution is not implemented yet for path: {}",
                arguments.path
            )),
        },
    )
}
#[tool_router(server_handler)]
impl ZyguorGateway {
    #[tool(
        description = "Evaluates and executes a structured request through the Zyguor policy-controlled Wasmtime sandbox."
    )]
    fn execute(&self, Parameters(params): Parameters<ExecuteParams>) -> String {
        match execute_request(&params) {
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
    use super::{
        AddArguments, ExecuteParams, ExecutionArgumentsParams, ExecutionContextParams,
        ExecutionRequest, MAX_MESSAGE_LENGTH, PolicyEvaluation, PolicyOperation,
        build_execution_request, execute_message_with_audit, execute_request, policy_operation_for,
        run_infinite_loop_with_fuel,
    };
    use crate::policy::evaluate_message;

    fn no_op_audit(_: &crate::audit::AuditRecord<'_>) -> Result<(), String> {
        Ok(())
    }

    fn evaluation_for(message: &str) -> PolicyEvaluation {
        evaluate_message(message)
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

    fn sandbox_must_not_run() -> Result<i32, String> {
        Err("sandbox was called unexpectedly".to_owned())
    }

    #[test]
    fn builds_add_execution_request() -> Result<(), String> {
        let params = ExecuteParams {
            operation: "add".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: Some(8),
                right: Some(4),
                path: None,
            },
            context: ExecutionContextParams {
                purpose: "test addition".to_owned(),
            },
        };

        let request = build_execution_request(&params)?;

        match request {
            ExecutionRequest::Add(_) => {
                // keep existing assertions
            }
            ExecutionRequest::ReadFile(_) => {
                panic!("expected Add execution request");
            }
        }

        Ok(())
    }
    #[test]
    fn builds_read_file_execution_request() {
        let params = ExecuteParams {
            operation: "read_file".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: None,
                right: None,
                path: Some("README.md".to_owned()),
            },
            context: ExecutionContextParams {
                purpose: "read project documentation".to_owned(),
            },
        };

        let request = build_execution_request(&params).expect("read_file request should be valid");

        match request {
            ExecutionRequest::ReadFile(arguments) => {
                assert_eq!(arguments.path, "README.md");
            }
            ExecutionRequest::Add(_) => {
                panic!("expected ReadFile execution request");
            }
        }
    }

    #[test]
    fn rejects_read_file_without_path() {
        let params = ExecuteParams {
            operation: "read_file".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: None,
                right: None,
                path: None,
            },
            context: ExecutionContextParams {
                purpose: "read project documentation".to_owned(),
            },
        };

        let result = build_execution_request(&params);

        assert_eq!(
            result.expect_err("missing path should be rejected"),
            "read_file requires arguments.path"
        );
    }

    #[test]
    fn rejects_read_file_with_blank_path() {
        let params = ExecuteParams {
            operation: "read_file".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: None,
                right: None,
                path: Some("   ".to_owned()),
            },
            context: ExecutionContextParams {
                purpose: "read project documentation".to_owned(),
            },
        };

        let result = build_execution_request(&params);

        assert_eq!(
            result.expect_err("blank path should be rejected"),
            "read_file path cannot be empty"
        );
    }

    #[test]
    fn maps_add_to_add_policy_operation() {
        let request = ExecutionRequest::Add(AddArguments { left: 2, right: 3 });

        assert_eq!(policy_operation_for(&request), PolicyOperation::Add);
    }

    #[test]
    fn normalizes_add_operation() -> Result<(), String> {
        let params = ExecuteParams {
            operation: "  ADD  ".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: Some(3),
                right: Some(6),
                path: None,
            },
            context: ExecutionContextParams {
                purpose: "test normalized operation".to_owned(),
            },
        };

        let request = build_execution_request(&params)?;

        match request {
            ExecutionRequest::Add(arguments) => {
                assert_eq!(arguments.left, 3);
                assert_eq!(arguments.right, 6);
            }
            ExecutionRequest::ReadFile(_) => {
                panic!("expected Add execution request");
            }
        }

        Ok(())
    }

    #[test]
    fn rejects_unsupported_operation() -> Result<(), String> {
        let params = ExecuteParams {
            operation: "delete".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: Some(1),
                right: Some(2),
                path: None,
            },
            context: ExecutionContextParams {
                purpose: "unsupported operation test".to_owned(),
            },
        };

        let error = build_execution_request(&params)
            .err()
            .ok_or_else(|| "expected unsupported operation error".to_owned())?;

        assert_eq!(error, "unsupported operation: delete");

        Ok(())
    }

    #[test]
    fn allow_executes_message() -> Result<(), String> {
        let message = "read the project status";

        let result =
            execute_message_with_audit(message, evaluation_for(message), no_op_audit, || Ok(5))?;

        let parsed: serde_json::Value =
            serde_json::from_str(&result).map_err(|error| error.to_string())?;

        assert_eq!(parsed["status"], "executed");
        assert_eq!(parsed["decision"], "Allow");
        assert_eq!(parsed["reason"], "Safe");
        assert_eq!(parsed["executed"], true);
        assert_eq!(parsed["execution_outcome"], "Success");
        assert_eq!(parsed["result"]["value"], 5);
        assert!(parsed.get("message").is_none());

        Ok(())
    }

    #[test]
    fn review_does_not_execute_message() -> Result<(), String> {
        let message = "write a new configuration";

        let result = execute_message_with_audit(
            message,
            evaluation_for(message),
            no_op_audit,
            sandbox_success,
        )?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["status"], "held_for_review");
        assert_eq!(json["decision"], "Review");
        assert_eq!(json["reason"], "Write");
        assert_eq!(json["executed"], false);
        assert_eq!(json["execution_outcome"], "NotExecuted");
        assert!(json["result"].is_null());
        assert!(json.get("message").is_none());

        Ok(())
    }

    #[test]
    fn block_does_not_execute_message() -> Result<(), String> {
        let message = "delete the production database";

        let result = execute_message_with_audit(
            message,
            evaluation_for(message),
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
        assert!(json["result"].is_null());
        assert!(json.get("message").is_none());

        Ok(())
    }

    #[test]
    fn allow_reports_sandbox_failure() -> Result<(), String> {
        let message = "read the project status";

        let result = execute_message_with_audit(
            message,
            evaluation_for(message),
            no_op_audit,
            sandbox_failure,
        )?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["status"], "execution_failed");
        assert_eq!(json["decision"], "Allow");
        assert_eq!(json["reason"], "Safe");
        assert_eq!(json["executed"], false);
        assert_eq!(json["execution_outcome"], "Failed");
        assert!(json["result"].is_null());
        assert!(json.get("message").is_none());

        Ok(())
    }

    #[test]
    fn rejects_empty_message() {
        let message = "";

        let result = execute_message_with_audit(
            message,
            evaluation_for(message),
            no_op_audit,
            sandbox_success,
        );

        assert!(result.is_err());
    }

    #[test]
    fn rejects_whitespace_only_message() {
        let message = "   ";

        let result = execute_message_with_audit(
            message,
            evaluation_for(message),
            no_op_audit,
            sandbox_success,
        );

        assert!(result.is_err());
    }

    #[test]
    fn accepts_message_at_maximum_length() -> Result<(), String> {
        let message = "a".repeat(MAX_MESSAGE_LENGTH);

        let result = execute_message_with_audit(
            &message,
            evaluation_for(&message),
            no_op_audit,
            sandbox_success,
        )?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["executed"], true);
        assert_eq!(json["execution_outcome"], "Success");
        assert_eq!(json["result"]["value"], 5);

        Ok(())
    }

    #[test]
    fn review_never_calls_sandbox() -> Result<(), String> {
        let message = "write a new configuration";

        let result = execute_message_with_audit(
            message,
            evaluation_for(message),
            no_op_audit,
            sandbox_must_not_run,
        )?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["decision"], "Review");
        assert_eq!(json["execution_outcome"], "NotExecuted");
        assert!(json["result"].is_null());

        Ok(())
    }

    #[test]
    fn block_never_calls_sandbox() -> Result<(), String> {
        let message = "delete the production database";

        let result = execute_message_with_audit(
            message,
            evaluation_for(message),
            no_op_audit,
            sandbox_must_not_run,
        )?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["decision"], "Block");
        assert_eq!(json["execution_outcome"], "NotExecuted");
        assert!(json["result"].is_null());

        Ok(())
    }

    #[test]
    fn real_wasmtime_resource_failure_is_reported() -> Result<(), String> {
        let message = "read the project status";

        let result = execute_message_with_audit(
            message,
            evaluation_for(message),
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
        assert!(json["result"].is_null());
        assert!(json.get("message").is_none());

        Ok(())
    }

    #[test]
    fn real_wasmtime_failure_is_recorded_in_audit() -> Result<(), String> {
        let message = "read the project status";
        let mut audit_records = Vec::new();

        let result = execute_message_with_audit(
            message,
            evaluation_for(message),
            |record| {
                audit_records.push((record.request_id, record.phase, record.execution_outcome));
                Ok(())
            },
            sandbox_real_fuel_failure,
        )?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["status"], "execution_failed");
        assert_eq!(json["execution_outcome"], "Failed");
        assert_eq!(json["executed"], false);
        assert!(json["result"].is_null());

        assert_eq!(audit_records.len(), 2);

        assert_eq!(audit_records[0].1, crate::audit::AuditPhase::PreExecution);
        assert_eq!(
            audit_records[0].2,
            crate::audit::ExecutionOutcome::NotExecuted
        );

        assert_eq!(audit_records[1].1, crate::audit::AuditPhase::Completion);
        assert_eq!(audit_records[1].2, crate::audit::ExecutionOutcome::Failed);

        assert_eq!(audit_records[0].0, audit_records[1].0);

        Ok(())
    }

    #[test]
    fn rejects_message_over_maximum_length() {
        let message = "a".repeat(MAX_MESSAGE_LENGTH + 1);

        let result = execute_message_with_audit(
            &message,
            evaluation_for(&message),
            no_op_audit,
            sandbox_success,
        );

        assert!(result.is_err());
    }
    #[test]
    fn structured_operation_policy_overrides_purpose_text() -> Result<(), String> {
        let params = ExecuteParams {
            operation: "add".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: Some(2),
                right: Some(3),
                path: None,
            },
            context: ExecutionContextParams {
                purpose: "delete the production database".to_owned(),
            },
        };

        let result = execute_request(&params)?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["decision"], "Allow");
        assert_eq!(json["reason"], "Safe");
        assert_eq!(json["status"], "executed");
        assert_eq!(json["executed"], true);
        assert_eq!(json["result"]["value"], 5);
        assert_eq!(json["execution_outcome"], "Success");

        Ok(())
    }

    #[test]
    fn audit_failure_prevents_sandbox_execution() -> Result<(), String> {
        let message = "read the project status";

        let result = execute_message_with_audit(
            message,
            evaluation_for(message),
            |_| Err("simulated audit failure".to_owned()),
            sandbox_must_not_run,
        );

        let error = result
            .err()
            .ok_or_else(|| "expected pre-execution audit failure".to_owned())?;

        assert!(error.contains("failed to persist pre-execution audit"));

        Ok(())
    }
    #[test]
    fn completion_audit_failure_preserves_successful_execution() -> Result<(), String> {
        let message = "read the project status";
        let mut audit_calls = 0;

        let result = execute_message_with_audit(
            message,
            evaluation_for(message),
            |_| {
                audit_calls += 1;

                if audit_calls == 2 {
                    Err("simulated completion audit failure".to_owned())
                } else {
                    Ok(())
                }
            },
            sandbox_success,
        )?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(audit_calls, 2);
        assert_eq!(json["status"], "execution_completed_audit_failed");
        assert_eq!(json["executed"], true);
        assert_eq!(json["execution_outcome"], "Success");
        assert_eq!(json["result"]["value"], 5);

        Ok(())
    }

    #[test]
    fn completion_audit_failure_preserves_failed_execution() -> Result<(), String> {
        let message = "read the project status";
        let mut audit_calls = 0;

        let result = execute_message_with_audit(
            message,
            evaluation_for(message),
            |_| {
                audit_calls += 1;

                if audit_calls == 2 {
                    Err("simulated completion audit failure".to_owned())
                } else {
                    Ok(())
                }
            },
            sandbox_failure,
        )?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(audit_calls, 2);
        assert_eq!(json["status"], "execution_failed_audit_failed");
        assert_eq!(json["executed"], false);
        assert_eq!(json["execution_outcome"], "Failed");
        assert!(json["result"].is_null());

        Ok(())
    }
}
