mod audit;
mod execution;
mod filesystem;
mod policy;
mod sandbox;
use audit::{AuditPhase, AuditRecord, ExecutionOutcome, persist_audit};
use execution::{AddArguments, ExecutionRequest, ReadFileArguments, WriteFileArguments};
use filesystem::FileSystemCapability;
use policy::{
    PolicyDecision, PolicyEvaluation, PolicyOperation, block_out_of_scope, evaluate_operation,
};
use sandbox::{SandboxConfig, SandboxExecutor};

#[cfg(test)]
use sandbox::run_infinite_loop_with_fuel;

use rmcp::{
    ServiceExt, handler::server::wrapper::Parameters, schemars, tool, tool_router, transport::stdio,
};

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ExecutionArgumentsParams {
    #[serde(default)]
    #[schemars(with = "i32")]
    left: Option<i32>,

    #[serde(default)]
    #[schemars(with = "i32")]
    right: Option<i32>,

    #[serde(default)]
    #[schemars(with = "String")]
    path: Option<String>,

    #[serde(default)]
    #[schemars(with = "String")]
    content: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ExecutionResult {
    Integer { value: i32 },
    Text { content: String },
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
struct ZyguorGateway {
    filesystem: FileSystemCapability,
}

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
    audit_writer: F,
    sandbox_runner: S,
) -> Result<String, String>
where
    F: FnMut(&AuditRecord<'_>) -> Result<(), String>,
    S: FnOnce() -> Result<ExecutionResult, String>,
{
    execute_message_with_audit_id(
        uuid::Uuid::new_v4(),
        message,
        evaluation,
        audit_writer,
        sandbox_runner,
    )
}

fn execute_message_with_audit_id<F, S>(
    request_id: uuid::Uuid,
    message: &str,
    evaluation: PolicyEvaluation,
    mut audit_writer: F,
    sandbox_runner: S,
) -> Result<String, String>
where
    F: FnMut(&AuditRecord<'_>) -> Result<(), String>,
    S: FnOnce() -> Result<ExecutionResult, String>,
{
    validate_message(message)?;

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
                Ok(result) => ("executed", true, Some(result), ExecutionOutcome::Success),
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
        "write_file" => {
            let path = params
                .arguments
                .path
                .as_ref()
                .ok_or_else(|| "write_file requires arguments.path".to_owned())?;

            if path.trim().is_empty() {
                return Err("write_file path cannot be empty".to_owned());
            }

            let content = params
                .arguments
                .content
                .as_ref()
                .ok_or_else(|| "write_file requires arguments.content".to_owned())?;

            Ok(ExecutionRequest::WriteFile(WriteFileArguments {
                path: path.clone(),
                content: content.clone(),
            }))
        }
        other => Err(format!("unsupported operation: {other}")),
    }
}

fn evaluate_request(
    request: &ExecutionRequest,
    filesystem: &FileSystemCapability,
) -> PolicyEvaluation {
    match request {
        ExecutionRequest::Add(_) => evaluate_operation(PolicyOperation::Add),

        ExecutionRequest::ReadFile(arguments) => {
            if filesystem.resolve_existing_path(&arguments.path).is_err() {
                block_out_of_scope()
            } else {
                evaluate_operation(PolicyOperation::ReadFile)
            }
        }

        ExecutionRequest::WriteFile(arguments) => {
            if filesystem.resolve_write_target(&arguments.path).is_err() {
                block_out_of_scope()
            } else {
                evaluate_operation(PolicyOperation::WriteFile)
            }
        }
    }
}

fn execute_request(
    params: &ExecuteParams,
    filesystem: &FileSystemCapability,
) -> Result<String, String> {
    let request = build_execution_request(params)?;
    let evaluation = evaluate_request(&request, filesystem);
    let executor = SandboxExecutor::new(SandboxConfig::default());

    execute_message_with_audit(
        &params.context.purpose,
        evaluation,
        persist_audit,
        || match request {
            ExecutionRequest::Add(arguments) => executor
                .execute_add(arguments)
                .map(|value| ExecutionResult::Integer { value }),

            ExecutionRequest::ReadFile(arguments) => filesystem
                .read_text_file(&arguments.path)
                .map(|content| ExecutionResult::Text { content }),

            ExecutionRequest::WriteFile(_) => {
                Err("write_file execution requires approval and is not enabled".to_owned())
            }
        },
    )
}
#[tool_router(server_handler)]
impl ZyguorGateway {
    #[tool(
        description = "Evaluates and executes structured requests through Zyguor policy-controlled execution capabilities."
    )]
    fn execute(&self, Parameters(params): Parameters<ExecuteParams>) -> String {
        match execute_request(&params, &self.filesystem) {
            Ok(result) => result,
            Err(error) => format!("GATEWAY_ERROR: {error}"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace_root = std::env::var("ZYGUOR_WORKSPACE_ROOT")
        .map_err(|_| "ZYGUOR_WORKSPACE_ROOT must be configured")?;

    let gateway = ZyguorGateway {
        filesystem: FileSystemCapability::new(workspace_root.into()),
    };

    let service = gateway.serve(stdio()).await?;

    service.waiting().await?;

    Ok(())
}

#[cfg(test)]
mod gateway_tests {
    use super::ExecutionResult;
    use super::{
        AddArguments, ExecuteParams, ExecutionArgumentsParams, ExecutionContextParams,
        ExecutionRequest, FileSystemCapability, MAX_MESSAGE_LENGTH, PolicyDecision,
        PolicyEvaluation, ReadFileArguments, WriteFileArguments, build_execution_request,
        evaluate_request, execute_message_with_audit, execute_message_with_audit_id,
        execute_request, run_infinite_loop_with_fuel,
    };
    use crate::policy::evaluate_message;

    fn no_op_audit(_: &crate::audit::AuditRecord<'_>) -> Result<(), String> {
        Ok(())
    }

    fn evaluation_for(message: &str) -> PolicyEvaluation {
        evaluate_message(message)
    }

    fn sandbox_success() -> Result<ExecutionResult, String> {
        Ok(ExecutionResult::Integer { value: 5 })
    }

    fn sandbox_real_fuel_failure() -> Result<ExecutionResult, String> {
        run_infinite_loop_with_fuel(1_000)?;
        Ok(ExecutionResult::Integer { value: 0 })
    }

    fn sandbox_failure() -> Result<ExecutionResult, String> {
        Err("simulated sandbox failure".to_owned())
    }

    fn sandbox_must_not_run() -> Result<ExecutionResult, String> {
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
                content: None,
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
            ExecutionRequest::ReadFile(_) | ExecutionRequest::WriteFile(_) => {
                panic!("expected Add execution request");
            }
        }

        Ok(())
    }
    #[test]
    fn supplied_request_id_is_preserved_in_response_and_audit() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();
        let message = "write a new configuration";
        let mut audited_request_id = None;

        let result = execute_message_with_audit_id(
            request_id,
            message,
            evaluation_for(message),
            |record| {
                audited_request_id = Some(record.request_id);
                Ok(())
            },
            sandbox_success,
        )?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["request_id"], request_id.to_string());
        assert_eq!(audited_request_id, Some(request_id));
        assert_eq!(json["status"], "held_for_review");
        assert_eq!(json["executed"], false);

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
                content: None,
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
            ExecutionRequest::Add(_) | ExecutionRequest::WriteFile(_) => {
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
                content: None,
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
                content: None,
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
    fn builds_write_file_execution_request() {
        let params = ExecuteParams {
            operation: "write_file".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: None,
                right: None,
                path: Some("notes.txt".to_owned()),
                content: Some("Hello from Zyguor".to_owned()),
            },
            context: ExecutionContextParams {
                purpose: "prepare workspace update".to_owned(),
            },
        };

        let request = build_execution_request(&params).expect("write_file request should be valid");

        match request {
            ExecutionRequest::WriteFile(arguments) => {
                assert_eq!(arguments.path, "notes.txt");
                assert_eq!(arguments.content, "Hello from Zyguor");
            }
            ExecutionRequest::Add(_) | ExecutionRequest::ReadFile(_) => {
                panic!("expected WriteFile execution request");
            }
        }
    }

    #[test]
    fn rejects_write_file_without_path() {
        let params = ExecuteParams {
            operation: "write_file".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: None,
                right: None,
                path: None,
                content: Some("Hello from Zyguor".to_owned()),
            },
            context: ExecutionContextParams {
                purpose: "prepare workspace update".to_owned(),
            },
        };

        let result = build_execution_request(&params);

        assert_eq!(
            result.expect_err("missing path should be rejected"),
            "write_file requires arguments.path"
        );
    }

    #[test]
    fn rejects_write_file_with_blank_path() {
        let params = ExecuteParams {
            operation: "write_file".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: None,
                right: None,
                path: Some("   ".to_owned()),
                content: Some("Hello from Zyguor".to_owned()),
            },
            context: ExecutionContextParams {
                purpose: "prepare workspace update".to_owned(),
            },
        };

        let result = build_execution_request(&params);

        assert_eq!(
            result.expect_err("blank path should be rejected"),
            "write_file path cannot be empty"
        );
    }

    #[test]
    fn rejects_write_file_without_content() {
        let params = ExecuteParams {
            operation: "write_file".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: None,
                right: None,
                path: Some("notes.txt".to_owned()),
                content: None,
            },
            context: ExecutionContextParams {
                purpose: "prepare workspace update".to_owned(),
            },
        };

        let result = build_execution_request(&params);

        assert_eq!(
            result.expect_err("missing content should be rejected"),
            "write_file requires arguments.content"
        );
    }

    #[test]
    fn allows_write_file_with_empty_content() {
        let params = ExecuteParams {
            operation: "write_file".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: None,
                right: None,
                path: Some("empty.txt".to_owned()),
                content: Some(String::new()),
            },
            context: ExecutionContextParams {
                purpose: "prepare empty workspace file".to_owned(),
            },
        };

        let request = build_execution_request(&params).expect("empty content should be valid");

        match request {
            ExecutionRequest::WriteFile(arguments) => {
                assert_eq!(arguments.path, "empty.txt");
                assert!(arguments.content.is_empty());
            }
            ExecutionRequest::Add(_) | ExecutionRequest::ReadFile(_) => {
                panic!("expected WriteFile execution request");
            }
        }
    }

    #[test]
    fn authorizes_add_request() {
        let request = ExecutionRequest::Add(AddArguments { left: 2, right: 3 });
        let filesystem = FileSystemCapability::new(std::env::temp_dir());

        let evaluation = evaluate_request(&request, &filesystem);

        assert_eq!(evaluation.decision, PolicyDecision::Allow);
        assert_eq!(evaluation.reason, crate::policy::PolicyReason::Safe);
    }
    #[test]
    fn blocks_out_of_scope_read_file_request() {
        let filesystem = FileSystemCapability::new(std::env::temp_dir());

        let request = ExecutionRequest::ReadFile(ReadFileArguments {
            path: "../outside.txt".to_owned(),
        });

        let evaluation = evaluate_request(&request, &filesystem);

        assert_eq!(evaluation.decision, PolicyDecision::Block);
        assert_eq!(evaluation.reason, crate::policy::PolicyReason::OutOfScope);
    }
    #[test]
    fn reviews_write_file_inside_workspace() -> Result<(), String> {
        use std::fs;

        let test_root =
            std::env::temp_dir().join(format!("zyguor-write-policy-test-{}", std::process::id()));

        let workspace = test_root.join("workspace");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        let filesystem = FileSystemCapability::new(workspace);

        let request = ExecutionRequest::WriteFile(WriteFileArguments {
            path: "new.txt".to_owned(),
            content: "approved content".to_owned(),
        });

        let evaluation = evaluate_request(&request, &filesystem);

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        assert_eq!(evaluation.decision, PolicyDecision::Review);
        assert_eq!(evaluation.reason, crate::policy::PolicyReason::Write);

        Ok(())
    }

    #[test]
    fn blocks_out_of_scope_write_file_request() {
        let filesystem = FileSystemCapability::new(std::env::temp_dir());

        let request = ExecutionRequest::WriteFile(WriteFileArguments {
            path: "../outside.txt".to_owned(),
            content: "must not be written".to_owned(),
        });

        let evaluation = evaluate_request(&request, &filesystem);

        assert_eq!(evaluation.decision, PolicyDecision::Block);
        assert_eq!(evaluation.reason, crate::policy::PolicyReason::OutOfScope);
    }

    #[test]
    fn normalizes_add_operation() -> Result<(), String> {
        let params = ExecuteParams {
            operation: "  ADD  ".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: Some(3),
                right: Some(6),
                path: None,
                content: None,
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
            ExecutionRequest::ReadFile(_) | ExecutionRequest::WriteFile(_) => {
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
                content: None,
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
        let message = "read project status";

        let result = execute_message_with_audit(
            message,
            evaluation_for(message),
            no_op_audit,
            sandbox_success,
        )?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["status"], "executed");
        assert_eq!(json["decision"], "Allow");
        assert_eq!(json["reason"], "Safe");
        assert_eq!(json["executed"], true);
        assert_eq!(json["execution_outcome"], "Success");
        assert_eq!(json["result"]["type"], "integer");
        assert_eq!(json["result"]["value"], 5);
        assert!(json.get("message").is_none());

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
                content: None,
            },
            context: ExecutionContextParams {
                purpose: "delete the production database".to_owned(),
            },
        };

        let workspace_root = std::env::temp_dir();
        let filesystem = FileSystemCapability::new(workspace_root);
        let result = execute_request(&params, &filesystem)?;

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
    fn read_file_executes_inside_workspace() -> Result<(), String> {
        let workspace_root = std::env::temp_dir().join(format!(
            "zyguor-read-file-integration-{}",
            std::process::id()
        ));

        std::fs::create_dir_all(&workspace_root)
            .map_err(|error| format!("failed to create test workspace: {error}"))?;

        let file_path = workspace_root.join("hello.txt");

        std::fs::write(&file_path, "Hello from Zyguor")
            .map_err(|error| format!("failed to write test file: {error}"))?;

        let filesystem = FileSystemCapability::new(workspace_root.clone());

        let params = ExecuteParams {
            operation: "read_file".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: None,
                right: None,
                path: Some("hello.txt".to_owned()),
                content: None,
            },
            context: ExecutionContextParams {
                purpose: "read an approved workspace file".to_owned(),
            },
        };

        let result = execute_request(&params, &filesystem)?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["decision"], "Allow");
        assert_eq!(json["reason"], "Safe");
        assert_eq!(json["status"], "executed");
        assert_eq!(json["executed"], true);
        assert_eq!(json["execution_outcome"], "Success");
        assert_eq!(json["result"]["type"], "text");
        assert_eq!(json["result"]["content"], "Hello from Zyguor");

        std::fs::remove_dir_all(&workspace_root)
            .map_err(|error| format!("failed to remove test workspace: {error}"))?;

        Ok(())
    }
    #[test]
    fn read_file_rejects_path_outside_workspace() -> Result<(), String> {
        let workspace_root =
            std::env::temp_dir().join(format!("zyguor-read-file-escape-{}", std::process::id()));

        std::fs::create_dir_all(&workspace_root)
            .map_err(|error| format!("failed to create test workspace: {error}"))?;

        let filesystem = FileSystemCapability::new(workspace_root.clone());

        let params = ExecuteParams {
            operation: "read_file".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: None,
                right: None,
                path: Some("../outside.txt".to_owned()),
                content: None,
            },
            context: ExecutionContextParams {
                purpose: "attempt to read outside the approved workspace".to_owned(),
            },
        };

        let result = execute_request(&params, &filesystem)?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["decision"], "Block");
        assert_eq!(json["reason"], "OutOfScope");
        assert_eq!(json["status"], "blocked");
        assert_eq!(json["executed"], false);
        assert_eq!(json["execution_outcome"], "NotExecuted");
        assert!(json["result"].is_null());

        std::fs::remove_dir_all(&workspace_root)
            .map_err(|error| format!("failed to remove test workspace: {error}"))?;

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
