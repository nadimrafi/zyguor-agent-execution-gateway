mod audit;
mod cargo_test;
mod config;
mod execution;
mod filesystem;
mod git;
mod http;
mod http_execution;
mod pending_review;
mod policy;
mod sandbox;
use audit::{AuditPhase, AuditRecord, ExecutionOutcome, persist_audit};
use cargo_test::{CargoTestExecutor, CargoTestResult};
use config::{GatewayConfig, resolve_gateway_config};
use execution::{
    AddArguments, ExecutionRequest, HttpMethod, HttpRequestArguments, ReadFileArguments,
    WriteFileArguments,
};
use filesystem::FileSystemCapability;
use git::read_git_status;
use http::{ValidatedHttpUrl, validate_http_destination};
use http_execution::{HttpExecutionResult, HttpExecutor};
use pending_review::{PendingReview, PendingReviewStore};
use policy::{
    PolicyDecision, PolicyEvaluation, PolicyOperation, PolicyReason, block_out_of_scope,
    evaluate_operation_with_config,
};
use sandbox::SandboxExecutor;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

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
    #[serde(default)]
    #[schemars(with = "String")]
    method: Option<String>,

    #[serde(default)]
    #[schemars(with = "String")]
    url: Option<String>,

    #[serde(default)]
    #[schemars(with = "String")]
    body: Option<String>,
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
    CargoTest { result: CargoTestResult },
    Http { result: HttpExecutionResult },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ReviewedOperationResult {
    Success(Option<ExecutionResult>),

    FailedWithResult {
        error: String,
        result: ExecutionResult,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReviewedExecutionOutcome {
    Success,
    SuccessWithResult(ExecutionResult),

    ExecutionFailed(String),

    ExecutionFailedWithResult {
        error: String,
        result: ExecutionResult,
    },

    CompletionAuditFailed {
        execution_outcome: ExecutionOutcome,
        error: String,
        result: Option<ExecutionResult>,
    },
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
    pending_reviews: Arc<Mutex<PendingReviewStore>>,
    config: Arc<GatewayConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdminCommand {
    Approve { request_id: uuid::Uuid },
    Reject { request_id: uuid::Uuid },
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum AdminOutcome {
    Approved {
        request_id: uuid::Uuid,
    },
    Rejected {
        pending: PendingReview,
    },
    WriteFailed {
        request_id: uuid::Uuid,
        error: String,
    },
    CargoTestCompleted {
        request_id: uuid::Uuid,
        result: CargoTestResult,
    },
    CargoTestFailed {
        request_id: uuid::Uuid,
        result: CargoTestResult,
    },
    CompletionAuditFailed {
        request_id: uuid::Uuid,
        execution_outcome: ExecutionOutcome,
        error: String,
        result: Option<ExecutionResult>,
    },
    CargoTestExecutionFailed {
        request_id: uuid::Uuid,
        error: String,
    },
    HttpPostCompleted {
        request_id: uuid::Uuid,
        result: HttpExecutionResult,
    },
    HttpPostFailed {
        request_id: uuid::Uuid,
        result: HttpExecutionResult,
    },
    HttpPostExecutionFailed {
        request_id: uuid::Uuid,
        error: String,
    },
}
fn format_admin_outcome_response(outcome: &AdminOutcome) -> String {
    match outcome {
        AdminOutcome::Approved { request_id } => {
            format!("OK APPROVED {request_id}\n")
        }
        AdminOutcome::Rejected { pending } => {
            format!("OK REJECTED {}\n", pending.request_id)
        }
        AdminOutcome::WriteFailed { request_id, error } => {
            format!("ERROR WRITE_FAILED {request_id} {error}\n")
        }
        AdminOutcome::CargoTestExecutionFailed { request_id, error } => {
            format!("ERROR CARGO_TEST_EXECUTION_FAILED {request_id} {error}\n")
        }
        AdminOutcome::CargoTestCompleted { request_id, result } => {
            match serde_json::to_string(result) {
                Ok(json) => format!("OK CARGO_TEST_COMPLETED {request_id} {json}\n"),
                Err(error) => {
                    format!("ERROR RESPONSE_SERIALIZATION_FAILED {request_id} {error}\n")
                }
            }
        }

        AdminOutcome::CargoTestFailed { request_id, result } => {
            match serde_json::to_string(result) {
                Ok(json) => format!("ERROR CARGO_TEST_FAILED {request_id} {json}\n"),
                Err(error) => {
                    format!("ERROR RESPONSE_SERIALIZATION_FAILED {request_id} {error}\n")
                }
            }
        }

        AdminOutcome::HttpPostExecutionFailed { request_id, error } => {
            format!("ERROR HTTP_POST_EXECUTION_FAILED {request_id} {error}\n")
        }

        AdminOutcome::HttpPostCompleted { request_id, result } => {
            match serde_json::to_string(result) {
                Ok(json) => format!("OK HTTP_POST_COMPLETED {request_id} {json}\n"),
                Err(error) => {
                    format!("ERROR RESPONSE_SERIALIZATION_FAILED {request_id} {error}\n")
                }
            }
        }

        AdminOutcome::HttpPostFailed { request_id, result } => {
            match serde_json::to_string(result) {
                Ok(json) => format!("ERROR HTTP_POST_FAILED {request_id} {json}\n"),
                Err(error) => {
                    format!("ERROR RESPONSE_SERIALIZATION_FAILED {request_id} {error}\n")
                }
            }
        }
        AdminOutcome::CompletionAuditFailed {
            request_id, error, ..
        } => {
            format!("ERROR COMPLETION_AUDIT_FAILED {request_id} {error}\n")
        }
    }
}

fn parse_admin_command(input: &str) -> Result<AdminCommand, String> {
    let trimmed = input.trim();

    let mut parts = trimmed.split_whitespace();

    let command = parts
        .next()
        .ok_or_else(|| "admin command cannot be empty".to_owned())?;

    let request_id = parts
        .next()
        .ok_or_else(|| "admin command requires a request ID".to_owned())?;

    if parts.next().is_some() {
        return Err("admin command contains unexpected arguments".to_owned());
    }

    let request_id = uuid::Uuid::parse_str(request_id)
        .map_err(|_| "admin command contains an invalid request ID".to_owned())?;

    match command {
        "APPROVE" => Ok(AdminCommand::Approve { request_id }),
        "REJECT" => Ok(AdminCommand::Reject { request_id }),
        _ => Err("unsupported admin command".to_owned()),
    }
}

const MAX_MESSAGE_LENGTH: usize = 4096;
const MAX_ADMIN_COMMAND_LENGTH: usize = 256;

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
        "http_request" => {
            let method = params
                .arguments
                .method
                .as_ref()
                .ok_or_else(|| "http_request requires arguments.method".to_owned())?;

            let method = match method.trim().to_ascii_lowercase().as_str() {
                "get" => HttpMethod::Get,
                "post" => HttpMethod::Post,
                other => {
                    return Err(format!(
                        "unsupported HTTP method: {other}; expected get or post"
                    ));
                }
            };

            let url = params
                .arguments
                .url
                .as_ref()
                .ok_or_else(|| "http_request requires arguments.url".to_owned())?;

            if url.trim().is_empty() {
                return Err("http_request URL cannot be empty".to_owned());
            }

            if method == HttpMethod::Get && params.arguments.body.is_some() {
                return Err("HTTP GET request must not include a body".to_owned());
            }

            Ok(ExecutionRequest::HttpRequest(HttpRequestArguments {
                method,
                url: url.clone(),
                body: params.arguments.body.clone(),
            }))
        }
        "git_status" => Ok(ExecutionRequest::GitStatus),
        "run_cargo_test" => Ok(ExecutionRequest::RunCargoTest),
        other => Err(format!("unsupported operation: {other}")),
    }
}

fn evaluate_request_with_config(
    request: &ExecutionRequest,
    filesystem: &FileSystemCapability,
    config: &GatewayConfig,
) -> PolicyEvaluation {
    match request {
        ExecutionRequest::Add(_) => {
            evaluate_operation_with_config(PolicyOperation::Add, &config.policy)
        }

        ExecutionRequest::HttpRequest(arguments) => {
            if validate_http_destination(&arguments.url, &config.http.allowed_hosts).is_err() {
                return block_out_of_scope();
            }

            match arguments.method {
                HttpMethod::Get => {
                    evaluate_operation_with_config(PolicyOperation::HttpGet, &config.policy)
                }

                HttpMethod::Post => {
                    evaluate_operation_with_config(PolicyOperation::HttpPost, &config.policy)
                }
            }
        }

        ExecutionRequest::RunCargoTest => {
            evaluate_operation_with_config(PolicyOperation::RunCargoTest, &config.policy)
        }

        ExecutionRequest::ReadFile(arguments) => {
            if filesystem.resolve_existing_path(&arguments.path).is_err() {
                block_out_of_scope()
            } else {
                evaluate_operation_with_config(PolicyOperation::ReadFile, &config.policy)
            }
        }

        ExecutionRequest::WriteFile(arguments) => {
            if filesystem.resolve_write_target(&arguments.path).is_err() {
                block_out_of_scope()
            } else {
                evaluate_operation_with_config(PolicyOperation::WriteFile, &config.policy)
            }
        }

        ExecutionRequest::GitStatus => {
            evaluate_operation_with_config(PolicyOperation::GitStatus, &config.policy)
        }
    }
}

fn reject_pending_request(
    request_id: uuid::Uuid,
    pending_reviews: &Arc<Mutex<PendingReviewStore>>,
) -> Result<PendingReview, String> {
    let mut store = pending_reviews
        .lock()
        .map_err(|_| "pending review store lock poisoned".to_owned())?;

    store
        .take(&request_id)
        .ok_or_else(|| "pending review request not found".to_owned())
}
fn inspect_pending_request(
    request_id: uuid::Uuid,
    pending_reviews: &Arc<Mutex<PendingReviewStore>>,
) -> Result<PendingReview, String> {
    let store = pending_reviews
        .lock()
        .map_err(|_| "pending review store lock poisoned".to_owned())?;

    store
        .get(&request_id)
        .cloned()
        .ok_or_else(|| "pending review request not found".to_owned())
}
fn restore_claimed_request(
    pending: PendingReview,
    pending_reviews: &Arc<Mutex<PendingReviewStore>>,
) -> Result<(), String> {
    let mut store = pending_reviews
        .lock()
        .map_err(|_| "pending review store lock poisoned".to_owned())?;

    store.restore_claimed(pending)
}
fn review_reason_for_request(request: &ExecutionRequest) -> Result<PolicyReason, String> {
    match request {
        ExecutionRequest::WriteFile(_) => Ok(PolicyReason::Write),

        ExecutionRequest::RunCargoTest => Ok(PolicyReason::CodeExecution),

        ExecutionRequest::HttpRequest(arguments) if arguments.method == HttpMethod::Post => {
            Ok(PolicyReason::ExternalWrite)
        }

        _ => Err("request is not eligible for human review".to_owned()),
    }
}
fn revalidate_pending_request_with_config(
    pending: &PendingReview,
    filesystem: &FileSystemCapability,
    config: &GatewayConfig,
) -> Result<(), String> {
    match &pending.request {
        ExecutionRequest::WriteFile(arguments) => filesystem
            .revalidate_write_target(&arguments.path)
            .map_err(|error| format!("pending write target is no longer valid: {error}")),

        ExecutionRequest::RunCargoTest => filesystem
            .resolve_existing_path("Cargo.toml")
            .map(|_| ())
            .map_err(|error| format!("pending Cargo test workspace is no longer valid: {error}")),

        ExecutionRequest::HttpRequest(arguments) if arguments.method == HttpMethod::Post => {
            validate_http_destination(&arguments.url, &config.http.allowed_hosts)
                .map(|_| ())
                .map_err(|error| {
                    format!("pending HTTP POST destination is no longer valid: {error}")
                })
        }

        _ => Err("pending request is not eligible for approval".to_owned()),
    }
}

fn write_approval_audit<F>(pending: &PendingReview, mut audit_writer: F) -> Result<(), String>
where
    F: FnMut(&AuditRecord<'_>) -> Result<(), String>,
{
    let reason = review_reason_for_request(&pending.request)?;

    let record = AuditRecord::new(
        pending.request_id,
        &pending.purpose,
        PolicyDecision::Review,
        reason,
        AuditPhase::Approval,
        ExecutionOutcome::NotExecuted,
    )
    .map_err(|error| format!("failed to create approval audit record: {error}"))?;

    audit_writer(&record).map_err(|error| format!("failed to persist approval audit: {error}"))
}

fn write_rejection_audit<F>(pending: &PendingReview, mut audit_writer: F) -> Result<(), String>
where
    F: FnMut(&AuditRecord<'_>) -> Result<(), String>,
{
    let record = AuditRecord::new(
        pending.request_id,
        &pending.purpose,
        PolicyDecision::Review,
        review_reason_for_request(&pending.request)?,
        AuditPhase::Rejection,
        ExecutionOutcome::NotExecuted,
    )
    .map_err(|error| format!("failed to create rejection audit record: {error}"))?;

    audit_writer(&record).map_err(|error| format!("failed to persist rejection audit: {error}"))
}
fn audit_claimed_rejection<F>(
    claimed: &PendingReview,
    pending_reviews: &Arc<Mutex<PendingReviewStore>>,
    audit_writer: F,
) -> Result<(), String>
where
    F: FnMut(&AuditRecord<'_>) -> Result<(), String>,
{
    if let Err(audit_error) = write_rejection_audit(claimed, audit_writer) {
        restore_claimed_request(claimed.clone(), pending_reviews).map_err(|restore_error| {
            format!("{audit_error}; failed to restore claimed request: {restore_error}")
        })?;

        return Err(audit_error);
    }

    Ok(())
}

fn audit_claimed_approval<F>(
    claimed: &PendingReview,
    pending_reviews: &Arc<Mutex<PendingReviewStore>>,
    audit_writer: F,
) -> Result<(), String>
where
    F: FnMut(&AuditRecord<'_>) -> Result<(), String>,
{
    if let Err(audit_error) = write_approval_audit(claimed, audit_writer) {
        restore_claimed_request(claimed.clone(), pending_reviews).map_err(|restore_error| {
            format!("{audit_error}; failed to restore claimed request: {restore_error}")
        })?;

        return Err(audit_error);
    }

    Ok(())
}
fn execute_cargo_test_with_config(
    filesystem: &FileSystemCapability,
    config: &GatewayConfig,
) -> Result<ReviewedOperationResult, String> {
    let executor = CargoTestExecutor::new(config.cargo_test);
    let result = executor.run(filesystem.workspace_root())?;

    let execution_result = ExecutionResult::CargoTest {
        result: result.clone(),
    };

    if result.success {
        Ok(ReviewedOperationResult::Success(Some(execution_result)))
    } else {
        let error = if result.timed_out {
            "cargo test timed out".to_owned()
        } else {
            match result.exit_code {
                Some(code) => format!("cargo test exited with status {code}"),
                None => "cargo test failed without an exit status".to_owned(),
            }
        };

        Ok(ReviewedOperationResult::FailedWithResult {
            error,
            result: execution_result,
        })
    }
}
fn execute_http_post_with_config(
    arguments: &HttpRequestArguments,
    config: &GatewayConfig,
) -> Result<ReviewedOperationResult, String> {
    if arguments.method != HttpMethod::Post {
        return Err("reviewed HTTP execution requires POST".to_owned());
    }
    let destination = validate_http_destination(&arguments.url, &config.http.allowed_hosts)?;

    let executor = HttpExecutor::new(config.http.execution)?;

    let result = executor.execute(HttpMethod::Post, &destination, arguments.body.as_deref())?;

    let execution_result = ExecutionResult::Http {
        result: result.clone(),
    };

    if (200..400).contains(&result.status_code) {
        Ok(ReviewedOperationResult::Success(Some(execution_result)))
    } else {
        Ok(ReviewedOperationResult::FailedWithResult {
            error: format!("HTTP POST returned status {}", result.status_code),
            result: execution_result,
        })
    }
}

fn execute_reviewed_action<F, W>(
    pending: &PendingReview,
    mut audit_writer: F,
    operation: W,
) -> Result<ReviewedExecutionOutcome, String>
where
    F: FnMut(&AuditRecord<'_>) -> Result<(), String>,
    W: FnOnce() -> Result<ReviewedOperationResult, String>,
{
    let reason = review_reason_for_request(&pending.request)?;

    let pre_execution_record = AuditRecord::new(
        pending.request_id,
        &pending.purpose,
        PolicyDecision::Review,
        reason,
        AuditPhase::PreExecution,
        ExecutionOutcome::NotExecuted,
    )
    .map_err(|error| format!("failed to create pre-execution audit record: {error}"))?;

    audit_writer(&pre_execution_record)
        .map_err(|error| format!("failed to persist pre-execution audit: {error}"))?;

    let execution_result = operation();

    let execution_outcome = match &execution_result {
        Ok(ReviewedOperationResult::Success(_)) => ExecutionOutcome::Success,

        Ok(ReviewedOperationResult::FailedWithResult { .. }) | Err(_) => ExecutionOutcome::Failed,
    };
    let preserved_result = match &execution_result {
        Ok(ReviewedOperationResult::Success(Some(result))) => Some(result.clone()),

        Ok(ReviewedOperationResult::FailedWithResult { result, .. }) => Some(result.clone()),

        Ok(ReviewedOperationResult::Success(None)) | Err(_) => None,
    };

    let completion_record = match AuditRecord::new(
        pending.request_id,
        &pending.purpose,
        PolicyDecision::Review,
        reason,
        AuditPhase::Completion,
        execution_outcome,
    ) {
        Ok(record) => record,
        Err(error) => {
            return Ok(ReviewedExecutionOutcome::CompletionAuditFailed {
                execution_outcome,
                error: format!("failed to create completion audit record: {error}"),
                result: preserved_result.clone(),
            });
        }
    };

    if let Err(error) = audit_writer(&completion_record) {
        return Ok(ReviewedExecutionOutcome::CompletionAuditFailed {
            execution_outcome,
            error,
            result: preserved_result,
        });
    }

    match execution_result {
        Ok(ReviewedOperationResult::Success(Some(result))) => {
            Ok(ReviewedExecutionOutcome::SuccessWithResult(result))
        }

        Ok(ReviewedOperationResult::Success(None)) => Ok(ReviewedExecutionOutcome::Success),

        Ok(ReviewedOperationResult::FailedWithResult { error, result }) => {
            Ok(ReviewedExecutionOutcome::ExecutionFailedWithResult { error, result })
        }

        Err(error) => Ok(ReviewedExecutionOutcome::ExecutionFailed(error)),
    }
}
fn execute_approved_write<F, W>(
    pending: &PendingReview,
    audit_writer: F,
    write_operation: W,
) -> Result<ReviewedExecutionOutcome, String>
where
    F: FnMut(&AuditRecord<'_>) -> Result<(), String>,
    W: FnOnce() -> Result<(), String>,
{
    execute_reviewed_action(pending, audit_writer, || {
        write_operation().map(|()| ReviewedOperationResult::Success(None))
    })
}
fn execute_claimed_reviewed_action<F, W>(
    claimed: &PendingReview,
    pending_reviews: &Arc<Mutex<PendingReviewStore>>,
    audit_writer: F,
    operation: W,
) -> Result<ReviewedExecutionOutcome, String>
where
    F: FnMut(&AuditRecord<'_>) -> Result<(), String>,
    W: FnOnce() -> Result<ReviewedOperationResult, String>,
{
    match execute_reviewed_action(claimed, audit_writer, operation) {
        Ok(outcome) => Ok(outcome),

        Err(execution_error) => {
            restore_claimed_request(claimed.clone(), pending_reviews).map_err(|restore_error| {
                format!("{execution_error}; failed to restore claimed request: {restore_error}")
            })?;

            Err(execution_error)
        }
    }
}
fn execute_claimed_write<F, W>(
    claimed: &PendingReview,
    pending_reviews: &Arc<Mutex<PendingReviewStore>>,
    audit_writer: F,
    write_operation: W,
) -> Result<ReviewedExecutionOutcome, String>
where
    F: FnMut(&AuditRecord<'_>) -> Result<(), String>,
    W: FnOnce() -> Result<(), String>,
{
    match execute_approved_write(claimed, audit_writer, write_operation) {
        Ok(outcome) => Ok(outcome),
        Err(execution_error) => {
            restore_claimed_request(claimed.clone(), pending_reviews).map_err(|restore_error| {
                format!("{execution_error}; failed to restore claimed request: {restore_error}")
            })?;

            Err(execution_error)
        }
    }
}
fn handle_admin_command_with_http_runner<H>(
    command: AdminCommand,
    pending_reviews: &Arc<Mutex<PendingReviewStore>>,
    filesystem: &FileSystemCapability,
    config: &GatewayConfig,
    http_post_runner: H,
) -> Result<AdminOutcome, String>
where
    H: FnOnce(&HttpRequestArguments) -> Result<ReviewedOperationResult, String>,
{
    match command {
        AdminCommand::Approve { request_id } => {
            let pending = inspect_pending_request(request_id, pending_reviews)?;

            revalidate_pending_request_with_config(&pending, filesystem, config)?;

            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            let claimed = store.claim(&request_id)?;

            drop(store);

            audit_claimed_approval(&claimed, pending_reviews, persist_audit)?;

            match &claimed.request {
                ExecutionRequest::WriteFile(arguments) => {
                    let outcome =
                        execute_claimed_write(&claimed, pending_reviews, persist_audit, || {
                            filesystem.write_text_file(&arguments.path, &arguments.content)
                        })?;
                    match outcome {
                        ReviewedExecutionOutcome::Success => {
                            Ok(AdminOutcome::Approved { request_id })
                        }
                        ReviewedExecutionOutcome::SuccessWithResult(_) => {
                            Err("write approval returned an unexpected execution result".to_owned())
                        }
                        ReviewedExecutionOutcome::ExecutionFailed(error) => {
                            Ok(AdminOutcome::WriteFailed { request_id, error })
                        }
                        ReviewedExecutionOutcome::ExecutionFailedWithResult { .. } => {
                            Err("write approval returned an unexpected execution result".to_owned())
                        }
                        ReviewedExecutionOutcome::CompletionAuditFailed {
                            execution_outcome,
                            error,
                            ..
                        } => Ok(AdminOutcome::CompletionAuditFailed {
                            request_id,
                            execution_outcome,
                            error,
                            result: None,
                        }),
                    }
                }

                ExecutionRequest::RunCargoTest => {
                    let outcome = execute_claimed_reviewed_action(
                        &claimed,
                        pending_reviews,
                        persist_audit,
                        || execute_cargo_test_with_config(filesystem, config),
                    )?;

                    match outcome {
                        ReviewedExecutionOutcome::SuccessWithResult(
                            ExecutionResult::CargoTest { result },
                        ) => Ok(AdminOutcome::CargoTestCompleted { request_id, result }),

                        ReviewedExecutionOutcome::ExecutionFailedWithResult {
                            result: ExecutionResult::CargoTest { result },
                            ..
                        } => Ok(AdminOutcome::CargoTestFailed { request_id, result }),

                        ReviewedExecutionOutcome::ExecutionFailed(error) => {
                            Ok(AdminOutcome::CargoTestExecutionFailed { request_id, error })
                        }

                        ReviewedExecutionOutcome::CompletionAuditFailed {
                            execution_outcome,
                            error,
                            result,
                        } => Ok(AdminOutcome::CompletionAuditFailed {
                            request_id,
                            execution_outcome,
                            error,
                            result,
                        }),

                        ReviewedExecutionOutcome::Success => {
                            Err("cargo test approval returned no execution result".to_owned())
                        }

                        ReviewedExecutionOutcome::SuccessWithResult(_)
                        | ReviewedExecutionOutcome::ExecutionFailedWithResult { .. } => Err(
                            "cargo test approval returned an unexpected execution result"
                                .to_owned(),
                        ),
                    }
                }
                ExecutionRequest::HttpRequest(arguments)
                    if arguments.method == HttpMethod::Post =>
                {
                    let outcome = execute_claimed_reviewed_action(
                        &claimed,
                        pending_reviews,
                        persist_audit,
                        || http_post_runner(arguments),
                    )?;

                    match outcome {
                        ReviewedExecutionOutcome::SuccessWithResult(ExecutionResult::Http {
                            result,
                        }) => Ok(AdminOutcome::HttpPostCompleted { request_id, result }),

                        ReviewedExecutionOutcome::ExecutionFailedWithResult {
                            result: ExecutionResult::Http { result },
                            ..
                        } => Ok(AdminOutcome::HttpPostFailed { request_id, result }),

                        ReviewedExecutionOutcome::ExecutionFailed(error) => {
                            Ok(AdminOutcome::HttpPostExecutionFailed { request_id, error })
                        }

                        ReviewedExecutionOutcome::CompletionAuditFailed {
                            execution_outcome,
                            error,
                            result,
                        } => Ok(AdminOutcome::CompletionAuditFailed {
                            request_id,
                            execution_outcome,
                            error,
                            result,
                        }),

                        ReviewedExecutionOutcome::Success => {
                            Err("HTTP POST approval returned no execution result".to_owned())
                        }

                        ReviewedExecutionOutcome::SuccessWithResult(_)
                        | ReviewedExecutionOutcome::ExecutionFailedWithResult { .. } => {
                            Err("HTTP POST approval returned an unexpected execution result"
                                .to_owned())
                        }
                    }
                }

                _ => Err("claimed request is not eligible for approval".to_owned()),
            }
        }
        AdminCommand::Reject { request_id } => {
            let pending = reject_pending_request(request_id, pending_reviews)?;

            audit_claimed_rejection(&pending, pending_reviews, persist_audit)?;

            Ok(AdminOutcome::Rejected { pending })
        }
    }
}
fn handle_admin_command_with_config(
    command: AdminCommand,
    pending_reviews: &Arc<Mutex<PendingReviewStore>>,
    filesystem: &FileSystemCapability,
    config: &GatewayConfig,
) -> Result<AdminOutcome, String> {
    handle_admin_command_with_http_runner(
        command,
        pending_reviews,
        filesystem,
        config,
        |arguments| execute_http_post_with_config(arguments, config),
    )
}

fn execute_request_with_http_runner<H>(
    params: &ExecuteParams,
    filesystem: &FileSystemCapability,
    pending_reviews: &Arc<Mutex<PendingReviewStore>>,
    config: &GatewayConfig,
    http_runner: H,
) -> Result<String, String>
where
    H: FnOnce(HttpMethod, &ValidatedHttpUrl, Option<&str>) -> Result<HttpExecutionResult, String>,
{
    let request = build_execution_request(params)?;
    let evaluation = evaluate_request_with_config(&request, filesystem, config);
    let request_id = uuid::Uuid::new_v4();

    if evaluation.decision == PolicyDecision::Review {
        let pending =
            PendingReview::new(request_id, request.clone(), params.context.purpose.clone());

        let mut store = pending_reviews
            .lock()
            .map_err(|_| "pending review store lock poisoned".to_owned())?;

        store.insert(pending)?;
    }

    let executor = SandboxExecutor::new(config.sandbox);

    execute_message_with_audit_id(
        request_id,
        &params.context.purpose,
        evaluation,
        persist_audit,
        || match request {
            ExecutionRequest::HttpRequest(arguments) => match arguments.method {
                HttpMethod::Get => {
                    let destination =
                        validate_http_destination(&arguments.url, &config.http.allowed_hosts)?;

                    http_runner(HttpMethod::Get, &destination, arguments.body.as_deref())
                        .map(|result| ExecutionResult::Http { result })
                }

                HttpMethod::Post => {
                    Err("http POST execution requires approval and is not enabled".to_owned())
                }
            },

            ExecutionRequest::Add(arguments) => executor
                .execute_add(arguments)
                .map(|value| ExecutionResult::Integer { value }),

            ExecutionRequest::ReadFile(arguments) => filesystem
                .read_text_file(&arguments.path)
                .map(|content| ExecutionResult::Text { content }),

            ExecutionRequest::GitStatus => {
                let status = read_git_status(filesystem.workspace_root())?;

                serde_json::to_string(&status)
                    .map(|content| ExecutionResult::Text { content })
                    .map_err(|error| format!("failed to serialize Git status result: {error}"))
            }

            ExecutionRequest::WriteFile(_) => {
                Err("write_file execution requires approval and is not enabled".to_owned())
            }

            ExecutionRequest::RunCargoTest => {
                Err("run_cargo_test execution requires approval and is not enabled".to_owned())
            }
        },
    )
}

fn execute_request_with_config(
    params: &ExecuteParams,
    filesystem: &FileSystemCapability,
    pending_reviews: &Arc<Mutex<PendingReviewStore>>,
    config: &GatewayConfig,
) -> Result<String, String> {
    execute_request_with_http_runner(
        params,
        filesystem,
        pending_reviews,
        config,
        |method, destination, body| {
            let executor = HttpExecutor::new(config.http.execution)?;

            executor.execute(method, destination, body)
        },
    )
}

#[tool_router(server_handler)]
impl ZyguorGateway {
    #[tool(
        description = "Evaluates and executes structured requests through Zyguor policy-controlled execution capabilities."
    )]
    fn execute(&self, Parameters(params): Parameters<ExecuteParams>) -> String {
        match execute_request_with_config(
            &params,
            &self.filesystem,
            &self.pending_reviews,
            self.config.as_ref(),
        ) {
            Ok(result) => result,
            Err(error) => format!("GATEWAY_ERROR: {error}"),
        }
    }
}

async fn create_admin_listener(socket_path: &Path) -> Result<UnixListener, String> {
    if socket_path.exists() {
        return Err("admin socket path already exists".to_owned());
    }

    let listener = UnixListener::bind(socket_path)
        .map_err(|error| format!("failed to create admin socket: {error}"))?;

    let permissions = std::fs::Permissions::from_mode(0o600);

    std::fs::set_permissions(socket_path, permissions)
        .map_err(|error| format!("failed to secure admin socket permissions: {error}"))?;

    Ok(listener)
}
async fn handle_admin_connection(
    stream: tokio::net::UnixStream,
    pending_reviews: &Arc<Mutex<PendingReviewStore>>,
    filesystem: &FileSystemCapability,
    config: &GatewayConfig,
) -> Result<AdminOutcome, String> {
    let reader = BufReader::new(stream);
    let mut reader = reader.take((MAX_ADMIN_COMMAND_LENGTH + 1) as u64);
    let mut input = String::new();

    let bytes_read = reader
        .read_line(&mut input)
        .await
        .map_err(|error| format!("failed to read admin command: {error}"))?;

    if bytes_read == 0 {
        return Err("admin connection closed without a command".to_owned());
    }

    if input.len() > MAX_ADMIN_COMMAND_LENGTH {
        let error = "admin command exceeds maximum length".to_owned();
        let response = format!("ERROR {error}\n");

        reader
            .get_mut()
            .write_all(response.as_bytes())
            .await
            .map_err(|write_error| {
                format!("{error}; failed to write admin error response: {write_error}")
            })?;

        return Err(error);
    }

    let result = match parse_admin_command(&input) {
        Ok(command) => {
            handle_admin_command_with_config(command, pending_reviews, filesystem, config)
        }
        Err(error) => Err(error),
    };

    match result {
        Ok(outcome) => {
            let response = format_admin_outcome_response(&outcome);

            reader
                .get_mut()
                .write_all(response.as_bytes())
                .await
                .map_err(|error| format!("failed to write admin response: {error}"))?;

            Ok(outcome)
        }
        Err(error) => {
            let response = format!("ERROR {error}\n");

            reader
                .get_mut()
                .write_all(response.as_bytes())
                .await
                .map_err(|write_error| {
                    format!("{error}; failed to write admin error response: {write_error}")
                })?;

            Err(error)
        }
    }
}
async fn run_admin_listener(
    listener: UnixListener,
    pending_reviews: Arc<Mutex<PendingReviewStore>>,
    filesystem: FileSystemCapability,
    config: Arc<GatewayConfig>,
) -> Result<(), String> {
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|error| format!("failed to accept admin connection: {error}"))?;

        if let Err(error) =
            handle_admin_connection(stream, &pending_reviews, &filesystem, &config).await
        {
            eprintln!("admin command rejected: {error}");
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace_root = std::env::var("ZYGUOR_WORKSPACE_ROOT")
        .map_err(|_| "ZYGUOR_WORKSPACE_ROOT must be configured")?;

    let admin_socket_path = std::env::var("ZYGUOR_ADMIN_SOCKET")
        .map_err(|_| "ZYGUOR_ADMIN_SOCKET must be configured")?;

    let config_path = match std::env::var("ZYGUOR_CONFIG_PATH") {
        Ok(path) => Some(path),

        Err(std::env::VarError::NotPresent) => None,

        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("ZYGUOR_CONFIG_PATH must contain valid UTF-8".into());
        }
    };

    let config = resolve_gateway_config(config_path.as_deref().map(Path::new))
        .map_err(|error| format!("failed to resolve gateway configuration: {error}"))?;

    let config = Arc::new(config);

    let admin_listener = create_admin_listener(Path::new(&admin_socket_path)).await?;

    let pending_reviews = Arc::new(Mutex::new(PendingReviewStore::new()));

    let filesystem = FileSystemCapability::try_new(workspace_root.into())?;

    let gateway = ZyguorGateway {
        filesystem: filesystem.clone(),
        pending_reviews: Arc::clone(&pending_reviews),
        config: Arc::clone(&config),
    };

    let admin_task = tokio::spawn(run_admin_listener(
        admin_listener,
        Arc::clone(&pending_reviews),
        filesystem,
        Arc::clone(&config),
    ));

    let service = gateway.serve(stdio()).await?;

    service.waiting().await?;

    admin_task.abort();

    Ok(())
}
#[cfg(test)]
fn evaluate_request(
    request: &ExecutionRequest,
    filesystem: &FileSystemCapability,
) -> PolicyEvaluation {
    let config = GatewayConfig::default();

    evaluate_request_with_config(request, filesystem, &config)
}
#[cfg(test)]
fn revalidate_pending_request(
    pending: &PendingReview,
    filesystem: &FileSystemCapability,
) -> Result<(), String> {
    let config = GatewayConfig::default();

    revalidate_pending_request_with_config(pending, filesystem, &config)
}
#[cfg(test)]
fn handle_admin_command(
    command: AdminCommand,
    pending_reviews: &Arc<Mutex<PendingReviewStore>>,
    filesystem: &FileSystemCapability,
) -> Result<AdminOutcome, String> {
    let config = GatewayConfig::default();

    handle_admin_command_with_config(command, pending_reviews, filesystem, &config)
}
#[cfg(test)]
fn execute_request(
    params: &ExecuteParams,
    filesystem: &FileSystemCapability,
    pending_reviews: &Arc<Mutex<PendingReviewStore>>,
) -> Result<String, String> {
    let config = GatewayConfig::default();

    execute_request_with_config(params, filesystem, pending_reviews, &config)
}

#[cfg(test)]
mod gateway_tests {
    use super::ExecutionResult;
    use super::{
        AddArguments, AdminCommand, AdminOutcome, AuditPhase, ExecuteParams,
        ExecutionArgumentsParams, ExecutionContextParams, ExecutionOutcome, ExecutionRequest,
        FileSystemCapability, GatewayConfig, HttpExecutionResult, HttpMethod,
        MAX_ADMIN_COMMAND_LENGTH, MAX_MESSAGE_LENGTH, PolicyDecision, PolicyEvaluation,
        PolicyReason, ReadFileArguments, ReviewedExecutionOutcome, ReviewedOperationResult,
        WriteFileArguments, audit_claimed_approval, build_execution_request, create_admin_listener,
        evaluate_request, evaluate_request_with_config, execute_http_post_with_config,
        execute_message_with_audit_id, execute_request, execute_request_with_http_runner,
        handle_admin_command, handle_admin_command_with_http_runner, handle_admin_connection,
        parse_admin_command, reject_pending_request, revalidate_pending_request,
        review_reason_for_request, run_infinite_loop_with_fuel,
    };
    use crate::execution::HttpRequestArguments;
    use crate::pending_review::{PendingReview, PendingReviewStore};
    use crate::policy::evaluate_message;
    use std::sync::{Arc, Mutex};

    fn no_op_audit(_: &crate::audit::AuditRecord<'_>) -> Result<(), String> {
        Ok(())
    }
    fn empty_pending_review_store() -> Arc<Mutex<PendingReviewStore>> {
        Arc::new(Mutex::new(PendingReviewStore::new()))
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
    fn execute_message_with_audit<F, S>(
        message: &str,
        evaluation: PolicyEvaluation,
        audit_writer: F,
        sandbox_runner: S,
    ) -> Result<String, String>
    where
        F: FnMut(&crate::audit::AuditRecord<'_>) -> Result<(), String>,
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

    fn sandbox_must_not_run() -> Result<ExecutionResult, String> {
        Err("sandbox was called unexpectedly".to_owned())
    }
    #[tokio::test]
    async fn admin_connection_rejects_pending_request() -> Result<(), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        let socket_path =
            std::env::temp_dir().join(format!("zyguor-admin-{}.sock", uuid::Uuid::new_v4()));

        let listener = create_admin_listener(&socket_path).await?;
        let pending_reviews = empty_pending_review_store();
        let request_id = uuid::Uuid::new_v4();

        {
            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            store.insert(crate::pending_review::PendingReview::new(
                request_id,
                ExecutionRequest::WriteFile(WriteFileArguments {
                    path: "config/settings.txt".to_owned(),
                    content: "enabled=true".to_owned(),
                }),
                "Update application configuration".to_owned(),
            ))?;
        }

        let client_path = socket_path.clone();

        let client = tokio::spawn(async move {
            let mut stream = UnixStream::connect(&client_path)
                .await
                .map_err(|error| format!("failed to connect to admin socket: {error}"))?;

            let command = format!("REJECT {request_id}\n");

            stream
                .write_all(command.as_bytes())
                .await
                .map_err(|error| format!("failed to write admin command: {error}"))?;

            let mut response = String::new();

            stream
                .read_to_string(&mut response)
                .await
                .map_err(|error| format!("failed to read admin response: {error}"))?;

            Ok::<String, String>(response)
        });

        let (stream, _) = listener
            .accept()
            .await
            .map_err(|error| format!("failed to accept admin connection: {error}"))?;

        let filesystem = FileSystemCapability::new(std::env::temp_dir());
        let config = GatewayConfig::default();
        let rejected =
            handle_admin_connection(stream, &pending_reviews, &filesystem, &config).await?;

        let response = client
            .await
            .map_err(|error| format!("admin client task failed: {error}"))??;

        assert_eq!(response, format!("OK REJECTED {request_id}\n"));

        let AdminOutcome::Rejected { pending } = rejected else {
            return Err("expected rejected admin outcome".to_owned());
        };

        assert_eq!(pending.request_id, request_id);

        {
            let store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            assert!(store.get(&request_id).is_none());
        }

        drop(listener);

        std::fs::remove_file(&socket_path)
            .map_err(|error| format!("failed to remove test admin socket: {error}"))?;

        Ok(())
    }
    #[test]
    fn admin_outcome_formatter_reports_execution_and_audit_failures() {
        let request_id = uuid::Uuid::new_v4();

        let write_failed = AdminOutcome::WriteFailed {
            request_id,
            error: "simulated write failure".to_owned(),
        };

        assert_eq!(
            super::format_admin_outcome_response(&write_failed),
            format!("ERROR WRITE_FAILED {request_id} simulated write failure\n")
        );

        let completion_audit_failed = AdminOutcome::CompletionAuditFailed {
            request_id,
            execution_outcome: ExecutionOutcome::Success,
            error: "simulated completion audit failure".to_owned(),
            result: None,
        };

        assert_eq!(
            super::format_admin_outcome_response(&completion_audit_failed),
            format!(
                "ERROR COMPLETION_AUDIT_FAILED {request_id} simulated completion audit failure\n"
            )
        );
    }
    #[tokio::test]
    async fn admin_connection_approves_pending_request_and_returns_response() -> Result<(), String>
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        let request_id = uuid::Uuid::new_v4();

        let socket_path =
            std::env::temp_dir().join(format!("zyguor-admin-{}.sock", uuid::Uuid::new_v4()));

        let workspace = std::env::temp_dir().join(format!(
            "zyguor-admin-approval-test-{}-{request_id}",
            std::process::id()
        ));

        std::fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create test workspace: {error}"))?;

        let listener = create_admin_listener(&socket_path).await?;
        let pending_reviews = empty_pending_review_store();

        {
            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            store.insert(PendingReview::new(
                request_id,
                ExecutionRequest::WriteFile(WriteFileArguments {
                    path: "approved.txt".to_owned(),
                    content: "approved content".to_owned(),
                }),
                "Test admin approval response".to_owned(),
            ))?;
        }

        let client_path = socket_path.clone();

        let client = tokio::spawn(async move {
            let mut stream = UnixStream::connect(&client_path)
                .await
                .map_err(|error| format!("failed to connect to admin socket: {error}"))?;

            let command = format!("APPROVE {request_id}\n");

            stream
                .write_all(command.as_bytes())
                .await
                .map_err(|error| format!("failed to write admin command: {error}"))?;

            let mut response = String::new();

            stream
                .read_to_string(&mut response)
                .await
                .map_err(|error| format!("failed to read admin response: {error}"))?;

            Ok::<String, String>(response)
        });

        let (stream, _) = listener
            .accept()
            .await
            .map_err(|error| format!("failed to accept admin connection: {error}"))?;

        let filesystem = FileSystemCapability::try_new(workspace.clone())?;

        let config = GatewayConfig::default();
        let outcome =
            handle_admin_connection(stream, &pending_reviews, &filesystem, &config).await?;

        let response = client
            .await
            .map_err(|error| format!("admin client task failed: {error}"))??;

        assert_eq!(response, format!("OK APPROVED {request_id}\n"));
        assert_eq!(outcome, AdminOutcome::Approved { request_id });

        let written_content = std::fs::read_to_string(workspace.join("approved.txt"))
            .map_err(|error| format!("failed to read approved test file: {error}"))?;

        assert_eq!(written_content, "approved content");

        {
            let store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            assert!(store.get(&request_id).is_none());
        }

        drop(listener);

        std::fs::remove_file(&socket_path)
            .map_err(|error| format!("failed to remove test admin socket: {error}"))?;

        std::fs::remove_dir_all(&workspace)
            .map_err(|error| format!("failed to remove test workspace: {error}"))?;

        Ok(())
    }

    #[test]
    fn approval_of_unknown_request_is_rejected() {
        let pending_reviews = empty_pending_review_store();
        let request_id = uuid::Uuid::new_v4();

        let filesystem = FileSystemCapability::new(std::env::temp_dir());
        let result = handle_admin_command(
            AdminCommand::Approve { request_id },
            &pending_reviews,
            &filesystem,
        );

        assert_eq!(result, Err("pending review request not found".to_owned()));
    }

    #[test]
    fn allows_http_get_to_allowlisted_host() {
        let filesystem = FileSystemCapability::new(std::env::temp_dir());

        let request = ExecutionRequest::HttpRequest(HttpRequestArguments {
            method: HttpMethod::Get,
            url: "https://api.example.com/status".to_owned(),
            body: None,
        });

        let evaluation = evaluate_request(&request, &filesystem);

        assert_eq!(evaluation.decision, PolicyDecision::Allow);
        assert_eq!(evaluation.reason, PolicyReason::Safe);
    }

    #[test]
    fn blocks_http_request_to_unapproved_host() {
        let filesystem = FileSystemCapability::new(std::env::temp_dir());

        let request = ExecutionRequest::HttpRequest(HttpRequestArguments {
            method: HttpMethod::Get,
            url: "https://evil.example/status".to_owned(),
            body: None,
        });

        let evaluation = evaluate_request(&request, &filesystem);

        assert_eq!(evaluation.decision, PolicyDecision::Block);
        assert_eq!(evaluation.reason, PolicyReason::OutOfScope);
    }
    #[test]
    fn reviews_http_post_to_allowlisted_host() {
        let filesystem = FileSystemCapability::new(std::env::temp_dir());

        let request = ExecutionRequest::HttpRequest(HttpRequestArguments {
            method: HttpMethod::Post,
            url: "https://api.example.com/items".to_owned(),
            body: Some(r#"{"name":"example"}"#.to_owned()),
        });

        let evaluation = evaluate_request(&request, &filesystem);

        assert_eq!(evaluation.decision, PolicyDecision::Review);
        assert_eq!(evaluation.reason, PolicyReason::ExternalWrite);
    }

    #[test]
    fn approval_revalidates_write_target_and_retains_invalid_request() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();
        let pending_reviews = empty_pending_review_store();

        {
            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            store.insert(crate::pending_review::PendingReview::new(
                request_id,
                ExecutionRequest::WriteFile(WriteFileArguments {
                    path: "../outside.txt".to_owned(),
                    content: "should not be written".to_owned(),
                }),
                "Attempt invalid write".to_owned(),
            ))?;
        }

        let filesystem = FileSystemCapability::new(std::env::temp_dir());

        let result = handle_admin_command(
            AdminCommand::Approve { request_id },
            &pending_reviews,
            &filesystem,
        );

        assert_eq!(
        result,
        Err(
            "pending write target is no longer valid: parent directory traversal is not allowed"
                .to_owned()
        )
    );

        let store = pending_reviews
            .lock()
            .map_err(|_| "pending review store lock poisoned".to_owned())?;

        assert!(store.get(&request_id).is_some());
        assert_eq!(store.len(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn admin_connection_rejects_oversized_command_without_consuming_request()
    -> Result<(), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;
        let socket_path =
            std::env::temp_dir().join(format!("zyguor-admin-{}.sock", uuid::Uuid::new_v4()));

        let listener = create_admin_listener(&socket_path).await?;
        let pending_reviews = empty_pending_review_store();
        let request_id = uuid::Uuid::new_v4();

        {
            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            store.insert(crate::pending_review::PendingReview::new(
                request_id,
                ExecutionRequest::WriteFile(WriteFileArguments {
                    path: "config/settings.txt".to_owned(),
                    content: "enabled=true".to_owned(),
                }),
                "Update application configuration".to_owned(),
            ))?;
        }

        let client_path = socket_path.clone();

        let client = tokio::spawn(async move {
            let mut stream = UnixStream::connect(&client_path)
                .await
                .map_err(|error| format!("failed to connect to admin socket: {error}"))?;

            let oversized = format!(
                "REJECT {request_id} {}",
                "x".repeat(MAX_ADMIN_COMMAND_LENGTH)
            );

            stream
                .write_all(oversized.as_bytes())
                .await
                .map_err(|error| format!("failed to write admin command: {error}"))?;

            let mut response = String::new();

            stream
                .read_to_string(&mut response)
                .await
                .map_err(|error| format!("failed to read admin response: {error}"))?;

            Ok::<String, String>(response)
        });

        let (stream, _) = listener
            .accept()
            .await
            .map_err(|error| format!("failed to accept admin connection: {error}"))?;

        let filesystem = FileSystemCapability::new(std::env::temp_dir());
        let config = GatewayConfig::default();
        let result = handle_admin_connection(stream, &pending_reviews, &filesystem, &config).await;

        let response = client
            .await
            .map_err(|error| format!("admin client task failed: {error}"))??;

        assert_eq!(
            result,
            Err("admin command exceeds maximum length".to_owned())
        );
        assert_eq!(response, "ERROR admin command exceeds maximum length\n");

        {
            let store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            assert!(store.get(&request_id).is_some());
        }

        drop(listener);

        std::fs::remove_file(&socket_path)
            .map_err(|error| format!("failed to remove test admin socket: {error}"))?;

        Ok(())
    }
    #[tokio::test]
    async fn admin_connection_returns_error_for_invalid_command() -> Result<(), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        let socket_path =
            std::env::temp_dir().join(format!("zyguor-admin-{}.sock", uuid::Uuid::new_v4()));

        let listener = create_admin_listener(&socket_path).await?;
        let pending_reviews = empty_pending_review_store();

        let client_path = socket_path.clone();

        let client = tokio::spawn(async move {
            let mut stream = UnixStream::connect(&client_path)
                .await
                .map_err(|error| format!("failed to connect to admin socket: {error}"))?;

            stream
                .write_all(b"INVALID COMMAND\n")
                .await
                .map_err(|error| format!("failed to write admin command: {error}"))?;

            let mut response = String::new();

            stream
                .read_to_string(&mut response)
                .await
                .map_err(|error| format!("failed to read admin response: {error}"))?;

            Ok::<String, String>(response)
        });

        let (stream, _) = listener
            .accept()
            .await
            .map_err(|error| format!("failed to accept admin connection: {error}"))?;

        let filesystem = FileSystemCapability::new(std::env::temp_dir());
        let config = GatewayConfig::default();

        let result = handle_admin_connection(stream, &pending_reviews, &filesystem, &config).await;

        let response = client
            .await
            .map_err(|error| format!("admin client task failed: {error}"))??;

        assert!(result.is_err());
        assert!(response.starts_with("ERROR "));

        drop(listener);

        std::fs::remove_file(&socket_path)
            .map_err(|error| format!("failed to remove test admin socket: {error}"))?;

        Ok(())
    }
    #[tokio::test]
    async fn admin_connection_returns_error_for_unknown_request() -> Result<(), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        let socket_path =
            std::env::temp_dir().join(format!("zyguor-admin-{}.sock", uuid::Uuid::new_v4()));

        let listener = create_admin_listener(&socket_path).await?;
        let pending_reviews = empty_pending_review_store();
        let request_id = uuid::Uuid::new_v4();

        let client_path = socket_path.clone();

        let client = tokio::spawn(async move {
            let mut stream = UnixStream::connect(&client_path)
                .await
                .map_err(|error| format!("failed to connect to admin socket: {error}"))?;

            let command = format!("APPROVE {request_id}\n");

            stream
                .write_all(command.as_bytes())
                .await
                .map_err(|error| format!("failed to write admin command: {error}"))?;

            let mut response = String::new();

            stream
                .read_to_string(&mut response)
                .await
                .map_err(|error| format!("failed to read admin response: {error}"))?;

            Ok::<String, String>(response)
        });

        let (stream, _) = listener
            .accept()
            .await
            .map_err(|error| format!("failed to accept admin connection: {error}"))?;

        let filesystem = FileSystemCapability::new(std::env::temp_dir());
        let config = GatewayConfig::default();

        let result = handle_admin_connection(stream, &pending_reviews, &filesystem, &config).await;

        let response = client
            .await
            .map_err(|error| format!("admin client task failed: {error}"))??;

        assert_eq!(result, Err("pending review request not found".to_owned()));

        assert_eq!(response, "ERROR pending review request not found\n");

        drop(listener);

        std::fs::remove_file(&socket_path)
            .map_err(|error| format!("failed to remove test admin socket: {error}"))?;

        Ok(())
    }
    #[test]
    fn parses_reject_admin_command() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();
        let input = format!("REJECT {request_id}");

        let command = parse_admin_command(&input)?;

        assert_eq!(command, AdminCommand::Reject { request_id });

        Ok(())
    }
    #[test]
    fn rejects_invalid_admin_commands() {
        let request_id = uuid::Uuid::new_v4();

        assert_eq!(
            parse_admin_command(""),
            Err("admin command cannot be empty".to_owned())
        );

        assert_eq!(
            parse_admin_command("REJECT"),
            Err("admin command requires a request ID".to_owned())
        );

        assert_eq!(
            parse_admin_command("REJECT not-a-uuid"),
            Err("admin command contains an invalid request ID".to_owned())
        );

        assert_eq!(
            parse_admin_command(&format!("REJECT {request_id} extra")),
            Err("admin command contains unexpected arguments".to_owned())
        );
    }
    #[test]
    fn builds_run_cargo_test_execution_request() -> Result<(), String> {
        let params = ExecuteParams {
            operation: "run_cargo_test".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: None,
                right: None,
                path: None,
                content: None,
                method: None,
                url: None,
                body: None,
            },
            context: ExecutionContextParams {
                purpose: "run approved Rust tests".to_owned(),
            },
        };

        let request = build_execution_request(&params)?;

        assert_eq!(request, ExecutionRequest::RunCargoTest);

        Ok(())
    }
    #[test]
    fn approved_cargo_test_preserves_failed_test_result() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();
        let pending_reviews = empty_pending_review_store();

        let workspace = std::env::temp_dir().join(format!(
            "zyguor-cargo-failure-test-{}-{request_id}",
            std::process::id()
        ));

        let src_directory = workspace.join("src");

        std::fs::create_dir_all(&src_directory)
            .map_err(|error| format!("failed to create Cargo test workspace: {error}"))?;

        std::fs::write(
            workspace.join("Cargo.toml"),
            r#"[package]
name = "zyguor-cargo-failure-fixture"
version = "0.1.0"
edition = "2024"
"#,
        )
        .map_err(|error| format!("failed to write Cargo.toml: {error}"))?;

        std::fs::write(
            workspace.join("Cargo.lock"),
            r#"# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "zyguor-cargo-failure-fixture"
version = "0.1.0"
"#,
        )
        .map_err(|error| format!("failed to write Cargo.lock: {error}"))?;

        std::fs::write(
            src_directory.join("lib.rs"),
            r#"#[cfg(test)]
mod tests {
    #[test]
    fn fixture_fails() {
        assert_eq!(2 + 2, 5);
    }
}
"#,
        )
        .map_err(|error| format!("failed to write Cargo test source: {error}"))?;

        {
            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            store.insert(crate::pending_review::PendingReview::new(
                request_id,
                ExecutionRequest::RunCargoTest,
                "Test failed Cargo execution".to_owned(),
            ))?;
        }

        let filesystem = FileSystemCapability::try_new(workspace.clone())?;

        let result = handle_admin_command(
            AdminCommand::Approve { request_id },
            &pending_reviews,
            &filesystem,
        )?;

        match result {
            AdminOutcome::CargoTestFailed {
                request_id: failed_request_id,
                result,
            } => {
                assert_eq!(failed_request_id, request_id);
                assert!(!result.success);
                assert!(!result.timed_out);
                assert_ne!(result.exit_code, Some(0));
            }

            other => {
                return Err(format!("expected failed Cargo test outcome, got {other:?}"));
            }
        }

        let store = pending_reviews
            .lock()
            .map_err(|_| "pending review store lock poisoned".to_owned())?;

        assert!(store.get(&request_id).is_none());
        assert!(store.is_empty());

        drop(store);

        std::fs::remove_dir_all(&workspace)
            .map_err(|error| format!("failed to remove Cargo test workspace: {error}"))?;

        Ok(())
    }
    #[test]
    fn cargo_test_approval_revalidation_retains_invalid_request() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();
        let pending_reviews = empty_pending_review_store();

        let workspace = std::env::temp_dir().join(format!(
            "zyguor-cargo-revalidation-test-{}-{request_id}",
            std::process::id()
        ));

        std::fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create Cargo test workspace: {error}"))?;

        {
            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            store.insert(crate::pending_review::PendingReview::new(
                request_id,
                ExecutionRequest::RunCargoTest,
                "Test Cargo approval revalidation".to_owned(),
            ))?;
        }

        let filesystem = FileSystemCapability::try_new(workspace.clone())?;

        let result = handle_admin_command(
            AdminCommand::Approve { request_id },
            &pending_reviews,
            &filesystem,
        );

        assert!(result.is_err());

        let error = result.expect_err("Cargo approval should fail revalidation");

        assert!(
            error.contains("pending Cargo test workspace is no longer valid"),
            "unexpected error: {error}"
        );

        let store = pending_reviews
            .lock()
            .map_err(|_| "pending review store lock poisoned".to_owned())?;

        assert!(store.get(&request_id).is_some());
        assert_eq!(store.len(), 1);

        drop(store);

        std::fs::remove_dir_all(&workspace)
            .map_err(|error| format!("failed to remove Cargo test workspace: {error}"))?;

        Ok(())
    }

    #[test]
    fn valid_approval_claims_and_consumes_pending_request() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();
        let pending_reviews = empty_pending_review_store();

        {
            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            store.insert(crate::pending_review::PendingReview::new(
                request_id,
                ExecutionRequest::WriteFile(WriteFileArguments {
                    path: "config/settings.txt".to_owned(),
                    content: "enabled=true".to_owned(),
                }),
                "Update application configuration".to_owned(),
            ))?;
        }

        let workspace =
            std::env::temp_dir().join(format!("zyguor-approval-claim-test-{request_id}"));

        let config_dir = workspace.join("config");

        std::fs::create_dir_all(&config_dir)
            .map_err(|error| format!("failed to create test workspace: {error}"))?;

        let filesystem = FileSystemCapability::try_new(workspace.clone())?;

        let result = handle_admin_command(
            AdminCommand::Approve { request_id },
            &pending_reviews,
            &filesystem,
        );

        assert_eq!(result, Ok(AdminOutcome::Approved { request_id }));

        let target = workspace.join("config/settings.txt");

        let written_content = std::fs::read_to_string(&target)
            .map_err(|error| format!("failed to read approved test file: {error}"))?;

        assert_eq!(written_content, "enabled=true");

        let store = pending_reviews
            .lock()
            .map_err(|_| "pending review store lock poisoned".to_owned())?;

        assert!(store.get(&request_id).is_none());
        assert!(store.is_empty());

        drop(store);

        std::fs::remove_dir_all(&workspace)
            .map_err(|error| format!("failed to remove test workspace: {error}"))?;

        Ok(())
    }
    #[test]
    fn parses_approve_admin_command() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();
        let input = format!("APPROVE {request_id}");

        let command = parse_admin_command(&input)?;

        assert_eq!(command, AdminCommand::Approve { request_id });

        Ok(())
    }
    #[tokio::test]
    async fn admin_socket_is_created_with_owner_only_permissions() -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt;

        let socket_path =
            std::env::temp_dir().join(format!("zyguor-admin-{}.sock", uuid::Uuid::new_v4()));

        let listener = create_admin_listener(&socket_path).await?;

        let metadata = std::fs::metadata(&socket_path)
            .map_err(|error| format!("failed to inspect admin socket: {error}"))?;

        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        drop(listener);

        std::fs::remove_file(&socket_path)
            .map_err(|error| format!("failed to remove test admin socket: {error}"))?;

        Ok(())
    }
    #[tokio::test]
    async fn admin_socket_refuses_existing_path() -> Result<(), String> {
        let socket_path = std::env::temp_dir().join(format!(
            "zyguor-admin-existing-{}.sock",
            uuid::Uuid::new_v4()
        ));

        std::fs::write(&socket_path, b"do not overwrite")
            .map_err(|error| format!("failed to create test path: {error}"))?;

        let result = create_admin_listener(&socket_path).await;

        assert_eq!(
            result.err(),
            Some("admin socket path already exists".to_owned())
        );

        let contents = std::fs::read(&socket_path)
            .map_err(|error| format!("failed to read existing test path: {error}"))?;

        assert_eq!(contents, b"do not overwrite");

        std::fs::remove_file(&socket_path)
            .map_err(|error| format!("failed to remove test path: {error}"))?;

        Ok(())
    }
    #[test]
    fn builds_http_get_execution_request() -> Result<(), String> {
        let params = ExecuteParams {
            operation: "http_request".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: None,
                right: None,
                path: None,
                content: None,
                method: Some("get".to_owned()),
                url: Some("https://api.example.com/status".to_owned()),
                body: None,
            },
            context: ExecutionContextParams {
                purpose: "read approved API status".to_owned(),
            },
        };

        let request = build_execution_request(&params)?;

        assert_eq!(
            request,
            ExecutionRequest::HttpRequest(HttpRequestArguments {
                method: HttpMethod::Get,
                url: "https://api.example.com/status".to_owned(),
                body: None,
            })
        );

        Ok(())
    }

    #[test]
    fn builds_http_post_execution_request() -> Result<(), String> {
        let params = ExecuteParams {
            operation: "http_request".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: None,
                right: None,
                path: None,
                content: None,
                method: Some("post".to_owned()),
                url: Some("https://api.example.com/items".to_owned()),
                body: Some(r#"{"name":"example"}"#.to_owned()),
            },
            context: ExecutionContextParams {
                purpose: "send approved API request".to_owned(),
            },
        };

        let request = build_execution_request(&params)?;

        assert_eq!(
            request,
            ExecutionRequest::HttpRequest(HttpRequestArguments {
                method: HttpMethod::Post,
                url: "https://api.example.com/items".to_owned(),
                body: Some(r#"{"name":"example"}"#.to_owned()),
            })
        );

        Ok(())
    }

    #[test]
    fn rejects_unsupported_http_method() {
        let params = ExecuteParams {
            operation: "http_request".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: None,
                right: None,
                path: None,
                content: None,
                method: Some("delete".to_owned()),
                url: Some("https://api.example.com/items".to_owned()),
                body: None,
            },
            context: ExecutionContextParams {
                purpose: "unsupported HTTP method".to_owned(),
            },
        };

        let result = build_execution_request(&params);

        assert_eq!(
            result,
            Err("unsupported HTTP method: delete; expected get or post".to_owned())
        );
    }

    #[test]
    fn rejects_http_get_with_body() {
        let params = ExecuteParams {
            operation: "http_request".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: None,
                right: None,
                path: None,
                content: None,
                method: Some("get".to_owned()),
                url: Some("https://api.example.com/status".to_owned()),
                body: Some("unexpected body".to_owned()),
            },
            context: ExecutionContextParams {
                purpose: "invalid GET body".to_owned(),
            },
        };

        let result = build_execution_request(&params);

        assert_eq!(
            result,
            Err("HTTP GET request must not include a body".to_owned())
        );
    }
    #[test]
    fn configured_http_request_body_limit_is_enforced() {
        let arguments = HttpRequestArguments {
            method: HttpMethod::Post,
            url: "https://api.example.com/items".to_owned(),
            body: Some("123456".to_owned()),
        };

        let mut config = GatewayConfig::default();
        config.http.execution.max_request_body_bytes = 5;

        let result = execute_http_post_with_config(&arguments, &config);

        assert_eq!(
            result,
            Err("HTTP request body exceeds maximum size of 5 bytes".to_owned())
        );
    }
    #[test]
    fn custom_http_allowlist_changes_policy_decision() {
        let filesystem = FileSystemCapability::new(std::env::temp_dir());

        let request = ExecutionRequest::HttpRequest(HttpRequestArguments {
            method: HttpMethod::Get,
            url: "https://custom.example.com/status".to_owned(),
            body: None,
        });

        let mut config = GatewayConfig::default();
        config.http.allowed_hosts = vec!["custom.example.com".to_owned()];

        let evaluation = evaluate_request_with_config(&request, &filesystem, &config);

        assert_eq!(evaluation.decision, PolicyDecision::Allow);
        assert_eq!(evaluation.reason, PolicyReason::Safe);
    }

    #[test]
    fn empty_http_allowlist_blocks_outbound_http() {
        let filesystem = FileSystemCapability::new(std::env::temp_dir());

        let request = ExecutionRequest::HttpRequest(HttpRequestArguments {
            method: HttpMethod::Get,
            url: "https://api.example.com/status".to_owned(),
            body: None,
        });

        let mut config = GatewayConfig::default();
        config.http.allowed_hosts.clear();

        let evaluation = evaluate_request_with_config(&request, &filesystem, &config);

        assert_eq!(evaluation.decision, PolicyDecision::Block);
        assert_eq!(evaluation.reason, PolicyReason::OutOfScope);
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
                method: None,
                url: None,
                body: None,
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
            ExecutionRequest::ReadFile(_)
            | ExecutionRequest::WriteFile(_)
            | ExecutionRequest::GitStatus
            | ExecutionRequest::RunCargoTest
            | ExecutionRequest::HttpRequest(_) => {
                panic!("expected Add execution request");
            }
        }

        Ok(())
    }
    #[test]
    fn successful_rejection_audit_keeps_request_consumed() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();
        let pending_reviews = empty_pending_review_store();

        let pending = PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
        );

        let claimed = {
            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            store.insert(pending)?;
            store.claim(&request_id)?
        };

        super::audit_claimed_rejection(&claimed, &pending_reviews, |_| Ok(()))?;

        let store = pending_reviews
            .lock()
            .map_err(|_| "pending review store lock poisoned".to_owned())?;

        assert!(store.get(&request_id).is_none());
        assert!(store.is_empty());

        Ok(())
    }
    #[test]
    fn rejecting_pending_request_consumes_it_once() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();
        let pending_reviews = empty_pending_review_store();

        {
            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            store.insert(crate::pending_review::PendingReview::new(
                request_id,
                ExecutionRequest::WriteFile(WriteFileArguments {
                    path: "config/settings.txt".to_owned(),
                    content: "enabled=true".to_owned(),
                }),
                "Update application configuration".to_owned(),
            ))?;
        }

        let filesystem = FileSystemCapability::new(std::env::temp_dir());
        let rejected = handle_admin_command(
            AdminCommand::Reject { request_id },
            &pending_reviews,
            &filesystem,
        )?;

        let AdminOutcome::Rejected { pending } = rejected else {
            return Err("expected rejected admin outcome".to_owned());
        };

        assert_eq!(pending.request_id, request_id);
        assert_eq!(pending.purpose, "Update application configuration");

        let second_rejection = reject_pending_request(request_id, &pending_reviews);

        assert_eq!(
            second_rejection,
            Err("pending review request not found".to_owned())
        );

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
                method: None,
                url: None,
                body: None,
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
            ExecutionRequest::Add(_)
            | ExecutionRequest::WriteFile(_)
            | ExecutionRequest::GitStatus
            | ExecutionRequest::RunCargoTest
            | ExecutionRequest::HttpRequest(_) => {
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
                method: None,
                url: None,
                body: None,
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
                method: None,
                url: None,
                body: None,
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
    fn builds_git_status_execution_request() -> Result<(), String> {
        let params = ExecuteParams {
            operation: "git_status".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: None,
                right: None,
                path: None,
                content: None,
                method: None,
                url: None,
                body: None,
            },
            context: ExecutionContextParams {
                purpose: "inspect repository status".to_owned(),
            },
        };

        let request = build_execution_request(&params)?;

        assert_eq!(request, ExecutionRequest::GitStatus);

        Ok(())
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
                method: None,
                url: None,
                body: None,
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
            ExecutionRequest::Add(_)
            | ExecutionRequest::ReadFile(_)
            | ExecutionRequest::GitStatus
            | ExecutionRequest::RunCargoTest
            | ExecutionRequest::HttpRequest(_) => {
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
                method: None,
                url: None,
                body: None,
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
                method: None,
                url: None,
                body: None,
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
                method: None,
                url: None,
                body: None,
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
                method: None,
                url: None,
                body: None,
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
            ExecutionRequest::Add(_)
            | ExecutionRequest::ReadFile(_)
            | ExecutionRequest::GitStatus
            | ExecutionRequest::RunCargoTest
            | ExecutionRequest::HttpRequest(_) => {
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
    fn reviewed_write_request_is_stored_as_pending() -> Result<(), String> {
        use std::fs;

        let test_root =
            std::env::temp_dir().join(format!("zyguor-pending-write-test-{}", std::process::id()));

        let workspace = test_root.join("workspace");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        let filesystem = FileSystemCapability::new(workspace);

        let params = ExecuteParams {
            operation: "write_file".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: None,
                right: None,
                path: Some("new.txt".to_owned()),
                content: Some("pending content".to_owned()),
                method: None,
                url: None,
                body: None,
            },
            context: ExecutionContextParams {
                purpose: "Update application configuration".to_owned(),
            },
        };

        let pending_reviews = empty_pending_review_store();

        let result = execute_request(&params, &filesystem, &pending_reviews)?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["status"], "held_for_review");
        assert_eq!(json["decision"], "Review");
        assert_eq!(json["executed"], false);

        let request_id = json["request_id"]
            .as_str()
            .ok_or_else(|| "response request_id must be a string".to_owned())?;

        let request_id = uuid::Uuid::parse_str(request_id)
            .map_err(|error| format!("response request_id is invalid: {error}"))?;

        let store = pending_reviews
            .lock()
            .map_err(|_| "pending review store lock poisoned".to_owned())?;

        assert_eq!(store.len(), 1);

        let pending = store
            .get(&request_id)
            .ok_or_else(|| "reviewed request was not stored".to_owned())?;

        assert_eq!(pending.request_id, request_id);
        assert_eq!(pending.purpose, "Update application configuration");

        assert_eq!(
            pending.request,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "new.txt".to_owned(),
                content: "pending content".to_owned(),
            })
        );

        drop(store);

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

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
                method: None,
                url: None,
                body: None,
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

            ExecutionRequest::ReadFile(_)
            | ExecutionRequest::WriteFile(_)
            | ExecutionRequest::GitStatus
            | ExecutionRequest::RunCargoTest
            | ExecutionRequest::HttpRequest(_) => {
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
                method: None,
                url: None,
                body: None,
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
                method: None,
                url: None,
                body: None,
            },
            context: ExecutionContextParams {
                purpose: "delete the production database".to_owned(),
            },
        };

        let workspace_root = std::env::temp_dir();
        let filesystem = FileSystemCapability::new(workspace_root);
        let pending_reviews = empty_pending_review_store();
        let result = execute_request(&params, &filesystem, &pending_reviews)?;

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
                method: None,
                url: None,
                body: None,
            },
            context: ExecutionContextParams {
                purpose: "read an approved workspace file".to_owned(),
            },
        };
        let pending_reviews = empty_pending_review_store();
        let result = execute_request(&params, &filesystem, &pending_reviews)?;

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
    fn http_get_executes_through_gateway_with_injected_runner() -> Result<(), String> {
        let filesystem = FileSystemCapability::new(std::env::temp_dir());
        let pending_reviews = empty_pending_review_store();

        let params = ExecuteParams {
            operation: "http_request".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: None,
                right: None,
                path: None,
                content: None,
                method: Some("get".to_owned()),
                url: Some("https://api.example.com/status".to_owned()),
                body: None,
            },
            context: ExecutionContextParams {
                purpose: "read approved API status".to_owned(),
            },
        };

        let config = GatewayConfig::default();

        let result = execute_request_with_http_runner(
            &params,
            &filesystem,
            &pending_reviews,
            &config,
            |method, destination, body| {
                assert_eq!(method, HttpMethod::Get);
                assert_eq!(
                    destination.as_url().as_str(),
                    "https://api.example.com/status"
                );
                assert!(body.is_none());

                Ok(HttpExecutionResult {
                    status_code: 200,
                    body: "hello".to_owned(),
                    body_truncated: false,
                    duration_ms: 5,
                })
            },
        )?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["decision"], "Allow");
        assert_eq!(json["reason"], "Safe");
        assert_eq!(json["status"], "executed");
        assert_eq!(json["executed"], true);
        assert_eq!(json["execution_outcome"], "Success");

        assert_eq!(json["result"]["type"], "http");
        assert_eq!(json["result"]["result"]["status_code"], 200);
        assert_eq!(json["result"]["result"]["body"], "hello");
        assert_eq!(json["result"]["result"]["body_truncated"], false);
        assert_eq!(json["result"]["result"]["duration_ms"], 5);

        Ok(())
    }

    #[test]
    fn git_status_executes_inside_workspace() -> Result<(), String> {
        let workspace_root = std::env::temp_dir().join(format!(
            "zyguor-git-status-integration-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));

        std::fs::create_dir_all(&workspace_root)
            .map_err(|error| format!("failed to create test workspace: {error}"))?;

        git2::Repository::init(&workspace_root)
            .map_err(|error| format!("failed to initialize test repository: {error}"))?;

        std::fs::write(workspace_root.join("notes.txt"), "Hello from Zyguor")
            .map_err(|error| format!("failed to write test file: {error}"))?;

        let filesystem = FileSystemCapability::new(workspace_root.clone());

        let params = ExecuteParams {
            operation: "git_status".to_owned(),
            arguments: ExecutionArgumentsParams {
                left: None,
                right: None,
                path: None,
                content: None,
                method: None,
                url: None,
                body: None,
            },
            context: ExecutionContextParams {
                purpose: "inspect approved workspace repository".to_owned(),
            },
        };

        let pending_reviews = empty_pending_review_store();
        let result = execute_request(&params, &filesystem, &pending_reviews)?;

        let json: serde_json::Value = serde_json::from_str(&result)
            .map_err(|error| format!("failed to parse gateway response: {error}"))?;

        assert_eq!(json["decision"], "Allow");
        assert_eq!(json["reason"], "Safe");
        assert_eq!(json["status"], "executed");
        assert_eq!(json["executed"], true);
        assert_eq!(json["execution_outcome"], "Success");
        assert_eq!(json["result"]["type"], "text");

        let content = json["result"]["content"]
            .as_str()
            .ok_or_else(|| "expected Git status text result".to_owned())?;

        let git_status: serde_json::Value = serde_json::from_str(content)
            .map_err(|error| format!("failed to parse Git status result: {error}"))?;

        let entries = git_status["entries"]
            .as_array()
            .ok_or_else(|| "expected Git status entries array".to_owned())?;

        let notes_entry = entries
            .iter()
            .find(|entry| entry["path"] == "notes.txt")
            .ok_or_else(|| "expected notes.txt in Git status".to_owned())?;

        assert_eq!(notes_entry["worktree"][0], "new");

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
                method: None,
                url: None,
                body: None,
            },
            context: ExecutionContextParams {
                purpose: "attempt to read outside the approved workspace".to_owned(),
            },
        };

        let pending_reviews = empty_pending_review_store();
        let result = execute_request(&params, &filesystem, &pending_reviews)?;

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
    fn approved_write_records_failed_completion() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();

        let pending = crate::pending_review::PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "approved.txt".to_owned(),
                content: "approved content".to_owned(),
            }),
            "Test approved write failure audit".to_owned(),
        );

        let mut records = Vec::new();

        let result = super::execute_approved_write(
            &pending,
            |record| {
                records.push((record.phase, record.execution_outcome));
                Ok(())
            },
            || Err("simulated write failure".to_owned()),
        );

        assert_eq!(
            result,
            Ok(ReviewedExecutionOutcome::ExecutionFailed(
                "simulated write failure".to_owned()
            ))
        );

        assert_eq!(
            records,
            vec![
                (AuditPhase::PreExecution, ExecutionOutcome::NotExecuted),
                (AuditPhase::Completion, ExecutionOutcome::Failed),
            ]
        );

        Ok(())
    }
    #[test]
    fn approved_write_distinguishes_completion_audit_failure_after_success() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();

        let pending = crate::pending_review::PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "approved.txt".to_owned(),
                content: "approved content".to_owned(),
            }),
            "Test completion audit failure".to_owned(),
        );

        let mut audit_count = 0;
        let mut write_called = false;

        let result = super::execute_approved_write(
            &pending,
            |_| {
                audit_count += 1;

                if audit_count == 2 {
                    return Err("simulated completion audit failure".to_owned());
                }

                Ok(())
            },
            || {
                write_called = true;
                Ok(())
            },
        );

        assert!(write_called);
        assert_eq!(audit_count, 2);

        assert_eq!(
            result,
            Ok(ReviewedExecutionOutcome::CompletionAuditFailed {
                execution_outcome: ExecutionOutcome::Success,
                error: "simulated completion audit failure".to_owned(),
                result: None,
            })
        );

        Ok(())
    }

    #[test]
    fn valid_approval_executes_secure_write() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();
        let pending_reviews = empty_pending_review_store();

        let workspace = std::env::temp_dir().join(format!(
            "zyguor-approval-test-{}-{request_id}",
            std::process::id()
        ));

        std::fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create test workspace: {error}"))?;

        let target = workspace.join("approved.txt");

        {
            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            store.insert(crate::pending_review::PendingReview::new(
                request_id,
                ExecutionRequest::WriteFile(WriteFileArguments {
                    path: "approved.txt".to_owned(),
                    content: "approved content".to_owned(),
                }),
                "Test valid approval execution".to_owned(),
            ))?;
        }

        let filesystem = FileSystemCapability::try_new(workspace.clone())?;

        let result = handle_admin_command(
            AdminCommand::Approve { request_id },
            &pending_reviews,
            &filesystem,
        );

        assert_eq!(result, Ok(AdminOutcome::Approved { request_id }));

        let written_content = std::fs::read_to_string(&target)
            .map_err(|error| format!("failed to read approved test file: {error}"))?;

        assert_eq!(written_content, "approved content");

        let store = pending_reviews
            .lock()
            .map_err(|_| "pending review store lock poisoned".to_owned())?;

        assert!(store.get(&request_id).is_none());
        assert!(store.is_empty());
        drop(store);

        std::fs::remove_dir_all(&workspace)
            .map_err(|error| format!("failed to remove test workspace: {error}"))?;

        Ok(())
    }
    #[test]
    fn valid_approval_executes_cargo_test() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();
        let pending_reviews = empty_pending_review_store();

        let workspace = std::env::temp_dir().join(format!(
            "zyguor-cargo-approval-test-{}-{request_id}",
            std::process::id()
        ));

        let src_directory = workspace.join("src");

        std::fs::create_dir_all(&src_directory)
            .map_err(|error| format!("failed to create Cargo test workspace: {error}"))?;

        std::fs::write(
            workspace.join("Cargo.toml"),
            r#"[package]
name = "zyguor-cargo-test-fixture"
version = "0.1.0"
edition = "2024"
"#,
        )
        .map_err(|error| format!("failed to write Cargo.toml: {error}"))?;

        std::fs::write(
            workspace.join("Cargo.lock"),
            r#"# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "zyguor-cargo-test-fixture"
version = "0.1.0"
"#,
        )
        .map_err(|error| format!("failed to write Cargo.lock: {error}"))?;

        std::fs::write(
            src_directory.join("lib.rs"),
            r#"#[cfg(test)]
mod tests {
    #[test]
    fn fixture_passes() {
        assert_eq!(2 + 2, 4);
    }
}
"#,
        )
        .map_err(|error| format!("failed to write Cargo test source: {error}"))?;

        {
            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            store.insert(crate::pending_review::PendingReview::new(
                request_id,
                ExecutionRequest::RunCargoTest,
                "Test approved Cargo execution".to_owned(),
            ))?;
        }

        let filesystem = FileSystemCapability::try_new(workspace.clone())?;

        let result = handle_admin_command(
            AdminCommand::Approve { request_id },
            &pending_reviews,
            &filesystem,
        )?;

        match result {
            AdminOutcome::CargoTestCompleted {
                request_id: completed_request_id,
                result,
            } => {
                assert_eq!(completed_request_id, request_id);
                assert!(result.success);
                assert!(!result.timed_out);
                assert_eq!(result.exit_code, Some(0));
            }

            other => {
                return Err(format!(
                    "expected successful Cargo test outcome, got {other:?}"
                ));
            }
        }

        let store = pending_reviews
            .lock()
            .map_err(|_| "pending review store lock poisoned".to_owned())?;

        assert!(store.get(&request_id).is_none());
        assert!(store.is_empty());

        drop(store);

        std::fs::remove_dir_all(&workspace)
            .map_err(|error| format!("failed to remove Cargo test workspace: {error}"))?;

        Ok(())
    }
    #[test]
    fn approved_http_post_returns_completed_result() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();
        let pending_reviews = empty_pending_review_store();

        {
            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            store.insert(crate::pending_review::PendingReview::new(
                request_id,
                ExecutionRequest::HttpRequest(HttpRequestArguments {
                    method: HttpMethod::Post,
                    url: "https://api.example.com/items".to_owned(),
                    body: Some(r#"{"name":"zyguor"}"#.to_owned()),
                }),
                "Test approved HTTP POST".to_owned(),
            ))?;
        }

        let filesystem = FileSystemCapability::new(std::env::temp_dir());

        let config = GatewayConfig::default();
        let outcome = handle_admin_command_with_http_runner(
            AdminCommand::Approve { request_id },
            &pending_reviews,
            &filesystem,
            &config,
            |arguments| {
                assert_eq!(arguments.method, HttpMethod::Post);
                assert_eq!(arguments.url, "https://api.example.com/items");

                let result = HttpExecutionResult {
                    status_code: 200,
                    body: r#"{"ok":true}"#.to_owned(),
                    body_truncated: false,
                    duration_ms: 5,
                };

                Ok(ReviewedOperationResult::Success(Some(
                    ExecutionResult::Http { result },
                )))
            },
        )?;

        match outcome {
            AdminOutcome::HttpPostCompleted {
                request_id: completed_request_id,
                result,
            } => {
                assert_eq!(completed_request_id, request_id);
                assert_eq!(result.status_code, 200);
                assert_eq!(result.body, r#"{"ok":true}"#);
                assert!(!result.body_truncated);
            }

            other => {
                return Err(format!(
                    "expected HTTP POST completed outcome, got {other:?}"
                ));
            }
        }

        let store = pending_reviews
            .lock()
            .map_err(|_| "pending review store lock poisoned".to_owned())?;

        assert!(store.get(&request_id).is_none());

        Ok(())
    }
    #[test]
    fn approved_http_post_preserves_failed_http_result() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();
        let pending_reviews = empty_pending_review_store();

        {
            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            store.insert(crate::pending_review::PendingReview::new(
                request_id,
                ExecutionRequest::HttpRequest(HttpRequestArguments {
                    method: HttpMethod::Post,
                    url: "https://api.example.com/items".to_owned(),
                    body: Some(r#"{"name":"zyguor"}"#.to_owned()),
                }),
                "Test failed HTTP POST response".to_owned(),
            ))?;
        }

        let filesystem = FileSystemCapability::new(std::env::temp_dir());

        let config = GatewayConfig::default();
        let outcome = handle_admin_command_with_http_runner(
            AdminCommand::Approve { request_id },
            &pending_reviews,
            &filesystem,
            &config,
            |_arguments| {
                let result = HttpExecutionResult {
                    status_code: 500,
                    body: r#"{"error":"server failure"}"#.to_owned(),
                    body_truncated: false,
                    duration_ms: 8,
                };

                Ok(ReviewedOperationResult::FailedWithResult {
                    error: "HTTP POST returned status 500".to_owned(),
                    result: ExecutionResult::Http { result },
                })
            },
        )?;

        match outcome {
            AdminOutcome::HttpPostFailed {
                request_id: failed_request_id,
                result,
            } => {
                assert_eq!(failed_request_id, request_id);
                assert_eq!(result.status_code, 500);
                assert_eq!(result.body, r#"{"error":"server failure"}"#);
            }

            other => {
                return Err(format!("expected HTTP POST failed outcome, got {other:?}"));
            }
        }

        Ok(())
    }
    #[test]
    fn approved_http_post_reports_transport_failure() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();
        let pending_reviews = empty_pending_review_store();

        {
            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            store.insert(crate::pending_review::PendingReview::new(
                request_id,
                ExecutionRequest::HttpRequest(HttpRequestArguments {
                    method: HttpMethod::Post,
                    url: "https://api.example.com/items".to_owned(),
                    body: None,
                }),
                "Test HTTP POST transport failure".to_owned(),
            ))?;
        }

        let filesystem = FileSystemCapability::new(std::env::temp_dir());
        let config = GatewayConfig::default();

        let outcome = handle_admin_command_with_http_runner(
            AdminCommand::Approve { request_id },
            &pending_reviews,
            &filesystem,
            &config,
            |_arguments| Err("HTTP request failed: simulated transport failure".to_owned()),
        )?;

        match outcome {
            AdminOutcome::HttpPostExecutionFailed {
                request_id: failed_request_id,
                error,
            } => {
                assert_eq!(failed_request_id, request_id);
                assert_eq!(error, "HTTP request failed: simulated transport failure");
            }

            other => {
                return Err(format!(
                    "expected HTTP POST execution failure, got {other:?}"
                ));
            }
        }

        Ok(())
    }

    #[test]
    fn approval_audit_failure_is_propagated() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();

        let pending = crate::pending_review::PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "approved.txt".to_owned(),
                content: "approved content".to_owned(),
            }),
            "Test approval audit failure".to_owned(),
        );

        let result = super::write_approval_audit(&pending, |_| {
            Err("simulated approval audit failure".to_owned())
        });

        assert_eq!(
            result,
            Err("failed to persist approval audit: simulated approval audit failure".to_owned())
        );

        Ok(())
    }
    #[test]
    fn rejection_audit_records_human_rejection() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();

        let pending = PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
        );

        let mut observed = None;

        super::write_rejection_audit(&pending, |record| {
            observed = Some((
                record.request_id,
                record.decision,
                record.reason,
                record.phase,
                record.execution_outcome,
            ));

            Ok(())
        })?;

        assert_eq!(
            observed,
            Some((
                request_id,
                PolicyDecision::Review,
                crate::policy::PolicyReason::Write,
                AuditPhase::Rejection,
                ExecutionOutcome::NotExecuted,
            ))
        );

        Ok(())
    }
    #[test]
    fn http_post_uses_external_write_review_reason() -> Result<(), String> {
        let request = ExecutionRequest::HttpRequest(HttpRequestArguments {
            method: HttpMethod::Post,
            url: "https://api.example.com/items".to_owned(),
            body: Some(r#"{"name":"zyguor"}"#.to_owned()),
        });

        let reason = review_reason_for_request(&request)?;

        assert_eq!(reason, PolicyReason::ExternalWrite);

        Ok(())
    }

    #[test]
    fn http_get_is_not_eligible_for_human_review() {
        let request = ExecutionRequest::HttpRequest(HttpRequestArguments {
            method: HttpMethod::Get,
            url: "https://api.example.com/status".to_owned(),
            body: None,
        });

        let result = review_reason_for_request(&request);

        assert_eq!(
            result,
            Err("request is not eligible for human review".to_owned())
        );
    }

    #[test]
    fn pending_http_post_revalidation_rejects_unapproved_destination() {
        let pending = PendingReview::new(
            uuid::Uuid::new_v4(),
            ExecutionRequest::HttpRequest(HttpRequestArguments {
                method: HttpMethod::Post,
                url: "https://not-allowed.example.com/items".to_owned(),
                body: Some(r#"{"name":"zyguor"}"#.to_owned()),
            }),
            "submit external API request".to_owned(),
        );

        let filesystem = FileSystemCapability::new(std::env::temp_dir());

        let result = revalidate_pending_request(&pending, &filesystem);

        assert!(result.is_err());
    }
    #[test]
    fn rejection_audit_failure_restores_claimed_request() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();
        let pending_reviews = empty_pending_review_store();

        let pending = PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
        );

        {
            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            store.insert(pending.clone())?;

            let claimed = store.claim(&request_id)?;

            assert!(store.get(&request_id).is_none());

            drop(store);

            let result = super::audit_claimed_rejection(&claimed, &pending_reviews, |_| {
                Err("simulated rejection audit failure".to_owned())
            });

            assert_eq!(
                result,
                Err(
                    "failed to persist rejection audit: simulated rejection audit failure"
                        .to_owned()
                )
            );
        }

        let store = pending_reviews
            .lock()
            .map_err(|_| "pending review store lock poisoned".to_owned())?;

        assert_eq!(store.get(&request_id), Some(&pending));
        assert_eq!(store.len(), 1);

        Ok(())
    }
    #[test]
    fn approval_audit_failure_restores_claimed_request() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();
        let pending_reviews = empty_pending_review_store();

        let pending = PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
        );

        {
            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            store.insert(pending.clone())?;

            let claimed = store.claim(&request_id)?;

            assert!(store.get(&request_id).is_none());

            drop(store);

            let result = audit_claimed_approval(&claimed, &pending_reviews, |_| {
                Err("simulated audit failure".to_owned())
            });

            assert_eq!(
                result,
                Err("failed to persist approval audit: simulated audit failure".to_owned())
            );
        }

        let store = pending_reviews
            .lock()
            .map_err(|_| "pending review store lock poisoned".to_owned())?;

        assert_eq!(store.get(&request_id), Some(&pending));
        assert_eq!(store.len(), 1);

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
    #[test]
    fn approved_write_does_not_execute_when_pre_execution_audit_fails() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();

        let pending = crate::pending_review::PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "approved.txt".to_owned(),
                content: "approved content".to_owned(),
            }),
            "Test approved write audit gate".to_owned(),
        );

        let mut write_called = false;

        let result = super::execute_approved_write(
            &pending,
            |_| Err("simulated pre-execution audit failure".to_owned()),
            || {
                write_called = true;
                Ok(())
            },
        );

        assert_eq!(
            result,
            Err(
                "failed to persist pre-execution audit: simulated pre-execution audit failure"
                    .to_owned()
            )
        );

        assert!(!write_called);

        Ok(())
    }
    #[test]
    fn pre_execution_audit_failure_restores_claimed_request() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();
        let pending_reviews = empty_pending_review_store();

        let pending = PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "approved.txt".to_owned(),
                content: "approved content".to_owned(),
            }),
            "Test pre-execution failure restoration".to_owned(),
        );

        {
            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            store.insert(pending.clone())?;

            let claimed = store.claim(&request_id)?;

            assert!(store.get(&request_id).is_none());

            drop(store);

            let mut write_called = false;

            let result = super::execute_claimed_write(
                &claimed,
                &pending_reviews,
                |_| Err("simulated pre-execution audit failure".to_owned()),
                || {
                    write_called = true;
                    Ok(())
                },
            );

            assert_eq!(
                result,
                Err(
                    "failed to persist pre-execution audit: simulated pre-execution audit failure"
                        .to_owned()
                )
            );

            assert!(!write_called);
        }

        let store = pending_reviews
            .lock()
            .map_err(|_| "pending review store lock poisoned".to_owned())?;

        assert_eq!(store.get(&request_id), Some(&pending));
        assert_eq!(store.len(), 1);

        Ok(())
    }
    #[test]
    fn write_failure_does_not_restore_claimed_request() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();
        let pending_reviews = empty_pending_review_store();

        let pending = PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "approved.txt".to_owned(),
                content: "approved content".to_owned(),
            }),
            "Test failed write remains consumed".to_owned(),
        );

        let claimed = {
            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            store.insert(pending)?;

            store.claim(&request_id)?
        };

        let mut write_called = false;

        let result = super::execute_claimed_write(
            &claimed,
            &pending_reviews,
            |_| Ok(()),
            || {
                write_called = true;
                Err("simulated write failure".to_owned())
            },
        );

        assert_eq!(
            result,
            Ok(ReviewedExecutionOutcome::ExecutionFailed(
                "simulated write failure".to_owned()
            ))
        );

        assert!(write_called);

        let store = pending_reviews
            .lock()
            .map_err(|_| "pending review store lock poisoned".to_owned())?;

        assert!(store.get(&request_id).is_none());
        assert!(store.is_empty());

        Ok(())
    }
    #[test]
    fn completion_audit_failure_after_success_does_not_restore_claimed_request()
    -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();
        let pending_reviews = empty_pending_review_store();

        let pending = PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "approved.txt".to_owned(),
                content: "approved content".to_owned(),
            }),
            "Test completion audit failure remains consumed".to_owned(),
        );

        let claimed = {
            let mut store = pending_reviews
                .lock()
                .map_err(|_| "pending review store lock poisoned".to_owned())?;

            store.insert(pending)?;

            store.claim(&request_id)?
        };

        let mut audit_calls = 0;
        let mut write_called = false;

        let result = super::execute_claimed_write(
            &claimed,
            &pending_reviews,
            |_| {
                audit_calls += 1;

                if audit_calls == 1 {
                    Ok(())
                } else {
                    Err("simulated completion audit failure".to_owned())
                }
            },
            || {
                write_called = true;
                Ok(())
            },
        );

        assert_eq!(
            result,
            Ok(ReviewedExecutionOutcome::CompletionAuditFailed {
                execution_outcome: ExecutionOutcome::Success,
                error: "simulated completion audit failure".to_owned(),
                result: None,
            })
        );

        assert!(write_called);
        assert_eq!(audit_calls, 2);

        let store = pending_reviews
            .lock()
            .map_err(|_| "pending review store lock poisoned".to_owned())?;

        assert!(store.get(&request_id).is_none());
        assert!(store.is_empty());

        Ok(())
    }

    #[test]
    fn approved_write_executes_after_pre_execution_audit_succeeds() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();

        let pending = crate::pending_review::PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "approved.txt".to_owned(),
                content: "approved content".to_owned(),
            }),
            "Test approved write execution".to_owned(),
        );

        let mut write_count = 0;

        let result = super::execute_approved_write(
            &pending,
            |_| Ok(()),
            || {
                write_count += 1;
                Ok(())
            },
        );

        assert_eq!(result, Ok(ReviewedExecutionOutcome::Success));
        assert_eq!(write_count, 1);

        Ok(())
    }
    #[test]
    fn approved_write_records_successful_completion() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();

        let pending = crate::pending_review::PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "approved.txt".to_owned(),
                content: "approved content".to_owned(),
            }),
            "Test approved write completion audit".to_owned(),
        );

        let mut records = Vec::new();

        let result = super::execute_approved_write(
            &pending,
            |record| {
                records.push((record.phase, record.execution_outcome));
                Ok(())
            },
            || Ok(()),
        );

        assert_eq!(result, Ok(ReviewedExecutionOutcome::Success));

        assert_eq!(
            records,
            vec![
                (AuditPhase::PreExecution, ExecutionOutcome::NotExecuted),
                (AuditPhase::Completion, ExecutionOutcome::Success),
            ]
        );

        Ok(())
    }
    #[test]
    fn configured_http_get_block_applies_to_gateway_policy() {
        let filesystem = FileSystemCapability::new(std::env::temp_dir());

        let request = ExecutionRequest::HttpRequest(HttpRequestArguments {
            method: HttpMethod::Get,
            url: "https://api.example.com/status".to_owned(),
            body: None,
        });

        let mut config = GatewayConfig::default();
        config.policy.http_get = PolicyDecision::Block;

        let evaluation = evaluate_request_with_config(&request, &filesystem, &config);

        assert_eq!(evaluation.decision, PolicyDecision::Block);
        assert_eq!(evaluation.reason, PolicyReason::Safe);
    }
    #[test]
    fn configured_write_file_block_applies_to_in_scope_request() -> Result<(), String> {
        let workspace = std::env::temp_dir().join(format!(
            "zyguor-configured-write-policy-test-{}",
            uuid::Uuid::new_v4()
        ));

        std::fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create test workspace: {error}"))?;

        let filesystem = FileSystemCapability::try_new(workspace.clone())?;

        let request = ExecutionRequest::WriteFile(WriteFileArguments {
            path: "settings.txt".to_owned(),
            content: "enabled=true".to_owned(),
        });

        let mut config = GatewayConfig::default();
        config.policy.write_file = PolicyDecision::Block;

        let evaluation = evaluate_request_with_config(&request, &filesystem, &config);

        assert_eq!(evaluation.decision, PolicyDecision::Block);
        assert_eq!(evaluation.reason, PolicyReason::Write);

        std::fs::remove_dir_all(&workspace)
            .map_err(|error| format!("failed to remove test workspace: {error}"))?;

        Ok(())
    }
}
