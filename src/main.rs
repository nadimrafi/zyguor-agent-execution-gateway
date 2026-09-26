mod audit;
mod execution;
mod filesystem;
mod pending_review;
mod policy;
mod sandbox;

use audit::{AuditPhase, AuditRecord, ExecutionOutcome, persist_audit};
use execution::{AddArguments, ExecutionRequest, ReadFileArguments, WriteFileArguments};
use filesystem::FileSystemCapability;
use pending_review::{PendingReview, PendingReviewStore};
use policy::{
    PolicyDecision, PolicyEvaluation, PolicyOperation, block_out_of_scope, evaluate_operation,
};
use sandbox::{SandboxConfig, SandboxExecutor};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
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
    pending_reviews: Arc<Mutex<PendingReviewStore>>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdminCommand {
    Approve { request_id: uuid::Uuid },
    Reject { request_id: uuid::Uuid },
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
fn revalidate_pending_request(
    pending: &PendingReview,
    filesystem: &FileSystemCapability,
) -> Result<(), String> {
    match &pending.request {
        ExecutionRequest::WriteFile(arguments) => filesystem
            .resolve_write_target(&arguments.path)
            .map(|_| ())
            .map_err(|error| format!("pending write target is no longer valid: {error}")),

        _ => Err("pending request is not eligible for approval".to_owned()),
    }
}

fn handle_admin_command(
    command: AdminCommand,
    pending_reviews: &Arc<Mutex<PendingReviewStore>>,
    filesystem: &FileSystemCapability,
) -> Result<PendingReview, String> {
    match command {
        AdminCommand::Approve { request_id } => {
            let pending = inspect_pending_request(request_id, pending_reviews)?;

            revalidate_pending_request(&pending, filesystem)?;

            Err("admin approval is not enabled".to_owned())
        }
        AdminCommand::Reject { request_id } => reject_pending_request(request_id, pending_reviews),
    }
}

fn execute_request(
    params: &ExecuteParams,
    filesystem: &FileSystemCapability,
    pending_reviews: &Arc<Mutex<PendingReviewStore>>,
) -> Result<String, String> {
    let request = build_execution_request(params)?;
    let evaluation = evaluate_request(&request, filesystem);
    let request_id = uuid::Uuid::new_v4();

    if evaluation.decision == PolicyDecision::Review {
        let pending =
            PendingReview::new(request_id, request.clone(), params.context.purpose.clone());

        let mut store = pending_reviews
            .lock()
            .map_err(|_| "pending review store lock poisoned".to_owned())?;

        store.insert(pending)?;
    }

    let executor = SandboxExecutor::new(SandboxConfig::default());

    execute_message_with_audit_id(
        request_id,
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
        match execute_request(&params, &self.filesystem, &self.pending_reviews) {
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
) -> Result<PendingReview, String> {
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
        return Err("admin command exceeds maximum length".to_owned());
    }

    let command = parse_admin_command(&input)?;

    handle_admin_command(command, pending_reviews, filesystem)
}
async fn run_admin_listener(
    listener: UnixListener,
    pending_reviews: Arc<Mutex<PendingReviewStore>>,
    filesystem: FileSystemCapability,
) -> Result<(), String> {
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|error| format!("failed to accept admin connection: {error}"))?;

        if let Err(error) = handle_admin_connection(stream, &pending_reviews, &filesystem).await {
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

    let admin_listener = create_admin_listener(Path::new(&admin_socket_path)).await?;

    let pending_reviews = Arc::new(Mutex::new(PendingReviewStore::new()));

    let filesystem = FileSystemCapability::new(workspace_root.into());

    let gateway = ZyguorGateway {
        filesystem: filesystem.clone(),
        pending_reviews: Arc::clone(&pending_reviews),
    };

    let admin_task = tokio::spawn(run_admin_listener(
        admin_listener,
        Arc::clone(&pending_reviews),
        filesystem,
    ));

    let service = gateway.serve(stdio()).await?;

    service.waiting().await?;

    admin_task.abort();

    Ok(())
}

#[cfg(test)]
mod gateway_tests {
    use super::ExecutionResult;
    use super::{
        AddArguments, AdminCommand, ExecuteParams, ExecutionArgumentsParams,
        ExecutionContextParams, ExecutionRequest, FileSystemCapability, MAX_ADMIN_COMMAND_LENGTH,
        MAX_MESSAGE_LENGTH, PolicyDecision, PolicyEvaluation, ReadFileArguments,
        WriteFileArguments, build_execution_request, create_admin_listener, evaluate_request,
        execute_message_with_audit_id, execute_request, handle_admin_command,
        handle_admin_connection, parse_admin_command, reject_pending_request,
        run_infinite_loop_with_fuel,
    };
    use crate::pending_review::PendingReviewStore;
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
        use tokio::io::AsyncWriteExt;
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
                .map_err(|error| format!("failed to write admin command: {error}"))
        });

        let (stream, _) = listener
            .accept()
            .await
            .map_err(|error| format!("failed to accept admin connection: {error}"))?;

        let filesystem = FileSystemCapability::new(std::env::temp_dir());
        let rejected = handle_admin_connection(stream, &pending_reviews, &filesystem).await?;

        client
            .await
            .map_err(|error| format!("admin client task failed: {error}"))??;

        assert_eq!(rejected.request_id, request_id);

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
        use tokio::io::AsyncWriteExt;
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
                .map_err(|error| format!("failed to write admin command: {error}"))
        });

        let (stream, _) = listener
            .accept()
            .await
            .map_err(|error| format!("failed to accept admin connection: {error}"))?;

        let filesystem = FileSystemCapability::new(std::env::temp_dir());
        let result = handle_admin_connection(stream, &pending_reviews, &filesystem).await;

        client
            .await
            .map_err(|error| format!("admin client task failed: {error}"))??;

        assert_eq!(
            result,
            Err("admin command exceeds maximum length".to_owned())
        );

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
    fn disabled_approval_does_not_consume_pending_request() -> Result<(), String> {
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
            std::env::temp_dir().join(format!("zyguor-disabled-approval-test-{request_id}"));

        let config_dir = workspace.join("config");

        std::fs::create_dir_all(&config_dir)
            .map_err(|error| format!("failed to create test workspace: {error}"))?;

        let filesystem = FileSystemCapability::new(workspace.clone());
        let result = handle_admin_command(
            AdminCommand::Approve { request_id },
            &pending_reviews,
            &filesystem,
        );

        assert_eq!(result, Err("admin approval is not enabled".to_owned()));

        let store = pending_reviews
            .lock()
            .map_err(|_| "pending review store lock poisoned".to_owned())?;

        assert!(store.get(&request_id).is_some());
        assert_eq!(store.len(), 1);

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

        assert_eq!(rejected.request_id, request_id);
        assert_eq!(rejected.purpose, "Update application configuration");

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
    fn valid_approval_revalidation_still_does_not_execute_write() -> Result<(), String> {
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
                "Test valid approval revalidation".to_owned(),
            ))?;
        }

        let filesystem = FileSystemCapability::new(workspace.clone());

        let result = handle_admin_command(
            AdminCommand::Approve { request_id },
            &pending_reviews,
            &filesystem,
        );

        assert_eq!(result, Err("admin approval is not enabled".to_owned()));

        assert!(!target.exists());

        let store = pending_reviews
            .lock()
            .map_err(|_| "pending review store lock poisoned".to_owned())?;

        assert!(store.get(&request_id).is_some());
        assert_eq!(store.len(), 1);

        drop(store);

        std::fs::remove_dir_all(&workspace)
            .map_err(|error| format!("failed to remove test workspace: {error}"))?;

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
