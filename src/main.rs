mod audit;
mod policy;
use audit::AuditRecord;
use policy::evaluate_message;
use rmcp::{
    ServiceExt, handler::server::wrapper::Parameters, schemars, tool, tool_router, transport::stdio,
};

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct EchoParams {
    message: String,
}

#[derive(Clone)]
struct ZyguorGateway;

fn execute_message(message: &str) -> Result<String, String> {
    let decision = evaluate_message(message);

    let audit_record = AuditRecord::new(message, decision)
        .map_err(|error| format!("failed to create audit record: {error}"))?;

    let audit_json = serde_json::to_string(&audit_record)
        .map_err(|error| format!("failed to serialize audit record: {error}"))?;

    match decision {
        policy::PolicyDecision::Allow => {
            Ok(format!("EXECUTED\nmessage={message}\naudit={audit_json}"))
        }

        policy::PolicyDecision::Review => Ok(format!("HELD_FOR_REVIEW\naudit={audit_json}")),

        policy::PolicyDecision::Block => Ok(format!("BLOCKED\naudit={audit_json}")),
    }
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
    use super::execute_message;

    #[test]
    fn allow_executes_message() -> Result<(), String> {
        let result = execute_message("read the project status")?;

        assert!(result.starts_with("EXECUTED"));
        assert!(result.contains("read the project status"));

        Ok(())
    }

    #[test]
    fn review_does_not_execute_message() -> Result<(), String> {
        let result = execute_message("write a new configuration")?;

        assert!(result.starts_with("HELD_FOR_REVIEW"));
        assert!(!result.contains("message=write a new configuration"));

        Ok(())
    }

    #[test]
    fn block_does_not_execute_message() -> Result<(), String> {
        let result = execute_message("delete the production database")?;

        assert!(result.starts_with("BLOCKED"));
        assert!(!result.contains("message=delete the production database"));

        Ok(())
    }
}
