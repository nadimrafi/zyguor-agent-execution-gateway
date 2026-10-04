use crate::config::CapabilityPolicyConfig;

pub fn evaluate_operation_with_config(
    operation: PolicyOperation,
    config: &CapabilityPolicyConfig,
) -> PolicyEvaluation {
    match operation {
        PolicyOperation::Add => PolicyEvaluation {
            decision: config.add,
            reason: PolicyReason::Safe,
        },

        PolicyOperation::ReadFile => PolicyEvaluation {
            decision: config.read_file,
            reason: PolicyReason::Safe,
        },

        PolicyOperation::WriteFile => PolicyEvaluation {
            decision: config.write_file,
            reason: PolicyReason::Write,
        },

        PolicyOperation::GitStatus => PolicyEvaluation {
            decision: config.git_status,
            reason: PolicyReason::Safe,
        },

        PolicyOperation::RunCargoTest => PolicyEvaluation {
            decision: config.run_cargo_test,
            reason: PolicyReason::CodeExecution,
        },

        PolicyOperation::HttpGet => PolicyEvaluation {
            decision: config.http_get,
            reason: PolicyReason::Safe,
        },

        PolicyOperation::HttpPost => PolicyEvaluation {
            decision: config.http_post,
            reason: PolicyReason::ExternalWrite,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[allow(dead_code)]
pub enum PolicyDecision {
    Allow,
    Review,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[allow(dead_code)]
pub enum PolicyReason {
    Safe,
    Write,
    ExternalWrite,
    CodeExecution,
    Destructive,
    OutOfScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct PolicyEvaluation {
    pub decision: PolicyDecision,
    pub reason: PolicyReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyOperation {
    Add,
    ReadFile,
    WriteFile,
    GitStatus,
    RunCargoTest,
    HttpGet,
    HttpPost,
}

#[cfg(test)]
pub fn evaluate_operation(operation: PolicyOperation) -> PolicyEvaluation {
    match operation {
        PolicyOperation::Add | PolicyOperation::ReadFile | PolicyOperation::GitStatus => {
            PolicyEvaluation {
                decision: PolicyDecision::Allow,
                reason: PolicyReason::Safe,
            }
        }

        PolicyOperation::WriteFile => PolicyEvaluation {
            decision: PolicyDecision::Review,
            reason: PolicyReason::Write,
        },

        PolicyOperation::RunCargoTest => PolicyEvaluation {
            decision: PolicyDecision::Review,
            reason: PolicyReason::CodeExecution,
        },
        PolicyOperation::HttpGet => PolicyEvaluation {
            decision: PolicyDecision::Allow,
            reason: PolicyReason::Safe,
        },

        PolicyOperation::HttpPost => PolicyEvaluation {
            decision: PolicyDecision::Review,
            reason: PolicyReason::ExternalWrite,
        },
    }
}
pub fn block_out_of_scope() -> PolicyEvaluation {
    PolicyEvaluation {
        decision: PolicyDecision::Block,
        reason: PolicyReason::OutOfScope,
    }
}

#[cfg(test)]
pub fn evaluate_message(message: &str) -> PolicyEvaluation {
    let normalized = message.trim().to_lowercase();

    if normalized.contains("delete")
        || normalized.contains("drop table")
        || normalized.contains("rm -rf")
    {
        PolicyEvaluation {
            decision: PolicyDecision::Block,
            reason: PolicyReason::Destructive,
        }
    } else if normalized.contains("modify")
        || normalized.contains("write")
        || normalized.contains("update")
    {
        PolicyEvaluation {
            decision: PolicyDecision::Review,
            reason: PolicyReason::Write,
        }
    } else {
        PolicyEvaluation {
            decision: PolicyDecision::Allow,
            reason: PolicyReason::Safe,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PolicyDecision, PolicyOperation, PolicyReason, block_out_of_scope, evaluate_message,
        evaluate_operation, evaluate_operation_with_config,
    };
    use crate::config::CapabilityPolicyConfig;

    #[test]
    fn blocks_out_of_scope_resource() {
        let evaluation = block_out_of_scope();

        assert_eq!(evaluation.decision, PolicyDecision::Block);
        assert_eq!(evaluation.reason, PolicyReason::OutOfScope);
    }

    #[test]
    fn allows_add_operation() {
        let evaluation = evaluate_operation(PolicyOperation::Add);

        assert_eq!(evaluation.decision, PolicyDecision::Allow);
        assert_eq!(evaluation.reason, PolicyReason::Safe);
    }
    #[test]
    fn reviews_write_file_operation() {
        let evaluation = evaluate_operation(PolicyOperation::WriteFile);

        assert_eq!(evaluation.decision, PolicyDecision::Review);
        assert_eq!(evaluation.reason, PolicyReason::Write);
    }
    #[test]
    fn allows_git_status_operation() {
        let evaluation = evaluate_operation(PolicyOperation::GitStatus);

        assert_eq!(evaluation.decision, PolicyDecision::Allow);
        assert_eq!(evaluation.reason, PolicyReason::Safe);
    }
    #[test]
    fn reviews_run_cargo_test_operation() {
        let evaluation = evaluate_operation(PolicyOperation::RunCargoTest);

        assert_eq!(evaluation.decision, PolicyDecision::Review);
        assert_eq!(evaluation.reason, PolicyReason::CodeExecution);
    }

    #[test]
    fn allows_safe_message() {
        let evaluation = evaluate_message("read the project status");

        assert_eq!(evaluation.decision, PolicyDecision::Allow);
        assert_eq!(evaluation.reason, PolicyReason::Safe);
    }

    #[test]
    fn reviews_write_request() {
        let evaluation = evaluate_message("write a new configuration");

        assert_eq!(evaluation.decision, PolicyDecision::Review);
        assert_eq!(evaluation.reason, PolicyReason::Write);
    }

    #[test]
    fn blocks_delete_request() {
        let evaluation = evaluate_message("delete the production database");

        assert_eq!(evaluation.decision, PolicyDecision::Block);
        assert_eq!(evaluation.reason, PolicyReason::Destructive);
    }

    #[test]
    fn block_is_case_insensitive() {
        let evaluation = evaluate_message("DELETE the production database");

        assert_eq!(evaluation.decision, PolicyDecision::Block);
        assert_eq!(evaluation.reason, PolicyReason::Destructive);
    }

    #[test]
    fn review_is_case_insensitive() {
        let evaluation = evaluate_message("WRITE a new configuration");

        assert_eq!(evaluation.decision, PolicyDecision::Review);
        assert_eq!(evaluation.reason, PolicyReason::Write);
    }

    #[test]
    fn trims_surrounding_whitespace() {
        let evaluation = evaluate_message("   read the project status   ");

        assert_eq!(evaluation.decision, PolicyDecision::Allow);
        assert_eq!(evaluation.reason, PolicyReason::Safe);
    }
    #[test]
    fn allows_http_get_operation() {
        let evaluation = evaluate_operation(PolicyOperation::HttpGet);

        assert_eq!(evaluation.decision, PolicyDecision::Allow);
        assert_eq!(evaluation.reason, PolicyReason::Safe);
    }

    #[test]
    fn reviews_http_post_operation() {
        let evaluation = evaluate_operation(PolicyOperation::HttpPost);

        assert_eq!(evaluation.decision, PolicyDecision::Review);
        assert_eq!(evaluation.reason, PolicyReason::ExternalWrite);
    }
    #[test]
    fn configured_http_get_can_be_blocked() {
        let config = CapabilityPolicyConfig {
            http_get: PolicyDecision::Block,
            ..CapabilityPolicyConfig::default()
        };

        let evaluation = evaluate_operation_with_config(PolicyOperation::HttpGet, &config);

        assert_eq!(evaluation.decision, PolicyDecision::Block);
        assert_eq!(evaluation.reason, PolicyReason::Safe);
    }

    #[test]
    fn configured_write_file_can_be_blocked() {
        let config = CapabilityPolicyConfig {
            write_file: PolicyDecision::Block,
            ..CapabilityPolicyConfig::default()
        };

        let evaluation = evaluate_operation_with_config(PolicyOperation::WriteFile, &config);

        assert_eq!(evaluation.decision, PolicyDecision::Block);
        assert_eq!(evaluation.reason, PolicyReason::Write);
    }
}
