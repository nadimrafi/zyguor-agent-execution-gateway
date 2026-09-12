#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum PolicyDecision {
    Allow,
    Review,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum PolicyReason {
    Safe,
    Write,
    Destructive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct PolicyEvaluation {
    pub decision: PolicyDecision,
    pub reason: PolicyReason,
}

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
    use super::{PolicyDecision, PolicyReason, evaluate_message};

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
        let evaluation = evaluate_message("   delete the production database   ");

        assert_eq!(evaluation.decision, PolicyDecision::Block);
        assert_eq!(evaluation.reason, PolicyReason::Destructive);
    }
}
