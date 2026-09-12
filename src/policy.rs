#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum PolicyDecision {
    Allow,
    Review,
    Block,
}

pub fn evaluate_message(message: &str) -> PolicyDecision {
    let normalized = message.trim().to_lowercase();

    if normalized.contains("delete")
        || normalized.contains("drop table")
        || normalized.contains("rm -rf")
    {
        PolicyDecision::Block
    } else if normalized.contains("modify")
        || normalized.contains("write")
        || normalized.contains("update")
    {
        PolicyDecision::Review
    } else {
        PolicyDecision::Allow
    }
}
#[cfg(test)]
mod tests {
    use super::{PolicyDecision, evaluate_message};

    #[test]
    fn allows_safe_message() {
        assert_eq!(
            evaluate_message("read the project status"),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn reviews_write_request() {
        assert_eq!(
            evaluate_message("write a new configuration"),
            PolicyDecision::Review
        );
    }

    #[test]
    fn blocks_delete_request() {
        assert_eq!(
            evaluate_message("delete the production database"),
            PolicyDecision::Block
        );
    }
}
