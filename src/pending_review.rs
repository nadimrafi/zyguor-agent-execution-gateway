use std::collections::HashMap;

use uuid::Uuid;

use crate::execution::ExecutionRequest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReview {
    pub request_id: Uuid,
    pub request: ExecutionRequest,
    pub purpose: String,
}

impl PendingReview {
    pub fn new(request_id: Uuid, request: ExecutionRequest, purpose: String) -> Self {
        Self {
            request_id,
            request,
            purpose,
        }
    }
}
#[derive(Debug, Default)]
pub struct PendingReviewStore {
    reviews: HashMap<Uuid, PendingReview>,
}

impl PendingReviewStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, pending: PendingReview) -> Result<(), String> {
        if self.reviews.contains_key(&pending.request_id) {
            return Err("pending review request ID already exists".to_owned());
        }

        self.reviews.insert(pending.request_id, pending);
        Ok(())
    }

    pub fn take(&mut self, request_id: &Uuid) -> Option<PendingReview> {
        self.reviews.remove(request_id)
    }

    pub fn get(&self, request_id: &Uuid) -> Option<&PendingReview> {
        self.reviews.get(request_id)
    }
    pub fn claim(&mut self, request_id: &Uuid) -> Result<PendingReview, String> {
        self.reviews
            .remove(request_id)
            .ok_or_else(|| "pending review request not found".to_owned())
    }
    pub fn restore_claimed(&mut self, pending: PendingReview) -> Result<(), String> {
        if self.reviews.contains_key(&pending.request_id) {
            return Err("pending review request ID already exists".to_owned());
        }

        self.reviews.insert(pending.request_id, pending);

        Ok(())
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.reviews.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.reviews.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{PendingReview, PendingReviewStore};
    use crate::execution::{ExecutionRequest, WriteFileArguments};

    #[test]
    fn stores_and_retrieves_pending_review_by_request_id() {
        let request_id = uuid::Uuid::new_v4();

        let request = ExecutionRequest::WriteFile(WriteFileArguments {
            path: "config/settings.txt".to_owned(),
            content: "enabled=true".to_owned(),
        });

        let pending = PendingReview::new(
            request_id,
            request.clone(),
            "Update application configuration".to_owned(),
        );

        let mut store = PendingReviewStore::new();

        assert!(store.is_empty());
        assert!(store.insert(pending).is_ok());
        assert_eq!(store.len(), 1);

        let stored = store.get(&request_id);

        assert!(stored.is_some());
        assert_eq!(stored.map(|review| &review.request), Some(&request));
    }

    #[test]
    fn claiming_pending_review_is_single_use() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();

        let pending = PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
        );

        let mut store = PendingReviewStore::new();

        store.insert(pending.clone())?;

        let claimed = store.claim(&request_id)?;

        assert_eq!(claimed, pending);
        assert!(store.get(&request_id).is_none());
        assert!(store.is_empty());

        assert_eq!(
            store.claim(&request_id),
            Err("pending review request not found".to_owned())
        );

        Ok(())
    }

    #[test]
    fn rejects_duplicate_request_id_without_replacing_original() {
        let request_id = uuid::Uuid::new_v4();

        let original = PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/original.txt".to_owned(),
                content: "original".to_owned(),
            }),
            "Original request".to_owned(),
        );

        let duplicate = PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/replacement.txt".to_owned(),
                content: "replacement".to_owned(),
            }),
            "Replacement request".to_owned(),
        );

        let mut store = PendingReviewStore::new();

        assert!(store.insert(original).is_ok());
        assert_eq!(
            store.insert(duplicate),
            Err("pending review request ID already exists".to_owned())
        );

        let stored = store.get(&request_id);

        assert_eq!(
            stored.map(|review| review.purpose.as_str()),
            Some("Original request")
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn creates_pending_review_with_stable_request_identity() {
        let request_id = uuid::Uuid::new_v4();

        let request = ExecutionRequest::WriteFile(WriteFileArguments {
            path: "config/settings.txt".to_owned(),
            content: "enabled=true".to_owned(),
        });

        let pending = PendingReview::new(
            request_id,
            request.clone(),
            "Update application configuration".to_owned(),
        );

        assert_eq!(pending.request_id, request_id);
        assert_eq!(pending.request, request);
        assert_eq!(pending.purpose, "Update application configuration");
    }
    #[test]
    fn taking_pending_review_removes_it_from_store() {
        let request_id = uuid::Uuid::new_v4();

        let pending = PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
        );

        let mut store = PendingReviewStore::new();

        assert!(store.insert(pending.clone()).is_ok());

        let taken = store.take(&request_id);

        assert_eq!(taken, Some(pending));
        assert!(store.get(&request_id).is_none());
        assert!(store.is_empty());

        let second_take = store.take(&request_id);

        assert_eq!(second_take, None);
    }
    #[test]
    fn restores_claimed_review_for_safe_retry() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();

        let pending = PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
        );

        let mut store = PendingReviewStore::new();

        store.insert(pending.clone())?;

        let claimed = store.claim(&request_id)?;

        assert!(store.get(&request_id).is_none());

        store.restore_claimed(claimed)?;

        assert_eq!(store.get(&request_id), Some(&pending));
        assert_eq!(store.len(), 1);

        Ok(())
    }
    #[test]
    fn restore_claimed_refuses_to_replace_existing_review() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();

        let original = PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/original.txt".to_owned(),
                content: "original".to_owned(),
            }),
            "Original request".to_owned(),
        );

        let replacement = PendingReview::new(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/replacement.txt".to_owned(),
                content: "replacement".to_owned(),
            }),
            "Replacement request".to_owned(),
        );

        let mut store = PendingReviewStore::new();

        store.insert(original.clone())?;

        let result = store.restore_claimed(replacement);

        assert_eq!(
            result,
            Err("pending review request ID already exists".to_owned())
        );
        assert_eq!(store.get(&request_id), Some(&original));
        assert_eq!(store.len(), 1);

        Ok(())
    }
}
