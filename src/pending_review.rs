use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::execution::{ExecutionRequest, HttpMethod, HttpRequestArguments, WriteFileArguments};
use crate::filesystem::WriteTargetState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReview {
    pub request_id: Uuid,
    pub request: ExecutionRequest,
    pub purpose: String,
    pub workspace_fingerprint: Option<String>,
    pub write_target_state: Option<WriteTargetState>,
}

impl PendingReview {
    pub fn new(request_id: Uuid, request: ExecutionRequest, purpose: String) -> Self {
        Self {
            request_id,
            request,
            purpose,
            workspace_fingerprint: None,
            write_target_state: None,
        }
    }

    pub fn new_with_workspace_fingerprint(
        request_id: Uuid,
        request: ExecutionRequest,
        purpose: String,
        workspace_fingerprint: String,
    ) -> Self {
        Self {
            request_id,
            request,
            purpose,
            workspace_fingerprint: Some(workspace_fingerprint),
            write_target_state: None,
        }
    }

    pub fn new_with_write_target_state(
        request_id: Uuid,
        request: ExecutionRequest,
        purpose: String,
        write_target_state: WriteTargetState,
    ) -> Self {
        Self {
            request_id,
            request,
            purpose,
            workspace_fingerprint: None,
            write_target_state: Some(write_target_state),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct PersistedPendingReviewState {
    version: u32,
    reviews: Vec<PersistedPendingReview>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct PersistedPendingReview {
    request_id: Uuid,
    purpose: String,
    status: PersistedReviewStatus,
    operation: PersistedReviewOperation,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PersistedReviewStatus {
    Pending,
    Claimed,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PersistedReviewOperation {
    WriteFile {
        path: String,
        content: String,
        target_state: WriteTargetState,
    },
    RunCargoTest {
        workspace_fingerprint: String,
    },
    HttpPost {
        url: String,
        body: Option<String>,
    },
}

impl TryFrom<&PendingReview> for PersistedPendingReview {
    type Error = String;

    fn try_from(pending: &PendingReview) -> Result<Self, Self::Error> {
        let operation = match &pending.request {
            ExecutionRequest::WriteFile(arguments) => {
                let target_state = pending
                    .write_target_state
                    .clone()
                    .ok_or_else(|| "write pending review is missing target state".to_owned())?;

                PersistedReviewOperation::WriteFile {
                    path: arguments.path.clone(),
                    content: arguments.content.clone(),
                    target_state,
                }
            }

            ExecutionRequest::RunCargoTest => {
                let workspace_fingerprint =
                    pending.workspace_fingerprint.clone().ok_or_else(|| {
                        "Cargo test pending review is missing workspace fingerprint".to_owned()
                    })?;

                PersistedReviewOperation::RunCargoTest {
                    workspace_fingerprint,
                }
            }

            ExecutionRequest::HttpRequest(arguments) if arguments.method == HttpMethod::Post => {
                PersistedReviewOperation::HttpPost {
                    url: arguments.url.clone(),
                    body: arguments.body.clone(),
                }
            }

            _ => {
                return Err("only reviewable privileged operations can be persisted".to_owned());
            }
        };

        Ok(Self {
            request_id: pending.request_id,
            purpose: pending.purpose.clone(),
            status: PersistedReviewStatus::Pending,
            operation,
        })
    }
}

impl TryFrom<PersistedPendingReview> for PendingReview {
    type Error = String;

    fn try_from(persisted: PersistedPendingReview) -> Result<Self, Self::Error> {
        let request = match persisted.operation {
            PersistedReviewOperation::WriteFile {
                path,
                content,
                target_state,
            } => {
                return Ok(PendingReview::new_with_write_target_state(
                    persisted.request_id,
                    ExecutionRequest::WriteFile(WriteFileArguments { path, content }),
                    persisted.purpose,
                    target_state,
                ));
            }

            PersistedReviewOperation::RunCargoTest {
                workspace_fingerprint,
            } => {
                return Ok(PendingReview::new_with_workspace_fingerprint(
                    persisted.request_id,
                    ExecutionRequest::RunCargoTest,
                    persisted.purpose,
                    workspace_fingerprint,
                ));
            }

            PersistedReviewOperation::HttpPost { url, body } => {
                ExecutionRequest::HttpRequest(HttpRequestArguments {
                    method: HttpMethod::Post,
                    url,
                    body,
                })
            }
        };

        Ok(PendingReview::new(
            persisted.request_id,
            request,
            persisted.purpose,
        ))
    }
}

impl PersistedPendingReviewState {
    const VERSION: u32 = 3;
}
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PersistenceTestFault {
    BeforeCommit,
    AfterCommit,
}

#[derive(Debug)]
enum PersistenceFailure {
    BeforeCommit(String),
    AfterCommit(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConsumeClaimedFailure {
    NotCommitted(String),
    DurabilityUncertain(String),
}

impl std::fmt::Display for ConsumeClaimedFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotCommitted(message) | Self::DurabilityUncertain(message) => {
                formatter.write_str(message)
            }
        }
    }
}
#[cfg(test)]
impl PersistenceFailure {
    fn into_message(self) -> String {
        match self {
            Self::BeforeCommit(message) | Self::AfterCommit(message) => message,
        }
    }
}
impl std::fmt::Display for PersistenceFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BeforeCommit(message) | Self::AfterCommit(message) => {
                formatter.write_str(message)
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct PendingReviewStore {
    reviews: HashMap<Uuid, PendingReview>,
    claimed_reviews: HashMap<Uuid, PendingReview>,
    persistence_path: Option<PathBuf>,

    #[cfg(test)]
    persistence_test_fault: Option<PersistenceTestFault>,
}

impl PendingReviewStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn persist(&self) -> Result<(), PersistenceFailure> {
        match &self.persistence_path {
            Some(path) => self.save_to_path_classified(path),
            None => Ok(()),
        }
    }
    pub(crate) fn consume_claimed_classified(
        &mut self,
        request_id: &Uuid,
    ) -> Result<PendingReview, ConsumeClaimedFailure> {
        let claimed = self.claimed_reviews.remove(request_id).ok_or_else(|| {
            ConsumeClaimedFailure::NotCommitted("claimed review request not found".to_owned())
        })?;

        if let Err(error) = self.persist() {
            match error {
                PersistenceFailure::BeforeCommit(message) => {
                    self.claimed_reviews.insert(*request_id, claimed.clone());

                    return Err(ConsumeClaimedFailure::NotCommitted(format!(
                        "failed to persist consumed claimed review: {message}"
                    )));
                }

                PersistenceFailure::AfterCommit(message) => {
                    return Err(ConsumeClaimedFailure::DurabilityUncertain(format!(
                        "claimed review was consumed but persistence durability is uncertain: {message}"
                    )));
                }
            }
        }

        Ok(claimed)
    }
    #[cfg(test)]
    pub(crate) fn consume_claimed(&mut self, request_id: &Uuid) -> Result<PendingReview, String> {
        self.consume_claimed_classified(request_id)
            .map_err(|error| error.to_string())
    }

    pub fn get_claimed(&self, request_id: &Uuid) -> Option<&PendingReview> {
        self.claimed_reviews.get(request_id)
    }
    pub fn claimed_count(&self) -> usize {
        self.claimed_reviews.len()
    }
    #[cfg(test)]
    pub(crate) fn set_persistence_test_fault(&mut self, fault: Option<PersistenceTestFault>) {
        self.persistence_test_fault = fault;
    }

    pub fn serialize_state(&self) -> Result<String, String> {
        let mut reviews = Vec::new();

        for pending in self.reviews.values() {
            let mut persisted = PersistedPendingReview::try_from(pending)?;
            persisted.status = PersistedReviewStatus::Pending;
            reviews.push(persisted);
        }

        for claimed in self.claimed_reviews.values() {
            let mut persisted = PersistedPendingReview::try_from(claimed)?;
            persisted.status = PersistedReviewStatus::Claimed;
            reviews.push(persisted);
        }

        let state = PersistedPendingReviewState {
            version: PersistedPendingReviewState::VERSION,
            reviews,
        };

        serde_json::to_string_pretty(&state)
            .map_err(|error| format!("failed to serialize pending review state: {error}"))
    }

    pub fn from_serialized_state(input: &str) -> Result<Self, String> {
        let state: PersistedPendingReviewState = serde_json::from_str(input)
            .map_err(|error| format!("failed to deserialize pending review state: {error}"))?;

        if state.version != PersistedPendingReviewState::VERSION {
            return Err(format!(
                "unsupported pending review state version: {}",
                state.version
            ));
        }

        let mut store = Self::new();

        for persisted in state.reviews {
            let status = persisted.status;
            let pending = PendingReview::try_from(persisted)?;
            let request_id = pending.request_id;

            if store.reviews.contains_key(&request_id)
                || store.claimed_reviews.contains_key(&request_id)
            {
                return Err("duplicate pending review request ID in persisted state".to_owned());
            }

            match status {
                PersistedReviewStatus::Pending => {
                    store.reviews.insert(request_id, pending);
                }

                PersistedReviewStatus::Claimed => {
                    store.claimed_reviews.insert(request_id, pending);
                }
            }
        }

        Ok(store)
    }

    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        let mut store = match std::fs::read_to_string(path) {
            Ok(contents) => Self::from_serialized_state(&contents)?,

            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::new(),

            Err(error) => {
                return Err(format!(
                    "failed to read pending review state file '{}': {error}",
                    path.display()
                ));
            }
        };

        store.persistence_path = Some(path.to_path_buf());

        Ok(store)
    }

    fn save_to_path_classified(&self, path: &Path) -> Result<(), PersistenceFailure> {
        let serialized = self
            .serialize_state()
            .map_err(PersistenceFailure::BeforeCommit)?;

        let parent = path.parent().ok_or_else(|| {
            PersistenceFailure::BeforeCommit(
                "pending review state path must have a parent directory".to_owned(),
            )
        })?;

        path.file_name().ok_or_else(|| {
            PersistenceFailure::BeforeCommit(
                "pending review state path must include a file name".to_owned(),
            )
        })?;

        let temporary_path = parent.join(format!(".zyguor-pending-reviews-{}.tmp", Uuid::new_v4()));

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        options.mode(0o600);

        let save_result = (|| -> Result<(), PersistenceFailure> {
            let mut temporary_file = options.open(&temporary_path).map_err(|error| {
                PersistenceFailure::BeforeCommit(format!(
                    "failed to create temporary pending review state file: {error}"
                ))
            })?;

            temporary_file
                .write_all(serialized.as_bytes())
                .map_err(|error| {
                    PersistenceFailure::BeforeCommit(format!(
                        "failed to write pending review state file: {error}"
                    ))
                })?;

            temporary_file.sync_all().map_err(|error| {
                PersistenceFailure::BeforeCommit(format!(
                    "failed to sync pending review state file: {error}"
                ))
            })?;

            drop(temporary_file);

            #[cfg(unix)]
            let parent_directory = std::fs::File::open(parent).map_err(|error| {
                PersistenceFailure::BeforeCommit(format!(
                    "failed to open pending review state parent directory for sync: {error}"
                ))
            })?;
            #[cfg(test)]
            if matches!(
                self.persistence_test_fault,
                Some(PersistenceTestFault::BeforeCommit)
            ) {
                return Err(PersistenceFailure::BeforeCommit(
                    "injected pre-commit persistence failure".to_owned(),
                ));
            }

            std::fs::rename(&temporary_path, path).map_err(|error| {
                PersistenceFailure::BeforeCommit(format!(
                    "failed to atomically replace pending review state file: {error}"
                ))
            })?;

            #[cfg(test)]
            if matches!(
                self.persistence_test_fault,
                Some(PersistenceTestFault::AfterCommit)
            ) {
                return Err(PersistenceFailure::AfterCommit(
                    "injected post-commit persistence failure".to_owned(),
                ));
            }

            #[cfg(unix)]
            parent_directory.sync_all().map_err(|error| {
                PersistenceFailure::AfterCommit(format!(
                    "pending review state was replaced but parent directory sync failed: {error}"
                ))
            })?;

            Ok(())
        })();

        if save_result.is_err() {
            match std::fs::remove_file(&temporary_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {}
            }
        }

        save_result
    }
    #[cfg(test)]
    pub fn save_to_path(&self, path: &Path) -> Result<(), String> {
        self.save_to_path_classified(path)
            .map_err(PersistenceFailure::into_message)
    }

    pub fn insert(&mut self, pending: PendingReview) -> Result<(), String> {
        if self.reviews.contains_key(&pending.request_id) {
            return Err("pending review request ID already exists".to_owned());
        }

        let request_id = pending.request_id;

        self.reviews.insert(request_id, pending);

        if let Err(error) = self.persist() {
            if matches!(&error, PersistenceFailure::BeforeCommit(_)) {
                self.reviews.remove(&request_id);
            }

            return Err(format!(
                "failed to persist pending review insertion: {error}"
            ));
        }

        Ok(())
    }

    #[cfg(test)]
    pub fn take(&mut self, request_id: &Uuid) -> Result<Option<PendingReview>, String> {
        let removed = self.reviews.remove(request_id);

        if removed.is_none() {
            return Ok(None);
        }

        if let Err(error) = self.persist() {
            if matches!(&error, PersistenceFailure::BeforeCommit(_))
                && let Some(pending) = removed.clone()
            {
                self.reviews.insert(*request_id, pending);
            }

            return Err(format!("failed to persist pending review removal: {error}"));
        }
        Ok(removed)
    }

    pub fn get(&self, request_id: &Uuid) -> Option<&PendingReview> {
        self.reviews.get(request_id)
    }

    pub fn claim(&mut self, request_id: &Uuid) -> Result<PendingReview, String> {
        if self.claimed_reviews.contains_key(request_id) {
            return Err("pending review request is already claimed".to_owned());
        }

        let pending = self
            .reviews
            .remove(request_id)
            .ok_or_else(|| "pending review request not found".to_owned())?;

        self.claimed_reviews.insert(*request_id, pending.clone());

        if let Err(error) = self.persist() {
            if matches!(&error, PersistenceFailure::BeforeCommit(_)) {
                self.claimed_reviews.remove(request_id);
                self.reviews.insert(*request_id, pending);
            }

            return Err(format!("failed to persist pending review claim: {error}"));
        }

        Ok(pending)
    }

    pub fn restore_claimed(&mut self, pending: PendingReview) -> Result<(), String> {
        let request_id = pending.request_id;

        if self.reviews.contains_key(&request_id) {
            return Err("pending review request ID already exists".to_owned());
        }

        let claimed = self
            .claimed_reviews
            .remove(&request_id)
            .ok_or_else(|| "claimed review request not found".to_owned())?;

        if claimed != pending {
            self.claimed_reviews.insert(request_id, claimed);

            return Err("claimed review does not match restoration request".to_owned());
        }

        self.reviews.insert(request_id, pending.clone());

        if let Err(error) = self.persist() {
            if matches!(&error, PersistenceFailure::BeforeCommit(_)) {
                self.reviews.remove(&request_id);
                self.claimed_reviews.insert(request_id, pending);
            }

            return Err(format!(
                "failed to persist restored pending review: {error}"
            ));
        }

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
    use super::{
        ConsumeClaimedFailure, PendingReview, PendingReviewStore, PersistenceFailure,
        PersistenceTestFault,
    };
    use crate::execution::{ExecutionRequest, WriteFileArguments};
    use crate::filesystem::WriteTargetState;

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
            Err("pending review request is already claimed".to_owned())
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

        assert_eq!(taken, Ok(Some(pending)));
        assert!(store.get(&request_id).is_none());
        assert!(store.is_empty());

        let second_take = store.take(&request_id);

        assert_eq!(second_take, Ok(None));
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

    #[test]
    fn serialized_pending_review_state_round_trips() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();

        let pending = PendingReview::new_with_write_target_state(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
            WriteTargetState::Missing,
        );

        let mut store = PendingReviewStore::new();
        store.insert(pending.clone())?;

        let serialized = store.serialize_state()?;
        let restored = PendingReviewStore::from_serialized_state(&serialized)?;

        assert_eq!(restored.get(&request_id), Some(&pending));

        Ok(())
    }

    #[test]
    fn rejects_unsupported_persisted_state_version() {
        let input = r#"{
            "version": 999,
            "reviews": []
        }"#;

        let result = PendingReviewStore::from_serialized_state(input);

        let error = result.expect_err("unsupported persisted state version should be rejected");

        assert_eq!(error, "unsupported pending review state version: 999");
    }

    #[cfg(unix)]
    #[test]
    fn saves_pending_review_state_as_private_file() -> Result<(), String> {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-pending-review-save-test-{}",
            uuid::Uuid::new_v4()
        ));

        fs::create_dir_all(&test_root)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let state_path = test_root.join("pending-reviews.json");
        let request_id = uuid::Uuid::new_v4();

        let pending = PendingReview::new_with_write_target_state(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
            WriteTargetState::Missing,
        );

        let mut store = PendingReviewStore::new();

        store.insert(pending.clone())?;
        store.save_to_path(&state_path)?;

        let serialized = fs::read_to_string(&state_path)
            .map_err(|error| format!("failed to read saved state: {error}"))?;

        let restored = PendingReviewStore::from_serialized_state(&serialized)?;

        assert_eq!(restored.get(&request_id), Some(&pending));

        let mode = fs::metadata(&state_path)
            .map_err(|error| format!("failed to read state metadata: {error}"))?
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(mode, 0o600);

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }

    #[test]
    fn missing_pending_review_state_file_loads_empty_store() -> Result<(), String> {
        let state_path = std::env::temp_dir().join(format!(
            "zyguor-missing-pending-review-state-{}.json",
            uuid::Uuid::new_v4()
        ));

        let store = PendingReviewStore::load_from_path(&state_path)?;

        assert!(store.is_empty());

        Ok(())
    }

    #[test]
    fn corrupt_pending_review_state_is_rejected() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-corrupt-pending-review-state-{}",
            uuid::Uuid::new_v4()
        ));

        fs::create_dir_all(&test_root)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let state_path = test_root.join("pending-reviews.json");

        fs::write(&state_path, "{not-valid-json")
            .map_err(|error| format!("failed to write corrupt state: {error}"))?;

        let result = PendingReviewStore::load_from_path(&state_path);

        assert!(result.is_err());

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }

    #[test]
    fn memory_only_store_persist_is_no_op() -> Result<(), String> {
        let store = PendingReviewStore::new();

        store.persist().map_err(PersistenceFailure::into_message)?;

        Ok(())
    }

    #[test]
    fn persistent_insert_is_saved_to_disk() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-persistent-insert-test-{}",
            uuid::Uuid::new_v4()
        ));

        fs::create_dir_all(&test_root)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let state_path = test_root.join("pending-reviews.json");
        let request_id = uuid::Uuid::new_v4();

        let mut store = PendingReviewStore::load_from_path(&state_path)?;

        let pending = PendingReview::new_with_write_target_state(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
            WriteTargetState::Missing,
        );

        store.insert(pending.clone())?;

        let restored = PendingReviewStore::load_from_path(&state_path)?;

        assert_eq!(restored.get(&request_id), Some(&pending));

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
    #[test]
    fn after_commit_insert_failure_keeps_memory_aligned_with_disk() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-after-commit-insert-test-{}",
            uuid::Uuid::new_v4()
        ));

        fs::create_dir_all(&test_root)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let state_path = test_root.join("pending-reviews.json");
        let request_id = uuid::Uuid::new_v4();

        let mut store = PendingReviewStore::load_from_path(&state_path)?;

        let pending = PendingReview::new_with_write_target_state(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
            WriteTargetState::Missing,
        );

        store.set_persistence_test_fault(Some(PersistenceTestFault::AfterCommit));

        let result = store.insert(pending.clone());

        let error = result.expect_err("injected post-commit failure should be reported");

        assert!(
            error.contains("injected post-commit persistence failure"),
            "unexpected persistence error: {error}"
        );

        // The rename already committed the new state, so memory must NOT roll back.
        assert_eq!(store.get(&request_id), Some(&pending));

        // The renamed state file must also contain the inserted review.
        let restored = PendingReviewStore::load_from_path(&state_path)?;

        assert_eq!(restored.get(&request_id), Some(&pending));

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
    #[test]
    fn before_commit_insert_failure_rolls_memory_back() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-before-commit-insert-test-{}",
            uuid::Uuid::new_v4()
        ));

        fs::create_dir_all(&test_root)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let state_path = test_root.join("pending-reviews.json");
        let request_id = uuid::Uuid::new_v4();

        let mut store = PendingReviewStore::load_from_path(&state_path)?;

        let pending = PendingReview::new_with_write_target_state(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
            WriteTargetState::Missing,
        );

        store.set_persistence_test_fault(Some(PersistenceTestFault::BeforeCommit));

        let result = store.insert(pending);

        let error = result.expect_err("injected pre-commit failure should be reported");

        assert!(
            error.contains("injected pre-commit persistence failure"),
            "unexpected persistence error: {error}"
        );

        // The rename never happened, so memory must roll back.
        assert!(store.get(&request_id).is_none());

        // No committed state file should exist.
        assert!(!state_path.exists());

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
    #[test]
    fn before_commit_consume_failure_keeps_claimed_request() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-before-commit-consume-test-{}",
            uuid::Uuid::new_v4()
        ));

        fs::create_dir_all(&test_root)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let state_path = test_root.join("pending-reviews.json");
        let request_id = uuid::Uuid::new_v4();

        let mut store = PendingReviewStore::load_from_path(&state_path)?;

        let pending = PendingReview::new_with_write_target_state(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
            WriteTargetState::Missing,
        );

        store.insert(pending.clone())?;
        store.claim(&request_id)?;

        store.set_persistence_test_fault(Some(PersistenceTestFault::BeforeCommit));

        let result = store.consume_claimed_classified(&request_id);

        let error = result.expect_err("injected pre-commit consume failure should be reported");

        assert!(
            matches!(error, ConsumeClaimedFailure::NotCommitted(_)),
            "expected NotCommitted consume failure, got: {error:?}"
        );

        assert_eq!(store.get_claimed(&request_id), Some(&pending));

        let restored = PendingReviewStore::load_from_path(&state_path)?;

        assert_eq!(restored.get_claimed(&request_id), Some(&pending));

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }

    #[test]
    fn after_commit_consume_failure_reports_durability_uncertain() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-after-commit-consume-test-{}",
            uuid::Uuid::new_v4()
        ));

        fs::create_dir_all(&test_root)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let state_path = test_root.join("pending-reviews.json");
        let request_id = uuid::Uuid::new_v4();

        let mut store = PendingReviewStore::load_from_path(&state_path)?;

        let pending = PendingReview::new_with_write_target_state(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
            WriteTargetState::Missing,
        );

        store.insert(pending)?;
        store.claim(&request_id)?;

        store.set_persistence_test_fault(Some(PersistenceTestFault::AfterCommit));

        let result = store.consume_claimed_classified(&request_id);

        let error = result.expect_err("injected post-commit consume failure should be reported");

        assert!(
            matches!(error, ConsumeClaimedFailure::DurabilityUncertain(_)),
            "expected DurabilityUncertain consume failure, got: {error:?}"
        );

        // The rename already crossed the commit boundary, so the running
        // process must not restore the claimed request.
        assert!(store.get_claimed(&request_id).is_none());
        assert!(store.get(&request_id).is_none());

        // The renamed disk state should also reflect the consumed request.
        let restored = PendingReviewStore::load_from_path(&state_path)?;

        assert!(restored.get_claimed(&request_id).is_none());
        assert!(restored.get(&request_id).is_none());

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }

    #[test]
    fn persistent_claim_moves_review_to_claimed_state() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-persistent-claim-test-{}",
            uuid::Uuid::new_v4()
        ));

        fs::create_dir_all(&test_root)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let state_path = test_root.join("pending-reviews.json");
        let request_id = uuid::Uuid::new_v4();

        let mut store = PendingReviewStore::load_from_path(&state_path)?;

        let pending = PendingReview::new_with_write_target_state(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
            WriteTargetState::Missing,
        );

        store.insert(pending.clone())?;

        let claimed = store.claim(&request_id)?;

        assert_eq!(claimed, pending);

        let restored = PendingReviewStore::load_from_path(&state_path)?;

        assert!(restored.get(&request_id).is_none());
        assert_eq!(restored.get_claimed(&request_id), Some(&pending));

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }

    #[test]
    fn persistent_take_removes_review_from_disk() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-persistent-take-test-{}",
            uuid::Uuid::new_v4()
        ));

        fs::create_dir_all(&test_root)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let state_path = test_root.join("pending-reviews.json");
        let request_id = uuid::Uuid::new_v4();

        let mut store = PendingReviewStore::load_from_path(&state_path)?;

        let pending = PendingReview::new_with_write_target_state(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
            WriteTargetState::Missing,
        );

        store.insert(pending.clone())?;

        let removed = store.take(&request_id)?;

        assert_eq!(removed, Some(pending));

        let restored = PendingReviewStore::load_from_path(&state_path)?;

        assert!(restored.get(&request_id).is_none());
        assert!(restored.is_empty());

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }

    #[test]
    fn persistent_restore_claimed_is_saved_to_disk() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-persistent-restore-test-{}",
            uuid::Uuid::new_v4()
        ));

        fs::create_dir_all(&test_root)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let state_path = test_root.join("pending-reviews.json");
        let request_id = uuid::Uuid::new_v4();

        let mut store = PendingReviewStore::load_from_path(&state_path)?;

        let pending = PendingReview::new_with_write_target_state(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
            WriteTargetState::Missing,
        );

        store.insert(pending.clone())?;

        let claimed = store.claim(&request_id)?;

        assert!(store.get(&request_id).is_none());

        store.restore_claimed(claimed)?;

        let restored = PendingReviewStore::load_from_path(&state_path)?;

        assert_eq!(restored.get(&request_id), Some(&pending));

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }

    #[test]
    fn pending_review_survives_store_reload() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-pending-review-reload-test-{}",
            uuid::Uuid::new_v4()
        ));

        fs::create_dir_all(&test_root)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let state_path = test_root.join("pending-reviews.json");
        let request_id = uuid::Uuid::new_v4();

        {
            let mut store = PendingReviewStore::load_from_path(&state_path)?;

            store.insert(PendingReview::new_with_write_target_state(
                request_id,
                ExecutionRequest::WriteFile(WriteFileArguments {
                    path: "config/settings.txt".to_owned(),
                    content: "enabled=true".to_owned(),
                }),
                "Update application configuration".to_owned(),
                WriteTargetState::Missing,
            ))?;
        }

        let restored = PendingReviewStore::load_from_path(&state_path)?;

        let pending = restored
            .get(&request_id)
            .ok_or_else(|| "pending review did not survive reload".to_owned())?;

        assert_eq!(pending.request_id, request_id);

        assert_eq!(pending.purpose, "Update application configuration");

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }

    #[test]
    fn persistent_claim_is_not_silently_lost_after_restart() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-persistent-claim-restart-test-{}",
            uuid::Uuid::new_v4()
        ));

        fs::create_dir_all(&test_root)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let state_path = test_root.join("pending-reviews.json");
        let request_id = uuid::Uuid::new_v4();

        let mut store = PendingReviewStore::load_from_path(&state_path)?;

        store.insert(PendingReview::new_with_write_target_state(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
            WriteTargetState::Missing,
        ))?;

        let _claimed = store.claim(&request_id)?;

        let restored = PendingReviewStore::load_from_path(&state_path)?;

        assert!(
            restored.get_claimed(&request_id).is_some(),
            "claimed review must survive restart as claimed state"
        );

        assert!(
            restored.get(&request_id).is_none(),
            "claimed review must not become normally approvable after restart"
        );

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }

    #[test]
    fn persistent_consume_removes_claimed_review_from_disk() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-persistent-consume-test-{}",
            uuid::Uuid::new_v4()
        ));

        fs::create_dir_all(&test_root)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let state_path = test_root.join("pending-reviews.json");
        let request_id = uuid::Uuid::new_v4();

        let mut store = PendingReviewStore::load_from_path(&state_path)?;

        let pending = PendingReview::new_with_write_target_state(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
            WriteTargetState::Missing,
        );

        store.insert(pending.clone())?;
        store.claim(&request_id)?;

        assert_eq!(store.get_claimed(&request_id), Some(&pending));

        let consumed = store.consume_claimed(&request_id)?;

        assert_eq!(consumed, pending);

        let restored = PendingReviewStore::load_from_path(&state_path)?;

        assert!(restored.get(&request_id).is_none());
        assert!(restored.get_claimed(&request_id).is_none());

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
    #[test]
    fn claimed_count_reports_claimed_reviews() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();

        let mut store = PendingReviewStore::new();

        store.insert(PendingReview::new_with_write_target_state(
            request_id,
            ExecutionRequest::WriteFile(WriteFileArguments {
                path: "config/settings.txt".to_owned(),
                content: "enabled=true".to_owned(),
            }),
            "Update application configuration".to_owned(),
            WriteTargetState::Missing,
        ))?;

        assert_eq!(store.claimed_count(), 0);

        store.claim(&request_id)?;

        assert_eq!(store.claimed_count(), 1);

        Ok(())
    }
}
