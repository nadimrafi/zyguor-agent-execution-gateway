use std::path::Path;
const MAX_GIT_STATUS_ENTRIES: usize = 10_000;

fn ensure_status_entry_capacity(current_count: usize, maximum: usize) -> Result<(), String> {
    if current_count >= maximum {
        return Err(format!(
            "Git status exceeds maximum entry count of {maximum}"
        ));
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GitStatusResult {
    pub branch: Option<String>,
    pub entries: Vec<GitStatusEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GitStatusEntry {
    pub path: String,
    pub index: Vec<GitChange>,
    pub worktree: Vec<GitChange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitChange {
    New,
    Modified,
    Deleted,
    Renamed,
    Typechange,
}

pub fn read_git_status(repository_path: &Path) -> Result<GitStatusResult, String> {
    let repository = git2::Repository::open(repository_path)
        .map_err(|error| format!("failed to open Git repository: {error}"))?;
    let authorized_root = repository_path
        .canonicalize()
        .map_err(|error| format!("failed to resolve authorized workspace: {error}"))?;

    let git_directory = repository
        .path()
        .canonicalize()
        .map_err(|error| format!("failed to resolve Git metadata directory: {error}"))?;

    if !git_directory.starts_with(&authorized_root) {
        return Err("Git metadata resolves outside the authorized workspace".to_owned());
    }

    let worktree = repository
        .workdir()
        .ok_or_else(|| "bare Git repositories are not supported".to_owned())?
        .canonicalize()
        .map_err(|error| format!("failed to resolve Git worktree: {error}"))?;

    if worktree != authorized_root {
        return Err("Git worktree does not match the authorized workspace".to_owned());
    }

    let branch = repository
        .head()
        .ok()
        .and_then(|head| head.shorthand().ok().map(str::to_owned));

    let statuses = repository
        .statuses(None)
        .map_err(|error| format!("failed to read Git status: {error}"))?;

    let mut entries = Vec::new();

    for entry in statuses.iter() {
        ensure_status_entry_capacity(entries.len(), MAX_GIT_STATUS_ENTRIES)?;
        let path = entry
            .path()
            .map_err(|error| format!("failed to read Git status path: {error}"))?;

        let status = entry.status();

        let mut index = Vec::new();
        let mut worktree = Vec::new();

        if status.contains(git2::Status::INDEX_NEW) {
            index.push(GitChange::New);
        }

        if status.contains(git2::Status::INDEX_MODIFIED) {
            index.push(GitChange::Modified);
        }

        if status.contains(git2::Status::INDEX_DELETED) {
            index.push(GitChange::Deleted);
        }

        if status.contains(git2::Status::INDEX_RENAMED) {
            index.push(GitChange::Renamed);
        }

        if status.contains(git2::Status::INDEX_TYPECHANGE) {
            index.push(GitChange::Typechange);
        }

        if status.contains(git2::Status::WT_NEW) {
            worktree.push(GitChange::New);
        }

        if status.contains(git2::Status::WT_MODIFIED) {
            worktree.push(GitChange::Modified);
        }

        if status.contains(git2::Status::WT_DELETED) {
            worktree.push(GitChange::Deleted);
        }

        if status.contains(git2::Status::WT_RENAMED) {
            worktree.push(GitChange::Renamed);
        }

        if status.contains(git2::Status::WT_TYPECHANGE) {
            worktree.push(GitChange::Typechange);
        }

        entries.push(GitStatusEntry {
            path: path.to_owned(),
            index,
            worktree,
        });
    }

    Ok(GitStatusResult { branch, entries })
}

#[cfg(test)]
mod tests {
    use super::{GitChange, read_git_status};

    #[test]
    fn reports_untracked_file_in_repository() -> Result<(), String> {
        let repository_path =
            std::env::temp_dir().join(format!("zyguor-git-status-test-{}", uuid::Uuid::new_v4()));

        std::fs::create_dir_all(&repository_path)
            .map_err(|error| format!("failed to create test repository directory: {error}"))?;

        git2::Repository::init(&repository_path)
            .map_err(|error| format!("failed to initialize test repository: {error}"))?;

        std::fs::write(repository_path.join("notes.txt"), "hello")
            .map_err(|error| format!("failed to write test file: {error}"))?;

        let status = read_git_status(&repository_path)?;

        let entry = status
            .entries
            .iter()
            .find(|entry| entry.path == "notes.txt")
            .ok_or_else(|| "expected notes.txt in Git status".to_owned())?;

        assert!(entry.worktree.contains(&GitChange::New));

        std::fs::remove_dir_all(&repository_path)
            .map_err(|error| format!("failed to remove test repository: {error}"))?;

        Ok(())
    }
    #[test]
    fn rejects_git_metadata_outside_workspace() -> Result<(), String> {
        let base =
            std::env::temp_dir().join(format!("zyguor-git-boundary-test-{}", uuid::Uuid::new_v4()));

        let workspace = base.join("workspace");
        let external_repository = base.join("external-repository");

        std::fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        std::fs::create_dir_all(&external_repository)
            .map_err(|error| format!("failed to create external repository directory: {error}"))?;

        let repository = git2::Repository::init(&external_repository)
            .map_err(|error| format!("failed to initialize external repository: {error}"))?;

        let git_dir = repository.path();

        std::fs::write(
            workspace.join(".git"),
            format!("gitdir: {}\n", git_dir.display()),
        )
        .map_err(|error| format!("failed to write Git indirection file: {error}"))?;

        let result = read_git_status(&workspace);

        assert_eq!(
            result,
            Err("Git metadata resolves outside the authorized workspace".to_owned())
        );
        std::fs::remove_dir_all(&base)
            .map_err(|error| format!("failed to remove test directories: {error}"))?;

        Ok(())
    }
    #[test]
    fn accepts_git_status_entry_below_limit() -> Result<(), String> {
        super::ensure_status_entry_capacity(9_999, 10_000)
    }

    #[test]
    fn rejects_git_status_entry_at_limit() {
        let result = super::ensure_status_entry_capacity(10_000, 10_000);

        assert_eq!(
            result,
            Err("Git status exceeds maximum entry count of 10000".to_owned())
        );
    }
}
