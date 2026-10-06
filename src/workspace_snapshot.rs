use std::fs;
use std::path::{Path, PathBuf};

const ROOT_FILES: &[&str] = &["Cargo.toml", "Cargo.lock", "build.rs"];
const SOURCE_DIRECTORIES: &[&str] = &["src", "tests"];

#[derive(Debug)]
pub struct WorkspaceSnapshot {
    path: PathBuf,
}

impl WorkspaceSnapshot {
    pub fn create(workspace: &Path) -> Result<Self, String> {
        let snapshot_root = std::env::temp_dir().join(format!(
            "zyguor-cargo-snapshot-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));

        fs::create_dir(&snapshot_root)
            .map_err(|error| format!("failed to create workspace snapshot: {error}"))?;

        let copy_result = copy_workspace_inputs(workspace, &snapshot_root);

        if let Err(error) = copy_result {
            let _ = fs::remove_dir_all(&snapshot_root);
            return Err(error);
        }

        Ok(Self {
            path: snapshot_root,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for WorkspaceSnapshot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn copy_workspace_inputs(workspace: &Path, snapshot: &Path) -> Result<(), String> {
    for file_name in ROOT_FILES {
        let source = workspace.join(file_name);

        match fs::symlink_metadata(&source) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(format!(
                        "workspace snapshot file must not be a symbolic link: {file_name}"
                    ));
                }

                if metadata.is_file() {
                    fs::copy(&source, snapshot.join(file_name)).map_err(|error| {
                        format!("failed to copy workspace file '{file_name}': {error}")
                    })?;
                }
            }

            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}

            Err(error) => {
                return Err(format!(
                    "failed to inspect workspace file '{file_name}': {error}"
                ));
            }
        }
    }

    for directory_name in SOURCE_DIRECTORIES {
        let source = workspace.join(directory_name);

        match fs::symlink_metadata(&source) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(format!(
                        "workspace snapshot directory must not be a symbolic link: \
                         {directory_name}"
                    ));
                }

                if metadata.is_dir() {
                    let destination = snapshot.join(directory_name);

                    fs::create_dir(&destination).map_err(|error| {
                        format!("failed to create snapshot directory '{directory_name}': {error}")
                    })?;

                    copy_directory(workspace, &source, &destination)?;
                }
            }

            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}

            Err(error) => {
                return Err(format!(
                    "failed to inspect workspace directory '{directory_name}': {error}"
                ));
            }
        }
    }

    Ok(())
}

fn copy_directory(workspace: &Path, source: &Path, destination: &Path) -> Result<(), String> {
    let entries = fs::read_dir(source).map_err(|error| {
        format!(
            "failed to read workspace directory '{}': {error}",
            source.strip_prefix(workspace).unwrap_or(source).display()
        )
    })?;

    for entry_result in entries {
        let entry = entry_result
            .map_err(|error| format!("failed to read workspace directory entry: {error}"))?;

        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());

        let metadata = fs::symlink_metadata(&source_path).map_err(|error| {
            format!(
                "failed to inspect workspace entry '{}': {error}",
                source_path.display()
            )
        })?;

        if metadata.file_type().is_symlink() {
            return Err(format!(
                "workspace snapshot entry must not be a symbolic link: {}",
                source_path
                    .strip_prefix(workspace)
                    .unwrap_or(&source_path)
                    .display()
            ));
        }

        if metadata.is_dir() {
            fs::create_dir(&destination_path).map_err(|error| {
                format!(
                    "failed to create snapshot directory '{}': {error}",
                    destination_path.display()
                )
            })?;

            copy_directory(workspace, &source_path, &destination_path)?;
        } else if metadata.is_file() {
            fs::copy(&source_path, &destination_path).map_err(|error| {
                format!(
                    "failed to copy workspace file '{}': {error}",
                    source_path.display()
                )
            })?;
        }
    }

    Ok(())
}
#[cfg(test)]
mod tests {
    use super::WorkspaceSnapshot;
    use std::fs;

    fn create_test_workspace(name: &str) -> Result<std::path::PathBuf, String> {
        let root = std::env::temp_dir().join(format!(
            "zyguor-workspace-snapshot-source-{name}-{}",
            uuid::Uuid::new_v4()
        ));

        fs::create_dir_all(root.join("src"))
            .map_err(|error| format!("failed to create test workspace: {error}"))?;

        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"snapshot-test\"\nversion = \"0.1.0\"\n",
        )
        .map_err(|error| format!("failed to write Cargo.toml: {error}"))?;

        fs::write(
            root.join("Cargo.lock"),
            "# snapshot test lockfile\nversion = 4\n",
        )
        .map_err(|error| format!("failed to write Cargo.lock: {error}"))?;

        fs::write(root.join("src/main.rs"), "fn main() {}\n")
            .map_err(|error| format!("failed to write source file: {error}"))?;

        Ok(root)
    }

    #[test]
    fn snapshot_copies_cargo_inputs() -> Result<(), String> {
        let workspace = create_test_workspace("copies-inputs")?;

        let snapshot = WorkspaceSnapshot::create(&workspace)?;

        assert!(snapshot.path().join("Cargo.toml").is_file());
        assert!(snapshot.path().join("Cargo.lock").is_file());
        assert!(snapshot.path().join("src/main.rs").is_file());

        fs::remove_dir_all(&workspace)
            .map_err(|error| format!("failed to remove test workspace: {error}"))?;

        Ok(())
    }

    #[test]
    fn snapshot_does_not_copy_target_or_operational_files() -> Result<(), String> {
        let workspace = create_test_workspace("ignores-unrelated")?;

        fs::create_dir_all(workspace.join("target/debug"))
            .map_err(|error| format!("failed to create target directory: {error}"))?;

        fs::write(workspace.join("target/debug/generated"), "generated")
            .map_err(|error| format!("failed to write target fixture: {error}"))?;

        fs::write(workspace.join("zyguor-audit.jsonl"), "{}\n")
            .map_err(|error| format!("failed to write audit fixture: {error}"))?;

        let snapshot = WorkspaceSnapshot::create(&workspace)?;

        assert!(!snapshot.path().join("target").exists());
        assert!(!snapshot.path().join("zyguor-audit.jsonl").exists());

        fs::remove_dir_all(&workspace)
            .map_err(|error| format!("failed to remove test workspace: {error}"))?;

        Ok(())
    }

    #[test]
    fn snapshot_is_removed_when_dropped() -> Result<(), String> {
        let workspace = create_test_workspace("drop-cleanup")?;

        let snapshot_path = {
            let snapshot = WorkspaceSnapshot::create(&workspace)?;
            let path = snapshot.path().to_path_buf();

            assert!(path.exists());

            path
        };

        assert!(!snapshot_path.exists());

        fs::remove_dir_all(&workspace)
            .map_err(|error| format!("failed to remove test workspace: {error}"))?;

        Ok(())
    }
}
