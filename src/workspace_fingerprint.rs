use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const ROOT_FILES: &[&str] = &["Cargo.toml", "Cargo.lock", "build.rs"];
const SOURCE_DIRECTORIES: &[&str] = &["src", "tests"];

pub fn compute_workspace_fingerprint(workspace: &Path) -> Result<String, String> {
    let mut files = Vec::new();

    for file_name in ROOT_FILES {
        let path = workspace.join(file_name);

        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(format!(
                        "fingerprinted workspace file must not be a symbolic link: {file_name}"
                    ));
                }

                if metadata.is_file() {
                    files.push(path);
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
        let directory = workspace.join(directory_name);

        match fs::symlink_metadata(&directory) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(format!(
                        "fingerprinted workspace directory must not be a symbolic link: \
                         {directory_name}"
                    ));
                }

                if metadata.is_dir() {
                    collect_files(workspace, &directory, &mut files)?;
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

    files.sort_by(|left, right| {
        let left_relative = left.strip_prefix(workspace).unwrap_or(left);
        let right_relative = right.strip_prefix(workspace).unwrap_or(right);

        left_relative.cmp(right_relative)
    });

    let mut hasher = Sha256::new();

    for path in files {
        let relative_path = path
            .strip_prefix(workspace)
            .map_err(|error| format!("failed to create relative workspace path: {error}"))?;

        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "failed to inspect fingerprinted file '{}': {error}",
                relative_path.display()
            )
        })?;

        if metadata.file_type().is_symlink() {
            return Err(format!(
                "fingerprinted workspace file must not be a symbolic link: {}",
                relative_path.display()
            ));
        }

        if !metadata.is_file() {
            return Err(format!(
                "fingerprinted workspace entry must be a regular file: {}",
                relative_path.display()
            ));
        }

        let contents = fs::read(&path).map_err(|error| {
            format!(
                "failed to read fingerprinted file '{}': {error}",
                relative_path.display()
            )
        })?;

        let relative_bytes = relative_path.to_string_lossy();

        hasher.update((relative_bytes.len() as u64).to_le_bytes());
        hasher.update(relative_bytes.as_bytes());
        hasher.update((contents.len() as u64).to_le_bytes());
        hasher.update(contents);
    }

    let digest = hasher.finalize();

    let fingerprint = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    Ok(fingerprint)
}

fn collect_files(
    workspace: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let entries = fs::read_dir(directory).map_err(|error| {
        let display_path = directory
            .strip_prefix(workspace)
            .unwrap_or(directory)
            .display();

        format!("failed to read workspace directory '{display_path}': {error}")
    })?;

    for entry_result in entries {
        let entry = entry_result
            .map_err(|error| format!("failed to read workspace directory entry: {error}"))?;

        let path = entry.path();

        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "failed to inspect workspace entry '{}': {error}",
                path.display()
            )
        })?;

        if metadata.file_type().is_symlink() {
            return Err(format!(
                "fingerprinted workspace entry must not be a symbolic link: {}",
                path.strip_prefix(workspace).unwrap_or(&path).display()
            ));
        }

        if metadata.is_dir() {
            collect_files(workspace, &path, files)?;
        } else if metadata.is_file() {
            files.push(path);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::compute_workspace_fingerprint;
    use std::fs;

    fn create_test_workspace(name: &str) -> Result<std::path::PathBuf, String> {
        let root = std::env::temp_dir().join(format!(
            "zyguor-workspace-fingerprint-{name}-{}",
            uuid::Uuid::new_v4()
        ));

        fs::create_dir_all(root.join("src"))
            .map_err(|error| format!("failed to create test workspace: {error}"))?;

        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"fingerprint-test\"\nversion = \"0.1.0\"\n",
        )
        .map_err(|error| format!("failed to write Cargo.toml: {error}"))?;

        fs::write(root.join("src/main.rs"), "fn main() {}\n")
            .map_err(|error| format!("failed to write test source: {error}"))?;

        Ok(root)
    }

    #[test]
    fn fingerprint_is_stable_for_unchanged_workspace() -> Result<(), String> {
        let workspace = create_test_workspace("stable")?;

        let first = compute_workspace_fingerprint(&workspace)?;
        let second = compute_workspace_fingerprint(&workspace)?;

        let cleanup_result = fs::remove_dir_all(&workspace)
            .map_err(|error| format!("failed to remove test workspace: {error}"));

        assert_eq!(first, second);

        cleanup_result
    }

    #[test]
    fn fingerprint_changes_when_rust_source_changes() -> Result<(), String> {
        let workspace = create_test_workspace("source-change")?;

        let before = compute_workspace_fingerprint(&workspace)?;

        fs::write(
            workspace.join("src/main.rs"),
            "fn main() { println!(\"changed\"); }\n",
        )
        .map_err(|error| format!("failed to modify test source: {error}"))?;

        let after = compute_workspace_fingerprint(&workspace)?;

        let cleanup_result = fs::remove_dir_all(&workspace)
            .map_err(|error| format!("failed to remove test workspace: {error}"));

        assert_ne!(before, after);

        cleanup_result
    }

    #[test]
    fn target_directory_does_not_change_fingerprint() -> Result<(), String> {
        let workspace = create_test_workspace("target-ignore")?;

        let before = compute_workspace_fingerprint(&workspace)?;

        fs::create_dir_all(workspace.join("target/debug"))
            .map_err(|error| format!("failed to create target directory: {error}"))?;

        fs::write(workspace.join("target/debug/generated"), "generated output")
            .map_err(|error| format!("failed to write target file: {error}"))?;

        let after = compute_workspace_fingerprint(&workspace)?;

        let cleanup_result = fs::remove_dir_all(&workspace)
            .map_err(|error| format!("failed to remove test workspace: {error}"));

        assert_eq!(before, after);

        cleanup_result
    }
}
