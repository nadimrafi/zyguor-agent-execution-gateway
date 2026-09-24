use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const MAX_READ_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct FileSystemCapability {
    workspace_root: PathBuf,
}

impl FileSystemCapability {
    pub fn new(workspace_root: PathBuf) -> Self {
        Self { workspace_root }
    }

    pub fn validate_relative_path(&self, requested_path: &str) -> Result<PathBuf, String> {
        let path = Path::new(requested_path);

        if path.is_absolute() {
            return Err("absolute paths are not allowed".to_owned());
        }

        for component in path.components() {
            match component {
                Component::ParentDir => {
                    return Err("parent directory traversal is not allowed".to_owned());
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err("path must remain inside the workspace".to_owned());
                }
                Component::CurDir | Component::Normal(_) => {}
            }
        }

        Ok(self.workspace_root.join(path))
    }

    pub fn resolve_existing_path(&self, requested_path: &str) -> Result<PathBuf, String> {
        let candidate = self.validate_relative_path(requested_path)?;

        let canonical_root = self
            .workspace_root
            .canonicalize()
            .map_err(|error| format!("failed to resolve workspace root: {error}"))?;

        let canonical_candidate = candidate
            .canonicalize()
            .map_err(|error| format!("failed to resolve requested path: {error}"))?;

        if !canonical_candidate.starts_with(&canonical_root) {
            return Err("requested path escapes the workspace".to_owned());
        }

        Ok(canonical_candidate)
    }

    pub fn resolve_write_target(&self, requested_path: &str) -> Result<PathBuf, String> {
        let candidate = self.validate_relative_path(requested_path)?;

        let canonical_root = self
            .workspace_root
            .canonicalize()
            .map_err(|error| format!("failed to resolve workspace root: {error}"))?;

        if candidate.exists() {
            let canonical_candidate = candidate
                .canonicalize()
                .map_err(|error| format!("failed to resolve requested path: {error}"))?;

            if !canonical_candidate.starts_with(&canonical_root) {
                return Err("requested path escapes the workspace".to_owned());
            }

            return Ok(canonical_candidate);
        }

        let parent = candidate
            .parent()
            .ok_or_else(|| "write target must have a parent directory".to_owned())?;

        let canonical_parent = parent
            .canonicalize()
            .map_err(|error| format!("failed to resolve write target parent: {error}"))?;

        if !canonical_parent.starts_with(&canonical_root) {
            return Err("requested path escapes the workspace".to_owned());
        }

        let file_name = candidate
            .file_name()
            .ok_or_else(|| "write target must include a file name".to_owned())?;

        Ok(canonical_parent.join(file_name))
    }

    pub fn read_text_file(&self, requested_path: &str) -> Result<String, String> {
        let resolved_path = self.resolve_existing_path(requested_path)?;

        let file = File::open(&resolved_path)
            .map_err(|error| format!("failed to open requested file: {error}"))?;

        let mut buffer = Vec::new();

        file.take(MAX_READ_BYTES + 1)
            .read_to_end(&mut buffer)
            .map_err(|error| format!("failed to read requested file: {error}"))?;

        if buffer.len() as u64 > MAX_READ_BYTES {
            return Err(format!(
                "requested file exceeds maximum read size of {MAX_READ_BYTES} bytes"
            ));
        }

        String::from_utf8(buffer)
            .map_err(|error| format!("requested file is not valid UTF-8: {error}"))
    }
}
#[cfg(test)]
mod tests {
    use super::{FileSystemCapability, MAX_READ_BYTES};
    use std::path::PathBuf;

    #[test]
    fn accepts_relative_path_inside_workspace() {
        let capability = FileSystemCapability::new(PathBuf::from("/workspace"));

        let result = capability
            .validate_relative_path("docs/README.md")
            .expect("relative workspace path should be accepted");

        assert_eq!(result, PathBuf::from("/workspace/docs/README.md"));
    }

    #[test]
    fn rejects_parent_directory_traversal() {
        let capability = FileSystemCapability::new(PathBuf::from("/workspace"));

        let result = capability.validate_relative_path("../secret.txt");

        assert_eq!(
            result.expect_err("parent traversal should be rejected"),
            "parent directory traversal is not allowed"
        );
    }

    #[test]
    fn rejects_nested_parent_directory_traversal() {
        let capability = FileSystemCapability::new(PathBuf::from("/workspace"));

        let result = capability.validate_relative_path("docs/../../secret.txt");

        assert_eq!(
            result.expect_err("nested parent traversal should be rejected"),
            "parent directory traversal is not allowed"
        );
    }

    #[test]
    fn rejects_absolute_path() {
        let capability = FileSystemCapability::new(PathBuf::from("/workspace"));

        let result = capability.validate_relative_path("/etc/passwd");

        assert_eq!(
            result.expect_err("absolute path should be rejected"),
            "absolute paths are not allowed"
        );
    }
    #[cfg(unix)]
    #[test]
    fn rejects_symlink_that_escapes_workspace() -> Result<(), String> {
        use std::fs;
        use std::os::unix::fs::symlink;

        let test_root =
            std::env::temp_dir().join(format!("zyguor-filesystem-test-{}", std::process::id()));

        let workspace = test_root.join("workspace");
        let outside = test_root.join("outside");
        let outside_file = outside.join("secret.txt");
        let workspace_link = workspace.join("escape");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        fs::create_dir_all(&outside)
            .map_err(|error| format!("failed to create outside directory: {error}"))?;

        fs::write(&outside_file, "outside workspace")
            .map_err(|error| format!("failed to create outside test file: {error}"))?;

        symlink(&outside_file, &workspace_link)
            .map_err(|error| format!("failed to create test symlink: {error}"))?;

        let capability = FileSystemCapability::new(workspace);

        let result = capability.resolve_existing_path("escape");

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        assert_eq!(
            result.expect_err("symlink escape should be rejected"),
            "requested path escapes the workspace"
        );

        Ok(())
    }

    #[test]
    fn resolves_existing_file_inside_workspace() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-valid-test-{}",
            std::process::id()
        ));

        let workspace = test_root.join("workspace");
        let docs = workspace.join("docs");
        let file = docs.join("README.md");

        fs::create_dir_all(&docs)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        fs::write(&file, "approved workspace file")
            .map_err(|error| format!("failed to create test file: {error}"))?;

        let capability = FileSystemCapability::new(workspace);

        let resolved = capability.resolve_existing_path("docs/README.md")?;

        let expected = file
            .canonicalize()
            .map_err(|error| format!("failed to resolve expected test file: {error}"))?;

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        assert_eq!(resolved, expected);

        Ok(())
    }

    #[test]
    fn resolves_new_write_target_inside_workspace() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-write-new-test-{}",
            std::process::id()
        ));

        let workspace = test_root.join("workspace");
        let docs = workspace.join("docs");

        fs::create_dir_all(&docs)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let capability = FileSystemCapability::new(workspace);

        let resolved = capability.resolve_write_target("docs/new.txt")?;

        let canonical_docs = docs
            .canonicalize()
            .map_err(|error| format!("failed to resolve expected directory: {error}"))?;

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        assert_eq!(resolved, canonical_docs.join("new.txt"));

        Ok(())
    }

    #[test]
    fn resolves_existing_write_target_inside_workspace() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-write-existing-test-{}",
            std::process::id()
        ));

        let workspace = test_root.join("workspace");
        let file = workspace.join("existing.txt");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        fs::write(&file, "existing content")
            .map_err(|error| format!("failed to create test file: {error}"))?;

        let capability = FileSystemCapability::new(workspace);

        let resolved = capability.resolve_write_target("existing.txt")?;

        let expected = file
            .canonicalize()
            .map_err(|error| format!("failed to resolve expected file: {error}"))?;

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        assert_eq!(resolved, expected);

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_existing_write_symlink_that_escapes_workspace() -> Result<(), String> {
        use std::fs;
        use std::os::unix::fs::symlink;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-write-symlink-test-{}",
            std::process::id()
        ));

        let workspace = test_root.join("workspace");
        let outside = test_root.join("outside");
        let outside_file = outside.join("secret.txt");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        fs::create_dir_all(&outside)
            .map_err(|error| format!("failed to create outside directory: {error}"))?;

        fs::write(&outside_file, "outside workspace")
            .map_err(|error| format!("failed to create outside file: {error}"))?;

        symlink(&outside_file, workspace.join("escape.txt"))
            .map_err(|error| format!("failed to create test symlink: {error}"))?;

        let capability = FileSystemCapability::new(workspace);

        let result = capability.resolve_write_target("escape.txt");

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        assert_eq!(
            result.expect_err("symlink escape should be rejected"),
            "requested path escapes the workspace"
        );

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_write_through_symlinked_parent_outside_workspace() -> Result<(), String> {
        use std::fs;
        use std::os::unix::fs::symlink;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-write-parent-symlink-test-{}",
            std::process::id()
        ));

        let workspace = test_root.join("workspace");
        let outside = test_root.join("outside");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        fs::create_dir_all(&outside)
            .map_err(|error| format!("failed to create outside directory: {error}"))?;

        symlink(&outside, workspace.join("escape"))
            .map_err(|error| format!("failed to create directory symlink: {error}"))?;

        let capability = FileSystemCapability::new(workspace);

        let result = capability.resolve_write_target("escape/new.txt");

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        assert_eq!(
            result.expect_err("symlinked parent escape should be rejected"),
            "requested path escapes the workspace"
        );

        Ok(())
    }

    #[test]
    fn reads_text_file_inside_workspace() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-read-test-{}",
            std::process::id()
        ));

        let workspace = test_root.join("workspace");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        fs::write(workspace.join("hello.txt"), "Hello from Zyguor")
            .map_err(|error| format!("failed to create test file: {error}"))?;

        let capability = FileSystemCapability::new(workspace);

        let content = capability.read_text_file("hello.txt")?;

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        assert_eq!(content, "Hello from Zyguor");

        Ok(())
    }
    #[test]
    fn rejects_file_larger_than_read_limit() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-large-test-{}",
            std::process::id()
        ));

        let workspace = test_root.join("workspace");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        let oversized_content = vec![b'a'; (MAX_READ_BYTES + 1) as usize];

        fs::write(workspace.join("large.txt"), oversized_content)
            .map_err(|error| format!("failed to create oversized test file: {error}"))?;

        let capability = FileSystemCapability::new(workspace);

        let result = capability.read_text_file("large.txt");

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        assert_eq!(
            result.expect_err("oversized file should be rejected"),
            format!("requested file exceeds maximum read size of {MAX_READ_BYTES} bytes")
        );

        Ok(())
    }

    #[test]
    fn rejects_invalid_utf8_file() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-utf8-test-{}",
            std::process::id()
        ));

        let workspace = test_root.join("workspace");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        fs::write(workspace.join("binary.dat"), [0xff, 0xfe, 0xfd])
            .map_err(|error| format!("failed to create invalid UTF-8 test file: {error}"))?;

        let capability = FileSystemCapability::new(workspace);

        let result = capability.read_text_file("binary.dat");

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        let error = result.expect_err("invalid UTF-8 file should be rejected");

        assert!(error.starts_with("requested file is not valid UTF-8:"));

        Ok(())
    }
}
