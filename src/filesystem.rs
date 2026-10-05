use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

const MAX_READ_BYTES: u64 = 1024 * 1024;
const MAX_WRITE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct FileSystemCapability {
    workspace_root: PathBuf,
    workspace_dir: Option<Arc<Dir>>,
}

impl FileSystemCapability {
    #[cfg(test)]
    pub fn new(workspace_root: PathBuf) -> Self {
        Self {
            workspace_root,
            workspace_dir: None,
        }
    }
    pub fn try_new(workspace_root: PathBuf) -> Result<Self, String> {
        let workspace_dir = Dir::open_ambient_dir(&workspace_root, ambient_authority())
            .map_err(|error| format!("failed to open workspace capability: {error}"))?;

        Ok(Self {
            workspace_root,
            workspace_dir: Some(Arc::new(workspace_dir)),
        })
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
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
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

        if candidate.symlink_metadata().is_ok() {
            let canonical_candidate = candidate
                .canonicalize()
                .map_err(|error| format!("failed to resolve requested path: {error}"))?;

            if !canonical_candidate.starts_with(&canonical_root) {
                return Err("requested path escapes the workspace".to_owned());
            }
            if !canonical_candidate.is_file() {
                return Err("write target must be a regular file".to_owned());
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
    pub fn revalidate_write_target(&self, requested_path: &str) -> Result<(), String> {
        let relative_path = Path::new(requested_path);

        if relative_path.is_absolute() {
            return Err("absolute paths are not allowed".to_owned());
        }

        for component in relative_path.components() {
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

        let parent = relative_path
            .parent()
            .ok_or_else(|| "write target must have a parent directory".to_owned())?;

        let workspace = self.workspace_dir.as_ref().ok_or_else(|| {
            "write revalidation requires an anchored workspace capability".to_owned()
        })?;

        if !parent.as_os_str().is_empty() {
            workspace
                .open_dir_nofollow(parent)
                .map_err(|error| format!("failed to revalidate write target parent: {error}"))?;
        }

        match workspace.symlink_metadata(relative_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err("write target must not be a symbolic link".to_owned());
                }

                if !metadata.is_file() {
                    return Err("write target must be a regular file".to_owned());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "failed to revalidate existing write target: {error}"
                ));
            }
        }

        Ok(())
    }

    pub fn write_text_file(&self, requested_path: &str, content: &str) -> Result<(), String> {
        if content.len() > MAX_WRITE_BYTES {
            return Err(format!(
                "write content exceeds maximum size of {MAX_WRITE_BYTES} bytes"
            ));
        }

        let relative_path = Path::new(requested_path);

        if relative_path.is_absolute() {
            return Err("absolute paths are not allowed".to_owned());
        }

        for component in relative_path.components() {
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

        relative_path
            .file_name()
            .ok_or_else(|| "write target must include a file name".to_owned())?;
        let parent = relative_path.parent().unwrap_or_else(|| Path::new(""));

        let workspace = self
            .workspace_dir
            .as_ref()
            .ok_or_else(|| "secure write requires an anchored workspace capability".to_owned())?;

        self.revalidate_write_target(requested_path)?;

        let existing_permissions = match workspace.symlink_metadata(relative_path) {
            Ok(metadata) => Some(metadata.permissions()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(format!(
                    "failed to read existing write target metadata: {error}"
                ));
            }
        };

        let temporary_name = format!(".zyguor-write-{}.tmp", uuid::Uuid::new_v4());

        let temporary_path = if parent.as_os_str().is_empty() {
            PathBuf::from(&temporary_name)
        } else {
            parent.join(&temporary_name)
        };

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        options.follow(FollowSymlinks::No);

        let write_result = (|| -> Result<(), String> {
            let mut temporary_file = workspace
                .open_with(&temporary_path, &options)
                .map_err(|error| format!("failed to create temporary write file: {error}"))?;

            if let Some(permissions) = existing_permissions {
                temporary_file
                    .set_permissions(permissions)
                    .map_err(|error| {
                        format!("failed to preserve existing file permissions: {error}")
                    })?;
            }

            temporary_file
                .write_all(content.as_bytes())
                .map_err(|error| format!("failed to write temporary file: {error}"))?;

            temporary_file
                .sync_all()
                .map_err(|error| format!("failed to sync temporary file: {error}"))?;

            drop(temporary_file);

            workspace
                .rename(&temporary_path, workspace, relative_path)
                .map_err(|error| format!("failed to atomically replace requested file: {error}"))?;

            Ok(())
        })();
        if write_result.is_err() {
            match workspace.remove_file(&temporary_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {}
            }
        }

        write_result
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
    use super::{FileSystemCapability, MAX_READ_BYTES, MAX_WRITE_BYTES};
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

        let capability = FileSystemCapability::try_new(workspace)?;

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
    #[test]
    fn rejects_directory_as_write_target() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-write-directory-test-{}",
            std::process::id()
        ));

        let workspace = test_root.join("workspace");
        let directory_target = workspace.join("existing-directory");

        fs::create_dir_all(&directory_target)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let capability = FileSystemCapability::new(workspace);

        let result = capability.resolve_write_target("existing-directory");

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        assert_eq!(
            result.expect_err("directory write target should be rejected"),
            "write target must be a regular file"
        );

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_broken_final_symlink_as_write_target() -> Result<(), String> {
        use std::fs;
        use std::os::unix::fs::symlink;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-broken-write-symlink-test-{}",
            std::process::id()
        ));

        let workspace = test_root.join("workspace");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        symlink("missing-target.txt", workspace.join("broken-link.txt"))
            .map_err(|error| format!("failed to create broken symlink: {error}"))?;

        let capability = FileSystemCapability::new(workspace);

        let result = capability.resolve_write_target("broken-link.txt");

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        let error = result.expect_err("broken final symlink should be rejected");

        assert!(error.starts_with("failed to resolve requested path:"));

        Ok(())
    }
    #[test]
    fn securely_writes_new_file_inside_workspace() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-secure-write-test-{}",
            uuid::Uuid::new_v4()
        ));

        let workspace = test_root.join("workspace");
        let config_dir = workspace.join("config");

        fs::create_dir_all(&config_dir)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let capability = FileSystemCapability::try_new(workspace.clone())?;

        capability.write_text_file("config/settings.txt", "enabled=true")?;

        let content = fs::read_to_string(workspace.join("config/settings.txt"))
            .map_err(|error| format!("failed to read written test file: {error}"))?;

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        assert_eq!(content, "enabled=true");

        Ok(())
    }
    #[test]
    fn secure_write_rejects_parent_directory_traversal() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-write-traversal-test-{}",
            uuid::Uuid::new_v4()
        ));

        let workspace = test_root.join("workspace");
        let outside_file = test_root.join("outside.txt");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        let capability = FileSystemCapability::new(workspace);

        let result = capability.write_text_file("../outside.txt", "must-not-be-written");

        assert_eq!(
            result,
            Err("parent directory traversal is not allowed".to_owned())
        );
        assert!(!outside_file.exists());

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn secure_write_rejects_symlink_escape_outside_workspace() -> Result<(), String> {
        use std::fs;
        use std::os::unix::fs::symlink;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-write-symlink-escape-test-{}",
            uuid::Uuid::new_v4()
        ));

        let workspace = test_root.join("workspace");
        let outside_file = test_root.join("outside.txt");
        let symlink_path = workspace.join("escape.txt");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        fs::write(&outside_file, "original")
            .map_err(|error| format!("failed to create outside test file: {error}"))?;

        symlink(&outside_file, &symlink_path)
            .map_err(|error| format!("failed to create test symlink: {error}"))?;

        let capability = FileSystemCapability::try_new(workspace)?;

        let result = capability.write_text_file("escape.txt", "must-not-be-written");

        assert!(result.is_err());

        let outside_content = fs::read_to_string(&outside_file)
            .map_err(|error| format!("failed to read outside test file: {error}"))?;

        assert_eq!(outside_content, "original");

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn secure_write_rejects_parent_symlink_escape_outside_workspace() -> Result<(), String> {
        use std::fs;
        use std::os::unix::fs::symlink;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-write-parent-symlink-test-{}",
            uuid::Uuid::new_v4()
        ));

        let workspace = test_root.join("workspace");
        let outside_dir = test_root.join("outside");
        let outside_file = outside_dir.join("settings.txt");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        fs::create_dir_all(&outside_dir)
            .map_err(|error| format!("failed to create outside directory: {error}"))?;

        fs::write(&outside_file, "original")
            .map_err(|error| format!("failed to create outside test file: {error}"))?;

        symlink(&outside_dir, workspace.join("config"))
            .map_err(|error| format!("failed to create parent symlink: {error}"))?;

        let capability = FileSystemCapability::try_new(workspace)?;

        let result = capability.write_text_file("config/settings.txt", "must-not-be-written");

        assert!(result.is_err());

        let outside_content = fs::read_to_string(&outside_file)
            .map_err(|error| format!("failed to read outside test file: {error}"))?;

        assert_eq!(outside_content, "original");

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn secure_write_rejects_internal_parent_symlink() -> Result<(), String> {
        use std::fs;
        use std::os::unix::fs::symlink;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-write-internal-symlink-test-{}",
            uuid::Uuid::new_v4()
        ));

        let workspace = test_root.join("workspace");
        let real_dir = workspace.join("real-config");

        fs::create_dir_all(&real_dir)
            .map_err(|error| format!("failed to create real directory: {error}"))?;

        fs::write(real_dir.join("settings.txt"), "original")
            .map_err(|error| format!("failed to create test file: {error}"))?;

        symlink(&real_dir, workspace.join("config"))
            .map_err(|error| format!("failed to create internal symlink: {error}"))?;

        let capability = FileSystemCapability::try_new(workspace.clone())?;

        let result = capability.write_text_file("config/settings.txt", "updated");

        let content = fs::read_to_string(real_dir.join("settings.txt"))
            .map_err(|error| format!("failed to read test file: {error}"))?;

        assert!(result.is_err());
        assert_eq!(content, "original");
        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
    #[test]
    fn anchored_revalidation_accepts_new_file_with_valid_parent() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-revalidation-valid-new-file-test-{}",
            uuid::Uuid::new_v4()
        ));

        let workspace = test_root.join("workspace");
        let config_dir = workspace.join("config");

        fs::create_dir_all(&config_dir)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        let capability = FileSystemCapability::try_new(workspace)?;

        let result = capability.revalidate_write_target("config/settings.txt");

        assert_eq!(result, Ok(()));

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
    #[test]
    fn anchored_revalidation_accepts_existing_regular_file() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-revalidation-existing-file-test-{}",
            uuid::Uuid::new_v4()
        ));

        let workspace = test_root.join("workspace");
        let existing_file = workspace.join("settings.txt");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        fs::write(&existing_file, "original")
            .map_err(|error| format!("failed to create existing test file: {error}"))?;

        let capability = FileSystemCapability::try_new(workspace)?;

        let result = capability.revalidate_write_target("settings.txt");

        assert_eq!(result, Ok(()));

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
    #[test]
    fn anchored_revalidation_accepts_new_file_at_workspace_root() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-revalidation-root-file-test-{}",
            uuid::Uuid::new_v4()
        ));

        let workspace = test_root.join("workspace");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        let capability = FileSystemCapability::try_new(workspace)?;

        let result = capability.revalidate_write_target("new.txt");

        assert_eq!(result, Ok(()));

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn anchored_revalidation_rejects_final_symlink() -> Result<(), String> {
        use std::fs;
        use std::os::unix::fs::symlink;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-revalidation-final-symlink-test-{}",
            uuid::Uuid::new_v4()
        ));

        let workspace = test_root.join("workspace");
        let real_file = workspace.join("real.txt");
        let linked_file = workspace.join("linked.txt");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        fs::write(&real_file, "original")
            .map_err(|error| format!("failed to create test file: {error}"))?;

        symlink(&real_file, &linked_file)
            .map_err(|error| format!("failed to create final symlink: {error}"))?;

        let capability = FileSystemCapability::try_new(workspace)?;

        let result = capability.revalidate_write_target("linked.txt");

        assert!(result.is_err(), "unexpected result: {result:?}");

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn anchored_revalidation_rejects_internal_parent_symlink() -> Result<(), String> {
        use std::fs;
        use std::os::unix::fs::symlink;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-revalidation-parent-symlink-test-{}",
            uuid::Uuid::new_v4()
        ));

        let workspace = test_root.join("workspace");
        let real_dir = workspace.join("real");

        fs::create_dir_all(&real_dir)
            .map_err(|error| format!("failed to create test directory: {error}"))?;

        symlink(&real_dir, workspace.join("linked"))
            .map_err(|error| format!("failed to create parent symlink: {error}"))?;

        let capability = FileSystemCapability::try_new(workspace)?;

        let result = capability.revalidate_write_target("linked/new.txt");

        assert!(result.is_err());

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn secure_write_rejects_internal_final_symlink() -> Result<(), String> {
        use std::fs;
        use std::os::unix::fs::symlink;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-write-final-symlink-test-{}",
            uuid::Uuid::new_v4()
        ));

        let workspace = test_root.join("workspace");
        let real_file = workspace.join("real.txt");
        let alias_file = workspace.join("alias.txt");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        fs::write(&real_file, "original")
            .map_err(|error| format!("failed to create real test file: {error}"))?;

        symlink("real.txt", &alias_file)
            .map_err(|error| format!("failed to create internal symlink: {error}"))?;

        let capability = FileSystemCapability::try_new(workspace)?;

        let result = capability.write_text_file("alias.txt", "must-not-be-written");

        assert!(result.is_err());

        let content = fs::read_to_string(&real_file)
            .map_err(|error| format!("failed to read real test file: {error}"))?;

        assert_eq!(content, "original");

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
    #[test]
    fn secure_write_rejects_content_over_maximum_size() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-write-size-test-{}",
            uuid::Uuid::new_v4()
        ));

        let workspace = test_root.join("workspace");
        let target = workspace.join("large.txt");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        let capability = FileSystemCapability::new(workspace);
        let oversized_content = "a".repeat(MAX_WRITE_BYTES + 1);

        let result = capability.write_text_file("large.txt", &oversized_content);

        assert_eq!(
            result,
            Err(format!(
                "write content exceeds maximum size of {MAX_WRITE_BYTES} bytes"
            ))
        );

        assert!(!target.exists());

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
    #[test]
    fn secure_write_accepts_content_at_maximum_size() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-write-max-test-{}",
            uuid::Uuid::new_v4()
        ));

        let workspace = test_root.join("workspace");
        let target = workspace.join("maximum.txt");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        let capability = FileSystemCapability::try_new(workspace)?;
        let content = "a".repeat(MAX_WRITE_BYTES);

        capability.write_text_file("maximum.txt", &content)?;

        let written =
            fs::read(&target).map_err(|error| format!("failed to read written file: {error}"))?;

        assert_eq!(written.len(), MAX_WRITE_BYTES);

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
    #[test]
    fn secure_write_overwrites_existing_regular_file() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-write-overwrite-test-{}",
            uuid::Uuid::new_v4()
        ));

        let workspace = test_root.join("workspace");
        let target = workspace.join("settings.txt");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        fs::write(&target, "old-value")
            .map_err(|error| format!("failed to create existing file: {error}"))?;

        let capability = FileSystemCapability::try_new(workspace)?;

        capability.write_text_file("settings.txt", "new-value")?;

        let written = fs::read_to_string(&target)
            .map_err(|error| format!("failed to read overwritten file: {error}"))?;

        assert_eq!(written, "new-value");

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn secure_write_replaces_existing_file_atomically() -> Result<(), String> {
        use std::fs::{self, File};
        use std::io::{Read, Seek, SeekFrom};

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-atomic-write-test-{}",
            uuid::Uuid::new_v4()
        ));

        let workspace = test_root.join("workspace");
        let target = workspace.join("settings.txt");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        fs::write(&target, "old-value")
            .map_err(|error| format!("failed to create existing file: {error}"))?;

        let mut old_handle = File::open(&target)
            .map_err(|error| format!("failed to open existing file: {error}"))?;

        let capability = FileSystemCapability::try_new(workspace)?;

        capability.write_text_file("settings.txt", "new-value")?;

        let current_content = fs::read_to_string(&target)
            .map_err(|error| format!("failed to read replacement file: {error}"))?;

        assert_eq!(current_content, "new-value");

        old_handle
            .seek(SeekFrom::Start(0))
            .map_err(|error| format!("failed to seek old file handle: {error}"))?;

        let mut old_content = String::new();

        old_handle
            .read_to_string(&mut old_content)
            .map_err(|error| format!("failed to read old file handle: {error}"))?;

        assert_eq!(old_content, "old-value");

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
    #[test]
    fn secure_write_rejects_missing_parent_directory() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-write-missing-parent-test-{}",
            uuid::Uuid::new_v4()
        ));

        let workspace = test_root.join("workspace");
        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        let capability = FileSystemCapability::try_new(workspace.clone())?;

        let result = capability.write_text_file("missing/settings.txt", "enabled=true");

        assert!(result.is_err());
        assert!(!workspace.join("missing").exists());
        assert!(!workspace.join("missing/settings.txt").exists());

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
    #[test]
    fn secure_write_rejects_directory_target() -> Result<(), String> {
        use std::fs;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-write-directory-test-{}",
            uuid::Uuid::new_v4()
        ));

        let workspace = test_root.join("workspace");
        let target_directory = workspace.join("config");

        fs::create_dir_all(&target_directory)
            .map_err(|error| format!("failed to create target directory: {error}"))?;

        let capability = FileSystemCapability::try_new(workspace)?;

        let result = capability.write_text_file("config", "must-not-be-written");

        assert!(result.is_err());
        assert!(target_directory.is_dir());

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn secure_write_preserves_existing_file_permissions() -> Result<(), String> {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let test_root = std::env::temp_dir().join(format!(
            "zyguor-filesystem-write-permissions-test-{}",
            uuid::Uuid::new_v4()
        ));

        let workspace = test_root.join("workspace");
        let target = workspace.join("settings.txt");

        fs::create_dir_all(&workspace)
            .map_err(|error| format!("failed to create workspace: {error}"))?;

        fs::write(&target, "old-value")
            .map_err(|error| format!("failed to create existing file: {error}"))?;

        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("failed to set test permissions: {error}"))?;

        let capability = FileSystemCapability::try_new(workspace)?;

        capability.write_text_file("settings.txt", "new-value")?;

        let permissions = fs::metadata(&target)
            .map_err(|error| format!("failed to read replacement metadata: {error}"))?
            .permissions();

        assert_eq!(permissions.mode() & 0o777, 0o600);

        fs::remove_dir_all(&test_root)
            .map_err(|error| format!("failed to clean up test directory: {error}"))?;

        Ok(())
    }
}
