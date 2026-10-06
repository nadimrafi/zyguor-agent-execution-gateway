use std::ffi::{OsStr, OsString};
#[cfg(unix)]
use std::os::unix::{fs::OpenOptionsExt, process::CommandExt};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy)]
pub struct CargoTestConfig {
    pub timeout: Duration,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
}

impl Default for CargoTestConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CargoTestResult {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub duration_ms: u128,
}

#[cfg(unix)]
fn terminate_process_group(process_id: u32) -> Result<(), String> {
    let process_group = i32::try_from(process_id)
        .map_err(|_| "cargo process ID does not fit in pid_t".to_owned())?;

    let result = unsafe { libc::killpg(process_group, libc::SIGKILL) };

    if result == 0 {
        return Ok(());
    }

    let error = std::io::Error::last_os_error();

    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }

    Err(format!("failed to terminate cargo process group: {error}"))
}
#[cfg(test)]
fn process_group_id(process_id: u32) -> Result<i32, String> {
    let pid = i32::try_from(process_id)
        .map_err(|_| "cargo process ID does not fit in pid_t".to_owned())?;

    let process_group = unsafe { libc::getpgid(pid) };

    if process_group == -1 {
        return Err(format!(
            "failed to inspect cargo process group: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(process_group)
}
fn create_capture_file(label: &str) -> Result<(PathBuf, File), String> {
    let path = std::env::temp_dir().join(format!(
        "zyguor-cargo-{label}-{}-{}.log",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));

    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("failed to create Cargo {label} capture file: {error}"))?;

    Ok((path, file))
}

fn read_capture_file(path: &Path, maximum_bytes: usize) -> Result<(String, bool), String> {
    let file = File::open(path)
        .map_err(|error| format!("failed to open Cargo output capture file: {error}"))?;

    read_bounded(file, maximum_bytes)
}

fn remove_capture_file(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),

        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),

        Err(error) => Err(format!(
            "failed to remove Cargo output capture file {}: {error}",
            path.display()
        )),
    }
}
fn configure_cargo_environment(command: &mut Command) {
    configure_cargo_environment_from(command, std::env::vars_os());
}

fn configure_cargo_environment_from<I>(command: &mut Command, environment: I)
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    const ALLOWED_ENVIRONMENT: &[&str] = &["PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "TMPDIR"];

    command.env_clear();

    for (name, value) in environment {
        let allowed = ALLOWED_ENVIRONMENT
            .iter()
            .any(|allowed_name| name.as_os_str() == OsStr::new(allowed_name));

        if allowed {
            command.env(name, value);
        }
    }
}
pub struct CargoTestExecutor {
    config: CargoTestConfig,
}

impl CargoTestExecutor {
    pub fn new(config: CargoTestConfig) -> Self {
        Self { config }
    }

    pub fn run(&self, workspace: &Path) -> Result<CargoTestResult, String> {
        let started = Instant::now();

        let (stdout_path, stdout_file) = create_capture_file("stdout")?;

        let (stderr_path, stderr_file) = match create_capture_file("stderr") {
            Ok(capture) => capture,

            Err(error) => {
                let _ = remove_capture_file(&stdout_path);
                return Err(error);
            }
        };

        let mut command = Command::new("cargo");

        command
            .arg("test")
            .arg("--locked")
            .arg("--offline")
            .current_dir(workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .process_group(0);

        configure_cargo_environment(&mut command);

        let spawn_result = command.spawn();

        let mut child = match spawn_result {
            Ok(child) => child,

            Err(error) => {
                let _ = remove_capture_file(&stdout_path);
                let _ = remove_capture_file(&stderr_path);

                return Err(format!("failed to start cargo test: {error}"));
            }
        };

        let process_id = child.id();
        let mut timed_out = false;

        let status_result = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),

                Ok(None) => {}

                Err(error) => {
                    break Err(format!("failed to poll cargo test process: {error}"));
                }
            }

            if started.elapsed() >= self.config.timeout {
                timed_out = true;

                if let Err(error) = terminate_process_group(process_id) {
                    break Err(error);
                }

                match child.wait() {
                    Ok(status) => break Ok(status),

                    Err(error) => {
                        break Err(format!("failed to wait for terminated cargo test: {error}"));
                    }
                }
            }

            thread::sleep(Duration::from_millis(25));
        };

        let status = match status_result {
            Ok(status) => status,

            Err(error) => {
                let _ = terminate_process_group(process_id);
                let _ = child.wait();
                let _ = remove_capture_file(&stdout_path);
                let _ = remove_capture_file(&stderr_path);

                return Err(error);
            }
        };

        // Cargo may have exited normally while one of its descendants remains alive.
        // On timeout, the process group has already been terminated above.
        if !timed_out {
            terminate_process_group(process_id)?;
        }
        let stdout_result = read_capture_file(&stdout_path, self.config.max_stdout_bytes);
        let stderr_result = read_capture_file(&stderr_path, self.config.max_stderr_bytes);

        let stdout_cleanup = remove_capture_file(&stdout_path);
        let stderr_cleanup = remove_capture_file(&stderr_path);

        let (stdout, stdout_truncated) = stdout_result?;
        let (stderr, stderr_truncated) = stderr_result?;

        stdout_cleanup?;
        stderr_cleanup?;

        Ok(CargoTestResult {
            success: status.success() && !timed_out,
            exit_code: status.code(),
            timed_out,
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
            duration_ms: started.elapsed().as_millis(),
        })
    }
}
fn read_bounded<R: Read>(mut reader: R, maximum_bytes: usize) -> Result<(String, bool), String> {
    let mut captured = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .map_err(|error| format!("failed to read process output: {error}"))?;

        if bytes_read == 0 {
            break;
        }

        let remaining = maximum_bytes.saturating_sub(captured.len());
        let bytes_to_keep = bytes_read.min(remaining);

        if bytes_to_keep > 0 {
            captured.extend_from_slice(&buffer[..bytes_to_keep]);
        }

        if bytes_to_keep < bytes_read {
            truncated = true;
        }
    }

    Ok((String::from_utf8_lossy(&captured).into_owned(), truncated))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{
        CargoTestConfig, CargoTestExecutor, configure_cargo_environment_from, process_group_id,
        read_bounded, terminate_process_group,
    };
    use std::process::Command;

    #[test]
    fn bounded_reader_preserves_output_within_limit() -> Result<(), String> {
        let input = std::io::Cursor::new(b"hello".to_vec());

        let (output, truncated) = read_bounded(input, 5)?;

        assert_eq!(output, "hello");
        assert!(!truncated);

        Ok(())
    }

    #[test]
    fn bounded_reader_detects_output_above_limit() -> Result<(), String> {
        let input = std::io::Cursor::new(b"hello world".to_vec());

        let (output, truncated) = read_bounded(input, 5)?;

        assert_eq!(output, "hello");
        assert!(truncated);

        Ok(())
    }
    #[test]
    fn cargo_test_executor_times_out_and_terminates_process_group() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();

        let workspace = std::env::temp_dir().join(format!(
            "zyguor-cargo-timeout-test-{}-{request_id}",
            std::process::id()
        ));

        let src_directory = workspace.join("src");

        std::fs::create_dir_all(&src_directory)
            .map_err(|error| format!("failed to create timeout test workspace: {error}"))?;

        std::fs::write(
            workspace.join("Cargo.toml"),
            r#"[package]
name = "zyguor-cargo-timeout-fixture"
version = "0.1.0"
edition = "2024"
"#,
        )
        .map_err(|error| format!("failed to write Cargo.toml: {error}"))?;

        std::fs::write(
            workspace.join("Cargo.lock"),
            r#"# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "zyguor-cargo-timeout-fixture"
version = "0.1.0"
"#,
        )
        .map_err(|error| format!("failed to write Cargo.lock: {error}"))?;

        std::fs::write(
            src_directory.join("lib.rs"),
            r#"#[cfg(test)]
mod tests {
    use std::time::Duration;

    #[test]
    fn fixture_sleeps() {
        std::thread::sleep(Duration::from_secs(2));
    }
}
"#,
        )
        .map_err(|error| format!("failed to write timeout fixture source: {error}"))?;

        // Warm the temporary crate so the short timeout below primarily
        // exercises the running test process rather than compilation.
        let warm_executor = CargoTestExecutor::new(CargoTestConfig {
            timeout: Duration::from_secs(15),
            ..CargoTestConfig::default()
        });

        let warm_result = warm_executor.run(&workspace)?;

        assert!(
            warm_result.success,
            "timeout fixture warm-up unexpectedly failed: {}",
            warm_result.stderr
        );

        let executor = CargoTestExecutor::new(CargoTestConfig {
            timeout: Duration::from_millis(250),
            ..CargoTestConfig::default()
        });

        let started = Instant::now();

        let result = executor.run(&workspace)?;

        let elapsed = started.elapsed();

        assert!(!result.success);
        assert!(result.timed_out);

        assert!(
            elapsed < Duration::from_secs(5),
            "timed-out Cargo execution took too long: {elapsed:?}"
        );

        std::fs::remove_dir_all(&workspace)
            .map_err(|error| format!("failed to remove timeout test workspace: {error}"))?;

        Ok(())
    }
    #[test]
    fn cargo_test_executor_cleans_up_descendants_after_normal_exit() -> Result<(), String> {
        let request_id = uuid::Uuid::new_v4();

        let workspace = std::env::temp_dir().join(format!(
            "zyguor-cargo-descendant-test-{}-{request_id}",
            std::process::id()
        ));

        let src_directory = workspace.join("src");

        std::fs::create_dir_all(&src_directory)
            .map_err(|error| format!("failed to create descendant test workspace: {error}"))?;

        std::fs::write(
            workspace.join("Cargo.toml"),
            r#"[package]
name = "zyguor-cargo-descendant-fixture"
version = "0.1.0"
edition = "2024"
"#,
        )
        .map_err(|error| format!("failed to write Cargo.toml: {error}"))?;

        std::fs::write(
            workspace.join("Cargo.lock"),
            r#"# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "zyguor-cargo-descendant-fixture"
version = "0.1.0"
"#,
        )
        .map_err(|error| format!("failed to write Cargo.lock: {error}"))?;

        std::fs::write(
            src_directory.join("lib.rs"),
            r#"#[cfg(test)]
mod tests {
    use std::{
        path::Path,
        process::Command,
    };

    #[test]
    fn fixture_may_spawn_descendant() -> Result<(), String> {
        if Path::new("spawn-descendant.flag").exists() {
            Command::new("sleep")
                .arg("5")
                .spawn()
                .map_err(|error| format!("failed to spawn descendant: {error}"))?;
        }

        Ok(())
    }
}
"#,
        )
        .map_err(|error| format!("failed to write descendant fixture source: {error}"))?;

        let executor = CargoTestExecutor::new(CargoTestConfig {
            timeout: Duration::from_secs(10),
            ..CargoTestConfig::default()
        });

        // First run compiles the fixture without spawning a descendant.
        let warm_result = executor.run(&workspace)?;

        assert!(
            warm_result.success,
            "descendant fixture warm-up unexpectedly failed: {}",
            warm_result.stderr
        );

        std::fs::write(workspace.join("spawn-descendant.flag"), b"spawn")
            .map_err(|error| format!("failed to create descendant flag: {error}"))?;

        let started = Instant::now();

        let result = executor.run(&workspace)?;

        let elapsed = started.elapsed();

        assert!(result.success);
        assert!(!result.timed_out);

        assert!(
            elapsed < Duration::from_secs(3),
            "Cargo execution waited too long for a descendant process: {elapsed:?}"
        );

        std::fs::remove_dir_all(&workspace)
            .map_err(|error| format!("failed to remove descendant test workspace: {error}"))?;

        Ok(())
    }
    #[test]
    fn cargo_environment_filters_unapproved_variables() -> Result<(), String> {
        use std::ffi::OsString;

        let mut command = Command::new("/usr/bin/env");

        configure_cargo_environment_from(
            &mut command,
            vec![
                (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
                (OsString::from("HOME"), OsString::from("/tmp/zyguor-home")),
                (
                    OsString::from("ZYGUOR_TEST_SECRET"),
                    OsString::from("must-not-leak"),
                ),
                (
                    OsString::from("UNRELATED_API_TOKEN"),
                    OsString::from("also-must-not-leak"),
                ),
            ],
        );

        let output = command
            .output()
            .map_err(|error| format!("failed to inspect filtered Cargo environment: {error}"))?;

        let environment = String::from_utf8_lossy(&output.stdout);

        assert!(environment.contains("PATH=/usr/bin:/bin"));
        assert!(environment.contains("HOME=/tmp/zyguor-home"));

        assert!(!environment.contains("ZYGUOR_TEST_SECRET"));
        assert!(!environment.contains("UNRELATED_API_TOKEN"));

        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn spawned_process_group_identity_matches_group_leader() -> Result<(), String> {
        use std::os::unix::process::CommandExt;

        let mut child = Command::new("sleep")
            .arg("1")
            .process_group(0)
            .spawn()
            .map_err(|error| format!("failed to spawn process-group fixture: {error}"))?;

        let process_id = child.id();

        let process_group = process_group_id(process_id)?;

        assert_eq!(
            process_group,
            i32::try_from(process_id).map_err(|_| "fixture PID does not fit in pid_t".to_owned())?
        );

        terminate_process_group(process_id)?;

        child
            .wait()
            .map_err(|error| format!("failed to wait for process-group fixture: {error}"))?;

        Ok(())
    }
}
