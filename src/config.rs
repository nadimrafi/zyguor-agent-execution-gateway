use crate::policy::PolicyDecision;
use serde::Deserialize;

use std::{collections::HashSet, path::Path, time::Duration};

use url::Host;

use crate::{
    cargo_test::CargoTestConfig, http_execution::HttpExecutionConfig, sandbox::SandboxConfig,
};
const MAX_HTTP_TIMEOUT_SECONDS: u64 = 60;
const MAX_HTTP_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const MAX_HTTP_RESPONSE_BODY_BYTES: usize = 4 * 1024 * 1024;

const MAX_CARGO_TEST_TIMEOUT_SECONDS: u64 = 10 * 60;
const MAX_CARGO_OUTPUT_BYTES: usize = 1024 * 1024;

const MAX_SANDBOX_FUEL_LIMIT: u64 = 10_000_000;
const MAX_SANDBOX_MEMORY_BYTES: usize = 64 * 1024 * 1024;
const MAX_SANDBOX_TIMEOUT_MILLISECONDS: u64 = 5_000;

#[derive(Debug, Clone)]
pub struct HttpPolicyConfig {
    pub allowed_hosts: Vec<String>,
    pub execution: HttpExecutionConfig,
}

impl Default for HttpPolicyConfig {
    fn default() -> Self {
        Self {
            allowed_hosts: vec!["api.example.com".to_owned()],
            execution: HttpExecutionConfig::default(),
        }
    }
}
#[derive(Debug, Clone)]
pub struct CapabilityPolicyConfig {
    pub add: PolicyDecision,
    pub read_file: PolicyDecision,
    pub write_file: PolicyDecision,
    pub git_status: PolicyDecision,
    pub run_cargo_test: PolicyDecision,
    pub http_get: PolicyDecision,
    pub http_post: PolicyDecision,
}

impl Default for CapabilityPolicyConfig {
    fn default() -> Self {
        Self {
            add: PolicyDecision::Allow,
            read_file: PolicyDecision::Allow,
            write_file: PolicyDecision::Review,
            git_status: PolicyDecision::Allow,
            run_cargo_test: PolicyDecision::Review,
            http_get: PolicyDecision::Allow,
            http_post: PolicyDecision::Review,
        }
    }
}
impl CapabilityPolicyConfig {
    pub fn validate(&self) -> Result<(), String> {
        for (name, decision) in [
            ("add", self.add),
            ("read_file", self.read_file),
            ("git_status", self.git_status),
            ("http_get", self.http_get),
        ] {
            if decision == PolicyDecision::Review {
                return Err(format!(
                    "{name} policy cannot require review because reviewed execution is not supported for this capability"
                ));
            }
        }

        for (name, decision) in [
            ("write_file", self.write_file),
            ("run_cargo_test", self.run_cargo_test),
            ("http_post", self.http_post),
        ] {
            if decision == PolicyDecision::Allow {
                return Err(format!("{name} policy cannot bypass required human review"));
            }
        }

        Ok(())
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayConfigFile {
    http: Option<HttpConfigFile>,
    policy: Option<CapabilityPolicyConfigFile>,
    cargo_test: Option<CargoTestConfigFile>,
    sandbox: Option<SandboxConfigFile>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoTestConfigFile {
    timeout_seconds: Option<u64>,
    max_stdout_bytes: Option<usize>,
    max_stderr_bytes: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SandboxConfigFile {
    fuel_limit: Option<u64>,
    memory_limit_bytes: Option<usize>,
    timeout_milliseconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpConfigFile {
    allowed_hosts: Option<Vec<String>>,
    timeout_seconds: Option<u64>,
    max_request_body_bytes: Option<usize>,
    max_response_body_bytes: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityPolicyConfigFile {
    add: Option<String>,
    read_file: Option<String>,
    write_file: Option<String>,
    git_status: Option<String>,
    run_cargo_test: Option<String>,
    http_get: Option<String>,
    http_post: Option<String>,
}
fn parse_policy_decision(name: &str, value: &str) -> Result<PolicyDecision, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "allow" => Ok(PolicyDecision::Allow),
        "review" => Ok(PolicyDecision::Review),
        "block" => Ok(PolicyDecision::Block),

        other => Err(format!(
            "invalid policy decision for {name}: {other}; expected allow, review, or block"
        )),
    }
}
pub fn parse_gateway_config_toml(input: &str) -> Result<GatewayConfig, String> {
    let file: GatewayConfigFile = toml::from_str(input)
        .map_err(|error| format!("failed to parse gateway configuration: {error}"))?;

    let mut config = GatewayConfig::default();

    if let Some(http) = file.http {
        if let Some(allowed_hosts) = http.allowed_hosts {
            config.http.allowed_hosts = allowed_hosts;
        }

        if let Some(timeout_seconds) = http.timeout_seconds {
            config.http.execution.timeout = Duration::from_secs(timeout_seconds);
        }

        if let Some(maximum_bytes) = http.max_request_body_bytes {
            config.http.execution.max_request_body_bytes = maximum_bytes;
        }

        if let Some(maximum_bytes) = http.max_response_body_bytes {
            config.http.execution.max_response_body_bytes = maximum_bytes;
        }
    }

    if let Some(cargo_test) = file.cargo_test {
        if let Some(timeout_seconds) = cargo_test.timeout_seconds {
            config.cargo_test.timeout = Duration::from_secs(timeout_seconds);
        }

        if let Some(maximum_bytes) = cargo_test.max_stdout_bytes {
            config.cargo_test.max_stdout_bytes = maximum_bytes;
        }

        if let Some(maximum_bytes) = cargo_test.max_stderr_bytes {
            config.cargo_test.max_stderr_bytes = maximum_bytes;
        }
    }

    if let Some(sandbox) = file.sandbox {
        if let Some(fuel_limit) = sandbox.fuel_limit {
            config.sandbox.fuel_limit = fuel_limit;
        }

        if let Some(memory_limit_bytes) = sandbox.memory_limit_bytes {
            config.sandbox.memory_limit_bytes = memory_limit_bytes;
        }

        if let Some(timeout_milliseconds) = sandbox.timeout_milliseconds {
            config.sandbox.timeout = Duration::from_millis(timeout_milliseconds);
        }
    }

    if let Some(policy) = file.policy {
        if let Some(value) = policy.add {
            config.policy.add = parse_policy_decision("add", &value)?;
        }

        if let Some(value) = policy.read_file {
            config.policy.read_file = parse_policy_decision("read_file", &value)?;
        }

        if let Some(value) = policy.write_file {
            config.policy.write_file = parse_policy_decision("write_file", &value)?;
        }

        if let Some(value) = policy.git_status {
            config.policy.git_status = parse_policy_decision("git_status", &value)?;
        }

        if let Some(value) = policy.run_cargo_test {
            config.policy.run_cargo_test = parse_policy_decision("run_cargo_test", &value)?;
        }

        if let Some(value) = policy.http_get {
            config.policy.http_get = parse_policy_decision("http_get", &value)?;
        }

        if let Some(value) = policy.http_post {
            config.policy.http_post = parse_policy_decision("http_post", &value)?;
        }
    }

    config.validate()?;

    Ok(config)
}

pub fn resolve_gateway_config(config_path: Option<&Path>) -> Result<GatewayConfig, String> {
    match config_path {
        Some(path) => load_gateway_config_from_path(path),

        None => {
            let config = GatewayConfig::default();

            config.validate()?;

            Ok(config)
        }
    }
}
pub fn load_gateway_config_from_path(path: &Path) -> Result<GatewayConfig, String> {
    let contents = std::fs::read_to_string(path).map_err(|error| {
        format!(
            "failed to read gateway configuration '{}': {error}",
            path.display()
        )
    })?;

    parse_gateway_config_toml(&contents)
}

#[derive(Debug, Clone, Default)]
pub struct GatewayConfig {
    pub http: HttpPolicyConfig,
    pub cargo_test: CargoTestConfig,
    pub sandbox: SandboxConfig,
    pub policy: CapabilityPolicyConfig,
}

impl HttpPolicyConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.execution.timeout.is_zero() {
            return Err("HTTP timeout must be greater than zero".to_owned());
        }

        if self.execution.max_request_body_bytes == 0 {
            return Err("HTTP maximum request body size must be greater than zero".to_owned());
        }

        if self.execution.max_response_body_bytes == 0 {
            return Err("HTTP maximum response body size must be greater than zero".to_owned());
        }

        if self.execution.timeout > Duration::from_secs(MAX_HTTP_TIMEOUT_SECONDS) {
            return Err(format!(
                "HTTP timeout must not exceed {MAX_HTTP_TIMEOUT_SECONDS} seconds"
            ));
        }

        if self.execution.max_request_body_bytes > MAX_HTTP_REQUEST_BODY_BYTES {
            return Err(format!(
                "HTTP maximum request body size must not exceed {MAX_HTTP_REQUEST_BODY_BYTES} bytes"
            ));
        }

        if self.execution.max_response_body_bytes > MAX_HTTP_RESPONSE_BODY_BYTES {
            return Err(format!(
                "HTTP maximum response body size must not exceed {MAX_HTTP_RESPONSE_BODY_BYTES} bytes"
            ));
        }

        let mut seen_hosts = HashSet::new();

        for allowed_host in &self.allowed_hosts {
            let host = allowed_host.trim();

            if host.is_empty() {
                return Err("HTTP allowed host cannot be empty".to_owned());
            }

            let parsed_host = Host::parse(host)
                .map_err(|error| format!("invalid HTTP allowed host '{host}': {error}"))?;

            let domain = match parsed_host {
                Host::Domain(domain) => domain,

                Host::Ipv4(_) | Host::Ipv6(_) => {
                    return Err(format!(
                        "HTTP allowed host must not be an IP literal: {host}"
                    ));
                }
            };

            if domain.eq_ignore_ascii_case("localhost") {
                return Err("localhost cannot be an HTTP allowed host".to_owned());
            }

            let normalized = domain.to_ascii_lowercase();

            if !seen_hosts.insert(normalized) {
                return Err(format!("duplicate HTTP allowed host: {host}"));
            }
        }

        Ok(())
    }
}

impl GatewayConfig {
    pub fn validate(&self) -> Result<(), String> {
        self.http.validate()?;
        self.policy.validate()?;

        if self.cargo_test.timeout.is_zero() {
            return Err("Cargo test timeout must be greater than zero".to_owned());
        }

        if self.cargo_test.max_stdout_bytes == 0 {
            return Err("Cargo test stdout limit must be greater than zero".to_owned());
        }

        if self.cargo_test.max_stderr_bytes == 0 {
            return Err("Cargo test stderr limit must be greater than zero".to_owned());
        }

        if self.cargo_test.timeout > Duration::from_secs(MAX_CARGO_TEST_TIMEOUT_SECONDS) {
            return Err(format!(
                "Cargo test timeout must not exceed {MAX_CARGO_TEST_TIMEOUT_SECONDS} seconds"
            ));
        }

        if self.cargo_test.max_stdout_bytes > MAX_CARGO_OUTPUT_BYTES {
            return Err(format!(
                "Cargo test stdout limit must not exceed {MAX_CARGO_OUTPUT_BYTES} bytes"
            ));
        }

        if self.cargo_test.max_stderr_bytes > MAX_CARGO_OUTPUT_BYTES {
            return Err(format!(
                "Cargo test stderr limit must not exceed {MAX_CARGO_OUTPUT_BYTES} bytes"
            ));
        }

        if self.sandbox.fuel_limit == 0 {
            return Err("sandbox fuel limit must be greater than zero".to_owned());
        }

        if self.sandbox.memory_limit_bytes == 0 {
            return Err("sandbox memory limit must be greater than zero".to_owned());
        }

        if self.sandbox.timeout.is_zero() {
            return Err("sandbox timeout must be greater than zero".to_owned());
        }

        if self.sandbox.fuel_limit > MAX_SANDBOX_FUEL_LIMIT {
            return Err(format!(
                "sandbox fuel limit must not exceed {MAX_SANDBOX_FUEL_LIMIT}"
            ));
        }

        if self.sandbox.memory_limit_bytes > MAX_SANDBOX_MEMORY_BYTES {
            return Err(format!(
                "sandbox memory limit must not exceed {MAX_SANDBOX_MEMORY_BYTES} bytes"
            ));
        }

        if self.sandbox.timeout > Duration::from_millis(MAX_SANDBOX_TIMEOUT_MILLISECONDS) {
            return Err(format!(
                "sandbox timeout must not exceed {MAX_SANDBOX_TIMEOUT_MILLISECONDS} milliseconds"
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        GatewayConfig, MAX_CARGO_OUTPUT_BYTES, MAX_CARGO_TEST_TIMEOUT_SECONDS,
        MAX_HTTP_REQUEST_BODY_BYTES, MAX_HTTP_RESPONSE_BODY_BYTES, MAX_HTTP_TIMEOUT_SECONDS,
        MAX_SANDBOX_FUEL_LIMIT, MAX_SANDBOX_MEMORY_BYTES, MAX_SANDBOX_TIMEOUT_MILLISECONDS,
        load_gateway_config_from_path, parse_gateway_config_toml, resolve_gateway_config,
    };

    use crate::policy::PolicyDecision;

    #[test]
    fn gateway_config_defaults_match_existing_runtime_defaults() {
        let config = GatewayConfig::default();

        assert_eq!(
            config.http.allowed_hosts,
            vec!["api.example.com".to_owned()]
        );

        assert_eq!(config.http.execution.timeout, Duration::from_secs(10));
        assert_eq!(config.http.execution.max_request_body_bytes, 64 * 1024);
        assert_eq!(config.http.execution.max_response_body_bytes, 256 * 1024);

        assert_eq!(config.cargo_test.timeout, Duration::from_secs(60));
        assert_eq!(config.cargo_test.max_stdout_bytes, 64 * 1024);
        assert_eq!(config.cargo_test.max_stderr_bytes, 64 * 1024);

        assert_eq!(config.sandbox.fuel_limit, 10_000);
        assert_eq!(config.sandbox.memory_limit_bytes, 2 * 1024 * 1024);
        assert_eq!(config.sandbox.timeout, Duration::from_millis(250));
    }
    #[test]
    fn default_gateway_config_is_valid() {
        let config = GatewayConfig::default();

        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn empty_http_allowlist_is_valid() {
        let mut config = GatewayConfig::default();
        config.http.allowed_hosts.clear();

        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn rejects_localhost_http_allowlist_entry() {
        let mut config = GatewayConfig::default();
        config.http.allowed_hosts = vec!["localhost".to_owned()];

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_ip_literal_http_allowlist_entry() {
        let mut config = GatewayConfig::default();
        config.http.allowed_hosts = vec!["127.0.0.1".to_owned()];

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_http_allowlist_entries_case_insensitively() {
        let mut config = GatewayConfig::default();
        config.http.allowed_hosts =
            vec!["api.example.com".to_owned(), "API.EXAMPLE.COM".to_owned()];

        assert!(config.validate().is_err());
    }
    #[test]
    fn rejects_zero_http_timeout() {
        let mut config = GatewayConfig::default();
        config.http.execution.timeout = Duration::ZERO;

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_zero_http_request_body_limit() {
        let mut config = GatewayConfig::default();
        config.http.execution.max_request_body_bytes = 0;

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_zero_http_response_body_limit() {
        let mut config = GatewayConfig::default();
        config.http.execution.max_response_body_bytes = 0;

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_zero_cargo_timeout() {
        let mut config = GatewayConfig::default();
        config.cargo_test.timeout = Duration::ZERO;

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_zero_cargo_stdout_limit() {
        let mut config = GatewayConfig::default();
        config.cargo_test.max_stdout_bytes = 0;

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_zero_cargo_stderr_limit() {
        let mut config = GatewayConfig::default();
        config.cargo_test.max_stderr_bytes = 0;

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_zero_sandbox_fuel_limit() {
        let mut config = GatewayConfig::default();
        config.sandbox.fuel_limit = 0;

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_zero_sandbox_memory_limit() {
        let mut config = GatewayConfig::default();
        config.sandbox.memory_limit_bytes = 0;

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_zero_sandbox_timeout() {
        let mut config = GatewayConfig::default();
        config.sandbox.timeout = Duration::ZERO;

        assert!(config.validate().is_err());
    }
    #[test]
    fn rejects_url_instead_of_hostname_in_allowlist() {
        let mut config = GatewayConfig::default();
        config.http.allowed_hosts = vec!["https://api.example.com".to_owned()];

        assert!(config.validate().is_err());
    }
    #[test]
    fn default_capability_policy_matches_existing_behavior() {
        let config = GatewayConfig::default();

        assert_eq!(config.policy.add, PolicyDecision::Allow);
        assert_eq!(config.policy.read_file, PolicyDecision::Allow);
        assert_eq!(config.policy.write_file, PolicyDecision::Review);
        assert_eq!(config.policy.git_status, PolicyDecision::Allow);
        assert_eq!(config.policy.run_cargo_test, PolicyDecision::Review);
        assert_eq!(config.policy.http_get, PolicyDecision::Allow);
        assert_eq!(config.policy.http_post, PolicyDecision::Review);
    }

    #[test]
    fn default_capability_policy_is_valid() {
        let config = GatewayConfig::default();

        assert_eq!(config.policy.validate(), Ok(()));
    }

    #[test]
    fn write_file_policy_cannot_bypass_review() {
        let mut config = GatewayConfig::default();
        config.policy.write_file = PolicyDecision::Allow;

        assert!(config.validate().is_err());
    }

    #[test]
    fn cargo_test_policy_cannot_bypass_review() {
        let mut config = GatewayConfig::default();
        config.policy.run_cargo_test = PolicyDecision::Allow;

        assert!(config.validate().is_err());
    }

    #[test]
    fn http_post_policy_cannot_bypass_review() {
        let mut config = GatewayConfig::default();
        config.policy.http_post = PolicyDecision::Allow;

        assert!(config.validate().is_err());
    }

    #[test]
    fn safe_capability_cannot_use_unsupported_review_path() {
        let mut config = GatewayConfig::default();
        config.policy.http_get = PolicyDecision::Review;

        assert!(config.validate().is_err());
    }
    #[test]
    fn parses_empty_toml_as_safe_defaults() -> Result<(), String> {
        let config = parse_gateway_config_toml("")?;

        assert_eq!(
            config.http.allowed_hosts,
            vec!["api.example.com".to_owned()]
        );

        assert_eq!(config.policy.http_get, PolicyDecision::Allow);
        assert_eq!(config.policy.http_post, PolicyDecision::Review);

        Ok(())
    }

    #[test]
    fn parses_http_configuration_overrides() -> Result<(), String> {
        let config = parse_gateway_config_toml(
            r#"
        [http]
        allowed_hosts = ["service.example.com"]
        timeout_seconds = 5
        max_request_body_bytes = 1024
        max_response_body_bytes = 2048
        "#,
        )?;

        assert_eq!(
            config.http.allowed_hosts,
            vec!["service.example.com".to_owned()]
        );

        assert_eq!(config.http.execution.timeout, Duration::from_secs(5));

        assert_eq!(config.http.execution.max_request_body_bytes, 1024);

        assert_eq!(config.http.execution.max_response_body_bytes, 2048);

        Ok(())
    }

    #[test]
    fn parses_capability_policy_overrides() -> Result<(), String> {
        let config = parse_gateway_config_toml(
            r#"
        [policy]
        http_get = "block"
        write_file = "block"
        "#,
        )?;

        assert_eq!(config.policy.http_get, PolicyDecision::Block);
        assert_eq!(config.policy.write_file, PolicyDecision::Block);

        Ok(())
    }

    #[test]
    fn rejects_unknown_configuration_field() {
        let result = parse_gateway_config_toml(
            r#"
        [http]
        timeout_seconds = 5
        mystery_setting = true
        "#,
        );

        assert!(result.is_err());
    }
    #[test]
    fn rejects_toml_that_bypasses_http_post_review() {
        let result = parse_gateway_config_toml(
            r#"
        [policy]
        http_post = "allow"
        "#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn rejects_toml_with_zero_http_timeout() {
        let result = parse_gateway_config_toml(
            r#"
        [http]
        timeout_seconds = 0
        "#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn rejects_toml_with_unsafe_http_host() {
        let result = parse_gateway_config_toml(
            r#"
        [http]
        allowed_hosts = ["localhost"]
        "#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn rejects_invalid_policy_value_from_toml() {
        let result = parse_gateway_config_toml(
            r#"
        [policy]
        http_get = "sometimes"
        "#,
        );

        assert!(result.is_err());
    }
    #[test]
    fn loads_valid_gateway_config_from_file() -> Result<(), String> {
        let path =
            std::env::temp_dir().join(format!("zyguor-config-{}.toml", uuid::Uuid::new_v4()));

        std::fs::write(
            &path,
            r#"
        [http]
        allowed_hosts = ["service.example.com"]
        timeout_seconds = 7

        [policy]
        http_get = "block"
        "#,
        )
        .map_err(|error| format!("failed to write temporary config file: {error}"))?;

        let config = load_gateway_config_from_path(&path)?;

        assert_eq!(
            config.http.allowed_hosts,
            vec!["service.example.com".to_owned()]
        );

        assert_eq!(config.http.execution.timeout, Duration::from_secs(7));

        assert_eq!(config.policy.http_get, PolicyDecision::Block);

        std::fs::remove_file(&path)
            .map_err(|error| format!("failed to remove temporary config file: {error}"))?;

        Ok(())
    }
    #[test]
    fn missing_gateway_config_file_is_rejected() {
        let path = std::env::temp_dir().join(format!(
            "zyguor-missing-config-{}.toml",
            uuid::Uuid::new_v4()
        ));

        let result = load_gateway_config_from_path(&path);

        assert!(result.is_err());
    }
    #[test]
    fn invalid_gateway_config_file_is_rejected() -> Result<(), String> {
        let path = std::env::temp_dir().join(format!(
            "zyguor-invalid-config-{}.toml",
            uuid::Uuid::new_v4()
        ));

        std::fs::write(
            &path,
            r#"
        [policy]
        http_post = "allow"
        "#,
        )
        .map_err(|error| format!("failed to write temporary config file: {error}"))?;

        let result = load_gateway_config_from_path(&path);

        std::fs::remove_file(&path)
            .map_err(|error| format!("failed to remove temporary config file: {error}"))?;

        assert!(result.is_err());

        Ok(())
    }
    #[test]
    fn resolves_safe_defaults_when_config_path_is_absent() -> Result<(), String> {
        let config = resolve_gateway_config(None)?;

        assert_eq!(
            config.http.allowed_hosts,
            vec!["api.example.com".to_owned()]
        );

        assert_eq!(config.policy.http_post, PolicyDecision::Review);

        Ok(())
    }
    #[test]
    fn resolves_gateway_config_from_supplied_path() -> Result<(), String> {
        let path = std::env::temp_dir().join(format!(
            "zyguor-resolved-config-{}.toml",
            uuid::Uuid::new_v4()
        ));

        std::fs::write(
            &path,
            r#"
        [http]
        allowed_hosts = ["configured.example.com"]

        [policy]
        http_get = "block"
        "#,
        )
        .map_err(|error| format!("failed to write temporary config file: {error}"))?;

        let config = resolve_gateway_config(Some(&path))?;

        assert_eq!(
            config.http.allowed_hosts,
            vec!["configured.example.com".to_owned()]
        );

        assert_eq!(config.policy.http_get, PolicyDecision::Block);

        std::fs::remove_file(&path)
            .map_err(|error| format!("failed to remove temporary config file: {error}"))?;

        Ok(())
    }
    #[test]
    fn parses_cargo_test_configuration_overrides() -> Result<(), String> {
        let config = parse_gateway_config_toml(
            r#"
        [cargo_test]
        timeout_seconds = 30
        max_stdout_bytes = 4096
        max_stderr_bytes = 8192
        "#,
        )?;

        assert_eq!(config.cargo_test.timeout, Duration::from_secs(30));
        assert_eq!(config.cargo_test.max_stdout_bytes, 4096);
        assert_eq!(config.cargo_test.max_stderr_bytes, 8192);

        Ok(())
    }

    #[test]
    fn parses_sandbox_configuration_overrides() -> Result<(), String> {
        let config = parse_gateway_config_toml(
            r#"
        [sandbox]
        fuel_limit = 20000
        memory_limit_bytes = 4194304
        timeout_milliseconds = 500
        "#,
        )?;

        assert_eq!(config.sandbox.fuel_limit, 20_000);
        assert_eq!(config.sandbox.memory_limit_bytes, 4_194_304);
        assert_eq!(config.sandbox.timeout, Duration::from_millis(500));

        Ok(())
    }
    #[test]
    fn rejects_toml_with_zero_cargo_timeout() {
        let result = parse_gateway_config_toml(
            r#"
        [cargo_test]
        timeout_seconds = 0
        "#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn rejects_toml_with_zero_sandbox_fuel_limit() {
        let result = parse_gateway_config_toml(
            r#"
        [sandbox]
        fuel_limit = 0
        "#,
        );

        assert!(result.is_err());
    }
    #[test]
    fn accepts_configuration_at_resource_upper_bounds() {
        let mut config = GatewayConfig::default();

        config.http.execution.timeout = Duration::from_secs(MAX_HTTP_TIMEOUT_SECONDS);
        config.http.execution.max_request_body_bytes = MAX_HTTP_REQUEST_BODY_BYTES;
        config.http.execution.max_response_body_bytes = MAX_HTTP_RESPONSE_BODY_BYTES;

        config.cargo_test.timeout = Duration::from_secs(MAX_CARGO_TEST_TIMEOUT_SECONDS);
        config.cargo_test.max_stdout_bytes = MAX_CARGO_OUTPUT_BYTES;
        config.cargo_test.max_stderr_bytes = MAX_CARGO_OUTPUT_BYTES;

        config.sandbox.fuel_limit = MAX_SANDBOX_FUEL_LIMIT;
        config.sandbox.memory_limit_bytes = MAX_SANDBOX_MEMORY_BYTES;
        config.sandbox.timeout = Duration::from_millis(MAX_SANDBOX_TIMEOUT_MILLISECONDS);

        assert_eq!(config.validate(), Ok(()));
    }
    #[test]
    fn rejects_http_timeout_above_maximum() {
        let mut config = GatewayConfig::default();
        config.http.execution.timeout = Duration::from_secs(MAX_HTTP_TIMEOUT_SECONDS + 1);

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_http_request_body_above_maximum() {
        let mut config = GatewayConfig::default();
        config.http.execution.max_request_body_bytes = MAX_HTTP_REQUEST_BODY_BYTES + 1;

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_http_response_body_above_maximum() {
        let mut config = GatewayConfig::default();
        config.http.execution.max_response_body_bytes = MAX_HTTP_RESPONSE_BODY_BYTES + 1;

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_cargo_timeout_above_maximum() {
        let mut config = GatewayConfig::default();
        config.cargo_test.timeout = Duration::from_secs(MAX_CARGO_TEST_TIMEOUT_SECONDS + 1);

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_cargo_stdout_above_maximum() {
        let mut config = GatewayConfig::default();
        config.cargo_test.max_stdout_bytes = MAX_CARGO_OUTPUT_BYTES + 1;

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_cargo_stderr_above_maximum() {
        let mut config = GatewayConfig::default();
        config.cargo_test.max_stderr_bytes = MAX_CARGO_OUTPUT_BYTES + 1;

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_sandbox_fuel_above_maximum() {
        let mut config = GatewayConfig::default();
        config.sandbox.fuel_limit = MAX_SANDBOX_FUEL_LIMIT + 1;

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_sandbox_memory_above_maximum() {
        let mut config = GatewayConfig::default();
        config.sandbox.memory_limit_bytes = MAX_SANDBOX_MEMORY_BYTES + 1;

        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_sandbox_timeout_above_maximum() {
        let mut config = GatewayConfig::default();
        config.sandbox.timeout = Duration::from_millis(MAX_SANDBOX_TIMEOUT_MILLISECONDS + 1);

        assert!(config.validate().is_err());
    }
}
