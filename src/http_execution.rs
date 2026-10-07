use crate::{execution::HttpMethod, http::ValidatedHttpUrl};
use std::{
    io::Read,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    time::Duration,
};

#[derive(Debug, Clone, Copy)]
pub struct HttpExecutionConfig {
    pub timeout: Duration,
    pub max_request_body_bytes: usize,
    pub max_response_body_bytes: usize,
}

impl Default for HttpExecutionConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_request_body_bytes: 64 * 1024,
            max_response_body_bytes: 256 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HttpExecutionResult {
    pub status_code: u16,
    pub body: String,
    pub body_truncated: bool,
    pub duration_ms: u128,
}
fn is_safe_outbound_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();

            let is_shared_address_space = octets[0] == 100 && (64..=127).contains(&octets[1]);

            let is_benchmarking = octets[0] == 198 && (octets[1] == 18 || octets[1] == 19);

            !(address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_unspecified()
                || address.is_broadcast()
                || address.is_multicast()
                || is_shared_address_space
                || is_benchmarking)
        }

        IpAddr::V6(address) => {
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                || address.is_multicast())
        }
    }
}
fn resolve_safe_outbound_addresses(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    let resolved = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("failed to resolve HTTP destination: {error}"))?;

    let mut addresses = Vec::new();

    for address in resolved {
        if !is_safe_outbound_ip(address.ip()) {
            return Err(format!(
                "HTTP destination resolved to a disallowed address: {}",
                address.ip()
            ));
        }

        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }

    if addresses.is_empty() {
        return Err("HTTP destination resolved to no addresses".to_owned());
    }

    Ok(addresses)
}

fn read_bounded_body<R: Read>(
    mut reader: R,
    maximum_bytes: usize,
) -> Result<(String, bool), String> {
    let mut captured = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .map_err(|error| format!("failed to read HTTP response body: {error}"))?;

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

pub struct HttpExecutor {
    config: HttpExecutionConfig,
}

impl HttpExecutor {
    pub fn new(config: HttpExecutionConfig) -> Result<Self, String> {
        Ok(Self { config })
    }

    pub fn validate_request_body(&self, body: Option<&str>) -> Result<(), String> {
        let body_length = body.map_or(0, str::len);

        if body_length > self.config.max_request_body_bytes {
            return Err(format!(
                "HTTP request body exceeds maximum size of {} bytes",
                self.config.max_request_body_bytes
            ));
        }

        Ok(())
    }

    pub fn read_response_body<R: Read>(&self, reader: R) -> Result<(String, bool), String> {
        read_bounded_body(reader, self.config.max_response_body_bytes)
    }

    pub fn execute(
        &self,
        method: HttpMethod,
        destination: &ValidatedHttpUrl,
        body: Option<&str>,
    ) -> Result<HttpExecutionResult, String> {
        self.validate_request_body(body)?;

        if method == HttpMethod::Get && body.is_some() {
            return Err("HTTP GET request must not include a body".to_owned());
        }

        let client = self.build_client_for_destination(destination)?;

        self.execute_with_client(&client, method, destination, body)
    }

    fn execute_with_client(
        &self,
        client: &reqwest::blocking::Client,
        method: HttpMethod,
        destination: &ValidatedHttpUrl,
        body: Option<&str>,
    ) -> Result<HttpExecutionResult, String> {
        let started = std::time::Instant::now();

        let request = match method {
            HttpMethod::Get => client.get(destination.as_url().as_str()),

            HttpMethod::Post => {
                let request = client.post(destination.as_url().as_str());

                match body {
                    Some(body) => request.body(body.to_owned()),
                    None => request,
                }
            }
        };

        let mut response = request
            .send()
            .map_err(|error| format!("HTTP request failed: {error}"))?;

        let status_code = response.status().as_u16();

        let (body, body_truncated) = self.read_response_body(&mut response)?;

        Ok(HttpExecutionResult {
            status_code,
            body,
            body_truncated,
            duration_ms: started.elapsed().as_millis(),
        })
    }

    fn build_client_for_destination(
        &self,
        destination: &ValidatedHttpUrl,
    ) -> Result<reqwest::blocking::Client, String> {
        let host = destination
            .as_url()
            .host_str()
            .ok_or_else(|| "validated HTTP destination is missing a host".to_owned())?;

        let port = destination
            .as_url()
            .port_or_known_default()
            .ok_or_else(|| "validated HTTP destination has no usable port".to_owned())?;

        let addresses = resolve_safe_outbound_addresses(host, port)?;

        reqwest::blocking::Client::builder()
            .timeout(self.config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .https_only(true)
            .resolve_to_addrs(host, &addresses)
            .build()
            .map_err(|error| format!("failed to build HTTP client: {error}"))
    }
}
#[cfg(test)]
mod tests {
    use super::{HttpExecutionConfig, HttpExecutor};

    #[test]
    fn accepts_request_body_at_maximum_size() -> Result<(), String> {
        let config = HttpExecutionConfig {
            max_request_body_bytes: 5,
            ..HttpExecutionConfig::default()
        };

        let executor = HttpExecutor::new(config)?;

        executor.validate_request_body(Some("hello"))
    }

    #[test]
    fn rejects_request_body_above_maximum_size() -> Result<(), String> {
        let config = HttpExecutionConfig {
            max_request_body_bytes: 5,
            ..HttpExecutionConfig::default()
        };

        let executor = HttpExecutor::new(config)?;

        let result = executor.validate_request_body(Some("hello!"));

        assert_eq!(
            result,
            Err("HTTP request body exceeds maximum size of 5 bytes".to_owned())
        );

        Ok(())
    }

    #[test]
    fn accepts_missing_request_body() -> Result<(), String> {
        let executor = HttpExecutor::new(HttpExecutionConfig::default())?;

        executor.validate_request_body(None)
    }
    #[test]
    fn preserves_response_body_within_limit() -> Result<(), String> {
        let config = HttpExecutionConfig {
            max_response_body_bytes: 5,
            ..HttpExecutionConfig::default()
        };

        let executor = HttpExecutor::new(config)?;

        let input = std::io::Cursor::new(b"hello".to_vec());

        let (body, truncated) = executor.read_response_body(input)?;

        assert_eq!(body, "hello");
        assert!(!truncated);

        Ok(())
    }

    #[test]
    fn truncates_response_body_above_limit() -> Result<(), String> {
        let config = HttpExecutionConfig {
            max_response_body_bytes: 5,
            ..HttpExecutionConfig::default()
        };

        let executor = HttpExecutor::new(config)?;

        let input = std::io::Cursor::new(b"hello world".to_vec());

        let (body, truncated) = executor.read_response_body(input)?;

        assert_eq!(body, "hello");
        assert!(truncated);

        Ok(())
    }
    #[test]
    fn executes_get_against_local_test_server() -> Result<(), String> {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
        };

        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|error| format!("failed to bind local HTTP test server: {error}"))?;

        let address = listener
            .local_addr()
            .map_err(|error| format!("failed to read local test server address: {error}"))?;

        let server = thread::spawn(move || -> Result<(), String> {
            let (mut stream, _) = listener
                .accept()
                .map_err(|error| format!("failed to accept local HTTP connection: {error}"))?;

            let mut request_buffer = [0_u8; 1024];

            let _ = stream
                .read(&mut request_buffer)
                .map_err(|error| format!("failed to read local HTTP request: {error}"))?;

            let response =
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";

            stream
                .write_all(response)
                .map_err(|error| format!("failed to write local HTTP response: {error}"))?;

            Ok(())
        });

        let url = url::Url::parse(&format!("http://{address}/status"))
            .map_err(|error| format!("failed to build local test URL: {error}"))?;

        let destination = crate::http::ValidatedHttpUrl::from_url_for_test(url);

        let executor = HttpExecutor::new(HttpExecutionConfig::default())?;

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| format!("failed to build test HTTP client: {error}"))?;

        let result = executor.execute_with_client(
            &client,
            crate::execution::HttpMethod::Get,
            &destination,
            None,
        )?;

        assert_eq!(result.status_code, 200);
        assert_eq!(result.body, "hello");
        assert!(!result.body_truncated);

        server
            .join()
            .map_err(|_| "local HTTP test server thread panicked".to_owned())??;

        Ok(())
    }
    #[test]
    fn rejects_unsafe_ipv4_outbound_addresses() -> Result<(), String> {
        use std::net::IpAddr;

        let unsafe_addresses = [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "0.0.0.0",
            "224.0.0.1",
            "100.64.0.1",
            "198.18.0.1",
        ];

        for address in unsafe_addresses {
            let address = address
                .parse::<IpAddr>()
                .map_err(|error| format!("failed to parse test IP address: {error}"))?;

            assert!(
                !super::is_safe_outbound_ip(address),
                "{address} should be rejected"
            );
        }

        Ok(())
    }

    #[test]
    fn rejects_unsafe_ipv6_outbound_addresses() -> Result<(), String> {
        use std::net::IpAddr;

        let unsafe_addresses = ["::1", "::", "fc00::1", "fd00::1", "fe80::1", "ff02::1"];

        for address in unsafe_addresses {
            let address = address
                .parse::<IpAddr>()
                .map_err(|error| format!("failed to parse test IP address: {error}"))?;

            assert!(
                !super::is_safe_outbound_ip(address),
                "{address} should be rejected"
            );
        }

        Ok(())
    }

    #[test]
    fn accepts_public_outbound_addresses() -> Result<(), String> {
        use std::net::IpAddr;

        let public_addresses = ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"];

        for address in public_addresses {
            let address = address
                .parse::<IpAddr>()
                .map_err(|error| format!("failed to parse test IP address: {error}"))?;

            assert!(
                super::is_safe_outbound_ip(address),
                "{address} should be allowed"
            );
        }

        Ok(())
    }
    #[test]
    fn rejects_localhost_resolution_as_unsafe() {
        let result = super::resolve_safe_outbound_addresses("localhost", 443);

        assert!(result.is_err());

        let error = result.expect_err("localhost resolution should be rejected");

        assert!(
            error.contains("HTTP destination resolved to a disallowed address"),
            "unexpected error: {error}"
        );
    }
    #[test]
    fn execute_rejects_destination_resolving_to_loopback() -> Result<(), String> {
        let url = url::Url::parse("https://localhost/status")
            .map_err(|error| format!("failed to build test URL: {error}"))?;

        let destination = crate::http::ValidatedHttpUrl::from_url_for_test(url);

        let executor = HttpExecutor::new(HttpExecutionConfig::default())?;

        let result = executor.execute(crate::execution::HttpMethod::Get, &destination, None);

        assert!(result.is_err());

        let error = result.expect_err("loopback-resolving destination should be rejected");

        assert!(
            error.contains("HTTP destination resolved to a disallowed address"),
            "unexpected error: {error}"
        );

        Ok(())
    }
}
