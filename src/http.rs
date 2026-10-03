use url::{Host, Url};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedHttpUrl {
    url: Url,
}

impl ValidatedHttpUrl {
    pub fn as_url(&self) -> &Url {
        &self.url
    }
    #[cfg(test)]
    pub fn from_url_for_test(url: Url) -> Self {
        Self { url }
    }
}

pub fn validate_http_destination(
    input: &str,
    allowed_hosts: &[&str],
) -> Result<ValidatedHttpUrl, String> {
    let url = Url::parse(input).map_err(|error| format!("invalid HTTP URL: {error}"))?;

    if url.scheme() != "https" {
        return Err("HTTP destination must use HTTPS".to_owned());
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err("HTTP destination must not contain embedded credentials".to_owned());
    }

    let host = match url.host() {
        Some(Host::Domain(host)) => host,
        Some(Host::Ipv4(_)) | Some(Host::Ipv6(_)) => {
            return Err("HTTP destination must not use an IP-literal host".to_owned());
        }
        None => {
            return Err("HTTP destination must include a host".to_owned());
        }
    };

    if host.eq_ignore_ascii_case("localhost") {
        return Err("localhost HTTP destinations are not allowed".to_owned());
    }

    if url.port().is_some_and(|port| port != 443) {
        return Err("HTTP destination must use the default HTTPS port".to_owned());
    }

    let allowed = allowed_hosts
        .iter()
        .any(|allowed_host| host.eq_ignore_ascii_case(allowed_host));

    if !allowed {
        return Err("HTTP destination host is not allowlisted".to_owned());
    }

    Ok(ValidatedHttpUrl { url })
}

#[cfg(test)]
mod tests {
    use super::validate_http_destination;

    const ALLOWED_HOSTS: &[&str] = &["api.example.com"];

    #[test]
    fn accepts_allowlisted_https_host() -> Result<(), String> {
        let validated = validate_http_destination("https://api.example.com/status", ALLOWED_HOSTS)?;

        assert_eq!(
            validated.as_url().as_str(),
            "https://api.example.com/status"
        );

        Ok(())
    }

    #[test]
    fn rejects_http_scheme() {
        let result = validate_http_destination("http://api.example.com/status", ALLOWED_HOSTS);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_unapproved_host() {
        let result = validate_http_destination("https://evil.example/status", ALLOWED_HOSTS);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_ip_literal_host() {
        let result = validate_http_destination("https://127.0.0.1/status", ALLOWED_HOSTS);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_localhost() {
        let result = validate_http_destination("https://localhost/status", &["localhost"]);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_embedded_credentials() {
        let result =
            validate_http_destination("https://user:secret@api.example.com/status", ALLOWED_HOSTS);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_non_default_https_port() {
        let result =
            validate_http_destination("https://api.example.com:8443/status", ALLOWED_HOSTS);

        assert!(result.is_err());
    }
}
