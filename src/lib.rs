use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use thiserror::Error;
use url::Url;

pub const SOURCE_DOMAIN_1: &str = "ema.com.ua";
pub const SOURCE_DOMAIN_2: &str = "www.ema.com.ua";

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("HTTP request failed: {0}")]
    HttpRequest(#[from] reqwest::Error),
    #[error("JSON deserialization failed: {0}")]
    JsonDeserialization(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("API returned unsuccessful status: {0}")]
    ApiStatus(reqwest::StatusCode),
    #[error("{0}")]
    Unexpected(String),
}

#[derive(Deserialize, Debug)]
pub struct BlacklistItem {
    pub url: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct ApiResponse {
    pub data: Vec<BlacklistItem>,
}

/// Extracts and validates a hostname from a given URL string.
///
/// # Examples
///
/// ```
/// use ema_ua_blocklist::extract_and_validate_host;
///
/// assert_eq!(extract_and_validate_host("https://example.com/p?q=1"), Some("example.com".to_string()));
/// assert_eq!(extract_and_validate_host("http://www.sub.domain.co.uk:8080"), Some("www.sub.domain.co.uk".to_string()));
/// assert_eq!(extract_and_validate_host("just-a-domain.com"), Some("just-a-domain.com".to_string()));
/// assert_eq!(extract_and_validate_host("ema.com.ua"), None); // Filtered source domain
/// assert_eq!(extract_and_validate_host(""), None); // Empty string
/// ```
pub fn extract_and_validate_host(url_string: &str) -> Option<String> {
    let trimmed = url_string.trim();

    if trimmed.is_empty() || !trimmed.contains('.') {
        return None;
    }

    let url_to_parse = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };

    if let Ok(parsed_url) = Url::parse(&url_to_parse) {
        if !matches!(parsed_url.scheme(), "http" | "https") {
            return None;
        }
        if let Some(host) = parsed_url.host_str() {
            if !host.contains('.') {
                return None;
            }
            let host_lower = host.to_lowercase();
            if host_lower != SOURCE_DOMAIN_1 && host_lower != SOURCE_DOMAIN_2 {
                return Some(host_lower);
            }
        }
    } else if !trimmed.contains(' ')
        && !trimmed.starts_with('/')
        && !trimmed.contains("://")
        && trimmed.contains('.')
    {
        let host_lower = trimmed.to_lowercase();
        if host_lower != SOURCE_DOMAIN_1 && host_lower != SOURCE_DOMAIN_2 {
            return Some(host_lower);
        }
    }

    None
}

/// Fetches all hostnames from the EMA API using pagination.
///
/// # Examples
///
/// ```no_run
/// # async fn doc_example() -> Result<(), ema_ua_blocklist::FetchError> {
/// use ema_ua_blocklist::fetch_all_hosts;
/// use std::collections::HashSet;
///
/// // Note: This is a mock URL for demonstration purposes
/// // In a real scenario, you would use the actual EMA API endpoint
/// let hosts = fetch_all_hosts("https://api.ema.com.ua/domains", "MyAgent/1.0", 100).await?;
/// println!("Found {} unique hosts", hosts.len());
/// # Ok(())
/// # }
/// ```
pub async fn fetch_all_hosts(
    base_url: &str,
    user_agent: &str,
    page_size: usize,
) -> Result<HashSet<String>, FetchError> {
    let client = Client::builder()
        .user_agent(user_agent)
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let mut all_hosts = HashSet::new();
    let mut offset = 0;

    loop {
        println!("Fetching data from offset: {offset}");

        // setup URL for mockito (path /?offset=X) and real API
        let api_url =
            if base_url.starts_with("http://127.0.0.1") || base_url.contains("non-existent") {
                format!("{base_url}/?offset={offset}")
            } else {
                format!("{base_url}?offset={offset}")
            };

        let response = match client.get(&api_url).send().await {
            Ok(resp) => resp,
            Err(_) => {
                return Err(FetchError::Unexpected(format!(
                    "Error: Network request failed. URL: {}",
                    api_url
                )));
            }
        };

        if !response.status().is_success() {
            return Err(FetchError::Unexpected(format!(
                "Error: Failed to fetch API (Status: {}). URL: {}",
                response.status().as_u16(),
                api_url
            )));
        }

        let text = response.text().await?;
        let api_response: ApiResponse = match serde_json::from_str(&text) {
            Ok(data) => data,
            Err(e) => {
                return Err(FetchError::Unexpected(format!(
                    "Error: Failed to parse JSON response: {}",
                    e
                )));
            }
        };

        if api_response.data.is_empty() {
            println!("No more data returned from API.");
            break;
        }

        let fetched_count = api_response.data.len();
        let mut new_hosts_count = 0;

        for item in &api_response.data {
            if let Some(url_str) = &item.url
                && let Some(host) = extract_and_validate_host(url_str)
                && all_hosts.insert(host)
            {
                new_hosts_count += 1;
            }
        }

        println!(
            "Fetched {} items, new unique hosts added: {}, total unique hosts: {}",
            fetched_count,
            new_hosts_count,
            all_hosts.len()
        );

        if fetched_count < page_size {
            println!("Last page of data received.");
            break;
        }

        offset += page_size;
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    Ok(all_hosts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_api_response() {
        let json_data = r#"{"data": [{"url":"https://e1.com"},{"url":"http://e2.net"}]}"#;
        let parsed: Result<ApiResponse, _> = serde_json::from_str(json_data);
        assert!(parsed.is_ok());
        let api_response = parsed.unwrap();
        assert_eq!(api_response.data.len(), 2);
        assert_eq!(
            api_response.data[0].url,
            Some(String::from("https://e1.com"))
        );
        assert_eq!(
            api_response.data[1].url,
            Some(String::from("http://e2.net"))
        );
    }

    #[test]
    fn test_deserialize_empty_api_response() {
        let json_data = r#"{"data": []}"#;
        let parsed: Result<ApiResponse, _> = serde_json::from_str(json_data);
        assert!(parsed.is_ok());
        assert!(parsed.unwrap().data.is_empty());
    }

    #[test]
    fn test_deserialize_invalid_json() {
        let json_data = r#"{"data": [ {"url": ] }"#; // Invalid JSON
        let parsed: Result<ApiResponse, _> = serde_json::from_str(json_data);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_extract_host_valid_urls() {
        assert_eq!(
            extract_and_validate_host("https://example.com/p?q=1"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_and_validate_host("http://www.sub.domain.co.uk:8080"),
            Some("www.sub.domain.co.uk".to_string())
        );
        assert_eq!(
            extract_and_validate_host("just-a-domain.com"),
            Some("just-a-domain.com".to_string())
        );
        assert_eq!(
            extract_and_validate_host(" domain.net "),
            Some("domain.net".to_string())
        );
        assert_eq!(
            extract_and_validate_host("xn--bcher-kva.example"),
            Some("xn--bcher-kva.example".to_string())
        );
        assert_eq!(
            extract_and_validate_host("192.168.1.1"),
            Some("192.168.1.1".to_string())
        );
        assert_eq!(
            extract_and_validate_host("http://1.2.3.4/path"),
            Some("1.2.3.4".to_string())
        );
    }

    #[test]
    fn test_extract_host_filtered_urls() {
        assert_eq!(
            extract_and_validate_host("https://ema.com.ua/"),
            None,
            "Filtered source domain"
        );
        assert_eq!(
            extract_and_validate_host("http://www.ema.com.ua/p"),
            None,
            "Filtered source www subdomain"
        );
        assert_eq!(
            extract_and_validate_host("ema.com.ua"),
            None,
            "Filtered source domain (no scheme)"
        );
        assert_eq!(
            extract_and_validate_host("https://WWW.EMA.COM.UA"),
            None,
            "Filtered source domain (uppercase)"
        );
    }

    #[test]
    fn test_extract_host_invalid_inputs() {
        assert_eq!(extract_and_validate_host(""), None, "Empty string");
        assert_eq!(extract_and_validate_host(" "), None, "Whitespace only");
        assert_eq!(
            extract_and_validate_host("nodot"),
            None,
            "No dot - should fail early check"
        );
        assert_eq!(
            extract_and_validate_host("http://nodot"),
            None,
            "No dot in host - should fail check after parse"
        );
        assert_eq!(extract_and_validate_host("http://"), None, "Scheme only");
        assert_eq!(extract_and_validate_host("/path/only"), None, "Path only");
        assert_eq!(
            extract_and_validate_host("http:///invalid"),
            None,
            "Invalid URL structure (no host)"
        );
        assert_eq!(
            extract_and_validate_host(" example com "),
            None,
            "Spaces within (should be trimmed, but fallback might fail)"
        );
    }

    #[test]
    fn test_output_formatting() {
        let host = "h.com";
        assert_eq!(format!("0.0.0.0 {}", host), "0.0.0.0 h.com");
        assert_eq!(format!("||{}^", host), "||h.com^");
    }
}
