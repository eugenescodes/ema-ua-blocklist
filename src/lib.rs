use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use thiserror::Error;
use url::Url;

const MAX_REQUEST_RETRIES: u32 = 3;
const INITIAL_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(250);
const MAX_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(30);

pub const SOURCE_DOMAIN_1: &str = "ema.com.ua";
pub const SOURCE_DOMAIN_2: &str = "www.ema.com.ua";

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("HTTP request failed: {0}")]
    HttpRequest(#[from] reqwest::Error),
    #[error("Network request failed for {url}: {source}")]
    Request {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
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

#[derive(Debug, Default, PartialEq, Eq)]
pub struct BlacklistEntries {
    pub hosts: HashSet<String>,
    pub ips: HashSet<std::net::IpAddr>,
}

fn is_allowed_api_url(url: &Url) -> bool {
    match url.scheme() {
        "https" => true,
        // Local HTTP is reserved for loopback mock servers; public API URLs must use TLS.
        "http" => {
            matches!(url.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
                || matches!(url.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback())
        }
        _ => false,
    }
}

fn is_allowed_redirect(previous: &[Url], next: &Url) -> bool {
    is_allowed_api_url(next)
        && !(previous.iter().any(|url| url.scheme() == "https") && next.scheme() != "https")
}

fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS
}

fn is_retryable_request_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect() || error.is_body()
}

fn is_retryable_body_error(error: &reqwest::Error) -> bool {
    is_retryable_request_error(error)
        || (error.is_decode() && error.status().is_some_and(|status| status.is_success()))
}

fn exponential_retry_delay(retry_number: u32) -> std::time::Duration {
    INITIAL_RETRY_DELAY
        .saturating_mul(2u32.saturating_pow(retry_number))
        .min(MAX_RETRY_DELAY)
}

fn retry_after_delay(
    value: Option<&reqwest::header::HeaderValue>,
    now: std::time::SystemTime,
) -> Option<std::time::Duration> {
    let value = value?.to_str().ok()?.trim();

    if let Ok(seconds) = value.parse::<u64>() {
        return Some(std::time::Duration::from_secs(seconds).min(MAX_RETRY_DELAY));
    }

    let retry_at = httpdate::parse_http_date(value).ok()?;
    Some(
        retry_at
            .duration_since(now)
            .unwrap_or_default()
            .min(MAX_RETRY_DELAY),
    )
}

fn jittered_retry_delay(
    retry_number: u32,
    retry_after: Option<&reqwest::header::HeaderValue>,
    now: std::time::SystemTime,
    random_sample: u64,
) -> std::time::Duration {
    if let Some(delay) = retry_after_delay(retry_after, now) {
        return delay;
    }

    let ceiling = exponential_retry_delay(retry_number).as_millis() as u64;
    let lower_bound = (ceiling / 2).max(1);
    let jitter_millis = lower_bound + random_sample % (ceiling - lower_bound + 1);
    std::time::Duration::from_millis(jitter_millis)
}

fn normalize_url_entry(value: &str) -> String {
    value
        .chars()
        .filter(|character| !matches!(*character, '\u{200B}'..='\u{200D}' | '\u{FEFF}'))
        .collect::<String>()
        .trim()
        .trim_matches('.')
        .to_string()
}

fn extract_ip_from_url(value: &str) -> Option<std::net::IpAddr> {
    let normalized = normalize_url_entry(value);
    if normalized.is_empty() {
        return None;
    }

    let url_to_parse = if normalized.contains("://") {
        normalized
    } else {
        format!("http://{normalized}")
    };
    let parsed_url = Url::parse(&url_to_parse).ok()?;
    if !matches!(parsed_url.scheme(), "http" | "https") {
        return None;
    }

    match parsed_url.host()? {
        url::Host::Ipv4(ip) => Some(ip.into()),
        url::Host::Ipv6(ip) => Some(ip.into()),
        url::Host::Domain(_) => None,
    }
}

fn is_valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return false;
    }

    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }

    labels.iter().all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && bytes[0].is_ascii_alphanumeric()
            && bytes[bytes.len() - 1].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    })
}

fn is_source_domain(host: &str) -> bool {
    host == SOURCE_DOMAIN_1 || host.ends_with(&format!(".{SOURCE_DOMAIN_1}"))
}

async fn send_with_retries(
    client: &Client,
    api_url: &Url,
) -> Result<(reqwest::StatusCode, String), FetchError> {
    let mut retries = 0;

    loop {
        match client.get(api_url.clone()).send().await {
            Ok(response)
                if is_retryable_status(response.status()) && retries < MAX_REQUEST_RETRIES =>
            {
                let status = response.status();
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .cloned();
                retries += 1;
                let delay = jittered_retry_delay(
                    retries - 1,
                    retry_after.as_ref(),
                    std::time::SystemTime::now(),
                    fastrand::u64(..),
                );
                drop(response);
                eprintln!(
                    "Transient API status {status} for {api_url}; retrying in {delay:?} ({retries}/{MAX_REQUEST_RETRIES})"
                );
                tokio::time::sleep(delay).await;
            }
            Ok(response) => {
                let status = response.status();
                match response.text().await {
                    Ok(body) => return Ok((status, body)),
                    Err(error)
                        if is_retryable_body_error(&error) && retries < MAX_REQUEST_RETRIES =>
                    {
                        retries += 1;
                        let delay = jittered_retry_delay(
                            retries - 1,
                            None,
                            std::time::SystemTime::now(),
                            fastrand::u64(..),
                        );
                        eprintln!(
                            "Transient response-body error for {api_url}: {error}; retrying in {delay:?} ({retries}/{MAX_REQUEST_RETRIES})"
                        );
                        tokio::time::sleep(delay).await;
                    }
                    Err(source) => {
                        return Err(FetchError::Request {
                            url: api_url.to_string(),
                            source,
                        });
                    }
                }
            }
            Err(error) if is_retryable_request_error(&error) && retries < MAX_REQUEST_RETRIES => {
                retries += 1;
                let delay = jittered_retry_delay(
                    retries - 1,
                    None,
                    std::time::SystemTime::now(),
                    fastrand::u64(..),
                );
                eprintln!(
                    "Transient request error for {api_url}: {error}; retrying in {delay:?} ({retries}/{MAX_REQUEST_RETRIES})"
                );
                tokio::time::sleep(delay).await;
            }
            Err(source) => {
                return Err(FetchError::Request {
                    url: api_url.to_string(),
                    source,
                });
            }
        }
    }
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
pub fn extract_and_validate_ip(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let candidate = trimmed
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(trimmed);
    if candidate.is_empty() {
        return None;
    }

    if let Ok(ipv4) = candidate.parse::<std::net::Ipv4Addr>() {
        return Some(ipv4.to_string());
    }

    if let Ok(ipv6) = candidate.parse::<std::net::Ipv6Addr>() {
        return Some(ipv6.to_string());
    }

    None
}

pub fn extract_and_validate_host(url_string: &str) -> Option<String> {
    let normalized = normalize_url_entry(url_string);
    let trimmed = normalized.trim();

    if trimmed.is_empty() || !trimmed.contains('.') {
        return None;
    }

    if extract_and_validate_ip(trimmed).is_some() {
        return None;
    }

    let url_to_parse = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };

    let parsed_url = Url::parse(&url_to_parse).ok()?;
    if !matches!(parsed_url.scheme(), "http" | "https") {
        return None;
    }

    let host_lower = parsed_url.host_str()?.to_ascii_lowercase();
    if !is_valid_hostname(&host_lower) || is_source_domain(&host_lower) {
        return None;
    }

    if extract_and_validate_ip(&host_lower).is_some() {
        return None;
    }

    Some(host_lower)
}

/// Fetches all hostnames from the API using pagination.
///
/// The API URL must use HTTPS. HTTP is permitted only for loopback addresses, such as local test servers.
/// `page_size` is sent as the API's `count` parameter and must be greater than zero.
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
    Ok(fetch_all_entries(base_url, user_agent, page_size)
        .await?
        .hosts)
}

/// Fetches all unique hostnames and IP addresses from the API using pagination.
///
/// The API URL must use HTTPS. HTTP is permitted only for loopback addresses, such as local test servers.
/// `page_size` is sent as the API's `count` parameter and must be greater than zero.
pub async fn fetch_all_entries(
    base_url: &str,
    user_agent: &str,
    page_size: usize,
) -> Result<BlacklistEntries, FetchError> {
    if page_size == 0 {
        return Err(FetchError::Unexpected(
            "Page size must be greater than zero".to_string(),
        ));
    }

    let parsed_base_url = Url::parse(base_url)
        .map_err(|error| FetchError::Unexpected(format!("Error: Invalid API URL: {error}")))?;
    if !is_allowed_api_url(&parsed_base_url) {
        return Err(FetchError::Unexpected(format!(
            "Error: API URL must use HTTPS (HTTP is allowed only for loopback): {base_url}"
        )));
    }

    let existing_query: Vec<(String, String)> = parsed_base_url
        .query_pairs()
        .filter(|(key, _)| key != "count" && key != "offset")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();

    let client = Client::builder()
        .user_agent(user_agent)
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if is_allowed_redirect(attempt.previous(), attempt.url()) {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .build()?;

    let mut entries = BlacklistEntries::default();
    let mut offset = 0;

    loop {
        println!("Fetching data from offset: {offset}");

        let mut api_url = parsed_base_url.clone();
        api_url.set_query(None);
        {
            let mut query = api_url.query_pairs_mut();
            for (key, value) in &existing_query {
                query.append_pair(key, value);
            }
            query
                .append_pair("count", &page_size.to_string())
                .append_pair("offset", &offset.to_string());
        }

        let (status, text) = send_with_retries(&client, &api_url).await?;

        if !status.is_success() {
            return Err(FetchError::Unexpected(format!(
                "Error: Failed to fetch API (Status: {}). URL: {}",
                status.as_u16(),
                api_url
            )));
        }

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
        let mut new_ips_count = 0;

        for item in &api_response.data {
            if let Some(url_str) = &item.url {
                for url in url_str.split_whitespace() {
                    if let Some(ip) = extract_ip_from_url(url) {
                        if entries.ips.insert(ip) {
                            new_ips_count += 1;
                        }
                    } else if let Some(host) = extract_and_validate_host(url)
                        && entries.hosts.insert(host)
                    {
                        new_hosts_count += 1;
                    }
                }
            }
        }

        println!(
            "Fetched {} items, new unique hosts added: {}, new IPs added: {}, total unique hosts: {}, total IPs: {}",
            fetched_count,
            new_hosts_count,
            new_ips_count,
            entries.hosts.len(),
            entries.ips.len()
        );

        if fetched_count < page_size {
            println!("Last page of data received.");
            break;
        }

        offset += fetched_count;
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_url_scheme_validation() {
        assert!(is_allowed_api_url(
            &Url::parse("https://api.example.com").unwrap()
        ));
        assert!(is_allowed_api_url(
            &Url::parse("http://127.0.0.1:8080").unwrap()
        ));
        assert!(is_allowed_api_url(
            &Url::parse("http://[::1]:8080").unwrap()
        ));
        assert!(!is_allowed_api_url(
            &Url::parse("http://api.example.com").unwrap()
        ));
        assert!(!is_allowed_api_url(
            &Url::parse("ftp://api.example.com").unwrap()
        ));
        assert!(!is_allowed_redirect(
            &[Url::parse("https://api.example.com").unwrap()],
            &Url::parse("http://127.0.0.1:8080").unwrap(),
        ));
    }

    #[test]
    fn retry_after_supports_delta_seconds_and_caps_long_delays() {
        let now = std::time::SystemTime::UNIX_EPOCH;
        let zero = reqwest::header::HeaderValue::from_static("0");
        let five = reqwest::header::HeaderValue::from_static("5");
        let excessive = reqwest::header::HeaderValue::from_static("3600");

        assert_eq!(
            retry_after_delay(Some(&zero), now),
            Some(std::time::Duration::ZERO)
        );
        assert_eq!(
            retry_after_delay(Some(&five), now),
            Some(std::time::Duration::from_secs(5))
        );
        assert_eq!(
            retry_after_delay(Some(&excessive), now),
            Some(MAX_RETRY_DELAY)
        );
    }

    #[test]
    fn retry_after_supports_http_date_and_falls_back_for_invalid_values() {
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let retry_at = now + std::time::Duration::from_secs(12);
        let header =
            reqwest::header::HeaderValue::from_str(&httpdate::fmt_http_date(retry_at)).unwrap();
        let invalid = reqwest::header::HeaderValue::from_static("not-a-date");

        assert_eq!(
            retry_after_delay(Some(&header), now),
            Some(std::time::Duration::from_secs(12))
        );
        assert_eq!(retry_after_delay(Some(&invalid), now), None);
        assert_eq!(
            jittered_retry_delay(0, Some(&invalid), now, 249),
            std::time::Duration::from_millis(248)
        );
    }

    #[test]
    fn retry_after_http_date_is_clamped_and_past_dates_mean_zero_delay() {
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let far_future = now + std::time::Duration::from_secs(3_600);
        let past = now - std::time::Duration::from_secs(3_600);
        let far_future_header =
            reqwest::header::HeaderValue::from_str(&httpdate::fmt_http_date(far_future)).unwrap();
        let past_header =
            reqwest::header::HeaderValue::from_str(&httpdate::fmt_http_date(past)).unwrap();

        assert_eq!(
            retry_after_delay(Some(&far_future_header), now),
            Some(MAX_RETRY_DELAY)
        );
        assert_eq!(
            retry_after_delay(Some(&past_header), now),
            Some(std::time::Duration::ZERO)
        );
    }

    #[test]
    fn jitter_is_bounded_by_exponential_backoff_ceiling() {
        let now = std::time::SystemTime::UNIX_EPOCH;
        assert_eq!(
            jittered_retry_delay(0, None, now, 250),
            std::time::Duration::from_millis(249)
        );
        assert_eq!(
            jittered_retry_delay(0, None, now, 0),
            std::time::Duration::from_millis(125)
        );
        assert!(exponential_retry_delay(100) <= MAX_RETRY_DELAY);
        assert_eq!(exponential_retry_delay(0), INITIAL_RETRY_DELAY);
    }

    #[test]
    fn test_deserialize_api_response() {
        let json_data = r#"{"data": [{"url":"https://e1.com"},{"url":"http://e2.net"}]}"#;
        let parsed: Result<ApiResponse, _> = serde_json::from_str(json_data);
        assert!(parsed.is_ok());
        let api_response = parsed.unwrap_or_else(|_| ApiResponse { data: vec![] });
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
        let api_response = parsed.unwrap_or_else(|_| ApiResponse { data: vec![] });
        assert!(api_response.data.is_empty());
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
            extract_and_validate_ip("192.168.1.1"),
            Some("192.168.1.1".to_string())
        );
        assert_eq!(extract_and_validate_ip("[::1]"), Some("::1".to_string()));
        assert_eq!(extract_and_validate_host("192.168.1.1"), None);
        assert_eq!(extract_and_validate_host("http://1.2.3.4/path"), None);
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
        assert_eq!(
            extract_and_validate_host("https://phishing.ema.com.ua/login"),
            None,
            "Filtered source subdomain"
        );
        assert_eq!(
            extract_and_validate_host("https://notema.com.ua/"),
            Some("notema.com.ua".to_string()),
            "Do not filter domains that merely end in the source-domain string"
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
        assert_eq!(extract_and_validate_host("https://bad..example/path"), None);
        assert_eq!(extract_and_validate_host("https://-bad.example/path"), None);
        assert_eq!(extract_and_validate_host("https://bad-.example/path"), None);
        assert_eq!(
            extract_and_validate_host("https://bad_name.example/path"),
            None
        );
        assert_eq!(extract_and_validate_host("https://example."), None);
    }

    #[test]
    fn test_hostname_validation_enforces_dns_label_limits() {
        let valid_63_character_label = format!("{}.example", "a".repeat(63));
        let invalid_64_character_label = format!("{}.example", "a".repeat(64));
        let invalid_254_character_hostname = format!(
            "{}.{}.{}.{}.{}",
            "a".repeat(50),
            "b".repeat(50),
            "c".repeat(50),
            "d".repeat(50),
            "e".repeat(50)
        );

        assert!(is_valid_hostname("example.com"));
        assert!(is_valid_hostname(&valid_63_character_label));
        assert!(!is_valid_hostname(&invalid_64_character_label));
        assert!(!is_valid_hostname(&invalid_254_character_hostname));
        assert!(!is_valid_hostname("example..com"));
        assert!(!is_valid_hostname("-example.com"));
        assert!(!is_valid_hostname("example-.com"));
        assert!(!is_valid_hostname("example_com"));
    }

    #[test]
    fn test_output_formatting() {
        let host = "h.com";
        assert_eq!(format!("0.0.0.0 {}", host), "0.0.0.0 h.com");
        assert_eq!(format!("||{}^", host), "||h.com^");
    }
}
