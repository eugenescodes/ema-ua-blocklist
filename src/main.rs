//! EMA UA Blocklist Fetcher
//!
//! This program fetches blacklist data from the EMA API, extracts hostnames,
//! filters them, and generates output files in hosts format (0.0.0.0 ...)
//! and uBlock Origin format (||...^).

use chrono::Utc;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufWriter, Write};
use thiserror::Error;
use url::Url;

const BASE_API_URL: &str = "https://www.ema.com.ua/wp-json/api/blacklist-query";
const USER_AGENT: &str = "ema scraper bot (github.com/eugenescodes/ema-ua-blocklist)";
const PAGE_SIZE: usize = 12;
const REPO_NAME: &str = "ema-ua-blocklist";
const LICENSE_FILE: &str = "LICENSE";
const HOSTS_FILENAME: &str = "hosts_ema.txt";
const UBLOCK_FILENAME: &str = "hosts_ema_ublock.txt";
const SOURCE_DOMAIN_1: &str = "ema.com.ua";
const SOURCE_DOMAIN_2: &str = "www.ema.com.ua";

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
    #[error("Unexpected error: {0}")]
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
/// Returns the lowercase hostname if valid and not filtered, otherwise None.
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
pub async fn fetch_all_hosts(client: &Client) -> Result<HashSet<String>, FetchError> {
    let mut all_hosts = HashSet::new();
    let mut offset = 0;

    loop {
        println!("Fetching data from offset: {offset}");
        let api_url = format!("{BASE_API_URL}?offset={offset}");
        let response = client.get(&api_url).send().await?;

        if !response.status().is_success() {
            return Err(FetchError::ApiStatus(response.status()));
        }

        let api_response: ApiResponse = response.json().await?;

        if api_response.data.is_empty() {
            println!("No more data returned from API.");
            break;
        }

        let _before_count = all_hosts.len();
        let fetched_count = api_response.data.len();

        let mut new_hosts_count = 0;
        for item in &api_response.data {
            if let Some(url_str) = &item.url {
                if let Some(host) = extract_and_validate_host(url_str) {
                    if all_hosts.insert(host) {
                        new_hosts_count += 1;
                    }
                }
            }
        }

        println!(
            "Fetched {} items, new unique hosts added: {}, total unique hosts: {}",
            fetched_count,
            new_hosts_count,
            all_hosts.len()
        );

        if fetched_count < PAGE_SIZE {
            println!("Last page of data received.");
            break;
        }

        offset += PAGE_SIZE;

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    Ok(all_hosts)
}

fn write_hosts_file(hosts: &[String]) -> Result<(), FetchError> {
    let homepage_url = format!("https://github.com/eugenescodes/{REPO_NAME}");
    let license_url =
        format!("https://github.com/eugenescodes/{REPO_NAME}/blob/main/{LICENSE_FILE}",);
    let source_description = "ema.com.ua Blacklist API";
    let timestamp_str = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    let header = format!(
        r#"# Title: Blocklist from {} for DNS-level blocking (e.g., hosts file, Pi-hole)
# Homepage: {}
# License: {}
#
# Last modified: {}
#
# Sources:
# - {} ({})
#
# Format: 0.0.0.0 domain.tld
# Number of entries: {}
#
# Source:
"#,
        source_description,
        homepage_url,
        license_url,
        timestamp_str,
        BASE_API_URL,
        source_description,
        hosts.len()
    );

    let file = File::create(HOSTS_FILENAME)?;
    let mut writer = BufWriter::new(file);

    writer.write_all(header.as_bytes())?;
    for host in hosts {
        writeln!(writer, "0.0.0.0 {host}")?;
    }
    writer.flush()?;

    println!("Successfully wrote {HOSTS_FILENAME}");
    Ok(())
}

fn write_ublock_file(hosts: &[String]) -> Result<(), FetchError> {
    let homepage_url = format!("https://github.com/eugenescodes/{REPO_NAME}");
    let license_url =
        format!("https://github.com/eugenescodes/{REPO_NAME}/blob/main/{LICENSE_FILE}",);
    let source_description = "ema.com.ua Blacklist API";
    let timestamp_str = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    let header = format!(
        r#"! Title: ema.com.ua Blacklist for Adblockers (uBlock Origin, AdGuard, etc.)
! Homepage: {}
! License: {}
! Last modified: {}
! Expires: 1 day (update frequency recommendation)
! Sources: {} ({})
! Number of entries: {}
!
"#,
        homepage_url,
        license_url,
        timestamp_str,
        BASE_API_URL,
        source_description,
        hosts.len()
    );

    let file = File::create(UBLOCK_FILENAME)?;
    let mut writer = BufWriter::new(file);

    writer.write_all(header.as_bytes())?;
    for host in hosts {
        writeln!(writer, "||{host}^")?;
    }
    writer.flush()?;

    println!("Successfully wrote {UBLOCK_FILENAME}");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), FetchError> {
    println!("Starting data fetch from EMA API...");

    let client = Client::builder()
        .user_agent(USER_AGENT)
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let all_hosts = fetch_all_hosts(&client).await?;

    println!("Finished fetching data.");
    println!("\nTotal unique hosts collected: {}", all_hosts.len());

    if all_hosts.is_empty() {
        println!("No hosts were collected. Skipping file generation.");
        return Ok(());
    }

    let mut sorted_hosts: Vec<String> = all_hosts.into_iter().collect();
    sorted_hosts.sort_unstable();

    write_hosts_file(&sorted_hosts)?;
    write_ublock_file(&sorted_hosts)?;

    println!("\nScript finished successfully.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

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
