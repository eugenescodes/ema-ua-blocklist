// Project: ema-ua-blocklist
// This script fetches blacklist data from the EMA API, extracts hostnames,
// filters them, and generates output files in hosts format (0.0.0.0 ...)
// and uBlock Origin format (||...^).

use chrono::Utc;
use reqwest;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufWriter, Write};
use url::Url;

// --- Structs for Deserialization ---

/// Represents a single item in the blacklist data array from the API.
#[derive(Deserialize, Debug, Clone)]
pub struct BlacklistItem {
    pub url: Option<String>,
}

/// Represents the overall structure of the API JSON response.
#[derive(Deserialize, Debug, Clone)]
pub struct ApiResponse {
    pub data: Vec<BlacklistItem>,
}

// --- Core Logic Functions (made public for integration tests) ---

/// Extracts and validates a hostname from a given URL string.
/// Returns the lowercase hostname if valid and not filtered, otherwise None.
pub fn extract_and_validate_host(url_string: &str) -> Option<String> {
    let trimmed_url = url_string.trim();
    // check for invalid inputs ---
    if trimmed_url.is_empty() || !trimmed_url.contains('.') {
        return None;
    }

    let url_to_parse = if !trimmed_url.contains("://") {
        format!("http://{trimmed_url}")
    } else {
        trimmed_url.to_string()
    };

    if let Ok(parsed_url) = Url::parse(&url_to_parse) {
        // --- Scheme Check ---
        // Only proceed if the scheme is http or https
        if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
            return None; // Reject other schemes like mailto, ftp, etc.
        }

        if let Some(host_str) = parsed_url.host_str() {
            if !host_str.contains('.') {
                return None; // Host must contain a dot
            }
            let host_lower = host_str.to_lowercase();
            // Filter the source domain itself
            if !host_lower.eq_ignore_ascii_case("ema.com.ua")
                && !host_lower.eq_ignore_ascii_case("www.ema.com.ua")
            {
                return Some(host_lower);
            }
        }
    } else if !trimmed_url.contains(' ')
        && !trimmed_url.starts_with('/')
        && !trimmed_url.contains("://")
        && trimmed_url.contains('.')
    {
        let host_lower = trimmed_url.to_lowercase();
        if !host_lower.eq_ignore_ascii_case("ema.com.ua")
            && !host_lower.eq_ignore_ascii_case("www.ema.com.ua")
        {
            return Some(host_lower);
        }
    }

    None
}

/// Fetches all hostnames from the EMA API using pagination.
pub async fn fetch_all_hosts(
    base_api_url: &str,
    user_agent: &str,
    page_size: usize,
) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let mut all_hosts = HashSet::new();
    let mut offset = 0;

    loop {
        let api_url = format!("{base_api_url}?offset={offset}");

        let response_result = client.get(&api_url).send().await;

        match response_result {
            Ok(response) => {
                if !response.status().is_success() {
                    return Err(format!(
                        "Error: Failed to fetch API (Status: {}). URL: {}",
                        response.status(),
                        api_url
                    )
                    .into());
                }
                match response.json::<ApiResponse>().await {
                    Ok(api_response) => {
                        if api_response.data.is_empty() {
                            return Ok(all_hosts);
                        }

                        for item in &api_response.data {
                            if let Some(url_str) = &item.url {
                                if let Some(host) = extract_and_validate_host(url_str) {
                                    all_hosts.insert(host);
                                }
                            }
                        }
                        if api_response.data.len() < page_size {
                            return Ok(all_hosts);
                        }
                        offset += page_size;
                    }
                    Err(e) => {
                        return Err(format!(
                            "Error: Failed to parse JSON response from {api_url}: {e}"
                        )
                        .into());
                    }
                }
            }
            Err(e) => {
                return Err(format!("Error: Network request failed for {api_url}: {e}").into());
            }
        }
        // pause between requests
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
}

// --- Main Application Entry Point ---

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Configuration ---
    let base_api_url = "https://www.ema.com.ua/wp-json/api/blacklist-query";
    let user_agent = "ema scraper bot (github.com/eugenescodes/ema-ua-blocklist)";
    let page_size = 12; // Page size (number of items per API request)
    let repo_name = "ema-ua-blocklist";
    let license_file = "LICENSE";
    let hosts_filename = "hosts_ema.txt";
    let ublock_filename = "hosts_ema_ublock.txt";
    // --- End Configuration ---

    // --- Fetch Data ---
    println!("Starting data fetch from EMA API...");
    let all_hosts = match fetch_all_hosts(base_api_url, user_agent, page_size).await {
        Ok(hosts) => hosts,
        Err(e) => {
            eprintln!("Error fetching data: {e}");
            return Err(e);
        }
    };
    println!("Finished fetching data.");

    // --- Process Collected Data and Write Files ---
    println!("\nTotal unique hosts collected: {}", all_hosts.len());
    if all_hosts.is_empty() {
        println!("No hosts were collected. Skipping file generation.");
        return Ok(());
    }
    let mut sorted_hosts: Vec<String> = all_hosts.into_iter().collect();
    sorted_hosts.sort_unstable();

    // --- Prepare Header Information ---
    // Construct URLs assuming the script runs from the repo root
    let homepage_url = format!("https://github.com/eugenescodes/{repo_name}");
    // Correct path assuming LICENSE is in the root
    let license_url =
        format!("https://github.com/eugenescodes/{repo_name}/blob/main/{license_file}",);
    let source_description = "ema.com.ua Blacklist API";
    let now_utc = Utc::now();
    let timestamp_str = now_utc.format("%Y-%m-%d %H:%M:%S UTC").to_string();

    // --- Construct Header Text for Hosts File ---
    let hosts_file_header = format!(
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
        base_api_url, // Use the original base_api_url here for the header
        source_description,
        sorted_hosts.len()
    );

    // --- Write Hosts File (0.0.0.0 format) ---
    println!("\nWriting hosts file (0.0.0.0 format): {hosts_filename}");
    match File::create(hosts_filename) {
        Ok(file) => {
            let mut writer = BufWriter::new(file);
            if write!(writer, "{hosts_file_header}").is_ok() {
                for host in &sorted_hosts {
                    // Add newline consistently with writeln!
                    if writeln!(writer, "0.0.0.0 {host}").is_err() {
                        eprintln!("Error writing host line to {hosts_filename}");
                        // Consider returning an error instead of just breaking
                        return Err(format!("Failed to write to {hosts_filename}").into());
                    }
                }
                if writer.flush().is_err() {
                    eprintln!("Error flushing buffer for {hosts_filename}");
                    // Consider returning an error
                    return Err(format!("Failed to flush {hosts_filename}").into());
                } else {
                    println!("Successfully wrote {hosts_filename}");
                }
            } else {
                eprintln!("Error writing header to {hosts_filename}");
                return Err(format!("Failed to write header to {hosts_filename}").into());
            }
        }
        Err(e) => {
            eprintln!("Error creating file {hosts_filename}: {e}");
            return Err(e.into());
        }
    }

    // --- Write uBlock Origin File (||domain.tld^ format) ---
    println!("\nWriting uBlock Origin file: {ublock_filename}");
    match File::create(ublock_filename) {
        Ok(file) => {
            let mut writer = BufWriter::new(file);
            let ublock_header = format!(
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
                base_api_url, // Use the original base_api_url here for the header
                source_description,
                sorted_hosts.len()
            );
            if write!(writer, "{ublock_header}").is_ok() {
                for host in &sorted_hosts {
                    if writeln!(writer, "||{host}^").is_err() {
                        eprintln!("Error writing uBlock line to {ublock_filename}");
                        return Err(format!("Failed to write to {ublock_filename}").into());
                    }
                }
                if writer.flush().is_err() {
                    eprintln!("Error flushing buffer for {ublock_filename}");
                    return Err(format!("Failed to flush {ublock_filename}").into());
                } else {
                    println!("Successfully wrote {ublock_filename}");
                }
            } else {
                eprintln!("Error writing header to {ublock_filename}");
                return Err(format!("Failed to write header to {ublock_filename}").into());
            }
        }
        Err(e) => {
            eprintln!("Error creating file {ublock_filename}: {e}");
            return Err(e.into());
        }
    }

    println!("\nScript finished successfully.");
    Ok(())
}

// --- Unit Test Module  ---
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    // --- JSON Deserialization Tests ---
    #[test]
    fn test_deserialize_api_response() {
        let json_data = r#"{"data": [{"url":"https://e1.com"},{"url":"http://e2.net"}]}"#;
        let parsed: Result<ApiResponse, _> = serde_json::from_str(json_data);
        assert!(parsed.is_ok());
        let api_response = parsed.unwrap();
        assert_eq!(api_response.data.len(), 2);
        // Compare with Some(String::from(...))
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

    // --- Host Extraction Tests ---
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
        ); // Trimmed
        assert_eq!(
            extract_and_validate_host("xn--bcher-kva.example"),
            Some("xn--bcher-kva.example".to_string())
        ); // IDN
        assert_eq!(
            extract_and_validate_host("192.168.1.1"),
            Some("192.168.1.1".to_string())
        ); // IP (treated as host by Url)
        assert_eq!(
            extract_and_validate_host("http://1.2.3.4/path"),
            Some("1.2.3.4".to_string())
        ); // IP in URL
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

    // --- Output Formatting Tests ---
    #[test]
    fn test_output_formatting() {
        let host = "h.com";
        assert_eq!(format!("0.0.0.0 {}", host), "0.0.0.0 h.com");
        assert_eq!(format!("||{}^", host), "||h.com^");
    }
}
