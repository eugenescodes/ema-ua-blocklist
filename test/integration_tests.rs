// Integration tests using mockito for API interaction

// Import items from the main binary crate.
// Replace 'ema_ua_blocklist' if your package name in Cargo.toml is different.
use ema_ua_blocklist::{fetch_all_hosts, extract_and_validate_host};

use mockito;
use std::collections::HashSet;

// create a HashSet from a slice of strings for easier comparison
fn hosts(items: &[&str]) -> HashSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[tokio::test]
async fn test_fetch_successful_pagination() {
    let mut server = mockito::Server::new_async().await;
    let base_url = server.url();
    let user_agent = "test-agent";
    let page_size = 2; 

    // Mock first page request (offset=0)
    let mock1 = server
        .mock("GET", "/?offset=0") // Mockito matches path and query string
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"data": [{"url":"http://page1.com"},{"url":"https://page1.net"}]}"#)
        .create_async()
        .await;

    // Mock second page request (offset=2)
    let mock2 = server
        .mock("GET", "/?offset=2")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"data": [{"url":"page2.org"},{"url":" ftp://ignored.com "}]}"#) // Includes one to be filtered by extract_and_validate_host
        .create_async()
        .await;

    let mock3 = server
        .mock("GET", "/?offset=4")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"data": []}"#)
        .create_async()
        .await;

    // Call the function under test using the mock server's URL
    let result = fetch_all_hosts(&base_url, user_agent, page_size).await;

    mock1.assert_async().await;
    mock2.assert_async().await;
    mock3.assert_async().await;

    assert!(result.is_ok());
    let expected_hosts = hosts(&["page1.com", "page1.net", "page2.org"]);
    assert_eq!(result.unwrap(), expected_hosts);
}

#[tokio::test]
async fn test_fetch_empty_first_page() {
    let mut server = mockito::Server::new_async().await;
    let base_url = server.url();
    let user_agent = "test-agent";
    let page_size = 10;

    // Mock the first page request (offset=0) returning empty data
    let mock = server
        .mock("GET", "/?offset=0")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"data": []}"#)
        .create_async()
        .await;

    // Call the function under test
    let result = fetch_all_hosts(&base_url, user_agent, page_size).await;

    // Assert the mock was called
    mock.assert_async().await;
    // Assert the result is Ok
    assert!(result.is_ok());
    // Assert the returned HashSet is empty
    assert!(result.unwrap().is_empty());
}

#[tokio::test]
async fn test_fetch_api_error_status() {
    let mut server = mockito::Server::new_async().await;
    let base_url = server.url();
    let user_agent = "test-agent";
    let page_size = 10;

    // Mock the API request returning a 500 Internal Server Error
    let mock = server
        .mock("GET", "/?offset=0")
        .with_status(500)
        .with_body("Internal Server Error") // Body might not be JSON in this case
        .create_async()
        .await;

    // Call the function under test
    let result = fetch_all_hosts(&base_url, user_agent, page_size).await;

    // Assert the mock was called
    mock.assert_async().await;
    // Assert the result is an error
    assert!(result.is_err());
    // Check the error message content
    let error_message = result.err().unwrap().to_string();
    assert!(error_message.contains("Error: Failed to fetch API (Status: 500"));
    assert!(error_message.contains(&format!("URL: {}/?offset=0", base_url))); // Check URL is part of the error
}

#[tokio::test]
async fn test_fetch_invalid_json_response() {
    let mut server = mockito::Server::new_async().await;
    let base_url = server.url();
    let user_agent = "test-agent";
    let page_size = 10;

    // Mock the API request returning status 200 but malformed JSON
    let mock = server
        .mock("GET", "/?offset=0")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"data": [ {"url": } ]}"#) // Malformed JSON
        .create_async()
        .await;

    // Call the function under test
    let result = fetch_all_hosts(&base_url, user_agent, page_size).await;

    // Assert the mock was called
    mock.assert_async().await;
    // Assert the result is an error
    assert!(result.is_err());
    // Check the error message content for JSON parsing failure
    let error_message = result.err().unwrap().to_string();
    assert!(error_message.contains("Error: Failed to parse JSON response"));
    assert!(error_message.contains("expected value at line 1 column"));
}

#[tokio::test]
async fn test_fetch_network_error() {
    let base_url = "http://non-existent-domain-for-rust-test.local";
    let user_agent = "test-agent";
    let page_size = 10;

    let result = fetch_all_hosts(base_url, user_agent, page_size).await;

    assert!(result.is_err());
    let error_message = result.err().unwrap().to_string();
    assert!(error_message.contains("Error: Network request failed"));
    assert!(error_message.contains(base_url));
}

#[tokio::test]
async fn test_fetch_stops_on_short_page() {
    let mut server = mockito::Server::new_async().await;
    let base_url = server.url();
    let user_agent = "test-agent";
    let page_size = 5; // Set page size to 5

    // Mock the first page request (offset=0) returning fewer items than page_size
    let mock1 = server
        .mock("GET", "/?offset=0")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"data": [{"url":"http://item1.com"},{"url":"item2.net"}]}"#) // Only 2 items returned
        .create_async()
        .await;


    let result = fetch_all_hosts(&base_url, user_agent, page_size).await;

    mock1.assert_async().await;

    assert!(result.is_ok());
    let expected_hosts = hosts(&["item1.com", "item2.net"]);
    assert_eq!(result.unwrap(), expected_hosts);
}