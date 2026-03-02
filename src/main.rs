use chrono::Utc;
use ema_ua_blocklist::{FetchError, fetch_all_hosts};
use std::fs::File;
use std::io::{BufWriter, Write};

const BASE_API_URL: &str = "https://www.ema.com.ua/wp-json/api/blacklist-query";
const USER_AGENT: &str = "ema scraper bot (github.com/eugenescodes/ema-ua-blocklist)";
const PAGE_SIZE: usize = 12;
const REPO_NAME: &str = "ema-ua-blocklist";
const LICENSE_FILE: &str = "LICENSE";
const HOSTS_FILENAME: &str = "hosts_ema.txt";
const UBLOCK_FILENAME: &str = "hosts_ema_ublock.txt";

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

    let all_hosts = fetch_all_hosts(BASE_API_URL, USER_AGENT, PAGE_SIZE).await?;

    println!("Finished fetching data.");
    println!("\nTotal unique hosts collected: {}", all_hosts.len());

    if all_hosts.is_empty() {
        println!("No hosts were collected. Skipping file generation.");
        return Ok(());
    }

    let mut sorted_hosts: Vec<String> = all_hosts.into_iter().collect();
    sorted_hosts.sort_unstable();

    let _ = write_hosts_file(&sorted_hosts);
    let _ = write_ublock_file(&sorted_hosts);

    println!("\nScript finished successfully.");
    Ok(())
}
