# Blacklist Generator from ema.com.ua

A simple tool to fetch the official EMA (Association of Payment System Members of Ukraine) blacklist, extract potentially harmful hostnames, and generate blocklist files suitable for DNS-level blocking (e.g., Pi-hole, hosts file) and ad blockers (e.g., uBlock Origin, AdGuard).

## Features

* Fetches data directly from the official EMA API.
* Automatically handles API pagination.
* Extracts and validates hostnames from URLs.
* Filters out the source domain (`ema.com.ua`) and invalid entries (e.g., non-HTTP/HTTPS URLs).
* Generates blocklists in two common formats:
  * `hosts_ema.txt` (for `/etc/hosts`, Pi-hole, etc.)
  * `hosts_ema_ublock.txt` (for uBlock Origin, AdGuard, etc.)
* Includes informative headers in the generated files (timestamp, source, entry count).

## Data Source

Data is obtained from the public API provided by the Association of Payment System Members of Ukraine (EMA):
`https://www.ema.com.ua/wp-json/api/blacklist-query`

This list typically contains domains associated with financial fraud or phishing attempts targeting Ukrainian users.

## Output File Formats

* **`hosts_ema.txt`**: Contains entries in the `0.0.0.0 domain.tld` format. This file can be used directly as a source for Pi-hole or added to the system's `hosts` file (e.g., `/etc/hosts` on Linux/macOS) for DNS-level domain blocking.
  * **Warning:** Be cautious when modifying your system's `hosts` file. Administrator privileges (`sudo`) are usually required.
* **`hosts_ema_ublock.txt`**: Contains entries in the `||domain.tld^` format. This file can be added as a custom filter list in browser extensions like uBlock Origin or AdGuard.

## Usage

The script will fetch the latest data from the EMA API and generate (or overwrite) the `hosts_ema.txt` and `hosts_ema_ublock.txt` files in the current directory.

During execution, the script provides detailed progress output, including:

* The current offset of items being fetched from the API.
* The number of items fetched in each request.
* The number of new unique hosts added from each batch.
* The total unique hosts collected so far.

This output helps users understand the data fetching progress and the difference between total items fetched and unique hosts collected.

link to import uBlock Origin

```bash
https://raw.githubusercontent.com/eugenescodes/ema-ua-blocklist/refs/heads/main/hosts_ema_ublock.txt
```

## Acknowledgments

Thanks for [Ukrainian Interbank Association of Payment Systems Members EMA] (<https://ema.com.ua>) for this data

## License

This project is licensed under the terms of the GNU General Public License v3.0 license. See the `LICENSE` file for details.

## Disclaimer

This tool automates the process of fetching and formatting data from EMA. The accuracy and completeness of the blocklist depend entirely on the data provided by EMA. Use the generated blocklists at your own risk. Blocking domains can sometimes interfere with legitimate websites or services.
