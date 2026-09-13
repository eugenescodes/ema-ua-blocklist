# ema-ua-blocklist

Generate DNS blocklists from the official EMA (Association of Payment System Members of Ukraine) blacklist of fraudulent and phishing domains.

> [!NOTE]
> Data comes from the public EMA API: `https://www.ema.com.ua/wp-json/api/blacklist-query`

> [!TIP]
> Ready-to-use URLs for Pi-hole, hosts files and ad blockers:
> - hosts format: `https://raw.githubusercontent.com/eugenescodes/ema-ua-blocklist/refs/heads/main/hosts_ema.txt`
> - uBlock format: `https://raw.githubusercontent.com/eugenescodes/ema-ua-blocklist/refs/heads/main/hosts_ema_ublock.txt`

## Overview

Fetches the EMA blacklist, extracts every unique hostname, filters the source
domain out, and writes two ready-to-consume blocklist files:

| File | Format | Use with |
| --- | --- | --- |
| `hosts_ema.txt` | `0.0.0.0 domain.tld` | `/etc/hosts`, Pi-hole, DNS-level blocking |
| `hosts_ema_ublock.txt` | `\|\|domain.tld^` | uBlock Origin, AdGuard |

The lists are refreshed automatically by GitHub Actions every 6 hours, so the
files committed in this repository are always up to date.

### Sources

| Source | Description |
| --- | --- |
| [ema.com.ua Blacklist API](https://www.ema.com.ua/wp-json/api/blacklist-query) | Domains associated with financial fraud and phishing targeting Ukrainian users |

## Features

- Pulls data directly from the official EMA API
- Handles API pagination automatically
- Extracts and validates hostnames from URLs
- Rejects non-HTTP/HTTPS entries, schemeless junk and the source domain itself
- Normalizes hostnames to lowercase and deduplicates across all pages
- Writes deterministic, alphabetically sorted output
- Adds an informative header (timestamp, source, entry count) to both files

## Usage

### Option 1 — Cargo (recommended)

```bash
# Install Rust if not already installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and run
git clone https://github.com/eugenescodes/ema-ua-blocklist
cd ema-ua-blocklist
cargo run --release
```

After running, `hosts_ema.txt` and `hosts_ema_ublock.txt` are created in the
current directory. Progress is printed while fetching (offset, items per page,
new unique hosts, running total).

### Option 2 — Docker

```bash
docker build -t ema-ua-blocklist .
```

```bash
# Linux / macOS
docker run --rm -v "$(pwd)":/output ema-ua-blocklist

# Windows (PowerShell)
docker run --rm -v "${PWD}:/output" ema-ua-blocklist
```

> [!NOTE]
> The binary writes its output to its working directory, which is `/output`
> inside the container. Mounting your current directory there makes the
> generated files appear directly on the host — no manual copying needed.
>
> On SELinux systems (Fedora, RHEL, CentOS), add the `:Z` suffix to the volume
> so the bind mount is relabeled for the container: `-v "$(pwd)":/output:Z`.

## Integration

### Pi-hole / hosts file

Point Pi-hole at the raw URL, or download the list and use it locally:

```bash
curl -o hosts_ema.txt https://raw.githubusercontent.com/eugenescodes/ema-ua-blocklist/refs/heads/main/hosts_ema.txt
```

> [!WARNING]
> Editing the system `hosts` file directly requires administrator privileges
> (`sudo`) and can break name resolution if done carelessly. Prefer a
> dedicated tool such as Pi-hole or a local DNS blocker.

### uBlock Origin / AdGuard

Add the raw URL as a custom filter list:

```
https://raw.githubusercontent.com/eugenescodes/ema-ua-blocklist/refs/heads/main/hosts_ema_ublock.txt
```

The generated file includes an `! Expires: 1 day` hint, so the extension
refreshes it automatically.

## Development

This project uses [Cargo](https://doc.rust-lang.org/cargo/) for dependency
management and [Clippy](https://github.com/rust-lang/rust-clippy) +
[rustfmt](https://github.com/rust-lang/rustfmt) for linting and formatting.

### Prerequisites

Install Rust via [rustup](https://rustup.rs/):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Lint and format

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
```

### Tests

```bash
cargo test --verbose
cargo test --doc
```

## Contributing

1. Open a [GitHub issue](https://github.com/eugenescodes/ema-ua-blocklist/issues) to discuss major changes before starting work.
2. Fork the repo and create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes and run tests: `cargo test --verbose`
4. Commit with a clear message and push to your fork.
5. Open a Pull Request targeting `main` with a description of what and why.

## License

[GNU GPL v3.0](LICENSE)

## Acknowledgments

- [Ukrainian Interbank Association of Payment Systems Members EMA](https://ema.com.ua) for publishing the blacklist data

---

## Disclaimer

This tool automates fetching and formatting data from EMA. The accuracy and
completeness of the blocklist depend entirely on the data provided by EMA. Use
the generated blocklists at your own risk — blocking domains can occasionally
interfere with legitimate websites or services.

> This tool is not affiliated with EMA.
