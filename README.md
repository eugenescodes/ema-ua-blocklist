# ema-ua-blocklist

Generate DNS blocklists from the official EMA (Association of Payment System
Members of Ukraine) blacklist of fraudulent and phishing domains.

> [!NOTE]
> Data comes from the public EMA API:
> `https://www.ema.com.ua/wp-json/api/blacklist-query`

> [!TIP]
> Ready-to-use URLs for Pi-hole, hosts files and ad blockers:
>
> - hosts format:
>   `https://raw.githubusercontent.com/eugenescodes/ema-ua-blocklist/refs/heads/main/hosts_ema.txt`
> - uBlock format:
>   `https://raw.githubusercontent.com/eugenescodes/ema-ua-blocklist/refs/heads/main/hosts_ema_ublock.txt`

## Overview

Fetches the EMA blacklist, extracts every unique hostname, filters the source
domain out, and writes two ready-to-consume list files:

| File | Format | Use with |
| --- | --- | --- |
| `hosts_ema.txt` | `0.0.0.0 domain.tld` | `/etc/hosts`, Pi-hole, DNS-level blocking |
| `hosts_ema_ublock.txt` | `\|\|domain.tld^` | uBlock Origin, AdGuard |

This project is hostname-oriented: it converts URL entries to their hostnames,
does not preserve URL paths, and excludes IP addresses from its output. It does
not generate a firewall or IP-address blocklist.

### Sources

| Source | Description |
| --- | --- |
| [ema.com.ua Blacklist API](https://www.ema.com.ua/wp-json/api/blacklist-query) | Domains associated with financial fraud and phishing targeting Ukrainian users |

## Features

- Pulls data directly from the official EMA API
- Handles API pagination automatically
- Retries transient network errors, rate limits and server errors with bounded
  exponential backoff, jitter, and support for the server's `Retry-After` header
- Extracts and validates hostnames from URLs
- Excludes IP addresses from hostname blocklists
- Handles multiple whitespace-separated URLs in one API entry and removes
  zero-width characters before parsing
- Rejects non-HTTP/HTTPS entries, malformed DNS hostnames, and the source domain
  including its subdomains
- Normalizes hostnames to lowercase and deduplicates across all pages
- Writes deterministic, alphabetically sorted output
- Adds an informative header (timestamp, source, entry count) to both files
- Stages complete output files before replacing the previous generated files,
  and recovers or rolls back interrupted multi-file replacement on the next run
- Prevents concurrent generator runs from writing into the same output directory
- Fails rather than publishing empty lists, and validates generated files before
  the scheduled workflow proposes them in a pull request
- Uses CI-gated pull requests for automated publication

## Automated updates

GitHub Actions refreshes the lists every 6 hours and opens or updates a pull
request. CI validates the generated files and runs on the update commit; the PR
is left open for review and merge. The workflow does not push directly to
`main` or enable auto-merge.

To enable automated PR creation, allow GitHub Actions to create pull requests in
the repository's Actions settings. Protect `main` by requiring a pull request
and the `build` status check before merging.

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
new unique hosts and IPs, running totals); IP addresses are reported but not
written to an output file.

### Option 2 — Docker

```bash
docker build -t ema-ua-blocklist .
```

Check the image version without making a request to the EMA API:

```bash
docker run --rm ema-ua-blocklist --version
```

```bash
# Linux / macOS
docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges:true \
  --user "$(id -u):$(id -g)" -v "$(pwd)":/output ema-ua-blocklist

# Windows (PowerShell)
docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges:true `
  -v "${PWD}:/output" ema-ua-blocklist
```

> [!NOTE]
> The container runs as an unprivileged user and writes its output to `/output`.
> The examples also make the container root filesystem read-only, drop Linux
> capabilities, and prevent privilege escalation; the mounted output directory
> remains writable.
> On Linux and macOS, pass your host UID/GID as shown above so the generated
> files are owned by your user. Mounting your current directory there makes the
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

```text
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
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
```

### Tests

```bash
cargo test --locked
```

### Validate generated lists

GitHub Actions runs `--validate` against the committed lists. You can also use
`--check-freshness` locally to compare generated and committed lists:

```bash
cargo run --release --locked -- --validate .
cargo run --release --locked -- --check-freshness generated-hosts .
```

`--validate` checks list formats, hostnames, counts, sorting, uniqueness, and
consistency between output files. `--check-freshness` also verifies that the
generated and committed lists are no more than 24 hours old.

## Contributing

1. Open a
   [GitHub issue](https://github.com/eugenescodes/ema-ua-blocklist/issues) to
   discuss major changes before starting work.
2. Fork the repo and create a feature branch:
   `git checkout -b feature/your-feature`
3. Make your changes and run tests: `cargo test --locked`
4. Commit with a clear message and push to your fork.
5. Open a Pull Request targeting `main` with a description of what and why.

## License

[GNU GPL v3.0](LICENSE)

## Acknowledgments

- [Ukrainian Interbank Association of Payment Systems Members EMA](https://ema.com.ua)
  for publishing the blacklist data

---

## Disclaimer

This tool automates fetching and formatting data from EMA. The accuracy and
completeness of the blocklist depend entirely on the data provided by EMA. Use
the generated blocklists at your own risk — blocking domains can occasionally
interfere with legitimate websites or services.

> This tool is not affiliated with EMA.
