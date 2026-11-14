use chrono::Utc;
use ema_ua_blocklist::{FetchError, SOURCE_DOMAIN_1, fetch_all_entries};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const BASE_API_URL: &str = "https://www.ema.com.ua/wp-json/api/blacklist-query";
const USER_AGENT: &str = "ema scraper bot (github.com/eugenescodes/ema-ua-blocklist)";
const PAGE_SIZE: usize = 1_000;
const REPO_NAME: &str = "ema-ua-blocklist";
const LICENSE_FILE: &str = "LICENSE";
const HOSTS_FILENAME: &str = "hosts_ema.txt";
const UBLOCK_FILENAME: &str = "hosts_ema_ublock.txt";
const TRANSACTION_JOURNAL: &str = ".ema-ua-blocklist.transaction.json";
const TRANSACTION_COMMIT_MARKER: &str = ".ema-ua-blocklist.transaction.committed";
const OUTPUT_LOCK: &str = ".ema-ua-blocklist.lock";

struct HeaderMeta {
    homepage_url: String,
    license_url: String,
    source_description: &'static str,
    timestamp_str: String,
}

impl HeaderMeta {
    fn now() -> Self {
        Self {
            homepage_url: format!("https://github.com/eugenescodes/{REPO_NAME}"),
            license_url: format!(
                "https://github.com/eugenescodes/{REPO_NAME}/blob/main/{LICENSE_FILE}"
            ),
            source_description: "ema.com.ua Blacklist API",
            timestamp_str: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        }
    }
}

struct StagedFile {
    destination: PathBuf,
    temporary: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Serialize)]
struct TransactionFile {
    destination: PathBuf,
    backup: Option<PathBuf>,
    temporary: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
struct TransactionJournal {
    files: Vec<TransactionFile>,
}

struct OutputLock {
    _file: File,
}

impl OutputLock {
    fn acquire(directory: &Path) -> Result<Self, FetchError> {
        let lock_path = directory.join(OUTPUT_LOCK);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        file.lock()?;
        Ok(Self { _file: file })
    }
}

impl StagedFile {
    fn commit(&mut self) -> Result<(), FetchError> {
        let temporary = self.temporary.as_ref().ok_or_else(|| {
            FetchError::Unexpected("Staged output file has already been committed".to_string())
        })?;
        fs::rename(temporary, &self.destination)?;
        sync_parent_directory(&self.destination)?;
        self.temporary = None;
        println!("Successfully wrote {}", self.destination.display());
        Ok(())
    }
}

fn create_backup_file(destination: &Path) -> Result<PathBuf, FetchError> {
    let parent = normalized_parent(destination);
    let file_name = destination.file_name().ok_or_else(|| {
        FetchError::Unexpected(format!(
            "Output path has no file name: {}",
            destination.display()
        ))
    })?;

    for attempt in 0..100 {
        let backup_path = parent.join(format!(
            ".{}.backup.{}.{}.tmp",
            file_name.to_string_lossy(),
            std::process::id(),
            attempt
        ));
        let backup_file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&backup_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        };
        drop(backup_file);

        let backup_result = (|| -> Result<(), std::io::Error> {
            fs::copy(destination, &backup_path)?;
            fs::set_permissions(&backup_path, fs::metadata(destination)?.permissions())?;
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&backup_path)?
                .sync_all()?;
            Ok(())
        })();

        if let Err(error) = backup_result {
            if let Err(cleanup_error) = fs::remove_file(&backup_path) {
                eprintln!(
                    "Failed to remove incomplete backup {}: {cleanup_error}",
                    backup_path.display()
                );
            }
            return Err(error.into());
        }

        sync_parent_directory(&backup_path)?;
        return Ok(backup_path);
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("Could not create backup path for {}", destination.display()),
    )
    .into())
}

fn transaction_journal_path(directory: &Path) -> PathBuf {
    directory.join(TRANSACTION_JOURNAL)
}

fn transaction_commit_marker_path(journal_path: &Path) -> PathBuf {
    journal_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join(TRANSACTION_COMMIT_MARKER)
}

fn normalized_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn sync_parent_directory(path: &Path) -> Result<(), FetchError> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;

    Ok(())
}

fn write_transaction_journal(
    journal_path: &Path,
    journal: &TransactionJournal,
) -> Result<(), FetchError> {
    let parent = journal_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = journal_path.file_name().ok_or_else(|| {
        FetchError::Unexpected(format!(
            "Transaction journal has no file name: {}",
            journal_path.display()
        ))
    })?;

    for attempt in 0..100 {
        let temporary_path = parent.join(format!(
            ".{}.{}.{}.tmp",
            file_name.to_string_lossy(),
            std::process::id(),
            attempt
        ));
        let file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        };

        let write_result = (|| -> Result<(), FetchError> {
            let mut writer = BufWriter::new(file);
            serde_json::to_writer(&mut writer, journal).map_err(|error| {
                FetchError::Unexpected(format!("Could not serialize transaction journal: {error}"))
            })?;
            writer.write_all(b"\n")?;
            writer.flush()?;
            #[cfg(unix)]
            fs::set_permissions(&temporary_path, fs::Permissions::from_mode(0o600))?;
            writer.get_ref().sync_all()?;
            fs::rename(&temporary_path, journal_path)?;
            sync_parent_directory(journal_path)?;
            fs::set_permissions(journal_path, fs::Permissions::from_mode(0o600))?;
            Ok(())
        })();

        if write_result.is_err()
            && let Err(error) = fs::remove_file(&temporary_path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!(
                "Failed to clean temporary journal {}: {error}",
                temporary_path.display()
            );
        }
        return write_result;
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "Could not create a unique temporary transaction journal",
    )
    .into())
}

fn write_commit_marker(marker_path: &Path) -> Result<(), FetchError> {
    let (temporary, file) = create_staging_file(marker_path)?;
    let write_result = (|| -> Result<(), FetchError> {
        let mut writer = BufWriter::new(file);
        writer.write_all(b"committed\n")?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        fs::rename(&temporary, marker_path)?;
        sync_parent_directory(marker_path)
    })();

    if write_result.is_err()
        && let Err(error) = fs::remove_file(&temporary)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!(
            "Failed to clean temporary commit marker {}: {error}",
            temporary.display()
        );
    }
    write_result
}

fn validate_transaction_journal(
    journal_path: &Path,
    journal: &TransactionJournal,
) -> Result<(), FetchError> {
    if journal.files.is_empty() || journal.files.len() > 2 {
        return Err(FetchError::Unexpected(
            "Transaction journal contains an invalid number of files".to_string(),
        ));
    }

    let parent = journal_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut destinations = HashSet::new();
    for file in &journal.files {
        if normalized_parent(&file.destination) != parent
            || ![HOSTS_FILENAME, UBLOCK_FILENAME].iter().any(|name| {
                file.destination
                    .file_name()
                    .is_some_and(|value| value == *name)
            })
            || !destinations.insert(file.destination.clone())
        {
            return Err(FetchError::Unexpected(
                "Transaction journal contains an unexpected destination".to_string(),
            ));
        }

        for auxiliary in file.backup.iter().chain(std::iter::once(&file.temporary)) {
            let auxiliary_name = auxiliary.file_name().and_then(|name| name.to_str());
            let destination_name = file
                .destination
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            let allowed_prefix = format!(".{destination_name}.");
            if normalized_parent(auxiliary) != parent
                || !auxiliary_name.is_some_and(|name| {
                    (name.starts_with(&allowed_prefix)
                        || name.starts_with("..ema-ua-blocklist.transaction."))
                        && name.ends_with(".tmp")
                })
            {
                return Err(FetchError::Unexpected(
                    "Transaction journal contains an invalid temporary path".to_string(),
                ));
            }
        }
    }

    Ok(())
}

fn recover_transaction(journal_path: &Path) -> Result<(), FetchError> {
    let mut contents = String::new();
    let mut journal_file = match File::open(journal_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let directory = normalized_parent(journal_path);
            remove_if_exists(&transaction_commit_marker_path(journal_path))?;
            prune_old_orphaned_backups(directory)?;
            cleanup_orphaned_transaction_files(directory)?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    journal_file.read_to_string(&mut contents)?;
    let journal: TransactionJournal = serde_json::from_str(&contents).map_err(|error| {
        FetchError::Unexpected(format!(
            "Could not parse transaction journal {}: {error}",
            journal_path.display()
        ))
    })?;
    validate_transaction_journal(journal_path, &journal)?;

    let mut destinations = journal
        .files
        .iter()
        .map(|file| file.destination.file_name().map(PathBuf::from))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            FetchError::Unexpected("Transaction destination has no file name".to_string())
        })?;
    destinations.sort();
    let expected = [
        PathBuf::from(HOSTS_FILENAME),
        PathBuf::from(UBLOCK_FILENAME),
    ];
    if destinations != expected {
        return Err(FetchError::Unexpected(
            "Transaction journal does not describe both generated blocklists".to_string(),
        ));
    }

    let commit_marker = transaction_commit_marker_path(journal_path);
    match read_commit_marker(&commit_marker)? {
        Ok(_) => {
            for file in &journal.files {
                remove_if_exists(&file.temporary)?;
            }
            for backup in journal.files.iter().filter_map(|file| file.backup.as_ref()) {
                if backup.exists() {
                    remove_if_exists(backup)?;
                }
            }
            remove_if_exists(&commit_marker)?;
            sync_parent_directory(journal_path)?;
            remove_if_exists(journal_path)?;
            sync_parent_directory(journal_path)?;
            prune_old_orphaned_backups(normalized_parent(journal_path))?;
            cleanup_orphaned_transaction_files(normalized_parent(journal_path))?;
            return Ok(());
        }
        Err(()) => {
            for file in journal.files.iter().rev() {
                if let Some(backup) = &file.backup {
                    if !backup.exists() && file.destination.exists() {
                        // This backup was already restored in an earlier recovery attempt.
                    } else {
                        restore_backup(backup, &file.destination)?;
                    }
                } else if let Err(error) = fs::remove_file(&file.destination)
                    && error.kind() != std::io::ErrorKind::NotFound
                {
                    return Err(error.into());
                }
                remove_if_exists(&file.temporary)?;
            }
        }
    }

    for backup in journal.files.iter().filter_map(|file| file.backup.as_ref()) {
        if backup.exists() {
            remove_if_exists(backup)?;
        }
    }
    remove_if_exists(&commit_marker)?;
    sync_parent_directory(journal_path)?;
    remove_if_exists(journal_path)?;
    sync_parent_directory(journal_path)?;
    prune_old_orphaned_backups(normalized_parent(journal_path))?;
    cleanup_orphaned_transaction_files(normalized_parent(journal_path))?;
    Ok(())
}

fn read_commit_marker(marker_path: &Path) -> Result<Result<(), ()>, FetchError> {
    let mut contents = String::new();
    let mut file = match File::open(marker_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Err(())),
        Err(error) => return Err(error.into()),
    };
    file.read_to_string(&mut contents)?;
    if contents == "committed\n" {
        Ok(Ok(()))
    } else {
        Err(FetchError::Unexpected(format!(
            "Invalid transaction commit marker: {}",
            marker_path.display()
        )))
    }
}

fn cleanup_orphaned_transaction_files(directory: &Path) -> Result<(), FetchError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let is_transaction_temporary = [
            ".hosts_ema.txt.",
            ".hosts_ema_ublock.txt.",
            "..ema-ua-blocklist.transaction.json.",
            "..ema-ua-blocklist.transaction.committed.",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix) && name.ends_with(".tmp"))
            && !name.starts_with(&format!(".{HOSTS_FILENAME}.backup."))
            && !name.starts_with(&format!(".{UBLOCK_FILENAME}.backup."));
        if is_transaction_temporary && entry.file_type()?.is_file() {
            remove_if_exists(&entry.path())?;
        }
    }
    Ok(())
}

fn prune_old_orphaned_backups(directory: &Path) -> Result<(), FetchError> {
    let cutoff = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(24 * 60 * 60))
        .unwrap_or(std::time::UNIX_EPOCH);
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let is_backup = [
            format!(".{HOSTS_FILENAME}."),
            format!(".{UBLOCK_FILENAME}."),
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix) && name.ends_with(".tmp"));
        if is_backup && entry.file_type()?.is_file() {
            let modified = entry.metadata()?.modified()?;
            if modified < cutoff {
                remove_if_exists(&entry.path())?;
            }
        }
    }
    Ok(())
}

fn remove_if_exists(path: &Path) -> Result<(), FetchError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn restore_backup(backup: &Path, destination: &Path) -> Result<(), FetchError> {
    if !backup.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Transaction backup is missing: {}", backup.display()),
        )
        .into());
    }

    let (temporary, temporary_file) = create_staging_file(destination)?;
    drop(temporary_file);
    let restore_result = (|| -> Result<(), FetchError> {
        fs::copy(backup, &temporary)?;
        fs::set_permissions(&temporary, fs::metadata(backup)?.permissions())?;
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&temporary)?
            .sync_all()?;
        fs::rename(&temporary, destination)?;
        sync_parent_directory(destination)?;
        Ok(())
    })();

    if restore_result.is_err()
        && let Err(error) = fs::remove_file(&temporary)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!(
            "Failed to clean restore staging file {}: {error}",
            temporary.display()
        );
    }
    restore_result
}

fn commit_staged_files(
    staged_files: Vec<StagedFile>,
    journal_path: &Path,
) -> Result<(), FetchError> {
    commit_staged_files_with(staged_files, journal_path, StagedFile::commit)
}

fn commit_staged_files_with<F>(
    mut staged_files: Vec<StagedFile>,
    journal_path: &Path,
    mut commit: F,
) -> Result<(), FetchError>
where
    F: FnMut(&mut StagedFile) -> Result<(), FetchError>,
{
    let mut backups = Vec::with_capacity(staged_files.len());
    for staged_file in &staged_files {
        let backup_result = if staged_file.destination.exists() {
            create_backup_file(&staged_file.destination).map(Some)
        } else {
            Ok(None)
        };
        match backup_result {
            Ok(backup) => backups.push(backup),
            Err(error) => {
                for backup in backups.iter().flatten() {
                    remove_if_exists(backup)?;
                }
                return Err(error);
            }
        };
    }

    let journal = TransactionJournal {
        files: staged_files
            .iter()
            .zip(backups)
            .map(|(staged_file, backup)| TransactionFile {
                destination: staged_file.destination.clone(),
                backup,
                temporary: staged_file
                    .temporary
                    .as_ref()
                    .expect("staged output always has a temporary path")
                    .clone(),
            })
            .collect(),
    };
    if let Err(error) = write_transaction_journal(journal_path, &journal) {
        // A directory sync can fail after the journal rename. Keep backups if the
        // journal is present so the next invocation can still recover safely.
        if !journal_path.exists() {
            for backup in journal.files.iter().filter_map(|file| file.backup.as_ref()) {
                remove_if_exists(backup)?;
            }
        }
        return Err(error);
    }

    for staged_file in &mut staged_files {
        let commit_result = commit(staged_file);
        if let Err(commit_error) = commit_result {
            return match recover_transaction(journal_path) {
                Ok(()) => Err(commit_error),
                Err(recovery_error) => Err(FetchError::Unexpected(format!(
                    "Failed to commit generated files ({commit_error}); recovery journal retained at {}: {recovery_error}",
                    journal_path.display()
                ))),
            };
        }
    }

    let marker_path = transaction_commit_marker_path(journal_path);
    write_commit_marker(&marker_path)?;
    recover_transaction(journal_path)
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if let Some(temporary) = &self.temporary
            && let Err(error) = fs::remove_file(temporary)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!(
                "Failed to remove staging file {}: {error}",
                temporary.display()
            );
        }
    }
}

fn create_staging_file(destination: &Path) -> Result<(PathBuf, File), FetchError> {
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = destination.file_name().ok_or_else(|| {
        FetchError::Unexpected(format!(
            "Output path has no file name: {}",
            destination.display()
        ))
    })?;

    for attempt in 0..100 {
        let temporary = parent.join(format!(
            ".{}.{}.{}.tmp",
            file_name.to_string_lossy(),
            std::process::id(),
            attempt
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "Could not create a unique staging file for {}",
            destination.display()
        ),
    )
    .into())
}

fn stage_blocklist(
    filename: &str,
    header: &str,
    hosts: &[String],
    prefix: &str,
    suffix: &str,
) -> Result<StagedFile, FetchError> {
    let destination = PathBuf::from(filename);
    let (temporary, file) = create_staging_file(&destination)?;
    let staged_file = StagedFile {
        destination,
        temporary: Some(temporary.clone()),
    };
    let mut writer = BufWriter::new(file);
    #[cfg(unix)]
    fs::set_permissions(
        staged_file
            .temporary
            .as_ref()
            .ok_or_else(|| FetchError::Unexpected("Missing staging path".to_string()))?,
        fs::Permissions::from_mode(0o644),
    )?;

    writer.write_all(header.as_bytes())?;
    for host in hosts {
        writeln!(writer, "{prefix}{host}{suffix}")?;
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    sync_parent_directory(&temporary)?;

    Ok(staged_file)
}

fn stage_hosts_file(hosts: &[String], meta: &HeaderMeta) -> Result<StagedFile, FetchError> {
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
        meta.source_description,
        meta.homepage_url,
        meta.license_url,
        meta.timestamp_str,
        BASE_API_URL,
        meta.source_description,
        hosts.len()
    );

    stage_blocklist(HOSTS_FILENAME, &header, hosts, "0.0.0.0 ", "")
}

fn stage_ublock_file(hosts: &[String], meta: &HeaderMeta) -> Result<StagedFile, FetchError> {
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
        meta.homepage_url,
        meta.license_url,
        meta.timestamp_str,
        BASE_API_URL,
        meta.source_description,
        hosts.len()
    );

    stage_blocklist(UBLOCK_FILENAME, &header, hosts, "||", "^")
}

fn ensure_hosts_available(hosts: &[String]) -> Result<(), FetchError> {
    if hosts.is_empty() {
        return Err(FetchError::Unexpected(
            "No hostnames were collected; refusing to generate empty domain blocklists".to_string(),
        ));
    }

    Ok(())
}

fn validate_blocklist_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return false;
    }
    let labels: Vec<_> = host.split('.').collect();
    !labels.is_empty()
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn read_blocklist_entries(
    path: &Path,
    prefix: &str,
    suffix: &str,
    count_header: &str,
) -> Result<Vec<String>, FetchError> {
    let contents = fs::read_to_string(path)?;
    let mut declared_count = None;
    let mut entries = Vec::new();

    for line in contents.lines() {
        if let Some(count) = line.strip_prefix(count_header) {
            if declared_count.is_some() {
                return Err(FetchError::Unexpected(format!(
                    "{}: multiple entry-count headers",
                    path.display()
                )));
            }
            declared_count = Some(count.parse::<usize>().map_err(|error| {
                FetchError::Unexpected(format!("{}: invalid entry count: {error}", path.display()))
            })?);
            continue;
        }

        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }

        let entry = line
            .strip_prefix(prefix)
            .and_then(|value| value.strip_suffix(suffix))
            .ok_or_else(|| {
                FetchError::Unexpected(format!(
                    "{}: malformed blocklist line {line:?}",
                    path.display()
                ))
            })?;
        if !validate_blocklist_host(entry)
            || entry == SOURCE_DOMAIN_1
            || entry.ends_with(&format!(".{SOURCE_DOMAIN_1}"))
        {
            return Err(FetchError::Unexpected(format!(
                "{}: invalid or disallowed host {entry:?}",
                path.display()
            )));
        }
        entries.push(entry.to_string());
    }

    let declared_count = declared_count.ok_or_else(|| {
        FetchError::Unexpected(format!("{}: missing entry-count header", path.display()))
    })?;
    if entries.is_empty() || entries.len() != declared_count {
        return Err(FetchError::Unexpected(format!(
            "{}: expected {declared_count} entries but found {}",
            path.display(),
            entries.len()
        )));
    }
    if entries.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(FetchError::Unexpected(format!(
            "{}: entries must be unique and sorted",
            path.display()
        )));
    }

    Ok(entries)
}

fn validate_blocklists(directory: &Path) -> Result<usize, FetchError> {
    let hosts = read_blocklist_entries(
        &directory.join(HOSTS_FILENAME),
        "0.0.0.0 ",
        "",
        "# Number of entries: ",
    )?;
    let ublock = read_blocklist_entries(
        &directory.join(UBLOCK_FILENAME),
        "||",
        "^",
        "! Number of entries: ",
    )?;
    if hosts != ublock {
        return Err(FetchError::Unexpected(
            "hosts and uBlock blocklists contain different entries".to_string(),
        ));
    }
    Ok(hosts.len())
}

fn read_blocklist_timestamp(path: &Path) -> Result<chrono::DateTime<Utc>, FetchError> {
    let contents = fs::read_to_string(path)?;
    let marker = if path.file_name().is_some_and(|name| name == UBLOCK_FILENAME) {
        "! Last modified: "
    } else {
        "# Last modified: "
    };
    let mut timestamps = contents
        .lines()
        .filter_map(|line| line.strip_prefix(marker));
    let timestamp = timestamps.next().ok_or_else(|| {
        FetchError::Unexpected(format!(
            "{}: missing Last modified timestamp",
            path.display()
        ))
    })?;
    if timestamps.next().is_some() {
        return Err(FetchError::Unexpected(format!(
            "{}: multiple Last modified timestamps",
            path.display()
        )));
    }
    let parsed = chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S UTC")
        .map_err(|error| {
            FetchError::Unexpected(format!(
                "{}: invalid Last modified timestamp: {error}",
                path.display()
            ))
        })?;
    Ok(parsed.and_utc())
}

fn check_blocklist_freshness(
    generated_directory: &Path,
    committed_directory: &Path,
    max_age: chrono::Duration,
) -> Result<(), FetchError> {
    validate_blocklists(generated_directory)?;
    validate_blocklists(committed_directory)?;

    let generated_hosts = read_blocklist_timestamp(&generated_directory.join(HOSTS_FILENAME))?;
    let generated_ublock = read_blocklist_timestamp(&generated_directory.join(UBLOCK_FILENAME))?;
    let committed_hosts = read_blocklist_timestamp(&committed_directory.join(HOSTS_FILENAME))?;
    let committed_ublock = read_blocklist_timestamp(&committed_directory.join(UBLOCK_FILENAME))?;
    if generated_hosts != generated_ublock || committed_hosts != committed_ublock {
        return Err(FetchError::Unexpected(
            "Blocklist files have inconsistent generation timestamps".to_string(),
        ));
    }

    let now = Utc::now();
    for (name, timestamp) in [
        ("generated artifact", generated_hosts),
        ("committed blocklists", committed_hosts),
    ] {
        let age = now.signed_duration_since(timestamp);
        if age < chrono::Duration::minutes(-5) {
            return Err(FetchError::Unexpected(format!(
                "{name} timestamp is in the future"
            )));
        }
        if age > max_age {
            return Err(FetchError::Unexpected(format!(
                "{name} are stale ({age} old; maximum is {max_age})"
            )));
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), FetchError> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--version") => {
            if args.next().is_some() {
                return Err(FetchError::Unexpected(
                    "--version does not accept additional arguments".to_string(),
                ));
            }
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some("--validate") => {
            let directory = args.next().ok_or_else(|| {
                FetchError::Unexpected("Usage: --validate <directory>".to_string())
            })?;
            if args.next().is_some() {
                return Err(FetchError::Unexpected(
                    "Usage: --validate <directory>".to_string(),
                ));
            }
            let count = validate_blocklists(Path::new(&directory))?;
            println!("Validated {count} blocklist entries.");
            return Ok(());
        }
        Some("--check-freshness") => {
            let generated_directory = args.next().ok_or_else(|| {
                FetchError::Unexpected(
                    "Usage: --check-freshness <generated-directory> <committed-directory>"
                        .to_string(),
                )
            })?;
            let committed_directory = args.next().ok_or_else(|| {
                FetchError::Unexpected(
                    "Usage: --check-freshness <generated-directory> <committed-directory>"
                        .to_string(),
                )
            })?;
            if args.next().is_some() {
                return Err(FetchError::Unexpected(
                    "Usage: --check-freshness <generated-directory> <committed-directory>"
                        .to_string(),
                ));
            }
            check_blocklist_freshness(
                Path::new(&generated_directory),
                Path::new(&committed_directory),
                chrono::Duration::hours(24),
            )?;
            println!("Generated and committed blocklists are valid and fresh.");
            return Ok(());
        }
        Some(argument) => {
            return Err(FetchError::Unexpected(format!(
                "Unknown argument {argument:?}. Use --version, --validate, or --check-freshness."
            )));
        }
        None => {}
    }

    let _output_lock = OutputLock::acquire(Path::new("."))?;
    let journal_path = transaction_journal_path(Path::new("."));
    recover_transaction(&journal_path)?;

    println!("Starting data fetch from EMA API...");

    let all_entries = fetch_all_entries(BASE_API_URL, USER_AGENT, PAGE_SIZE).await?;

    println!("Finished fetching data.");
    let skipped_ip_count = all_entries.ips.len();
    println!(
        "\nTotal unique hostnames collected: {}, IP addresses skipped: {}",
        all_entries.hosts.len(),
        skipped_ip_count
    );

    let mut sorted_hosts: Vec<String> = all_entries.hosts.into_iter().collect();
    ensure_hosts_available(&sorted_hosts)?;

    sorted_hosts.sort_unstable();

    let meta = HeaderMeta::now();
    let staged_files = [
        stage_hosts_file(&sorted_hosts, &meta)?,
        stage_ublock_file(&sorted_hosts, &meta)?,
    ];
    commit_staged_files(staged_files.into(), &journal_path)?;

    println!("\nScript finished successfully.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn refuses_to_generate_blocklists_without_hostnames() {
        let error = ensure_hosts_available(&[]).unwrap_err();
        assert!(matches!(
            error,
            FetchError::Unexpected(message)
                if message == "No hostnames were collected; refusing to generate empty domain blocklists"
        ));
    }

    #[test]
    fn allows_nonempty_domain_blocklists() {
        assert!(ensure_hosts_available(&["example.com".to_string()]).is_ok());
    }

    #[test]
    fn staged_write_preserves_old_file_until_complete_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("blocklist.txt");
        fs::write(&destination, "old complete contents\n").unwrap();

        let mut staged = stage_blocklist(
            destination.to_str().unwrap(),
            "header\n",
            &["example.com".to_string()],
            "0.0.0.0 ",
            "",
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            "old complete contents\n"
        );
        staged.commit().unwrap();
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            "header\n0.0.0.0 example.com\n"
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn transaction_recovery_rolls_back_partial_replacement_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let journal_path = transaction_journal_path(directory.path());
        let first_destination = directory.path().join(HOSTS_FILENAME);
        let second_destination = directory.path().join(UBLOCK_FILENAME);
        fs::write(&first_destination, "new first contents\n").unwrap();
        fs::write(&second_destination, "old second contents\n").unwrap();

        let first_backup = directory.path().join(".hosts_ema.txt.backup.tmp");
        let second_backup = directory.path().join(".hosts_ema_ublock.txt.backup.tmp");
        let first_temporary = directory.path().join(".hosts_ema.txt.staged.tmp");
        let second_temporary = directory.path().join(".hosts_ema_ublock.txt.staged.tmp");
        fs::write(&second_destination, "old second contents\n").unwrap();
        fs::write(&first_backup, "old first contents\n").unwrap();
        fs::write(&second_backup, "old second contents\n").unwrap();
        fs::write(&first_temporary, "new first contents\n").unwrap();
        fs::write(&second_temporary, "new second contents\n").unwrap();
        let journal = TransactionJournal {
            files: vec![
                TransactionFile {
                    destination: first_destination.clone(),
                    backup: Some(first_backup.clone()),
                    temporary: first_temporary.clone(),
                },
                TransactionFile {
                    destination: second_destination.clone(),
                    backup: Some(second_backup.clone()),
                    temporary: second_temporary.clone(),
                },
            ],
        };
        write_transaction_journal(&journal_path, &journal).unwrap();

        recover_transaction(&journal_path).unwrap();

        assert_eq!(
            fs::read_to_string(&first_destination).unwrap(),
            "old first contents\n"
        );
        assert_eq!(
            fs::read_to_string(&second_destination).unwrap(),
            "old second contents\n"
        );
        assert!(!journal_path.exists());
        assert!(!first_backup.exists());
        assert!(!second_backup.exists());
        assert!(!first_temporary.exists());
        assert!(!second_temporary.exists());
        assert!(!transaction_commit_marker_path(&journal_path).exists());
    }

    #[test]
    fn transaction_recovery_finishes_cleanup_after_commit_marker() {
        let directory = tempfile::tempdir().unwrap();
        let journal_path = transaction_journal_path(directory.path());
        let destination = directory.path().join(HOSTS_FILENAME);
        let second_destination = directory.path().join(UBLOCK_FILENAME);
        let backup = directory.path().join(".hosts_ema.txt.backup.123.0.tmp");
        let second_backup = directory.path().join(".hosts_ema_ublock.txt.backup.tmp");
        let temporary = directory.path().join(".hosts_ema.txt.staged.tmp");
        let second_temporary = directory.path().join(".hosts_ema_ublock.txt.staged.tmp");
        fs::write(&destination, "new complete contents\n").unwrap();
        fs::write(&second_destination, "new second contents\n").unwrap();
        fs::write(&backup, "old contents\n").unwrap();
        fs::write(&second_backup, "old second contents\n").unwrap();
        let journal = TransactionJournal {
            files: vec![
                TransactionFile {
                    destination: destination.clone(),
                    backup: Some(backup.clone()),
                    temporary: temporary.clone(),
                },
                TransactionFile {
                    destination: second_destination,
                    backup: Some(second_backup.clone()),
                    temporary: second_temporary,
                },
            ],
        };
        write_transaction_journal(&journal_path, &journal).unwrap();
        write_commit_marker(&transaction_commit_marker_path(&journal_path)).unwrap();

        recover_transaction(&journal_path).unwrap();

        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            "new complete contents\n"
        );
        assert!(!journal_path.exists());
        assert!(!transaction_commit_marker_path(&journal_path).exists());
        assert!(!backup.exists());
        assert!(!second_backup.exists());
    }

    #[test]
    fn transaction_recovery_finishes_cleanup_if_journal_removal_was_interrupted() {
        let directory = tempfile::tempdir().unwrap();
        let journal_path = transaction_journal_path(directory.path());
        let destination = directory.path().join(HOSTS_FILENAME);
        let second_destination = directory.path().join(UBLOCK_FILENAME);
        let backup = directory.path().join(".hosts_ema.txt.backup.123.0.tmp");
        let second_backup = directory
            .path()
            .join(".hosts_ema_ublock.txt.backup.123.0.tmp");
        let temporary = directory.path().join(".hosts_ema.txt.staged.tmp");
        let second_temporary = directory.path().join(".hosts_ema_ublock.txt.staged.tmp");
        fs::write(&destination, "new contents\n").unwrap();
        fs::write(&second_destination, "new second contents\n").unwrap();
        fs::write(&backup, "old contents\n").unwrap();
        fs::write(&second_backup, "old second contents\n").unwrap();
        let journal = TransactionJournal {
            files: vec![
                TransactionFile {
                    destination: destination.clone(),
                    backup: Some(backup.clone()),
                    temporary: temporary.clone(),
                },
                TransactionFile {
                    destination: second_destination.clone(),
                    backup: Some(second_backup.clone()),
                    temporary: second_temporary.clone(),
                },
            ],
        };
        write_transaction_journal(&journal_path, &journal).unwrap();
        write_commit_marker(&transaction_commit_marker_path(&journal_path)).unwrap();

        recover_transaction(&journal_path).unwrap();

        assert_eq!(fs::read_to_string(&destination).unwrap(), "new contents\n");
        assert_eq!(
            fs::read_to_string(&second_destination).unwrap(),
            "new second contents\n"
        );
        assert!(!backup.exists());
        assert!(!second_backup.exists());
        assert!(!transaction_commit_marker_path(&journal_path).exists());
        assert!(!temporary.exists());
        assert!(!second_temporary.exists());
    }

    #[test]
    fn recovery_without_journal_keeps_recent_backup_for_manual_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let journal_path = transaction_journal_path(directory.path());
        let backup = directory.path().join(".hosts_ema.txt.backup.123.0.tmp");
        fs::write(&backup, "last known good copy\n").unwrap();

        recover_transaction(&journal_path).unwrap();

        assert!(backup.exists());
    }

    #[test]
    fn recovery_keeps_a_backup_if_restoring_it_fails() {
        let directory = tempfile::tempdir().unwrap();
        let journal_path = transaction_journal_path(directory.path());
        let first_destination = directory.path().join(HOSTS_FILENAME);
        let second_destination = directory.path().join(UBLOCK_FILENAME);
        let first_backup = directory.path().join(".hosts_ema.txt.backup.1.0.tmp");
        let second_backup = directory
            .path()
            .join(".hosts_ema_ublock.txt.backup.1.0.tmp");
        let journal = TransactionJournal {
            files: vec![
                TransactionFile {
                    destination: first_destination.clone(),
                    backup: Some(first_backup.clone()),
                    temporary: directory.path().join(".hosts_ema.txt.staged.tmp"),
                },
                TransactionFile {
                    destination: second_destination.clone(),
                    backup: Some(second_backup.clone()),
                    temporary: directory.path().join(".hosts_ema_ublock.txt.staged.tmp"),
                },
            ],
        };
        fs::write(&first_destination, "new first\n").unwrap();
        fs::write(&first_backup, "old first\n").unwrap();
        fs::write(&second_backup, "old second\n").unwrap();
        // A directory at the target prevents replacement but still exists as a path.
        fs::create_dir(&second_destination).unwrap();
        write_transaction_journal(&journal_path, &journal).unwrap();

        assert!(recover_transaction(&journal_path).is_err());
        assert!(journal_path.exists());
        assert!(first_backup.exists());
        assert!(second_backup.exists());
    }

    #[test]
    fn transaction_recovery_cleans_backup_after_journal_was_removed() {
        let directory = tempfile::tempdir().unwrap();
        let journal_path = transaction_journal_path(directory.path());
        let destination = directory.path().join(HOSTS_FILENAME);
        let backup = directory.path().join(".hosts_ema.txt.backup.123.0.tmp");
        fs::write(&destination, "old contents\n").unwrap();
        fs::write(&backup, "orphan backup contents\n").unwrap();
        let old_modified =
            std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 24 * 60 * 60);
        File::options()
            .write(true)
            .open(&backup)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old_modified))
            .unwrap();

        recover_transaction(&journal_path).unwrap();

        assert!(!backup.exists());
    }

    #[test]
    fn orphan_backup_cleanup_does_not_remove_recent_backups_or_unrelated_temp_files() {
        let directory = tempfile::tempdir().unwrap();
        let blocklist_backup = directory.path().join(".hosts_ema.txt.123.0.tmp");
        let unrelated_temp = directory.path().join(".user-data.tmp");
        fs::write(&blocklist_backup, "backup").unwrap();
        fs::write(&unrelated_temp, "unrelated").unwrap();

        prune_old_orphaned_backups(directory.path()).unwrap();

        assert!(blocklist_backup.exists());
        assert!(unrelated_temp.exists());
    }

    #[test]
    fn transaction_recovery_can_repeat_after_interrupted_rollback_step() {
        let directory = tempfile::tempdir().unwrap();
        let journal_path = transaction_journal_path(directory.path());
        let destination = directory.path().join(HOSTS_FILENAME);
        let second_destination = directory.path().join(UBLOCK_FILENAME);
        let backup = directory.path().join(".hosts_ema.txt.backup.123.0.tmp");
        let second_backup = directory
            .path()
            .join(".hosts_ema_ublock.txt.backup.123.0.tmp");
        let temporary = directory.path().join(".hosts_ema.txt.staged.tmp");
        let second_temporary = directory.path().join(".hosts_ema_ublock.txt.staged.tmp");
        fs::write(&destination, "old contents\n").unwrap();
        fs::write(&second_destination, "old second contents\n").unwrap();
        fs::write(&backup, "old contents\n").unwrap();
        fs::write(&second_backup, "old second contents\n").unwrap();
        let journal = TransactionJournal {
            files: vec![
                TransactionFile {
                    destination: destination.clone(),
                    backup: Some(backup.clone()),
                    temporary: temporary.clone(),
                },
                TransactionFile {
                    destination: second_destination,
                    backup: Some(second_backup.clone()),
                    temporary: second_temporary,
                },
            ],
        };
        write_transaction_journal(&journal_path, &journal).unwrap();

        recover_transaction(&journal_path).unwrap();
        recover_transaction(&journal_path).unwrap();

        assert_eq!(fs::read_to_string(&destination).unwrap(), "old contents\n");
        assert!(!journal_path.exists());
        assert!(!backup.exists());
        assert!(!second_backup.exists());
    }

    #[test]
    fn transaction_rejects_journal_paths_outside_output_directory() {
        let directory = tempfile::tempdir().unwrap();
        let journal_path = transaction_journal_path(directory.path());
        let journal = TransactionJournal {
            files: vec![TransactionFile {
                destination: PathBuf::from("/tmp/important-file"),
                backup: None,
                temporary: PathBuf::from("/tmp/.important-file.tmp"),
            }],
        };

        assert!(validate_transaction_journal(&journal_path, &journal).is_err());
    }

    #[test]
    fn transaction_recovery_resumes_partially_completed_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let journal_path = transaction_journal_path(directory.path());
        let first_destination = directory.path().join(HOSTS_FILENAME);
        let second_destination = directory.path().join(UBLOCK_FILENAME);
        let first_backup = directory.path().join(".hosts_ema.txt.backup.tmp");
        let second_backup = directory.path().join(".hosts_ema_ublock.txt.backup.tmp");
        let first_temporary = directory.path().join(".hosts_ema.txt.staged.tmp");
        let second_temporary = directory.path().join(".hosts_ema_ublock.txt.staged.tmp");
        fs::write(&first_backup, "old first contents\n").unwrap();
        fs::write(&first_destination, "old first contents\n").unwrap();
        fs::write(&second_destination, "new second contents\n").unwrap();
        fs::write(&second_backup, "old second contents\n").unwrap();
        let journal = TransactionJournal {
            files: vec![
                TransactionFile {
                    destination: first_destination.clone(),
                    backup: Some(first_backup),
                    temporary: first_temporary,
                },
                TransactionFile {
                    destination: second_destination.clone(),
                    backup: Some(second_backup.clone()),
                    temporary: second_temporary,
                },
            ],
        };
        write_transaction_journal(&journal_path, &journal).unwrap();

        recover_transaction(&journal_path).unwrap();

        assert_eq!(
            fs::read_to_string(&first_destination).unwrap(),
            "old first contents\n"
        );
        assert_eq!(
            fs::read_to_string(&second_destination).unwrap(),
            "old second contents\n"
        );
        assert!(!second_backup.exists());
    }

    #[test]
    fn transaction_recovery_rejects_incomplete_or_corrupt_commit_marker() {
        let directory = tempfile::tempdir().unwrap();
        let journal_path = transaction_journal_path(directory.path());
        let first_destination = directory.path().join(HOSTS_FILENAME);
        let second_destination = directory.path().join(UBLOCK_FILENAME);
        let first_backup = directory.path().join(".hosts_ema.txt.backup.tmp");
        let second_backup = directory.path().join(".hosts_ema_ublock.txt.backup.tmp");
        let journal = TransactionJournal {
            files: vec![
                TransactionFile {
                    destination: first_destination.clone(),
                    backup: Some(first_backup.clone()),
                    temporary: directory.path().join(".hosts_ema.txt.staged.tmp"),
                },
                TransactionFile {
                    destination: second_destination.clone(),
                    backup: Some(second_backup.clone()),
                    temporary: directory.path().join(".hosts_ema_ublock.txt.staged.tmp"),
                },
            ],
        };
        fs::write(&first_destination, "new first\n").unwrap();
        fs::write(&second_destination, "new second\n").unwrap();
        fs::write(&first_backup, "old first\n").unwrap();
        fs::write(&second_backup, "old second\n").unwrap();
        write_transaction_journal(&journal_path, &journal).unwrap();
        fs::write(
            transaction_commit_marker_path(&journal_path),
            "partial marker",
        )
        .unwrap();

        assert!(recover_transaction(&journal_path).is_err());
        assert!(journal_path.exists());
        assert!(first_backup.exists());
        assert!(second_backup.exists());
    }

    #[test]
    fn failed_second_commit_restores_the_first_output() {
        let directory = tempfile::tempdir().unwrap();
        let first_destination = directory.path().join(HOSTS_FILENAME);
        let second_destination = directory.path().join(UBLOCK_FILENAME);
        fs::write(&first_destination, "old first contents\n").unwrap();
        fs::write(&second_destination, "old second contents\n").unwrap();

        let staged_files = vec![
            stage_blocklist(
                first_destination.to_str().unwrap(),
                "new first\n",
                &["first.example".to_string()],
                "",
                "",
            )
            .unwrap(),
            stage_blocklist(
                second_destination.to_str().unwrap(),
                "new second\n",
                &["second.example".to_string()],
                "",
                "",
            )
            .unwrap(),
        ];
        let first_staged_path = staged_files[0].temporary.clone().unwrap();
        let second_staged_path = staged_files[1].temporary.clone().unwrap();
        let journal_path = transaction_journal_path(directory.path());
        let mut commit_count = 0;
        let result = commit_staged_files_with(staged_files, &journal_path, |staged_file| {
            commit_count += 1;
            if commit_count == 2 {
                return Err(FetchError::Unexpected(
                    "injected commit failure".to_string(),
                ));
            }
            staged_file.commit()
        });

        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(&first_destination).unwrap(),
            "old first contents\n"
        );
        assert_eq!(
            fs::read_to_string(&second_destination).unwrap(),
            "old second contents\n"
        );
        assert!(!journal_path.exists());
        assert!(!first_staged_path.exists());
        assert!(!second_staged_path.exists());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[test]
    fn output_lock_is_exclusive_and_released_when_dropped() {
        let directory = tempfile::tempdir().unwrap();
        let lock = OutputLock::acquire(directory.path()).unwrap();
        let second = OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.path().join(OUTPUT_LOCK))
            .unwrap();
        assert!(second.try_lock().is_err());

        drop(lock);
        assert!(second.try_lock().is_ok());
    }

    #[test]
    fn recovery_cleanup_does_not_remove_an_active_lock_file() {
        let directory = tempfile::tempdir().unwrap();
        let _lock = OutputLock::acquire(directory.path()).unwrap();

        cleanup_orphaned_transaction_files(directory.path()).unwrap();

        assert!(directory.path().join(OUTPUT_LOCK).exists());
    }
}
