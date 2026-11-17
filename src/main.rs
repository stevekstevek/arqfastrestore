// SPDX-License-Identifier: MIT
// Use jemalloc as the global allocator. glibc's malloc retains freed arena
// pages indefinitely; jemalloc returns them to the OS much more aggressively,
// which matters during large scans (millions of small Tree allocations).
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

mod crypto;
mod format;
mod restore;
mod scan;
mod storage;

use crypto::{Arq5Keys, Arq7Keys, decrypt_arq5_object, decrypt_arq7_object};

/// Resolve the effective password string from the mutually-exclusive
/// `--password` / `--password-file` CLI options.
///
/// - Both provided → error
/// - Neither provided → error
/// - `password` provided → return it as-is
/// - `password_file` provided → read the file, split by newlines, trim each
///   line, filter empty lines, join with `","`. Errors if the result is empty.
fn resolve_password(password: Option<String>, password_file: Option<String>) -> anyhow::Result<String> {
    match (password, password_file) {
        (Some(_), Some(_)) => bail!("cannot specify both --password and --password-file"),
        (None, None) => bail!("one of --password or --password-file is required"),
        (Some(pw), None) => Ok(pw),
        (None, Some(path)) => {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("reading password file {path}"))?;
            let joined: String = content
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect::<Vec<_>>()
                .join(",");
            if joined.is_empty() {
                bail!("password file {path} contains no non-empty lines");
            }
            Ok(joined)
        }
    }
}
use format::arq5_adapter::{arq5_tree_to_tree, blob_key_to_blob_loc, strip_encrypted_prefix};
use format::{Arq5Commit, Arq5Tree, BackupRecord, PackIndexDb, list_all_backup_folders, read_arq5_computer_info, read_backup_config};
use restore::{RestoreEngine, RestoreStats, TreeCache, TreeParseFn};
use restore::csv_restore::{UuidContext, items_from_csv};
use storage::{DecryptFn, LocalStorage};

#[derive(Parser)]
#[command(name = "arqfastrestore")]
#[command(about = "Fast, parallel restore tool for Arq backups", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List available backups and their timestamps
    List {
        /// Path to the Arq backup folder (local or mount point)
        #[arg(short, long)]
        backup_path: String,

        /// Backup encryption password. Use --password-file to avoid quoting special characters.
        #[arg(short, long, env = "ARQ_PASSWORD")]
        password: Option<String>,

        /// Path to a file containing one password per line. Alternative to --password.
        #[arg(long)]
        password_file: Option<String>,
    },
    /// Scan all snapshots across all backup folders and emit a CSV of unique files
    Scan {
        /// Path to an Arq backup folder (a single UUID directory) OR the parent
        /// directory containing multiple UUID backup folders.  When pointing at the
        /// parent, all UUID subdirectories are scanned automatically.
        #[arg(short, long)]
        backup_path: String,

        /// Backup encryption password(s).  Accepts one password or a
        /// comma-separated list.  Each password is tried against every UUID
        /// directory found; directories that don't match any password are skipped
        /// with a warning.  Use the ARQ_PASSWORD environment variable to avoid
        /// putting passwords on the command line.
        /// Use --password-file to specify passwords one per line instead.
        #[arg(short, long, env = "ARQ_PASSWORD")]
        password: Option<String>,

        /// Path to a file containing one password per line. Alternative to --password.
        #[arg(long)]
        password_file: Option<String>,

        /// Comma-separated glob patterns to filter filenames (e.g. "*.mov,*.mp4").
        /// Patterns are case-insensitive and match the filename only, not the full path.
        /// If omitted, all files are included.
        #[arg(long)]
        filter: Option<String>,
    },
    /// Restore files from a backup
    Restore {
        /// Path to the Arq backup folder
        #[arg(short, long)]
        backup_path: String,

        /// Backup encryption password. Use --password-file to avoid quoting special characters.
        #[arg(short, long, env = "ARQ_PASSWORD")]
        password: Option<String>,

        /// Path to a file containing one password per line. Alternative to --password.
        #[arg(long)]
        password_file: Option<String>,

        /// Destination directory for restored files
        #[arg(short, long)]
        dest: String,

        /// Restore from a specific backup timestamp (Unix epoch). Defaults to most recent.
        #[arg(short, long)]
        timestamp: Option<u64>,

        /// Number of parallel worker threads (default: number of CPU cores)
        #[arg(short = 'j', long)]
        threads: Option<usize>,

        /// Simulate the restore without writing any files to disk
        #[arg(long)]
        dry_run: bool,

        /// Print detailed timing and I/O statistics after the restore
        #[arg(long)]
        verbose: bool,

        /// Path to the tree cache database (speeds up repeated restores by caching parsed trees)
        #[arg(long)]
        cache_path: Option<String>,

        /// Disable the persistent tree cache
        #[arg(long)]
        no_cache: bool,

        /// Number of pack files to process concurrently (default: 1).
        ///
        /// Use 1 (default) for spinning disks and USB storage — processes packs
        /// sequentially to avoid seek overhead.  Use 4–8 for SSDs or fast
        /// network storage to keep the CPU/decrypt pipeline saturated.
        #[arg(long, default_value = "1")]
        pack_concurrency: usize,
    },
    /// Restore one file or folder from one backup record (Arq7 only)
    RestorePath {
        /// Path to the Arq plan folder (the UUID directory)
        #[arg(short, long)]
        backup_path: String,

        /// Backup encryption password. Prefer --password-file.
        #[arg(short, long, env = "ARQ_PASSWORD")]
        password: Option<String>,

        /// Path to a file containing the password (one line).
        #[arg(long)]
        password_file: Option<String>,

        /// Which backup record: a Unix timestamp as shown by `list`, `latest`,
        /// `before:<rfc3339>` (newest record strictly before that instant) or
        /// `near:<rfc3339>` (closest record in either direction).
        /// Example: --record before:2026-11-01T12:50:00Z
        #[arg(long)]
        record: String,

        /// File or folder to restore, relative to the backed-up root
        /// (e.g. src/project/file.json, no leading slash needed).
        #[arg(long)]
        path: String,

        /// Destination directory. The relative path is recreated beneath it.
        #[arg(short, long)]
        dest: String,

        /// Resolve the record and path and print what would be restored, writing nothing
        #[arg(long)]
        dry_run: bool,

        /// Tree cache database path (keep it off the backup volume)
        #[arg(long)]
        cache_path: Option<String>,

        /// Disable the persistent tree cache
        #[arg(long)]
        no_cache: bool,
    },
    /// Restore specific files from a scan CSV (rows with action=restore)
    RestoreFromCsv {
        /// Path to the scan CSV file produced by the `scan` command
        #[arg(long)]
        csv: String,

        /// Path to the Arq backup folder (single UUID dir) OR parent directory
        /// containing multiple UUID backup folders.  Same semantics as `scan`.
        #[arg(short, long)]
        backup_path: String,

        /// Backup encryption password(s).  Accepts one password or a
        /// comma-separated list.  Each password is tried against every UUID
        /// directory found.
        /// Use --password-file to specify passwords one per line instead.
        #[arg(short, long, env = "ARQ_PASSWORD")]
        password: Option<String>,

        /// Path to a file containing one password per line. Alternative to --password.
        #[arg(long)]
        password_file: Option<String>,

        /// Destination directory for restored files
        #[arg(short, long)]
        dest: String,

        /// Number of parallel worker threads (default: number of CPU cores)
        #[arg(short = 'j', long)]
        threads: Option<usize>,

        /// Simulate the restore without writing any files to disk
        #[arg(long)]
        dry_run: bool,

        /// Print detailed timing and I/O statistics after the restore
        #[arg(long)]
        verbose: bool,

        /// Number of pack files to process concurrently (default: 1)
        #[arg(long, default_value = "1")]
        pack_concurrency: usize,
    },
}

// ---------------------------------------------------------------------------
// Backup format detection
// ---------------------------------------------------------------------------

/// Detected backup format and corresponding decryption keys.
enum BackupFormat {
    Arq7(Arq7Keys),
    Arq5(Arq5Keys),
    Unencrypted,
}

/// Detect the backup format by checking for known key files.
///
/// Priority:
/// 1. `encryptedkeyset.dat` → Arq7 encrypted
/// 2. `encryptionv2.dat`    → Arq5 encrypted
/// 3. Neither found         → Unencrypted
fn detect_format(backup_path: &Path, password: &str) -> Result<BackupFormat> {
    let arq7_key_path = backup_path.join("encryptedkeyset.dat");
    if arq7_key_path.exists() {
        let dat = std::fs::read(&arq7_key_path)
            .with_context(|| format!("reading {}", arq7_key_path.display()))?;
        let keys =
            Arq7Keys::from_dat(&dat, password).context("deriving keys from encryptedkeyset.dat")?;
        return Ok(BackupFormat::Arq7(keys));
    }

    let arq5_key_path = backup_path.join("encryptionv2.dat");
    if arq5_key_path.exists() {
        let dat = std::fs::read(&arq5_key_path)
            .with_context(|| format!("reading {}", arq5_key_path.display()))?;
        let keys =
            Arq5Keys::from_dat(&dat, password).context("deriving keys from encryptionv2.dat")?;
        return Ok(BackupFormat::Arq5(keys));
    }

    Ok(BackupFormat::Unencrypted)
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::List {
            backup_path,
            password,
            password_file,
        } => {
            let password = resolve_password(password, password_file)?;
            let bp = PathBuf::from(&backup_path);
            let fmt = detect_format(&bp, &password)?;

            let folders: Vec<(String, String, Vec<BackupRecord>)> = match fmt {
                BackupFormat::Arq5(keys) => list_arq5_buckets(&bp, &keys)?,
                BackupFormat::Arq7(keys) => {
                    let storage = LocalStorage::new(&backup_path);
                    list_backup_folders_all_plans(&storage, Some(&keys))?
                }
                BackupFormat::Unencrypted => {
                    let storage = LocalStorage::new(&backup_path);
                    list_backup_folders_all_plans(&storage, None)?
                }
            };

            if folders.is_empty() {
                println!("No backup folders found in {backup_path}");
                return Ok(());
            }

            for (folder_uuid, local_path, records) in &folders {
                println!("Folder: {local_path}  (uuid: {folder_uuid})");
                if records.is_empty() {
                    println!("  (no backup records)");
                } else {
                    for r in records {
                        let complete = if r.is_complete { "" } else { " [incomplete]" };
                        println!(
                            "  timestamp={}  date={}  arq={}{}",
                            r.timestamp,
                            format_rfc3339(r.timestamp),
                            r.arq_version,
                            complete
                        );
                    }
                }
            }

            Ok(())
        }
        Commands::Scan {
            backup_path,
            password,
            password_file,
            filter,
        } => {
            let password = resolve_password(password, password_file)?;
            let bp = PathBuf::from(&backup_path);
            let passwords: Vec<&str> = password.split(',').map(str::trim).collect();

            // Discover UUID directories to scan.
            // If bp itself is a UUID dir (has encryptedkeyset.dat or backupfolders),
            // scan just that one.  Otherwise treat bp as a parent and discover all
            // UUID subdirectories automatically.
            let uuid_dirs: Vec<PathBuf> = if is_uuid_backup_dir(&bp) {
                vec![bp.clone()]
            } else {
                discover_uuid_dirs(&bp)
            };

            if uuid_dirs.is_empty() {
                eprintln!("No Arq backup UUID directories found under {backup_path}");
                return Ok(());
            }

            // storage_root is the parent of the UUID dirs (BlobLocs are relative to it).
            let storage_root = uuid_dirs[0]
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| bp.clone());

            // Collect folders (snapshot lists) from all UUID dirs, trying each password.
            let mut all_folders: Vec<(String, String, Vec<BackupRecord>)> = Vec::new();
            let mut scan_parse_tree: Option<TreeParseFn> = None;
            // Per-folder-UUID decrypt functions (each backup set has its own key).
            let mut decrypt_map: std::collections::HashMap<String, DecryptFn> =
                std::collections::HashMap::new();
            // Per-folder-UUID storage root overrides (Arq5 uses UUID dir, not parent).
            let mut storage_root_map: std::collections::HashMap<String, PathBuf> =
                std::collections::HashMap::new();
            // Per-folder-UUID parse_tree functions (Arq5 needs bucket-specific parsers).
            let mut parse_tree_map: std::collections::HashMap<String, TreeParseFn> =
                std::collections::HashMap::new();
            // Map folder_uuid → (computer_name, backup_name) for CSV output.
            let mut plan_meta: std::collections::HashMap<String, (String, String)> =
                std::collections::HashMap::new();

            for uuid_dir in &uuid_dirs {
                let uuid_name = uuid_dir
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();

                let mut found = false;
                for pw in &passwords {
                    match detect_format(uuid_dir, pw) {
                        Err(e) => {
                            tracing::debug!("detect_format error for {uuid_name}: {e}");
                            continue;
                        }
                        Ok(fmt) => {
                            match build_scan_context(uuid_dir, &uuid_dir.to_string_lossy(), fmt) {
                                Err(e) => {
                                    tracing::warn!("skipping {uuid_name}: {e}");
                                }
                                Ok((folders, decrypt, parse_tree, meta, storage_override)) => {
                                    eprintln!(
                                        "scan: found {} snapshot(s) in {}",
                                        folders.iter().map(|(_, _, r)| r.len()).sum::<usize>(),
                                        uuid_name
                                    );
                                    // Register per-UUID decrypt fn and storage root for every folder.
                                    if let Some(dfn) = decrypt {
                                        for (folder_uuid, _, _) in &folders {
                                            decrypt_map.insert(folder_uuid.clone(), dfn.clone());
                                        }
                                    }
                                    if let Some(ref root) = storage_override {
                                        for (folder_uuid, _, _) in &folders {
                                            storage_root_map.insert(folder_uuid.clone(), root.clone());
                                            // Arq5: each folder uses same parse_tree (bucket-aware closure).
                                            parse_tree_map.insert(folder_uuid.clone(), parse_tree.clone());
                                        }
                                    }
                                    all_folders.extend(folders);
                                    plan_meta.extend(meta);
                                    if scan_parse_tree.is_none() {
                                        scan_parse_tree = Some(parse_tree);
                                    }
                                    found = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if !found {
                    eprintln!("scan: skipping {uuid_name} (no matching password or unsupported format)");
                }
            }

            if all_folders.is_empty() {
                eprintln!("No accessible snapshots found.");
                return Ok(());
            }

            let parse_tree = scan_parse_tree
                .context("no parse_tree function — all UUID dirs failed to open")?;

            let config = scan::ScanConfig {
                storage_root,
                storage_root_map,
                decrypt_map,
                parse_tree,
                parse_tree_map,
                filter,
                files_only: true,
                tree_cache: open_tree_cache(false, None, false)?
                    .map(std::sync::Arc::new),
            };

            let stdout = std::io::stdout();
            let mut out = std::io::BufWriter::new(stdout.lock());
            scan::run_scan(&config, &all_folders, &plan_meta, &mut out)?;
            Ok(())
        }
        Commands::Restore {
            backup_path,
            password,
            password_file,
            dest,
            timestamp,
            threads,
            dry_run,
            verbose,
            cache_path,
            no_cache,
            pack_concurrency,
        } => {
            let password = resolve_password(password, password_file)?;
            if let Some(n) = threads {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(n)
                    .build_global()
                    .ok();
            }

            let bp = PathBuf::from(&backup_path);
            let fmt = detect_format(&bp, &password)?;

            match fmt {
                BackupFormat::Arq5(keys) => {
                    restore_arq5(
                        &bp, keys, &dest, timestamp, dry_run, verbose, cache_path, no_cache,
                        pack_concurrency,
                    )?;
                }
                BackupFormat::Arq7(keys) => {
                    restore_arq7(
                        &backup_path,
                        Some(keys),
                        &dest,
                        timestamp,
                        dry_run,
                        verbose,
                        cache_path,
                        no_cache,
                        pack_concurrency,
                    )?;
                }
                BackupFormat::Unencrypted => {
                    restore_arq7(
                        &backup_path,
                        None,
                        &dest,
                        timestamp,
                        dry_run,
                        verbose,
                        cache_path,
                        no_cache,
                        pack_concurrency,
                    )?;
                }
            }

            Ok(())
        }
        Commands::RestorePath {
            backup_path,
            password,
            password_file,
            record,
            path,
            dest,
            dry_run,
            cache_path,
            no_cache,
        } => {
            let password = resolve_password(password, password_file)?;
            let bp = PathBuf::from(&backup_path);
            let keys = match detect_format(&bp, &password)? {
                BackupFormat::Arq7(k) => Some(k),
                BackupFormat::Unencrypted => None,
                BackupFormat::Arq5(_) => bail!("restore-path supports Arq7 backups only"),
            };
            restore_path_arq7(&backup_path, keys, &record, &path, &dest, dry_run, cache_path, no_cache)
        }
        Commands::RestoreFromCsv {
            csv,
            backup_path,
            password,
            password_file,
            dest,
            threads,
            dry_run,
            verbose,
            pack_concurrency,
        } => {
            let password = resolve_password(password, password_file)?;
            if let Some(n) = threads {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(n)
                    .build_global()
                    .ok();
            }

            restore_from_csv(
                &csv,
                &backup_path,
                &password,
                &dest,
                dry_run,
                verbose,
                pack_concurrency,
            )?;
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Restore-from-CSV path
// ---------------------------------------------------------------------------

/// Restore specific files listed in a scan CSV (rows with `action=restore`).
///
/// Discovers all backup UUID directories under `backup_path`, opens each one
/// with the matching password, then walks the most-recent snapshot for each
/// UUID referenced in the CSV to collect the requested [`RestoreItem`]s.
/// The items are fed into the sort-by-pack [`RestoreEngine`] for efficient
/// sequential disk access.
#[allow(clippy::too_many_arguments)]
fn restore_from_csv(
    csv_path: &str,
    backup_path: &str,
    password: &str,
    dest: &str,
    dry_run: bool,
    verbose: bool,
    pack_concurrency: usize,
) -> Result<()> {
    use restore::csv_restore::UuidContext;

    let bp = PathBuf::from(backup_path);
    let passwords: Vec<&str> = password.split(',').map(str::trim).collect();

    // Discover UUID directories.
    let uuid_dirs: Vec<PathBuf> = if is_uuid_backup_dir(&bp) {
        vec![bp.clone()]
    } else {
        discover_uuid_dirs(&bp)
    };

    if uuid_dirs.is_empty() {
        bail!("No Arq backup UUID directories found under {backup_path}");
    }

    // Storage root for Arq7 (parent of UUID dirs).
    let storage_root_arq7 = uuid_dirs[0]
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| bp.clone());

    // Build per-source contexts.
    // Keys must match the UUIDs emitted in the scan CSV `sources` column:
    // - Arq7: backup-folder UUIDs
    // - Arq5: bucket UUIDs
    let mut uuid_contexts: std::collections::HashMap<String, UuidContext> =
        std::collections::HashMap::new();

    for uuid_dir in &uuid_dirs {
        let uuid_name = uuid_dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let mut found = false;
        for pw in &passwords {
            match detect_format(uuid_dir, pw) {
                Err(_) => continue,
                Ok(fmt) => {
                    match build_uuid_contexts(uuid_dir, &storage_root_arq7, &uuid_name, fmt) {
                        Err(e) => {
                            tracing::warn!("csv-restore: skipping {uuid_name}: {e}");
                        }
                        Ok(contexts) => {
                            for (source_uuid, ctx) in contexts {
                                uuid_contexts.insert(source_uuid, ctx);
                            }
                            found = true;
                            break;
                        }
                    }
                }
            }
        }
        if !found {
            eprintln!("csv-restore: skipping {uuid_name} (no matching password)");
        }
    }

    if uuid_contexts.is_empty() {
        bail!("No accessible backup sets found — check --backup-path and --password");
    }

    let cache = open_tree_cache(false, None, verbose)?;
    let dest_root = PathBuf::from(dest);

    let (items, not_found) = items_from_csv(
        Path::new(csv_path),
        &dest_root,
        &uuid_contexts,
        cache.as_ref(),
    )?;

    if items.is_empty() {
        println!("Nothing to restore — no matching files found.");
        return Ok(());
    }

    eprintln!(
        "csv-restore: {} item(s) collected; running sort-by-pack restore{}",
        items.len(),
        if dry_run { " [DRY RUN]" } else { "" }
    );

    // Feed into sort-by-pack engine.
    // We need a storage + decrypt for the engine; use the first context's storage.
    // Since items already have BlobLocs with the correct relative paths, the
    // storage root must match.  For multi-UUID restores the items may come from
    // different storage roots — we handle that by using the parent storage root
    // (which contains all UUID dirs) as the engine's storage root.
    //
    // The BlobLoc.relative_path for Arq7 already includes the plan UUID prefix,
    // so the parent dir is correct.  For Arq5, BlobLocs are relative to the UUID
    // dir itself; those items' paths won't be found under the parent.  For now,
    // single-format restores work correctly; multi-format is a future enhancement.
    let engine_storage_root = if uuid_dirs.len() == 1 {
        // Single UUID dir: use its storage root directly (works for both Arq5 + Arq7).
        uuid_contexts
            .values()
            .next()
            .map(|c| c.storage_root.clone())
            .unwrap_or(storage_root_arq7.clone())
    } else {
        // Multiple UUID dirs (mixed backup): use parent dir (Arq7 compatible).
        storage_root_arq7.clone()
    };

    // For the engine we need a single decrypt fn.  Since items from different
    // backup sets may need different keys, and the engine applies one DecryptFn
    // to all blobs, we use a dispatch closure keyed by ARQO magic detection.
    // For single-UUID restores this is just that UUID's fn.
    // For multi-UUID: attempt each fn in order — the correct key will succeed.
    let decrypt_fns: Vec<DecryptFn> = uuid_contexts
        .values()
        .filter_map(|c| c.decrypt.clone())
        .collect();

    let engine_decrypt: Option<DecryptFn> = if decrypt_fns.is_empty() {
        None
    } else if decrypt_fns.len() == 1 {
        Some(decrypt_fns.into_iter().next().unwrap())
    } else {
        // Multi-key dispatch: try each decrypt fn, return first success.
        let fns = Arc::new(decrypt_fns);
        Some(Arc::new(move |data: &[u8]| -> Result<Vec<u8>> {
            let mut last_err = anyhow::anyhow!("no decrypt functions available");
            for f in fns.iter() {
                match f(data) {
                    Ok(plain) => return Ok(plain),
                    Err(e) => last_err = e,
                }
            }
            Err(last_err)
        }))
    };

    // Use the Arq7 parse_tree as the engine's parse_tree (items from Arq5 already
    // have BlobLocs translated via the arq5_adapter, so Arq7 tree parsing is n/a
    // for the file-data restore phase — the engine only calls parse_tree during
    // tree walk, which we bypassed here).
    use crate::format::arq7::Tree;
    let parse_tree: TreeParseFn = Arc::new(|data: &[u8]| Tree::parse(data));

    let engine_storage: Arc<dyn storage::Storage> =
        Arc::new(LocalStorage::new(&engine_storage_root));

    // Sort items by pack order (reuse engine's sort, but we call it manually
    // since we collected items ourselves rather than going through engine.restore()).
    // We'll wrap a synthetic BackupRecord with no root_tree_blob_loc and use
    // the engine's restore_items() path.  Actually, engine.restore() requires a
    // BackupRecord to start the tree walk — we need to drive it differently.
    //
    // Cleanest solution: expose a method on RestoreEngine that takes pre-collected
    // items and runs Phase 2+3 only.  Add that now.
    let engine = RestoreEngine::new(
        engine_storage,
        engine_decrypt,
        dest_root.clone(),
        dry_run,
        verbose,
        cache,
        parse_tree,
        pack_concurrency,
    );

    let stats = engine.restore_items(items)?;
    print_restore_stats(&stats, dry_run);

    if !not_found.is_empty() {
        eprintln!(
            "WARNING: {} file(s) from the CSV were not found in any snapshot.",
            not_found.len()
        );
    }

    Ok(())
}

/// Build [`UuidContext`]s for one UUID backup directory.
///
/// The returned keys match the `sources` values emitted by the `scan` command:
/// Arq7 backup-folder UUIDs and Arq5 bucket UUIDs.
fn build_uuid_contexts(
    uuid_dir: &Path,
    storage_root_arq7: &Path,
    uuid_name: &str,
    fmt: BackupFormat,
) -> Result<Vec<(String, UuidContext)>> {
    match fmt {
        BackupFormat::Arq7(keys) => {
            let storage = LocalStorage::new(uuid_dir.to_string_lossy().as_ref());
            let folders = list_backup_folders_all_plans(&storage, Some(&keys))?;
            let decrypt: Option<DecryptFn> = Some(Arc::new(move |data: &[u8]| {
                decrypt_arq7_object(data, &keys)
            }));
            use crate::format::arq7::Tree;
            let parse_tree: TreeParseFn = Arc::new(|data: &[u8]| Tree::parse(data));

            let mut contexts = Vec::new();
            for (folder_uuid, _local_path, records) in folders {
                contexts.push((
                    folder_uuid,
                    UuidContext {
                        storage_root: storage_root_arq7.to_path_buf(),
                        decrypt: decrypt.clone(),
                        parse_tree: parse_tree.clone(),
                        records,
                    },
                ));
            }

            if contexts.is_empty() {
                bail!("no Arq7 backup folders found in {}", uuid_dir.display());
            }

            Ok(contexts)
        }
        BackupFormat::Unencrypted => {
            let storage = LocalStorage::new(uuid_dir.to_string_lossy().as_ref());
            let folders = list_backup_folders_all_plans(&storage, None)?;
            use crate::format::arq7::Tree;
            let parse_tree: TreeParseFn = Arc::new(|data: &[u8]| Tree::parse(data));

            let mut contexts = Vec::new();
            for (folder_uuid, _local_path, records) in folders {
                contexts.push((
                    folder_uuid,
                    UuidContext {
                        storage_root: storage_root_arq7.to_path_buf(),
                        decrypt: None,
                        parse_tree: parse_tree.clone(),
                        records,
                    },
                ));
            }

            if contexts.is_empty() {
                bail!("no unencrypted backup folders found in {}", uuid_dir.display());
            }

            Ok(contexts)
        }
        BackupFormat::Arq5(keys) => {
            let folders = list_arq5_buckets(uuid_dir, &keys)?;

            let keys_clone = keys.clone();
            let decrypt: Option<DecryptFn> = Some(Arc::new(move |data: &[u8]| {
                let arqo = format::arq5_adapter::strip_encrypted_prefix(data);
                decrypt_arq5_object(arqo, &keys_clone)
            }));

            // Build combined Arq5 parse_tree (same logic as build_scan_context).
            let computer_uuid = uuid_name.to_string();
            let mut all_tree_dbs: Vec<(Arc<PackIndexDb>, String)> = Vec::new();
            let mut all_blob_dbs: Vec<(Arc<PackIndexDb>, String)> = Vec::new();

            for (bucket_uuid, _, _) in &folders {
                let tree_packset_rel = format!("packsets/{bucket_uuid}-trees");
                let blob_packset_rel = format!("packsets/{bucket_uuid}-blobs");
                let tree_packset_dir = uuid_dir.join(&tree_packset_rel);
                let blob_packset_dir = uuid_dir.join(&blob_packset_rel);
                let packset_key_trees = format!("{computer_uuid}-{bucket_uuid}-trees");
                let packset_key_blobs = format!("{computer_uuid}-{bucket_uuid}-blobs");

                if let Ok(db) = load_pack_indexes_cached(&tree_packset_dir, &packset_key_trees) {
                    all_tree_dbs.push((Arc::new(db), tree_packset_rel));
                }
                if let Ok(db) = load_pack_indexes_cached(&blob_packset_dir, &packset_key_blobs) {
                    all_blob_dbs.push((Arc::new(db), blob_packset_rel));
                }
            }

            let all_tree_dbs = Arc::new(all_tree_dbs);
            let all_blob_dbs = Arc::new(all_blob_dbs);

            let parse_tree: TreeParseFn = Arc::new(move |data: &[u8]| {
                let arq5_tree = Arq5Tree::parse(data)?;
                let mut last_err = anyhow::anyhow!("no pack index found for Arq5 tree blob");
                for ((blob_db, blob_dir), (tree_db, tree_dir)) in
                    all_blob_dbs.iter().zip(all_tree_dbs.iter())
                {
                    match format::arq5_adapter::arq5_tree_to_tree(
                        &arq5_tree, blob_db, blob_dir, tree_db, tree_dir,
                    ) {
                        Ok(tree) => return Ok(tree),
                        Err(e) => last_err = e,
                    }
                }
                Err(last_err)
            });

            let mut contexts = Vec::new();
            for (bucket_uuid, _local_path, records) in folders {
                contexts.push((
                    bucket_uuid,
                    UuidContext {
                        storage_root: uuid_dir.to_path_buf(),
                        decrypt: decrypt.clone(),
                        parse_tree: parse_tree.clone(),
                        records,
                    },
                ));
            }

            if contexts.is_empty() {
                bail!("no Arq5 buckets found in {}", uuid_dir.display());
            }

            Ok(contexts)
        }
    }
}

// ---------------------------------------------------------------------------
// Arq7 / unencrypted restore path
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn restore_arq7(
    backup_path: &str,
    keys: Option<Arq7Keys>,
    dest: &str,
    timestamp: Option<u64>,
    dry_run: bool,
    verbose: bool,
    cache_path: Option<String>,
    no_cache: bool,
    pack_concurrency: usize,
) -> Result<()> {
    let storage = LocalStorage::new(backup_path);
    let folders = list_backup_folders_all_plans(&storage, keys.as_ref())?;

    let record =
        select_record(&folders, timestamp).context("no backup records found to restore")?;

    println!(
        "Restoring backup timestamp={} from {} to {}{}",
        record.timestamp,
        record.local_path,
        dest,
        if dry_run { " [DRY RUN]" } else { "" }
    );

    // For Arq7, relativePath includes the plan UUID dir, so storage root is the
    // *parent* of backup_path.
    let blob_storage_root = PathBuf::from(backup_path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(backup_path));
    let storage_arc: Arc<dyn storage::Storage> = Arc::new(LocalStorage::new(&blob_storage_root));

    let decrypt: Option<DecryptFn> =
        keys.map(|k| -> DecryptFn { Arc::new(move |data: &[u8]| decrypt_arq7_object(data, &k)) });

    use crate::format::arq7::Tree;
    let parse_tree: TreeParseFn = Arc::new(|data: &[u8]| Tree::parse(data));

    let cache = open_tree_cache(no_cache, cache_path, verbose)?;

    let engine = RestoreEngine::new(
        storage_arc,
        decrypt,
        PathBuf::from(dest),
        dry_run,
        verbose,
        cache,
        parse_tree,
        pack_concurrency,
    );
    let stats = engine.restore(record)?;
    print_restore_stats(&stats, dry_run);
    Ok(())
}

// ---------------------------------------------------------------------------
// Arq5 restore path
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn restore_arq5(
    backup_path: &Path,
    keys: Arq5Keys,
    dest: &str,
    timestamp: Option<u64>,
    dry_run: bool,
    verbose: bool,
    cache_path: Option<String>,
    no_cache: bool,
    pack_concurrency: usize,
) -> Result<()> {
    let buckets = list_arq5_buckets(backup_path, &keys)?;

    let folders: Vec<(String, String, Vec<BackupRecord>)> = buckets
        .iter()
        .map(|(uuid, local_path, records)| (uuid.clone(), local_path.clone(), records.clone()))
        .collect();

    let record =
        select_record(&folders, timestamp).context("no backup records found to restore")?;

    println!(
        "Restoring backup timestamp={} from {} to {}{}",
        record.timestamp,
        record.local_path,
        dest,
        if dry_run { " [DRY RUN]" } else { "" }
    );

    // Find the bucket UUID for the selected record so we can build packset paths.
    // The record's local_path matches what we stored per bucket.
    let bucket_uuid = buckets
        .iter()
        .find(|(_, lp, records)| {
            records
                .iter()
                .any(|r| r.timestamp == record.timestamp && r.local_path == *lp)
        })
        .map(|(uuid, _, _)| uuid.clone())
        .context("could not find bucket UUID for selected record")?;

    // For Arq5, paths inside BlobLoc are relative to backup_path itself.
    let storage_arc: Arc<dyn storage::Storage> = Arc::new(LocalStorage::new(backup_path));

    let tree_packset_rel = format!("packsets/{bucket_uuid}-trees");
    let blob_packset_rel = format!("packsets/{bucket_uuid}-blobs");

    let computer_uuid = backup_path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();

    let tree_packset_dir = backup_path.join(&tree_packset_rel);
    let blob_packset_dir = backup_path.join(&blob_packset_rel);

    eprintln!("Loading tree pack indexes...");
    let tree_pack_db = load_pack_indexes_cached(
        &tree_packset_dir,
        &format!("{computer_uuid}-{bucket_uuid}-trees"),
    )?;
    eprintln!("Loading blob pack indexes...");
    let blob_pack_db = load_pack_indexes_cached(
        &blob_packset_dir,
        &format!("{computer_uuid}-{bucket_uuid}-blobs"),
    )?;

    // Build DecryptFn: strip "encrypted" prefix then decrypt with Arq5 keys.
    let keys_clone = keys.clone();
    let decrypt: Option<DecryptFn> = Some(Arc::new(move |data: &[u8]| {
        let arqo = strip_encrypted_prefix(data);
        decrypt_arq5_object(arqo, &keys_clone)
    }));

    // Build TreeParseFn: parse Arq5Tree then adapt to unified Tree.
    let blob_db = Arc::new(blob_pack_db);
    let tree_db = Arc::new(tree_pack_db);
    let blob_dir_s = blob_packset_rel.clone();
    let tree_dir_s = tree_packset_rel.clone();
    let parse_tree: TreeParseFn = Arc::new(move |data: &[u8]| {
        let arq5_tree = Arq5Tree::parse(data)?;
        arq5_tree_to_tree(&arq5_tree, &blob_db, &blob_dir_s, &tree_db, &tree_dir_s)
    });

    let cache = open_tree_cache(no_cache, cache_path, verbose)?;

    let engine = RestoreEngine::new(
        storage_arc,
        decrypt,
        PathBuf::from(dest),
        dry_run,
        verbose,
        cache,
        parse_tree,
        pack_concurrency,
    );
    let stats = engine.restore(record)?;
    print_restore_stats(&stats, dry_run);
    Ok(())
}

// ---------------------------------------------------------------------------
// Arq5 bucket listing
// ---------------------------------------------------------------------------

/// List all Arq5 buckets in `backup_path/buckets/`, returning
/// `(bucket_uuid, local_path, Vec<BackupRecord>)` tuples.
fn list_arq5_buckets(
    backup_path: &Path,
    keys: &Arq5Keys,
) -> Result<Vec<(String, String, Vec<BackupRecord>)>> {
    use format::arq5::Arq5BlobKey;

    let buckets_dir = backup_path.join("buckets");
    if !buckets_dir.exists() {
        return Ok(vec![]);
    }

    let computer_uuid = backup_path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut results = Vec::new();

    let entries = std::fs::read_dir(&buckets_dir)
        .with_context(|| format!("reading buckets dir {}", buckets_dir.display()))?;

    for entry in entries {
        let entry = entry.context("iterating buckets dir")?;
        let bucket_uuid = entry.file_name().to_string_lossy().to_string();

        // Read and decrypt the bucket plist to get LocalPath.
        let bucket_data = std::fs::read(entry.path())
            .with_context(|| format!("reading bucket plist {}", entry.path().display()))?;
        let arqo_data = strip_encrypted_prefix(&bucket_data);
        let plaintext = match decrypt_arq5_object(arqo_data, keys) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("skipping bucket {bucket_uuid}: decrypt failed: {e}");
                continue;
            }
        };

        let local_path = extract_plist_string(&plaintext, "LocalPath")
            .unwrap_or_else(|| format!("(unknown: {bucket_uuid})"));

        // Read HEAD commit SHA1 from refs/heads/master.
        let head_path = backup_path
            .join("bucketdata")
            .join(&bucket_uuid)
            .join("refs/heads/master");
        let head_content = match std::fs::read_to_string(&head_path) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("skipping bucket {bucket_uuid}: cannot read HEAD: {e}");
                continue;
            }
        };
        let head_sha1 = head_content.trim().trim_end_matches('Y').to_string();

        // Load tree pack indexes for this bucket (with cache).
        let tree_packset_rel = format!("packsets/{bucket_uuid}-trees");
        let tree_packset_dir = backup_path.join(&tree_packset_rel);
        let packset_key = format!("{computer_uuid}-{bucket_uuid}-trees");

        let tree_index_db = match load_pack_indexes_cached(&tree_packset_dir, &packset_key) {
            Ok(db) => db,
            Err(e) => {
                tracing::warn!("skipping bucket {bucket_uuid}: pack index load failed: {e}");
                continue;
            }
        };

        // Resolve the commit object.
        let commit_raw = match resolve_arq5_object(
            backup_path,
            &head_sha1,
            &tree_index_db,
            &tree_packset_dir,
            keys,
        ) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("skipping bucket {bucket_uuid}: resolve commit failed: {e}");
                continue;
            }
        };

        // Decompress (commits may be gzip-compressed).
        let commit_bytes = match decompress_arq5_auto(&commit_raw) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("skipping bucket {bucket_uuid}: commit decompress failed: {e}");
                continue;
            }
        };

        let commit = match Arq5Commit::parse(&commit_bytes) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("skipping bucket {bucket_uuid}: commit parse failed: {e}");
                continue;
            }
        };

        // Build a BlobLoc for the root tree.
        let root_blob_loc = if let Some(ref tree_sha1) = commit.tree_sha1 {
            let tree_key = Arq5BlobKey {
                sha1: Some(tree_sha1.clone()),
                stretch_encryption_key: commit.tree_encryption_key_stretched,
                storage_type: 0,
                archive_id: None,
                archive_size: 0,
                archive_upload_date: None,
            };
            match blob_key_to_blob_loc(
                &tree_key,
                commit.tree_compression_type,
                &tree_index_db,
                &tree_packset_rel,
            ) {
                Ok(loc) => Some(loc),
                Err(e) => {
                    tracing::warn!("bucket {bucket_uuid}: could not build root tree blob loc: {e}");
                    None
                }
            }
        } else {
            None
        };

        let record = BackupRecord {
            timestamp: commit.creation_date_ms.unwrap_or(0) / 1000,
            root_tree_blob_loc: root_blob_loc,
            local_path: local_path.clone(),
            arq_version: commit.arq_version.clone().unwrap_or_else(|| "arq5".to_owned()),
            is_complete: commit.is_complete,
        };

        let mut records = vec![record];

        // Walk the parent commit chain (like git history) to collect all
        // historical snapshots, not just HEAD.
        walk_arq5_commit_chain(
            &commit,
            backup_path,
            &tree_index_db,
            &tree_packset_dir,
            &tree_packset_rel,
            keys,
            &bucket_uuid,
            &local_path,
            &mut records,
        );

        eprintln!(
            "  bucket {bucket_uuid}: {local_path} — {} snapshot(s)",
            records.len()
        );

        results.push((bucket_uuid, local_path, records));
    }

    Ok(results)
}

/// Walk the Arq5 parent commit chain starting from `commit`, appending a
/// [`BackupRecord`] for each historical snapshot.
///
/// Arq5 commits form a singly-linked list (like git): each commit has
/// `parent_commits` with SHA1 references to older commits. We follow the
/// chain until we reach a commit with no parents (the initial backup).
///
/// Errors resolving individual parent commits are warned and stop the chain
/// walk — we keep whatever records we've already collected.
#[allow(clippy::too_many_arguments)]
fn walk_arq5_commit_chain(
    head_commit: &Arq5Commit,
    backup_path: &Path,
    tree_index_db: &PackIndexDb,
    tree_packset_dir: &Path,
    tree_packset_rel: &str,
    keys: &Arq5Keys,
    bucket_uuid: &str,
    local_path: &str,
    records: &mut Vec<BackupRecord>,
) {
    use format::arq5::Arq5BlobKey;

    let mut current_parents = head_commit.parent_commits.clone();
    let mut seen = std::collections::HashSet::new();

    loop {
        // Take the first parent (Arq5 typically has 0 or 1 parent per commit).
        let parent_sha1 = match current_parents.first().and_then(|p| p.sha1.as_deref()) {
            Some(sha) if !sha.is_empty() => sha.to_string(),
            _ => break, // No more parents — end of chain.
        };

        // Guard against cycles (shouldn't happen, but be defensive).
        if !seen.insert(parent_sha1.clone()) {
            tracing::warn!("bucket {bucket_uuid}: cycle detected at commit {parent_sha1}");
            break;
        }

        // Resolve, decrypt, decompress, parse the parent commit.
        let commit_raw = match resolve_arq5_object(
            backup_path,
            &parent_sha1,
            tree_index_db,
            tree_packset_dir,
            keys,
        ) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(
                    "bucket {bucket_uuid}: stopping chain walk at {parent_sha1}: {e:#}"
                );
                break;
            }
        };

        let commit_bytes = match decompress_arq5_auto(&commit_raw) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    "bucket {bucket_uuid}: decompress failed for commit {parent_sha1}: {e:#}"
                );
                break;
            }
        };

        let commit = match Arq5Commit::parse(&commit_bytes) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    "bucket {bucket_uuid}: parse failed for commit {parent_sha1}: {e:#}"
                );
                break;
            }
        };

        // Build a BlobLoc for this commit's root tree.
        let root_blob_loc = if let Some(ref tree_sha1) = commit.tree_sha1 {
            let tree_key = Arq5BlobKey {
                sha1: Some(tree_sha1.clone()),
                stretch_encryption_key: commit.tree_encryption_key_stretched,
                storage_type: 0,
                archive_id: None,
                archive_size: 0,
                archive_upload_date: None,
            };
            match blob_key_to_blob_loc(
                &tree_key,
                commit.tree_compression_type,
                tree_index_db,
                tree_packset_rel,
            ) {
                Ok(loc) => Some(loc),
                Err(e) => {
                    tracing::warn!(
                        "bucket {bucket_uuid}: could not build root tree blob loc for commit {parent_sha1}: {e}"
                    );
                    None
                }
            }
        } else {
            None
        };

        records.push(BackupRecord {
            timestamp: commit.creation_date_ms.unwrap_or(0) / 1000,
            root_tree_blob_loc: root_blob_loc,
            local_path: local_path.to_string(),
            arq_version: commit.arq_version.unwrap_or_else(|| "arq5".to_owned()),
            is_complete: commit.is_complete,
        });

        current_parents = commit.parent_commits;
    }
}

// ---------------------------------------------------------------------------
// Arq5 object resolution helpers
// ---------------------------------------------------------------------------

/// Resolve and decrypt an Arq5 object by SHA1. Tries standalone objects first,
/// then pack index.
fn resolve_arq5_object(
    backup_path: &Path,
    sha1: &str,
    tree_index_db: &PackIndexDb,
    tree_packset_dir: &Path,
    keys: &Arq5Keys,
) -> Result<Vec<u8>> {
    if sha1.len() < 2 {
        bail!("SHA1 too short: {sha1}");
    }
    let prefix = &sha1[..2];
    let rest = &sha1[2..];
    let standalone_path = backup_path.join("objects").join(prefix).join(rest);

    let raw = if standalone_path.exists() {
        std::fs::read(&standalone_path)
            .with_context(|| format!("reading standalone object {}", standalone_path.display()))?
    } else if let Some((pack_id, offset, length)) = tree_index_db.lookup(sha1) {
        let pack_path = tree_packset_dir.join(format!("{pack_id}.pack"));
        let pack_data = std::fs::read(&pack_path)
            .with_context(|| format!("reading pack {}", pack_path.display()))?;
        extract_from_arq5_pack(&pack_data, offset as usize, length as usize)?
    } else {
        bail!("Arq5 object {sha1} not found in standalone objects or pack indexes");
    };

    let arqo = strip_encrypted_prefix(&raw);
    decrypt_arq5_object(arqo, keys).context("decrypting Arq5 object")
}

/// Extract an object from an Arq5 pack file at the given offset/length.
///
/// Tries two strategies:
/// 1. Direct: if `ARQO` or `encrypted` magic appears at the offset, take `length` bytes directly.
/// 2. Header-parse: skip the per-entry header (mimetype + name + data_len) and return the data.
fn extract_from_arq5_pack(pack_data: &[u8], offset: usize, length: usize) -> Result<Vec<u8>> {
    // Strategy 1: ARQO/encrypted magic directly at offset
    if offset + 9 <= pack_data.len()
        && (pack_data[offset..].starts_with(b"ARQO")
            || pack_data[offset..].starts_with(b"encrypted"))
    {
        let end = offset + length;
        anyhow::ensure!(end <= pack_data.len(), "offset+length exceeds pack size");
        return Ok(pack_data[offset..end].to_vec());
    }

    // Strategy 2: Parse pack entry header (mimetype + name + data_len + data).
    let entry = &pack_data[offset..];
    let mut pos = 0;

    // Skip mimetype string (Arq encoding: 1 byte null flag + opt u64 len + bytes)
    if entry[pos] == 0 {
        pos += 1;
    } else {
        pos += 1;
        let len = u64::from_be_bytes(entry[pos..pos + 8].try_into()?) as usize;
        pos += 8 + len;
    }
    // Skip name string
    if entry[pos] == 0 {
        pos += 1;
    } else {
        pos += 1;
        let len = u64::from_be_bytes(entry[pos..pos + 8].try_into()?) as usize;
        pos += 8 + len;
    }
    // Read data_len + data
    let data_len = u64::from_be_bytes(entry[pos..pos + 8].try_into()?) as usize;
    pos += 8;
    let data_start = offset + pos;
    let data_end = data_start + data_len;
    anyhow::ensure!(
        data_end <= pack_data.len(),
        "pack data extends past end: data_start={data_start}, data_len={data_len}, pack_size={}",
        pack_data.len()
    );
    Ok(pack_data[data_start..data_end].to_vec())
}

// ---------------------------------------------------------------------------
// Arq5 decompression helpers
// ---------------------------------------------------------------------------

/// Decompress Arq5 data by explicitly given compression type.
///
/// Type 0 = uncompressed, 1 = gzip, 2 = LZ4 (size-prepended).
fn decompress_arq5(data: &[u8], compression_type: i32) -> Result<Vec<u8>> {
    match compression_type {
        0 => Ok(data.to_vec()),
        1 => {
            use std::io::Read;
            let mut decoder = flate2::read::GzDecoder::new(data);
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .context("gzip decompression")?;
            Ok(out)
        }
        2 => lz4_flex::decompress_size_prepended(data)
            .map_err(|e| anyhow::anyhow!("LZ4 decompression: {e}")),
        other => bail!("unknown Arq5 compression type: {other}"),
    }
}

/// Auto-detect decompression for commit objects (detect gzip by magic bytes).
fn decompress_arq5_auto(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        return decompress_arq5(data, 1);
    }
    Ok(data.to_vec())
}

// ---------------------------------------------------------------------------
// Pack index loading helpers
// ---------------------------------------------------------------------------

/// Load pack indexes from `dir`, using the persistent cache when available.
fn load_pack_indexes_cached(dir: &Path, packset_key: &str) -> Result<PackIndexDb> {
    let cache_path = default_pack_index_cache_path();
    let t0 = std::time::Instant::now();
    if let Some(db) = PackIndexDb::load_cache(&cache_path, packset_key)? {
        eprintln!(
            "  Pack index cache hit: {} entries ({:.2}s)",
            db.total_entries(),
            t0.elapsed().as_secs_f64()
        );
        return Ok(db);
    }
    eprintln!("  Loading pack indexes from storage...");
    let mut db = PackIndexDb::new();
    load_pack_indexes_from_dir(dir, &mut db)?;
    let elapsed = t0.elapsed().as_secs_f64();
    eprintln!("  Loaded {} entries ({:.1}s)", db.total_entries(), elapsed);
    db.save_cache(&cache_path, packset_key)?;
    Ok(db)
}

/// Default path for the persistent pack index cache database.
fn default_pack_index_cache_path() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("arqfastrestore")
        .join("pack_indexes.redb")
}

/// Load all `.index` files from a packset directory into a [`PackIndexDb`].
fn load_pack_indexes_from_dir(dir: &Path, db: &mut PackIndexDb) -> Result<usize> {
    use format::PackIndex;

    if !dir.exists() {
        return Ok(0);
    }

    let mut count = 0;
    let entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("reading packset dir {}", dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .context("iterating packset dir")?;

    for entry in &entries {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".index") {
            continue;
        }
        let pack_id = name.trim_end_matches(".index").to_string();
        let data = std::fs::read(entry.path())
            .with_context(|| format!("reading index {}", entry.path().display()))?;
        let index =
            PackIndex::parse(&data, pack_id).with_context(|| format!("parsing index {name}"))?;
        db.add_index(index);
        count += 1;
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract a string value for a key from an XML or binary plist.
///
/// Works for XML plists by finding `<key>K</key>...<string>V</string>`.
fn extract_plist_string(data: &[u8], key: &str) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    let needle = format!("<key>{key}</key>");
    let idx = text.find(&needle)?;
    let after = &text[idx + needle.len()..];
    let start = after.find("<string>")? + "<string>".len();
    let end = after.find("</string>")?;
    Some(after[start..end].to_owned())
}

/// Default path for the persistent tree cache database.
///
/// Uses the platform cache directory (`~/.cache/arqfastrestore/trees.redb` on Linux,
/// `~/Library/Caches/arqfastrestore/trees.redb` on macOS, etc.).
fn default_cache_path() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("arqfastrestore")
        .join("trees.redb")
}

/// Open the tree cache unless `no_cache` is set.
fn open_tree_cache(
    no_cache: bool,
    cache_path: Option<String>,
    verbose: bool,
) -> Result<Option<TreeCache>> {
    if no_cache {
        return Ok(None);
    }
    let path = cache_path
        .map(PathBuf::from)
        .unwrap_or_else(default_cache_path);
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        tracing::warn!(
            "could not create cache directory {:?}: {e} — continuing without cache",
            parent
        );
    }
    match TreeCache::open(&path) {
        Ok(c) => {
            if verbose {
                eprintln!("tree_cache.path={}", path.display());
            }
            Ok(Some(c))
        }
        Err(e) => {
            tracing::warn!(
                "could not open tree cache at {:?}: {e} — continuing without cache",
                path
            );
            Ok(None)
        }
    }
}

/// Print restore completion statistics.
fn print_restore_stats(stats: &RestoreStats, dry_run: bool) {
    let label = if dry_run {
        "dry-run complete"
    } else {
        "complete"
    };
    if stats.files_failed > 0 {
        println!(
            "Restore {label}: {} files, {} dirs, {} bytes ({} items failed — missing or corrupt)",
            stats.files_restored, stats.dirs_created, stats.bytes_written, stats.files_failed
        );
    } else {
        println!(
            "Restore {label}: {} files, {} dirs, {} bytes",
            stats.files_restored, stats.dirs_created, stats.bytes_written
        );
    }
}

/// List all backup folders across all plan-UUID subdirectories in the backup
/// root, as well as the root itself (to handle single-plan layouts).
///
/// Returns `(folder_uuid, local_path, Vec<BackupRecord>)` tuples.
fn list_backup_folders_all_plans(
    storage: &LocalStorage,
    keys: Option<&Arq7Keys>,
) -> Result<Vec<(String, String, Vec<BackupRecord>)>> {
    use crate::storage::Storage;

    // Try the root as a plan directory first (some Arq setups put backupfolders/
    // directly under the backup root).
    let mut results = Vec::new();

    let root_entries = storage.list("").unwrap_or_default();

    // If there's a `backupfolders` directory at the root, treat the root as the
    // plan directory.
    if root_entries.iter().any(|e| e == "backupfolders") {
        let folders = list_all_backup_folders(storage, "", keys).unwrap_or_else(|e| {
            tracing::warn!("failed to list root plan: {e}");
            vec![]
        });
        results.extend(folders);
    }

    // Also descend into any UUID-like subdirectories (plan directories).
    for entry in &root_entries {
        if entry == "backupfolders" {
            continue; // already handled above
        }
        // Heuristic: plan directories look like UUIDs (contain hyphens).
        if !entry.contains('-') {
            continue;
        }
        // Check if this subdirectory contains a `backupfolders` sub-directory.
        let sub_entries = storage.list(entry).unwrap_or_default();
        if sub_entries.iter().any(|e| e == "backupfolders") {
            let folders = list_all_backup_folders(storage, entry, keys).unwrap_or_else(|e| {
                tracing::warn!("failed to list plan {entry}: {e}");
                vec![]
            });
            results.extend(folders);
        }
    }

    Ok(results)
}

/// Returns true if `dir` looks like an Arq UUID backup directory
/// (contains `encryptedkeyset.dat`, `backupfolders`, or `encryptionv2.dat`).
fn is_uuid_backup_dir(dir: &Path) -> bool {
    dir.join("encryptedkeyset.dat").exists()
        || dir.join("backupfolders").exists()
        || dir.join("encryptionv2.dat").exists()
}

/// Discover all UUID backup subdirectories under `parent`.
///
/// A UUID dir is any subdirectory that passes [`is_uuid_backup_dir`].
fn discover_uuid_dirs(parent: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return vec![];
    };
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir() && is_uuid_backup_dir(p))
        .collect();
    dirs.sort();
    dirs
}

/// Return type alias for `build_scan_context`.
/// `(folders, decrypt, parse_tree, plan_meta, storage_root_override)` where:
/// - `plan_meta` maps folder_uuid → (computer_name, backup_name)
/// - `storage_root_override` is Some(path) when this backup set needs a
///   different storage root than the parent directory (Arq5 case)
type ScanContext = (
    Vec<(String, String, Vec<BackupRecord>)>,
    Option<DecryptFn>,
    TreeParseFn,
    std::collections::HashMap<String, (String, String)>,
    Option<PathBuf>,  // per-UUID storage root override (Arq5)
);

/// Build the folder list, decrypt function, tree-parse function, and plan
/// metadata map needed for a scan run.
fn build_scan_context(
    bp: &Path,
    backup_path: &str,
    fmt: BackupFormat,
) -> Result<ScanContext> {
    // Plan UUID is the directory name of backup_path.
    let plan_uuid = bp
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    match fmt {
        BackupFormat::Arq7(keys) => {
            let storage = LocalStorage::new(backup_path);
            let folders = list_backup_folders_all_plans(&storage, Some(&keys))?;
            // Build plan_meta: folder_uuid → (computer_name, backup_name).
            // backupconfig.json lives at the plan root (backup_path), keyed by plan_uuid.
            let (computer_name, backup_name) = read_backup_config(&storage, "");
            let mut plan_meta = std::collections::HashMap::new();
            for (folder_uuid, _, _) in &folders {
                plan_meta.insert(folder_uuid.clone(), (computer_name.clone(), backup_name.clone()));
            }
            // Also store under plan_uuid itself for lookup convenience.
            plan_meta.insert(plan_uuid, (computer_name, backup_name));
            let decrypt: Option<DecryptFn> = Some(Arc::new(move |data: &[u8]| {
                decrypt_arq7_object(data, &keys)
            }));
            use crate::format::arq7::Tree;
            let parse_tree: TreeParseFn = Arc::new(|data: &[u8]| Tree::parse(data));
            Ok((folders, decrypt, parse_tree, plan_meta, None))
        }
        BackupFormat::Unencrypted => {
            let storage = LocalStorage::new(backup_path);
            let folders = list_backup_folders_all_plans(&storage, None)?;
            let (computer_name, backup_name) = read_backup_config(&storage, "");
            let mut plan_meta = std::collections::HashMap::new();
            for (folder_uuid, _, _) in &folders {
                plan_meta.insert(folder_uuid.clone(), (computer_name.clone(), backup_name.clone()));
            }
            plan_meta.insert(plan_uuid, (computer_name, backup_name));
            use crate::format::arq7::Tree;
            let parse_tree: TreeParseFn = Arc::new(|data: &[u8]| Tree::parse(data));
            Ok((folders, None, parse_tree, plan_meta, None))
        }
        BackupFormat::Arq5(keys) => {
            // List buckets — each becomes one folder entry with one BackupRecord.
            let folders = list_arq5_buckets(bp, &keys)?;
            if folders.is_empty() {
                anyhow::bail!("no Arq5 buckets found in {backup_path}");
            }

            // For Arq5, read computer name from the `computerinfo` plist in the plan root.
            let (computer_name, _user_name) = read_arq5_computer_info(&LocalStorage::new(backup_path));
            let computer_name = if computer_name.is_empty() { plan_uuid.clone() } else { computer_name };
            let backup_name = String::from("Arq5 backup");
            let mut plan_meta = std::collections::HashMap::new();
            for (folder_uuid, _, _) in &folders {
                plan_meta.insert(folder_uuid.clone(), (computer_name.clone(), backup_name.clone()));
            }
            plan_meta.insert(plan_uuid.clone(), (computer_name, backup_name));

            // Build per-bucket parse_tree closures.  Each bucket has its own pack
            // indexes.  We build a single unified parse_tree that covers all buckets
            // by loading all pack indexes up front.
            let keys_clone = keys.clone();
            let decrypt: Option<DecryptFn> = Some(Arc::new(move |data: &[u8]| {
                let arqo = format::arq5_adapter::strip_encrypted_prefix(data);
                decrypt_arq5_object(arqo, &keys_clone)
            }));

            // Build a combined parse_tree that handles all buckets.
            // For each bucket, load tree + blob pack indexes, then merge into a
            // single closure that tries each bucket's indexes in order.
            let mut all_tree_dbs: Vec<(Arc<PackIndexDb>, String)> = Vec::new();
            let mut all_blob_dbs: Vec<(Arc<PackIndexDb>, String)> = Vec::new();
            let computer_uuid = plan_uuid.clone();

            for (bucket_uuid, _, _) in &folders {
                let tree_packset_rel = format!("packsets/{bucket_uuid}-trees");
                let blob_packset_rel = format!("packsets/{bucket_uuid}-blobs");
                let tree_packset_dir = bp.join(&tree_packset_rel);
                let blob_packset_dir = bp.join(&blob_packset_rel);
                let packset_key_trees = format!("{computer_uuid}-{bucket_uuid}-trees");
                let packset_key_blobs = format!("{computer_uuid}-{bucket_uuid}-blobs");

                if let Ok(db) = load_pack_indexes_cached(&tree_packset_dir, &packset_key_trees) {
                    all_tree_dbs.push((Arc::new(db), tree_packset_rel));
                }
                if let Ok(db) = load_pack_indexes_cached(&blob_packset_dir, &packset_key_blobs) {
                    all_blob_dbs.push((Arc::new(db), blob_packset_rel));
                }
            }

            let all_tree_dbs = Arc::new(all_tree_dbs);
            let all_blob_dbs = Arc::new(all_blob_dbs);
            let _keys_for_parse = keys.clone();

            let parse_tree: TreeParseFn = Arc::new(move |data: &[u8]| {
                let arq5_tree = Arq5Tree::parse(data)?;
                // Try each bucket's blob/tree pack index until one resolves.
                let mut last_err = anyhow::anyhow!("no pack index found for Arq5 tree blob");
                for ((blob_db, blob_dir), (tree_db, tree_dir)) in
                    all_blob_dbs.iter().zip(all_tree_dbs.iter())
                {
                    match format::arq5_adapter::arq5_tree_to_tree(
                        &arq5_tree,
                        blob_db,
                        blob_dir,
                        tree_db,
                        tree_dir,
                    ) {
                        Ok(tree) => return Ok(tree),
                        Err(e) => last_err = e,
                    }
                }
                Err(last_err)
            });

            // Arq5 storage root is the UUID dir itself (BlobLoc paths are relative to it).
            let storage_root_override = Some(bp.to_path_buf());
            Ok((folders, decrypt, parse_tree, plan_meta, storage_root_override))
        }
    }
}

/// How `restore-path --record` picks a backup record.
#[derive(Debug, PartialEq, Eq)]
enum RecordSelector {
    Latest,
    Timestamp(u64),
    /// Newest record with timestamp strictly before the instant.
    Before(u64),
    /// Record closest to the instant (ties go to the earlier one).
    Near(u64),
}

fn parse_record_selector(s: &str) -> Result<RecordSelector> {
    if s == "latest" {
        return Ok(RecordSelector::Latest);
    }
    if let Some(t) = s.strip_prefix("before:") {
        return Ok(RecordSelector::Before(parse_rfc3339(t)?));
    }
    if let Some(t) = s.strip_prefix("near:") {
        return Ok(RecordSelector::Near(parse_rfc3339(t)?));
    }
    s.parse::<u64>()
        .map(RecordSelector::Timestamp)
        .map_err(|_| anyhow::anyhow!("--record must be a timestamp, 'latest', 'before:<rfc3339>' or 'near:<rfc3339>', got '{s}'"))
}

fn select_record_by<'a>(
    folders: &'a [(String, String, Vec<BackupRecord>)],
    sel: &RecordSelector,
) -> Option<&'a BackupRecord> {
    let all = folders
        .iter()
        .flat_map(|(_, _, rs)| rs.iter())
        .filter(|r| r.root_tree_blob_loc.is_some());
    match *sel {
        RecordSelector::Latest => all.max_by_key(|r| r.timestamp),
        RecordSelector::Timestamp(t) => all.into_iter().find(|r| r.timestamp == t),
        RecordSelector::Before(t) => all.filter(|r| r.timestamp < t).max_by_key(|r| r.timestamp),
        // Key puts the earlier record first on a tie (Reverse timestamp as tiebreak).
        RecordSelector::Near(t) => all.min_by_key(|r| (r.timestamp.abs_diff(t), r.timestamp)),
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Format Unix seconds as `YYYY-MM-DDTHH:MM:SSZ` (UTC).
fn format_rfc3339(ts: u64) -> String {
    let days = (ts / 86400) as i64;
    let rem = ts % 86400;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.frac](Z|+HH:MM|-HH:MM)` to Unix seconds.
fn parse_rfc3339(s: &str) -> Result<u64> {
    let err = || anyhow::anyhow!("invalid RFC 3339 time '{s}' (want e.g. 2026-11-01T12:50:00Z)");
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !(b[10] == b'T' || b[10] == b't' || b[10] == b' ') || b[13] != b':' || b[16] != b':' {
        return Err(err());
    }
    let num = |a: usize, z: usize| -> Result<i64> { s.get(a..z).and_then(|t| t.parse().ok()).ok_or_else(err) };
    let (y, mo, d, h, mi, sec) = (num(0, 4)?, num(5, 7)?, num(8, 10)?, num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return Err(err());
    }
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
    }
    let offset = match &s[i..] {
        "Z" | "z" => 0,
        o if o.len() == 6 && (o.starts_with('+') || o.starts_with('-')) && &o[3..4] == ":" => {
            let hh: i64 = o[1..3].parse().map_err(|_| err())?;
            let mm: i64 = o[4..6].parse().map_err(|_| err())?;
            let v = hh * 3600 + mm * 60;
            if o.starts_with('-') { -v } else { v }
        }
        _ => return Err(err()),
    };
    let t = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + sec - offset;
    u64::try_from(t).map_err(|_| err())
}

#[allow(clippy::too_many_arguments)]
fn restore_path_arq7(
    backup_path: &str,
    keys: Option<Arq7Keys>,
    record_sel: &str,
    rel_path: &str,
    dest: &str,
    dry_run: bool,
    cache_path: Option<String>,
    no_cache: bool,
) -> Result<()> {
    let sel = parse_record_selector(record_sel)?;
    let storage = LocalStorage::new(backup_path);
    let folders = list_backup_folders_all_plans(&storage, keys.as_ref())?;
    let record = select_record_by(&folders, &sel)
        .with_context(|| format!("no backup record matches --record {record_sel}"))?;
    println!(
        "Record timestamp={} date={} folder={} complete={}",
        record.timestamp,
        format_rfc3339(record.timestamp),
        record.local_path,
        record.is_complete
    );
    let root_loc = record.root_tree_blob_loc.as_ref().context("record has no root tree")?;

    // Same layout rule as restore_arq7: blob relativePaths include the plan UUID dir.
    let blob_storage_root = PathBuf::from(backup_path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(backup_path));
    let storage_arc: Arc<dyn storage::Storage> = Arc::new(LocalStorage::new(&blob_storage_root));
    let decrypt: Option<DecryptFn> =
        keys.map(|k| -> DecryptFn { Arc::new(move |data: &[u8]| decrypt_arq7_object(data, &k)) });
    use crate::format::arq7::Tree;
    let parse_tree: TreeParseFn = Arc::new(|data: &[u8]| Tree::parse(data));
    let cache = open_tree_cache(no_cache, cache_path, false)?;

    let reader = storage::BlobReader::new(storage_arc.clone(), decrypt.clone());
    let items = restore::collect_path_items(
        &reader,
        root_loc,
        rel_path,
        Path::new(dest),
        cache.as_ref(),
        &indicatif::ProgressBar::hidden(),
        &parse_tree,
    )?;
    for it in &items {
        println!(
            "  {} ({} bytes){}",
            it.dest_path.display(),
            it.node.item_size,
            if it.node.is_tree { " [dir]" } else { "" }
        );
    }

    let engine = RestoreEngine::new(storage_arc, decrypt, PathBuf::from(dest), dry_run, false, cache, parse_tree, 1);
    let stats = engine.restore_items(items)?;
    print_restore_stats(&stats, dry_run);
    if stats.files_failed > 0 {
        bail!("{} item(s) failed to restore", stats.files_failed);
    }
    Ok(())
}

/// Select the backup record matching the given timestamp, or the most recent
/// record if `timestamp` is `None`.
fn select_record(
    folders: &[(String, String, Vec<BackupRecord>)],
    timestamp: Option<u64>,
) -> Option<&BackupRecord> {
    let mut all_records = folders.iter().flat_map(|(_, _, records)| records.iter());

    match timestamp {
        Some(ts) => all_records.find(|r| r.timestamp == ts),
        None => all_records.max_by_key(|r| r.timestamp),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::arq7::BackupRecord;

    fn make_record(ts: u64) -> BackupRecord {
        BackupRecord {
            timestamp: ts,
            root_tree_blob_loc: None,
            local_path: format!("/path/{ts}"),
            arq_version: "7.0".to_owned(),
            is_complete: true,
        }
    }

    #[test]
    fn rfc3339_roundtrip_and_offsets() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(parse_rfc3339("2026-11-01T12:50:00Z").unwrap(), 1793537400);
        assert_eq!(format_rfc3339(1793537400), "2026-11-01T12:50:00Z");
        assert_eq!(parse_rfc3339("2026-11-01T13:50:00.5+01:00").unwrap(), 1793537400);
        assert_eq!(format_rfc3339(951782400), "2000-02-29T00:00:00Z");
        assert!(parse_rfc3339("2026-13-01T00:00:00Z").is_err());
        assert!(parse_rfc3339("yesterday").is_err());
    }

    #[test]
    fn record_selectors() {
        let folders = vec![("u".to_owned(), "/x".to_owned(), vec![make_record(100), make_record(200), make_record(300)])];
        let mut folders = folders;
        for r in &mut folders[0].2 {
            r.root_tree_blob_loc = Some(crate::format::arq7::BlobLoc {
                identifier: "x".into(), is_packed: false, is_large_pack: false, relative_path: None,
                offset: 0, length: 0, stretch_encryption_key: false, compression_type: 0, is_arq5_pack_entry: false,
            });
        }
        let pick = |s: &str| select_record_by(&folders, &parse_record_selector(s).unwrap()).map(|r| r.timestamp);
        assert_eq!(pick("latest"), Some(300));
        assert_eq!(pick("200"), Some(200));
        assert_eq!(pick("before:1970-01-01T00:04:20Z"), Some(200));
        assert_eq!(pick("before:1970-01-01T00:01:40Z"), None); // strictly before 100
        assert_eq!(pick("near:1970-01-01T00:02:30Z"), Some(100)); // tie -> earlier
        assert!(parse_record_selector("soon").is_err());
    }

    #[test]
    fn select_most_recent() {
        let folders = vec![
            (
                "uuid1".to_owned(),
                "/foo".to_owned(),
                vec![make_record(100), make_record(200)],
            ),
            (
                "uuid2".to_owned(),
                "/bar".to_owned(),
                vec![make_record(300)],
            ),
        ];
        let record = select_record(&folders, None).unwrap();
        assert_eq!(record.timestamp, 300);
    }

    #[test]
    fn select_by_timestamp() {
        let folders = vec![(
            "uuid1".to_owned(),
            "/foo".to_owned(),
            vec![make_record(100), make_record(200), make_record(300)],
        )];
        let record = select_record(&folders, Some(200)).unwrap();
        assert_eq!(record.timestamp, 200);
    }

    #[test]
    fn select_missing_timestamp_returns_none() {
        let folders = vec![(
            "uuid1".to_owned(),
            "/foo".to_owned(),
            vec![make_record(100)],
        )];
        assert!(select_record(&folders, Some(999)).is_none());
    }

    #[test]
    fn select_empty_returns_none() {
        let folders: Vec<(String, String, Vec<BackupRecord>)> = vec![];
        assert!(select_record(&folders, None).is_none());
    }

    #[test]
    fn extract_plist_string_xml() {
        let xml = br#"<?xml version="1.0"?><plist><dict>
<key>BucketName</key><string>MyBucket</string>
<key>LocalPath</key><string>/home/user/docs</string>
</dict></plist>"#;
        assert_eq!(
            extract_plist_string(xml, "BucketName"),
            Some("MyBucket".to_owned())
        );
        assert_eq!(
            extract_plist_string(xml, "LocalPath"),
            Some("/home/user/docs".to_owned())
        );
        assert_eq!(extract_plist_string(xml, "Missing"), None);
    }

    #[test]
    fn decompress_arq5_none() {
        let data = b"hello world";
        let out = decompress_arq5(data, 0).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn decompress_arq5_unknown_type() {
        let err = decompress_arq5(b"data", 99).unwrap_err();
        assert!(err.to_string().contains("unknown Arq5 compression type"));
    }

    #[test]
    fn extract_from_arq5_pack_arqo_magic() {
        // Build a fake pack: padding, then ARQO data at offset 4
        let mut pack = vec![0u8; 4];
        pack.extend_from_slice(b"ARQO");
        pack.extend_from_slice(&[0xAB; 20]);
        let result = extract_from_arq5_pack(&pack, 4, 24).unwrap();
        assert_eq!(&result[..4], b"ARQO");
        assert_eq!(result.len(), 24);
    }

    #[test]
    fn extract_from_arq5_pack_encrypted_magic() {
        let mut pack = vec![0u8; 10];
        pack.extend_from_slice(b"encrypted");
        pack.extend_from_slice(&[0xCD; 5]);
        // At offset 10, "encrypted" (9 bytes) + 5 bytes = 14 bytes total
        let result = extract_from_arq5_pack(&pack, 10, 14).unwrap();
        assert_eq!(&result[..9], b"encrypted");
    }
}
