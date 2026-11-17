# arqfastrestore

Fast, parallel restore tool for [Arq](https://www.arqbackup.com/) backups. Supports both Arq5 and Arq7 backup formats, AES-CBC encryption, and multiple compression algorithms (LZ4, zlib, zstd).

## Features

- **Arq5 and Arq7 support** — reads both backup formats, including full Arq5 snapshot history
- **Encrypted backups** — AES-CBC with HMAC-SHA1/SHA256, PBKDF2 key derivation
- **Sort-by-pack restore** — sorts all files by pack location before restoring, achieving ~1× read amplification (vs 13× naive)
- **Parallel restore** — configurable pack concurrency via Rayon
- **Multiple compression formats** — LZ4, zlib/gzip, zstd
- **Timestamp preservation** — restores mtime/atime from backup metadata
- **Unix permissions** — restores file modes (owner/group/other rwx + sticky/setuid/setgid)
- **Scan command** — walks all snapshots across all backup sets, emits a deduplicated CSV for review before restoring
- **Progress bar** — live progress with ETA during restore (suppressed automatically when not a TTY)
- **List backups** — inspect available backup records without restoring
- **Password file** — `--password-file` reads passwords from a file (one per line) to avoid shell quoting issues with special characters
- **jemalloc** — bounded RSS under heavy allocation workloads

## Installation

```bash
cargo build --release
# Binary at: target/release/arqfastrestore
```

## Usage

### List backup records

```bash
arqfastrestore list --backup-path /path/to/backup --password "your-password"
```

### Scan: find files across all snapshots

The `scan` command is designed for the common recovery workflow: *"I know I had some files — find them across all my backups so I can decide what to restore."*

It walks every snapshot in every backup set, collects file metadata, deduplicates by content hash, and emits a CSV. You review the CSV (e.g. in Excel), mark rows `restore`, and then run `restore --from-csv` to efficiently restore exactly what you selected.

```bash
arqfastrestore scan \
  --backup-path /path/to/B2Sync2/ \
  --password "pass1,pass2,pass3" \
  --filter "*.mov,*.mp4,*.jpg,*.jpeg,*.heic,*.png,*.pdf" \
  > scan_results.csv
```

`--backup-path` can point to a single UUID backup directory or a parent directory
containing multiple UUID subdirectories — all are discovered and scanned automatically.
`--password` accepts a comma-separated list; each is tried against each UUID directory.

Use `--password-file /path/to/file` instead of `--password` to avoid quoting special characters. The file should contain one password per line. `--password` and `--password-file` are mutually exclusive.

#### Scan CSV format

The CSV has one row per unique `(path, blob_sha)` pair — the same file content at the
same path across 300 snapshots appears as one row, not 300.

| Column | Description |
|--------|-------------|
| `source_root` | Original backup root path (e.g. `/C/Users/steve/Videos`) |
| `computer_name` | Hostname from the backup config |
| `backup_name` | Backup set name |
| `path` | File path relative to the backup folder root |
| `size_bytes` | File size |
| `mtime` | Last-modified timestamp (UTC) |
| `blob_sha` | SHA-256 of the file's first data blob (used to distinguish versions for `restore-from-csv`) |
| `sources` | Semicolon-separated backup UUID(s) containing this file |
| `first_seen` | Unix timestamp of earliest snapshot with this content |
| `last_seen` | Unix timestamp of most recent snapshot with this content |
| `snapshot_count` | Approximate number of snapshots containing this version |
| `path_count` | How many distinct versions exist for this path (1 = never changed) |
| `sha_count` | How many paths share this exact content (useful for detecting duplicates) |
| `action` | Fill this in: `restore` to restore, leave blank to skip |

#### Workflow

1. Run `scan` with `--filter` for the file types you care about, redirect to a CSV file.
2. Open in Excel or Google Sheets. Sort by `path`, `size_bytes`, or `last_seen`.
3. For files you want back, set `action` to `restore`. For files with multiple versions
   (`path_count > 1`), review each row and mark the version(s) you want.
4. Save the CSV and run `restore-from-csv`. It matches rows by `(path, blob_sha)`, so if
   a file changed over time, the selected historical version is restored rather than always
   taking the newest snapshot.

#### Scan performance

The scan uses a persistent tree cache (same redb database as the restore tree cache).
The first run reads every tree blob from storage; subsequent runs are nearly instant for
unchanged subtrees. A `visited_trees` set per backup folder ensures that unchanged
directory subtrees shared across hundreds of snapshots are walked only once.

On a 680-snapshot corpus (304 Arq5 + 376 Arq7) with ~555K unique files, a warm-cache
scan completes in under 5 minutes at ~38 snapshots/second.

### Restore one file or folder from one record (Arq7)

`list` prints each record's date. `restore-path` reads only the trees along the path.

```bash
arqfastrestore restore-path \
  --backup-path /path/to/plan-uuid --password-file /path/to/pw \
  --record before:2026-11-01T12:50:00Z \
  --path src/project/file.json --dest /tmp/out --cache-path /tmp/trees.redb --dry-run
```

`--record` is a Unix timestamp, `latest`, `before:<rfc3339>` (newest record strictly before) or `near:<rfc3339>`.
The relative path is recreated under `--dest`. Drop `--dry-run` to write.

### Restore a backup

```bash
arqfastrestore restore \
  --backup-path /path/to/backup \
  --password "your-password" \
  --dest /path/to/restore/destination
```

#### Options

| Flag | Description |
|------|-------------|
| `--backup-path` / `-b` | Path to the Arq backup folder |
| `--password` / `-p` | Backup encryption password |
| `--password-file` | Path to a file containing one password per line (alternative to `--password`) |
| `--dest` / `-d` | Destination directory for restored files |
| `--timestamp` | Restore a specific snapshot (by Unix timestamp) |
| `--threads` | Number of parallel worker threads (default: all CPUs) |
| `--pack-concurrency` | Pack groups to process in parallel (default: 1; use 4–8 for SSDs) |
| `--dry-run` | Validate without writing any files |
| `--verbose` | Print detailed timing and I/O statistics after restore |
| `--cache-path` | Override tree cache location (default: `~/.cache/arqfastrestore/`) |
| `--no-cache` | Disable persistent tree cache |

### Examples

```bash
# List available backups
arqfastrestore list --backup-path /mnt/backup/MyBackup --password "hunter2"

# Restore latest snapshot
arqfastrestore restore \
  --backup-path /mnt/backup/MyBackup \
  --password "hunter2" \
  --dest /tmp/restored

# Restore a specific snapshot
arqfastrestore restore \
  --backup-path /mnt/backup/MyBackup \
  --password "hunter2" \
  --dest /tmp/restored \
  --timestamp 1700000000

# Scan all backup sets for media files (passwords in a file, one per line)
arqfastrestore scan \
  --backup-path /mnt/backup/ \
  --password-file /path/to/passwords.txt \
  --filter "*.mov,*.mp4,*.jpg,*.heic" \
  > media_scan.csv
```

## Performance

### vs official arqrestore

The [official open-source arqrestore](https://github.com/arqbackup/arq_restore) (Objective-C) has two restore paths with different characteristics:

- **Arq7:** `Arq7Restorer` is fully **single-threaded** — one blocking recursive tree walk, one blob read, one decryption, one file write, all sequential.
- **Arq5/6:** `StandardRestorer` uses **4 worker threads** with a lock-protected LIFO work queue, providing some parallelism during tree traversal.

Neither path has pack-aware I/O sorting, persistent caching, or parallel snapshot walking.

arqfastrestore rewrites the restore pipeline from scratch:

| | Official arqrestore | arqfastrestore |
|---|---|---|
| **Parallelism** | Single-threaded (Arq7) / 4 threads (Arq5/6) | Rayon thread pool, configurable concurrency |
| **Pack I/O** | Per-blob range reads, no pack caching | Sort-by-pack for sequential access; 512 MB in-memory cache |
| **Read amplification** | ~13× on large backups | ~1× (near-zero seeks) |
| **Caching** | In-memory only, per-run | Persistent redb cache (trees + pack indexes) |
| **Tree walk** | Blocking recursive traversal | Parallel across snapshots (Rayon) + persistent cache |
| **Memory** | Buffers full files | Streaming writes, O(blob_size) memory |
| **Allocator** | System malloc | jemalloc (bounded RSS under heavy allocation) |

### Benchmarks

**DDDDDDDD — 394 GB, 126,859 files, ~4,350 packs** (native ZFS over USB 3.0):

| Run | `--pack-concurrency` | Wall time | Read amplification | Storage read |
|-----|---------------------|-----------|-------------------|--------------|
| Old (no sort-by-pack) | — | 49m 29s | ~12.9× (est.) | ~278 GB |
| Sort-by-pack | 1 | **22m 19s** | **0.92×** | 103.7 GB |
| Sort-by-pack | 4 | 11m 37s | 2.53× | 283 GB |

`--pack-concurrency 1` achieves near-perfect sequential reads at ~75 MB/s with 12 ms disk latency. `--pack-concurrency 4` is 2× faster on wall time but causes cache thrashing on spinning HDDs (4,752 packs re-read due to 512 MB cache being insufficient for ~8 GB of unique pack data at that concurrency). For spinning disks, `--pack-concurrency 1` is recommended.

**CCCCCCCC — 32 GB, 13,324 files, 26 packs** (native ZFS, warm cache):

| Run | Wall time | Cache hit rate | Read amplification |
|-----|-----------|----------------|--------------------|
| Cold (no cache) | 94s | — | — |
| Warm (tree cache hit) | **7s** | 99.8% | 0.80× |

Warm-cache small backups complete in seconds. The tree cache is automatically maintained at `~/.cache/arqfastrestore/trees.redb`.

### How it works

#### Three-phase restore pipeline

1. **Tree walk (parallel):** For `restore-from-csv`, all snapshots for a given backup set are walked in parallel using Rayon — each snapshot gets its own thread and `BlobReader`. Results are merged by selecting the newest-snapshot match per file. This can saturate all CPU cores on decrypt-heavy workloads (AES-CBC + HMAC per tree blob). For full-backup restores via `restore`, a single sequential walk is used since full-tree traversal is I/O-bound rather than CPU-bound.

2. **Sort by pack:** All discovered files are sorted by `(pack_path, offset)`. Files sharing a pack are grouped together so each pack file is read exactly once from start to finish — converting random I/O into a linear sequential scan. This is the primary reason read amplification drops from ~13× to ~1×.

3. **File restore (parallel):** Pack groups are processed with configurable concurrency. Within each group, files are decrypted, decompressed, and written using streaming I/O. Use `--pack-concurrency` to control how many pack groups are in flight simultaneously.

#### Pack file cache

Arq stores file chunks in large pack files (typically 5–50 MB each), with many small files sharing a single pack. arqfastrestore caches full pack files in memory (512 MB by default) so that if multiple files share a pack, it is read from storage exactly once. An `OnceLock`-per-slot design prevents thundering-herd re-reads when multiple threads need the same pack.

On small backups this achieves a 99%+ cache hit rate. For large backups, sort-by-pack ordering means each pack is processed before it could be evicted, so the cache primarily serves as a read buffer.

#### Tree cache

On the first run, arqfastrestore parses every directory tree object from storage and writes them to a persistent local cache (`~/.cache/arqfastrestore/trees.redb`). On subsequent runs the tree walk completes in seconds instead of minutes, since no storage I/O is needed for directory metadata.

The cache is keyed by content hash, so it automatically stays valid across restores of the same backup. Use `--no-cache` to disable it, or `--cache-path` to relocate it.

Cache writes are batched per snapshot (one `fdatasync` per snapshot rather than per tree object), which avoids the performance cliff of thousands of individual fsync calls during a first-run scan.

#### Arq5 snapshot history

For Arq5 backups, arqfastrestore walks the full commit chain (like `git log`) rather than only reading the HEAD snapshot. A single Arq5 bucket may contain hundreds of historical snapshots linked as a parent-commit chain. The `scan` command benefits from this most: it can find files that existed in older Arq5 snapshots and have since been deleted.

#### Arq5 pack index cache

For Arq5 backups, pack indexes (which map file SHA1 hashes to pack file locations) must be loaded at startup. A large backup may have 16,000+ index files. arqfastrestore caches the merged index in redb, reducing startup from ~5 minutes to ~2 seconds on subsequent runs.

### Performance tuning

| Flag | Default | Effect |
|------|---------|--------|
| `--threads N` | all CPUs | Rayon worker threads for parallel file restore. Reduce if restoring to a slow disk where parallelism hurts more than it helps. |
| `--pack-concurrency N` | 1 | Pack groups to process in parallel. Use 1 (default) for spinning disks / SMB to avoid seek overhead. Use 4–8 for SSDs or fast network storage to keep the CPU pipeline saturated. |
| `--no-cache` | off | Disables the persistent tree cache. Useful if the cache is stale or you want a clean run. |
| `--cache-path PATH` | `~/.cache/arqfastrestore/` | Relocate the tree and pack index cache, e.g. to a fast local SSD when restoring from a remote share. |

The in-memory pack cache size (currently hardcoded at 512 MB) is not yet configurable via CLI.

## Architecture

```
src/
  lib.rs                     — Library facade (re-exports all modules)
  main.rs                    — CLI entry point (list + scan + restore subcommands)
  crypto/
    mod.rs                   — Re-exports Arq5Keys, Arq7Keys, decrypt_* functions
    arq5.rs                  — Arq5 key derivation (PBKDF2-SHA1) + ARQO decryption
    arq7.rs                  — Arq7 key derivation (PBKDF2-SHA256) + ARQO decryption
  format/
    mod.rs                   — Re-exports all format types
    primitives.rs            — Big-endian binary reader
    arq5.rs                  — Arq5 parsers: PackIndex, Commit, Tree, Node, pack files
    arq7.rs                  — Arq7 parsers: BlobLoc, Node, Tree, BackupRecord
    arq5_adapter.rs          — Converts Arq5 types → Arq7 types for unified pipeline
    backup_record.rs         — BackupRecord enumeration and parsing
  storage/
    mod.rs                   — Storage trait (blob I/O abstraction)
    local.rs                 — LocalStorage (filesystem-backed)
    blob_reader.rs           — BlobReader (decrypt + decompress + 512MB pack cache)
  restore/
    mod.rs                   — Module exports
    engine.rs                — RestoreEngine (three-phase sort-by-pack parallel restore)
    tree_walker.rs           — Sequential DFS tree walker
    tree_cache.rs            — Persistent redb-backed tree cache (with batch writes)
  scan/
    mod.rs                   — Scan engine: walk all snapshots, emit deduplicated CSV
```

See `codemap.md` for detailed module documentation and data flow diagrams.

## Development

```bash
# Run tests
cargo test

# Run a single test
cargo test process_item_writes_file

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt
```

## License

MIT
