// SPDX-License-Identifier: MIT
//! Sequential tree walker for Arq backups.
//!
//! Walks tree blobs recursively, **streaming** [`RestoreItem`]s over a channel
//! as they are discovered. This keeps RAM usage bounded to O(tree_depth ×
//! branching_factor) instead of O(total_items), which is critical for large
//! backups (e.g. 149 K items would OOM at 4–6 GB if buffered in a Vec).
//!
//! The walker runs on a dedicated thread; the restore engine reads from the
//! channel and processes items in parallel via rayon's `par_bridge()`.
//! Subtrees are walked **sequentially** to avoid disk thrashing on spinning
//! disks / network storage. The file *restore* phase (engine.rs) is still
//! parallel — that's where parallelism actually helps since it writes to a
//! fast local disk.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Sender;

use anyhow::{Context, Result};
use indicatif::ProgressBar;
use tracing::warn;

use crate::format::arq7::{BlobLoc, Node, Tree};
use crate::restore::tree_cache::TreeCache;
use crate::storage::BlobReader;

/// A pluggable tree-parsing function.
///
/// Given raw (decrypted, decompressed) tree blob bytes, returns a parsed [`Tree`].
/// Arq7 closures call `Tree::parse()`; Arq5 closures parse an `Arq5Tree` and
/// convert it via the adapter layer.
pub type TreeParseFn = Arc<dyn Fn(&[u8]) -> Result<Tree> + Send + Sync>;

/// Global counter for trees parsed (progress feedback during walk phase).
static TREES_PARSED: AtomicUsize = AtomicUsize::new(0);

/// A file or directory to be restored.
#[derive(Debug)]
pub struct RestoreItem {
    /// Absolute destination path on the output filesystem.
    pub dest_path: PathBuf,
    /// The parsed node (contains metadata + blob locs).
    pub node: Node,
}

/// Walk an Arq tree recursively, sending [`RestoreItem`]s over `tx` as they
/// are discovered.
///
/// - `blob_reader`: reads and decrypts/decompresses blobs from backup storage
/// - `root_tree_blob_loc`: the [`BlobLoc`] of the root tree blob
/// - `dest_root`: absolute path where files will be restored
/// - `cache`: optional persistent tree cache (redb); speeds up repeated walks
/// - `tx`: channel to stream [`RestoreItem`]s to the restore phase
/// - `pb`: progress bar to update as trees are parsed (pass a spinner from engine)
/// - `parse_tree`: pluggable function that parses raw tree blob bytes into a [`Tree`]
///
/// Items are emitted depth-first. Send errors (receiver dropped) cause the
/// walk to stop early (treated as a warning, not a fatal error).
pub fn walk_tree(
    blob_reader: &BlobReader,
    root_tree_blob_loc: &BlobLoc,
    dest_root: &Path,
    cache: Option<&TreeCache>,
    tx: &Sender<RestoreItem>,
    pb: &ProgressBar,
    parse_tree: &TreeParseFn,
) -> Result<()> {
    let tree_id = &root_tree_blob_loc.identifier;

    // --- 1. Read and parse the tree blob at this level (cache-aware) ---
    let tree = read_tree(blob_reader, root_tree_blob_loc, cache, parse_tree)?;

    let count = TREES_PARSED.fetch_add(1, Ordering::Relaxed) + 1;
    pb.set_position(count as u64);

    // --- 2. Iterate nodes, skipping deleted entries ---
    let mut subtrees: Vec<(BlobLoc, PathBuf)> = Vec::new();

    for (name, node) in tree.nodes {
        if node.deleted {
            continue;
        }

        let item_dest = dest_root.join(&name);

        // Queue subtree recursion before the node is moved into RestoreItem.
        if node.is_tree
            && let Some(ref subtree_loc) = node.tree_blob_loc
        {
            subtrees.push((subtree_loc.clone(), item_dest.clone()));
        }

        // Stream item to the restore phase immediately.
        if tx
            .send(RestoreItem {
                dest_path: item_dest,
                node,
            })
            .is_err()
        {
            // Receiver was dropped (e.g. restore phase aborted early).
            warn!("restore channel closed — stopping tree walk for '{tree_id}'");
            return Ok(());
        }
    }

    // --- 3. Recurse into subtrees sequentially ---
    // Sequential is better for I/O-bound tree reads (spinning disk, SMB, S3).
    // Parallel random seeks cause disk thrashing and are slower than sequential.
    for (blob_loc, path) in subtrees {
        if let Err(e) = walk_tree(blob_reader, &blob_loc, &path, cache, tx, pb, parse_tree) {
            warn!("skipping subtree '{path}': {e:#}", path = path.display());
        }
    }

    Ok(())
}

/// Read and parse a single tree blob, using the cache if available.
pub(crate) fn read_tree(
    blob_reader: &BlobReader,
    loc: &BlobLoc,
    cache: Option<&TreeCache>,
    parse_tree: &TreeParseFn,
) -> Result<Tree> {
    let tree_id = &loc.identifier;
    if let Some(c) = cache
        && let Some(cached) = c.get(tree_id)
    {
        return Ok(cached);
    }

    let bytes = blob_reader
        .read_blob(loc)
        .with_context(|| format!("reading tree blob '{tree_id}'"))?;
    let parsed = (parse_tree)(&bytes).with_context(|| format!("parsing tree blob '{tree_id}'"))?;

    if let Some(c) = cache {
        c.put(tree_id, &parsed);
    }

    Ok(parsed)
}

/// Reset the global tree counter (used between test runs / multiple restores).
pub fn reset_tree_counter() {
    TREES_PARSED.store(0, Ordering::Relaxed);
}
