// SPDX-License-Identifier: MIT
//! Single-path restore: descend one path through a backup record's tree and
//! collect only the [`RestoreItem`]s under it.
//!
//! Only the trees on the path (plus the subtree, if the target is a folder)
//! are read, so restoring one file from a large backup touches a handful of
//! tree blobs instead of walking the whole record.

use std::path::Path;
use std::sync::mpsc::channel;

use anyhow::{Result, bail};
use indicatif::ProgressBar;

use crate::format::arq7::BlobLoc;
use crate::restore::tree_cache::TreeCache;
use crate::restore::tree_walker::{RestoreItem, TreeParseFn, read_tree, walk_tree};
use crate::storage::BlobReader;

/// Split a user-supplied path into components, ignoring empty and `.` parts.
/// `..` is rejected so a path can never escape the destination directory.
pub fn split_rel_path(rel_path: &str) -> Result<Vec<&str>> {
    let mut comps = Vec::new();
    for c in rel_path.split('/') {
        match c {
            "" | "." => {}
            ".." => bail!("path may not contain '..': {rel_path}"),
            c => comps.push(c),
        }
    }
    if comps.is_empty() {
        bail!("path is empty");
    }
    Ok(comps)
}

/// Walk `rel_path` down from `root_loc` and return the items to restore.
///
/// Items land at `dest_root/<rel_path>` (the relative path is preserved so two
/// restores of same-named files from different folders cannot collide).
/// For a file the result is one item; for a folder it is the folder plus all
/// descendants. Fails with the names available at the point where the path
/// stops matching, so a typo or a moved folder is easy to diagnose.
pub fn collect_path_items(
    blob_reader: &BlobReader,
    root_loc: &BlobLoc,
    rel_path: &str,
    dest_root: &Path,
    cache: Option<&TreeCache>,
    pb: &ProgressBar,
    parse_tree: &TreeParseFn,
) -> Result<Vec<RestoreItem>> {
    let comps = split_rel_path(rel_path)?;
    let mut loc = root_loc.clone();
    let mut dest = dest_root.to_path_buf();
    let mut walked = String::new();

    for (i, comp) in comps.iter().enumerate() {
        let tree = read_tree(blob_reader, &loc, cache, parse_tree)?;
        let found = tree
            .nodes
            .into_iter()
            .find(|(name, node)| name == comp && !node.deleted);
        let Some((name, node)) = found else {
            // Names were consumed by into_iter; re-read (cached/cheap) for the message.
            let tree = read_tree(blob_reader, &loc, cache, parse_tree)?;
            let mut names: Vec<&str> = tree
                .nodes
                .iter()
                .filter(|(_, n)| !n.deleted)
                .map(|(n, _)| n.as_str())
                .collect();
            names.sort_unstable();
            let shown = names.iter().take(40).copied().collect::<Vec<_>>().join(", ");
            bail!(
                "'{comp}' not found under '/{walked}' ({} entries: {shown}{})",
                names.len(),
                if names.len() > 40 { ", ..." } else { "" }
            );
        };
        dest = dest.join(&name);
        walked = if walked.is_empty() { name } else { format!("{walked}/{name}") };

        if i + 1 == comps.len() {
            if node.is_tree {
                let Some(sub) = node.tree_blob_loc.clone() else {
                    bail!("folder '{walked}' has no tree blob");
                };
                let (tx, rx) = channel::<RestoreItem>();
                let dir_item = RestoreItem {
                    dest_path: dest.clone(),
                    node,
                };
                walk_tree(blob_reader, &sub, &dest, cache, &tx, pb, parse_tree)?;
                drop(tx);
                let mut items = vec![dir_item];
                items.extend(rx);
                return Ok(items);
            }
            return Ok(vec![RestoreItem {
                dest_path: dest,
                node,
            }]);
        }

        if !node.is_tree {
            bail!("'{walked}' is a file, not a folder");
        }
        let Some(next) = node.tree_blob_loc else {
            bail!("folder '{walked}' has no tree blob");
        };
        loc = next;
    }
    unreachable!("comps is non-empty and the last component returns")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::format::arq7::{Node, Tree};
    use crate::storage::Storage;

    /// Storage whose "blob" for a path is just the path bytes, so the test
    /// parse function can map a tree blob's path to a canned [`Tree`].
    struct EchoStorage;
    impl Storage for EchoStorage {
        fn read(&self, path: &str) -> Result<Vec<u8>> {
            Ok(path.as_bytes().to_vec())
        }
        fn list(&self, _: &str) -> Result<Vec<String>> {
            Ok(vec![])
        }
        fn exists(&self, _: &str) -> Result<bool> {
            Ok(true)
        }
    }

    fn loc(path: &str) -> BlobLoc {
        BlobLoc {
            identifier: path.to_owned(),
            is_packed: false,
            is_large_pack: false,
            relative_path: Some(path.to_owned()),
            offset: 0,
            length: 0,
            stretch_encryption_key: false,
            compression_type: 0,
            is_arq5_pack_entry: false,
        }
    }

    fn dir(path: &str) -> Node {
        Node { is_tree: true, tree_blob_loc: Some(loc(path)), ..Default::default() }
    }

    fn file(size: u64) -> Node {
        Node { item_size: size, ..Default::default() }
    }

    fn parse() -> TreeParseFn {
        Arc::new(|bytes: &[u8]| {
            let nodes = match bytes {
                b"root" => vec![("a".to_owned(), dir("a")), ("f.txt".to_owned(), file(1))],
                b"a" => vec![("b.json".to_owned(), file(2)), ("sub".to_owned(), dir("sub"))],
                b"sub" => vec![("c".to_owned(), file(3))],
                _ => bail!("unknown tree"),
            };
            Ok(Tree { version: 2, nodes })
        })
    }

    fn run(path: &str) -> Result<Vec<RestoreItem>> {
        let reader = BlobReader::new(Arc::new(EchoStorage), None);
        collect_path_items(
            &reader,
            &loc("root"),
            path,
            Path::new("/d"),
            None,
            &ProgressBar::hidden(),
            &parse(),
        )
    }

    #[test]
    fn single_file_keeps_relative_path() {
        let items = run("a/b.json").unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].dest_path, Path::new("/d/a/b.json"));
        assert_eq!(items[0].node.item_size, 2);
    }

    #[test]
    fn folder_returns_dir_and_descendants() {
        let items = run("/a/").unwrap();
        let mut paths: Vec<_> = items.iter().map(|i| i.dest_path.to_string_lossy().into_owned()).collect();
        paths.sort();
        assert_eq!(paths, ["/d/a", "/d/a/b.json", "/d/a/sub", "/d/a/sub/c"]);
    }

    #[test]
    fn missing_component_lists_siblings() {
        let err = run("a/nope").unwrap_err().to_string();
        assert!(err.contains("'nope' not found under '/a'"), "{err}");
        assert!(err.contains("b.json"), "{err}");
    }

    #[test]
    fn file_in_middle_and_dotdot_rejected() {
        assert!(run("f.txt/x").unwrap_err().to_string().contains("is a file"));
        assert!(split_rel_path("a/../b").is_err());
        assert!(split_rel_path("//").is_err());
    }
}
