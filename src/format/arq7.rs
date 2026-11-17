// SPDX-License-Identifier: MIT
//! Arq7 on-disk format structures.
//!
//! BackupRecord: LZ4-compressed plist + optional ARQO encryption.
//! Tree binary: [u32:version][u64:count]([String:name][Node])×count
//! Node binary: see official docs at https://www.arqbackup.com/documentation/arq7/English.lproj/dataFormat.html
//!
//! BlobLoc binary:
//!   [String:identifier] [Bool:isPacked]
//!   [Bool:isLargePack]  /* if tree_version >= 2 */
//!   [String:relativePath]
//!   [u64:offset] [u64:length] [Bool:stretchEncryptionKey] [u32:compressionType]

use crate::format::primitives::Reader;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

// OS type constants
#[allow(dead_code)]
pub const OS_TYPE_MAC: u8 = 1;
#[allow(dead_code)]
pub const OS_TYPE_WINDOWS: u8 = 2;

/// Location of a blob, either in a pack file or as a standalone object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobLoc {
    /// SHA256 hex identifier
    pub identifier: String,
    /// If true, the blob is in a pack file
    pub is_packed: bool,
    /// If true, the blob is in a large-file pack (tree_version >= 2 only)
    pub is_large_pack: bool,
    /// Relative path to the pack file (if packed) or blob file (may be null)
    pub relative_path: Option<String>,
    /// Byte offset within the pack file (0 if not packed)
    pub offset: u64,
    /// Byte length of the blob
    pub length: u64,
    /// Whether to use stretched encryption key (always true for new data)
    pub stretch_encryption_key: bool,
    /// Compression type: 0=none, 1=Gzip (legacy), 2=LZ4
    pub compression_type: u32,
    /// If true, the offset points to an Arq5 pack entry header that must be
    /// stripped (mimetype + name + data_len prefix) before decrypting/decompressing.
    pub is_arq5_pack_entry: bool,
}

impl BlobLoc {
    pub fn parse(r: &mut Reader, tree_version: u32) -> Result<Self> {
        let identifier = r.read_string_required().context("BlobLoc identifier")?;
        let is_packed = r.read_bool().context("BlobLoc is_packed")?;
        let is_large_pack = if tree_version >= 2 {
            r.read_bool().context("BlobLoc is_large_pack")?
        } else {
            false
        };
        let relative_path = r.read_string().context("BlobLoc relative_path")?;
        let offset = r.read_u64_be().context("BlobLoc offset")?;
        let length = r.read_u64_be().context("BlobLoc length")?;
        let stretch_encryption_key = r.read_bool().context("BlobLoc stretchEncryptionKey")?;
        let compression_type = r.read_u32_be().context("BlobLoc compressionType")?;
        Ok(Self {
            identifier,
            is_packed,
            is_large_pack,
            relative_path,
            offset,
            length,
            stretch_encryption_key,
            compression_type,
            is_arq5_pack_entry: false,
        })
    }
}

/// A node in an Arq7 tree (either a file or directory).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Node {
    pub is_tree: bool,
    /// If is_tree, the BlobLoc pointing to the subtree blob
    pub tree_blob_loc: Option<BlobLoc>,
    pub computer_os_type: u32,
    /// Data blob locations (for files; may be multiple for large files)
    pub data_blob_locs: Vec<BlobLoc>,
    /// ACL blob location (optional)
    pub acl_blob_loc: Option<BlobLoc>,
    /// Extended attribute blob locations
    pub xattrs_blob_locs: Vec<BlobLoc>,
    pub item_size: u64,
    pub contained_files_count: u64,
    /// Modification time seconds
    pub mtime_sec: i64,
    /// Modification time nanoseconds
    pub mtime_nsec: i64,
    /// Change time seconds
    pub ctime_sec: i64,
    /// Change time nanoseconds
    pub ctime_nsec: i64,
    /// Creation time seconds
    pub create_time_sec: i64,
    /// Creation time nanoseconds
    pub create_time_nsec: i64,
    pub username: Option<String>,
    pub group_name: Option<String>,
    pub deleted: bool,
    pub mac_st_dev: i32,
    pub mac_st_ino: u64,
    pub mac_st_mode: u32,
    pub mac_st_nlink: u32,
    pub mac_st_uid: u32,
    pub mac_st_gid: u32,
    pub mac_st_rdev: i32,
    pub mac_st_flags: i32,
    pub win_attrs: u32,
    /// Present if tree_version >= 2
    pub win_reparse_tag: Option<u32>,
    pub win_reparse_point_is_directory: Option<bool>,
}

impl Node {
    pub fn parse(r: &mut Reader, tree_version: u32, has_reparse: bool) -> Result<Self> {
        let is_tree = r.read_bool().context("Node is_tree")?;

        let tree_blob_loc = if is_tree {
            Some(BlobLoc::parse(r, tree_version).context("Node tree_blob_loc")?)
        } else {
            None
        };

        let computer_os_type = r.read_u32_be().context("Node computer_os_type")?;

        let data_blob_count = r.read_u64_be().context("Node data_blob_count")?;
        let mut data_blob_locs = Vec::with_capacity(data_blob_count as usize);
        for i in 0..data_blob_count {
            data_blob_locs.push(
                BlobLoc::parse(r, tree_version)
                    .with_context(|| format!("Node data_blob_loc[{i}]"))?,
            );
        }

        let acl_blob_loc_is_not_nil = r.read_bool().context("Node acl_blob_loc_is_not_nil")?;
        let acl_blob_loc = if acl_blob_loc_is_not_nil {
            Some(BlobLoc::parse(r, tree_version).context("Node acl_blob_loc")?)
        } else {
            None
        };

        let xattrs_count = r.read_u64_be().context("Node xattrs_count")?;
        let mut xattrs_blob_locs = Vec::with_capacity(xattrs_count as usize);
        for i in 0..xattrs_count {
            xattrs_blob_locs.push(
                BlobLoc::parse(r, tree_version)
                    .with_context(|| format!("Node xattrs_blob_loc[{i}]"))?,
            );
        }

        let item_size = r.read_u64_be().context("Node item_size")?;
        let contained_files_count = r.read_u64_be().context("Node contained_files_count")?;
        let mtime_sec = r.read_i64_be().context("Node mtime_sec")?;
        let mtime_nsec = r.read_i64_be().context("Node mtime_nsec")?;
        let ctime_sec = r.read_i64_be().context("Node ctime_sec")?;
        let ctime_nsec = r.read_i64_be().context("Node ctime_nsec")?;
        let create_time_sec = r.read_i64_be().context("Node create_time_sec")?;
        let create_time_nsec = r.read_i64_be().context("Node create_time_nsec")?;

        let username = r.read_string().context("Node username")?;
        let group_name = r.read_string().context("Node group_name")?;

        let deleted = r.read_bool().context("Node deleted")?;
        let mac_st_dev = r.read_i32_be().context("Node mac_st_dev")?;
        let mac_st_ino = r.read_u64_be().context("Node mac_st_ino")?;
        let mac_st_mode = r.read_u32_be().context("Node mac_st_mode")?;
        let mac_st_nlink = r.read_u32_be().context("Node mac_st_nlink")?;
        let mac_st_uid = r.read_u32_be().context("Node mac_st_uid")?;
        let mac_st_gid = r.read_u32_be().context("Node mac_st_gid")?;
        let mac_st_rdev = r.read_i32_be().context("Node mac_st_rdev")?;
        let mac_st_flags = r.read_i32_be().context("Node mac_st_flags")?;
        let win_attrs = r.read_u32_be().context("Node win_attrs")?;

        let (win_reparse_tag, win_reparse_point_is_directory) = if has_reparse {
            let tag = r.read_u32_be().context("Node win_reparse_tag")?;
            let is_dir = r
                .read_bool()
                .context("Node win_reparse_point_is_directory")?;
            (Some(tag), Some(is_dir))
        } else {
            (None, None)
        };

        // Tree version >= 4 appends added-time, document id and sparse-file
        // fields (see Arq 7 dataFormat.html). They are parsed only to stay in
        // step with the byte stream; restore does not use them (sparse-file
        // holes are NOT reconstructed; fine for ordinary files).
        if tree_version >= 4 {
            r.read_i64_be().context("Node added_time_sec")?;
            r.read_i64_be().context("Node added_time_nsec")?;
            r.read_u32_be().context("Node document_id")?;
            r.read_bool().context("Node has_document_id")?;
            r.read_bool().context("Node is_sparse")?;
            r.read_u64_be().context("Node sparse_logical_size")?;
            let hole_count = r.read_u64_be().context("Node hole_count")?;
            for i in 0..hole_count {
                r.read_u64_be()
                    .with_context(|| format!("Node hole_offset[{i}]"))?;
                r.read_u64_be()
                    .with_context(|| format!("Node hole_length[{i}]"))?;
            }
        }

        Ok(Self {
            is_tree,
            tree_blob_loc,
            computer_os_type,
            data_blob_locs,
            acl_blob_loc,
            xattrs_blob_locs,
            item_size,
            contained_files_count,
            mtime_sec,
            mtime_nsec,
            ctime_sec,
            ctime_nsec,
            create_time_sec,
            create_time_nsec,
            username,
            group_name,
            deleted,
            mac_st_dev,
            mac_st_ino,
            mac_st_mode,
            mac_st_nlink,
            mac_st_uid,
            mac_st_gid,
            mac_st_rdev,
            mac_st_flags,
            win_attrs,
            win_reparse_tag,
            win_reparse_point_is_directory,
        })
    }
}

/// A parsed Arq7 tree (directory listing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tree {
    pub version: u32,
    /// (name, node) pairs
    pub nodes: Vec<(String, Node)>,
}

impl Tree {
    /// Parse a decrypted+decompressed tree blob.
    ///
    /// The official arq_restore source gates reparse fields on tree_version >= 2,
    /// but real-world backups created by older Arq7 versions may have tree_version=2
    /// WITHOUT reparse fields. We try with reparse first; if that fails or leaves
    /// unconsumed bytes, we retry without reparse.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let version = r.read_u32_be().context("Tree version")?;
        let count = r.read_u64_be().context("Tree node count")?;

        if version >= 2 {
            // Save position after header so we can retry.
            let header_end = r.position();

            // Attempt 1: parse WITH reparse fields.
            match Self::parse_nodes(&mut r, version, count, true) {
                Ok(nodes) if r.is_empty() => return Ok(Self { version, nodes }),
                _ => {}
            }

            // Attempt 2: rewind and parse WITHOUT reparse fields.
            r.set_position(header_end);
            let nodes = Self::parse_nodes(&mut r, version, count, false)
                .context("Tree::parse failed both with and without reparse fields")?;
            Ok(Self { version, nodes })
        } else {
            // tree_version < 2 never has reparse fields.
            let nodes = Self::parse_nodes(&mut r, version, count, false)?;
            Ok(Self { version, nodes })
        }
    }

    /// Parse `count` (name, node) pairs from the reader.
    fn parse_nodes(
        r: &mut Reader,
        version: u32,
        count: u64,
        has_reparse: bool,
    ) -> Result<Vec<(String, Node)>> {
        let mut nodes = Vec::with_capacity(count as usize);
        for i in 0..count {
            let pos_before_name = r.position();
            let name = r.read_string_required().with_context(|| {
                format!("Tree node {i} name (at byte offset {pos_before_name})")
            })?;
            let node =
                Node::parse(r, version, has_reparse).with_context(|| format!("Tree node {i}"))?;
            nodes.push((name, node));
        }
        Ok(nodes)
    }
}

/// Metadata from a backup record (Arq7). Parsed from the plist.
#[derive(Debug, Clone)]
pub struct BackupRecord {
    /// Unix epoch seconds of the backup (creationDate field)
    pub timestamp: u64,
    /// BlobLoc of the root tree (from node.treeBlobLoc)
    pub root_tree_blob_loc: Option<BlobLoc>,
    /// Local path that was backed up
    pub local_path: String,
    /// Arq version string
    pub arq_version: String,
    /// Whether this backup is complete
    pub is_complete: bool,
}

/// Decompress an Arq7 LZ4-framed blob.
///
/// Format: 4-byte BE uncompressed length + LZ4 block data.
pub fn decompress_lz4(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 4 {
        bail!("LZ4 data too short: {} bytes", data.len());
    }
    let uncompressed_len = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
    let compressed = &data[4..];
    let out =
        lz4_flex::decompress(compressed, uncompressed_len).context("LZ4 decompression failed")?;
    Ok(out)
}

/// Decompress a blob based on compressionType value.
/// 0=none, 1=Gzip (legacy Arq5 reuse), 2=LZ4
pub fn decompress_blob(data: &[u8], compression_type: u32) -> Result<Vec<u8>> {
    match compression_type {
        0 => Ok(data.to_vec()),
        1 => {
            use std::io::Read;
            let mut decoder = flate2::read::GzDecoder::new(data);
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .context("Gzip decompression failed")?;
            Ok(out)
        }
        2 => decompress_lz4(data),
        3 => zstd::decode_all(data).context("zstd decompression failed"),
        other => bail!("unknown compression type {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lz4_too_short() {
        assert!(decompress_lz4(&[0, 0]).is_err());
    }

    #[test]
    fn roundtrip_lz4() {
        let original = b"hello world hello world hello world";
        let be_len = (original.len() as u32).to_be_bytes();
        let raw_compressed = lz4_flex::compress(original);
        let mut framed = be_len.to_vec();
        framed.extend_from_slice(&raw_compressed);
        let decompressed = decompress_lz4(&framed).unwrap();
        assert_eq!(decompressed, original);
    }
}
