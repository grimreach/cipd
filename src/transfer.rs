//! Whole-program **upload** (read every PLC file) over PCCC.
//!
//! Source discipline: this module is built ONLY from the decoded AP-01 Wireshark
//! capture (ACPAC `docs/ladder/pccc-upload-download.md`, 12 Nov 2026) and the
//! public DF1/PCCC command set — never guessed. It reuses the spec engine's
//! `0F A2` framing (`pccc::slc_typed_read_addr` + `Device::pccc`); it does not
//! re-implement CIP/PCCC wrapping.
//!
//! What the capture showed for an upload: 413 protected-typed-logical-reads
//! (CMD 0x0F FNC 0xA2), one file at a time, each read addressed as
//! `size, file#, type, element, sub-element` (a byte, or `FF lo hi` when > 254),
//! reassembled into that file's bytes. The *type codes seen on the wire* are
//! (from `ops/wire/pccc-files.py`): O=0x82 I=0x83 S=0x84 B=0x85 T=0x86 C=0x87
//! R=0x88 N=0x89 F=0x8A ST=0x8D L=0x91 MG=0x92 RIX=0x96; plus system/program/
//! config files by their own codes. (These wire codes differ from the logical
//! address-path codes in `pccc::file_type_info` for O/I — upload uses the wire
//! codes, so the manifest carries the raw type byte and this module never maps.)
//!
//! Scope of this version: **upload only** (read-only, safe on any PLC). The file
//! set + element counts are supplied as a manifest — exactly what
//! `pccc-files.py` emits from a capture — because the type-0x03 directory layout
//! that RSLogix reads first to enumerate files is not decoded yet. A later
//! version can build the manifest from that directory. Download is NOT here: it
//! is gated on four still-unknown pieces (0x03 directory build, 0F 88/8F payloads,
//! the doubled 0x47/0x49/0x4D writes, the mode change) and on the bench PLC.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU16, Ordering};

use crate::error::{Error, Result};
use crate::pccc::{self, SlcAddress, WordType};
use crate::router::Device;

/// SLC per-request byte cap (matches `Device::ml_read`).
pub const MAX_READ_BYTES: u16 = 240;

/// One file to read during an upload: its wire type code, number, and geometry.
/// This is the shape `ops/wire/pccc-files.py` reports per file.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FileSpec {
    /// Wire type code as seen in the `0F A2` address (e.g. 0x89 for N).
    pub file_type: u8,
    pub file_number: u16,
    /// Number of elements in the file.
    pub elements: u16,
    /// Bytes per element (N/B/O/I/S=2, F/L=4, T/C/R=6, ST=84, MG=50, ...).
    pub element_bytes: u16,
}

impl FileSpec {
    /// Total byte length of the reassembled file.
    pub fn total_bytes(&self) -> usize {
        self.elements as usize * self.element_bytes as usize
    }
}

/// A single `0F A2` read: starting element and byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadOp {
    pub element: u16,
    pub size: u8,
}

/// Split a file into element-aligned reads that each fit under `max_bytes`.
///
/// Pure and deterministic — this is the part proven by unit test; the wire I/O
/// around it is a thin loop. Returns an error if a single element exceeds the
/// per-request cap (no real ML1400 file element does; ST at 84 bytes is the
/// largest), rather than guessing a sub-element split.
pub fn plan_reads(spec: &FileSpec, max_bytes: u16) -> Result<Vec<ReadOp>> {
    if spec.element_bytes == 0 {
        return Err(Error::Protocol("file element_bytes = 0".into()));
    }
    if spec.element_bytes > max_bytes || spec.element_bytes > 255 {
        return Err(Error::Protocol(format!(
            "element of {} bytes exceeds the {max_bytes}-byte read cap",
            spec.element_bytes
        )));
    }
    let per_chunk = (max_bytes / spec.element_bytes).max(1);
    let mut ops = Vec::new();
    let mut e = 0u16;
    while e < spec.elements {
        let n = per_chunk.min(spec.elements - e);
        let size = (n * spec.element_bytes) as u8; // guaranteed <= max_bytes <= 255
        ops.push(ReadOp { element: e, size });
        e += n;
    }
    Ok(ops)
}

/// Reassemble read replies in order, verifying the total matches the file.
pub fn reassemble(spec: &FileSpec, chunks: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(spec.total_bytes());
    for c in chunks {
        out.extend_from_slice(c);
    }
    if out.len() != spec.total_bytes() {
        return Err(Error::Protocol(format!(
            "file type 0x{:02x} #{}: reassembled {} bytes, expected {}",
            spec.file_type,
            spec.file_number,
            out.len(),
            spec.total_bytes()
        )));
    }
    Ok(out)
}

/// A raw address for an upload read (no logical letter/decode — the manifest
/// already carries the wire type code).
fn read_addr(file_type: u8, file_number: u16, element: u16) -> SlcAddress {
    SlcAddress {
        letter: String::new(),
        file_number,
        file_type,
        element,
        sub_element: 0,
        has_sub: false,
        bit: None,
        element_size: 0,
        word_type: WordType::Raw,
    }
}

/// One uploaded file: its spec and reassembled bytes.
#[derive(Debug, Clone, Serialize)]
pub struct UploadedFile {
    pub file_type: u8,
    pub file_number: u16,
    pub bytes: Vec<u8>,
}

/// Monotonic transaction nonce for an upload. Independent of the device's own
/// counter; safe because every read below is issued and awaited serially.
#[derive(Default)]
pub struct Tns(AtomicU16);

impl Tns {
    pub fn next(&self) -> u16 {
        let v = self.0.fetch_add(1, Ordering::Relaxed);
        if v == 0 {
            self.0.fetch_add(1, Ordering::Relaxed)
        } else {
            v
        }
    }
}

/// Read one whole file by issuing the planned `0F A2` reads and reassembling.
pub async fn read_file(device: &Device, tns: &Tns, spec: &FileSpec) -> Result<Vec<u8>> {
    let ops = plan_reads(spec, MAX_READ_BYTES)?;
    let mut chunks = Vec::with_capacity(ops.len());
    for op in &ops {
        let addr = read_addr(spec.file_type, spec.file_number, op.element);
        let req = pccc::slc_typed_read_addr(tns.next(), op.size, &addr);
        let reply = device.pccc(&req).await?;
        chunks.push(reply.ok()?.to_vec());
    }
    reassemble(spec, &chunks)
}

/// Upload every file in `manifest`, in order, returning each file's bytes.
/// Read-only: issues only `0F A2` reads. The manifest is the file list a capture
/// decode (`pccc-files.py`) produces for the target.
pub async fn upload(device: &Device, manifest: &[FileSpec]) -> Result<Vec<UploadedFile>> {
    let tns = Tns::default();
    let mut files = Vec::with_capacity(manifest.len());
    for spec in manifest {
        let bytes = read_file(device, &tns, spec).await?;
        files.push(UploadedFile {
            file_type: spec.file_type,
            file_number: spec.file_number,
            bytes,
        });
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(file_type: u8, file_number: u16, elements: u16, element_bytes: u16) -> FileSpec {
        FileSpec { file_type, file_number, elements, element_bytes }
    }

    #[test]
    fn plan_small_int_file_one_read() {
        // N7 with 2 int16 elements = 4 bytes, one read.
        let ops = plan_reads(&spec(0x89, 7, 2, 2), MAX_READ_BYTES).unwrap();
        assert_eq!(ops, vec![ReadOp { element: 0, size: 4 }]);
    }

    #[test]
    fn plan_large_int_file_chunks_on_element_boundary() {
        // N7 with 252 int16 elements = 504 bytes. 240/2 = 120 elements/chunk.
        let ops = plan_reads(&spec(0x89, 7, 252, 2), MAX_READ_BYTES).unwrap();
        assert_eq!(ops.len(), 3);
        assert_eq!(ops[0], ReadOp { element: 0, size: 240 });
        assert_eq!(ops[1], ReadOp { element: 120, size: 240 });
        // remainder: 252 - 240 = 12 elements = 24 bytes
        assert_eq!(ops[2], ReadOp { element: 240, size: 24 });
        // Every element is covered exactly once.
        let covered: u16 = ops.iter().map(|o| o.size as u16 / 2).sum();
        assert_eq!(covered, 252);
    }

    #[test]
    fn plan_timer_file_three_word_elements() {
        // T4 with 75 elements * 6 bytes = 450 bytes. 240/6 = 40 elements/chunk.
        let ops = plan_reads(&spec(0x86, 4, 75, 6), MAX_READ_BYTES).unwrap();
        assert_eq!(ops[0], ReadOp { element: 0, size: 240 });
        assert_eq!(ops[1], ReadOp { element: 40, size: 210 });
        let covered: u16 = ops.iter().map(|o| o.size as u16 / 6).sum();
        assert_eq!(covered, 75);
    }

    #[test]
    fn plan_string_file_large_elements() {
        // ST with 10 elements * 84 bytes = 840 bytes. 240/84 = 2 elements/chunk.
        let ops = plan_reads(&spec(0x8D, 9, 10, 84), MAX_READ_BYTES).unwrap();
        assert_eq!(ops[0], ReadOp { element: 0, size: 168 });
        let covered: u16 = ops.iter().map(|o| o.size as u16 / 84).sum();
        assert_eq!(covered, 10);
    }

    #[test]
    fn plan_rejects_oversized_element() {
        assert!(plan_reads(&spec(0x99, 0, 1, 300), MAX_READ_BYTES).is_err());
        assert!(plan_reads(&spec(0x99, 0, 1, 0), MAX_READ_BYTES).is_err());
    }

    #[test]
    fn read_request_bytes_match_capture_shape() {
        // A whole-file read of N7 element 0, 2 bytes, must encode exactly as the
        // public DF1 protected-typed-read: CMD=0F STS=00 TNS=0001 FNC=A2
        // size=02 file=07 type=89 elem=00 sub=00.
        let addr = read_addr(0x89, 7, 0);
        let enc = pccc::slc_typed_read_addr(1, 2, &addr).encode();
        assert_eq!(enc, vec![0x0F, 0x00, 0x01, 0x00, 0xA2, 0x02, 0x07, 0x89, 0x00, 0x00]);
    }

    #[test]
    fn read_request_uses_extended_address_past_254() {
        // Element 300 must use the FF lo hi extended form (300 = 0x012C).
        let addr = read_addr(0x89, 7, 300);
        let enc = pccc::slc_typed_read_addr(1, 2, &addr).encode();
        assert!(enc.windows(3).any(|w| w == [0xFF, 0x2C, 0x01]));
    }

    #[test]
    fn reassemble_checks_length() {
        let s = spec(0x89, 7, 2, 2);
        assert!(reassemble(&s, &[vec![1, 2, 3, 4]]).is_ok());
        assert!(reassemble(&s, &[vec![1, 2]]).is_err()); // short
    }
}
