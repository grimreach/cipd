//! Whole-program **upload** (read every PLC file) over PCCC.
//!
//! Source discipline: this module is built ONLY from the decoded AP-01 Wireshark
//! capture (ACPAC `docs/ladder/pccc-upload-download.md`, 12 Nov 2026) and the
//! public DF1/PCCC command set — never guessed. It reuses the spec engine's
//! `0F A2` framing (`pccc::slc_typed_read_addr` + `Device::pccc`); it does not
//! re-implement CIP/PCCC wrapping.
//!
//! What the capture showed for an upload: 413 protected-typed-logical-reads
//! (CMD 0x0F FNC 0xA2), one file at a time, reassembled into each file's bytes.
//!
//! ## Addressing — matched to the capture, not assumed
//!
//! RSLogix does **not** step by element. It reads each file as a flat array of
//! **words**: the element field is fixed at `0x00`, the sub-element field carries
//! a **word offset**, and every read is 0x50 (80 bytes = 40 words) except a
//! shorter final read for the remainder. The sub-element steps 0, 40, 80, 120…
//! words, switching to the `FF lo hi` extended form past 254. Verbatim from AP-01:
//!
//! ```text
//!   N7   (type 0x89):  50 07 89 00 28 …   last  18 07 89 00 F0   (24 B at word 240)
//!   T4   (type 0x86):  50 04 86 00 28 …   last  32 04 86 00 C8   (50 B at word 200)
//!   LAD2 (type 0x22):  50 02 22 00 FF 18 01 (80 B at word 280)
//!                      last  38 02 22 00 FF 40 01 (56 B at word 320)
//! ```
//!
//! The same flat-word scheme holds for every type seen (N, T, C, ST, program
//! files, …) — timers (6-byte elements) and strings (84-byte elements) are read
//! on the same 40-word stride, so reads cross element boundaries freely. Because
//! of that, the only per-file geometry this planner needs is the **total byte
//! length**; element size matters only for the client that later decodes values.
//!
//! The *type codes seen on the wire* are (from `ops/wire/pccc-files.py`):
//! O=0x82 I=0x83 S=0x84 B=0x85 T=0x86 C=0x87 R=0x88 N=0x89 F=0x8A ST=0x8D L=0x91
//! MG=0x92 RIX=0x96; plus system/program/config files by their own codes. (These
//! wire codes differ from the logical address-path codes in `pccc::file_type_info`
//! for O/I — upload uses the wire codes, so the manifest carries the raw type byte
//! and this module never maps.)
//!
//! Scope of this version: **upload only** (read-only, safe on any PLC). The file
//! set + geometry are supplied as a manifest — exactly what `pccc-files.py` emits
//! from a capture — because the type-0x03 directory layout that RSLogix reads
//! first to enumerate files is not decoded yet. Download is NOT here: it is gated
//! on four still-unknown pieces (0x03 directory build, 0F 88/8F payloads, the
//! doubled 0x47/0x49/0x4D writes, the mode change) and on the bench PLC.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU16, Ordering};

use crate::error::{Error, Result};
use crate::pccc::{self, SlcAddress, WordType};
use crate::router::Device;

/// Per-request byte cap. The AP-01 capture used 0x50 (80 bytes) for every full
/// read; element stepping of program files and 240-byte reads are UNTESTED on the
/// ML1400, so this stays at 80 until a bench test shows a larger read is accepted.
pub const MAX_READ_BYTES: u16 = 80;

/// One file to read during an upload: its wire type code, number, and geometry.
/// This is the shape `ops/wire/pccc-files.py` reports per file. `element_bytes`
/// is not used to plan reads (RSLogix reads a flat word array; see module docs);
/// it is retained because it is part of the manifest and lets a client decode
/// values from the reassembled bytes.
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

/// A single `0F A2` read: starting **word offset** (the sub-element field) and
/// byte count. Element is always 0 on the wire, matching the capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadOp {
    pub word_offset: u16,
    pub size: u8,
}

/// Plan the reads for a file as RSLogix does: fixed-size chunks addressed by a
/// flat word offset, stepping `max_bytes/2` words each time, with a shorter final
/// read for the remainder.
///
/// Pure and deterministic — this is the part proven by unit test against the
/// capture bytes; the wire I/O around it is a thin loop. `max_bytes` is clamped to
/// an even value ≤ 254 so the byte count fits the single-byte DF1 size field and
/// the stride is a whole number of words.
pub fn plan_reads(spec: &FileSpec, max_bytes: u16) -> Result<Vec<ReadOp>> {
    let total = spec.total_bytes();
    if total == 0 {
        return Ok(Vec::new());
    }
    if total % 2 != 0 {
        return Err(Error::Protocol(format!(
            "file type 0x{:02x} #{}: {total} bytes is not word-aligned",
            spec.file_type, spec.file_number
        )));
    }
    // Chunk size: even (whole words) and within the single-byte size field.
    let chunk_bytes = (max_bytes.min(254) & !1).max(2);
    let chunk_words = chunk_bytes / 2;

    let mut ops = Vec::new();
    let mut word = 0u16;
    while (word as usize) * 2 < total {
        let remaining = total - (word as usize) * 2;
        let size = remaining.min(chunk_bytes as usize) as u8;
        ops.push(ReadOp { word_offset: word, size });
        word = word.saturating_add(chunk_words);
    }
    Ok(ops)
}

/// Reassemble read replies in order, verifying the total matches the file.
/// Reads are contiguous and non-overlapping (each full read is `chunk_bytes` and
/// the stride is `chunk_bytes/2` words), so concatenation reproduces the file.
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

/// A raw address for an upload read: element fixed at 0, word offset in the
/// sub-element field (no logical letter/decode — the manifest already carries the
/// wire type code). This mirrors exactly what the capture put on the wire.
fn read_addr(file_type: u8, file_number: u16, word_offset: u16) -> SlcAddress {
    SlcAddress {
        letter: String::new(),
        file_number,
        file_type,
        element: 0,
        sub_element: word_offset,
        has_sub: true,
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
        let addr = read_addr(spec.file_type, spec.file_number, op.word_offset);
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

    /// Encode a planned read to its full `0F A2` request bytes, for comparison
    /// against the capture.
    fn wire(spec: &FileSpec, op: &ReadOp) -> Vec<u8> {
        let addr = read_addr(spec.file_type, spec.file_number, op.word_offset);
        pccc::slc_typed_read_addr(1, op.size, &addr).encode()
    }

    #[test]
    fn plan_small_int_file_one_read() {
        // N7 with 2 int16 elements = 4 bytes, one read at word 0.
        let ops = plan_reads(&spec(0x89, 7, 2, 2), MAX_READ_BYTES).unwrap();
        assert_eq!(ops, vec![ReadOp { word_offset: 0, size: 4 }]);
    }

    #[test]
    fn plan_n7_matches_capture() {
        // N7 (type 0x89): 252 int16 = 504 bytes. 80-byte / 40-word stride.
        let s = spec(0x89, 7, 252, 2);
        let ops = plan_reads(&s, MAX_READ_BYTES).unwrap();
        assert_eq!(ops.first(), Some(&ReadOp { word_offset: 0, size: 80 }));
        assert_eq!(ops[1], ReadOp { word_offset: 40, size: 80 });
        assert_eq!(ops.last(), Some(&ReadOp { word_offset: 240, size: 24 }));
        // Second read on the wire: 50 07 89 00 28
        assert_eq!(
            wire(&s, &ops[1]),
            vec![0x0F, 0x00, 0x01, 0x00, 0xA2, 0x50, 0x07, 0x89, 0x00, 0x28]
        );
        // Last read on the wire: 18 07 89 00 F0
        assert_eq!(
            wire(&s, ops.last().unwrap()),
            vec![0x0F, 0x00, 0x01, 0x00, 0xA2, 0x18, 0x07, 0x89, 0x00, 0xF0]
        );
        // Contiguous full coverage.
        let covered: usize = ops.iter().map(|o| o.size as usize).sum();
        assert_eq!(covered, s.total_bytes());
    }

    #[test]
    fn plan_t4_stride_is_words_not_elements() {
        // T4 (type 0x86): 75 timers * 6 bytes = 450 bytes. Still a 40-word stride,
        // so reads cross the 3-word element boundary.
        let s = spec(0x86, 4, 75, 6);
        let ops = plan_reads(&s, MAX_READ_BYTES).unwrap();
        assert_eq!(ops[1], ReadOp { word_offset: 40, size: 80 });
        assert_eq!(ops.last(), Some(&ReadOp { word_offset: 200, size: 50 }));
        // Second read: 50 04 86 00 28
        assert_eq!(
            wire(&s, &ops[1]),
            vec![0x0F, 0x00, 0x01, 0x00, 0xA2, 0x50, 0x04, 0x86, 0x00, 0x28]
        );
        // Last read: 32 04 86 00 C8
        assert_eq!(
            wire(&s, ops.last().unwrap()),
            vec![0x0F, 0x00, 0x01, 0x00, 0xA2, 0x32, 0x04, 0x86, 0x00, 0xC8]
        );
        let covered: usize = ops.iter().map(|o| o.size as usize).sum();
        assert_eq!(covered, s.total_bytes());
    }

    #[test]
    fn plan_lad2_uses_extended_word_offset() {
        // LAD2 (type 0x22): 696 bytes = 348 words. The word offset passes 254 and
        // switches to the FF lo hi extended form. (element_bytes is irrelevant to
        // planning; 348*2 just gives the total length.)
        let s = spec(0x22, 2, 348, 2);
        let ops = plan_reads(&s, MAX_READ_BYTES).unwrap();
        // Read at word 280 (0x0118), full 80 bytes: 50 02 22 00 FF 18 01
        let at280 = ops.iter().find(|o| o.word_offset == 280).unwrap();
        assert_eq!(at280.size, 80);
        assert_eq!(
            wire(&s, at280),
            vec![0x0F, 0x00, 0x01, 0x00, 0xA2, 0x50, 0x02, 0x22, 0x00, 0xFF, 0x18, 0x01]
        );
        // Final read at word 320 (0x0140), 56 bytes: 38 02 22 00 FF 40 01
        assert_eq!(ops.last(), Some(&ReadOp { word_offset: 320, size: 56 }));
        assert_eq!(
            wire(&s, ops.last().unwrap()),
            vec![0x0F, 0x00, 0x01, 0x00, 0xA2, 0x38, 0x02, 0x22, 0x00, 0xFF, 0x40, 0x01]
        );
        let covered: usize = ops.iter().map(|o| o.size as usize).sum();
        assert_eq!(covered, s.total_bytes());
    }

    #[test]
    fn plan_string_file_crosses_element_boundaries() {
        // ST (type 0x8D): 10 elements * 84 bytes = 840 bytes = 420 words. The
        // 84-byte element is NOT respected; reads are still 80-byte / 40-word.
        let s = spec(0x8D, 9, 10, 84);
        let ops = plan_reads(&s, MAX_READ_BYTES).unwrap();
        assert_eq!(ops[0], ReadOp { word_offset: 0, size: 80 });
        assert_eq!(ops[1], ReadOp { word_offset: 40, size: 80 });
        let covered: usize = ops.iter().map(|o| o.size as usize).sum();
        assert_eq!(covered, 840);
        // 840 / 80 = exactly 10.5 → 10 full reads + a 40-byte tail.
        assert_eq!(ops.last(), Some(&ReadOp { word_offset: 400, size: 40 }));
    }

    #[test]
    fn plan_first_read_request_bytes() {
        // First read of N7 element 0 / word 0, 80 bytes:
        // CMD=0F STS=00 TNS=0001 FNC=A2 size=50 file=07 type=89 elem=00 sub=00.
        let s = spec(0x89, 7, 252, 2);
        let ops = plan_reads(&s, MAX_READ_BYTES).unwrap();
        assert_eq!(
            wire(&s, &ops[0]),
            vec![0x0F, 0x00, 0x01, 0x00, 0xA2, 0x50, 0x07, 0x89, 0x00, 0x00]
        );
    }

    #[test]
    fn plan_rejects_unaligned_total() {
        // An odd byte total is never word-addressable; refuse rather than guess.
        assert!(plan_reads(&spec(0x99, 0, 1, 1), MAX_READ_BYTES).is_err());
    }

    #[test]
    fn plan_empty_file_no_reads() {
        assert!(plan_reads(&spec(0x89, 7, 0, 2), MAX_READ_BYTES).unwrap().is_empty());
    }

    #[test]
    fn reassemble_checks_length() {
        let s = spec(0x89, 7, 2, 2);
        assert!(reassemble(&s, &[vec![1, 2, 3, 4]]).is_ok());
        assert!(reassemble(&s, &[vec![1, 2]]).is_err()); // short
    }
}
