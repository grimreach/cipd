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

/// Bytes per upload read, exactly as RSLogix 500 reads an ML1400 (AP-01 capture,
/// 12 Nov 2026): every read is 80 bytes (40 words), addressed `element = 0,
/// sub-element = word offset into the file`, for EVERY file type (ladder 0x22,
/// data, config), with a shorter last read. 75 of the 78 files in the capture
/// follow this exactly; the other three (status 0x00, 0x63, directory 0x03) are
/// RSLogix's extra probe reads, and even the 0x03 directory's content is then read
/// this way. Element-stepped or larger reads have never been seen on the ML1400,
/// so they are not used.
pub const READ_CHUNK_BYTES: u16 = 80;

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

/// A single `0F A2` read: word offset into the file (sent as the sub-element,
/// element 0) and byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadOp {
    pub word_offset: u16,
    pub size: u8,
}

/// Split a file into the reads RSLogix makes: `chunk` bytes each (80 in
/// practice, [`READ_CHUNK_BYTES`]), stepping a word offset, last read shorter.
///
/// Pure and deterministic; the wire I/O around it is a thin loop. Files are
/// word-addressed, so an odd byte length is refused rather than guessed at.
pub fn plan_reads(spec: &FileSpec, chunk: u16) -> Result<Vec<ReadOp>> {
    if spec.element_bytes == 0 {
        return Err(Error::Protocol("file element_bytes = 0".into()));
    }
    if chunk == 0 || chunk % 2 != 0 || chunk > 254 {
        return Err(Error::Protocol(format!("read chunk of {chunk} bytes: must be even and 2..254")));
    }
    let total = spec.total_bytes();
    if total % 2 != 0 {
        return Err(Error::Protocol(format!(
            "file type 0x{:02x} #{}: {total} bytes is not a whole number of words",
            spec.file_type, spec.file_number
        )));
    }
    if total / 2 > u16::MAX as usize {
        return Err(Error::Protocol(format!("file of {total} bytes is past the 16-bit word offset")));
    }
    let mut ops = Vec::new();
    let mut off = 0usize;
    while off < total {
        let n = (chunk as usize).min(total - off);
        ops.push(ReadOp { word_offset: (off / 2) as u16, size: n as u8 });
        off += n;
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
/// already carries the wire type code): element 0, sub-element = word offset,
/// as RSLogix sends it.
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
    let ops = plan_reads(spec, READ_CHUNK_BYTES)?;
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

    /// The `0F A2` data bytes (size, file, type, element, sub-element) the planner
    /// produces for a file, as hex strings, one per read.
    fn planned_hex(s: &FileSpec) -> Vec<String> {
        plan_reads(s, READ_CHUNK_BYTES)
            .unwrap()
            .iter()
            .map(|op| {
                let addr = read_addr(s.file_type, s.file_number, op.word_offset);
                let enc = pccc::slc_typed_read_addr(1, op.size, &addr).encode();
                // CMD STS TNSlo TNShi FNC | data
                enc[5..].iter().map(|b| format!("{b:02x}")).collect()
            })
            .collect()
    }

    // Expected request bytes are copied from RSLogix 500's upload of AP-01
    // (ap01-02-upload.pcapng, 12 Nov 2026; decode: ACPAC docs/ladder/pccc-upload-download.md).

    #[test]
    fn n7_reads_match_rslogix_exactly() {
        // N7: 252 words = 504 bytes -> 6 x 80 + 24, word offsets 0..240.
        assert_eq!(
            planned_hex(&spec(0x89, 7, 252, 2)),
            vec!["5007890000", "5007890028", "5007890050", "5007890078", "50078900a0", "50078900c8", "18078900f0"]
        );
    }

    #[test]
    fn ladder_file_reads_match_rslogix_exactly_with_extended_offsets() {
        // LAD 2 (type 0x22): 696 bytes -> 8 x 80 + 56; offsets past 254 use FF lo hi.
        assert_eq!(
            planned_hex(&spec(0x22, 2, 348, 2)),
            vec![
                "5002220000", "5002220028", "5002220050", "5002220078", "50022200a0",
                "50022200c8", "50022200f0", "50022200ff1801", "38022200ff4001",
            ]
        );
    }

    #[test]
    fn timer_file_is_stepped_by_words_not_elements() {
        // T4: 75 x 6 bytes = 450 -> 5 x 80 + 50, word offsets 0..200 (not element-aligned).
        assert_eq!(
            planned_hex(&spec(0x86, 4, 75, 6)),
            vec!["5004860000", "5004860028", "5004860050", "5004860078", "50048600a0", "32048600c8"]
        );
    }

    #[test]
    fn string_file_reads_match_rslogix_exactly() {
        // ST9: 3 x 84 bytes = 252 -> 3 x 80 + 12.
        assert_eq!(planned_hex(&spec(0x8D, 9, 3, 84)), vec!["50098d0000", "50098d0028", "50098d0050", "0c098d0078"]);
    }

    #[test]
    fn small_file_is_one_read() {
        assert_eq!(planned_hex(&spec(0x89, 40, 3, 2)), vec!["0628890000"]);
    }

    #[test]
    fn plan_covers_every_byte_once() {
        let s = spec(0x22, 4, 1872, 2); // LAD 4, 3744 bytes
        let ops = plan_reads(&s, READ_CHUNK_BYTES).unwrap();
        let total: usize = ops.iter().map(|o| o.size as usize).sum();
        assert_eq!(total, 3744);
        assert_eq!(ops.len(), 47); // as in the capture
        for w in ops.windows(2) {
            assert_eq!(w[1].word_offset as usize, w[0].word_offset as usize + w[0].size as usize / 2);
        }
    }

    #[test]
    fn plan_refuses_what_it_cannot_address() {
        assert!(plan_reads(&spec(0x99, 0, 1, 0), READ_CHUNK_BYTES).is_err()); // no bytes per element
        assert!(plan_reads(&spec(0x99, 0, 3, 1), READ_CHUNK_BYTES).is_err()); // odd byte length
        assert!(plan_reads(&spec(0x89, 7, 2, 2), 81).is_err()); // odd chunk
    }

    #[test]
    fn reassemble_checks_length() {
        let s = spec(0x89, 7, 2, 2);
        assert!(reassemble(&s, &[vec![1, 2, 3, 4]]).is_ok());
        assert!(reassemble(&s, &[vec![1, 2]]).is_err()); // short
    }
}
