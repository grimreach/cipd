//! Northbound API: newline-delimited JSON over a Unix domain socket.
//!
//! This is the primary client interface; a REST or OPC-UA server is a thin adapter that
//! calls the same `Router` methods (see ARCHITECTURE.md §2). One JSON request object per line,
//! one JSON response object per line.
//!
//! Request examples:
//!   {"op":"list_devices"}
//!   {"op":"slc_read","device":"plc1","size":2,"file":7,"file_type":137,"element":0,"sub_element":0}
//!   {"op":"slc_write","device":"plc1","file":7,"file_type":137,"element":0,"sub_element":0,"data":"2a00"}
//!   {"op":"raw_cip","device":"logix1","service":78,"path":"2006240 1","data":""}
//!   {"op":"ml_read","device":"plc1","address":"N7:0","count":10}
//!   {"op":"ml_read","device":"plc1","address":"T4:0.ACC"}
//!   {"op":"ml_write","device":"plc1","address":"F8:2","values":[3.14]}
//!   {"op":"ml_write","device":"plc1","address":"N7:0","values":[42,-7]}

use crate::cip::{self, MrRequest};
use crate::pccc::{self, WordType};
use crate::router::Router;
use crate::transfer::{self, FileSpec};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    ListDevices,
    SlcRead {
        device: String,
        size: u8,
        file: u8,
        file_type: u8,
        element: u8,
        sub_element: u8,
    },
    SlcWrite {
        device: String,
        file: u8,
        file_type: u8,
        element: u8,
        sub_element: u8,
        /// hex-encoded value bytes
        data: String,
    },
    RawCip {
        device: String,
        service: u8,
        /// hex-encoded EPATH bytes
        path: String,
        /// hex-encoded request data
        #[serde(default)]
        data: String,
    },
    /// Read a MicroLogix/SLC logical address, decoding values by file type.
    MlRead {
        device: String,
        address: String,
        #[serde(default = "default_count")]
        count: u16,
    },
    /// Write a MicroLogix/SLC logical address. Provide either `values`
    /// (numbers encoded per the file type) or `data` (raw hex).
    MlWrite {
        device: String,
        address: String,
        #[serde(default)]
        values: Vec<serde_json::Value>,
        #[serde(default)]
        data: String,
    },
    /// Whole-program **upload** (read-only). `files` is the manifest a capture
    /// decode (`ops/wire/pccc-files.py`) produces: each file's wire type code,
    /// number, element count and bytes-per-element. Returns each file's raw bytes.
    Upload {
        device: String,
        files: Vec<FileSpec>,
    },
}

fn default_count() -> u16 {
    1
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Response {
    Ok { data: serde_json::Value },
    Error { message: String },
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Decode raw reply bytes into a JSON array of scalars per the file's word type.
fn api_decode(wt: WordType, b: &[u8]) -> serde_json::Value {
    let vals: Vec<serde_json::Value> = match wt {
        WordType::F32 => b
            .chunks_exact(4)
            .map(|c| serde_json::json!(f32::from_le_bytes([c[0], c[1], c[2], c[3]])))
            .collect(),
        WordType::I32 => b
            .chunks_exact(4)
            .map(|c| serde_json::json!(i32::from_le_bytes([c[0], c[1], c[2], c[3]])))
            .collect(),
        WordType::I16 => b
            .chunks_exact(2)
            .map(|c| serde_json::json!(i16::from_le_bytes([c[0], c[1]])))
            .collect(),
        WordType::U16 => b
            .chunks_exact(2)
            .map(|c| serde_json::json!(u16::from_le_bytes([c[0], c[1]])))
            .collect(),
        WordType::Raw => return serde_json::Value::Null,
    };
    serde_json::Value::Array(vals)
}

/// Encode a JSON array of numbers into little-endian bytes per the file's word type.
fn api_encode(wt: WordType, vals: &[serde_json::Value]) -> Result<Vec<u8>, String> {
    if vals.is_empty() {
        return Err("provide 'values' (array of numbers) or 'data' (hex)".into());
    }
    let mut out = Vec::new();
    for v in vals {
        let n = v.as_f64().ok_or_else(|| format!("value {v} is not a number"))?;
        match wt {
            WordType::F32 => out.extend_from_slice(&(n as f32).to_le_bytes()),
            WordType::I32 => out.extend_from_slice(&(n as i32).to_le_bytes()),
            WordType::I16 => out.extend_from_slice(&(n as i16).to_le_bytes()),
            WordType::U16 => out.extend_from_slice(&(n as u16).to_le_bytes()),
            WordType::Raw => return Err("raw file types (ST/MG/PD) require hex 'data'".into()),
        }
    }
    Ok(out)
}

pub async fn serve(router: Arc<Router>, socket_path: &str) -> crate::error::Result<()> {
    // Fresh socket each start.
    let _ = std::fs::remove_file(socket_path);
    if let Some(dir) = std::path::Path::new(socket_path).parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let listener = UnixListener::bind(socket_path)?;
    tracing::info!(socket = socket_path, "API listening");

    loop {
        let (stream, _) = listener.accept().await?;
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(router, stream).await {
                tracing::warn!("client error: {e}");
            }
        });
    }
}

async fn handle_conn(router: Arc<Router>, stream: UnixStream) -> crate::error::Result<()> {
    let (rd, mut wr) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(&line) {
            Ok(req) => dispatch(&router, req).await,
            Err(e) => Response::Error { message: format!("bad request: {e}") },
        };
        let mut out = serde_json::to_vec(&resp).unwrap_or_default();
        out.push(b'\n');
        wr.write_all(&out).await?;
    }
    Ok(())
}

async fn dispatch(router: &Arc<Router>, req: Request) -> Response {
    match req {
        Request::ListDevices => Response::Ok {
            data: serde_json::json!({ "devices": router.device_names() }),
        },

        Request::SlcRead { device, size, file, file_type, element, sub_element } => {
            match router.device(&device) {
                Ok(d) => match d.slc_read(size, file, file_type, element, sub_element).await {
                    Ok(bytes) => Response::Ok {
                        data: serde_json::json!({ "data": hex_encode(&bytes) }),
                    },
                    Err(e) => Response::Error { message: e.to_string() },
                },
                Err(e) => Response::Error { message: e.to_string() },
            }
        }

        Request::SlcWrite { device, file, file_type, element, sub_element, data } => {
            let values = match hex_decode(&data) {
                Ok(v) => v,
                Err(e) => return Response::Error { message: e },
            };
            match router.device(&device) {
                Ok(d) => match d.slc_write(file, file_type, element, sub_element, &values).await {
                    Ok(()) => Response::Ok { data: serde_json::json!({}) },
                    Err(e) => Response::Error { message: e.to_string() },
                },
                Err(e) => Response::Error { message: e.to_string() },
            }
        }

        Request::RawCip { device, service, path, data } => {
            let path = match hex_decode(&path) {
                Ok(v) => v,
                Err(e) => return Response::Error { message: format!("path: {e}") },
            };
            let data = match hex_decode(&data) {
                Ok(v) => v,
                Err(e) => return Response::Error { message: format!("data: {e}") },
            };
            match router.device(&device) {
                Ok(d) => match d.raw_cip(MrRequest::new(service, path, data)).await {
                    Ok(reply) => Response::Ok {
                        data: serde_json::json!({
                            "general_status": reply.general_status,
                            "status_name": cip::cip_status_name(reply.general_status),
                            "additional_status": reply.additional_status,
                            "data": hex_encode(&reply.data),
                        }),
                    },
                    Err(e) => Response::Error { message: e.to_string() },
                },
                Err(e) => Response::Error { message: e.to_string() },
            }
        }

        Request::MlRead { device, address, count } => match router.device(&device) {
            Ok(d) => match d.ml_read(&address, count).await {
                Ok((a, bytes)) => Response::Ok {
                    data: serde_json::json!({
                        "address": address,
                        "file_type": a.file_type,
                        "elements": count,
                        "raw": hex_encode(&bytes),
                        "values": api_decode(a.word_type, &bytes),
                    }),
                },
                Err(e) => Response::Error { message: e.to_string() },
            },
            Err(e) => Response::Error { message: e.to_string() },
        },

        Request::MlWrite { device, address, values, data } => {
            let bytes = if !data.is_empty() {
                match hex_decode(&data) {
                    Ok(v) => v,
                    Err(e) => return Response::Error { message: format!("data: {e}") },
                }
            } else {
                let a = match pccc::parse_slc_address(&address) {
                    Ok(a) => a,
                    Err(e) => return Response::Error { message: e.to_string() },
                };
                match api_encode(a.word_type, &values) {
                    Ok(v) => v,
                    Err(e) => return Response::Error { message: e },
                }
            };
            match router.device(&device) {
                Ok(d) => match d.ml_write(&address, &bytes).await {
                    Ok(_) => Response::Ok { data: serde_json::json!({}) },
                    Err(e) => Response::Error { message: e.to_string() },
                },
                Err(e) => Response::Error { message: e.to_string() },
            }
        }

        Request::Upload { device, files } => match router.device(&device) {
            Ok(d) => match transfer::upload(&d, &files).await {
                Ok(uploaded) => Response::Ok {
                    data: serde_json::json!({
                        "file_count": uploaded.len(),
                        "files": uploaded
                            .iter()
                            .map(|f| serde_json::json!({
                                "file_type": f.file_type,
                                "file_number": f.file_number,
                                "bytes": f.bytes.len(),
                                "data": hex_encode(&f.bytes),
                            }))
                            .collect::<Vec<_>>(),
                    }),
                },
                Err(e) => Response::Error { message: e.to_string() },
            },
            Err(e) => Response::Error { message: e.to_string() },
        },
    }
}
