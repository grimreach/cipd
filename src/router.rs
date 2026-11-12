//! Unified CIP/PCCC router: device registry, lazy connect, route table, transaction nonces.
//!
//! This is the daemon analogue of the RSLinx ENGINE seam (see ARCHITECTURE.md §3/§6.3):
//! transports are interchangeable; the router owns CIP/PCCC semantics and routing.

use crate::cip::{self, MrReply, MrRequest};
use crate::config::{DeviceConfig, TransportConfig};
use crate::csp::CspSession;
use crate::df1::{Df1Link, ErrorCheck};
use crate::enip::EnipSession;
use crate::error::{Error, Result};
use crate::pccc::{self, PcccReply, PcccRequest};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

enum Transport {
    Enip(EnipSession),
    Csp(CspSession),
    Df1(Df1Link),
}

/// One addressable device (a PLC, or a bridge hop target).
pub struct Device {
    pub name: String,
    cfg: DeviceConfig,
    link: Mutex<Option<Transport>>,
    tns: AtomicU16,
    /// CIP route path (port segments) for multi-hop EtherNet/IP, or empty for direct.
    route_path: Vec<u8>,
}

impl Device {
    fn new(cfg: DeviceConfig) -> Self {
        let route_path = cfg
            .route
            .iter()
            .flat_map(|hop| cip::seg_port(hop.port, hop.link))
            .collect();
        Device {
            name: cfg.name.clone(),
            tns: AtomicU16::new(1),
            route_path,
            link: Mutex::new(None),
            cfg,
        }
    }

    fn next_tns(&self) -> u16 {
        let v = self.tns.fetch_add(1, Ordering::Relaxed);
        if v == 0 {
            self.tns.fetch_add(1, Ordering::Relaxed)
        } else {
            v
        }
    }

    async fn ensure_connected(&self, g: &mut Option<Transport>) -> Result<()> {
        if g.is_some() {
            return Ok(());
        }
        let t = match &self.cfg.transport {
            TransportConfig::Enip { host } => Transport::Enip(
                EnipSession::connect(
                    host,
                    Duration::from_millis(self.cfg.connect_timeout_ms),
                    Duration::from_millis(self.cfg.request_timeout_ms),
                )
                .await?,
            ),
            TransportConfig::Csp { host } => Transport::Csp(
                CspSession::connect(host, Duration::from_millis(self.cfg.connect_timeout_ms)).await?,
            ),
            TransportConfig::Df1 {
                port,
                baud,
                crc,
                dst,
                src,
                ack_timeout_ms,
                max_retries,
            } => Transport::Df1(Df1Link::open(
                port,
                *baud,
                if *crc { ErrorCheck::Crc } else { ErrorCheck::Bcc },
                *dst,
                *src,
                *ack_timeout_ms,
                *max_retries,
            )?),
        };
        *g = Some(t);
        Ok(())
    }

    /// Reset the link on error so the next call reconnects.
    async fn drop_link(&self) {
        *self.link.lock().await = None;
    }

    /// Send a raw CIP Message Router request (EtherNet/IP or CSP-less path).
    /// If the device has a route, the request is wrapped in an Unconnected_Send.
    pub async fn raw_cip(&self, mut req: MrRequest) -> Result<MrReply> {
        if !self.route_path.is_empty() {
            let (p, t) = cip::tick_timeout(self.cfg.request_timeout_ms as u32 / 1000 + 1);
            req = cip::unconnected_send(p, t, &req.encode(), &self.route_path);
        }
        let mut g = self.link.lock().await;
        self.ensure_connected(&mut g).await?;
        let res = match g.as_mut().unwrap() {
            Transport::Enip(s) => s.send_cip_unconnected(&req).await,
            Transport::Csp(_) | Transport::Df1(_) => Err(Error::Other(
                "raw CIP requires an EtherNet/IP device".into(),
            )),
        };
        if res.is_err() {
            drop(g);
            self.drop_link().await;
        }
        res
    }

    /// Send a PCCC request over whichever transport this device uses
    /// (native PCCC on DF1/CSP; PCCC-in-CIP over EtherNet/IP).
    pub async fn pccc(&self, req: &PcccRequest) -> Result<PcccReply> {
        let mut g = self.link.lock().await;
        self.ensure_connected(&mut g).await?;
        let res = match g.as_mut().unwrap() {
            Transport::Df1(l) => l.transact(req).await,
            Transport::Csp(c) => c.transact(req).await,
            Transport::Enip(s) => {
                let mut mr =
                    pccc::pccc_in_cip(self.cfg.vendor_id, self.cfg.serial_number, req);
                if !self.route_path.is_empty() {
                    let (p, t) = cip::tick_timeout(self.cfg.request_timeout_ms as u32 / 1000 + 1);
                    mr = cip::unconnected_send(p, t, &mr.encode(), &self.route_path);
                }
                let reply = s.send_cip_unconnected(&mr).await?;
                let data = reply.ok()?;
                pccc::pccc_from_cip_reply(data)
            }
        };
        if res.is_err() {
            drop(g);
            self.drop_link().await;
        }
        res
    }

    /// SLC protected typed read of `size` bytes at file/type/element/sub-element.
    pub async fn slc_read(
        &self,
        size: u8,
        file: u8,
        file_type: u8,
        element: u8,
        sub_element: u8,
    ) -> Result<Vec<u8>> {
        let req = pccc::slc_typed_read(self.next_tns(), size, file, file_type, element, sub_element);
        let reply = self.pccc(&req).await?;
        Ok(reply.ok()?.to_vec())
    }

    /// SLC protected typed write.
    pub async fn slc_write(
        &self,
        file: u8,
        file_type: u8,
        element: u8,
        sub_element: u8,
        values: &[u8],
    ) -> Result<()> {
        let req =
            pccc::slc_typed_write(self.next_tns(), file, file_type, element, sub_element, values);
        let reply = self.pccc(&req).await?;
        reply.ok()?;
        Ok(())
    }

    /// Read a MicroLogix/SLC logical address (`"N7:0"`, `"F8:2"`, `"T4:0.ACC"`, ...).
    /// `count` elements (or sub-element words). Returns the parsed address
    /// (so callers can decode by type) and the raw reply bytes.
    pub async fn ml_read(&self, address: &str, count: u16) -> Result<(pccc::SlcAddress, Vec<u8>)> {
        let a = pccc::parse_slc_address(address)?;
        let size = pccc::read_size(&a, count).min(240) as u8; // SLC per-request byte cap
        let req = pccc::slc_typed_read_addr(self.next_tns(), size, &a);
        let reply = self.pccc(&req).await?;
        Ok((a, reply.ok()?.to_vec()))
    }

    /// Write raw little-endian bytes to a MicroLogix/SLC logical address.
    pub async fn ml_write(&self, address: &str, values: &[u8]) -> Result<pccc::SlcAddress> {
        let a = pccc::parse_slc_address(address)?;
        if a.bit.is_some() {
            return Err(Error::Other(
                "bit-level write needs read-modify-write; address a whole word instead".into(),
            ));
        }
        if values.is_empty() {
            return Err(Error::Other("no data to write".into()));
        }
        let req = pccc::slc_typed_write_addr(self.next_tns(), &a, values);
        let reply = self.pccc(&req).await?;
        reply.ok()?;
        Ok(a)
    }
}

/// The router: name -> device.
pub struct Router {
    devices: HashMap<String, Arc<Device>>,
}

impl Router {
    pub fn new(cfgs: Vec<DeviceConfig>) -> Self {
        let mut devices = HashMap::new();
        for c in cfgs {
            let d = Arc::new(Device::new(c));
            devices.insert(d.name.clone(), d);
        }
        Router { devices }
    }

    pub fn device(&self, name: &str) -> Result<Arc<Device>> {
        self.devices
            .get(name)
            .cloned()
            .ok_or_else(|| Error::UnknownDevice(name.to_string()))
    }

    pub fn device_names(&self) -> Vec<String> {
        let mut v: Vec<_> = self.devices.keys().cloned().collect();
        v.sort();
        v
    }
}
