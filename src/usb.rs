//! USB transport: find the EDL device (05c6:9008), claim its vendor interface,
//! and do bulk transfers with timeouts.

use anyhow::{Context, Result, anyhow, bail};
use nusb::descriptors::TransferType;
use nusb::transfer::{Buffer, Bulk, Direction, In, Out, TransferError};
use nusb::{Endpoint, Interface, MaybeFuture};
use std::time::Duration;

/// Largest single bulk OUT submission; bigger writes are split.
const OUT_CHUNK: usize = 1 << 20;

#[derive(Debug, PartialEq, Eq)]
pub enum Mode {
    Edl,
    Fastboot(u16),
    /// Qualcomm VID with some other PID (e.g. 900e crash-dump mode).
    OtherQualcomm(u16),
    None,
}

/// What is plugged in right now, by VID/PID only (no I/O to the device).
pub fn detect(edl: (u16, u16), fastboot_vid: u16) -> Result<Mode> {
    let mut mode = Mode::None;
    for d in nusb::list_devices().wait().context("listing USB devices")? {
        let (v, p) = (d.vendor_id(), d.product_id());
        if (v, p) == edl {
            return Ok(Mode::Edl);
        } else if v == fastboot_vid {
            mode = Mode::Fastboot(p);
        } else if v == edl.0 && mode == Mode::None {
            mode = Mode::OtherQualcomm(p);
        }
    }
    Ok(mode)
}

pub struct Usb {
    _iface: Interface,
    out: Endpoint<Bulk, Out>,
    inp: Endpoint<Bulk, In>,
}

impl Usb {
    pub fn open(vid: u16, pid: u16) -> Result<Usb> {
        let info = nusb::list_devices()
            .wait()?
            .find(|d| d.vendor_id() == vid && d.product_id() == pid)
            .ok_or_else(|| anyhow!("no {vid:04x}:{pid:04x} device found"))?;
        let dev = info.open().wait().context("opening USB device (permissions/udev?)")?;
        let cfg = dev.active_configuration()?;
        // The EDL device exposes one vendor-class (0xff) interface with a bulk pair.
        let alt = cfg
            .interface_alt_settings()
            .find(|a| a.class() == 0xff)
            .ok_or_else(|| anyhow!("no vendor interface on {vid:04x}:{pid:04x}"))?;
        let bulk = |dir: Direction| {
            alt.endpoints()
                .find(|e| e.transfer_type() == TransferType::Bulk && e.direction() == dir)
                .map(|e| e.address())
                .ok_or_else(|| anyhow!("missing bulk {dir:?} endpoint"))
        };
        let (ep_in, ep_out) = (bulk(Direction::In)?, bulk(Direction::Out)?);
        let iface = dev
            .detach_and_claim_interface(alt.interface_number())
            .wait()
            .context("claiming interface")?;
        Ok(Usb {
            out: iface.endpoint(ep_out)?,
            inp: iface.endpoint(ep_in)?,
            _iface: iface,
        })
    }

    /// Bulk OUT; an empty `data` sends a zero-length packet.
    pub fn write(&mut self, data: &[u8], timeout: Duration) -> Result<()> {
        if data.is_empty() {
            let c = self.out.transfer_blocking(Buffer::new(0), timeout);
            return c.status.map_err(|e| anyhow!("USB zero-length write failed: {e}"));
        }
        for chunk in data.chunks(OUT_CHUNK) {
            let c = self.out.transfer_blocking(Buffer::from(chunk), timeout);
            match c.status {
                Ok(()) if c.actual_len == chunk.len() => {}
                Ok(()) => bail!("short USB write ({} of {})", c.actual_len, chunk.len()),
                Err(TransferError::Cancelled) => bail!("USB write timed out"),
                Err(e) => bail!("USB write failed: {e}"),
            }
        }
        Ok(())
    }

    /// One bulk IN transfer of up to `max` bytes (rounded up to the packet
    /// size). Returns `None` on timeout; an empty Vec is a zero-length packet.
    pub fn read(&mut self, max: usize, timeout: Duration) -> Result<Option<Vec<u8>>> {
        let mps = self.inp.max_packet_size();
        let len = max.max(1).div_ceil(mps) * mps;
        let c = self.inp.transfer_blocking(Buffer::new(len), timeout);
        match c.status {
            Ok(()) => {
                let mut v = c.buffer.into_vec();
                v.truncate(c.actual_len);
                Ok(Some(v))
            }
            Err(TransferError::Cancelled) => Ok(None),
            Err(e) => bail!("USB read failed: {e}"),
        }
    }
}

/// Byte transport used by the protocol layers (real USB, or a mock in tests).
pub trait Transport {
    fn write(&mut self, data: &[u8], timeout: Duration) -> Result<()>;
    fn read(&mut self, max: usize, timeout: Duration) -> Result<Option<Vec<u8>>>;
}

impl Transport for Usb {
    fn write(&mut self, data: &[u8], timeout: Duration) -> Result<()> {
        Usb::write(self, data, timeout)
    }
    fn read(&mut self, max: usize, timeout: Duration) -> Result<Option<Vec<u8>>> {
        Usb::read(self, max, timeout)
    }
}

/// Scripted transport for offline protocol tests: `reads` are returned in
/// order (None = timeout), every write is recorded.
#[cfg(test)]
pub struct Mock {
    pub reads: std::collections::VecDeque<Option<Vec<u8>>>,
    pub writes: Vec<Vec<u8>>,
}

#[cfg(test)]
impl Mock {
    pub fn new(reads: Vec<Option<Vec<u8>>>) -> Mock {
        Mock {
            reads: reads.into(),
            writes: vec![],
        }
    }
}

#[cfg(test)]
impl Transport for Mock {
    fn write(&mut self, data: &[u8], _: Duration) -> Result<()> {
        self.writes.push(data.to_vec());
        Ok(())
    }
    fn read(&mut self, max: usize, _: Duration) -> Result<Option<Vec<u8>>> {
        let r = self.reads.pop_front().unwrap_or(None);
        if let Some(d) = &r {
            assert!(d.len() <= max.max(512), "mock read larger than requested");
        }
        Ok(r)
    }
}
