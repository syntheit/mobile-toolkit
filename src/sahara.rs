//! Sahara: the PBL protocol used to identify the SoC and upload the firehose
//! loader. Ported from bkerler/edl `sahara.py` (GPL-3.0).

use crate::usb::Transport;
use anyhow::{Result, bail, ensure};
use std::time::Duration;

const HELLO_REQ: u32 = 0x01;
const HELLO_RSP: u32 = 0x02;
const READ_DATA: u32 = 0x03;
const END_TRANSFER: u32 = 0x04;
const DONE_REQ: u32 = 0x05;
const DONE_RSP: u32 = 0x06;
const CMD_READY: u32 = 0x0b;
const SWITCH_MODE: u32 = 0x0c;
const EXECUTE_REQ: u32 = 0x0d;
const EXECUTE_RSP: u32 = 0x0e;
const EXECUTE_DATA: u32 = 0x0f;
const READ_DATA_64: u32 = 0x12;

const MODE_IMAGE_TX_PENDING: u32 = 0;
const MODE_COMMAND: u32 = 3;

const EXEC_SERIAL: u32 = 1;
const EXEC_HWID: u32 = 2;
const EXEC_PKHASH: u32 = 3;

const TIMEOUT: Duration = Duration::from_secs(5);

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

#[derive(Debug, Clone, Copy)]
pub struct Hello {
    pub version: u32,
    pub mode: u32,
}

/// What the device is speaking when we first talk to it.
#[derive(Debug)]
pub enum Probe {
    Sahara(Hello),
    /// Loader already running; carries any bytes already read (log XML).
    Firehose(Vec<u8>),
}

#[derive(Debug, Default)]
pub struct Info {
    pub serial: u32,
    pub hwid: Option<u64>,
    pub pkhash: Option<Vec<u8>>,
}

fn status_text(s: u32) -> String {
    let d = match s {
        0x01 => "invalid command in current state",
        0x02 => "protocol mismatch",
        0x05 => "invalid packet size",
        0x06 => "unexpected image id",
        0x13 => "invalid ELF header",
        0x15 => "timeout receiving data",
        0x21 => "hash table authentication failure (loader not signed for this device?)",
        0x22 => "hash verification failure (loader corrupt?)",
        0x23 => "hash table not found",
        0x25 => "image authentication failure (loader not signed for this device?)",
        _ => "",
    };
    format!("Sahara status 0x{s:02x} {d}").trim_end().to_string()
}

fn read_pkt(t: &mut dyn Transport, timeout: Duration) -> Result<Vec<u8>> {
    match t.read(4096, timeout)? {
        Some(p) if p.len() >= 8 => Ok(p),
        Some(p) => bail!("short Sahara packet ({} bytes)", p.len()),
        None => bail!("timed out waiting for Sahara packet"),
    }
}

fn parse_hello(p: &[u8]) -> Result<Hello> {
    ensure!(p.len() >= 48 && u32le(p, 0) == HELLO_REQ, "expected Sahara hello");
    Ok(Hello {
        version: u32le(p, 8),
        mode: u32le(p, 20),
    })
}

/// END_TRANSFER carries an error status; anything else unexpected is reported raw.
fn unexpected(p: &[u8], what: &str) -> anyhow::Error {
    if u32le(p, 0) == END_TRANSFER && p.len() >= 16 {
        return anyhow::anyhow!("{what}: device ended transfer: {}", status_text(u32le(p, 12)));
    }
    anyhow::anyhow!("{what}: unexpected Sahara command 0x{:x}", u32le(p, 0))
}

/// Detect whether the device is waiting in Sahara or already running firehose.
pub fn probe(t: &mut dyn Transport) -> Result<Probe> {
    if let Some(p) = t.read(4096, Duration::from_millis(1500))? {
        if p.len() >= 48 && u32le(&p, 0) == HELLO_REQ {
            return Ok(Probe::Sahara(parse_hello(&p)?));
        }
        if p.windows(5).any(|w| w == b"<?xml") {
            return Ok(Probe::Firehose(p));
        }
        if p.len() >= 8 {
            return Err(unexpected(&p, "probe"));
        }
    }
    // Silent: either firehose waiting for a command, or Sahara whose hello was
    // already consumed by an earlier host. A firehose loader answers a nop.
    t.write(b"<?xml version=\"1.0\" ?><data><nop /></data>", TIMEOUT)?;
    match t.read(4096, Duration::from_secs(1))? {
        Some(p) if p.windows(5).any(|w| w == b"<?xml") => Ok(Probe::Firehose(p)),
        Some(p) if p.len() >= 8 => Err(unexpected(&p, "probe")),
        _ => bail!("device in EDL but not answering (stale Sahara session?)"),
    }
}

fn hello_rsp(t: &mut dyn Transport, version: u32, mode: u32) -> Result<()> {
    let mut b = Vec::with_capacity(48);
    for v in [HELLO_RSP, 0x30, version, 1, 0, mode, 1, 2, 3, 4, 5, 6] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    t.write(&b, TIMEOUT)
}

fn exec(t: &mut dyn Transport, cmd: u32) -> Result<Vec<u8>> {
    let pkt = |id: u32| [id.to_le_bytes(), 12u32.to_le_bytes(), cmd.to_le_bytes()].concat();
    t.write(&pkt(EXECUTE_REQ), TIMEOUT)?;
    let r = read_pkt(t, TIMEOUT)?;
    if u32le(&r, 0) != EXECUTE_RSP || r.len() < 16 {
        return Err(unexpected(&r, "execute"));
    }
    let len = u32le(&r, 12) as usize;
    t.write(&pkt(EXECUTE_DATA), TIMEOUT)?;
    let mut data = Vec::with_capacity(len);
    while data.len() < len {
        match t.read(len - data.len(), TIMEOUT)? {
            Some(d) => data.extend_from_slice(&d),
            None => bail!("timed out reading Sahara execute data"),
        }
    }
    data.truncate(len);
    Ok(data)
}

/// Enter command mode, read serial/HWID/PK hash, then switch back (the device
/// re-sends a hello, returned here). Same sequence edl uses.
pub fn info(t: &mut dyn Transport, hello: Hello) -> Result<(Info, Hello)> {
    hello_rsp(t, hello.version, MODE_COMMAND)?;
    let r = read_pkt(t, TIMEOUT)?;
    if u32le(&r, 0) != CMD_READY {
        return Err(unexpected(&r, "command mode"));
    }
    let serial = exec(t, EXEC_SERIAL)?;
    ensure!(serial.len() >= 4, "short serial");
    let mut info = Info {
        serial: u32le(&serial, 0),
        ..Info::default()
    };
    if hello.version < 3 {
        let hw = exec(t, EXEC_HWID)?;
        ensure!(hw.len() >= 8, "short HWID");
        info.hwid = Some(u64le(&hw, 0));
        info.pkhash = Some(exec(t, EXEC_PKHASH)?);
    }
    let sw = [SWITCH_MODE, 12, MODE_COMMAND].map(u32::to_le_bytes).concat();
    t.write(&sw, TIMEOUT)?;
    let again = parse_hello(&read_pkt(t, TIMEOUT)?)?;
    Ok((info, again))
}

/// Serve the loader ELF to the device until it reports end-of-image, then
/// finish with DONE. Returns the image id the device asked for.
pub fn upload(t: &mut dyn Transport, hello: Hello, loader: &[u8]) -> Result<u64> {
    hello_rsp(t, hello.version, MODE_IMAGE_TX_PENDING)?;
    let mut image_id = 0;
    loop {
        let p = read_pkt(t, TIMEOUT)?;
        let (id, off, len) = match u32le(&p, 0) {
            READ_DATA if p.len() >= 20 => (u32le(&p, 8) as u64, u32le(&p, 12) as u64, u32le(&p, 16) as u64),
            READ_DATA_64 if p.len() >= 32 => (u64le(&p, 8), u64le(&p, 16), u64le(&p, 24)),
            END_TRANSFER if p.len() >= 16 => {
                let status = u32le(&p, 12);
                ensure!(status == 0, "loader upload failed: {}", status_text(status));
                break;
            }
            _ => return Err(unexpected(&p, "upload")),
        };
        image_id = id;
        ensure!(len <= 16 << 20, "device asked for an implausible {len} bytes");
        let (off, len) = (off as usize, len as usize);
        // The PBL may read past the end of the file; pad with 0xff like edl.
        let mut chunk = loader.get(off..loader.len().min(off + len)).unwrap_or(&[]).to_vec();
        chunk.resize(len, 0xff);
        t.write(&chunk, TIMEOUT)?;
    }
    t.write(&[DONE_REQ, 8].map(u32::to_le_bytes).concat(), TIMEOUT)?;
    let r = read_pkt(t, TIMEOUT)?;
    if u32le(&r, 0) != DONE_RSP {
        return Err(unexpected(&r, "done"));
    }
    Ok(image_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::Mock;

    fn pkt(words: &[u32]) -> Option<Vec<u8>> {
        Some(words.iter().flat_map(|w| w.to_le_bytes()).collect())
    }

    fn hello() -> Option<Vec<u8>> {
        pkt(&[HELLO_REQ, 0x30, 2, 1, 0x400, 0, 0, 0, 0, 0, 0, 0])
    }

    #[test]
    fn upload_32_and_64_bit_reads() {
        let loader: Vec<u8> = (0..100u8).collect();
        let mut rd64 = pkt(&[READ_DATA_64, 32]).unwrap();
        for v in [0xdu64, 96, 8] {
            rd64.extend_from_slice(&v.to_le_bytes());
        }
        let mut m = Mock::new(vec![
            pkt(&[READ_DATA, 20, 0xd, 0, 16]),
            Some(rd64),
            pkt(&[END_TRANSFER, 16, 0xd, 0]),
            pkt(&[DONE_RSP, 12, 1]),
        ]);
        let Probe::Sahara(h) = probe(&mut Mock::new(vec![hello()])).unwrap() else {
            panic!()
        };
        assert_eq!(upload(&mut m, h, &loader).unwrap(), 0xd);
        assert_eq!(&m.writes[0][..12], pkt(&[HELLO_RSP, 0x30, 2]).unwrap());
        assert_eq!(u32le(&m.writes[0], 20), MODE_IMAGE_TX_PENDING);
        assert_eq!(m.writes[1], &loader[..16]);
        // Read past EOF is padded with 0xff.
        assert_eq!(m.writes[2], [96, 97, 98, 99, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(m.writes[3], pkt(&[DONE_REQ, 8]).unwrap());
    }

    #[test]
    fn upload_rejected() {
        let mut m = Mock::new(vec![pkt(&[END_TRANSFER, 16, 0xd, 0x25])]);
        let e = upload(&mut m, Hello { version: 2, mode: 0 }, &[0; 4]).unwrap_err();
        assert!(e.to_string().contains("0x25 image authentication"), "{e}");
    }

    #[test]
    fn command_mode_info() {
        let mut pk = vec![0xdd, 0x7c, 0x5f, 0x2e];
        pk.resize(48, 0xaa);
        let mut m = Mock::new(vec![
            pkt(&[CMD_READY, 8]),
            pkt(&[EXECUTE_RSP, 16, EXEC_SERIAL, 4]),
            pkt(&[0x1234_5678]),
            pkt(&[EXECUTE_RSP, 16, EXEC_HWID, 8]),
            Some(0x0008_b0e1_0051_459bu64.to_le_bytes().to_vec()),
            pkt(&[EXECUTE_RSP, 16, EXEC_PKHASH, 48]),
            Some(pk.clone()),
            hello(),
        ]);
        let (info, again) = info(&mut m, Hello { version: 2, mode: 0 }).unwrap();
        assert_eq!((info.serial, info.hwid), (0x1234_5678, Some(0x0008_b0e1_0051_459b)));
        assert_eq!(info.pkhash.unwrap(), pk);
        assert_eq!(again.version, 2);
        assert_eq!(u32le(&m.writes[0], 20), MODE_COMMAND);
        assert_eq!(
            m.writes.last().unwrap(),
            &pkt(&[SWITCH_MODE, 12, MODE_COMMAND]).unwrap()
        );
    }

    #[test]
    fn probe_detects_running_firehose() {
        let log = b"<?xml version=\"1.0\" ?><data><log value=\"hi\" /></data>".to_vec();
        assert!(matches!(
            probe(&mut Mock::new(vec![Some(log)])).unwrap(),
            Probe::Firehose(_)
        ));
        // Silent device that answers a nop with XML.
        let mut m = Mock::new(vec![
            None,
            Some(b"<?xml version=\"1.0\" ?><data><response value=\"ACK\" /></data>".to_vec()),
        ]);
        assert!(matches!(probe(&mut m).unwrap(), Probe::Firehose(_)));
        assert!(m.writes[0].starts_with(b"<?xml"));
        // Silent and no answer: stale Sahara.
        assert!(probe(&mut Mock::new(vec![None, None])).is_err());
    }
}
