//! Firehose: the XML protocol spoken by the uploaded loader: configure, read,
//! program, getstorageinfo, setbootablestoragedrive, power, nop. Framing ported
//! from bkerler/edl `firehose.py` (GPL-3.0). Callers write through `write.rs`.

use crate::usb::Transport;
use anyhow::{Context, Result, bail};
use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};
use std::io::Read;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);
/// Bulk IN size for the raw data phase.
const DATA_CHUNK: usize = 1 << 20;
/// Sectors per <read> command; large partitions are split into several.
const SECTORS_PER_CMD: u64 = 32 * 1024;

/// One parsed `<response>` plus the `<log>` lines that preceded it.
#[derive(Debug, Default)]
pub struct Reply {
    pub ack: bool,
    pub attrs: Vec<(String, String)>,
    pub logs: Vec<String>,
}

impl Reply {
    pub fn attr(&self, k: &str) -> Option<&str> {
        self.attrs.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str())
    }
}

/// Parse one `<data>` document into its log values and response attributes.
fn parse_doc(doc: &[u8], logs: &mut Vec<String>) -> Option<Vec<(String, String)>> {
    let mut r = Reader::from_reader(doc);
    let mut response = None;
    loop {
        match r.read_event() {
            Ok(Event::Start(e) | Event::Empty(e)) => {
                let attrs: Vec<(String, String)> = e
                    .attributes()
                    .flatten()
                    .map(|a| {
                        let v = a.normalized_value(XmlVersion::Implicit1_0).map(|v| v.into_owned());
                        (a.key.as_ref().to_owned(), v.unwrap_or_default())
                    })
                    .collect();
                match e.name().as_ref() {
                    "log" => logs.extend(attrs.into_iter().filter(|(k, _)| k == "value").map(|(_, v)| v)),
                    "response" => response = Some(attrs),
                    _ => {}
                }
            }
            Ok(Event::Eof) => return response,
            Err(_) => {
                logs.push(format!("(unparsable) {}", String::from_utf8_lossy(doc).trim()));
                return response;
            }
            _ => {}
        }
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

pub struct Firehose<T: Transport> {
    t: T,
    /// Bytes received but not yet consumed (partial XML or early raw data).
    pending: Vec<u8>,
    pub sector_size: usize,
    pub max_payload: usize,
    pub target: String,
}

impl<T: Transport> Firehose<T> {
    pub fn new(t: T, already_read: Vec<u8>, sector_size: usize) -> Self {
        Firehose {
            t,
            pending: already_read,
            sector_size,
            max_payload: 1 << 20,
            target: String::new(),
        }
    }

    fn send(&mut self, inner: &str) -> Result<()> {
        let xml = format!("<?xml version=\"1.0\" ?><data>{inner}</data>");
        self.t.write(xml.as_bytes(), TIMEOUT)
    }

    /// Next complete `<data>...</data>` document, reading more as needed.
    fn next_doc(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        loop {
            if let Some(end) = find(&self.pending, b"</data>") {
                let rest = self.pending.split_off(end + 7);
                return Ok(Some(std::mem::replace(&mut self.pending, rest)));
            }
            match self.t.read(DATA_CHUNK, timeout)? {
                Some(d) => self.pending.extend_from_slice(&d),
                None => return Ok(None),
            }
        }
    }

    /// Read documents until a `<response>` arrives.
    pub fn reply(&mut self, timeout: Duration) -> Result<Reply> {
        let mut logs = Vec::new();
        loop {
            let Some(doc) = self.next_doc(timeout)? else {
                bail!("timed out waiting for firehose response{}", fmt_logs(&logs));
            };
            if let Some(attrs) = parse_doc(&doc, &mut logs) {
                let ack = attrs.iter().any(|(k, v)| k == "value" && (v == "ACK" || v == "true"));
                return Ok(Reply { ack, attrs, logs });
            }
        }
    }

    /// Collect log lines the loader emits unprompted (e.g. right after boot).
    pub fn drain(&mut self) -> Result<Vec<String>> {
        let mut logs = Vec::new();
        while let Some(doc) = self.next_doc(Duration::from_millis(500))? {
            parse_doc(&doc, &mut logs);
        }
        Ok(logs)
    }

    fn command(&mut self, inner: &str, timeout: Duration) -> Result<Reply> {
        self.send(inner)?;
        let r = self.reply(timeout)?;
        if !r.ack {
            bail!(
                "firehose NAK for `{}`{}",
                inner.split_whitespace().next().unwrap_or(inner),
                fmt_logs(&r.logs)
            );
        }
        Ok(r)
    }

    pub fn nop(&mut self) -> Result<Reply> {
        self.command("<nop />", TIMEOUT)
    }

    /// Configure storage; renegotiates once if the loader NAKs our payload size.
    pub fn configure(&mut self, memory: &str) -> Result<Reply> {
        let mut payload = self.max_payload;
        for attempt in 0..2 {
            self.send(&format!(
                "<configure MemoryName=\"{memory}\" Verbose=\"0\" AlwaysValidate=\"0\" \
                 MaxDigestTableSizeInBytes=\"2048\" MaxPayloadSizeToTargetInBytes=\"{payload}\" \
                 ZLPAwareHost=\"1\" SkipStorageInit=\"0\" SkipWrite=\"0\"/>"
            ))?;
            let r = self.reply(Duration::from_secs(30))?;
            let offered = r.attr("MaxPayloadSizeToTargetInBytes").and_then(|v| v.parse().ok());
            if r.ack {
                self.max_payload = offered.unwrap_or(payload);
                self.target = r.attr("TargetName").unwrap_or("?").to_string();
                return Ok(r);
            }
            match offered {
                Some(p) if attempt == 0 && p != payload => payload = p,
                _ => bail!("configure rejected{}", fmt_logs(&r.logs)),
            }
        }
        unreachable!()
    }

    pub fn storage_info(&mut self, lun: u8) -> Result<Reply> {
        self.command(
            &format!("<getstorageinfo physical_partition_number=\"{lun}\"/>"),
            TIMEOUT,
        )
    }

    /// Stream `count` sectors starting at `start` on `lun` into `sink`.
    pub fn read(&mut self, lun: u8, start: u64, count: u64, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let mut done = 0;
        while done < count {
            let n = (count - done).min(SECTORS_PER_CMD);
            self.read_cmd(lun, start + done, n, sink)?;
            done += n;
        }
        Ok(())
    }

    fn read_cmd(&mut self, lun: u8, start: u64, n: u64, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let ss = self.sector_size;
        self.command(
            &format!(
                "<read SECTOR_SIZE_IN_BYTES=\"{ss}\" num_partition_sectors=\"{n}\" \
                 physical_partition_number=\"{lun}\" start_sector=\"{start}\"/>"
            ),
            TIMEOUT,
        )?;
        // Raw phase: exactly n*ss bytes, then a closing <response>.
        let mut left = n as usize * ss;
        if !self.pending.is_empty() {
            let take = left.min(self.pending.len());
            let rest = self.pending.split_off(take);
            sink(&std::mem::replace(&mut self.pending, rest))?;
            left -= take;
        }
        while left > 0 {
            match self.t.read(left.min(DATA_CHUNK), TIMEOUT)? {
                Some(d) if d.len() > left => bail!("device sent {} bytes, expected {left}", d.len()),
                Some(d) => {
                    sink(&d)?;
                    left -= d.len();
                }
                None => bail!("timed out in read data phase (LUN {lun}, sector {start}, {left} bytes left)"),
            }
        }
        let r = self.reply(TIMEOUT)?;
        if !r.ack {
            bail!("read of LUN {lun} sectors {start}+{n} failed{}", fmt_logs(&r.logs));
        }
        Ok(())
    }

    pub fn read_vec(&mut self, lun: u8, start: u64, count: u64) -> Result<Vec<u8>> {
        let mut v = Vec::with_capacity(count as usize * self.sector_size);
        self.read(lun, start, count, &mut |d| {
            v.extend_from_slice(d);
            Ok(())
        })?;
        Ok(v)
    }

    /// Write `len` bytes from `src` to `lun` at `start`, like edl `cmd_program`:
    /// `<program>`, ACK, then the raw data in max-payload transfers each
    /// followed by a ZLP (the final partial sector zero-padded), then a closing
    /// ACK. `sent` sees every byte put on the wire, padding included.
    pub fn program(
        &mut self,
        lun: u8,
        start: u64,
        len: u64,
        src: &mut dyn Read,
        sent: &mut dyn FnMut(&[u8]),
    ) -> Result<()> {
        let ss = self.sector_size;
        let n = len.div_ceil(ss as u64);
        self.command(
            &format!(
                "<program SECTOR_SIZE_IN_BYTES=\"{ss}\" num_partition_sectors=\"{n}\" \
                 physical_partition_number=\"{lun}\" start_sector=\"{start}\"/>"
            ),
            TIMEOUT,
        )?;
        let chunk = (self.max_payload / ss).max(1) * ss;
        let mut buf = vec![0u8; chunk];
        let (total, mut done) = (n * ss as u64, 0u64);
        while done < total {
            let c = (total - done).min(chunk as u64) as usize;
            let data = len.saturating_sub(done).min(c as u64) as usize;
            src.read_exact(&mut buf[..data])
                .with_context(|| format!("reading source at byte {done} (device left mid-write)"))?;
            buf[data..c].fill(0);
            self.t.write(&buf[..c], TIMEOUT)?;
            self.t.write(&[], TIMEOUT)?;
            sent(&buf[..c]);
            done += c as u64;
        }
        let r = self.reply(Duration::from_secs(60))?;
        if !r.ack {
            bail!("program of LUN {lun} sectors {start}+{n} failed{}", fmt_logs(&r.logs));
        }
        Ok(())
    }

    /// Select the UFS boot LUN (bBootLunEn): 1 = boot LU A, 2 = boot LU B.
    pub fn set_bootable(&mut self, lun: u8) -> Result<()> {
        self.command(&format!("<setbootablestoragedrive value=\"{lun}\" />"), TIMEOUT)
            .map(|_| ())
    }

    /// `reset` or `off`.
    pub fn power(&mut self, mode: &str) -> Result<()> {
        self.command(&format!("<power value=\"{mode}\"/>"), TIMEOUT).map(|_| ())
    }
}

fn fmt_logs(logs: &[String]) -> String {
    logs.iter().map(|l| format!("\n  {l}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::Mock;

    fn doc(inner: &str) -> Option<Vec<u8>> {
        Some(format!("<?xml version=\"1.0\" encoding=\"UTF-8\" ?><data>{inner}</data>").into_bytes())
    }

    #[test]
    fn configure_renegotiates_payload() {
        let m = Mock::new(vec![
            doc("<log value=\"INFO: hello\" />"),
            None, // loader goes quiet: drain stops
            doc("<response value=\"NAK\" MaxPayloadSizeToTargetInBytes=\"524288\" />"),
            doc("<response value=\"ACK\" MaxPayloadSizeToTargetInBytes=\"524288\" TargetName=\"8845\" />"),
        ]);
        let mut fh = Firehose::new(m, vec![], 4096);
        assert_eq!(fh.drain().unwrap(), ["INFO: hello"]);
        fh.configure("ufs").unwrap();
        assert_eq!((fh.max_payload, fh.target.as_str()), (524288, "8845"));
        let sent = String::from_utf8(fh.t.writes[1].clone()).unwrap();
        assert!(sent.contains("MaxPayloadSizeToTargetInBytes=\"524288\"") && sent.contains("MemoryName=\"ufs\""));
    }

    #[test]
    fn read_raw_phase() {
        let data: Vec<u8> = (0..8192u32).map(|i| i as u8).collect();
        // Response and the first raw bytes arrive in one transfer; then a ZLP.
        let mut first = doc("<response value=\"ACK\" rawmode=\"true\" />").unwrap();
        first.extend_from_slice(&data[..100]);
        let m = Mock::new(vec![
            Some(first),
            Some(data[100..4096].to_vec()),
            Some(data[4096..].to_vec()),
            Some(vec![]),
            doc("<response value=\"ACK\" rawmode=\"false\" />"),
        ]);
        let mut fh = Firehose::new(m, vec![], 4096);
        assert_eq!(fh.read_vec(4, 10, 2).unwrap(), data);
        let sent = String::from_utf8(fh.t.writes[0].clone()).unwrap();
        assert!(sent.contains("<read SECTOR_SIZE_IN_BYTES=\"4096\" num_partition_sectors=\"2\" physical_partition_number=\"4\" start_sector=\"10\"/>"));
    }

    #[test]
    fn read_nak_reports_logs() {
        let m = Mock::new(vec![doc(
            "<log value=\"ERROR: out of range\" /><response value=\"NAK\" />",
        )]);
        let e = Firehose::new(m, vec![], 4096).read_vec(0, 1 << 40, 1).unwrap_err();
        assert!(e.to_string().contains("ERROR: out of range"), "{e}");
    }

    fn program(m: Mock, payload: usize, data: &[u8]) -> (Result<()>, Vec<u8>, Mock) {
        let mut fh = Firehose::new(m, vec![], 4096);
        fh.max_payload = payload;
        let mut sent = Vec::new();
        let r = fh.program(4, 100, data.len() as u64, &mut &data[..], &mut |d| {
            sent.extend_from_slice(d)
        });
        (r, sent, fh.t)
    }

    #[test]
    fn program_framing_and_padding() {
        // 2.5 sectors with an 8 KiB payload: command, ACK, 8 KiB + ZLP,
        // 4 KiB (half zero-padded) + ZLP, closing ACK.
        let data: Vec<u8> = (0..10240u32).map(|i| (i % 251) as u8 + 1).collect();
        let m = Mock::new(vec![
            doc("<response value=\"ACK\" rawmode=\"true\" />"),
            doc("<response value=\"ACK\" rawmode=\"false\" />"),
        ]);
        let (r, sent, m) = program(m, 8192, &data);
        r.unwrap();
        let cmd = String::from_utf8(m.writes[0].clone()).unwrap();
        assert!(cmd.contains(
            "<program SECTOR_SIZE_IN_BYTES=\"4096\" num_partition_sectors=\"3\" \
             physical_partition_number=\"4\" start_sector=\"100\"/>"
        ));
        let lens: Vec<usize> = m.writes[1..].iter().map(Vec::len).collect();
        assert_eq!(lens, [8192, 0, 4096, 0]);
        assert_eq!(&m.writes[1][..], &data[..8192]);
        assert_eq!(&m.writes[3][..2048], &data[8192..]);
        assert!(m.writes[3][2048..].iter().all(|&b| b == 0));
        assert_eq!(sent.len(), 3 * 4096);
        assert_eq!(&sent[..], &[&m.writes[1][..], &m.writes[3][..]].concat()[..]);
    }

    #[test]
    fn program_nak() {
        // NAK on the command: no data phase at all.
        let m = Mock::new(vec![doc(
            "<log value=\"ERROR: write protect\" /><response value=\"NAK\" />",
        )]);
        let (r, sent, m) = program(m, 1 << 20, &[1; 4096]);
        assert!(r.unwrap_err().to_string().contains("write protect"));
        assert!(sent.is_empty() && m.writes.len() == 1);
        // NAK after the data phase.
        let m = Mock::new(vec![
            doc("<response value=\"ACK\" rawmode=\"true\" />"),
            doc("<log value=\"ERROR: failed to write\" /><response value=\"NAK\" rawmode=\"false\" />"),
        ]);
        let e = program(m, 1 << 20, &[1; 4096]).0.unwrap_err().to_string();
        assert!(
            e.contains("program of LUN 4 sectors 100+1 failed") && e.contains("failed to write"),
            "{e}"
        );
    }

    #[test]
    fn timeout_is_error() {
        let mut fh = Firehose::new(Mock::new(vec![]), vec![], 4096);
        assert!(fh.nop().unwrap_err().to_string().contains("timed out"));
    }
}
