//! Safety layer for every write command: dry run unless `yes`, refuse
//! protected partitions and oversize images, back up the target region
//! before writing, then read every written range back and compare SHA-256.

use crate::firehose::Firehose;
use crate::image::{Image, hex};
use crate::usb::Transport;
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// `userdata` (~245 GB on fajita) is backed up as its first and last MiB only
/// unless `full_backup` is set.
const PARTIAL_BACKUP: &str = "userdata";
const PARTIAL_BYTES: u64 = 1 << 20;
/// Show a progress line on stderr above this size.
const PROGRESS_BYTES: u64 = 64 << 20;

/// Sectors on a LUN that a write may touch: a partition, or a slice of the GPT.
#[derive(Debug, Clone)]
pub struct Region {
    pub name: String,
    pub lun: u8,
    pub start: u64,
    pub sectors: u64,
}

pub struct Write {
    pub region: Region,
    pub image: Image,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Opts {
    pub yes: bool,
    pub force_protected: bool,
    pub no_backup: bool,
    pub full_backup: bool,
}

pub fn size(bytes: u64) -> String {
    let units = ["B", "K", "M", "G", "T"];
    let (mut v, mut i) = (bytes as f64, 0);
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1}{}", units[i])
}

/// Check and print every write; unless dry run, back up all targets, then
/// write and verify each in order. Returns whether anything was written.
pub fn run<T: Transport>(
    fh: &mut Firehose<T>,
    protected: &[String],
    writes: &[Write],
    o: Opts,
    backup_root: &Path,
) -> Result<bool> {
    let ss = fh.sector_size as u64;
    for w in writes {
        let (r, img) = (&w.region, &w.image);
        ensure!(
            o.force_protected || !protected.contains(&r.name),
            "`{}` is a protected partition (device profile); refusing without --force-protected",
            r.name
        );
        ensure!(img.data_len() > 0, "{}: nothing to write", img.label);
        ensure!(
            img.extents.iter().all(|e| e.offset % ss == 0),
            "{}: data not aligned to {ss}-byte sectors",
            img.label
        );
        let need = img.extents.iter().map(|e| e.offset + e.len).fold(img.size, u64::max);
        ensure!(
            need.div_ceil(ss) <= r.sectors,
            "{} ({}) is larger than `{}` ({}); refusing",
            img.label,
            size(need),
            r.name,
            size(r.sectors * ss)
        );
    }
    for w in writes {
        print_plan(w, ss);
    }
    if !o.yes {
        println!("dry run  nothing written; re-run with --yes to write");
        return Ok(false);
    }

    if o.no_backup {
        println!("backup   SKIPPED (--no-backup)");
    } else {
        let dir = backup(fh, writes, o.full_backup, backup_root)?;
        println!("backup   saved to {}", dir.display());
    }

    for w in writes {
        let (r, img) = (&w.region, &w.image);
        let t0 = Instant::now();
        let mut p = Progress::new(&r.name, img.data_len());
        for e in &img.extents {
            let start = r.start + e.offset / ss;
            let mut h = Sha256::new();
            fh.program(r.lun, start, e.len, &mut img.reader(e), &mut |d| {
                h.update(d);
                p.add(d.len());
            })
            .with_context(|| format!("writing `{}`", r.name))?;
            let n = e.len.div_ceil(ss);
            let mut g = Sha256::new();
            fh.read(r.lun, start, n, &mut |d| {
                g.update(d);
                Ok(())
            })
            .with_context(|| format!("reading back `{}`", r.name))?;
            if g.finalize() != h.finalize() {
                bail!(
                    "READ-BACK MISMATCH on `{}`: LUN{} sectors {start}+{n} do not hold what was sent. \
                     The partition is in an unknown state; restore it from the backup above.",
                    r.name,
                    r.lun
                );
            }
        }
        p.done();
        let secs = t0.elapsed().as_secs_f64().max(0.001);
        println!(
            "wrote    {} ({}) and verified read-back in {secs:.1}s",
            r.name,
            size(img.data_len())
        );
    }
    Ok(true)
}

fn print_plan(w: &Write, ss: u64) {
    let (r, img) = (&w.region, &w.image);
    let sectors: u64 = img.extents.iter().map(|e| e.len.div_ceil(ss)).sum();
    println!(
        "write    {}: LUN{} sector {} count {sectors} ({}, {} B) of {} sectors",
        r.name,
        r.lun,
        r.start + img.extents[0].offset / ss,
        size(sectors * ss),
        img.data_len(),
        r.sectors
    );
    if img.sparse {
        println!(
            "         sparse image: {} runs, {} of {} expanded written (DONT_CARE left untouched)",
            img.extents.len(),
            size(img.data_len()),
            size(img.size)
        );
        let shown = if img.extents.len() <= 8 { img.extents.len() } else { 3 };
        for e in &img.extents[..shown] {
            println!(
                "         run sector {} count {}",
                r.start + e.offset / ss,
                e.len.div_ceil(ss)
            );
        }
        if shown < img.extents.len() {
            let e = img.extents.last().unwrap();
            println!(
                "         ... {} more, last at sector {} count {}",
                img.extents.len() - shown,
                r.start + e.offset / ss,
                e.len.div_ceil(ss)
            );
        }
    }
    println!("         source {}  sha256 {}", img.label, img.sha256);
}

/// Read every target region (or the head and tail of `userdata`) into a new
/// timestamped directory, with SHA256SUMS and LOCATIONS files.
fn backup<T: Transport>(fh: &mut Firehose<T>, writes: &[Write], full: bool, root: &Path) -> Result<PathBuf> {
    let ss = fh.sector_size as u64;
    std::fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
    let stamp = utc_stamp(SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()));
    let dir = (0..)
        .map(|i| root.join(if i == 0 { stamp.clone() } else { format!("{stamp}-{i}") }))
        .find(|d| std::fs::create_dir(d).is_ok())
        .unwrap();
    let append = |name: &str| OpenOptions::new().create(true).append(true).open(dir.join(name));
    let (mut sums, mut locs) = (append("SHA256SUMS")?, append("LOCATIONS")?);
    for w in writes {
        let r = &w.region;
        let part = PARTIAL_BYTES / ss;
        let ranges = if r.name == PARTIAL_BACKUP && !full && r.sectors > 2 * part {
            println!(
                "backup   {}: first and last MiB only (--full-backup for all of it)",
                r.name
            );
            vec![("head.img", 0, part), ("tail.img", r.sectors - part, part)]
        } else {
            vec![("img", 0, r.sectors)]
        };
        for (ext, off, n) in ranges {
            let file = format!("{}.{ext}", r.name);
            let mut f = std::io::BufWriter::new(File::create(dir.join(&file))?);
            let mut h = Sha256::new();
            let mut p = Progress::new(&format!("backup {}", r.name), n * ss);
            fh.read(r.lun, r.start + off, n, &mut |d| {
                h.update(d);
                p.add(d.len());
                f.write_all(d).map_err(Into::into)
            })
            .with_context(|| format!("backing up `{}`", r.name))?;
            p.done();
            f.flush()?;
            writeln!(sums, "{}  {file}", hex(&h.finalize()))?;
            writeln!(locs, "{file}  LUN{} sector {} count {n}", r.lun, r.start + off)?;
        }
    }
    Ok(dir)
}

struct Progress {
    label: String,
    total: u64,
    done: u64,
    shown: u64,
}

impl Progress {
    fn new(label: &str, total: u64) -> Progress {
        Progress {
            label: label.into(),
            total,
            done: 0,
            shown: 0,
        }
    }
    fn add(&mut self, n: usize) {
        self.done += n as u64;
        let pct = self.done * 100 / self.total.max(1);
        if self.total > PROGRESS_BYTES && pct != self.shown {
            self.shown = pct;
            eprint!("\r  {} {pct}%", self.label);
        }
    }
    fn done(&self) {
        if self.total > PROGRESS_BYTES {
            eprintln!();
        }
    }
}

/// `YYYYMMDDTHHMMSSZ` for a Unix time (civil-from-days, H. Hinnant).
fn utc_stamp(secs: u64) -> String {
    let (z, rem) = ((secs / 86400) as i64 + 719_468, secs % 86400);
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::time::Duration;

    const SS: usize = 4096;

    /// A firehose loader in miniature: answers read/program/nop against
    /// in-memory LUNs, accepting ZLPs, optionally corrupting what it stores.
    #[derive(Default)]
    struct Fake {
        luns: Vec<Vec<u8>>,
        out: VecDeque<Vec<u8>>,
        rx: Option<(usize, usize, usize, Vec<u8>)>,
        programs: usize,
        corrupt: bool,
        nak_program: bool,
    }

    fn resp(v: &str, raw: &str) -> Vec<u8> {
        format!("<?xml version=\"1.0\" ?><data><response value=\"{v}\" rawmode=\"{raw}\" /></data>").into_bytes()
    }

    impl Transport for Fake {
        fn write(&mut self, d: &[u8], _: Duration) -> Result<()> {
            if d.is_empty() {
                return Ok(()); // ZLP
            }
            if let Some((lun, off, want, buf)) = &mut self.rx {
                buf.extend_from_slice(d);
                assert!(buf.len() <= *want, "host sent more than num_partition_sectors");
                if buf.len() == *want {
                    let (lun, off, mut buf) = (*lun, *off, std::mem::take(buf));
                    if self.corrupt {
                        buf[*want / 2] ^= 0xff;
                    }
                    self.luns[lun][off..off + buf.len()].copy_from_slice(&buf);
                    self.rx = None;
                    self.out.push_back(resp("ACK", "false"));
                }
                return Ok(());
            }
            let x = String::from_utf8_lossy(d).into_owned();
            let attr = |k: &str| -> usize {
                let s = x.find(&format!("{k}=\"")).unwrap() + k.len() + 2;
                x[s..s + x[s..].find('"').unwrap()].parse().unwrap()
            };
            if x.contains("<read ") || x.contains("<program ") {
                let (lun, start, n) = (
                    attr("physical_partition_number"),
                    attr("start_sector"),
                    attr("num_partition_sectors"),
                );
                let (off, len) = (start * SS, n * SS);
                if off + len > self.luns[lun].len() || (x.contains("<program ") && self.nak_program) {
                    self.out.push_back(resp("NAK", "false"));
                } else if x.contains("<read ") {
                    self.out.push_back(resp("ACK", "true"));
                    self.out.push_back(self.luns[lun][off..off + len].to_vec());
                    self.out.push_back(resp("ACK", "false"));
                } else {
                    self.programs += 1;
                    self.out.push_back(resp("ACK", "true"));
                    self.rx = Some((lun, off, len, vec![]));
                }
            } else {
                self.out.push_back(resp("ACK", "false"));
            }
            Ok(())
        }

        fn read(&mut self, max: usize, _: Duration) -> Result<Option<Vec<u8>>> {
            let Some(mut d) = self.out.pop_front() else {
                return Ok(None);
            };
            if d.len() > max {
                self.out.push_front(d.split_off(max));
            }
            Ok(Some(d))
        }
    }

    fn fake(luns: Vec<Vec<u8>>) -> Firehose<Fake> {
        Firehose::new(
            Fake {
                luns,
                ..Default::default()
            },
            vec![],
            SS,
        )
    }

    fn region(name: &str, lun: u8, start: u64, sectors: u64) -> Region {
        Region {
            name: name.into(),
            lun,
            start,
            sectors,
        }
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mtk-write-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn yes() -> Opts {
        Opts {
            yes: true,
            ..Default::default()
        }
    }

    fn prot() -> Vec<String> {
        vec!["persist".into(), "modemst1".into()]
    }

    fn lun0() -> Vec<Vec<u8>> {
        vec![vec![0xaa; 32 * SS]]
    }

    #[test]
    fn dry_run_writes_nothing() {
        let mut fh = fake(lun0());
        let w = Write {
            region: region("boot_a", 0, 4, 8),
            image: Image::bytes("img", 0, vec![1; 3 * SS]),
        };
        let root = tmp("dry");
        assert!(!run(&mut fh, &prot(), &[w], Opts::default(), &root).unwrap());
        assert_eq!(fh.t.programs, 0);
        assert!(fh.t.luns == lun0() && !root.exists());
    }

    #[test]
    fn refuses_protected_and_oversize() {
        let mut fh = fake(lun0());
        let root = tmp("refuse");
        let w = |name: &str, len: usize| Write {
            region: region(name, 0, 4, 8),
            image: Image::bytes("img", 0, vec![1; len]),
        };
        let e = run(&mut fh, &prot(), &[w("boot_a", SS), w("persist", SS)], yes(), &root).unwrap_err();
        assert!(e.to_string().contains("protected"), "{e}");
        let e = run(&mut fh, &prot(), &[w("boot_a", 8 * SS + 1)], yes(), &root).unwrap_err();
        assert!(e.to_string().contains("larger than `boot_a`"), "{e}");
        assert_eq!(fh.t.programs, 0);
        assert!(fh.t.luns == lun0() && !root.exists());
        let o = Opts {
            force_protected: true,
            ..yes()
        };
        assert!(run(&mut fh, &prot(), &[w("persist", SS)], o, &root).unwrap());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn writes_pads_backs_up_and_verifies() {
        let mut fh = fake(lun0());
        let root = tmp("ok");
        let data: Vec<u8> = (0..SS * 2 + 100).map(|i| (i % 255) as u8 + 1).collect();
        let w = Write {
            region: region("boot_a", 0, 4, 8),
            image: Image::bytes("img", 0, data.clone()),
        };
        assert!(run(&mut fh, &prot(), &[w], yes(), &root).unwrap());
        let d = &fh.t.luns[0];
        assert_eq!(&d[4 * SS..4 * SS + data.len()], &data[..]);
        assert!(d[4 * SS + data.len()..7 * SS].iter().all(|&b| b == 0)); // padded tail sector
        assert!(d[7 * SS..].iter().all(|&b| b == 0xaa) && d[..4 * SS].iter().all(|&b| b == 0xaa));
        let dir = std::fs::read_dir(&root).unwrap().next().unwrap().unwrap().path();
        assert_eq!(std::fs::read(dir.join("boot_a.img")).unwrap(), vec![0xaa; 8 * SS]);
        let sums = std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap();
        assert_eq!(
            sums,
            format!("{}  boot_a.img\n", hex(&Sha256::digest(vec![0xaa; 8 * SS])))
        );
        let locs = std::fs::read_to_string(dir.join("LOCATIONS")).unwrap();
        assert_eq!(locs, "boot_a.img  LUN0 sector 4 count 8\n");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn detects_readback_mismatch_and_nak() {
        let mut fh = fake(lun0());
        fh.t.corrupt = true;
        let root = tmp("bad");
        let w = || Write {
            region: region("boot_a", 0, 4, 8),
            image: Image::bytes("img", 0, vec![7; SS]),
        };
        let e = run(&mut fh, &prot(), &[w()], yes(), &root).unwrap_err();
        assert!(e.to_string().contains("READ-BACK MISMATCH"), "{e}");
        let mut fh = fake(lun0());
        fh.t.nak_program = true;
        let o = Opts {
            no_backup: true,
            ..yes()
        };
        let e = run(&mut fh, &prot(), &[w()], o, &root).unwrap_err();
        assert!(format!("{e:#}").contains("NAK for `<program`"), "{e:#}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn sparse_skips_dont_care_and_userdata_backs_up_ends() {
        let (s, x, mask) = crate::image::tests::sparse_fixture();
        let src = std::env::temp_dir().join(format!("mtk-write-{}-sparse.img", std::process::id()));
        std::fs::write(&src, s).unwrap();
        let img = Image::open(&src).unwrap();
        std::fs::remove_file(&src).unwrap();
        let sectors = 600u64;
        let mut fh = fake(vec![vec![0xaa; sectors as usize * SS]]);
        let root = tmp("sparse");
        let w = Write {
            region: region("userdata", 0, 0, sectors),
            image: img,
        };
        assert!(run(&mut fh, &prot(), &[w], yes(), &root).unwrap());
        assert_eq!(fh.t.programs, 2);
        let d = &fh.t.luns[0];
        for (b, &written) in mask.iter().enumerate() {
            let got = &d[b * SS..(b + 1) * SS];
            if written {
                assert_eq!(got, &x[b * SS..(b + 1) * SS], "block {b}");
            } else {
                assert!(got.iter().all(|&v| v == 0xaa), "DONT_CARE block {b} was written");
            }
        }
        let dir = std::fs::read_dir(&root).unwrap().next().unwrap().unwrap().path();
        assert_eq!(std::fs::read(dir.join("userdata.head.img")).unwrap().len(), 1 << 20);
        assert_eq!(
            std::fs::read(dir.join("userdata.tail.img")).unwrap(),
            vec![0xaa; 1 << 20]
        );
        let locs = std::fs::read_to_string(dir.join("LOCATIONS")).unwrap();
        assert!(locs.contains("userdata.tail.img  LUN0 sector 344 count 256"), "{locs}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn stamp() {
        assert_eq!(utc_stamp(1_700_000_000), "20231114T221320Z");
        assert_eq!(utc_stamp(951_782_400), "20000229T000000Z");
    }
}
