//! Parses real device dumps (not in the repo). Run with:
//!   MTK_REAL_DUMPS=/path/to/dumps cargo test -- --ignored
//! Layout: crc/p{N}.bin = LBA 0.. of LUN N (PMBR, header, entries);
//! crc/b{N}.bin = backup entries LBA through the backup header (last sector);
//! devinfo.img, config.img.

use anyhow::{Result, bail};
use mobile_toolkit::gpt::{self, Entry, LunGpt};
use mobile_toolkit::{devinfo, profile::Profile, slot};
use std::path::PathBuf;

const SS: usize = 4096;

fn dir() -> PathBuf {
    std::env::var_os("MTK_REAL_DUMPS")
        .expect("set MTK_REAL_DUMPS to the dump directory")
        .into()
}

/// The dumped GPT sectors of one LUN, readable and writable by LBA.
#[derive(Clone, PartialEq, Eq)]
struct Dump {
    pri: Vec<u8>,
    bak: Vec<u8>,
    bak_start: u64,
    end: u64,
}

impl Dump {
    fn load(lun: u8) -> Dump {
        let d = dir();
        let pri = std::fs::read(d.join(format!("crc/p{lun}.bin"))).unwrap();
        let bak = std::fs::read(d.join(format!("crc/b{lun}.bin"))).unwrap();
        let alt = gpt::Header::parse(&pri[SS..2 * SS]).unwrap().alt_lba;
        let bak_start = alt + 1 - (bak.len() / SS) as u64;
        Dump {
            pri,
            bak,
            bak_start,
            end: alt + 1,
        }
    }

    fn span(&self, lba: u64, n: u64) -> Result<(bool, usize)> {
        if lba + n <= (self.pri.len() / SS) as u64 {
            Ok((true, lba as usize * SS))
        } else if lba >= self.bak_start && lba + n <= self.end {
            Ok((false, (lba - self.bak_start) as usize * SS))
        } else {
            bail!("LBA {lba}+{n} not in dump")
        }
    }

    fn read(&self, lba: u64, n: u64) -> Result<Vec<u8>> {
        let (p, s) = self.span(lba, n)?;
        let buf = if p { &self.pri } else { &self.bak };
        Ok(buf[s..s + n as usize * SS].to_vec())
    }

    fn write(&mut self, lba: u64, data: &[u8]) {
        let (p, s) = self.span(lba, (data.len() / SS) as u64).unwrap();
        let buf = if p { &mut self.pri } else { &mut self.bak };
        buf[s..s + data.len()].copy_from_slice(data);
    }

    fn gpt(&self) -> LunGpt {
        gpt::read_lun(&mut |lba, n| self.read(lba, n), SS).unwrap()
    }
}

fn load_all() -> Vec<Dump> {
    (0..6).map(Dump::load).collect()
}

fn gpts(d: &[Dump]) -> Vec<(u8, LunGpt)> {
    d.iter().enumerate().map(|(l, d)| (l as u8, d.gpt())).collect()
}

/// Apply the plans' writes sector by sector, stopping after `limit` sectors.
fn apply(d: &mut [Dump], plans: &[slot::LunPlan], limit: usize) -> usize {
    let mut n = 0;
    for p in plans {
        for (_, lba, data) in &p.writes {
            for (i, c) in data.chunks(SS).enumerate() {
                if n == limit {
                    return n;
                }
                d[p.lun as usize].write(lba + i as u64, c);
                n += 1;
            }
        }
    }
    n
}

fn switch(d: &mut [Dump], s: char) -> Vec<slot::LunPlan> {
    let p = slot::plan(&gpts(d), s, SS).unwrap();
    apply(d, &p, usize::MAX);
    let g = gpts(d);
    for (l, g) in &g {
        assert!(g.issues.is_empty(), "LUN{l} after slot {s}: {:?}", g.issues);
    }
    let all: Vec<(u8, &Entry)> = g.iter().flat_map(|(l, g)| g.entries.iter().map(|e| (*l, e))).collect();
    let pairs = gpt::pairs(&all);
    assert_eq!(gpt::boot_slot(&pairs).unwrap(), s);
    let issues: Vec<String> = pairs.iter().flat_map(|p| gpt::pair_issues(p, Some(s))).collect();
    assert!(issues.is_empty(), "{issues:?}");
    p
}

#[test]
#[ignore]
fn real_slot_a_is_noop() {
    let p = slot::plan(&gpts(&load_all()), 'a', SS).unwrap();
    for l in &p {
        assert!(
            l.changes.is_empty() && l.writes.is_empty(),
            "LUN{}: {:?}",
            l.lun,
            l.changes
        );
    }
}

#[test]
#[ignore]
fn real_slot_b_then_a_round_trips() {
    let orig = load_all();
    let mut d = orig.clone();
    let p = switch(&mut d, 'b');
    for l in &p {
        println!(
            "LUN{}: {} changed entries, {} writes",
            l.lun,
            l.changes.len(),
            l.writes.len()
        );
        for c in &l.changes {
            println!(
                "  {:<14} {:02x} {:08x} -> {:02x} {:08x}",
                c.name, c.old.0, c.old.1, c.new.0, c.new.1
            );
        }
    }
    assert!(p[3].writes.is_empty() && p[5].writes.is_empty()); // no A/B partitions there
    assert!(
        slot::plan(&gpts(&d), 'b', SS)
            .unwrap()
            .iter()
            .all(|l| l.writes.is_empty())
    );
    switch(&mut d, 'a');
    assert!(d == orig, "slot b then a is not byte-identical");
}

#[test]
#[ignore]
fn real_interrupted_slot_converges() {
    let mut want = load_all();
    switch(&mut want, 'b');
    let p = slot::plan(&gpts(&load_all()), 'b', SS).unwrap();
    // Half the LUNs switched (whole LUNs 0..2 done, 3.. not), then every sector cut point.
    let half: usize = p.iter().take(3).flat_map(|l| &l.writes).map(|w| w.2.len() / SS).sum();
    let total = apply(&mut load_all(), &p, usize::MAX);
    for cut in std::iter::once(half).chain(0..total) {
        let mut d = load_all();
        apply(&mut d, &p, cut);
        let again = slot::plan(&gpts(&d), 'b', SS).unwrap();
        apply(&mut d, &again, usize::MAX);
        assert!(d == want, "interrupted after {cut} of {total} sectors did not converge");
    }
}

#[test]
#[ignore]
fn real_dumps() {
    let d = dir();
    let p = Profile::load("fajita").unwrap();
    let mut all: Vec<(u8, Entry)> = Vec::new();
    for lun in 0..p.luns {
        let g = Dump::load(lun).gpt();
        let b = g.backup.as_ref().unwrap();
        println!(
            "LUN{lun}: {} partitions, n={} esz={}, backup hdr @{} entries @{}, issues {:?}",
            g.entries.len(),
            g.primary.header.num_entries,
            g.primary.header.entry_size,
            b.header.my_lba,
            b.header.entries_lba,
            g.issues
        );
        assert!(g.issues.is_empty(), "LUN{lun}: {:?}", g.issues);
        assert!(g.primary.header.crc_ok && g.primary.entries_crc_ok && b.header.crc_ok && b.entries_crc_ok);
        assert_eq!(g.primary.raw_entries, b.raw_entries);
        if lun == 0 {
            assert_eq!(
                (b.header.my_lba, b.header.entries_lba, b.header.num_entries),
                (61677567, 61677563, 32)
            );
        }
        if lun == 4 {
            assert_eq!(g.primary.header.num_entries, 96);
        }
        all.extend(g.entries.into_iter().map(|e| (lun, e)));
    }

    let ab = |name: &str| all.iter().find(|(l, e)| *l == 4 && e.name == name).unwrap().1.ab().0;
    assert_eq!(ab("boot_a"), 0x6f);
    assert_eq!(ab("boot_b"), 0x3a);
    let refs: Vec<(u8, &Entry)> = all.iter().map(|(l, e)| (*l, e)).collect();
    let pairs = gpt::pairs(&refs);
    let slot = gpt::boot_slot(&pairs).unwrap();
    assert_eq!(slot, 'a');
    let issues: Vec<String> = pairs.iter().flat_map(|p| gpt::pair_issues(p, Some(slot))).collect();
    println!("{} A/B pairs, slot issues {issues:?}", pairs.len());

    let di = devinfo::parse(&std::fs::read(d.join("devinfo.img")).unwrap()).unwrap();
    println!("devinfo: {di:?}");
    let cfg = std::fs::read(d.join("config.img")).unwrap();
    println!(
        "config[last] = 0x{:02x}  config[4095] = 0x{:02x}",
        cfg[cfg.len() - 1],
        cfg[4095]
    );
}
