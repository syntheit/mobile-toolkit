//! Parses real device dumps (not in the repo). Run with:
//!   MTK_REAL_DUMPS=/path/to/dumps cargo test -- --ignored
//! Layout: crc/p{N}.bin = LBA 0.. of LUN N (PMBR, header, entries);
//! crc/b{N}.bin = backup entries LBA through the backup header (last sector);
//! devinfo.img, config.img.

use anyhow::{Result, bail};
use mobile_toolkit::gpt::{self, Entry};
use mobile_toolkit::{devinfo, profile::Profile};
use std::path::PathBuf;

const SS: usize = 4096;

fn dir() -> PathBuf {
    std::env::var_os("MTK_REAL_DUMPS")
        .expect("set MTK_REAL_DUMPS to the dump directory")
        .into()
}

#[test]
#[ignore]
fn real_dumps() {
    let d = dir();
    let p = Profile::load("fajita").unwrap();
    let mut all: Vec<(u8, Entry)> = Vec::new();
    for lun in 0..p.luns {
        let pri = std::fs::read(d.join(format!("crc/p{lun}.bin"))).unwrap();
        let bak = std::fs::read(d.join(format!("crc/b{lun}.bin"))).unwrap();
        let alt = gpt::Header::parse(&pri[SS..2 * SS]).unwrap().alt_lba;
        let bak_start = alt + 1 - (bak.len() / SS) as u64;
        let mut read = |lba: u64, n: u64| -> Result<Vec<u8>> {
            let (buf, base) = if lba + n <= (pri.len() / SS) as u64 {
                (&pri, 0)
            } else if lba >= bak_start && lba + n <= alt + 1 {
                (&bak, bak_start)
            } else {
                bail!("LBA {lba}+{n} not in dump");
            };
            let s = (lba - base) as usize * SS;
            Ok(buf[s..s + n as usize * SS].to_vec())
        };
        let g = gpt::read_lun(&mut read, SS).unwrap();
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
    println!("config[4095] = 0x{:02x}", cfg[4095]);
}
