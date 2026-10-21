//! `mtk restore-stock`: write the stock firmware in a OnePlus `.ops` package
//! back to slot a, streaming every image straight out of the package.
//!
//! Every `<program>` entry for slot a or without a slot is written, except:
//! the GPT entries (the live layout already matches the package, and the
//! factory `gpt_main0` has a 0-length userdata that only the `<patch>`
//! fix-ups resize), the profile's protected partitions, and the partitions
//! holding this phone's identity, unlock state and NV data. Erase entries are
//! written as zeros. Each entry is checked against the live GPT before
//! anything is written.

use crate::gpt::Entry;
use crate::image::{Image, hex};
use crate::ops::{Program, Settings};
use crate::write::{Region, Write};
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;

const GPT: &[&str] = &["PrimaryGPT", "BackupGPT"];
/// Skipped unless `--include`d: this phone's identity, unlock and NV data.
const DEVICE_SPECIFIC: &[&str] = &["param", "config", "oem_dycnvbk", "oem_stanvbk", "devinfo"];

pub enum Action {
    Write(Image),
    Erase,
    Skip(&'static str),
}

pub struct Item<'a> {
    pub prog: &'a Program,
    pub action: Action,
}

/// Decide what happens to every program entry, opening each image to write
/// from `pkg` (and checking its settings.xml SHA-256 when it has one).
pub fn select<'a>(s: &'a Settings, pkg: &File, protected: &[String], include: &[String]) -> Result<Vec<Item<'a>>> {
    for i in include {
        ensure!(
            s.programs.iter().any(|p| &p.label == i),
            "--include {i}: no such entry in the package"
        );
        ensure!(
            !GPT.contains(&i.as_str()),
            "--include {i}: GPT entries need the package's <patch> fix-ups, which mtk does not apply"
        );
    }
    let mut out: Vec<Item> = Vec::new();
    for p in &s.programs {
        let l = p.label.as_str();
        let wanted = include.iter().any(|i| i == l);
        let action = if GPT.contains(&l) {
            Action::Skip("GPT: the live layout already matches; the factory one has a 0-length userdata")
        } else if l.ends_with("_b") {
            Action::Skip("slot b")
        } else if p.filename.is_empty() && !p.erase {
            Action::Skip("no image in the package")
        } else if protected.iter().any(|x| x == l) && !wanted {
            Action::Skip("protected (device profile); --include it (and --force-protected) to write")
        } else if DEVICE_SPECIFIC.contains(&l) && !wanted {
            Action::Skip("this phone's identity/unlock/NV data; --include it to write")
        } else if p.erase {
            Action::Erase
        } else if p.len == 0 {
            Action::Skip("empty image")
        } else {
            Action::Write(image(pkg, p)?)
        };
        if !matches!(action, Action::Skip(_)) {
            ensure!(
                !out.iter()
                    .any(|o| !matches!(o.action, Action::Skip(_)) && (o.prog.lun, &o.prog.label) == (p.lun, &p.label)),
                "`{l}` on LUN{} is listed twice in the package; unsupported",
                p.lun
            );
        }
        out.push(Item { prog: p, action });
    }
    Ok(out)
}

fn image(pkg: &File, p: &Program) -> Result<Image> {
    ensure!(
        p.file_sector_offset == 0,
        "`{}`: image split over several entries (file_sector_offset {}); unsupported",
        p.label,
        p.file_sector_offset
    );
    let img = Image::slice(pkg.try_clone()?, &p.filename, p.offset, p.len)?;
    // settings.xml hashes non-sparse images zero-padded to 4 KiB, as ops::Ops::copy.
    if !p.sparse && p.sha256.len() == 64 {
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut r = img.reader(&img.extents[0]);
        loop {
            let n = r.read(&mut buf).with_context(|| format!("reading {}", p.filename))?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        h.update(vec![0u8; (p.len.next_multiple_of(0x1000) - p.len) as usize]);
        ensure!(
            hex(&h.finalize()) == p.sha256,
            "{}: sha256 does not match settings.xml (corrupt package?)",
            p.filename
        );
    }
    Ok(img)
}

/// The writes for every selected entry, each located in the live GPT: same
/// LUN and label, and starting at the sector the package gives.
pub fn writes(items: Vec<Item>, parts: &[(u8, Entry)], ss: usize) -> Result<Vec<Write>> {
    let mut out = Vec::new();
    for Item { prog: p, action } in items {
        if matches!(action, Action::Skip(_)) {
            continue;
        }
        ensure!(
            p.sector_size as usize == ss,
            "`{}`: sector size {} in the package, {ss} on the device",
            p.label,
            p.sector_size
        );
        let Some((_, e)) = parts.iter().find(|(l, e)| *l == p.lun && e.name == p.label) else {
            bail!("`{}` is not on LUN{} of the device", p.label, p.lun);
        };
        let start: u64 = p
            .start_sector
            .parse()
            .with_context(|| format!("`{}`: start sector `{}` is not a number", p.label, p.start_sector))?;
        ensure!(
            start == e.first_lba,
            "`{}`: the package puts it at sector {start}, the device at {}; the layouts differ \
             (restoring the GPT is not supported)",
            p.label,
            e.first_lba
        );
        let region = Region {
            name: e.name.clone(),
            lun: p.lun,
            start,
            sectors: e.sectors(),
        };
        let image = match action {
            Action::Write(img) => img,
            _ => {
                let n = if p.num_sectors > 0 { p.num_sectors } else { e.sectors() };
                Image::zeros(&format!("zeros (erase {})", p.label), n * ss as u64)
            }
        };
        out.push(Write { region, image });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpt::tests::{SS, disk_of, entry, reader};
    use crate::gpt::{OP_INACTIVE_TYPE, read_lun};
    use crate::write::tests::{fake, tmp, yes};

    const REAL: u32 = 0x20117f86;

    fn disk() -> Vec<u8> {
        let mut d = disk_of(&[
            entry("boot_a", REAL, 10, 19, 0x6f),
            entry("boot_b", OP_INACTIVE_TYPE, 20, 29, 0x3a),
            entry("misc", 0x82acc91f, 30, 31, 0),
            entry("persist", 0x6c95e238, 32, 33, 0),
            entry("param", 0x3e1cfa0e, 34, 35, 0),
            entry("abl_a", 0xbd6928a1, 36, 37, 0x44),
            entry("abl_b", OP_INACTIVE_TYPE, 38, 39, 0x0b),
        ]);
        d[10 * SS..40 * SS].fill(0xaa);
        d
    }

    fn prog(label: &str, file: &str, start: &str, n: u64, off: u64, len: u64, extra: &str) -> String {
        format!(
            "<program SECTOR_SIZE_IN_BYTES=\"4096\" file_sector_offset=\"0\" filename=\"{file}\" label=\"{label}\" \
             num_partition_sectors=\"{n}\" physical_partition_number=\"0\" start_sector=\"{start}\" \
             FileOffsetInSrc=\"{}\" SizeInByteInSrc=\"{len}\" {extra} />\n",
            off / 512
        )
    }

    /// A package (images at sector-aligned offsets) and its settings.xml.
    fn package(name: &str, abl_sha: Option<&str>) -> (std::path::PathBuf, Settings, Vec<u8>, Vec<u8>) {
        let (sparse, expanded, _) = crate::image::tests::sparse_fixture();
        let abl: Vec<u8> = (0..5000u32).map(|i| (i % 253) as u8 + 1).collect();
        let mut padded = abl.clone();
        padded.resize(2 * SS, 0);
        let sha = abl_sha.map_or_else(|| hex(&Sha256::digest(&padded)), str::to_owned);
        let (boot_off, abl_off, p_off) = (512u64, 512 + 40 * 1024, 512 + 48 * 1024);
        let mut pkg = vec![0u8; p_off as usize + 4096];
        pkg[boot_off as usize..][..sparse.len()].copy_from_slice(&sparse);
        pkg[abl_off as usize..][..abl.len()].copy_from_slice(&abl);
        pkg[p_off as usize..].fill(0x55);
        let xml = [
            "<?xml version=\"1.0\" ?><Setting><BasicInfo Project=\"18801\" /><Program0>\n".to_string(),
            prog("misc", "", "30", 2, 0, 0, "sparse=\"false\" force_erase=\"true\""),
            prog(
                "boot_a",
                "boot.img",
                "10",
                10,
                boot_off,
                sparse.len() as u64,
                "sparse=\"true\"",
            ),
            prog("boot_b", "", "20", 10, 0, 0, ""),
            prog("persist", "persist.img", "32", 2, p_off, 4096, ""),
            prog("param", "param.bin", "34", 2, p_off, 4096, ""),
            prog(
                "abl_a",
                "abl.elf",
                "36",
                2,
                abl_off,
                5000,
                &format!("sparse=\"false\" Sha256=\"{sha}\""),
            ),
            prog("abl_b", "abl.elf", "38", 2, abl_off, 5000, ""),
            prog("PrimaryGPT", "gpt_main0.bin", "0", 6, p_off, 4096, ""),
            prog(
                "BackupGPT",
                "gpt_backup0.bin",
                "NUM_DISK_SECTORS-5.",
                5,
                p_off,
                4096,
                "",
            ),
            "</Program0></Setting>".into(),
        ]
        .concat();
        let path = std::env::temp_dir().join(format!("mtk-restore-{}-{name}.ops", std::process::id()));
        std::fs::write(&path, pkg).unwrap();
        (path, Settings::parse(xml.as_bytes()).unwrap(), expanded, padded)
    }

    fn prot() -> Vec<String> {
        vec!["persist".into()]
    }

    fn summary(items: &[Item]) -> Vec<String> {
        items
            .iter()
            .map(|i| {
                let a = match &i.action {
                    Action::Write(_) => "write".into(),
                    Action::Erase => "erase".into(),
                    Action::Skip(r) => format!("skip: {}", r.split([';', ':']).next().unwrap()),
                };
                format!("{} {a}", i.prog.label)
            })
            .collect()
    }

    #[test]
    fn selects_slot_a_and_skips_device_data() {
        let (path, s, _, _) = package("select", None);
        let pkg = File::open(&path).unwrap();
        let items = select(&s, &pkg, &prot(), &[]).unwrap();
        assert_eq!(
            summary(&items),
            [
                "misc erase",
                "boot_a write",
                "boot_b skip: slot b",
                "persist skip: protected (device profile)",
                "param skip: this phone's identity/unlock/NV data",
                "abl_a write",
                "abl_b skip: slot b",
                "PrimaryGPT skip: GPT",
                "BackupGPT skip: GPT",
            ]
        );
        let inc = |i: &str| select(&s, &pkg, &prot(), &[i.into()]);
        assert_eq!(summary(&inc("param").unwrap())[4], "param write");
        assert_eq!(summary(&inc("persist").unwrap())[3], "persist write");
        assert!(inc("PrimaryGPT").err().unwrap().to_string().contains("<patch>"));
        assert!(inc("nope").err().unwrap().to_string().contains("no such entry"));
        std::fs::remove_file(&path).unwrap();
        let (path, s, _, _) = package("badsha", Some(&"0".repeat(64)));
        let e = select(&s, &File::open(&path).unwrap(), &prot(), &[]).err().unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(e.to_string().contains("abl.elf: sha256 does not match"), "{e}");
    }

    #[test]
    fn restores_through_the_fake_loader() {
        let (path, s, boot, abl) = package("write", None);
        let items = select(&s, &File::open(&path).unwrap(), &prot(), &["param".into()]).unwrap();
        std::fs::remove_file(&path).unwrap();
        let orig = disk();
        let parts: Vec<(u8, Entry)> = read_lun(&mut reader(&orig), SS)
            .unwrap()
            .entries
            .into_iter()
            .map(|e| (0, e))
            .collect();
        let w = writes(items, &parts, SS).unwrap();
        let names: Vec<&str> = w.iter().map(|w| w.region.name.as_str()).collect();
        assert_eq!(names, ["misc", "boot_a", "param", "abl_a"]);
        let mut fh = fake(vec![orig.clone()]);
        let root = tmp("restore");
        assert!(crate::write::run(&mut fh, &prot(), &w, yes(), &root).unwrap());
        std::fs::remove_dir_all(&root).unwrap();
        let d = &fh.t.luns[0];
        let sec = |a: usize, b: usize| &d[a * SS..b * SS];
        assert!(sec(30, 32).iter().all(|&b| b == 0), "misc erased");
        // boot.img is sparse: its DONT_CARE blocks 3..6 keep the old bytes.
        assert_eq!(sec(10, 13), &boot[..3 * SS]);
        assert!(sec(13, 16).iter().all(|&b| b == 0xaa));
        assert_eq!(sec(16, 19), &boot[6 * SS..]);
        assert!(sec(34, 35).iter().all(|&b| b == 0x55), "param included");
        assert_eq!(sec(36, 38), &abl[..]);
        assert_eq!(sec(20, 30), &orig[20 * SS..30 * SS], "boot_b untouched");
        assert_eq!(sec(32, 34), &orig[32 * SS..34 * SS], "persist untouched");
        assert_eq!(sec(38, 40), &orig[38 * SS..40 * SS], "abl_b untouched");
        assert_eq!(sec(0, 10), &orig[..10 * SS], "GPT untouched");
    }

    #[test]
    fn refuses_a_different_layout() {
        let (path, s, _, _) = package("layout", None);
        let items = select(&s, &File::open(&path).unwrap(), &prot(), &[]).unwrap();
        std::fs::remove_file(&path).unwrap();
        let d = disk_of(&[entry("misc", 0x82acc91f, 40, 41, 0)]);
        let parts: Vec<(u8, Entry)> = read_lun(&mut reader(&d), SS)
            .unwrap()
            .entries
            .into_iter()
            .map(|e| (0, e))
            .collect();
        let e = writes(items, &parts, SS).err().unwrap().to_string();
        assert!(
            e.contains("`misc`: the package puts it at sector 30, the device at 40"),
            "{e}"
        );
    }
}
