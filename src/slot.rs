//! `mtk slot`: compute the GPT tables that make one A/B slot active.
//!
//! The desired table is a pure function of the current one and the target
//! slot, and applying it twice changes nothing, so a repeated or interrupted
//! run converges instead of flipping state like edl's `setactiveslot`:
//! - `boot_<t>` gets `BOOT_ACTIVE`, `boot_<o>` gets `BOOT_INACTIVE`;
//! - every other `_t` half gets the active bit set, every `_o` half cleared
//!   (abl `MarkPtnActive`); the rest of the attribute byte is kept;
//! - OnePlus type GUIDs: in a pair where exactly one half carries the inactive
//!   type `77036cd4…`, `_t` gets the real type and `_o` the inactive one.
//!   Pairs with two real types (xbl, on LUN1/LUN2) are left alone.
//!
//! Per LUN the writes are ordered backup entries, backup header, primary, so
//! at every point at least one copy has valid CRCs. A LUN whose primary
//! entries fail their CRC is rebuilt from the backup copy.

use crate::gpt::{self, Entry, LunGpt, OP_INACTIVE_TYPE};
use anyhow::{Result, anyhow, bail, ensure};

/// Priority 3, active, retry 5, successful: what the healthy booted slot carries (and what edl writes).
pub const BOOT_ACTIVE: u8 = 0x6f;
/// Priority 2, retry 7, not active: what abl leaves on the alternate slot.
pub const BOOT_INACTIVE: u8 = 0x3a;
const ACTIVE_BIT: u8 = 0x04;
/// Offset of the A/B byte (attribute bits 48..56) in a GPT entry.
const AB_OFFSET: usize = 54;

#[derive(Debug)]
pub struct Change {
    pub name: String,
    pub old: (u8, u32),
    pub new: (u8, u32),
}

/// One sector-aligned write: (region name, LBA, bytes).
pub type SectorWrite = (String, u64, Vec<u8>);

#[derive(Debug)]
pub struct LunPlan {
    pub lun: u8,
    /// Desired entry array.
    pub entries: Vec<u8>,
    /// Entry changes relative to the copy used as the base.
    pub changes: Vec<Change>,
    /// Writes in safe order; empty when both copies already match.
    pub writes: Vec<SectorWrite>,
    pub note: Option<String>,
}

pub fn plan(luns: &[(u8, LunGpt)], slot: char, ss: usize) -> Result<Vec<LunPlan>> {
    ensure!(slot == 'a' || slot == 'b', "slot must be a or b");
    let mut bases = Vec::new();
    for (lun, g) in luns {
        let b = g
            .backup
            .as_ref()
            .ok_or_else(|| anyhow!("LUN{lun}: no backup GPT; refusing"))?;
        let (ph, bh) = (&g.primary.header, &b.header);
        ensure!(ph.crc_ok && bh.crc_ok, "LUN{lun}: GPT header CRC mismatch; refusing");
        ensure!(
            ph.my_lba == bh.alt_lba && ph.alt_lba == bh.my_lba,
            "LUN{lun}: primary/backup header LBAs not mirrored; refusing"
        );
        ensure!(
            (ph.num_entries, ph.entry_size) == (bh.num_entries, bh.entry_size),
            "LUN{lun}: primary/backup entry geometry differs; refusing"
        );
        ensure!(
            ph.entries_bytes() % ss == 0,
            "LUN{lun}: entry array is not a whole number of sectors; unsupported"
        );
        let (base, note) = match (g.primary.entries_crc_ok, b.entries_crc_ok) {
            (true, true) if g.primary.raw_entries != b.raw_entries => (
                &g.primary.raw_entries,
                Some("primary and backup entries differ (interrupted run?); rebuilding both from the primary".into()),
            ),
            (true, _) => (&g.primary.raw_entries, None),
            (false, true) => (
                &b.raw_entries,
                Some("primary entries fail their CRC; rebuilding from the backup copy".into()),
            ),
            (false, false) => bail!("LUN{lun}: neither entry array matches its CRC; refusing"),
        };
        bases.push((*lun, g, base.clone(), note));
    }

    let parsed: Vec<(u8, Entry)> = bases
        .iter()
        .flat_map(|(lun, g, base, _)| {
            gpt::parse_entries(base, &g.primary.header)
                .into_iter()
                .map(|e| (*lun, e))
        })
        .collect();
    let refs: Vec<(u8, &Entry)> = parsed.iter().map(|(l, e)| (*l, e)).collect();
    let pairs = gpt::pairs(&refs);
    ensure!(
        pairs.iter().any(|p| p.base == "boot" && p.a.is_some() && p.b.is_some()),
        "no boot_a/boot_b pair"
    );

    let mut new: Vec<Vec<u8>> = bases.iter().map(|b| b.2.clone()).collect();
    let pos = |lun: u8| bases.iter().position(|b| b.0 == lun).unwrap();
    for p in &pairs {
        let (Some(a), Some(b)) = (p.a, p.b) else {
            continue;
        };
        let (t, o) = if slot == 'a' { (a, b) } else { (b, a) };
        let inactive = |e: &Entry| e.type_prefix() == OP_INACTIVE_TYPE;
        let types = match (inactive(t.1), inactive(o.1)) {
            (false, false) => None,
            (true, true) => bail!(
                "{}: both halves carry the inactive type {OP_INACTIVE_TYPE:08x}; the real type is unknown, refusing",
                p.base
            ),
            (false, true) => Some((t.1.type_guid, o.1.type_guid)),
            (true, false) if t.0 != o.0 => bail!(
                "{}: type swap across LUN{} and LUN{} is not supported",
                p.base,
                t.0,
                o.0
            ),
            (true, false) => Some((o.1.type_guid, t.1.type_guid)),
        };
        let boot = p.base == "boot";
        let ab_t = if boot { BOOT_ACTIVE } else { t.1.ab().0 | ACTIVE_BIT };
        let ab_o = if boot { BOOT_INACTIVE } else { o.1.ab().0 & !ACTIVE_BIT };
        for ((lun, e), ab, ty) in [(t, ab_t, types.map(|x| x.0)), (o, ab_o, types.map(|x| x.1))] {
            let esz = bases[pos(lun)].1.primary.header.entry_size as usize;
            let raw = &mut new[pos(lun)][e.index * esz..(e.index + 1) * esz];
            raw[AB_OFFSET] = ab;
            if let Some(ty) = ty {
                raw[..16].copy_from_slice(&ty);
            }
        }
    }

    let mut out = Vec::new();
    for ((lun, g, base, note), entries) in bases.into_iter().zip(new) {
        let (pri, bak) = (&g.primary, g.backup.as_ref().unwrap());
        let hdr = &pri.header;
        let changes = gpt::parse_entries(base.as_slice(), hdr)
            .into_iter()
            .zip(gpt::parse_entries(&entries, hdr))
            .filter(|(o, n)| (o.ab(), o.type_guid) != (n.ab(), n.type_guid))
            .map(|(o, n)| Change {
                old: (o.ab().0, o.type_prefix()),
                new: (n.ab().0, n.type_prefix()),
                name: o.name,
            })
            .collect();
        let ph = gpt::rebuild_header(&pri.raw_header, &entries);
        let bh = gpt::rebuild_header(&bak.raw_header, &entries);
        let mut writes: Vec<SectorWrite> = Vec::new();
        if bak.raw_entries != entries || bak.raw_header != bh {
            writes.push((
                format!("gpt{lun}-backup-entries"),
                bak.header.entries_lba,
                entries.clone(),
            ));
            writes.push((format!("gpt{lun}-backup-header"), bak.header.my_lba, bh));
        }
        if pri.raw_entries != entries || pri.raw_header != ph {
            if hdr.entries_lba == hdr.my_lba + 1 {
                writes.push((format!("gpt{lun}-primary"), hdr.my_lba, [ph, entries.clone()].concat()));
            } else {
                writes.push((format!("gpt{lun}-primary-entries"), hdr.entries_lba, entries.clone()));
                writes.push((format!("gpt{lun}-primary-header"), hdr.my_lba, ph));
            }
        }
        out.push(LunPlan {
            lun,
            entries,
            changes,
            writes,
            note,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpt::tests::{SS, disk_of, entry, reader};
    use crate::gpt::{boot_slot, pairs, read_lun};

    const REAL: u32 = 0x20117f86;

    /// LUN0: boot + aop pairs (OnePlus type swap) + a lone partition.
    /// LUN1/LUN2: xbl_a / xbl_b, both with the real type.
    fn disks() -> Vec<Vec<u8>> {
        vec![
            disk_of(&[
                entry("boot_a", REAL, 10, 19, 0x6f),
                entry("boot_b", OP_INACTIVE_TYPE, 20, 29, 0x3a),
                entry("aop_a", 0xd69e90a5, 30, 31, 0x44),
                entry("aop_b", OP_INACTIVE_TYPE, 32, 33, 0x0b),
                entry("modemst1", 0xebbeadaf, 34, 35, 0),
            ]),
            disk_of(&[entry("xbl_a", 0xdea0ba2c, 10, 11, 0x44)]),
            disk_of(&[entry("xbl_b", 0xdea0ba2c, 10, 11, 0x00)]),
        ]
    }

    fn gpts(d: &[Vec<u8>]) -> Vec<(u8, LunGpt)> {
        d.iter()
            .enumerate()
            .map(|(l, d)| (l as u8, read_lun(&mut reader(d), SS).unwrap()))
            .collect()
    }

    /// Apply the plans' writes, stopping after `limit` sectors (a power cut).
    fn apply(d: &mut [Vec<u8>], plans: &[LunPlan], limit: usize) -> usize {
        let sectors = plans.iter().flat_map(|p| {
            p.writes.iter().flat_map(move |(_, lba, data)| {
                data.chunks(SS)
                    .enumerate()
                    .map(move |(i, c)| (p.lun, *lba as usize + i, c))
            })
        });
        let mut n = 0;
        for (lun, lba, data) in sectors.take(limit) {
            d[lun as usize][lba * SS..(lba + 1) * SS].copy_from_slice(data);
            n += 1;
        }
        n
    }

    fn switch(d: &mut [Vec<u8>], slot: char) -> Vec<LunPlan> {
        let p = plan(&gpts(d), slot, SS).unwrap();
        apply(d, &p, usize::MAX);
        for (_, g) in gpts(d) {
            assert!(g.issues.is_empty(), "{:?}", g.issues);
        }
        p
    }

    fn summary(d: &[Vec<u8>]) -> Vec<(String, u8, u32)> {
        gpts(d)
            .into_iter()
            .flat_map(|(_, g)| {
                g.entries
                    .into_iter()
                    .map(|e| (e.name.clone(), e.ab().0, e.type_prefix()))
            })
            .collect()
    }

    #[test]
    fn current_slot_is_noop() {
        let p = plan(&gpts(&disks()), 'a', SS).unwrap();
        assert!(p.iter().all(|l| l.writes.is_empty() && l.changes.is_empty()));
    }

    #[test]
    fn switch_and_back_round_trips() {
        let orig = disks();
        let mut d = orig.clone();
        let p = switch(&mut d, 'b');
        assert_eq!(p[0].changes.len(), 4);
        assert_eq!(p[1].changes.len(), 1);
        let s = summary(&d);
        let get = |n: &str| s.iter().find(|x| x.0 == n).unwrap().clone();
        assert_eq!(get("boot_b"), ("boot_b".into(), BOOT_ACTIVE, REAL));
        assert_eq!(get("boot_a"), ("boot_a".into(), BOOT_INACTIVE, OP_INACTIVE_TYPE));
        assert_eq!(get("aop_b"), ("aop_b".into(), 0x0f, 0xd69e90a5));
        assert_eq!(get("aop_a"), ("aop_a".into(), 0x40, OP_INACTIVE_TYPE));
        assert_eq!(get("xbl_b"), ("xbl_b".into(), 0x04, 0xdea0ba2c));
        assert_eq!(get("xbl_a"), ("xbl_a".into(), 0x40, 0xdea0ba2c));
        assert_eq!(get("modemst1").1, 0);
        let g = gpts(&d);
        let all: Vec<(u8, &Entry)> = g.iter().flat_map(|(l, g)| g.entries.iter().map(|e| (*l, e))).collect();
        assert_eq!(boot_slot(&pairs(&all)).unwrap(), 'b');
        // Idempotent, then back to a byte for byte.
        assert!(plan(&gpts(&d), 'b', SS).unwrap().iter().all(|l| l.writes.is_empty()));
        switch(&mut d, 'a');
        assert_eq!(d, orig);
    }

    #[test]
    fn interrupted_runs_converge() {
        let mut want = disks();
        switch(&mut want, 'b');
        let p = plan(&gpts(&disks()), 'b', SS).unwrap();
        let total = apply(&mut disks(), &p, usize::MAX);
        assert_eq!(total, 2 * 3 + 2 * 3); // 3 LUNs change; each: backup entries+header, primary hdr+entries
        for cut in 0..total {
            let mut d = disks();
            apply(&mut d, &p, cut);
            let again = plan(&gpts(&d), 'b', SS).unwrap();
            apply(&mut d, &again, usize::MAX);
            assert_eq!(d, want, "interrupted after {cut} writes");
        }
    }

    #[test]
    fn rebuilds_from_valid_backup() {
        let mut d = disks();
        d[0][2 * SS + 60] ^= 1; // primary entries CRC now bad
        let p = plan(&gpts(&d), 'a', SS).unwrap();
        assert!(p[0].note.as_deref().unwrap().contains("backup"));
        assert_eq!(p[0].writes.len(), 1); // primary only
        assert!(p[1..].iter().all(|l| l.writes.is_empty()));
        apply(&mut d, &p, usize::MAX);
        assert_eq!(d, disks());
    }

    #[test]
    fn refuses_unknown_real_type() {
        let d = vec![disk_of(&[
            entry("boot_a", OP_INACTIVE_TYPE, 10, 19, 0x6f),
            entry("boot_b", OP_INACTIVE_TYPE, 20, 29, 0x3a),
        ])];
        let e = plan(&gpts(&d), 'b', SS).unwrap_err().to_string();
        assert!(e.contains("real type is unknown"), "{e}");
    }
}
