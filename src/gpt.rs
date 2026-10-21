//! GPT parsing and health checks (protective MBR, primary + backup header and
//! entry arrays, CRCs) plus Qualcomm A/B attribute decoding.

use anyhow::{Result, bail, ensure};
use std::fmt;

/// OnePlus marks inactive-slot partitions with a type GUID starting with this.
pub const OP_INACTIVE_TYPE: u32 = 0x7703_6cd4;
/// Sanity bound so a garbage header can't make us read megabytes of "entries".
const MAX_ENTRIES_BYTES: usize = 1 << 20;

#[derive(Debug, Clone)]
pub struct Header {
    pub my_lba: u64,
    pub alt_lba: u64,
    pub first_usable: u64,
    pub last_usable: u64,
    pub disk_guid: [u8; 16],
    pub entries_lba: u64,
    pub num_entries: u32,
    pub entry_size: u32,
    pub entries_crc: u32,
    pub crc_ok: bool,
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

impl Header {
    pub fn parse(sector: &[u8]) -> Result<Header> {
        ensure!(sector.len() >= 92, "short GPT header sector");
        ensure!(&sector[0..8] == b"EFI PART", "no GPT signature");
        let size = u32le(sector, 12) as usize;
        ensure!((92..=sector.len()).contains(&size), "bad GPT header size {size}");
        let mut h = sector[..size].to_vec();
        h[16..20].fill(0);
        let h = Header {
            my_lba: u64le(sector, 24),
            alt_lba: u64le(sector, 32),
            first_usable: u64le(sector, 40),
            last_usable: u64le(sector, 48),
            disk_guid: sector[56..72].try_into().unwrap(),
            entries_lba: u64le(sector, 72),
            num_entries: u32le(sector, 80),
            entry_size: u32le(sector, 84),
            entries_crc: u32le(sector, 88),
            crc_ok: crc32fast::hash(&h) == u32le(sector, 16),
        };
        ensure!(h.entry_size >= 128, "bad GPT entry size {}", h.entry_size);
        ensure!(h.entries_bytes() <= MAX_ENTRIES_BYTES, "GPT entry array too large");
        Ok(h)
    }

    pub fn entries_bytes(&self) -> usize {
        self.num_entries as usize * self.entry_size as usize
    }

    pub fn entries_sectors(&self, ss: usize) -> u64 {
        self.entries_bytes().div_ceil(ss) as u64
    }
}

/// Qualcomm A/B attribute byte (bits 48..56 of the GPT attributes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ab(pub u8);

impl Ab {
    pub fn priority(self) -> u8 {
        self.0 & 0x3
    }
    pub fn active(self) -> bool {
        self.0 & 0x4 != 0
    }
    pub fn retry(self) -> u8 {
        (self.0 >> 3) & 0x7
    }
    pub fn successful(self) -> bool {
        self.0 & 0x40 != 0
    }
    pub fn unbootable(self) -> bool {
        self.0 & 0x80 != 0
    }
}

impl fmt::Display for Ab {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:02x}[p{}", self.0, self.priority())?;
        if self.active() {
            f.write_str(" act")?;
        }
        if self.retry() != 0 {
            write!(f, " r{}", self.retry())?;
        }
        if self.successful() {
            f.write_str(" ok")?;
        }
        if self.unbootable() {
            f.write_str(" unb")?;
        }
        f.write_str("]")
    }
}

#[derive(Debug, Clone)]
pub struct Entry {
    /// Slot in the entry array.
    pub index: usize,
    pub type_guid: [u8; 16],
    pub unique_guid: [u8; 16],
    pub first_lba: u64,
    pub last_lba: u64,
    pub attrs: u64,
    pub name: String,
}

impl Entry {
    pub fn ab(&self) -> Ab {
        Ab((self.attrs >> 48) as u8)
    }
    pub fn sectors(&self) -> u64 {
        self.last_lba + 1 - self.first_lba
    }
    /// First field of the type GUID (little-endian u32), as edl prints it.
    pub fn type_prefix(&self) -> u32 {
        u32le(&self.type_guid, 0)
    }
}

/// Parse the used entries of an entry array (all-zero type GUID = unused).
pub fn parse_entries(buf: &[u8], hdr: &Header) -> Vec<Entry> {
    let esz = hdr.entry_size as usize;
    buf[..hdr.entries_bytes()]
        .chunks_exact(esz)
        .enumerate()
        .filter(|(_, e)| e[0..16].iter().any(|&b| b != 0))
        .map(|(index, e)| {
            let name: Vec<u16> = e[56..128]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&c| u16::from_le_bytes(c))
                .take_while(|&c| c != 0)
                .collect();
            Entry {
                index,
                type_guid: e[0..16].try_into().unwrap(),
                unique_guid: e[16..32].try_into().unwrap(),
                first_lba: u64le(e, 32),
                last_lba: u64le(e, 40),
                attrs: u64le(e, 48),
                name: String::from_utf16_lossy(&name),
            }
        })
        .collect()
}

/// One copy of the table: header + its raw entry array.
#[derive(Debug, Clone)]
pub struct Table {
    pub header: Header,
    /// The whole header sector as read.
    pub raw_header: Vec<u8>,
    pub raw_entries: Vec<u8>,
    pub entries_crc_ok: bool,
}

impl Table {
    fn new(header: Header, raw_header: &[u8], mut raw: Vec<u8>) -> Result<Table> {
        ensure!(raw.len() >= header.entries_bytes(), "short GPT entry array");
        raw.truncate(header.entries_bytes());
        let entries_crc_ok = crc32fast::hash(&raw) == header.entries_crc;
        Ok(Table {
            header,
            raw_header: raw_header.to_vec(),
            raw_entries: raw,
            entries_crc_ok,
        })
    }
}

/// Health of one LUN's GPT. `issues` empty == healthy.
#[derive(Debug)]
pub struct LunGpt {
    pub primary: Table,
    pub backup: Option<Table>,
    pub entries: Vec<Entry>,
    pub issues: Vec<String>,
}

/// Read and check a LUN's GPT. `read(lba, count)` returns `count` sectors.
pub fn read_lun(read: &mut dyn FnMut(u64, u64) -> Result<Vec<u8>>, ss: usize) -> Result<LunGpt> {
    let mut issues = Vec::new();
    let head = read(0, 2)?;
    ensure!(head.len() >= 2 * ss, "short read of LBA 0-1");
    if !pmbr_ok(&head[..ss]) {
        issues.push("protective MBR missing/invalid".into());
    }
    let ph = Header::parse(&head[ss..2 * ss])?;
    if ph.my_lba != 1 {
        issues.push(format!("primary header MyLBA={} (expected 1)", ph.my_lba));
    }
    let raw = read(ph.entries_lba, ph.entries_sectors(ss))?;
    let primary = Table::new(ph, &head[ss..2 * ss], raw)?;
    let ph = &primary.header;
    if !ph.crc_ok {
        issues.push("primary header CRC mismatch".into());
    }
    if !primary.entries_crc_ok {
        issues.push("primary entries CRC mismatch".into());
    }

    // Backup header lives at the primary's AlternateLBA; its entries at the
    // backup header's own PartitionEntryLBA (not necessarily alt-1).
    let backup = match read(ph.alt_lba, 1).and_then(|s| Ok((Header::parse(&s)?, s))) {
        Ok((bh, s)) => {
            let raw = read(bh.entries_lba, bh.entries_sectors(ss))?;
            Some(Table::new(bh, &s, raw)?)
        }
        Err(e) => {
            issues.push(format!("backup header at LBA {}: {e}", ph.alt_lba));
            None
        }
    };
    if let Some(b) = &backup {
        issues.extend(compare(&primary, b));
    }
    let entries = parse_entries(&primary.raw_entries, ph);
    Ok(LunGpt {
        primary,
        backup,
        entries,
        issues,
    })
}

/// A header sector updated for a new entry array: entries CRC, then header CRC.
pub fn rebuild_header(raw_header: &[u8], entries: &[u8]) -> Vec<u8> {
    let mut h = raw_header.to_vec();
    let size = u32le(&h, 12) as usize;
    h[88..92].copy_from_slice(&crc32fast::hash(entries).to_le_bytes());
    h[16..20].fill(0);
    let crc = crc32fast::hash(&h[..size]);
    h[16..20].copy_from_slice(&crc.to_le_bytes());
    h
}

fn pmbr_ok(s: &[u8]) -> bool {
    s.len() >= 512 && s[510] == 0x55 && s[511] == 0xaa && s[446 + 4] == 0xee
}

/// Differences between the primary and backup copies.
fn compare(p: &Table, b: &Table) -> Vec<String> {
    let (ph, bh) = (&p.header, &b.header);
    let mut out = Vec::new();
    if !bh.crc_ok {
        out.push("backup header CRC mismatch".into());
    }
    if !b.entries_crc_ok {
        out.push("backup entries CRC mismatch".into());
    }
    if bh.my_lba != ph.alt_lba || bh.alt_lba != ph.my_lba {
        out.push(format!(
            "header LBAs not mirrored: primary my={} alt={}, backup my={} alt={}",
            ph.my_lba, ph.alt_lba, bh.my_lba, bh.alt_lba
        ));
    }
    if (
        ph.first_usable,
        ph.last_usable,
        ph.disk_guid,
        ph.num_entries,
        ph.entry_size,
    ) != (
        bh.first_usable,
        bh.last_usable,
        bh.disk_guid,
        bh.num_entries,
        bh.entry_size,
    ) {
        out.push("primary/backup header fields differ".into());
    }
    if p.raw_entries != b.raw_entries {
        out.push("primary/backup entry arrays differ".into());
    }
    out
}

/// One `_a`/`_b` pair (either half may be missing).
pub struct Pair<'a> {
    pub base: String,
    pub a: Option<(u8, &'a Entry)>,
    pub b: Option<(u8, &'a Entry)>,
}

/// Group `<lun, entry>` items into A/B pairs, in first-seen order.
pub fn pairs<'a>(parts: &[(u8, &'a Entry)]) -> Vec<Pair<'a>> {
    let mut out: Vec<Pair> = Vec::new();
    for &(lun, e) in parts {
        let Some((base, slot)) = e.name.rsplit_once('_') else {
            continue;
        };
        if slot != "a" && slot != "b" {
            continue;
        }
        let idx = match out.iter().position(|p| p.base == base) {
            Some(i) => i,
            None => {
                out.push(Pair {
                    base: base.to_string(),
                    a: None,
                    b: None,
                });
                out.len() - 1
            }
        };
        let half = if slot == "a" { &mut out[idx].a } else { &mut out[idx].b };
        *half = Some((lun, e));
    }
    out
}

/// Active slot according to `boot_a`/`boot_b` attributes.
pub fn boot_slot(pairs: &[Pair]) -> Result<char> {
    let Some(p) = pairs.iter().find(|p| p.base == "boot") else {
        bail!("no boot_a/boot_b")
    };
    let act = |h: Option<(u8, &Entry)>| h.is_some_and(|(_, e)| e.ab().active());
    match (act(p.a), act(p.b)) {
        (true, false) => Ok('a'),
        (false, true) => Ok('b'),
        (true, true) => bail!("both boot_a and boot_b marked active"),
        (false, false) => bail!("neither boot_a nor boot_b marked active"),
    }
}

/// Inconsistencies in a pair, given the boot slot (if known).
pub fn pair_issues(p: &Pair, slot: Option<char>) -> Vec<String> {
    let (Some((_, a)), Some((_, b))) = (p.a, p.b) else {
        return vec![];
    };
    let mut out = Vec::new();
    let inactive_type = |e: &Entry| e.type_prefix() == OP_INACTIVE_TYPE;
    for e in [a, b] {
        if e.ab().active() && inactive_type(e) {
            out.push(format!(
                "{} marked active but has inactive type {OP_INACTIVE_TYPE:08x}",
                e.name
            ));
        }
    }
    if inactive_type(a) && inactive_type(b) {
        out.push(format!(
            "{}: both halves carry inactive type {OP_INACTIVE_TYPE:08x}",
            p.base
        ));
    }
    // Only pairs that use the active bit at all are expected to follow the slot.
    match (a.ab().active(), b.ab().active()) {
        (true, true) => out.push(format!("{}: both halves active", p.base)),
        (false, false) => {}
        (act_a, _) => {
            let s = if act_a { 'a' } else { 'b' };
            if slot.is_some_and(|boot| boot != s) {
                out.push(format!(
                    "{}: active on _{s} but boot slot is _{}",
                    p.base,
                    slot.unwrap()
                ));
            }
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const SS: usize = 4096;

    pub fn entry(name: &str, type_prefix: u32, first: u64, last: u64, ab: u8) -> Vec<u8> {
        let mut e = vec![0u8; 128];
        e[0..4].copy_from_slice(&type_prefix.to_le_bytes());
        e[4] = 1; // rest of the type GUID
        e[16] = 0x42;
        e[32..40].copy_from_slice(&first.to_le_bytes());
        e[40..48].copy_from_slice(&last.to_le_bytes());
        e[48..56].copy_from_slice(&((ab as u64) << 48).to_le_bytes());
        for (i, c) in name.encode_utf16().enumerate() {
            e[56 + 2 * i..58 + 2 * i].copy_from_slice(&c.to_le_bytes());
        }
        e
    }

    pub fn header(my: u64, alt: u64, entries_lba: u64, n: u32, ecrc: u32, last_lba: u64) -> Vec<u8> {
        let mut h = vec![0u8; SS];
        h[0..8].copy_from_slice(b"EFI PART");
        h[8..12].copy_from_slice(&0x10000u32.to_le_bytes());
        h[12..16].copy_from_slice(&92u32.to_le_bytes());
        h[24..32].copy_from_slice(&my.to_le_bytes());
        h[32..40].copy_from_slice(&alt.to_le_bytes());
        h[40..48].copy_from_slice(&6u64.to_le_bytes());
        h[48..56].copy_from_slice(&(last_lba - 5).to_le_bytes());
        h[56..72].copy_from_slice(&[7u8; 16]);
        h[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        h[80..84].copy_from_slice(&n.to_le_bytes());
        h[84..88].copy_from_slice(&128u32.to_le_bytes());
        h[88..92].copy_from_slice(&ecrc.to_le_bytes());
        let crc = crc32fast::hash(&h[..92]);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        h
    }

    /// A 64-sector disk laid out like a Qualcomm UFS LUN: entries at LBA 2..6,
    /// backup entries at last-4, backup header at last.
    pub fn disk() -> Vec<u8> {
        disk_of(&[
            entry("boot_a", 0x20117f86, 10, 19, 0x6f),
            entry("boot_b", OP_INACTIVE_TYPE, 20, 29, 0x3a),
            entry("xbl_a", 0xdea0ba2c, 30, 31, 0x44),
            entry("modemst1", 0xebbeadaf, 32, 33, 0),
        ])
    }

    /// A 64-sector disk holding the given (up to 32) entries.
    pub fn disk_of(entries: &[Vec<u8>]) -> Vec<u8> {
        let sectors = 64u64;
        let last = sectors - 1;
        let mut ents = entries.concat();
        ents.resize(32 * 128, 0);
        let ecrc = crc32fast::hash(&ents);
        let mut d = vec![0u8; sectors as usize * SS];
        d[446 + 4] = 0xee;
        d[510] = 0x55;
        d[511] = 0xaa;
        d[SS..2 * SS].copy_from_slice(&header(1, last, 2, 32, ecrc, last));
        d[2 * SS..2 * SS + ents.len()].copy_from_slice(&ents);
        let bl = (last - 4) as usize * SS;
        d[bl..bl + ents.len()].copy_from_slice(&ents);
        d[last as usize * SS..].copy_from_slice(&header(last, 1, last - 4, 32, ecrc, last));
        d
    }

    pub fn reader(d: &[u8]) -> impl FnMut(u64, u64) -> Result<Vec<u8>> + '_ {
        move |lba, n| {
            let (s, e) = (lba as usize * SS, (lba + n) as usize * SS);
            ensure!(e <= d.len(), "read past end of disk");
            Ok(d[s..e].to_vec())
        }
    }

    #[test]
    fn healthy_disk() {
        let d = disk();
        let g = read_lun(&mut reader(&d), SS).unwrap();
        assert!(g.issues.is_empty(), "{:?}", g.issues);
        assert_eq!(g.entries.len(), 4);
        assert_eq!(g.entries[0].name, "boot_a");
        assert_eq!(g.entries[0].sectors(), 10);
        assert_eq!(g.backup.unwrap().header.entries_lba, 59);
    }

    #[test]
    fn corrupt_primary_entries() {
        let mut d = disk();
        d[2 * SS + 60] ^= 1;
        let g = read_lun(&mut reader(&d), SS).unwrap();
        assert!(g.issues.iter().any(|i| i == "primary entries CRC mismatch"));
        assert!(g.issues.iter().any(|i| i == "primary/backup entry arrays differ"));
        assert!(!g.issues.iter().any(|i| i.starts_with("backup")));
    }

    #[test]
    fn corrupt_headers() {
        let mut d = disk();
        d[SS + 40] ^= 1; // primary FirstUsableLBA
        d[63 * SS + 80] ^= 1; // backup NumberOfEntries
        let g = read_lun(&mut reader(&d), SS).unwrap();
        assert!(g.issues.iter().any(|i| i == "primary header CRC mismatch"));
        assert!(g.issues.iter().any(|i| i == "backup header CRC mismatch"));
    }

    #[test]
    fn backup_entries_not_adjacent_to_header() {
        // Corrupting the sector just before the backup header must not matter:
        // the backup entries live at the header's PartitionEntryLBA.
        let mut d = disk();
        d[62 * SS] ^= 0xff;
        assert!(read_lun(&mut reader(&d), SS).unwrap().issues.is_empty());
    }

    #[test]
    fn missing_backup_and_pmbr() {
        let mut d = disk();
        d[63 * SS..63 * SS + 8].fill(0);
        d[510] = 0;
        let g = read_lun(&mut reader(&d), SS).unwrap();
        assert!(g.backup.is_none());
        assert!(g.issues[0].contains("protective MBR"));
        assert!(g.issues[1].contains("backup header at LBA 63"));
    }

    #[test]
    fn ab_bits() {
        let a = Ab(0x6f);
        assert_eq!(
            (a.priority(), a.active(), a.retry(), a.successful(), a.unbootable()),
            (3, true, 5, true, false)
        );
        assert_eq!(a.to_string(), "6f[p3 act r5 ok]");
        assert_eq!(Ab(0x3a).to_string(), "3a[p2 r7]");
        assert_eq!(Ab(0x80).to_string(), "80[p0 unb]");
    }

    #[test]
    fn slot_checks() {
        let d = disk();
        let g = read_lun(&mut reader(&d), SS).unwrap();
        let items: Vec<_> = g.entries.iter().map(|e| (4u8, e)).collect();
        let ps = pairs(&items);
        assert_eq!(ps.len(), 2); // boot, xbl
        assert_eq!(boot_slot(&ps).unwrap(), 'a');
        assert!(ps.iter().all(|p| pair_issues(p, Some('a')).is_empty()));

        // _a active while carrying the inactive type GUID.
        let mut bad = g.entries.clone();
        bad[0].type_guid[0..4].copy_from_slice(&OP_INACTIVE_TYPE.to_le_bytes());
        let items: Vec<_> = bad.iter().map(|e| (4u8, e)).collect();
        let is = pair_issues(&pairs(&items)[0], Some('a'));
        assert!(is.iter().any(|i| i.starts_with("boot_a marked active")));
        assert!(is.iter().any(|i| i.contains("both halves carry")));

        // Pair active on the other slot than boot.
        assert!(pair_issues(&pairs(&items)[0], Some('b'))[2].contains("boot slot is _b"));
    }
}
