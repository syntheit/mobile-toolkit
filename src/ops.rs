//! OnePlus `.ops` firmware packages (MsmDownloadTool). The footer points at an
//! encrypted `settings.xml` (the flash plan); the firehose loader is encrypted
//! too, everything else is stored plain. Ported from bkerler/oppo_decrypt
//! `opscrypto.py` (B. Kerler).
//!
//! The cipher is AES-shaped CFB-128 with the IV fixed to `KEY` per file, but the
//! round keys are not an AES key schedule: they are the 16 "mbox" bytes, each
//! widened to a 32-bit word, then zeros (10 rounds). Inputs shorter than one
//! block use a different keystream (the T-table bytes as round keys); that quirk
//! is kept for compatibility.

use anyhow::{Context, Result, bail, ensure};
use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const KEY: [u8; 16] = [
    0xd1, 0xb5, 0xe3, 0x9e, 0x5e, 0xea, 0x04, 0x9d, 0x67, 0x1d, 0xd5, 0xab, 0xd2, 0xaf, 0xcb, 0xaf,
];
/// Known mboxes, in the order they are tried.
const MBOXES: [(u8, [u8; 16]); 3] = [
    // guacamoles_31_O.09_190820
    (
        5,
        [
            0x60, 0x8a, 0x3f, 0x2d, 0x68, 0x6b, 0xd4, 0x23, 0x51, 0x0c, 0xd0, 0x95, 0xbb, 0x40, 0xe9, 0x76,
        ],
    ),
    // instantnoodlev_15_O.07_201103
    (
        6,
        [
            0xaa, 0x69, 0x82, 0x9e, 0x5d, 0xde, 0xb1, 0x3d, 0x30, 0xbb, 0x81, 0xa3, 0x46, 0x65, 0xa3, 0xe1,
        ],
    ),
    // guacamolet_21_O.08_190502
    (
        4,
        [
            0xc4, 0x5d, 0x05, 0x71, 0x99, 0xdd, 0xbb, 0xee, 0x29, 0xa1, 0x6d, 0xc7, 0xad, 0xbf, 0xa4, 0x3f,
        ],
    ),
];
const SECTOR: u64 = 0x200;
const CHUNK: usize = 1 << 20;

const fn aes_sbox() -> [u8; 256] {
    let mut s = [0u8; 256];
    let (mut p, mut q) = (1u8, 1u8);
    loop {
        p = p ^ (p << 1) ^ if p & 0x80 != 0 { 0x1b } else { 0 };
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        if q & 0x80 != 0 {
            q ^= 0x09;
        }
        s[p as usize] = q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4) ^ 0x63;
        if p == 1 {
            break;
        }
    }
    s[0] = 0x63;
    s
}
const SBOX: [u8; 256] = aes_sbox();

/// opscrypto's `sbox`: per byte s, the row [2s, s, s, 3s] twice (an AES T-table
/// laid out so unaligned 4-byte reads give its rotations).
const fn ttable() -> [u8; 2048] {
    let mut t = [0u8; 2048];
    let mut x = 0;
    while x < 256 {
        let s = SBOX[x];
        let s2 = (s << 1) ^ if s & 0x80 != 0 { 0x1b } else { 0 };
        let row = [s2, s, s, s2 ^ s];
        let mut k = 0;
        while k < 8 {
            t[x * 8 + k] = row[k % 4];
            k += 1;
        }
        x += 1;
    }
    t
}
static TBL: [u8; 2048] = ttable();

fn tw(x: u32, k: usize) -> u32 {
    let i = (x & 0xff) as usize * 8 + k;
    u32::from_le_bytes(TBL[i..i + 4].try_into().unwrap())
}

/// opscrypto `key_update`: one block through `rounds` rounds with round-key
/// words `rk(n)`. Transcribed as-is, including its final-round key order.
fn block(iv: [u32; 4], rk: impl Fn(usize) -> u32, rounds: usize) -> [u32; 4] {
    let (d, a, b, c) = (iv[0] ^ rk(0), iv[1] ^ rk(1), iv[2] ^ rk(2), iv[3] ^ rk(3));
    let mut e = tw(b >> 16, 2) ^ tw(a >> 8, 3) ^ tw(c >> 24, 1) ^ tw(d, 0) ^ rk(4);
    let mut h = tw(c >> 16, 2) ^ tw(b >> 8, 3) ^ tw(d >> 24, 1) ^ tw(a, 0) ^ rk(5);
    let mut i = tw(d >> 16, 2) ^ tw(c >> 8, 3) ^ tw(a >> 24, 1) ^ tw(b, 0) ^ rk(6);
    let mut a = tw(d >> 8, 3) ^ tw(a >> 16, 2) ^ tw(b >> 24, 1) ^ tw(c, 0) ^ rk(7);
    let mut g = 8;
    for _ in 2..rounds {
        (e, h, i, a) = (
            tw(i >> 16, 2) ^ tw(h >> 8, 3) ^ tw(a >> 24, 1) ^ tw(e, 0) ^ rk(g),
            tw(a >> 16, 2) ^ tw(i >> 8, 3) ^ tw(e >> 24, 1) ^ tw(h, 0) ^ rk(g + 1),
            tw(e >> 16, 2) ^ tw(a >> 8, 3) ^ tw(h >> 24, 1) ^ tw(i, 0) ^ rk(g + 2),
            tw(e >> 8, 3) ^ tw(h >> 16, 2) ^ tw(i >> 24, 1) ^ tw(a, 0) ^ rk(g + 3),
        );
        g += 4;
    }
    let sb = |x: u32, sh: u32| (SBOX[((x >> sh) & 0xff) as usize] as u32) << sh;
    let f = |w0, w1, w2, w3| sb(w0, 0) | sb(w1, 8) | sb(w2, 16) | sb(w3, 24);
    [
        f(e, h, i, a) ^ rk(g),
        f(h, i, a, e) ^ rk(g + 3),
        f(i, a, e, h) ^ rk(g + 2),
        f(a, e, h, i) ^ rk(g + 1),
    ]
}

fn words(b: &[u8]) -> [u32; 4] {
    std::array::from_fn(|n| u32::from_le_bytes(b[n * 4..n * 4 + 4].try_into().unwrap()))
}

/// Streaming decryptor for one stored file (fresh IV per file).
pub struct Cfb {
    iv: [u32; 4],
    mbox: [u8; 16],
    short: bool,
}

impl Cfb {
    /// `total` is the file's full length, which picks the <16-byte quirk.
    pub fn new(mbox: [u8; 16], total: u64) -> Cfb {
        Cfb {
            iv: words(&KEY),
            mbox,
            short: total < 16,
        }
    }

    fn keystream(&self) -> [u8; 16] {
        let ks = if self.short {
            block(self.iv, |n| TBL[n] as u32, TBL[0x3c] as usize)
        } else {
            block(self.iv, |n| self.mbox.get(n).map_or(0, |&b| b as u32), 10)
        };
        std::array::from_fn(|n| ks[n / 4].to_le_bytes()[n % 4])
    }

    /// Decrypt in place. Every call but the last must be a multiple of 16 bytes.
    pub fn decrypt(&mut self, buf: &mut [u8]) {
        for blk in buf.chunks_mut(16) {
            let ks = self.keystream();
            if blk.len() == 16 {
                self.iv = words(blk);
            }
            blk.iter_mut().zip(ks).for_each(|(b, k)| *b ^= k);
        }
    }

    /// Encrypt in place: the inverse of `decrypt` (used to build test packages).
    pub fn encrypt(&mut self, buf: &mut [u8]) {
        for blk in buf.chunks_mut(16) {
            let ks = self.keystream();
            blk.iter_mut().zip(ks).for_each(|(b, k)| *b ^= k);
            if blk.len() == 16 {
                self.iv = words(blk);
            }
        }
    }
}

/// A file stored in the package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    pub name: String,
    pub offset: u64,
    pub len: u64,
    pub encrypted: bool,
    /// Expected SHA-256 of the file zero-padded to 4 KiB. Only non-sparse program
    /// images: sparse ones carry a hash of something else (opscrypto skips them too).
    pub sha256: Option<String>,
}

/// One `<program>` entry: write `filename` to `label` on LUN `lun`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    pub lun: u8,
    pub label: String,
    /// Empty when the entry carries no image (the partition is left alone, or
    /// erased when `erase` is set).
    pub filename: String,
    pub sector_size: u32,
    /// A number, or an expression such as `NUM_DISK_SECTORS-5.` (backup GPT).
    pub start_sector: String,
    pub num_sectors: u64,
    pub file_sector_offset: u64,
    pub sparse: bool,
    pub erase: bool,
    pub offset: u64,
    pub len: u64,
    pub sha256: String,
}

/// One `<patch>` entry (GPT fix-ups once the disk size is known).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    pub lun: u8,
    pub sector_size: u32,
    pub filename: String,
    pub start_sector: String,
    pub byte_offset: u64,
    pub size_in_bytes: u32,
    pub value: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Settings {
    pub project: String,
    pub version: String,
    pub target: String,
    pub memory: String,
    /// `<SAHARA>` files (the firehose loader), encrypted.
    pub loaders: Vec<Blob>,
    /// `<UFS_PROVISION>` files by vendor.
    pub provision: Vec<(String, Blob)>,
    pub programs: Vec<Program>,
    pub patches: Vec<Patch>,
}

struct Attrs(Vec<(String, String)>);

impl Attrs {
    fn get(&self, k: &str) -> &str {
        self.0.iter().find(|(a, _)| a == k).map_or("", |(_, v)| v.as_str())
    }
    fn num<T: std::str::FromStr>(&self, k: &str) -> Result<T> {
        let v = self.get(k);
        v.parse().ok().with_context(|| format!("bad {k}=\"{v}\""))
    }
    fn blob(&self, name_key: &str, encrypted: bool) -> Result<Blob> {
        Ok(Blob {
            name: self.get(name_key).into(),
            offset: self.num::<u64>("FileOffsetInSrc")? * SECTOR,
            len: self.num("SizeInByteInSrc")?,
            encrypted,
            sha256: None,
        })
    }
    fn program(&self) -> Result<Program> {
        Ok(Program {
            lun: self.num("physical_partition_number")?,
            label: self.get("label").into(),
            filename: self.get("filename").into(),
            sector_size: self.num("SECTOR_SIZE_IN_BYTES")?,
            start_sector: self.get("start_sector").into(),
            num_sectors: self.num("num_partition_sectors")?,
            file_sector_offset: self.num("file_sector_offset")?,
            sparse: self.get("sparse") == "true",
            erase: self.get("force_erase") == "true",
            offset: self.num::<u64>("FileOffsetInSrc")? * SECTOR,
            len: self.num("SizeInByteInSrc")?,
            sha256: self.get("Sha256").to_ascii_lowercase(),
        })
    }
    fn patch(&self) -> Result<Patch> {
        Ok(Patch {
            lun: self.num("physical_partition_number")?,
            sector_size: self.num("SECTOR_SIZE_IN_BYTES")?,
            filename: self.get("filename").into(),
            start_sector: self.get("start_sector").into(),
            byte_offset: self.num("byte_offset")?,
            size_in_bytes: self.num("size_in_bytes")?,
            value: self.get("value").into(),
        })
    }
}

impl Settings {
    pub fn parse(xml: &[u8]) -> Result<Settings> {
        let mut s = Settings::default();
        let mut r = Reader::from_reader(xml);
        let (mut depth, mut section) = (0, String::new());
        loop {
            let (e, empty) = match r.read_event().context("settings.xml")? {
                Event::Start(e) => (e, false),
                Event::Empty(e) => (e, true),
                Event::End(_) => {
                    depth -= 1;
                    continue;
                }
                Event::Eof => break,
                _ => continue,
            };
            let tag = e.name().as_ref().to_owned();
            let a = Attrs(
                e.attributes()
                    .flatten()
                    .map(|a| {
                        let v = a.normalized_value(XmlVersion::Implicit1_0).map(|v| v.into_owned());
                        (a.key.as_ref().to_owned(), v.unwrap_or_default())
                    })
                    .collect(),
            );
            if depth == 1 {
                section.clone_from(&tag);
            }
            if !empty {
                depth += 1;
            }
            let ctx = || format!("settings.xml <{tag}> in <{section}>");
            match (section.as_str(), tag.as_str()) {
                (_, "BasicInfo") => {
                    s.project = a.get("Project").into();
                    s.version = a.get("Version").into();
                    s.target = a.get("TargetName").into();
                    s.memory = a.get("MemoryName").into();
                }
                ("SAHARA", "File") => s.loaders.push(a.blob("Path", true).with_context(ctx)?),
                ("UFS_PROVISION", "File") => s
                    .provision
                    .push((a.get("Name").into(), a.blob("Path", false).with_context(ctx)?)),
                (sec, "program") if sec.starts_with("Program") => s.programs.push(a.program().with_context(ctx)?),
                (sec, "patch") if sec.starts_with("Patch") => s.patches.push(a.patch().with_context(ctx)?),
                _ => {}
            }
        }
        Ok(s)
    }

    /// Every stored file once: loaders, provisioning XMLs, program images.
    pub fn blobs(&self) -> Result<Vec<Blob>> {
        let progs = self.programs.iter().filter(|p| !p.filename.is_empty()).map(|p| Blob {
            name: p.filename.clone(),
            offset: p.offset,
            len: p.len,
            encrypted: false,
            sha256: (!p.sparse && p.sha256.len() == 64).then(|| p.sha256.clone()),
        });
        let all = self
            .loaders
            .iter()
            .cloned()
            .chain(self.provision.iter().map(|(_, b)| b.clone()));
        let mut out: Vec<Blob> = Vec::new();
        for b in all.chain(progs) {
            ensure!(
                !b.name.is_empty() && !b.name.contains(['/', '\\']) && b.name != "." && b.name != "..",
                "unsafe file name {:?} in settings.xml",
                b.name
            );
            match out.iter().find(|o| o.name == b.name) {
                Some(o) if (o.offset, o.len) == (b.offset, b.len) => {}
                Some(_) => bail!("{} is listed twice with different contents", b.name),
                None => out.push(b),
            }
        }
        Ok(out)
    }
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

pub struct Ops {
    file: File,
    pub size: u64,
    /// Which mbox decrypted settings.xml (4, 5 or 6).
    pub mbox: u8,
    /// Project id and firmware name from the footer.
    pub project: String,
    pub firmware: String,
    /// Decrypted settings.xml, byte for byte.
    pub xml: Vec<u8>,
    pub settings: Settings,
    key: [u8; 16],
}

impl Ops {
    pub fn open(path: &Path) -> Result<Ops> {
        let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let size = file.metadata()?.len();
        ensure!(size >= SECTOR, "too small for an .ops package");
        let mut foot = [0u8; SECTOR as usize];
        file.seek(SeekFrom::Start(size - SECTOR))?;
        file.read_exact(&mut foot)?;
        let xml_len = u32::from_le_bytes(foot[0x18..0x1c].try_into().unwrap()) as u64;
        // As opscrypto: the XML (padded to whole sectors, a full extra sector
        // when already aligned) sits right before the footer.
        let stored = xml_len + SECTOR - xml_len % SECTOR;
        ensure!(stored + SECTOR <= size, "footer xml length {xml_len} out of range");
        let mut enc = vec![0u8; stored as usize];
        file.seek(SeekFrom::Start(size - SECTOR - stored))?;
        file.read_exact(&mut enc)?;
        for (id, mbox) in MBOXES {
            let mut xml = enc.clone();
            Cfb::new(mbox, stored).decrypt(&mut xml);
            if !xml.windows(4).any(|w| w == b"xml ") {
                continue;
            }
            xml.truncate(xml_len as usize);
            return Ok(Ops {
                file,
                size,
                mbox: id,
                project: cstr(&foot[0x1c..0x2c]),
                firmware: cstr(&foot[0x2c..0x100]),
                settings: Settings::parse(&xml)?,
                xml,
                key: mbox,
            });
        }
        bail!("settings.xml did not decrypt with any known mbox (not an .ops, or an unknown key)")
    }

    /// Stream one stored file into `out`; returns SHA-256 of it zero-padded to 4 KiB.
    pub fn copy(&self, b: &Blob, out: &mut dyn Write) -> Result<String> {
        let end = b.offset.checked_add(b.len);
        ensure!(
            end.is_some_and(|e| e <= self.size),
            "{} lies past the end of the package",
            b.name
        );
        let mut f = &self.file;
        f.seek(SeekFrom::Start(b.offset))?;
        let mut cfb = b.encrypted.then(|| Cfb::new(self.key, b.len));
        let (mut left, mut buf, mut h) = (b.len, vec![0u8; CHUNK], Sha256::new());
        while left > 0 {
            let n = left.min(CHUNK as u64) as usize;
            f.read_exact(&mut buf[..n])
                .with_context(|| format!("reading {}", b.name))?;
            if let Some(c) = &mut cfb {
                c.decrypt(&mut buf[..n]);
            }
            h.update(&buf[..n]);
            out.write_all(&buf[..n])?;
            left -= n as u64;
        }
        h.update(vec![0u8; (b.len.next_multiple_of(0x1000) - b.len) as usize]);
        Ok(h.finalize().iter().map(|x| format!("{x:02x}")).collect())
    }
}

fn size(bytes: u64) -> String {
    let units = ["B", "K", "M", "G"];
    let (mut v, mut i) = (bytes as f64, 0);
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1}{}", units[i])
}

/// `mtk ops`: summary, optional program table, optional extraction.
/// Returns false if any image failed its hash check.
pub fn cli(path: &Path, extract: Option<&Path>, list: bool) -> Result<bool> {
    let ops = Ops::open(path)?;
    let s = &ops.settings;
    println!(
        "ops      {}  project {} (footer {})  mbox{}  {} {}",
        ops.firmware, s.project, ops.project, ops.mbox, s.target, s.memory
    );
    let blobs = s.blobs()?;
    println!(
        "plan     {} program entries ({} with images), {} patches, {} files, {}",
        s.programs.len(),
        s.programs.iter().filter(|p| !p.filename.is_empty()).count(),
        s.patches.len(),
        blobs.len(),
        size(blobs.iter().map(|b| b.len).sum())
    );
    for b in &s.loaders {
        println!("loader   {} ({} bytes, encrypted)", b.name, b.len);
    }
    if list {
        println!(
            "  LUN {:<18} {:>20} {:>9}  {:<26} {:>8}",
            "partition", "start", "sectors", "file", "size"
        );
        for p in &s.programs {
            let file = if p.filename.is_empty() { "-" } else { &p.filename };
            let flags = [(p.sparse, " sparse"), (p.erase, " erase")];
            let flags: String = flags.iter().filter(|f| f.0).map(|f| f.1).collect();
            println!(
                "  {:>3} {:<18} {:>20} {:>9}  {:<26} {:>8}{flags}",
                p.lun,
                p.label,
                p.start_sector,
                p.num_sectors,
                file,
                if p.filename.is_empty() { "".into() } else { size(p.len) }
            );
        }
    }
    let Some(dir) = extract else { return Ok(true) };
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::write(dir.join("settings.xml"), &ops.xml)?;
    let mut bad = 0;
    for b in &blobs {
        let p = dir.join(&b.name);
        let mut w = std::io::BufWriter::new(File::create(&p).with_context(|| format!("creating {}", p.display()))?);
        let got = ops.copy(b, &mut w)?;
        w.flush()?;
        let check = match &b.sha256 {
            None => "",
            Some(want) if *want == got => "  sha256 ok",
            Some(_) => {
                bad += 1;
                "  sha256 MISMATCH"
            }
        };
        println!("wrote    {:<26} {:>8}{check}", b.name, size(b.len));
    }
    let checked = blobs.iter().filter(|b| b.sha256.is_some()).count();
    println!(
        "summary  {} files + settings.xml in {}; sha256 checked {checked}, {bad} mismatch(es)",
        blobs.len(),
        dir.display()
    );
    Ok(bad == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn table_matches_opscrypto() {
        assert_eq!(TBL[..16], unhex("c66363a5c66363a5f87c7c84f87c7c84")[..]);
        assert_eq!(TBL[2032..], unhex("6dbbbbd66dbbbbd62c16163a2c16163a")[..]);
    }

    /// Ciphertexts produced by opscrypto.py `key_custom(..., encrypt=True)`.
    #[test]
    fn decrypts_opscrypto_vectors() {
        let pt = b"The quick brown fox jumps over the lazy dog, 40B";
        let cases = [
            (
                4,
                "984d31b26e5df9276bded0a9398b3ba28c8e701448f551774ed84f7a6fd1b24b45882435e6e3f4527e3c485701d8f0f2",
            ),
            (
                5,
                "6273801c78eb05f25d8c6b45c451db6b6f0bb558bab370e6fc08e27154a793e44888d7d950a49137295052950a363735",
            ),
            (
                6,
                "e516887cb2aa8400cc53282621a398e80bd26a9fe1e347909b067d4401538896f8ffac9fc30837cb4b43de172b581a4f",
            ),
        ];
        for (id, ct) in cases {
            let mbox = MBOXES.iter().find(|m| m.0 == id).unwrap().1;
            let mut b = unhex(ct);
            Cfb::new(mbox, 48).decrypt(&mut b);
            assert_eq!(b, pt, "mbox{id}");
            // Partial last block, streamed in two calls.
            let mut b = unhex(&ct[..82]);
            let mut c = Cfb::new(mbox, 41);
            let (x, y) = b.split_at_mut(16);
            c.decrypt(x);
            c.decrypt(y);
            assert_eq!(b, pt[..41], "mbox{id} partial");
        }
        // Start of the real settings.xml in fajitat_34_O.01_210114.ops.
        let mut b = unhex("d9a05a0036e601fd16da6c45d84fda2537b8d1befd110cc98bb0528c6b9d33a2");
        Cfb::new(MBOXES[0].1, 86528).decrypt(&mut b);
        assert_eq!(b, "\u{feff}<?xml version=\"1.0\" encoding=".as_bytes());
        // Under one block: the T-table keystream, the same for every mbox.
        let mut b = unhex("2dfaf3492e43a18e30f796c6");
        Cfb::new(MBOXES[0].1, 12).decrypt(&mut b);
        assert_eq!(b, b"hello world!");
    }

    #[test]
    fn parses_settings() {
        let xml = br#"<?xml version="1.0" encoding="utf-8" ?>
<Setting>
  <BasicInfo Project="18801" Version="v1" MemoryName="ufs" TargetName="SDM845" />
  <SAHARA><File Id="13" Path="prog.elf" FileOffsetInSrc="0" SizeInSectorInSrc="2" SizeInByteInSrc="700" /></SAHARA>
  <UFS_PROVISION><File Name="samsung" Path="p.xml" FileOffsetInSrc="2" SizeInSectorInSrc="1" SizeInByteInSrc="9" /></UFS_PROVISION>
  <Program0>
    <program SECTOR_SIZE_IN_BYTES="4096" file_sector_offset="0" filename="" label="misc" num_partition_sectors="256" physical_partition_number="0" sparse="false" start_sector="8200" FileOffsetInSrc="0" SizeInByteInSrc="0" Sha256="0" force_erase="true" />
    <program SECTOR_SIZE_IN_BYTES="4096" file_sector_offset="0" filename="gpt_backup0.bin" label="BackupGPT" num_partition_sectors="5" physical_partition_number="0" sparse="false" start_sector="NUM_DISK_SECTORS-5." FileOffsetInSrc="3" SizeInByteInSrc="20480" Sha256="AB" />
  </Program0>
  <Program5>
    <group><program SECTOR_SIZE_IN_BYTES="4096" file_sector_offset="0" filename="gpt_backup0.bin" label="x" num_partition_sectors="5" physical_partition_number="5" sparse="true" start_sector="6" FileOffsetInSrc="3" SizeInByteInSrc="20480" Sha256="" /></group>
  </Program5>
  <Patch0>
    <patch SECTOR_SIZE_IN_BYTES="4096" byte_offset="48" filename="DISK" physical_partition_number="0" size_in_bytes="8" start_sector="1" value="NUM_DISK_SECTORS-6." what="w &apos;q&apos;" />
  </Patch0>
</Setting>"#;
        let s = Settings::parse(xml).unwrap();
        assert_eq!(
            (s.project.as_str(), s.target.as_str(), s.memory.as_str()),
            ("18801", "SDM845", "ufs")
        );
        assert_eq!(s.loaders[0].offset, 0);
        assert_eq!((s.provision[0].0.as_str(), s.provision[0].1.offset), ("samsung", 0x400));
        assert_eq!(s.programs.len(), 3);
        let (m, g) = (&s.programs[0], &s.programs[1]);
        assert!(m.erase && m.filename.is_empty() && m.num_sectors == 256 && m.start_sector == "8200");
        assert_eq!(
            (g.start_sector.as_str(), g.offset, g.len, g.sha256.as_str()),
            ("NUM_DISK_SECTORS-5.", 0x600, 20480, "ab")
        );
        assert!(s.programs[2].sparse && s.programs[2].lun == 5);
        assert_eq!(s.patches[0].value, "NUM_DISK_SECTORS-6.");
        let names: Vec<String> = s.blobs().unwrap().into_iter().map(|b| b.name).collect();
        assert_eq!(names, ["prog.elf", "p.xml", "gpt_backup0.bin"]);

        let bad = String::from_utf8_lossy(xml).replace("p.xml", "../p.xml");
        assert!(Settings::parse(bad.as_bytes()).unwrap().blobs().is_err());
    }
}
