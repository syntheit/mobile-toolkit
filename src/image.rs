//! Write sources: a raw file, an Android sparse image (expanded while
//! streaming), or bytes in memory. An image is a list of extents, contiguous
//! byte runs relative to the start of the target region. Sparse DONT_CARE
//! chunks split extents, so those sectors are never written.

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::path::Path;

pub const SPARSE_MAGIC: u32 = 0xed26_ff3a;
const RAW: u16 = 0xcac1;
const FILL: u16 = 0xcac2;
const DONT_CARE: u16 = 0xcac3;
const CRC32: u16 = 0xcac4;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    File { off: u64, len: u64 },
    Fill { word: [u8; 4], len: u64 },
    Mem { off: usize, len: usize },
}

impl Piece {
    fn len(&self) -> u64 {
        match *self {
            Piece::File { len, .. } | Piece::Fill { len, .. } => len,
            Piece::Mem { len, .. } => len as u64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extent {
    /// Byte offset from the start of the target region.
    pub offset: u64,
    pub len: u64,
    pieces: Vec<Piece>,
}

pub struct Image {
    pub label: String,
    file: Option<File>,
    mem: Vec<u8>,
    pub extents: Vec<Extent>,
    /// Expanded size in bytes (a sparse image's total_blks * blk_sz).
    pub size: u64,
    pub sparse: bool,
    /// SHA-256 of the source as given (the sparse file itself, not its expansion).
    pub sha256: String,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

impl Image {
    /// Bytes to place at `offset` (bytes) into the target region.
    pub fn bytes(label: &str, offset: u64, data: Vec<u8>) -> Image {
        let sha256 = hex(&Sha256::digest(&data));
        let len = data.len();
        Image {
            label: label.into(),
            file: None,
            extents: vec![Extent {
                offset,
                len: len as u64,
                pieces: vec![Piece::Mem { off: 0, len }],
            }],
            mem: data,
            size: offset + len as u64,
            sparse: false,
            sha256,
        }
    }

    /// Open a raw or sparse image file (detected by magic). Hashes the file.
    pub fn open(path: &Path) -> Result<Image> {
        let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let flen = f.metadata()?.len();
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut r = &f;
        loop {
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        let mut magic = [0u8; 4];
        let sparse = flen >= 28 && f.read_exact_at(&mut magic, 0).is_ok() && u32::from_le_bytes(magic) == SPARSE_MAGIC;
        let (extents, size) = if sparse {
            parse_sparse(&f, flen).with_context(|| format!("{}: bad sparse image", path.display()))?
        } else {
            let pieces = vec![Piece::File { off: 0, len: flen }];
            (
                vec![Extent {
                    offset: 0,
                    len: flen,
                    pieces,
                }],
                flen,
            )
        };
        Ok(Image {
            label: path.display().to_string(),
            file: Some(f),
            mem: vec![],
            extents,
            size,
            sparse,
            sha256: hex(&h.finalize()),
        })
    }

    /// Bytes actually written (DONT_CARE excluded).
    pub fn data_len(&self) -> u64 {
        self.extents.iter().map(|e| e.len).sum()
    }

    pub fn reader<'a>(&'a self, e: &'a Extent) -> impl Read + 'a {
        ExtentReader {
            img: self,
            pieces: &e.pieces,
            i: 0,
            pos: 0,
        }
    }
}

fn parse_sparse(f: &File, flen: u64) -> Result<(Vec<Extent>, u64)> {
    let mut h = [0u8; 28];
    f.read_exact_at(&mut h, 0)?;
    let (major, fhdr, chdr) = (le16(&h, 4), le16(&h, 8) as u64, le16(&h, 10) as u64);
    let (blk, total_blks, chunks) = (le32(&h, 12) as u64, le32(&h, 16) as u64, le32(&h, 20));
    ensure!(major == 1, "unsupported sparse version {major}");
    ensure!(fhdr >= 28 && chdr >= 12, "bad header sizes {fhdr}/{chdr}");
    ensure!(blk > 0 && blk % 4 == 0, "bad block size {blk}");

    let (mut extents, mut cur): (Vec<Extent>, Option<Extent>) = (vec![], None);
    let (mut pos, mut at) = (fhdr, 0u64);
    for i in 0..chunks {
        let mut c = [0u8; 12];
        f.read_exact_at(&mut c, pos)
            .with_context(|| format!("chunk {i} header"))?;
        let (kind, blocks, total) = (le16(&c, 0), le32(&c, 4) as u64, le32(&c, 8) as u64);
        ensure!(total >= chdr && pos + total <= flen, "chunk {i} overruns the file");
        let (data_off, data_len, out) = (pos + chdr, total - chdr, blocks * blk);
        let piece = match kind {
            RAW => {
                ensure!(data_len == out, "chunk {i}: RAW size {data_len} != {out}");
                Some(Piece::File {
                    off: data_off,
                    len: out,
                })
            }
            FILL => {
                ensure!(data_len == 4, "chunk {i}: FILL data size {data_len}");
                let mut word = [0u8; 4];
                f.read_exact_at(&mut word, data_off)?;
                Some(Piece::Fill { word, len: out })
            }
            DONT_CARE => None,
            CRC32 => {
                ensure!(blocks == 0, "chunk {i}: CRC32 chunk with {blocks} blocks");
                pos += total;
                continue;
            }
            k => bail!("chunk {i}: unknown type {k:#06x}"),
        };
        match piece {
            Some(p) if out > 0 => {
                let e = cur.get_or_insert_with(|| Extent {
                    offset: at,
                    len: 0,
                    pieces: vec![],
                });
                e.len += out;
                e.pieces.push(p);
            }
            Some(_) => {}
            None => extents.extend(cur.take()),
        }
        at += out;
        pos += total;
    }
    extents.extend(cur);
    ensure!(
        at == total_blks * blk,
        "chunks cover {at} bytes, header says {}",
        total_blks * blk
    );
    Ok((extents, at))
}

struct ExtentReader<'a> {
    img: &'a Image,
    pieces: &'a [Piece],
    i: usize,
    pos: u64,
}

impl Read for ExtentReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let Some(p) = self.pieces.get(self.i) else {
            return Ok(0);
        };
        let take = (p.len() - self.pos).min(buf.len() as u64) as usize;
        let n = match *p {
            Piece::File { off, .. } => {
                let f = self.img.file.as_ref().expect("file piece without file");
                let n = f.read_at(&mut buf[..take], off + self.pos)?;
                if n == 0 && take > 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                n
            }
            Piece::Fill { word, .. } => {
                for (k, b) in buf[..take].iter_mut().enumerate() {
                    *b = word[(self.pos as usize + k) % 4];
                }
                take
            }
            Piece::Mem { off, .. } => {
                let s = off + self.pos as usize;
                buf[..take].copy_from_slice(&self.img.mem[s..s + take]);
                take
            }
        };
        self.pos += n as u64;
        if self.pos == p.len() {
            self.i += 1;
            self.pos = 0;
        }
        Ok(n)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Hand-built sparse image, blk 4096: RAW(2) FILL(1) DONT_CARE(3) CRC32 RAW(1) FILL(2).
    /// Returns (sparse bytes, expanded bytes, written-mask per block).
    pub fn sparse_fixture() -> (Vec<u8>, Vec<u8>, Vec<bool>) {
        const B: usize = 4096;
        let raw1: Vec<u8> = (0..2 * B).map(|i| (i * 7 % 256) as u8).collect();
        let raw2: Vec<u8> = (0..B).map(|i| (i * 13 % 256) as u8 | 1).collect();
        let chunk = |kind: u16, blocks: u32, data: &[u8]| {
            let mut c = vec![];
            c.extend(kind.to_le_bytes());
            c.extend([0, 0]);
            c.extend(blocks.to_le_bytes());
            c.extend((12 + data.len() as u32).to_le_bytes());
            c.extend(data);
            c
        };
        let mut s = vec![];
        s.extend(SPARSE_MAGIC.to_le_bytes());
        s.extend(1u16.to_le_bytes());
        s.extend(0u16.to_le_bytes());
        s.extend(28u16.to_le_bytes());
        s.extend(12u16.to_le_bytes());
        s.extend((B as u32).to_le_bytes());
        s.extend(9u32.to_le_bytes()); // total blocks
        s.extend(6u32.to_le_bytes()); // chunks
        s.extend(0u32.to_le_bytes());
        s.extend(chunk(RAW, 2, &raw1));
        s.extend(chunk(FILL, 1, &[0xde, 0xad, 0xbe, 0xef]));
        s.extend(chunk(DONT_CARE, 3, &[]));
        s.extend(chunk(CRC32, 0, &[1, 2, 3, 4]));
        s.extend(chunk(RAW, 1, &raw2));
        s.extend(chunk(FILL, 2, &[0, 0, 0, 0]));
        let mut x = raw1;
        x.extend([0xde, 0xad, 0xbe, 0xef].repeat(B / 4));
        x.extend(vec![0u8; 3 * B]);
        x.extend(raw2);
        x.extend(vec![0u8; 2 * B]);
        let mask = vec![true, true, true, false, false, false, true, true, true];
        (s, x, mask)
    }

    fn write_tmp(name: &str, data: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("mtk-test-{}-{name}", std::process::id()));
        std::fs::write(&p, data).unwrap();
        p
    }

    fn expand(img: &Image, e: &Extent) -> Vec<u8> {
        let mut v = vec![];
        img.reader(e).read_to_end(&mut v).unwrap();
        assert_eq!(v.len() as u64, e.len);
        v
    }

    #[test]
    fn sparse_expands() {
        let (s, x, _) = sparse_fixture();
        let p = write_tmp("sparse.img", &s);
        let img = Image::open(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        assert!(img.sparse);
        assert_eq!(img.size, 9 * 4096);
        assert_eq!(img.sha256, hex(&Sha256::digest(&s)));
        // DONT_CARE splits: blocks 0..3 and 6..9.
        let spans: Vec<(u64, u64)> = img.extents.iter().map(|e| (e.offset, e.len)).collect();
        assert_eq!(spans, [(0, 3 * 4096), (6 * 4096, 3 * 4096)]);
        assert_eq!(expand(&img, &img.extents[0]), x[..3 * 4096]);
        assert_eq!(expand(&img, &img.extents[1]), x[6 * 4096..]);
        assert_eq!(img.data_len(), 6 * 4096);
    }

    #[test]
    fn sparse_rejects_garbage() {
        let (mut s, _, _) = sparse_fixture();
        s[16] = 10; // total_blks no longer matches the chunks
        let p = write_tmp("bad.img", &s);
        assert!(Image::open(&p).is_err());
        s.truncate(40); // chunk overruns the file
        std::fs::write(&p, &s).unwrap();
        let e = Image::open(&p).err().unwrap();
        std::fs::remove_file(&p).unwrap();
        assert!(format!("{e:#}").contains("overruns"), "{e:#}");
    }

    #[test]
    fn raw_and_mem() {
        let data: Vec<u8> = (0..10000u32).map(|i| i as u8).collect();
        let p = write_tmp("raw.img", &data);
        let img = Image::open(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        assert!(!img.sparse && img.size == 10000 && img.extents.len() == 1);
        assert_eq!(expand(&img, &img.extents[0]), data);
        let m = Image::bytes("x", 8192, vec![5; 100]);
        assert_eq!((m.extents[0].offset, m.size), (8192, 8292));
        assert_eq!(expand(&m, &m.extents[0]), [5; 100]);
    }
}
