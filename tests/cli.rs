//! Runs the `mtk` binary offline (no device): `ops` on a synthetic package.

use mobile_toolkit::ops::Cfb;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// mbox5 (guacamoles_31_O.09_190820), as in src/ops.rs.
const MBOX5: [u8; 16] = [
    0x60, 0x8a, 0x3f, 0x2d, 0x68, 0x6b, 0xd4, 0x23, 0x51, 0x0c, 0xd0, 0x95, 0xbb, 0x40, 0xe9, 0x76,
];

/// A minimal .ops: 2 sectors of image data, encrypted settings.xml, footer.
fn synthetic_ops() -> PathBuf {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<Setting>\n\
         <BasicInfo Project=\"18801\" Version=\"t\" MemoryName=\"ufs\" TargetName=\"SDM845\" />\n<Program0>\n",
    );
    for i in 0..2000 {
        xml += &format!(
            "<program SECTOR_SIZE_IN_BYTES=\"4096\" file_sector_offset=\"0\" filename=\"\" label=\"p{i}\" \
             num_partition_sectors=\"1\" physical_partition_number=\"0\" sparse=\"false\" start_sector=\"{i}\" \
             FileOffsetInSrc=\"0\" SizeInByteInSrc=\"0\" Sha256=\"\" />\n"
        );
    }
    xml += "</Program0>\n</Setting>\n";
    let mut enc = xml.into_bytes();
    let xml_len = enc.len();
    enc.resize(xml_len + 512 - xml_len % 512, 0);
    let stored = enc.len() as u64;
    Cfb::new(MBOX5, stored).encrypt(&mut enc);
    let mut foot = vec![0u8; 512];
    foot[0x18..0x1c].copy_from_slice(&(xml_len as u32).to_le_bytes());
    foot[0x1c..0x21].copy_from_slice(b"18801");
    foot[0x2c..0x34].copy_from_slice(b"test_fw1");
    let pkg = [vec![0u8; 1024], enc, foot].concat();
    let p = std::env::temp_dir().join(format!("mtk-cli-{}.ops", std::process::id()));
    std::fs::write(&p, pkg).unwrap();
    p
}

#[test]
fn ops_list_survives_a_closed_stdout() {
    let ops = synthetic_ops();
    let mtk = env!("CARGO_BIN_EXE_mtk");
    let out = Command::new(mtk).arg("ops").arg(&ops).arg("--list").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.starts_with("ops      test_fw1  project 18801") && text.contains(" p1999 "),
        "{text}"
    );

    // Like `| head` that has already exited: every write gets EPIPE.
    let (r, w) = std::io::pipe().unwrap();
    drop(r);
    let out = Command::new(mtk)
        .arg("ops")
        .arg(&ops)
        .arg("--list")
        .stdout(w)
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    std::fs::remove_file(&ops).unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && !err.contains("panicked"),
        "{:?} {err}",
        out.status
    );
}
