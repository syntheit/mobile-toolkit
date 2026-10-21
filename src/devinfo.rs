//! Android/Qualcomm ABL `devinfo` partition (lock state).

use anyhow::{Result, ensure};

const MAGIC: &[u8] = b"ANDROID-BOOT!";

#[derive(Debug, PartialEq, Eq)]
pub struct DevInfo {
    pub is_unlocked: bool,
    pub is_unlock_critical: bool,
    pub charger_screen: bool,
    pub bootloader_version: String,
    pub radio_version: String,
    pub verity_mode: u8,
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

pub fn parse(buf: &[u8]) -> Result<DevInfo> {
    ensure!(buf.len() > 0x90, "devinfo too short");
    ensure!(buf.starts_with(MAGIC), "devinfo: bad magic");
    Ok(DevInfo {
        is_unlocked: buf[0x0d] != 0,
        is_unlock_critical: buf[0x0e] != 0,
        charger_screen: buf[0x0f] != 0,
        bootloader_version: cstr(&buf[0x10..0x50]),
        radio_version: cstr(&buf[0x50..0x90]),
        verity_mode: buf[0x90],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        let mut b = vec![0u8; 4096];
        b[..13].copy_from_slice(MAGIC);
        b[0x0d] = 1;
        b[0x0f] = 1;
        b[0x10..0x13].copy_from_slice(b"abc");
        b[0x90] = 1;
        let d = parse(&b).unwrap();
        assert!(d.is_unlocked && !d.is_unlock_critical && d.charger_screen);
        assert_eq!(
            (d.bootloader_version.as_str(), d.radio_version.as_str(), d.verity_mode),
            ("abc", "", 1)
        );
        b[0] = b'X';
        assert!(parse(&b).is_err());
    }
}
