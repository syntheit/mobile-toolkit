//! Device profiles (`devices/*.toml`). Built-in profiles are embedded at
//! compile time; `--device path/to/x.toml` loads one from disk.

use anyhow::{Context, Result, anyhow};
use std::path::{Path, PathBuf};
use toml::{Table, Value};

const BUILTIN: &[(&str, &str)] = &[("fajita", include_str!("../devices/fajita.toml"))];

#[derive(Debug)]
pub struct Profile {
    pub name: String,
    pub edl_vid: u16,
    pub edl_pid: u16,
    pub fastboot_vid: u16,
    pub memory: String,
    pub sector_size: usize,
    pub luns: u8,
    pub loader_file: String,
    pub loader_sha256: String,
    pub hwid: Option<String>,
    pub pkhash_prefix: Option<String>,
    pub protected: Vec<String>,
    /// (partition, byte offset); a negative offset counts from the partition end.
    pub unlock_flag: Option<(String, i64)>,
    /// (partition, sha256), sorted by partition name.
    pub known_good: Vec<(String, String)>,
}

fn get<'a>(t: &'a Table, path: &str) -> Result<&'a Value> {
    let mut cur = t;
    let mut keys = path.split('.').peekable();
    while let Some(k) = keys.next() {
        let v = cur.get(k).ok_or_else(|| anyhow!("profile: missing `{path}`"))?;
        if keys.peek().is_none() {
            return Ok(v);
        }
        cur = v.as_table().ok_or_else(|| anyhow!("profile: `{k}` is not a table"))?;
    }
    unreachable!()
}

fn s(t: &Table, path: &str) -> Result<String> {
    get(t, path)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("profile: `{path}` must be a string"))
}

fn int(t: &Table, path: &str) -> Result<i64> {
    get(t, path)?
        .as_integer()
        .ok_or_else(|| anyhow!("profile: `{path}` must be an integer"))
}

impl Profile {
    pub fn parse(text: &str) -> Result<Profile> {
        let t: Table = text.parse().context("profile: invalid TOML")?;
        let strings = |path: &str| -> Result<Vec<String>> {
            get(&t, path)?
                .as_array()
                .ok_or_else(|| anyhow!("profile: `{path}` must be an array"))?
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| anyhow!("profile: `{path}` must hold strings"))
                })
                .collect()
        };
        let known_good = match t.get("known_good").and_then(Value::as_table) {
            Some(kg) => kg
                .iter()
                .map(|(k, v)| {
                    Ok((
                        k.clone(),
                        v.as_str()
                            .ok_or_else(|| anyhow!("known_good.{k}: not a string"))?
                            .to_owned(),
                    ))
                })
                .collect::<Result<_>>()?,
            None => vec![],
        };
        Ok(Profile {
            name: s(&t, "name")?,
            edl_vid: int(&t, "usb.edl_vid")? as u16,
            edl_pid: int(&t, "usb.edl_pid")? as u16,
            fastboot_vid: int(&t, "usb.fastboot_vid")? as u16,
            memory: s(&t, "storage.memory")?,
            sector_size: int(&t, "storage.sector_size")? as usize,
            luns: int(&t, "storage.luns")? as u8,
            loader_file: s(&t, "loader.file")?,
            loader_sha256: s(&t, "loader.sha256")?.to_lowercase(),
            hwid: s(&t, "loader.hwid").ok(),
            pkhash_prefix: s(&t, "loader.pkhash_prefix").ok(),
            protected: strings("partitions.protected").unwrap_or_default(),
            unlock_flag: s(&t, "oem.unlock_flag_partition")
                .ok()
                .zip(int(&t, "oem.unlock_flag_offset").ok()),
            known_good,
        })
    }

    /// Built-in name (e.g. `fajita`) or a path to a `.toml` file.
    pub fn load(device: &str) -> Result<Profile> {
        if let Some((_, text)) = BUILTIN.iter().find(|(n, _)| *n == device) {
            return Profile::parse(text);
        }
        let text = std::fs::read_to_string(device)
            .with_context(|| format!("unknown device `{device}` (built-in: fajita) and no such file"))?;
        Profile::parse(&text)
    }
}

/// `$MTK_DATA`, else `~/.local/share/mobile-toolkit`.
pub fn data_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("MTK_DATA") {
        return d.into();
    }
    let home = std::env::var_os("HOME").unwrap_or_default();
    Path::new(&home).join(".local/share/mobile-toolkit")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fajita_profile() {
        let p = Profile::load("fajita").unwrap();
        assert_eq!((p.edl_vid, p.edl_pid, p.luns, p.sector_size), (0x05c6, 0x9008, 6, 4096));
        assert_eq!(p.memory, "ufs");
        assert_eq!(p.protected, ["modemst1", "modemst2", "fsg", "fsc", "persist"]);
        assert_eq!(p.unlock_flag, Some(("config".into(), -1)));
        assert_eq!(p.known_good.len(), 17);
        assert!(
            p.known_good
                .iter()
                .any(|(n, h)| n == "boot_a" && h.starts_with("a1852772"))
        );
    }
}
