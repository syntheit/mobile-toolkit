use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use mobile_toolkit::firehose::Firehose;
use mobile_toolkit::gpt::{self, Entry, LunGpt, OP_INACTIVE_TYPE};
use mobile_toolkit::profile::{Profile, data_dir};
use mobile_toolkit::usb::{self, Mode, Usb};
use mobile_toolkit::{devinfo, sahara};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Qualcomm EDL recovery toolkit (read-only phase).
#[derive(Parser)]
#[command(name = "mtk", version)]
struct Cli {
    /// Built-in device profile name, or path to a profile .toml
    #[arg(long, global = true, default_value = "fajita")]
    device: String,
    /// Firehose loader to upload (default: <data dir>/loaders/<profile loader file>)
    #[arg(long, global = true)]
    loader: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Detect the device and report GPT health, slots and lock state
    Status {
        /// Also hash slot-a firmware and compare to the profile's known-good list
        #[arg(long)]
        verify: bool,
    },
    /// Dump a partition to a file
    Read {
        partition: String,
        out: PathBuf,
        #[arg(long)]
        lun: Option<u8>,
    },
    /// Print partition tables
    Gpt {
        #[arg(long)]
        lun: Option<u8>,
    },
    /// Reboot the device out of EDL (or power it off)
    Reset {
        #[arg(long)]
        off: bool,
    },
}

type Fh = Firehose<Usb>;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let res = Profile::load(&cli.device).and_then(|p| run(&cli, &p));
    match res {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: &Cli, p: &Profile) -> Result<ExitCode> {
    match &cli.cmd {
        Cmd::Status { verify } => status(p, cli.loader.as_deref(), *verify),
        Cmd::Read { partition, out, lun } => {
            let mut fh = connect(p, cli.loader.as_deref())?;
            read_partition(&mut fh, p, partition, out, *lun)?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Gpt { lun } => {
            let mut fh = connect(p, cli.loader.as_deref())?;
            let luns: Vec<u8> = lun.map_or_else(|| (0..p.luns).collect(), |l| vec![l]);
            for l in luns {
                print_gpt(l, &lun_gpt(&mut fh, l)?, p);
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Reset { off } => {
            connect(p, cli.loader.as_deref())?.power(if *off { "off" } else { "reset" })?;
            println!("sent power {}", if *off { "off" } else { "reset" });
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn load_loader(p: &Profile, over: Option<&Path>) -> Result<(PathBuf, Vec<u8>)> {
    let path = over.map_or_else(|| data_dir().join("loaders").join(&p.loader_file), Path::to_path_buf);
    let data = std::fs::read(&path).with_context(|| {
        format!(
            "reading loader {} (get `Loaders/oneplus/{}` from github.com/bkerler/edl and place it there)",
            path.display(),
            p.loader_file
        )
    })?;
    let sum = hex(&Sha256::digest(&data));
    if sum != p.loader_sha256 {
        if over.is_none() {
            bail!(
                "loader {} sha256 {sum} does not match profile {}",
                path.display(),
                p.loader_sha256
            );
        }
        println!("loader   note: sha256 {sum} differs from profile (override in use)");
    }
    Ok((path, data))
}

/// Get the device into firehose mode (uploading the loader if needed) and configure it.
fn connect(p: &Profile, loader: Option<&Path>) -> Result<Fh> {
    match usb::detect((p.edl_vid, p.edl_pid), p.fastboot_vid)? {
        Mode::Edl => {}
        m => bail!("device not in EDL mode ({})", describe(&m, p)),
    }
    let mut dev = Usb::open(p.edl_vid, p.edl_pid)?;
    let leftover = match sahara::probe(&mut dev)? {
        sahara::Probe::Sahara(hello) => {
            let (path, data) = load_loader(p, loader)?;
            let (info, hello) = sahara::info(&mut dev, hello)?;
            print_sahara(&info, hello.version, p);
            sahara::upload(&mut dev, hello, &data)?;
            println!("loader   uploaded {}", path.display());
            vec![]
        }
        sahara::Probe::Firehose(buf) => {
            println!("loader   already running (firehose answered), skipping upload");
            buf
        }
    };
    let mut fh = Firehose::new(dev, leftover, p.sector_size);
    fh.drain()?;
    fh.configure(&p.memory)?;
    println!(
        "firehose target {}, memory {}, max payload {}",
        fh.target, p.memory, fh.max_payload
    );
    Ok(fh)
}

fn print_sahara(info: &sahara::Info, version: u32, p: &Profile) {
    let hwid = info.hwid.map(|h| format!("{h:016x}"));
    let pk = info.pkhash.as_deref().map(hex);
    println!(
        "sahara   v{version}  serial {:08x}  hwid {}  pkhash {}",
        info.serial,
        hwid.as_deref().unwrap_or("?"),
        pk.as_deref().map_or("?", |s| &s[..s.len().min(16)])
    );
    if let (Some(want), Some(got)) = (&p.hwid, &hwid)
        && want != got
    {
        println!("         WARNING: hwid differs from profile ({want})");
    }
    if let (Some(want), Some(got)) = (&p.pkhash_prefix, &pk)
        && !got.starts_with(want.as_str())
    {
        println!("         WARNING: pkhash differs from profile ({want}...): loader likely rejected");
    }
}

fn describe(m: &Mode, p: &Profile) -> String {
    match m {
        Mode::Edl => format!("EDL {:04x}:{:04x}", p.edl_vid, p.edl_pid),
        Mode::Fastboot(pid) => format!("fastboot {:04x}:{pid:04x}", p.fastboot_vid),
        Mode::OtherQualcomm(pid) => format!("Qualcomm {:04x}:{pid:04x}, not EDL (900e = crash dump)", p.edl_vid),
        Mode::None => "no device found".into(),
    }
}

fn lun_gpt(fh: &mut Fh, lun: u8) -> Result<LunGpt> {
    let ss = fh.sector_size;
    gpt::read_lun(&mut |lba, n| fh.read_vec(lun, lba, n), ss).with_context(|| format!("LUN {lun} GPT"))
}

fn size(bytes: u64) -> String {
    let units = ["B", "K", "M", "G", "T"];
    let (mut v, mut i) = (bytes as f64, 0);
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1}{}", units[i])
}

fn print_gpt(lun: u8, g: &LunGpt, p: &Profile) {
    let h = &g.primary.header;
    println!(
        "LUN{lun}  {} entries x {}  usable {}..{}  backup @{}  {}",
        h.num_entries,
        h.entry_size,
        h.first_usable,
        h.last_usable,
        h.alt_lba,
        if g.issues.is_empty() { "ok" } else { "ISSUES" }
    );
    for i in &g.issues {
        println!("  ! {i}");
    }
    for e in &g.entries {
        let prot = if p.protected.contains(&e.name) {
            "  protected"
        } else {
            ""
        };
        println!(
            "  {:<18} {:>10} {:>10} {:>8}  {:<17} {:08x}{prot}",
            e.name,
            e.first_lba,
            e.sectors(),
            size(e.sectors() * p.sector_size as u64),
            e.ab().to_string(),
            e.type_prefix()
        );
    }
}

/// Look a partition up by name, across all LUNs unless one is given.
fn find_part(fh: &mut Fh, p: &Profile, name: &str, lun: Option<u8>) -> Result<(u8, Entry)> {
    let luns: Vec<u8> = lun.map_or_else(|| (0..p.luns).collect(), |l| vec![l]);
    let mut hits = Vec::new();
    for l in luns {
        let g = lun_gpt(fh, l)?;
        hits.extend(g.entries.into_iter().filter(|e| e.name == name).map(|e| (l, e)));
    }
    match hits.len() {
        0 => bail!("partition `{name}` not found"),
        1 => Ok(hits.remove(0)),
        _ => bail!(
            "`{name}` exists on several LUNs ({:?}); pass --lun",
            hits.iter().map(|h| h.0).collect::<Vec<_>>()
        ),
    }
}

/// Stream a partition into `sink`, with a progress line on stderr for big ones.
fn read_entry(fh: &mut Fh, lun: u8, e: &Entry, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
    let total = e.sectors() * fh.sector_size as u64;
    let (mut done, mut shown) = (0u64, 0);
    fh.read(lun, e.first_lba, e.sectors(), &mut |d| {
        done += d.len() as u64;
        let pct = done * 100 / total;
        if total > 64 << 20 && pct != shown {
            shown = pct;
            eprint!("\r  {} {pct}%", e.name);
        }
        sink(d)
    })?;
    if total > 64 << 20 {
        eprintln!();
    }
    Ok(())
}

fn read_partition(fh: &mut Fh, p: &Profile, name: &str, out: &Path, lun: Option<u8>) -> Result<()> {
    let (lun, e) = find_part(fh, p, name, lun)?;
    let bytes = e.sectors() * p.sector_size as u64;
    println!(
        "read     {name}: LUN{lun} sector {} count {} ({})",
        e.first_lba,
        e.sectors(),
        size(bytes)
    );
    let mut f =
        std::io::BufWriter::new(std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?);
    let mut h = Sha256::new();
    let t0 = std::time::Instant::now();
    read_entry(fh, lun, &e, &mut |d| {
        h.update(d);
        f.write_all(d).map_err(Into::into)
    })?;
    f.flush()?;
    let secs = t0.elapsed().as_secs_f64().max(0.001);
    println!(
        "wrote    {} in {secs:.1}s ({}/s)",
        out.display(),
        size((bytes as f64 / secs) as u64)
    );
    println!("sha256   {}", hex(&h.finalize()));
    Ok(())
}

fn status(p: &Profile, loader: Option<&Path>, verify: bool) -> Result<ExitCode> {
    println!("device   {}", p.name);
    let mode = usb::detect((p.edl_vid, p.edl_pid), p.fastboot_vid)?;
    println!("usb      {}", describe(&mode, p));
    match mode {
        Mode::Edl => {}
        Mode::Fastboot(_) => return Ok(ExitCode::SUCCESS),
        _ => return Ok(ExitCode::FAILURE),
    }
    let mut fh = connect(p, loader)?;
    let mut issues = 0;

    match fh.storage_info(0) {
        Ok(r) => {
            for l in r.logs.iter().filter(|l| !l.trim().is_empty()) {
                println!("storage  {}", l.trim());
            }
        }
        Err(e) => println!("storage  getstorageinfo failed: {e:#}"),
    }

    let mut parts: Vec<(u8, Entry)> = Vec::new();
    for lun in 0..p.luns {
        match lun_gpt(&mut fh, lun) {
            Ok(g) => {
                let bk = g
                    .backup
                    .as_ref()
                    .map_or("missing".into(), |b| format!("@{}", b.header.my_lba));
                let state = if g.issues.is_empty() { "ok" } else { "ISSUES" };
                println!("gpt      LUN{lun} {state}  {} partitions, backup {bk}", g.entries.len());
                for i in &g.issues {
                    println!("         ! {i}");
                }
                issues += g.issues.len();
                parts.extend(g.entries.into_iter().map(|e| (lun, e)));
            }
            Err(e) => {
                println!("gpt      LUN{lun} UNREADABLE: {e:#}");
                issues += 1;
            }
        }
    }

    let refs: Vec<(u8, &Entry)> = parts.iter().map(|(l, e)| (*l, e)).collect();
    let pairs = gpt::pairs(&refs);
    let slot = match gpt::boot_slot(&pairs) {
        Ok(s) => {
            println!("slots    boot slot _{s}   (~ = OnePlus inactive type {OP_INACTIVE_TYPE:08x})");
            Some(s)
        }
        Err(e) => {
            println!("slots    boot slot UNKNOWN: {e}");
            issues += 1;
            None
        }
    };
    let half = |h: Option<(u8, &Entry)>| match h {
        Some((l, e)) => {
            let t = if e.type_prefix() == OP_INACTIVE_TYPE { "~" } else { " " };
            format!("L{l} {:<17}{t}", e.ab().to_string())
        }
        None => format!("{:<22}", "-"),
    };
    for pr in &pairs {
        println!("  {:<14} a {}  b {}", pr.base, half(pr.a), half(pr.b));
        for i in gpt::pair_issues(pr, slot) {
            println!("         ! {i}");
            issues += 1;
        }
    }

    let find = |name: &str| parts.iter().find(|(_, e)| e.name == name).cloned();
    match find("devinfo") {
        Some((l, e)) => match fh.read_vec(l, e.first_lba, 1).and_then(|b| devinfo::parse(&b)) {
            Ok(d) => println!(
                "lock     devinfo: {}  unlock_critical={}  charger_screen={}  verity_mode={}",
                if d.is_unlocked { "UNLOCKED" } else { "locked" },
                d.is_unlock_critical as u8,
                d.charger_screen as u8,
                d.verity_mode
            ),
            Err(e) => println!("lock     devinfo unreadable: {e:#}"),
        },
        None => println!("lock     no devinfo partition"),
    }
    if let Some((pname, off)) = &p.unlock_flag {
        let ss = p.sector_size as u64;
        match find(pname) {
            Some((l, e)) => {
                let b = fh.read_vec(l, e.first_lba + off / ss, 1)?;
                let v = b[(off % ss) as usize];
                let meaning = if v != 0 {
                    "OEM unlock allowed"
                } else {
                    "OEM unlock NOT allowed"
                };
                println!("         {pname}[{off}] = 0x{v:02x} ({meaning})");
            }
            None => println!("         no `{pname}` partition"),
        }
    }

    if verify {
        for (name, want) in &p.known_good {
            let Some((l, e)) = find(name) else {
                println!("verify   {name:<14} MISSING");
                issues += 1;
                continue;
            };
            let mut h = Sha256::new();
            read_entry(&mut fh, l, &e, &mut |d| {
                h.update(d);
                Ok(())
            })?;
            let got = hex(&h.finalize());
            if &got == want {
                println!("verify   {name:<14} ok");
            } else {
                println!("verify   {name:<14} MISMATCH (got {})", &got[..16]);
                issues += 1;
            }
        }
    }

    println!("summary  {issues} issue(s); device left in firehose mode (`mtk reset` to reboot)");
    Ok(if issues == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
