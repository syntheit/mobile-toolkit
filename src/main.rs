use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use mobile_toolkit::firehose::{Firehose, storage_summary};
use mobile_toolkit::gpt::{self, Ab, Entry, LunGpt, OP_INACTIVE_TYPE};
use mobile_toolkit::image::{Image, hex};
use mobile_toolkit::profile::{Profile, chown_to_user, data_dir};
use mobile_toolkit::usb::{self, Mode, Usb};
use mobile_toolkit::write::{self, Opts, Region, size};
use mobile_toolkit::{devinfo, eprint, eprintln, println, sahara, slot};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Qualcomm EDL recovery toolkit.
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
        /// Print the raw getstorageinfo report
        #[arg(short, long)]
        verbose: bool,
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
    /// Write a raw or Android sparse image to a partition
    Flash {
        partition: String,
        image: PathBuf,
        #[arg(long)]
        lun: Option<u8>,
        #[command(flatten)]
        w: WriteFlags,
    },
    /// Make slot a or b active: GPT attributes, OnePlus type GUIDs and the UFS boot LUN
    Slot {
        slot: SlotArg,
        /// Leave the UFS boot LUN (which xbl runs) alone; only change the GPT
        #[arg(long)]
        no_bootlun: bool,
        #[command(flatten)]
        w: WriteFlags,
    },
    /// Set the bootloader-unlocked bytes (devinfo is_unlocked, config OEM-unlock flag)
    Unlock {
        /// Clear them instead
        #[arg(long)]
        relock: bool,
        #[command(flatten)]
        w: WriteFlags,
    },
    /// Flash mobile-nixos android-fastboot-images: boot.img -> boot_<slot>, system.img -> userdata
    InstallNixos {
        dir: PathBuf,
        /// Default: the current boot slot
        #[arg(long)]
        slot: Option<SlotArg>,
        #[command(flatten)]
        w: WriteFlags,
    },
    /// Inspect or extract a OnePlus .ops firmware package (no device needed)
    Ops {
        file: PathBuf,
        /// Decrypt settings.xml and write every image into this directory
        #[arg(long)]
        extract: Option<PathBuf>,
        /// Print the program table (LUN, partition, start, file)
        #[arg(long)]
        list: bool,
    },
}

#[derive(Args, Clone, Copy)]
struct WriteFlags {
    /// Write for real (default: dry run that prints what would be written)
    #[arg(long)]
    yes: bool,
    /// Allow writing partitions the profile marks protected
    #[arg(long)]
    force_protected: bool,
    /// Skip the backup of the target region
    #[arg(long)]
    no_backup: bool,
    /// Back up all of userdata, not only its first and last MiB
    #[arg(long)]
    full_backup: bool,
}

impl From<WriteFlags> for Opts {
    fn from(w: WriteFlags) -> Opts {
        Opts {
            yes: w.yes,
            force_protected: w.force_protected,
            no_backup: w.no_backup,
            full_backup: w.full_backup,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum SlotArg {
    A,
    B,
}

impl SlotArg {
    fn c(self) -> char {
        match self {
            SlotArg::A => 'a',
            SlotArg::B => 'b',
        }
    }
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
        Cmd::Status { verify, verbose } => status(p, cli.loader.as_deref(), *verify, *verbose),
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
        Cmd::Reset { off } => reset(p, cli.loader.as_deref(), if *off { "off" } else { "reset" }),
        Cmd::Flash {
            partition,
            image,
            lun,
            w,
        } => {
            let img = Image::open(image)?;
            let mut fh = connect(p, cli.loader.as_deref())?;
            let (lun, e) = find_part(&mut fh, p, partition, *lun)?;
            let target = write::Write {
                region: region(lun, &e),
                image: img,
            };
            write::run(&mut fh, &p.protected, &[target], (*w).into(), &backups())?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Slot { slot, no_bootlun, w } => {
            let mut fh = connect(p, cli.loader.as_deref())?;
            set_slot(&mut fh, p, slot.c(), !*no_bootlun, (*w).into())?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Unlock { relock, w } => {
            let mut fh = connect(p, cli.loader.as_deref())?;
            unlock(&mut fh, p, *relock, (*w).into())?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::InstallNixos { dir, slot, w } => {
            install_nixos(p, cli.loader.as_deref(), dir, slot.map(SlotArg::c), (*w).into())?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Ops { file, extract, list } => Ok(match mobile_toolkit::ops::cli(file, extract.as_deref(), *list)? {
            true => ExitCode::SUCCESS,
            false => ExitCode::FAILURE,
        }),
    }
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
/// The loader is read and checked first: failing after the Sahara hello was
/// consumed would leave the device wedged until it is power-cycled.
fn connect(p: &Profile, loader: Option<&Path>) -> Result<Fh> {
    let (path, data) = load_loader(p, loader)?;
    match usb::detect((p.edl_vid, p.edl_pid), p.fastboot_vid)? {
        Mode::Edl => {}
        m => bail!("device not in EDL mode ({})", describe(&m, p)),
    }
    let mut dev = Usb::open(p.edl_vid, p.edl_pid)?;
    // Any Sahara failure leaves the PBL waiting for a state we can't restore.
    let leftover = sahara_phase(&mut dev, p, &path, &data).map_err(|e| {
        anyhow!(
            "{e:#}\nhint: power-cycle it into EDL: unplug, hold Power+VolUp ~15 s, \
             then hold VolUp+VolDown while plugging in"
        )
    })?;
    let mut fh = Firehose::new(dev, leftover, p.sector_size);
    fh.drain()?;
    fh.configure(&p.memory)?;
    println!(
        "firehose target {}, memory {}, max payload {}",
        fh.target, p.memory, fh.max_payload
    );
    Ok(fh)
}

/// Probe; in Sahara, identify the SoC and upload the loader. Returns bytes a
/// running firehose loader already sent.
fn sahara_phase(dev: &mut Usb, p: &Profile, path: &Path, data: &[u8]) -> Result<Vec<u8>> {
    Ok(match sahara::probe(dev)? {
        sahara::Probe::Sahara(hello) => {
            let (info, hello) = sahara::info(dev, hello)?;
            print_sahara(&info, hello.version, p);
            sahara::upload(dev, hello, data)?;
            println!("loader   uploaded {}", path.display());
            vec![]
        }
        sahara::Probe::Firehose(buf) => {
            println!("loader   already running (firehose answered), skipping upload");
            buf
        }
    })
}

/// Send `<power>`, then keep the USB handle (so no kernel driver rebinds to a
/// live loader) until the device leaves EDL, and say whether it did.
fn reset(p: &Profile, loader: Option<&Path>, mode: &str) -> Result<ExitCode> {
    let mut fh = connect(p, loader)?;
    for l in fh.power(mode)? {
        println!("firehose {l}");
    }
    println!("power    {mode} acknowledged");
    let t0 = std::time::Instant::now();
    while usb::detect((p.edl_vid, p.edl_pid), p.fastboot_vid)? == Mode::Edl {
        if t0.elapsed() > std::time::Duration::from_secs(10) {
            println!(
                "warning  still in EDL 10 s after the power command; power-cycle it by hand \
                 (hold Power+VolUp ~15 s)"
            );
            return Ok(ExitCode::FAILURE);
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    drop(fh);
    println!("usb      device left EDL after {:.1}s", t0.elapsed().as_secs_f64());
    Ok(ExitCode::SUCCESS)
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

/// Byte offset of the OEM flag in its partition; negative counts from the end.
fn flag_offset(e: &Entry, ss: u64, off: i64) -> u64 {
    if off < 0 {
        e.sectors() * ss - off.unsigned_abs()
    } else {
        off as u64
    }
}

/// Look a partition up by name, across all LUNs unless one is given.
fn find_part(fh: &mut Fh, p: &Profile, name: &str, lun: Option<u8>) -> Result<(u8, Entry)> {
    let luns: Vec<u8> = lun.map_or_else(|| (0..p.luns).collect(), |l| vec![l]);
    let mut parts = Vec::new();
    for l in luns {
        parts.extend(lun_gpt(fh, l)?.entries.into_iter().map(|e| (l, e)));
    }
    find_in(&parts, name)
}

fn find_in(parts: &[(u8, Entry)], name: &str) -> Result<(u8, Entry)> {
    let mut hits: Vec<(u8, Entry)> = parts.iter().filter(|(_, e)| e.name == name).cloned().collect();
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
    chown_to_user(out);
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

fn status(p: &Profile, loader: Option<&Path>, verify: bool, verbose: bool) -> Result<ExitCode> {
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
            let lines: Vec<&str> = r.logs.iter().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();
            let (product, luns) = storage_summary(&r.logs);
            let mut line = p.memory.to_uppercase();
            if let Some(x) = &product {
                line += &format!(" {x}");
            }
            match luns {
                Some(n) => line += &format!(", {n} LUNs"),
                None if product.is_none() => line += &format!(", {} report lines (-v)", lines.len()),
                None => {}
            }
            println!("storage  {line}");
            if verbose {
                lines.iter().for_each(|l| println!("         {l}"));
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
                let off = flag_offset(&e, ss, *off);
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

fn backups() -> PathBuf {
    data_dir().join("backups")
}

fn region(lun: u8, e: &Entry) -> Region {
    Region {
        name: e.name.clone(),
        lun,
        start: e.first_lba,
        sectors: e.sectors(),
    }
}

fn all_gpts(fh: &mut Fh, p: &Profile) -> Result<Vec<(u8, LunGpt)>> {
    (0..p.luns).map(|l| Ok((l, lun_gpt(fh, l)?))).collect()
}

fn parts_of(gpts: &[(u8, LunGpt)]) -> Vec<(u8, Entry)> {
    gpts.iter()
        .flat_map(|(l, g)| g.entries.iter().map(|e| (*l, e.clone())))
        .collect()
}

fn boot_slot_of(parts: &[(u8, Entry)]) -> Result<char> {
    let refs: Vec<(u8, &Entry)> = parts.iter().map(|(l, e)| (*l, e)).collect();
    gpt::boot_slot(&gpt::pairs(&refs))
}

fn set_slot(fh: &mut Fh, p: &Profile, s: char, bootlun: bool, o: Opts) -> Result<()> {
    let ss = p.sector_size;
    let plans = slot::plan(&all_gpts(fh, p)?, s, ss)?;
    for l in &plans {
        if let Some(n) = &l.note {
            println!("slot     LUN{} note: {n}", l.lun);
        }
        if !l.changes.is_empty() {
            println!("slot     LUN{}: {} entries change", l.lun, l.changes.len());
        }
        for c in &l.changes {
            let ty = |t: u32| {
                if t == OP_INACTIVE_TYPE {
                    format!("~{t:08x}")
                } else {
                    format!(" {t:08x}")
                }
            };
            println!(
                "  {:<14} {:<17}{}  ->  {:<17}{}",
                c.name,
                Ab(c.old.0).to_string(),
                ty(c.old.1),
                Ab(c.new.0).to_string(),
                ty(c.new.1)
            );
        }
    }
    let writes: Vec<write::Write> = plans
        .iter()
        .flat_map(|l| {
            l.writes.iter().map(|(name, lba, data)| write::Write {
                region: Region {
                    name: name.clone(),
                    lun: l.lun,
                    start: *lba,
                    sectors: (data.len() / ss) as u64,
                },
                image: Image::bytes(name, 0, data.clone()),
            })
        })
        .collect();
    let boot_lun = if s == 'a' { 1 } else { 2 };
    if !bootlun {
        println!(
            "note     UFS boot LUN (bBootLunEn) NOT changed (--no-bootlun). It alone picks xbl_a (LUN1) \
             or xbl_b (LUN2) and cannot be read back; if it points at xbl_{}, boot hangs before the kernel",
            if s == 'a' { 'b' } else { 'a' }
        );
    }
    if writes.is_empty() {
        println!("slot     _{s} already active on every A/B pair; GPT unchanged");
    } else if write::run(fh, &p.protected, &writes, o, &backups())? {
        let after = all_gpts(fh, p)?;
        for ((l, g), plan) in after.iter().zip(&plans) {
            ensure!(g.issues.is_empty(), "LUN{l} GPT after writing: {:?}", g.issues);
            ensure!(
                g.primary.raw_entries == plan.entries,
                "LUN{l}: entries differ from the plan after writing"
            );
        }
        ensure!(
            boot_slot_of(&parts_of(&after))? == s,
            "boot slot is not _{s} after writing"
        );
        println!("slot     _{s} active; GPTs re-read: all CRCs valid, primary == backup");
    }
    // Always sent when wanted: it is cheap and its current value cannot be read back.
    if bootlun {
        if o.yes {
            fh.set_bootable(boot_lun)?;
            println!("bootlun  UFS boot LUN set to {boot_lun} (xbl_{s})");
        } else {
            println!("dry run  would set UFS boot LUN to {boot_lun} (xbl_{s}, setbootablestoragedrive)");
        }
    }
    Ok(())
}

fn unlock(fh: &mut Fh, p: &Profile, relock: bool, o: Opts) -> Result<()> {
    let (v, ss) = (!relock as u8, p.sector_size as u64);
    let mut writes = Vec::new();
    let (l, e) = find_part(fh, p, "devinfo", None)?;
    let mut s = fh.read_vec(l, e.first_lba, 1)?;
    devinfo::parse(&s).context("devinfo")?;
    println!("unlock   devinfo is_unlocked (byte 0x0d) = {}", s[0x0d]);
    if s[0x0d] != v {
        s[0x0d] = v;
        writes.push(write::Write {
            region: region(l, &e),
            image: Image::bytes("devinfo sector 0", 0, s),
        });
    }
    if let Some((name, off)) = &p.unlock_flag {
        let (l, e) = find_part(fh, p, name, None)?;
        let off = flag_offset(&e, ss, *off);
        let (sec, i) = (off / ss, (off % ss) as usize);
        let mut s = fh.read_vec(l, e.first_lba + sec, 1)?;
        println!(
            "unlock   {name}[{off}] (LUN{l} sector {} offset {i}) = {}",
            e.first_lba + sec,
            s[i]
        );
        if s[i] != v {
            s[i] = v;
            writes.push(write::Write {
                region: region(l, &e),
                image: Image::bytes(&format!("{name} sector {sec}"), sec * ss, s),
            });
        }
    }
    if writes.is_empty() {
        println!(
            "unlock   already {}; nothing to do",
            if relock { "locked" } else { "unlocked" }
        );
        return Ok(());
    }
    write::run(fh, &p.protected, &writes, o, &backups())?;
    Ok(())
}

fn install_nixos(p: &Profile, loader: Option<&Path>, dir: &Path, slot: Option<char>, o: Opts) -> Result<()> {
    let (boot_path, sys_path) = (dir.join("boot.img"), dir.join("system.img"));
    let mut magic = [0u8; 8];
    std::fs::File::open(&boot_path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .with_context(|| format!("reading {}", boot_path.display()))?;
    ensure!(
        &magic == b"ANDROID!",
        "{} is not an Android boot image",
        boot_path.display()
    );
    let boot = Image::open(&boot_path)?;
    let system = Image::open(&sys_path)?;

    let mut fh = connect(p, loader)?;
    let parts = parts_of(&all_gpts(&mut fh, p)?);
    let current = boot_slot_of(&parts);
    let s = match (slot, &current) {
        (Some(s), _) => s,
        (None, Ok(s)) => *s,
        (None, Err(e)) => bail!("cannot tell the boot slot ({e}); pass --slot"),
    };
    let (bl, be) = find_in(&parts, &format!("boot_{s}"))?;
    let (ul, ue) = find_in(&parts, "userdata")?;
    let writes = [
        write::Write {
            region: region(bl, &be),
            image: boot,
        },
        write::Write {
            region: region(ul, &ue),
            image: system,
        },
    ];
    if write::run(&mut fh, &p.protected, &writes, o, &backups())? {
        println!("next     installed to slot _{s}. Then:");
        if current.ok() != Some(s) {
            println!("           mtk slot {s} --yes");
        }
        println!("           mtk reset");
    }
    Ok(())
}
