# mobile-toolkit (`mtk`)

A small Rust CLI for recovering and inspecting Qualcomm phones over EDL
(emergency download mode, USB `05c6:9008`) from Linux. It replaces
bkerler/edl and OnePlus MSMDownloadTool for this job. It uses pure-Rust USB
(`nusb`), so libusb and Python are not needed.

First target: OnePlus 6T "fajita" (SDM845, UFS, 6 LUNs).

**Status:** phase 1 (read-only) is validated on the device. Phase 2
(writes) and phase 3 (`install-nixos`) are tested offline only so far.

## Commands

```
mtk status [--verify]            # mode, GPT health per LUN, A/B slots, lock state
mtk gpt [--lun N]                # print partition tables
mtk read <partition> <out> [--lun N]
mtk reset [--off]                # leave EDL (firehose power command)

mtk flash <partition> <image> [--lun N]   # raw or Android sparse image
mtk slot a|b [--no-bootlun]               # set the active A/B slot and UFS boot LUN
mtk unlock [--relock]                     # devinfo + config unlock bytes
mtk install-nixos <dir> [--slot a|b]      # mobile-nixos fastboot images

mtk ops <file.ops> [--list] [--extract <dir>]   # OnePlus firmware package, no device
```

Global options: `--device <name|file.toml>` (default `fajita`) and
`--loader <path>`.

`status` checks these:
- **GPT, per LUN:** protective MBR; primary and backup header CRCs; entry
  array CRCs; that the two copies mirror each other. The backup entries are
  read at the backup header's `PartitionEntryLBA`.
- **Slots:** the boot slot (from `boot_a`/`boot_b`) and the Qualcomm A/B
  attribute byte for every `_a`/`_b` pair (priority, active, retry count,
  successful, unbootable). It flags inconsistencies, such as a partition that
  is marked active but carries OnePlus's inactive-slot type GUID `77036cd4…`.
- **Lock state:** `devinfo` (`is_unlocked`, `is_unlock_critical`, …) and the
  OnePlus OEM-unlock-allowed byte in `config`.
- **`--verify`:** hashes the slot-a firmware and compares it to the profile's
  known-good SHA-256 list.

`ops` reads a OnePlus MsmDownloadTool `.ops` package. It decrypts the
`settings.xml` flash plan (mbox4/5/6 keys) and prints the project id, firmware
name and counts. `--list` prints every program entry (LUN, partition, start
sector, sector count, image file, sparse/erase flags). `--extract` streams
`settings.xml` and every image into a directory, decrypting the firehose loader,
and checks the SHA-256 that settings.xml gives for each non-sparse image.

## Writes

Every write command goes through one safety layer (`src/write.rs`):

- **Dry run by default.** mtk connects, reads the GPT and prints exactly what
  it would write: partition, LUN, start sector, sector count, bytes and the
  source SHA-256. Then it exits 0. Add `--yes` to write.
- **Protected partitions** from the profile (`modemst1`, `modemst2`, `fsg`,
  `fsc`, `persist`) are refused unless `--force-protected` is given.
- **Oversize images** are refused. For a sparse image the expanded size counts.
- **Backup first.** Before any write, every target region is read into
  `$MTK_DATA/backups/<UTC timestamp>/<partition>.img`, with `SHA256SUMS` and
  `LOCATIONS` (LUN, sector, count) next to it. `userdata` (about 245 GB) is
  backed up as its first and last MiB only (`userdata.head.img`,
  `userdata.tail.img`) unless `--full-backup` is given. `--no-backup` skips
  the backup.
- **Read-back.** After writing, mtk reads every written range back and
  compares its SHA-256 with what it sent. A mismatch is a hard error.

Images stream from disk in max-payload chunks, so multi-GB files are never
loaded into memory. Android sparse images (`img2simg` output) are expanded on
the fly. `DONT_CARE` chunks are skipped, as fastboot does, so those sectors
keep their old contents.

The edl OP6T loader needs no OnePlus auth for writes
(see `docs/oneplus-auth.md`).

### `mtk slot a|b`

The target table is computed from the current one; mtk never blindly swaps
anything. So running it twice changes nothing, and an interrupted run can
simply be repeated.

- `boot_<target>` gets `0x6f` (priority 3, active, retry 5, successful: the
  value of a healthy booted slot). `boot_<other>` gets `0x3a` (priority 2,
  retry 7, not active).
- Every other `_a`/`_b` pair gets the active bit set on the target half and
  cleared on the other half. The rest of the attribute byte is kept, which is
  what abl does.
- OnePlus type GUIDs: in a pair where exactly one half has the inactive type
  `77036cd4-03d5-42bb-8ed1-37e5a88baa34`, the target half gets the real type
  and the other half gets the inactive one. Pairs where both halves have the
  real type (`xbl`, `xbl_config` on LUN1/LUN2) keep their types. If both
  halves have the inactive type, mtk refuses.
- Per LUN the write order is: backup entries, backup header, then primary
  header and entries. At every point at least one copy has valid CRCs. If the
  primary entries fail their CRC, the LUN is rebuilt from the backup copy.
  mtk refuses a LUN whose header CRCs are bad.
- After writing, mtk re-reads all GPTs and checks CRCs, primary == backup,
  and the boot slot.
- Then it sets the UFS boot LUN (`bBootLunEn`) with firehose
  `setbootablestoragedrive`: 1 for a, 2 for b. It does this even when the GPT
  is already on the target slot, because the value is cheap to set and cannot
  be read back. `--no-bootlun` skips it.

Why the boot LUN matters: the boot ROM picks xbl from the boot LUN (`xbl_a` on
LUN1, `xbl_b` on LUN2) and never looks at the GPT slot attributes, so a slot
switch that leaves it behind runs one slot's xbl with the other slot's abl.
On fajita that hangs before any kernel starts, and every partition still
checks out fine, which is how a phone stayed bricked for seven weeks.

This avoids the edl `setactiveslot` bugs: it stopping after the first `_a`
partition, the unconditional type swap, and reading past the end of a LUN.

### `mtk unlock`

This sets devinfo `is_unlocked` (byte `0x0d`) and the OEM-unlock-allowed flag
in `config` to 1. It does a read-modify-write of just those two sectors.
The `config` flag is the **last byte** of the 512 KiB partition (sector 127,
offset 4095), as in Android's PersistentDataBlock. edl `oemunlock` patches
offset `0x7FFFF` too, but prints the partition start ("sector 85696, offset
4095"). If both bytes are already set, mtk does nothing. `--relock` writes 0s.

### `mtk install-nixos <dir>`

`<dir>` is the `mobile.outputs.android.android-fastboot-images` output of
mobile-nixos, which holds `boot.img` and `system.img` (sparse on sdm845).
`boot.img` goes to `boot_<slot>`, where the slot defaults to the current boot
slot. `system.img` goes to `userdata`. Afterwards mtk prints the next steps
(`mtk slot <s> --yes` if the slot changed, then `mtk reset`).

## Loader

The firehose loader is proprietary, so it is not in this repo. Get it from
bkerler/edl, file `Loaders/oneplus/0008b0e10051459b_dd7c5f2e53176bee_fhprg_op6t.bin`,
and put it in `$MTK_DATA/loaders/` (default
`~/.local/share/mobile-toolkit/loaders/`). mtk checks its SHA-256 against
the device profile before uploading it.

## Device profiles

Device-specific data lives in `devices/<name>.toml`: USB IDs, storage type,
sector size, LUN count, loader file and hash, protected partitions, OEM flag
location and known-good hashes. Built-in profiles are compiled into the
binary. To use another one, pass `--device path/to/profile.toml`.

## USB access

The user needs access to `05c6:9008`, for example with a udev rule:

```
SUBSYSTEM=="usb", ATTRS{idVendor}=="05c6", ATTRS{idProduct}=="9008", MODE="0660", TAG+="uaccess"
```

(A NixOS module will set this up later.)

## Building

```
nix build              # or: nix develop -c cargo build --release
nix develop -c cargo test
MTK_REAL_DUMPS=/path/to/dumps nix develop -c cargo test -- --ignored   # real GPT dumps, incl. slot round-trips
```

## Credits

The protocol logic (Sahara, Firehose framing, GPT/A-B handling, and the
OnePlus auth notes in `docs/oneplus-auth.md`) is ported from or informed by
[bkerler/edl](https://github.com/bkerler/edl) by B. Kerler (GPL-3.0). Thank
you. mtk is GPL-3.0 as well. The `.ops` decryption is ported from
[bkerler/oppo_decrypt](https://github.com/bkerler/oppo_decrypt) `opscrypto.py`
by B. Kerler (that file's header says MIT License).
