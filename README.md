# mobile-toolkit (`mtk`)

A small Rust CLI for recovering and inspecting Qualcomm phones over EDL
(emergency download mode, USB `05c6:9008`) from Linux. It replaces
bkerler/edl and OnePlus MSMDownloadTool for this job. It uses pure-Rust USB
(`nusb`), so libusb and Python are not needed.

First target: OnePlus 6T "fajita" (SDM845, UFS, 6 LUNs).

**Status: phase 1, read-only.** mtk uploads the firehose loader, then reads.
It has no write, program, erase or patch code.

## Commands

```
mtk status [--verify]            # mode, GPT health per LUN, A/B slots, lock state
mtk gpt [--lun N]                # print partition tables
mtk read <partition> <out> [--lun N]
mtk reset [--off]                # leave EDL (firehose power command)
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
MTK_REAL_DUMPS=/path/to/dumps nix develop -c cargo test -- --ignored   # parses real GPT dumps
```

## Credits

The protocol logic (Sahara, Firehose framing, GPT/A-B handling, and the
OnePlus auth notes in `docs/oneplus-auth.md`) is ported from or informed by
[bkerler/edl](https://github.com/bkerler/edl) by B. Kerler (GPL-3.0). Thank
you. mtk is GPL-3.0 as well.
