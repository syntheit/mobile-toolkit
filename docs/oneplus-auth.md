# OnePlus firehose authentication (design note for phase 2)

Source studied: bkerler/edl `edlclient/Library/Modules/{oneplus.py,init.py}`,
`firehose.py`, `firehose_client.py`, `cryptutils.py`.

## Finding: reads need no auth (and, with the edl OP6T loader, neither do writes)

- edl builds a `modules` object after `configure`, but the OnePlus part
  (`modules.ops`) is a lazy property. Only these touch it:
  - `writeprepare()`, called by the write/erase commands (`w`, `wl`, `ws`,
    `wf`, `e`, `ep`, `es`) before they send anything;
  - `addprogram()` / `addpatch()`, which add `pk="…" token="…"` attributes
    to `<program>`, `<patch>` and `<erase>`;
  - the `modules ops` command.
  `r`, `rl`, `printgpt`, `getstorageinfo`, `peek` and `reset` never call it.
- Even on the write path, edl only authenticates when the loader advertises
  the commands. `writeprepare()` sends `demacia` only if `"demacia"` is in
  `supported_functions`, and `setprojmodel` only if `"setprojmodel"` is.
  `addprogram()`/`addpatch()` add a token only if `setprojmodel` or
  `setswprojmodel` is supported. `supported_functions` comes from the
  loader's boot log (`Supported Functions (n): …`) plus a scan of the loader
  file for `demacia`, `setprojmodel`, `setswprojmodel`, `setprocstart`,
  `SetNetType` and `checkntfeature`.
- The OP6T loader in edl (`0008b0e10051459b_dd7c5f2e53176bee_fhprg_op6t.bin`,
  sha256 `fbaa5b48…519043`) contains **none** of those strings. Its command
  table is: `configure program firmwarewrite patch setbootablestoragedrive
  erase read getstorageinfo nop power benchmark peek poke fixgpt` (plus
  `ufs`/`emmc`). It also has no `getsha256digest`, so `--verify` has to hash
  on the host.
- So with this loader edl did **no** OnePlus auth at all. That is why stock
  `printgpt` and `r` worked, and why the `config` byte patch went through.
  mtk phase 1 implements no auth.

Phase 2 can write with this loader without auth too. Auth only matters if
we switch to a loader that advertises `demacia`/`setprojmodel` (OnePlus
MSM-package loaders for OP7 and later, possibly the MSMDownloadTool fajita
loader). Phase 2 should detect this from the boot log and refuse or
authenticate. It must never guess.

## Handshake, in case a loader requires it (edl "version 1", fajita = projid `18801`)

Inputs: `projid` (`18801` for fajita; read by edl from `param` at offset
24, 5 ASCII chars, when not given), `serial` (SoC serial as **decimal**
string, from the Sahara serial or the loader's `chip serial num` log),
`prodkey` = `b2fad511325185e5` for 18801/18825 (else `7016147d58e8c038`),
`pk` = 16 random chars from `[0-9A-Za-z]`. All ciphers are AES-256-CBC with
a 32-byte key built as `8 bytes ‖ pk (16 ASCII) ‖ 8 bytes`. Tokens are
upper-case hex.

1. `demacia` (only if advertised):
   - `h = SHA256("2e7006834dafe8ad" + serial.zfill(10) + "a6674c6b039707ff")` (raw 32 bytes)
   - plaintext = `b"907heavyworkload" + h`, zero-padded to 256 bytes
   - key = `0163A0D1FDE26711 ‖ pk ‖ 4827C208FBB0E6F0`, iv = `96E0790CAE2BB4AF684C36CB0BEC49CE`
   - send `<demacia token="…" pk="…" />`; success iff the reply contains `verify_res="0"`.
2. `setprojmodel` (only if advertised):
   - `mvht = HEXUP(SHA256(prodkey + projid + "0iyFR00pPnoqjVNL"))`
   - `ver = "guacamoles_21_O.22_191107"`, `cf = "0"`, `ts = unix time (decimal)`
   - `secret = HEXUP(SHA256("c4b95538c57df231" + projid + cf + serial + ver + ts + mvht + "5b0217457e49381b"))`
   - plaintext = `",".join([projid, "0iyFR00pPnoqjVNL", mvht, ver, cf, serial, ts, secret])`, zero-padded to 256
   - key = `10456387E37E2371 ‖ pk ‖ A2D4A0740FD32896`, iv = `9D614A1EAC81C9B2D376D74931036379`
   - send `<setprojmodel token="…" pk="…" />`; success iff `model_check="0"` **and** `auth_token_verify="0"`.
3. Every `<program>`/`<patch>`/`<erase>` then carries `pk="…" token="…"`.
   Here the token encrypts `ts + "," + secret` (fresh `ts`/`secret`, same
   key/iv as step 2).

Later OnePlus models (edl versions 2/3) swap `projid` for a per-model `cm`
value, or use `setprocstart` (which returns `device_timestamp`, mixed into
the key) followed by `setswprojmodel`. Fajita needs neither.

Crates needed if implemented: `aes` + `cbc` (not `cfb`). `sha2` is already
a dependency.
