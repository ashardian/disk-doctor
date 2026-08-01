# diskdoctor v2

Advanced diagnosis and **safe** repair for external hard drives on Linux, with
first-class support for **LUKS-encrypted ext4** volumes. One Python file, no
dependencies beyond the standard system tools it drives.

Read-only by default. Exactly one code path can write to a disk (Repair), and
it is fenced behind explicit `y/N` confirmations at every step.

---

## What it does

| Area | Capabilities |
|---|---|
| **Detection** | Full `lsblk` tree with LUKS lock/unlock state, transport (USB/SATA/NVMe), model & serial, capacity warnings above 90% |
| **SMART** | Attributes, temperature, overall health, short/long self-tests with progress bar, self-test log, drive error log |
| **Trends** | Every check snapshots into a per-drive history; growing defect counters ("pending sectors 8 → 24 since last week") are flagged — the single best early warning a drive gives you |
| **Surface** | Read-only `badblocks` scan (quick first-GiB or full disk) with live progress |
| **Speed** | Direct-I/O read sampling across the disk — slow regions often reveal sector retries *before* SMART admits anything |
| **USB layer** | UAS vs usb-storage driver detection, USB reset/disconnect counting — flaky cables and enclosures are the #1 cause of "corruption" on external drives |
| **ext4** | Superblock forensics via `dumpe2fs` (fs state, recorded error count, first/last error time, mount counts), backup-superblock lookup, `e2image` metadata backups |
| **fsck** | Read-only dry-run (`e2fsck -fn`), guarded repair with automatic escalation, **alternate-superblock recovery** when the primary superblock is destroyed |
| **LUKS** | Header inspection (version/cipher/keyslots) and **header backup to a file** — the most important insurance an encrypted drive can have |
| **lost+found** | Deep inspector: counts, sizes, file-type breakdown (via `file`), largest entries, salvage guidance |
| **Space** | Largest directories and files — find out what's eating a 95%-full drive |
| **Reporting** | 0–100 health score with itemized reasons, plain-English recommendation, export to JSON or text |
| **Audit** | Every command, prompt and finding logged to `~/.diskdoctor/logs/` |

## Requirements

- Linux with Python 3.8+
- Core tools (`lsblk`, `dmesg`, `e2fsck`, `dumpe2fs`, `e2image`, `badblocks`, `find`, `du`, `file`, `dd`) — present on virtually every distro via `util-linux` + `e2fsprogs` + `coreutils`
- Optional, offered for install when needed: `smartmontools` (SMART), `cryptsetup` (LUKS tools), `gddrescue` (rescue imaging), `psmisc` (busy-check)
- Root (or sudo) for SMART, fsck, and raw-device reads; `--scan` works unprivileged

```bash
chmod +x diskdoctor.py
./diskdoctor.py            # interactive menu (recommended)
```

## The menu

```
 1)  Scan & list all drives              [safe]
 2)  Quick diagnosis                     [SMART+trend+dmesg+USB+lost+found+fsck -n]
 3)  DEEP diagnosis                      [adds superblock, read-speed, optional surface scan]
 4)  SMART tools ▸                       [self-tests, logs, history]
 5)  Surface scan (read-only badblocks)
 6)  LUKS tools ▸                        [header info & backup]
 7)  ext4 tools ▸                        [superblock, e2image, backup superblocks]
 8)  lost+found inspector
 9)  Space analyzer                      [what's eating the drive]
10)  Health history & trends
11)  REPAIR filesystem                   [the only write path — guarded]
12)  Export last report (text / JSON)
```

Everything except **11** is read-only against your disk. (Some items write
*files* — reports, header backups, metadata images — never to the drive
under test.)

## Walkthrough: LUKS-encrypted ext4 external drive, ~95% full, files in lost+found

This is the scenario diskdoctor was built around.

**1. Unlock the drive yourself** (diskdoctor never touches passphrases):

```bash
sudo cryptsetup open /dev/sdb1 mydrive
sudo mount /dev/mapper/mydrive /mnt/mydrive     # optional, for lost+found/space tools
```

**2. Run `./diskdoctor.py`, choose `3` (deep diagnosis)** and select the
`/dev/mapper/mydrive` entry (picking the raw `sdb1` also works — filesystem
operations are automatically redirected to the unlocked mapper device).
You get: SMART health + temperature, trend vs. previous runs, kernel-log
errors, USB link stability, read-speed uniformity, superblock error history,
a read-only fsck verdict, lost+found stats, capacity gauge, a 0–100 score and
a recommendation.

**3. Back up the LUKS header now** — menu `6 → 2`. Thirty seconds of work;
without it, header corruption means permanent loss of everything regardless
of passphrase. Store the backup file *off* this drive, treat it like a key.

**4. Inspect lost+found** — menu `8`. Entries are named after inode numbers
(`#12345`) because a past fsck lost their directory entries, but contents are
intact. The inspector categorizes them by type and lists the largest so you
can salvage keepers and delete the rest.

**5. Free space** — menu `9` shows the largest directories and files. ext4
gets fragile and slow above ~90%; aim lower.

**6. Repair only if the dry-run found errors** — menu `11`. The flow will
offer a ddrescue image if SMART shows physical damage, offer a cheap e2image
metadata backup, confirm, unmount (aborting if it can't), run `e2fsck -fp`,
escalate to `-fy` only with your consent, recover via a backup superblock if
the primary is destroyed, and remount.

**7. Make trend-watching a habit** — run a quick diagnosis (menu `2`) weekly.
Menu `10` shows the counters over time; *growth* in reallocated/pending
sectors is the signal to replace the drive, not any absolute number.

## CLI flags (for scripts)

```bash
./diskdoctor.py --scan                              # inventory (add --json)
./diskdoctor.py --device /dev/sdb1                  # quick diagnosis
./diskdoctor.py --device /dev/mapper/mydrive --deep --json > report.json
./diskdoctor.py --device /dev/sdb --selftest short  # start SMART self-test
./diskdoctor.py --device /dev/sdb --history         # trend table
./diskdoctor.py --device /dev/mapper/mydrive --fix  # guarded repair
```

## Where diskdoctor writes its own files

```
~/.diskdoctor/
├── config.json       # optional threshold overrides (see below)
├── logs/             # audit trail of every command and prompt
├── history/          # per-drive SMART snapshots (trend data)
├── reports/          # exported text/JSON reports
├── e2image/          # ext4 metadata images taken before repairs
└── luks-headers/     # LUKS header backups (mode 600 — guard these)
```

Config example (all optional; defaults shown):

```json
{ "warn_full_pct": 90, "crit_full_pct": 95, "temp_warn_c": 55,
  "speed_samples": 6, "slow_factor": 0.35, "surface_quick_mb": 1024 }
```

## Safety model

1. **Read-only by default.** Only Repair writes to a disk, behind `y/N`
   prompts that default to *No*.
2. **Raw LUKS containers are never fsck'd or mounted** — operations are
   redirected to the unlocked `/dev/mapper` child. Header tools are the one
   sanctioned exception: they read the container and write only ordinary files.
3. **A mounted filesystem is never write-fsck'd.** If unmounting fails,
   repair aborts.
4. **badblocks runs in read-only `-sv` mode only.** The destructive `-w`/`-n`
   modes are deliberately not implemented.
5. **Passphrases are never requested or handled.**
6. **Header restore is never automated** — instructions only.

## Interpreting results

- **lost+found looks empty but you can see files in it?** The directory is
  root-owned mode 700 by design, so unprivileged runs can't look inside.
  diskdoctor now says "exists but unreadable — re-run with sudo" in that
  case (earlier builds wrongly reported it empty). For full counts and the
  inspector, run with `sudo`.
- **Score is a triage aid, not a prophecy.** An A-grade with growing pending
  sectors is worse than a C-grade that's been stable for a year.
- **fsck errors + USB resets + healthy SMART** = classic bad cable/port/
  enclosure signature. Swap the cable before blaming the disk.
- **"PRIMARY SUPERBLOCK damaged"** in a dry-run is recoverable: ext4 keeps
  backups, and Repair probes them automatically (`e2fsck -b`).
- **Unreadable blocks on a surface scan** = physical media damage. Stop
  repairing, start imaging (`ddrescue`), plan replacement.
- On a drive with known physical damage, **image first, repair the image's
  copy later**. Filesystem repair stresses exactly the sectors that are dying.

## Testing notes

Detection, dry-run, superblock forensics, e2image, surface scan, speed
sampling, scoring/recommendations, exports, and the full repair flow —
including recovery from a deliberately destroyed primary superblock — were
validated against real (file-backed) corrupted ext4 filesystems, with
byte-level verification that read-only operations never modify the target.
SMART and LUKS parsers were validated against canned `smartctl`/`cryptsetup`
output (ATA + NVMe, LUKS1 + LUKS2). The lost+found detector was additionally validated as an unprivileged user against a root-owned mode-700 directory (the case that previously produced a false "empty"). Behaviour on genuinely failing hardware
(ddrescue flow, USB reset detection on a live flaky link) follows the
documented tool semantics but hasn't been exercised on a dying drive here —
as ever: **backups first**.
