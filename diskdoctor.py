#!/usr/bin/env python3
"""
diskdoctor v2 — advanced diagnostic & repair suite for external drives on Linux.

Special support for LUKS-encrypted ext4 volumes.

WHAT'S IN THE BOX
-----------------
DETECTION   lsblk JSON tree, LUKS layer awareness, transport (USB/SATA/NVMe),
            serial/model capture, >90% full warnings.
SMART       attributes, temperature, overall health, short/long self-tests
            with progress polling, self-test log, ATA/NVMe error log, and a
            persistent per-drive HISTORY with trend analysis ("pending
            sectors grew 8 → 24 since last week").
SURFACE     read-only badblocks scan (quick first-GiB or full), live progress.
SPEED       direct-I/O read sampling across the disk to expose slow regions
            (sector-retry behaviour that SMART sometimes misses).
USB LAYER   detects usb-storage vs UAS driver, counts USB resets in dmesg —
            the #1 cause of "corruption" on external drives is actually the
            cable/enclosure, not the disk.
ext4        superblock forensics via dumpe2fs (fs state, error counters,
            first/last error time, mount counts), backup-superblock lookup,
            e2image metadata backups, fsck dry-run and guarded repair with
            alternate-superblock recovery.
LUKS        header dump (version/cipher/keyslots) and header BACKUP to a
            file — the single most important insurance for encrypted drives.
lost+found  deep inspector: counts, sizes, file-type breakdown, largest files.
SPACE       top-N largest directories & files (for drives at 90-95% capacity).
SCORE       0–100 heuristic health score with reasons, plain-English
            recommendation engine, JSON + plain-text report export.
AUDIT       every command, prompt and finding logged to ~/.diskdoctor/logs/.

SAFETY MODEL (unchanged from v1, enforced everywhere)
-----------------------------------------------------
1. READ-ONLY BY DEFAULT. The only write paths are: Repair (menu 11 /
   --fix), which is fenced by y/N prompts; and *file* outputs (images,
   header backups, reports) that never touch the drive itself.
2. Raw crypto_LUKS devices are never fsck'd/mounted — filesystem operations
   are redirected to the unlocked /dev/mapper child. (LUKS *header* tools
   are the sanctioned exception: they read the container and write only to
   ordinary files.)
3. Write-mode fsck NEVER runs on a mounted filesystem.
4. badblocks runs in read-only -sv mode ONLY; destructive -w/-n modes are
   not implemented on purpose.
5. diskdoctor never asks for or handles LUKS passphrases.

Interactive numbered menu by default; flags for scripting.
Python 3.8+, stdlib only.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import io
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# ==========================================================================
# ANSI colors (no external UI library)
# ==========================================================================

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def red(t: str) -> str:      return _c("31;1", t)
def yellow(t: str) -> str:   return _c("33;1", t)
def green(t: str) -> str:    return _c("32;1", t)
def cyan(t: str) -> str:     return _c("36", t)
def magenta(t: str) -> str:  return _c("35", t)
def bold(t: str) -> str:     return _c("1", t)
def dim(t: str) -> str:      return _c("2", t)


# ==========================================================================
# Config  (~/.diskdoctor/config.json overrides these defaults)
# ==========================================================================

BASE_DIR = Path.home() / ".diskdoctor"

_DEFAULTS = {
    "warn_full_pct": 90,        # flag filesystems fuller than this
    "crit_full_pct": 95,
    "realloc_warn": 1,          # any reallocated sector = warning
    "realloc_crit": 50,         # this many realloc+pending = failing
    "temp_warn_c": 55,
    "temp_crit_c": 65,
    "speed_samples": 6,         # read-speed test: number of sample points
    "speed_sample_mb": 8,       # MB read per sample
    "slow_factor": 0.35,        # sample < 35% of median speed => slow region
    "surface_quick_mb": 1024,   # "quick" badblocks scan covers first 1 GiB
    "history_keep": 200,        # SMART snapshots kept per drive
}


def _load_config() -> dict:
    cfg = dict(_DEFAULTS)
    p = BASE_DIR / "config.json"
    try:
        if p.exists():
            user = json.loads(p.read_text())
            for k, v in user.items():
                if k in cfg:
                    cfg[k] = v
    except (OSError, json.JSONDecodeError):
        pass
    return cfg


CFG = _load_config()


# ==========================================================================
# Audit log  →  ~/.diskdoctor/logs/diskdoctor-YYYYMMDD.log
# ==========================================================================

LOG_DIR = BASE_DIR / "logs"


class AuditLog:
    """Append-only audit trail: every run, command, prompt and finding."""

    def __init__(self) -> None:
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            self.path = LOG_DIR / f"diskdoctor-{_dt.date.today():%Y%m%d}.log"
        except OSError:                      # unwritable HOME — degrade quietly
            self.path = Path(os.devnull)
        self.write(f"=== session start (pid {os.getpid()}, uid {os.getuid()}, "
                   f"argv {sys.argv[1:]}) ===")

    def write(self, msg: str) -> None:
        ts = _dt.datetime.now().isoformat(timespec="seconds")
        try:
            with self.path.open("a") as f:
                f.write(f"[{ts}] {msg}\n")
        except OSError:
            pass  # logging must never break a diagnostic run


LOG = AuditLog()


# ==========================================================================
# Small helpers
# ==========================================================================

def run(cmd: list[str], timeout: int = 300,
        stdin_text: str | None = None) -> tuple[int, str, str]:
    """Run a command, capture output, log it. Never raises on rc != 0."""
    LOG.write(f"RUN: {' '.join(cmd)}")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, input=stdin_text)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"{cmd[0]}: timed out after {timeout}s"
    except OSError as e:      # missing binary, exec-permission denied, ...
        return 127, "", f"{cmd[0]}: {e}"


def run_shell(cmdline: str, timeout: int = 600) -> tuple[int, str, str]:
    """For the rare pipeline (dumpe2fs | grep -m ...). Logged like run()."""
    LOG.write(f"RUN(sh): {cmdline}")
    try:
        p = subprocess.run(cmdline, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def is_root() -> bool:
    return os.geteuid() == 0


def sudo_prefix() -> list[str]:
    return [] if is_root() else ["sudo"]


def confirm(question: str, danger: bool = False) -> bool:
    """y/N prompt — default is ALWAYS No. Answer is logged."""
    color = red if danger else yellow
    try:
        ans = input(color(f"{question} [y/N]: ")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        ans = "n"
    LOG.write(f"PROMPT: {question!r} -> {ans or 'n'}")
    return ans == "y"


def ask(question: str, default: str = "") -> str:
    try:
        ans = input(cyan(question)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return ans or default


def human_size(nbytes: float) -> str:
    size = float(nbytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{nbytes} B"


def offer_install(package: str, binary: str) -> bool:
    """Tell the user a tool is missing; offer to apt-install it."""
    print(yellow(f"  ⚠ '{binary}' is not installed (package: {package})."))
    if not sys.stdin.isatty() or not confirm(f"  Install {package} now via apt?"):
        return False
    rc, out, err = run(sudo_prefix() + ["apt-get", "install", "-y", package],
                       timeout=900)
    if rc == 0 and have(binary):
        print(green(f"  ✓ {package} installed."))
        return True
    print(red(f"  ✗ Install failed: {(err or out).strip()[:200]}"))
    return False


def device_size_bytes(path: str) -> int | None:
    """Size of a block device (or plain file, for tests) in bytes."""
    rc, out, _ = run(["lsblk", "-b", "-dn", "-o", "SIZE", path])
    if rc == 0 and out.strip().isdigit():
        return int(out.strip())
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def strip_ansi(text: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", text)


def _find_mountpoint(path: str) -> str | None:
    """
    LIVE mountpoint lookup (findmnt, then /proc/mounts). lsblk data is a
    snapshot from scan time — if the user mounted the drive afterwards, the
    Device object says 'not mounted' while reality disagrees.
    """
    if have("findmnt"):
        rc, out, _ = run(["findmnt", "-n", "-o", "TARGET", "--source", path])
        if rc == 0 and out.strip():
            return out.strip().splitlines()[0]
    try:
        real = os.path.realpath(path)
        for line in Path("/proc/mounts").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].startswith("/") \
                    and os.path.realpath(parts[0]) == real:
                return parts[1].replace("\\040", " ")   # escaped spaces
    except OSError:
        pass
    return None


# ==========================================================================
# 1. DETECTION / INVENTORY
# ==========================================================================

@dataclass
class Device:
    """One node of the lsblk tree (disk, partition, or dm mapper device)."""
    name: str
    path: str
    dtype: str                      # disk | part | crypt | ...
    fstype: str | None
    label: str | None
    uuid: str | None
    mountpoint: str | None
    fsuse_pct: int | None
    size: str | None
    tran: str | None = None        # usb | sata | nvme | None
    serial: str | None = None
    model: str | None = None
    parent: "Device | None" = None
    children: list["Device"] = field(default_factory=list)

    @property
    def is_luks_container(self) -> bool:
        return (self.fstype or "").lower() == "crypto_luks"

    @property
    def is_unlocked_luks(self) -> bool:
        return self.dtype == "crypt"

    @property
    def is_mounted(self) -> bool:
        return bool(self.mountpoint) and self.mountpoint != "[SWAP]"

    def physical_parent(self) -> "Device":
        node: Device = self
        while node.parent is not None:
            node = node.parent
        return node

    def flat(self) -> list["Device"]:
        out = [self]
        for ch in self.children:
            out.extend(ch.flat())
        return out

    def identity(self) -> str:
        """Stable id for history files: serial > uuid > name."""
        p = self.physical_parent()
        raw = p.serial or p.uuid or p.name
        return re.sub(r"[^A-Za-z0-9._-]", "_", raw)


def _dev_path(name: str, dtype: str) -> str:
    if dtype == "crypt" or name.startswith(("luks-", "dm-")):
        mapper = Path("/dev/mapper") / name
        if mapper.exists():
            return str(mapper)
    return f"/dev/{name}"


def _parse_pct(raw) -> int | None:
    if raw is None:
        return None
    m = re.search(r"(\d+)", str(raw))
    return int(m.group(1)) if m else None


def scan_devices() -> list[Device]:
    """Parse lsblk JSON into a Device tree. Works without root."""
    cols = "NAME,TYPE,FSTYPE,LABEL,UUID,MOUNTPOINT,FSUSE%,SIZE,TRAN,SERIAL,MODEL"
    rc, out, err = run(["lsblk", "-J", "-o", cols])
    if rc != 0:                                   # older lsblk fallback
        rc, out, err = run(["lsblk", "-f", "-J"])
        if rc != 0:
            print(red(f"lsblk failed: {err.strip()}"))
            return []

    def build(node: dict, parent: Device | None) -> Device:
        dtype = node.get("type", "")
        dev = Device(
            name=node.get("name", "?"),
            path=_dev_path(node.get("name", "?"), dtype),
            dtype=dtype,
            fstype=node.get("fstype"),
            label=node.get("label"),
            uuid=node.get("uuid"),
            mountpoint=node.get("mountpoint")
                       or (node.get("mountpoints") or [None])[0],
            fsuse_pct=_parse_pct(node.get("fsuse%")),
            size=node.get("size"),
            tran=node.get("tran"),
            serial=node.get("serial"),
            model=(node.get("model") or "").strip() or None,
            parent=parent,
        )
        for ch in node.get("children", []) or []:
            dev.children.append(build(ch, dev))
        return dev

    try:
        tree = json.loads(out)
    except json.JSONDecodeError:
        print(red("Could not parse lsblk JSON output."))
        return []

    disks: list[Device] = []
    for node in tree.get("blockdevices", []):
        if node.get("type") in ("loop", "rom"):
            continue
        disks.append(build(node, None))
    LOG.write(f"SCAN: {sum(len(d.flat()) for d in disks)} block nodes")
    return disks


def find_device(disks: list[Device], wanted: str) -> Device | None:
    wanted = wanted.strip()
    name = wanted.rsplit("/", 1)[-1]
    for disk in disks:
        for dev in disk.flat():
            if dev.path == wanted or dev.name == name:
                return dev
    return None


def resolve_target(dev: Device) -> tuple[Device, list[str]]:
    """
    SAFETY RULE for *filesystem* operations: never touch a raw crypto_LUKS
    device — redirect to the unlocked /dev/mapper child, or explain how to
    unlock. (LUKS header tools intentionally bypass this — they read the
    container and write only to regular files.)
    """
    notes: list[str] = []
    # Picked a bare disk? Descend an UNAMBIGUOUS single-child chain to the
    # actual filesystem/container (e.g. /dev/sdb → /dev/sdb1). With multiple
    # partitions we never guess — the user must choose.
    node = dev
    while not node.fstype and len(node.children) == 1:
        node = node.children[0]
        notes.append(f"{dev.path} → using its only child {node.path} "
                     f"({node.fstype or node.dtype})")
    dev = node
    if dev.is_luks_container:
        unlocked = [c for c in dev.children if c.is_unlocked_luks]
        if unlocked:
            target = unlocked[0]
            notes.append(f"{dev.path} is a raw LUKS container — redirecting "
                         f"filesystem operations to {target.path}.")
            LOG.write(f"LUKS-REDIRECT: {dev.path} -> {target.path}")
            return target, notes
        notes.append(f"{dev.path} is LUKS-encrypted and LOCKED. Unlock first, "
                     f"e.g.: sudo cryptsetup open {dev.path} mydrive "
                     f"(diskdoctor never handles passphrases).")
        return dev, notes
    return dev, notes


# ==========================================================================
# 2. SMART HISTORY  (~/.diskdoctor/history/<drive-id>.json)
# ==========================================================================

HIST_DIR = BASE_DIR / "history"


class HistoryStore:
    """Persist SMART snapshots per physical drive; compute trends."""

    def __init__(self, dev: Device) -> None:
        HIST_DIR.mkdir(parents=True, exist_ok=True)
        self.dev = dev.physical_parent()
        self.path = HIST_DIR / f"{dev.identity()}.json"

    def load(self) -> list[dict]:
        try:
            return json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError):
            return []

    def add(self, snap: dict) -> None:
        hist = self.load()
        hist.append(snap)
        hist = hist[-int(CFG["history_keep"]):]
        try:
            self.path.write_text(json.dumps(hist, indent=1))
            LOG.write(f"HISTORY {self.path.name}: snapshot added "
                      f"({len(hist)} total)")
        except OSError as e:
            LOG.write(f"HISTORY write failed: {e}")

    def trend(self) -> dict:
        """Compare newest snapshot against previous + oldest."""
        hist = self.load()
        out: dict = {"snapshots": len(hist), "warnings": [], "rows": hist[-8:]}
        if len(hist) < 2:
            return out
        new, prev, old = hist[-1], hist[-2], hist[0]

        def delta(key: str, label: str) -> None:
            a, b = prev.get(key), new.get(key)
            if a is not None and b is not None and b > a:
                out["warnings"].append(
                    f"{label} grew {a} → {b} since {prev['ts'][:16]}")
            c = old.get(key)
            if c is not None and b is not None and b > c and old is not prev:
                out["warnings"].append(
                    f"{label} grew {c} → {b} since first snapshot "
                    f"({old['ts'][:10]})")

        delta("pending_sectors", "Pending sectors")
        delta("reallocated_sectors", "Reallocated sectors")
        delta("uncorrectable_errors", "Uncorrectable errors")
        if new.get("overall_health") not in ("PASSED", "OK", None) \
                and prev.get("overall_health") in ("PASSED", "OK"):
            out["warnings"].append("Overall SMART health flipped to "
                                   + str(new.get("overall_health")))
        return out


# ==========================================================================
# 3. SMART SUITE
# ==========================================================================

_SMART_ATTRS = {
    5:   "reallocated_sectors",
    9:   "power_on_hours",
    194: "temperature_c",
    190: "temperature_c",          # airflow temp — used if 194 absent
    197: "pending_sectors",
    198: "uncorrectable_errors",
}


def _ensure_smartctl() -> bool:
    if have("smartctl"):
        return True
    return offer_install("smartmontools", "smartctl")


def smart_check(dev: Device, record_history: bool = True) -> dict:
    """
    `smartctl -a` on the PHYSICAL PARENT disk (never a partition/mapper).
    Parses attributes + temperature + health; snapshots into history.
    """
    parent = dev.physical_parent()
    result: dict = {
        "device": parent.path, "available": False, "overall_health": None,
        "reallocated_sectors": None, "pending_sectors": None,
        "uncorrectable_errors": None, "power_on_hours": None,
        "temperature_c": None, "serial": parent.serial, "model": parent.model,
        "selftest_in_progress": None, "verdict": "unknown", "notes": [],
    }

    if not _ensure_smartctl():
        result["notes"].append("smartctl not installed")
        result["verdict"] = "unavailable"
        return result
    if not is_root():
        print(dim("  (smartctl requires root; using sudo)"))

    rc, out, err = run(sudo_prefix() + ["smartctl", "-a", parent.path])
    text = out + "\n" + err
    if not out.strip() or "Permission denied" in text or \
            ("Smartctl open device" in text and "failed" in text):
        result["notes"].append(f"could not read SMART from {parent.path}: "
                               f"{err.strip()[:120] or f'rc={rc}'}")
        result["verdict"] = "unavailable"
        return result
    result["available"] = True
    _parse_smart_output(out, result)

    realloc = result["reallocated_sectors"] or 0
    pending = result["pending_sectors"] or 0
    uncorr = result["uncorrectable_errors"] or 0
    failed = result["overall_health"] not in (None, "PASSED", "OK")
    if failed or uncorr > 0 or realloc + pending >= CFG["realloc_crit"]:
        result["verdict"] = "failing"
    elif realloc >= CFG["realloc_warn"] or pending >= CFG["realloc_warn"]:
        result["verdict"] = "degraded"
    else:
        result["verdict"] = "healthy"

    if result["serial"] is None:
        m = re.search(r"Serial Number:\s*(\S+)", out)
        if m:
            result["serial"] = m.group(1)
            parent.serial = m.group(1)

    if record_history:
        HistoryStore(parent).add({
            "ts": _dt.datetime.now().isoformat(timespec="seconds"),
            "overall_health": result["overall_health"],
            "reallocated_sectors": result["reallocated_sectors"],
            "pending_sectors": result["pending_sectors"],
            "uncorrectable_errors": result["uncorrectable_errors"],
            "power_on_hours": result["power_on_hours"],
            "temperature_c": result["temperature_c"],
        })

    LOG.write(f"SMART {parent.path}: verdict={result['verdict']} "
              f"realloc={realloc} pending={pending} uncorr={uncorr} "
              f"temp={result['temperature_c']}")
    return result


def _parse_smart_output(out: str, result: dict) -> None:
    """Shared parser for `smartctl -a` text (ATA + NVMe). Testable."""
    m = re.search(r"self-assessment test result:\s*(\w+)", out, re.I) \
        or re.search(r"SMART Health Status:\s*(\w+)", out, re.I)
    if m:
        result["overall_health"] = m.group(1).upper()

    # ATA attribute table rows
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\s+(\S+)\s+0x[0-9a-fA-F]+\s+\d+\s+\d+\s+"
                     r"\d+\s+\S+\s+\S+\s+\S+\s+(\d+)", line)
        if m:
            key = _SMART_ATTRS.get(int(m.group(1)))
            if key and (result.get(key) is None or key != "temperature_c"):
                result[key] = int(m.group(3))

    # NVMe / fallback fields
    if result.get("power_on_hours") is None:
        m = re.search(r"Power On Hours:\s*([\d,]+)", out)
        if m:
            result["power_on_hours"] = int(m.group(1).replace(",", ""))
    if result.get("uncorrectable_errors") is None:
        m = re.search(r"Media and Data Integrity Errors:\s*(\d+)", out)
        if m:
            result["uncorrectable_errors"] = int(m.group(1))
    if result.get("temperature_c") is None:
        m = re.search(r"Temperature:\s*(\d+)\s*Celsius", out)
        if m:
            result["temperature_c"] = int(m.group(1))

    m = re.search(r"(\d+)% of test remaining", out)
    if m:
        result["selftest_in_progress"] = 100 - int(m.group(1))


def smart_selftest(dev: Device, kind: str) -> None:
    """Kick off a drive-firmware self-test (safe: read-only, data untouched).

    A long test on a *failing* drive is still a stress workload — we warn.
    """
    parent = dev.physical_parent()
    if not _ensure_smartctl():
        return
    if kind == "long":
        print(yellow("  A long self-test reads the ENTIRE surface (can take "
                     "hours on a 2 TB drive)\n  and is a real workload — on a "
                     "drive you suspect is dying, image it first."))
    if not confirm(f"  Start SMART {kind} self-test on {parent.path}?"):
        return
    rc, out, err = run(sudo_prefix() + ["smartctl", "-t", kind, parent.path])
    if rc == 0 or "has begun" in out:
        m = re.search(r"Please wait (\d+) (minutes|seconds)", out)
        eta = f" (~{m.group(1)} {m.group(2)})" if m else ""
        print(green(f"  ✓ {kind.capitalize()} self-test started{eta}."))
        print(dim("    Check progress via SMART menu → option 4; the drive "
                  "keeps working meanwhile."))
    else:
        print(red(f"  ✗ Could not start test: {(err or out).strip()[:200]}"))
    LOG.write(f"SELFTEST {kind} {parent.path}: rc={rc}")


def smart_selftest_log(dev: Device) -> None:
    parent = dev.physical_parent()
    if not _ensure_smartctl():
        return
    rc, out, err = run(sudo_prefix() + ["smartctl", "-l", "selftest",
                                        parent.path])
    print(bold(f"\n  SELF-TEST LOG — {parent.path}"))
    rows = [l for l in out.splitlines() if re.match(r"^#\s*\d+", l)]
    if not rows:
        print(dim("    No self-tests recorded yet."
                  if rc == 0 else f"    unavailable: {err.strip()[:120]}"))
        return
    for l in rows[:10]:
        line = l.strip()
        col = green if "without error" in line.lower() else \
              (red if re.search(r"fail|read failure", line, re.I) else yellow)
        print("    " + col(line))


def smart_error_log(dev: Device) -> None:
    parent = dev.physical_parent()
    if not _ensure_smartctl():
        return
    rc, out, err = run(sudo_prefix() + ["smartctl", "-l", "error", parent.path])
    print(bold(f"\n  DEVICE ERROR LOG — {parent.path}"))
    if "No Errors Logged" in out:
        print(green("    No errors logged by the drive. ✓"))
        return
    m = re.search(r"ATA Error Count:\s*(\d+)", out)
    if m:
        print(red(f"    Drive has logged {m.group(1)} ATA error(s). "
                  "Most recent entries:"))
    for line in out.splitlines():
        if re.match(r"^Error \d+", line):
            print(dim("      " + line.strip()[:110]))
    if not m and rc != 0:
        print(yellow(f"    unavailable: {(err or out).strip()[:150]}"))


def smart_progress(dev: Device) -> None:
    parent = dev.physical_parent()
    if not _ensure_smartctl():
        return
    rc, out, _ = run(sudo_prefix() + ["smartctl", "-a", parent.path])
    m = re.search(r"(\d+)% of test remaining", out)
    if m:
        done = 100 - int(m.group(1))
        barlen = done // 5
        print(cyan(f"    Self-test progress: [{'█'*barlen}{'░'*(20-barlen)}] "
                   f"{done}% complete"))
    elif re.search(r"previous self-test.*(completed|without error)", out, re.I):
        print(green("    No test running; last self-test completed."))
    else:
        print(dim("    No self-test currently in progress."))


def show_history(dev: Device) -> None:
    """Health history & trend for the physical drive."""
    parent = dev.physical_parent()
    tr = HistoryStore(parent).trend()
    print(bold(f"\n  HEALTH HISTORY — {parent.path} "
               f"({parent.model or 'unknown model'})"))
    if tr["snapshots"] == 0:
        print(dim("    No snapshots yet — run a diagnosis first."))
        return
    print(dim(f"    {tr['snapshots']} snapshot(s) on file. Most recent:"))
    hdr = f"    {'WHEN':<17}{'HEALTH':<8}{'REALLOC':<9}{'PENDING':<9}" \
          f"{'UNCORR':<8}{'TEMP':<6}{'HOURS'}"
    print(cyan(hdr))
    for s in tr["rows"]:
        print("    {:<17}{:<8}{:<9}{:<9}{:<8}{:<6}{}".format(
            s["ts"][:16].replace("T", " "),
            str(s.get("overall_health") or "-"),
            str(s.get("reallocated_sectors") if s.get("reallocated_sectors")
                is not None else "-"),
            str(s.get("pending_sectors") if s.get("pending_sectors")
                is not None else "-"),
            str(s.get("uncorrectable_errors") if s.get("uncorrectable_errors")
                is not None else "-"),
            str(s.get("temperature_c") or "-"),
            str(s.get("power_on_hours") or "-")))
    if tr["warnings"]:
        print()
        for w in tr["warnings"]:
            print(red("    ⚠ TREND: " + w))
        print(yellow("    Growing defect counters mean the drive is actively "
                     "deteriorating — back up now."))
    else:
        print(green("    ✓ No negative trends between snapshots."))


# ==========================================================================
# 4. KERNEL LOG + USB LAYER
# ==========================================================================

_DMESG_PATTERNS = re.compile(
    r"(i/o error|io error|ata error|ata bus error|blk_update_request|"
    r"buffer i/o|unrecovered read error|medium error|ext4-fs error|"
    r"ext4-fs warning|journal has aborted|critical (?:medium|target) error)",
    re.I)

_USB_PATTERNS = re.compile(
    r"(reset (?:high|full|superspeed)|usb \S+ reset|device descriptor "
    r"read.*error|uas_eh|device not accepting address|disconnect, device)",
    re.I)


def dmesg_check(dev: Device) -> dict:
    """Grep kernel ring buffer for errors touching this device family."""
    parent = dev.physical_parent()
    names = {parent.name} | {d.name for d in parent.flat()}
    result: dict = {"available": False, "matches": [], "usb_events": [],
                    "notes": []}

    rc, out, err = run(["dmesg", "--time-format", "iso"])
    if rc != 0:
        rc, out, err = run(sudo_prefix() + ["dmesg", "--time-format", "iso"])
        if rc != 0:
            result["notes"].append("dmesg unavailable "
                                   "(kernel.dmesg_restrict — needs root)")
            return result
    result["available"] = True
    name_re = re.compile(r"\b(" + "|".join(re.escape(n) for n in names) + r")\b")
    for line in out.splitlines():
        if name_re.search(line):
            if _DMESG_PATTERNS.search(line):
                result["matches"].append(line.strip())
            if _USB_PATTERNS.search(line):
                result["usb_events"].append(line.strip())
        elif "usb" in line.lower() and _USB_PATTERNS.search(line):
            # resets often log against the usb port, not sdX — keep a few
            result["usb_events"].append(line.strip())
    result["matches"] = result["matches"][-25:]
    result["usb_events"] = result["usb_events"][-15:]
    LOG.write(f"DMESG {parent.path}: {len(result['matches'])} err, "
              f"{len(result['usb_events'])} usb events")
    return result


def usb_layer_check(dev: Device, dmesg: dict | None = None) -> dict:
    """
    External-drive reality check: is this USB, which driver (UAS vs
    usb-storage), and has the link been resetting? Flaky cables/enclosures
    produce 'corruption' symptoms identical to a dying disk.
    """
    parent = dev.physical_parent()
    result: dict = {"transport": parent.tran, "driver": None,
                    "resets": len((dmesg or {}).get("usb_events", [])),
                    "notes": []}
    if parent.tran != "usb":
        result["notes"].append(f"transport is {parent.tran or 'unknown'} — "
                               "USB-layer checks skipped")
        return result
    # Walk sysfs upwards looking for the interface driver (uas/usb-storage).
    try:
        node = Path(f"/sys/block/{parent.name}/device").resolve()
        for _ in range(8):
            drv = node / "driver"
            if drv.is_symlink():
                name = os.path.basename(os.readlink(drv))
                if name in ("uas", "usb-storage"):
                    result["driver"] = name
                    break
            node = node.parent
    except OSError:
        pass
    LOG.write(f"USB {parent.path}: driver={result['driver']} "
              f"resets={result['resets']}")
    return result


# ==========================================================================
# 5. READ-SPEED SAMPLING  (read-only; exposes retry-slow regions)
# ==========================================================================

def read_speed_test(dev: Device, samples: int | None = None,
                    sample_mb: int | None = None) -> dict:
    """
    dd read samples at evenly spaced offsets with O_DIRECT (cache-bypassing).
    A healthy drive is roughly uniform; sectors being retried show up as
    samples far below the median — often before SMART admits anything.
    """
    samples = samples or int(CFG["speed_samples"])
    sample_mb = sample_mb or int(CFG["speed_sample_mb"])
    result: dict = {"device": dev.path, "samples": [], "median_mbps": None,
                    "slow_regions": 0, "notes": []}
    size = device_size_bytes(dev.path)
    if not size or size < sample_mb * 1024 * 1024 * 2:
        result["notes"].append("device too small for sampling")
        return result

    span = size - sample_mb * 1024 * 1024
    print(dim(f"  Sampling read speed at {samples} points "
              f"({sample_mb} MiB each, direct I/O)..."))
    speeds: list[float] = []
    for i in range(samples):
        offset_mb = int((span * i / max(1, samples - 1)) // (1024 * 1024))
        cmd = sudo_prefix() + ["dd", f"if={dev.path}", "of=/dev/null",
                               "bs=1M", f"count={sample_mb}",
                               f"skip={offset_mb}", "iflag=direct"]
        t0 = time.monotonic()
        rc, out, err = run(cmd, timeout=180)
        elapsed = time.monotonic() - t0
        if rc != 0 and "nvalid argument" in err:
            # filesystem/dev doesn't support O_DIRECT — retry buffered
            cmd = [c for c in cmd if c != "iflag=direct"]
            t0 = time.monotonic()
            rc, out, err = run(cmd, timeout=180)
            elapsed = time.monotonic() - t0
            if "cache" not in " ".join(result["notes"]):
                result["notes"].append("O_DIRECT unsupported — results may "
                                       "be cache-inflated")
        if rc != 0:
            result["samples"].append({"offset_mb": offset_mb, "mbps": None,
                                      "error": err.strip()[:80]})
            print(red(f"    sample @{offset_mb} MiB: READ ERROR "
                      f"({err.strip()[:60]})"))
            continue
        mbps = sample_mb / max(elapsed, 1e-6)
        speeds.append(mbps)
        result["samples"].append({"offset_mb": offset_mb,
                                  "mbps": round(mbps, 1)})
        print(dim(f"    @{offset_mb:>8} MiB : {mbps:7.1f} MB/s"))

    if speeds:
        med = statistics.median(speeds)
        result["median_mbps"] = round(med, 1)
        slow = [s for s in result["samples"]
                if s.get("mbps") and s["mbps"] < med * CFG["slow_factor"]]
        errored = [s for s in result["samples"] if s.get("error")]
        result["slow_regions"] = len(slow) + len(errored)
        if result["slow_regions"]:
            print(yellow(f"  ⚠ {result['slow_regions']} region(s) far below "
                         f"median ({med:.0f} MB/s) — possible sector retries."))
        else:
            print(green(f"  ✓ Uniform read speed (median {med:.0f} MB/s)."))
    LOG.write(f"SPEED {dev.path}: median={result['median_mbps']} "
              f"slow={result['slow_regions']}")
    return result


# ==========================================================================
# 6. SURFACE SCAN  (badblocks — READ-ONLY MODE ONLY)
# ==========================================================================

def surface_scan(dev: Device, quick: bool) -> dict:
    """
    badblocks -sv = read-only surface verification. Destructive modes
    (-w, -n) are deliberately NOT implemented in this tool.
    Progress streams live to the terminal; bad block numbers are captured.
    """
    result: dict = {"device": dev.path, "mode": "quick" if quick else "full",
                    "bad_blocks": [], "completed": False, "notes": []}
    if not have("badblocks"):
        if not offer_install("e2fsprogs", "badblocks"):
            result["notes"].append("badblocks unavailable")
            return result

    size = device_size_bytes(dev.path) or 0
    args = sudo_prefix() + ["badblocks", "-sv", "-b", "1024"]
    if quick:
        last_block = int(CFG["surface_quick_mb"]) * 1024   # 1 KiB blocks
        last_block = min(last_block, max(0, size // 1024 - 1)) or None
        if last_block:
            args += [dev.path, str(last_block)]
        else:
            args += [dev.path]
        scope = f"first {CFG['surface_quick_mb']} MiB"
    else:
        args += [dev.path]
        scope = "ENTIRE device"
        hours = size / (80 * 1024 * 1024) / 3600 if size else 0
        print(yellow(f"  Full surface scan reads the whole drive"
                     f"{f' (~{hours:.1f} h at 80 MB/s)' if hours else ''}."))
    if not confirm(f"  Start READ-ONLY surface scan of {dev.path} ({scope})?"):
        result["notes"].append("declined")
        return result

    print(dim("  badblocks progress (Ctrl-C aborts safely — it's read-only):"))
    LOG.write(f"SURFACE start {dev.path} quick={quick}")
    try:
        # stderr → terminal for live progress; stdout captured = bad blocks
        p = subprocess.Popen(args, stdout=subprocess.PIPE,
                             stderr=None, text=True)
        out, _ = p.communicate()
        rc = p.returncode
    except KeyboardInterrupt:
        p.terminate()
        result["notes"].append("aborted by user")
        print(yellow("\n  Scan aborted (no harm done — read-only)."))
        return result

    result["completed"] = True
    result["bad_blocks"] = [int(x) for x in out.split() if x.isdigit()][:500]
    n = len(result["bad_blocks"])
    if rc == 0 and n == 0:
        print(green(f"  ✓ Surface scan clean ({scope})."))
    elif n:
        print(red(f"  ✗ {n} unreadable block(s) found! First few: "
                  f"{result['bad_blocks'][:8]}"))
        print(yellow("    Unreadable blocks = physical media damage. "
                     "Image with ddrescue and plan replacement."))
    else:
        print(yellow(f"  badblocks exited rc={rc} — see log."))
    LOG.write(f"SURFACE {dev.path}: rc={rc} bad={n}")
    return result


# ==========================================================================
# 7. lost+found — quick check + deep inspector
# ==========================================================================

def lostfound_check(dev: Device) -> dict:
    """Quick stats used inside the standard report.

    Hardened after a real-world false negative: lost+found is root-owned
    mode 0700 BY DESIGN, and pathlib.rglob() silently SKIPS directories it
    can't read instead of raising — so an unprivileged run used to report
    a populated lost+found as "empty". We now scandir manually (errors are
    visible), fall back to sudo, and say "unreadable" when we truly can't
    look inside rather than pretending it's empty.
    """
    result: dict = {"checked": False, "path": None, "file_count": 0,
                    "total_bytes": 0, "readable": True, "notes": []}

    # lsblk snapshots go stale (drive mounted after the scan) — confirm live.
    mnt = dev.mountpoint if dev.is_mounted else _find_mountpoint(dev.path)
    if mnt in (None, "", "[SWAP]"):
        result["notes"].append("filesystem not mounted — mount it, then "
                               "re-run to inspect lost+found")
        return result
    if mnt != dev.mountpoint:
        dev.mountpoint = mnt
        result["notes"].append(f"live mountpoint detected: {mnt}")
    if dev.fstype and not dev.fstype.startswith(("ext", "xfs")):
        result["notes"].append(f"fstype {dev.fstype} does not use lost+found")

    lf = Path(mnt) / "lost+found"
    result["path"] = str(lf)

    # Presence check that survives odd permissions (exists() returns False
    # on PermissionError, which reads as "not detected").
    try:
        lf.lstat()
        present = True
    except FileNotFoundError:
        present = False
    except PermissionError:
        present = run(sudo_prefix() + ["test", "-e", str(lf)])[0] == 0
    if not present:
        result["notes"].append("no lost+found directory at the filesystem "
                               "root (it is recreated by fsck when needed)")
        return result
    result["checked"] = True

    # Manual walk: unlike rglob, PermissionError here is LOUD.
    count = total = 0
    denied = False
    stack: list[Path] = [lf]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    count += 1
                    try:
                        if e.is_file(follow_symlinks=False):
                            total += e.stat(follow_symlinks=False).st_size
                        elif e.is_dir(follow_symlinks=False):
                            stack.append(Path(e.path))
                    except OSError:
                        continue
        except PermissionError:
            denied = True
        except OSError as exc:
            result["notes"].append(f"read error in {d}: {exc}")

    if denied:
        rc, out, _ = run(sudo_prefix() + ["find", str(lf), "-mindepth", "1",
                                          "-printf", r"%s\t%y\n"])
        if rc == 0:
            count = total = 0
            for line in out.splitlines():
                try:
                    sz, typ = line.split("\t", 1)
                except ValueError:
                    continue
                count += 1
                if typ.strip() == "f" and sz.isdigit():
                    total += int(sz)
        else:
            result["readable"] = False
            result["notes"].append(
                "lost+found exists but is unreadable as this user (it is "
                "root-owned mode 700 by design) — re-run diskdoctor with "
                "sudo to see its contents")
    result["file_count"], result["total_bytes"] = count, total
    LOG.write(f"LOST+FOUND {lf}: {count} items, {total} bytes, "
              f"readable={result['readable']}")
    return result


_FILE_CATEGORIES = [
    ("image", re.compile(r"image|bitmap|JPEG|PNG|GIF", re.I)),
    ("video", re.compile(r"video|MP4|Matroska|AVI|MPEG", re.I)),
    ("audio", re.compile(r"audio|MP3|FLAC|WAVE", re.I)),
    ("document", re.compile(r"PDF|Word|Excel|OpenDocument|EPUB", re.I)),
    ("archive", re.compile(r"archive|compress|Zip|tar|7-?zip|RAR", re.I)),
    ("text", re.compile(r"text|JSON|XML|script", re.I)),
    ("binary", re.compile(r"ELF|executable|shared object", re.I)),
]


def lostfound_inspect(dev: Device) -> None:
    """Deep dive: categorize by `file` type, show the largest entries."""
    base = lostfound_check(dev)
    print(bold(f"\n  lost+found INSPECTOR — {base.get('path') or dev.path}"))
    if not base["checked"]:
        print(dim("    " + "; ".join(base["notes"])))
        return
    if not base.get("readable", True):
        print(yellow("    lost+found EXISTS but can't be read as this user "
                     "(root-owned mode 700 by design).\n    Re-run "
                     "diskdoctor with sudo to inspect it."))
        return
    if base["file_count"] == 0:
        print(green("    Empty — nothing was orphaned. ✓"))
        return
    print(yellow(f"    {base['file_count']} item(s), "
                 f"{human_size(base['total_bytes'])} total."))
    print(dim("    These files were rescued by a previous fsck. Names are "
              "gone (inode numbers\n    like #12345) but contents are intact."))

    # Enumerate entries (root-safe via sudo find)
    rc, out, _ = run(sudo_prefix() + ["find", str(base["path"]), "-mindepth",
                                      "1", "-maxdepth", "1", "-printf",
                                      r"%s\t%y\t%p\n"])
    entries: list[tuple[int, str, str]] = []
    for line in out.splitlines():
        try:
            sz, typ, path = line.split("\t", 2)
            entries.append((int(sz), typ, path))
        except ValueError:
            continue
    if not entries:
        print(dim("    (could not enumerate entries)"))
        return

    # Categorize a sample by content type
    cats: dict[str, int] = {}
    sample = [e for e in entries if e[1] == "f"][:150]
    if have("file") and sample:
        for _, _, path in sample:
            rc, desc, _ = run(sudo_prefix() + ["file", "-b", path], timeout=20)
            label = "other"
            for name, rx in _FILE_CATEGORIES:
                if rx.search(desc):
                    label = name
                    break
            cats[label] = cats.get(label, 0) + 1
        print(bold("\n    Type breakdown") + dim(f" (first {len(sample)} files):"))
        for name, n in sorted(cats.items(), key=lambda kv: -kv[1]):
            print(f"      {name:<10} {n}")

    print(bold("\n    Largest entries:"))
    for sz, typ, path in sorted(entries, reverse=True)[:10]:
        print(f"      {human_size(sz):>10}  {dim('[dir] ' if typ == 'd' else '')}"
              f"{path}")
    print(dim("\n    Salvage workflow: identify with 'sudo file <entry>', "
              "preview, move keepers\n    out, then delete the rest to "
              "reclaim space:  sudo rm -rI " + str(base["path"]) + "/*"))


# ==========================================================================
# 8. SPACE ANALYZER  (why is this drive 90-95% full?)
# ==========================================================================

def space_report(dev: Device) -> None:
    mnt = dev.mountpoint if dev.is_mounted else _find_mountpoint(dev.path)
    if not mnt or mnt == "[SWAP]":
        print(yellow("  Device is not mounted — mount it to analyze usage."))
        return
    dev.mountpoint = mnt
    print(bold(f"\n  SPACE ANALYZER — {mnt} "
               f"({dev.fsuse_pct}% full)" if dev.fsuse_pct is not None
               else f"\n  SPACE ANALYZER — {mnt}"))
    print(dim("    Scanning (large drives can take a few minutes)..."))

    rc, out, _ = run(sudo_prefix() + ["du", "-x", "--max-depth=2",
                                      "-B1", mnt], timeout=1800)
    if rc == 0 and out.strip():
        rows = []
        for line in out.splitlines():
            try:
                sz, path = line.split("\t", 1)
                rows.append((int(sz), path))
            except ValueError:
                continue
        rows.sort(reverse=True)
        print(bold("\n    Largest directories:"))
        for sz, path in rows[1:13]:                    # skip the mount itself
            print(f"      {human_size(sz):>10}  {path}")
    else:
        print(yellow("    du failed or produced nothing."))

    rc, out, _ = run(sudo_prefix() + ["find", mnt, "-xdev", "-type", "f",
                                      "-size", "+50M", "-printf",
                                      r"%s\t%p\n"], timeout=1800)
    if rc == 0 and out.strip():
        rows = []
        for line in out.splitlines():
            try:
                sz, path = line.split("\t", 1)
                rows.append((int(sz), path))
            except ValueError:
                continue
        rows.sort(reverse=True)
        print(bold("\n    Largest files (>50 MiB):"))
        for sz, path in rows[:12]:
            print(f"      {human_size(sz):>10}  {path}")
    print(dim("\n    Tip: ext4 needs breathing room — getting below "
              f"{CFG['warn_full_pct']}% avoids fragmentation\n    and "
              "write-failure edge cases. lost+found is often the quickest win."))


# ==========================================================================
# 9. LUKS TOOLS  (header read + header BACKUP — never restore, never
#    passphrases; these are the sanctioned raw-container operations)
# ==========================================================================

LUKS_DIR = BASE_DIR / "luks-headers"


def _ensure_cryptsetup() -> bool:
    if have("cryptsetup"):
        return True
    return offer_install("cryptsetup", "cryptsetup")


def luks_dump(dev: Device) -> dict:
    """cryptsetup luksDump — read-only header inspection."""
    result: dict = {"device": dev.path, "is_luks": False, "version": None,
                    "cipher": None, "keyslots": None, "notes": []}
    if not dev.is_luks_container:
        result["notes"].append("not a crypto_LUKS device")
        print(yellow(f"    {dev.path} is not a LUKS container."))
        return result
    if not _ensure_cryptsetup():
        result["notes"].append("cryptsetup unavailable")
        return result
    rc, out, err = run(sudo_prefix() + ["cryptsetup", "luksDump", dev.path])
    if rc != 0:
        result["notes"].append(f"luksDump failed: {err.strip()[:150]}")
        print(red(f"    ✗ Header unreadable: {err.strip()[:150]}"))
        print(yellow("      An unreadable LUKS header is CATASTROPHIC — if "
                     "you have a header backup,\n      that is now your "
                     "lifeline. Do not write anything to this device."))
        return result
    result["is_luks"] = True
    m = re.search(r"^Version:\s*(\d+)", out, re.M)
    result["version"] = int(m.group(1)) if m else None
    m = re.search(r"^\s*[Cc]ipher(?: name)?:\s*(\S+)", out, re.M)
    result["cipher"] = m.group(1) if m else None
    if result["version"] == 2:
        result["keyslots"] = len(re.findall(r"^\s{2}\d+:\s*luks2", out, re.M))
    else:
        result["keyslots"] = len(re.findall(r"Key Slot \d+: ENABLED", out))

    print(green(f"    ✓ LUKS{result['version']} header healthy — "
                f"cipher {result['cipher']}, "
                f"{result['keyslots']} active keyslot(s)."))
    if result["keyslots"] == 1:
        print(yellow("      Only ONE keyslot: a single forgotten passphrase "
                     "or damaged slot loses everything.\n      Consider "
                     "adding a second: sudo cryptsetup luksAddKey "
                     + dev.path))
    LOG.write(f"LUKSDUMP {dev.path}: v={result['version']} "
              f"slots={result['keyslots']}")
    return result


def luks_header_backup(dev: Device) -> None:
    """
    Write the LUKS header to a FILE. This is the most important insurance an
    encrypted drive can have: header corruption without a backup = permanent
    loss of all data, passphrase or not.
    """
    if not dev.is_luks_container:
        print(yellow(f"    {dev.path} is not a LUKS container."))
        return
    if not _ensure_cryptsetup():
        return
    LUKS_DIR.mkdir(parents=True, exist_ok=True)
    default = LUKS_DIR / f"{dev.uuid or dev.name}-{_dt.datetime.now():%Y%m%d-%H%M%S}.header"
    dest = ask(f"    Backup file [{default}]: ", str(default))
    dest_p = Path(dest).expanduser()
    if dest_p.exists():
        print(red("    Refusing to overwrite an existing file."))
        return
    dest_p.parent.mkdir(parents=True, exist_ok=True)
    rc, out, err = run(sudo_prefix() + ["cryptsetup", "luksHeaderBackup",
                                        dev.path, "--header-backup-file",
                                        str(dest_p)])
    if rc == 0:
        os.chmod(dest_p, 0o600)
        print(green(f"    ✓ Header backed up to {dest_p} (mode 600)."))
        print(yellow("    SECURITY: this file + your passphrase unlocks the "
                     "data — store it like a key,\n    ideally on an "
                     "encrypted medium AWAY from this drive. Also note: "
                     "after a\n    passphrase change, old header backups can "
                     "still unlock with the OLD passphrase."))
    else:
        print(red(f"    ✗ Backup failed: {(err or out).strip()[:200]}"))
    LOG.write(f"LUKSHEADERBACKUP {dev.path} -> {dest_p}: rc={rc}")


def luks_menu(dev: Device) -> None:
    container = dev if dev.is_luks_container else \
        (dev.parent if dev.parent and dev.parent.is_luks_container else None)
    if container is None:
        print(yellow("  Selected device has no LUKS layer."))
        return
    while True:
        print(bold(f"\n  LUKS TOOLS — {container.path}"))
        print("   1) Header info (version, cipher, keyslots)  " + dim("[read-only]"))
        print("   2) Back up LUKS header to a file  " + dim("[strongly recommended]"))
        print("   3) How to restore a header  " + dim("[instructions only]"))
        print("   b) Back")
        c = ask("  Choose: ").lower()
        if c == "1":
            luks_dump(container)
        elif c == "2":
            luks_header_backup(container)
        elif c == "3":
            print(dim("\n    Restoring OVERWRITES the on-disk header and all "
                      "keyslots — diskdoctor does not\n    automate it. "
                      "Manual command, only if the header is truly damaged:\n"
                      f"      sudo cryptsetup luksHeaderRestore {container.path}"
                      " --header-backup-file <backup>\n"
                      "    Verify the backup matches THIS device's UUID "
                      "first, and read the cryptsetup FAQ."))
        elif c == "b":
            return
        else:
            print(yellow("  Unknown option."))


# ==========================================================================
# 10. ext4 SUITE — superblock forensics, backups, e2image, fsck
# ==========================================================================

def superblock_info(dev: Device) -> dict:
    """dumpe2fs -h: the filesystem's own account of its health."""
    result: dict = {"device": dev.path, "available": False, "state": None,
                    "mount_count": None, "max_mount_count": None,
                    "last_checked": None, "error_count": None,
                    "first_error": None, "last_error": None,
                    "features": [], "notes": []}
    if (dev.fstype or "") not in ("ext2", "ext3", "ext4"):
        result["notes"].append(f"not an ext filesystem ({dev.fstype})")
        return result
    rc, out, err = run(sudo_prefix() + ["dumpe2fs", "-h", dev.path])
    if rc != 0:
        result["notes"].append(f"dumpe2fs failed: {err.strip()[:150]}")
        return result
    result["available"] = True

    def grab(label: str) -> str | None:
        m = re.search(rf"^{re.escape(label)}:\s*(.+)$", out, re.M)
        return m.group(1).strip() if m else None

    result["state"] = grab("Filesystem state")
    result["mount_count"] = grab("Mount count")
    result["max_mount_count"] = grab("Maximum mount count")
    result["last_checked"] = grab("Last checked")
    result["error_count"] = grab("FS Error count")
    result["first_error"] = grab("First error time")
    result["last_error"] = grab("Last error time")
    feats = grab("Filesystem features") or ""
    result["features"] = feats.split()
    LOG.write(f"SUPERBLOCK {dev.path}: state={result['state']} "
              f"errors={result['error_count']}")
    return result


def print_superblock(sb: dict) -> None:
    print(bold("\n  SUPERBLOCK / ext4 METADATA"))
    if not sb.get("available"):
        print(dim("    " + "; ".join(sb.get("notes", ["unavailable"]))))
        return
    state = sb["state"] or "?"
    scol = green if state == "clean" else red
    print(f"    Filesystem state:      {scol(state)}"
          + ("" if state == "clean" else
             red("  ← the fs has recorded errors")))
    if sb["error_count"] and sb["error_count"] not in ("0",):
        print(red(f"    Recorded error count:  {sb['error_count']}"))
        if sb["first_error"]:
            print(dim(f"      first error: {sb['first_error']}"))
        if sb["last_error"]:
            print(dim(f"      last  error: {sb['last_error']}"))
    print(f"    Mount count:           {sb['mount_count']} "
          f"(fsck-after limit: {sb['max_mount_count']})")
    print(f"    Last full check:       {sb['last_checked']}")
    j = "has_journal" in sb["features"]
    csum = "metadata_csum" in sb["features"]
    print(f"    Journal:               {green('present') if j else red('MISSING')}"
          f"    Metadata checksums: {green('yes') if csum else dim('no')}")


def backup_superblocks(dev: Device) -> list[int]:
    """Locate backup superblocks (streamed grep — cheap even on 2 TB)."""
    rc, out, _ = run_shell(
        f"dumpe2fs {dev.path} 2>/dev/null | grep -m 12 -oE "
        f"'[Bb]ackup superblock at [0-9]+'")
    blocks = [int(m) for m in re.findall(r"(\d+)", out)]
    if blocks:
        print(green(f"    Backup superblocks at: {', '.join(map(str, blocks[:8]))}"))
        print(dim("    Used for recovery as:  e2fsck -b <block> " + dev.path))
    else:
        print(yellow("    Could not enumerate backup superblocks "
                     "(typical 4k-blocksize locations: 32768, 98304, 163840)."))
    return blocks


def e2image_backup(dev: Device, auto_prompt: bool = True) -> Path | None:
    """
    e2image = metadata-only image (superblocks, bitmaps, inode tables — no
    file data). Small, fast, read-only, and lets e2fsck/experts reconstruct
    the fs if a repair goes wrong. Cheap insurance before any --fix.
    """
    if (dev.fstype or "") not in ("ext2", "ext3", "ext4"):
        return None
    if not have("e2image") and not offer_install("e2fsprogs", "e2image"):
        return None
    out_dir = BASE_DIR / "e2image"
    out_dir.mkdir(parents=True, exist_ok=True)
    default = out_dir / f"{dev.name}-{_dt.datetime.now():%Y%m%d-%H%M%S}.e2i"
    if auto_prompt:
        dest = ask(f"    Metadata image path [{default}]: ", str(default))
    else:
        dest = str(default)
    dest_p = Path(dest).expanduser()
    print(dim(f"    Writing metadata image (read-only on {dev.path})..."))
    rc, out, err = run(sudo_prefix() + ["e2image", dev.path, str(dest_p)],
                       timeout=3600)
    if rc == 0:
        try:
            sz = human_size(dest_p.stat().st_size)
        except OSError:
            sz = "?"
        print(green(f"    ✓ Metadata image saved: {dest_p} ({sz})."))
        LOG.write(f"E2IMAGE {dev.path} -> {dest_p}: ok")
        return dest_p
    print(red(f"    ✗ e2image failed: {(err or out).strip()[:200]}"))
    LOG.write(f"E2IMAGE {dev.path}: rc={rc}")
    return None


def ext4_menu(dev: Device) -> None:
    target, notes = resolve_target(dev)
    for n in notes:
        print(yellow("  note: " + n))
    if target.is_luks_container:
        return
    while True:
        print(bold(f"\n  ext4 TOOLS — {target.path}"))
        print("   1) Superblock health (state, error history, mount counts)  "
              + dim("[read-only]"))
        print("   2) Locate backup superblocks  " + dim("[read-only]"))
        print("   3) e2image metadata backup  " + dim("[reads fs, writes a file]"))
        print("   4) Journal & feature info  " + dim("[read-only]"))
        print("   b) Back")
        c = ask("  Choose: ").lower()
        if c == "1":
            print_superblock(superblock_info(target))
        elif c == "2":
            backup_superblocks(target)
        elif c == "3":
            e2image_backup(target)
        elif c == "4":
            sb = superblock_info(target)
            if sb.get("available"):
                feats = sb["features"]
                print(dim("    features: " + " ".join(feats)))
                print(("    " + green("✓ journaling active — power-loss "
                                      "resilient"))
                      if "has_journal" in feats else
                      ("    " + red("✗ NO JOURNAL — this fs is fragile; "
                                    "consider: tune2fs -O has_journal (unmounted)")))
        elif c == "b":
            return
        else:
            print(yellow("  Unknown option."))


# ==========================================================================
# 11. FILESYSTEM CHECK — dry-run + guarded repair (+ alt-superblock path)
# ==========================================================================

# All the ways e2fsck signals primary-superblock trouble: hard abort
# ("bad magic number"), or transparent recovery via a backup superblock
# ("Superblock invalid, trying backup blocks...").
_SB_DAMAGE_RE = re.compile(
    r"bad magic number in super-?block|"
    r"couldn't find valid filesystem superblock|"
    r"superblock invalid.{0,40}(trying|backup)|"
    r"trying backup blocks|"
    r"filesystem superblock is corrupt|"
    r"using (?:the )?backup superblock", re.I)


def fsck_dry_run(dev: Device) -> dict:
    """e2fsck -fn: forced, fully read-only. Safe always."""
    result: dict = {"device": dev.path, "mode": "dry-run", "clean": None,
                    "would_fix": [], "exit_code": None,
                    "superblock_damage": False, "notes": []}
    if (dev.fstype or "") not in ("ext2", "ext3", "ext4"):
        result["notes"].append(f"fstype '{dev.fstype}' — only ext2/3/4 supported")
        return result
    if dev.is_luks_container:
        result["notes"].append("refusing to fsck a raw LUKS container")
        return result
    live_mnt = _find_mountpoint(dev.path)
    if live_mnt and not dev.is_mounted:
        dev.mountpoint = live_mnt            # lsblk snapshot was stale
    if dev.is_mounted:
        result["notes"].append("filesystem is MOUNTED: dry-run may report "
                               "spurious errors from in-flight writes; "
                               "unmount for an authoritative result")
    print(dim(f"  Running e2fsck -fn {dev.path} (read-only)..."))
    rc, out, err = run(sudo_prefix() + ["e2fsck", "-fn", dev.path],
                       timeout=6 * 3600)
    result["exit_code"] = rc
    text = (out + "\n" + err).strip()
    if rc == 0:
        result["clean"] = True
    elif rc & 8:
        result["clean"] = None
        result["notes"].append(f"e2fsck operational error: {err.strip()[:200]}")
    else:
        result["clean"] = False
    # Superblock damage can surface two ways: e2fsck aborts (rc&8, "bad
    # magic"), or it silently FALLS BACK to a backup superblock and keeps
    # going ("Superblock invalid, trying backup blocks..."). Catch both by
    # inspecting the text regardless of exit code.
    if _SB_DAMAGE_RE.search(text):
        result["superblock_damage"] = True
        result["notes"].append(
            "PRIMARY SUPERBLOCK damaged/invalid — e2fsck had to use a backup "
            "superblock. Repair (menu 11) rewrites the primary; backups are "
            "listed under ext4 tools → option 2")
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("Pass ") or re.search(r"files \(\d", s) \
                or s.startswith(("e2fsck 1.", "Overwriting")):
            continue  # progress headers / version banner / summary — not findings
        if s.endswith("? no") or "Fix? no" in s:
            result["would_fix"].append(s)
        elif re.search(r"(inode|block|bitmap|count|orphan|unattached|corrupt|"
                       r"invalid|bad )", s, re.I) and "clean" not in s.lower():
            result["would_fix"].append(s)
    result["would_fix"] = result["would_fix"][:40]
    LOG.write(f"FSCK-DRY {dev.path}: clean={result['clean']} rc={rc} "
              f"{len(result['would_fix'])} findings")
    return result


def _fs_busy(dev: Device) -> list[str]:
    holders: list[str] = []
    if not dev.mountpoint:
        return holders
    if have("fuser"):
        rc, out, err = run(sudo_prefix() + ["fuser", "-vm", dev.mountpoint])
        blob = (out + err).strip()
        if rc == 0 and blob:
            holders = [l for l in blob.splitlines() if l.strip()][:15]
    elif have("lsof"):
        rc, out, _ = run(sudo_prefix() + ["lsof", "+f", "--", dev.mountpoint])
        if rc == 0 and out.strip():
            holders = out.splitlines()[:15]
    return holders


def maybe_offer_ddrescue(dev: Device, smart: dict) -> None:
    """Backup safety net before repair when SMART shows physical damage."""
    realloc = smart.get("reallocated_sectors") or 0
    pending = smart.get("pending_sectors") or 0
    if realloc == 0 and pending == 0 and smart.get("verdict") != "failing":
        return
    parent = dev.physical_parent()
    print()
    print(red(f"  ⚠ SMART shows physical damage (reallocated={realloc}, "
              f"pending={pending})."))
    print(yellow("  Repairing a filesystem on a dying drive can destroy "
                 "data.\n  Strongly recommended: full ddrescue image FIRST."))
    if not have("ddrescue") and not offer_install("gddrescue", "ddrescue"):
        print(yellow("  Continuing WITHOUT a rescue image (ddrescue "
                     "unavailable)."))
        return
    if not confirm(f"  Run ddrescue to image {parent.path} to a file now?"):
        LOG.write(f"DDRESCUE offered for {parent.path}: declined")
        return
    dest = ask("  Destination image path (on a DIFFERENT disk with enough "
               "space): ")
    if not dest:
        print(yellow("  No destination given — skipping image."))
        return
    dest_p = Path(dest).expanduser()
    dest_p.parent.mkdir(parents=True, exist_ok=True)
    mapfile = str(dest_p) + ".mapfile"
    if not confirm(f"  Confirm read-image {parent.path} → {dest_p}?",
                   danger=True):
        return
    rc, out, err = run(sudo_prefix() + ["ddrescue", "-d", parent.path,
                                        str(dest_p), mapfile],
                       timeout=48 * 3600)
    print(green(f"  ✓ Rescue image at {dest_p}") if rc == 0 else
          red(f"  ✗ ddrescue rc={rc}: {err.strip()[:200]}"))
    LOG.write(f"DDRESCUE {parent.path} -> {dest_p}: rc={rc}")


def fsck_repair(dev: Device, smart: dict) -> dict:
    """
    THE ONLY DISK-WRITE PATH IN THIS TOOL.
    Gates: ext-only → not raw LUKS → ddrescue offer → e2image offer →
    y/N confirm → busy check → unmount (abort if it fails) →
    e2fsck -fp (→ -fy with confirm) → alt-superblock path if the primary is
    dead (extra confirm) → remount.
    """
    result: dict = {"device": dev.path, "mode": "repair", "performed": False,
                    "exit_code": None, "remounted": None, "notes": []}
    if (dev.fstype or "") not in ("ext2", "ext3", "ext4"):
        msg = f"repair only supports ext2/3/4 (found {dev.fstype})"
        result["notes"].append(msg)
        print(red("  " + msg))
        return result
    if dev.is_luks_container:
        result["notes"].append("refusing to repair a raw LUKS container")
        print(red("  " + result["notes"][-1]))
        return result
    if not is_root():
        print(dim("  (repair requires root; commands run via sudo)"))

    # Refresh mount state LIVE — the lsblk snapshot may predate a mount or
    # umount. Wrong in either direction is dangerous here: stale "unmounted"
    # would write-fsck a mounted fs; stale "mounted" aborts on umount failure.
    dev.mountpoint = _find_mountpoint(dev.path)

    print()
    print(bold(red("  ═══ REPAIR MODE — this WILL write to the filesystem ═══")))
    print(f"  Target: {bold(dev.path)}"
          + (f" mounted at {dev.mountpoint}" if dev.is_mounted
             else " (not mounted)"))

    maybe_offer_ddrescue(dev, smart)

    if confirm("  Save an e2image METADATA backup first? (small file, "
               "cheap insurance)"):
        e2image_backup(dev, auto_prompt=False)

    if not confirm(f"  Proceed with REAL fsck repair on {dev.path}?",
                   danger=True):
        result["notes"].append("user declined final confirmation")
        print(yellow("  Repair cancelled."))
        return result

    was_mounted_at = dev.mountpoint if dev.is_mounted else None
    if was_mounted_at:
        holders = _fs_busy(dev)
        if holders:
            print(yellow(f"  Filesystem busy — processes using "
                         f"{was_mounted_at}:"))
            for h in holders:
                print(dim("    " + h))
            if not confirm("  Have you closed those programs — try "
                           "unmounting anyway?", danger=True):
                result["notes"].append("aborted: filesystem busy")
                return result
        print(dim(f"  Unmounting {was_mounted_at}..."))
        rc, out, err = run(sudo_prefix() + ["umount", dev.path])
        if rc != 0:
            result["notes"].append(f"umount failed: {err.strip()}")
            print(red(f"  ✗ Could not unmount ({err.strip()}). Aborting — "
                      "will not write-fsck a mounted filesystem."))
            return result
        print(green("  ✓ Unmounted."))

    print(dim(f"  Running e2fsck -fp {dev.path} ..."))
    rc, out, err = run(sudo_prefix() + ["e2fsck", "-fp", dev.path],
                       timeout=12 * 3600)
    text = out + err

    # Escalation 1: preen couldn't fix everything → -fy with consent
    if rc & 4:
        print(yellow("  Preen mode could not fix everything."))
        if confirm("  Re-run with e2fsck -fy (answer YES to all fixes)?",
                   danger=True):
            print(dim(f"  Running e2fsck -fy {dev.path} ..."))
            rc, out, err = run(sudo_prefix() + ["e2fsck", "-fy", dev.path],
                               timeout=12 * 3600)
            text = out + err

    # Escalation 2: superblock trouble AND the fs still isn't fixed
    # (rc&8 = couldn't operate, rc&4 = errors left uncorrected). If e2fsck
    # auto-recovered via a backup superblock and exited 0/1, the primary
    # was already rewritten — no need for an explicit -b pass.
    if (rc & 8 or rc & 4) and _SB_DAMAGE_RE.search(text):
        print(red("  Primary superblock appears damaged."))
        # Candidate sources, best first:
        #  1. dumpe2fs enumeration (works only if the primary is readable —
        #     often it isn't at this point),
        #  2. block numbers e2fsck itself suggested in its failure text
        #     ("you might try ... e2fsck -b 8193 <device>"),
        #  3. standard first-backup locations (32768 for 4k fs, 8193 for 1k).
        candidates = backup_superblocks(dev)
        candidates += [int(b) for b in re.findall(r"-b\s+(\d+)", text)]
        candidates += [32768, 8193]
        ordered: list[int] = []
        for b in candidates:
            if b not in ordered:
                ordered.append(b)
        if ordered and confirm(f"  Attempt repair from a backup superblock? "
                               f"(candidates: {ordered[:4]}; writes to disk)",
                               danger=True):
            for b in ordered[:6]:
                print(dim(f"  Running e2fsck -b {b} -fy {dev.path} ..."))
                rc, out, err = run(sudo_prefix() + ["e2fsck", "-b", str(b),
                                                    "-fy", dev.path],
                                   timeout=12 * 3600)
                text = out + err
                if not (rc & 8):          # this backup superblock worked
                    break
                print(dim(f"    backup {b} unusable (rc={rc}) — trying next"))

    result["performed"] = True
    result["exit_code"] = rc
    print(dim("  --- e2fsck output (tail) ---"))
    for line in text.strip().splitlines()[-12:]:
        print(dim("  " + line))
    if rc in (0, 1):
        print(green(f"  ✓ fsck finished (rc={rc}"
                    f"{', errors were corrected' if rc == 1 else ', clean'})."))
    elif rc & 2:
        print(yellow("  ⚠ fsck says a REBOOT is required."))
    else:
        print(red(f"  ✗ fsck exited rc={rc} — filesystem may still have "
                  "problems."))

    if was_mounted_at:
        print(dim(f"  Remounting {dev.path} → {was_mounted_at} ..."))
        rc2, _, err2 = run(sudo_prefix() + ["mount", dev.path, was_mounted_at])
        result["remounted"] = rc2 == 0
        print(green("  ✓ Remounted.") if rc2 == 0 else
              yellow(f"  ⚠ Remount failed ({err2.strip()}). Manually: "
                     f"sudo mount {dev.path} {was_mounted_at}"))
    LOG.write(f"REPAIR {dev.path}: rc={result['exit_code']} "
              f"remounted={result['remounted']}")
    return result


# ==========================================================================
# 12. SCORING + RECOMMENDATION ENGINE
# ==========================================================================

@dataclass
class ReportCtx:
    """Everything a report needs, in one bag."""
    dev: Device
    smart: dict
    dmesg: dict
    lf: dict
    fsck: dict
    notes: list[str] = field(default_factory=list)
    usb: dict | None = None
    speed: dict | None = None
    sb: dict | None = None
    surface: dict | None = None
    trend: dict | None = None


def health_score(ctx: ReportCtx) -> tuple[int, list[str]]:
    """Heuristic 0–100 score with itemized reasons. Not a prophecy —
    a triage aid that weights the strongest failure predictors."""
    score = 100
    reasons: list[str] = []

    def hit(points: int, why: str) -> None:
        nonlocal score
        score -= points
        reasons.append(f"-{points}  {why}")

    s = ctx.smart
    if s.get("available"):
        if s.get("overall_health") not in (None, "PASSED", "OK"):
            hit(60, f"SMART overall health = {s['overall_health']}")
        if (s.get("uncorrectable_errors") or 0) > 0:
            hit(40, f"{s['uncorrectable_errors']} uncorrectable error(s)")
        realloc = s.get("reallocated_sectors") or 0
        if realloc:
            hit(min(30, 10 + realloc // 5), f"{realloc} reallocated sector(s)")
        pending = s.get("pending_sectors") or 0
        if pending:
            hit(min(30, 10 + pending // 5), f"{pending} pending sector(s)")
        t = s.get("temperature_c")
        if t and t >= CFG["temp_crit_c"]:
            hit(10, f"temperature {t}°C (critical)")
        elif t and t >= CFG["temp_warn_c"]:
            hit(5, f"temperature {t}°C (warm)")
    else:
        reasons.append("±0  SMART unavailable (score is less reliable)")

    if ctx.trend and ctx.trend.get("warnings"):
        hit(15, "defect counters GROWING between snapshots")
    if ctx.dmesg.get("matches"):
        hit(10, f"{len(ctx.dmesg['matches'])} kernel I/O error line(s)")
    if ctx.usb and ctx.usb.get("resets", 0) > 0:
        hit(8, f"{ctx.usb['resets']} USB reset/disconnect event(s) "
               "(suspect cable/enclosure)")
    if ctx.speed and ctx.speed.get("slow_regions"):
        hit(12, f"{ctx.speed['slow_regions']} slow/erroring read region(s)")
    if ctx.surface and ctx.surface.get("bad_blocks"):
        hit(35, f"{len(ctx.surface['bad_blocks'])} unreadable block(s) on "
                "surface scan")
    if ctx.fsck.get("clean") is False:
        hit(15, f"filesystem dirty ({len(ctx.fsck['would_fix'])} fixable "
                "finding(s))")
    if ctx.sb and ctx.sb.get("available") and ctx.sb.get("state") != "clean":
        hit(8, f"superblock records state '{ctx.sb.get('state')}'")
    pct = ctx.dev.fsuse_pct or 0
    if pct >= CFG["crit_full_pct"]:
        hit(8, f"volume {pct}% full (critical)")
    elif pct >= CFG["warn_full_pct"]:
        hit(4, f"volume {pct}% full")
    if ctx.lf.get("file_count"):
        hit(3, f"lost+found holds {ctx.lf['file_count']} recovered item(s)")

    return max(0, min(100, score)), reasons


def _grade(score: int) -> tuple[str, "function"]:
    if score >= 90: return "A", green
    if score >= 75: return "B", green
    if score >= 60: return "C", yellow
    if score >= 40: return "D", yellow
    return "F", red


def _recommendation(ctx: ReportCtx) -> tuple[str, str]:
    s, fsck, lf, dm = ctx.smart, ctx.fsck, ctx.lf, ctx.dmesg
    verdict = s.get("verdict")
    fs_dirty = fsck.get("clean") is False
    kernel_errs = len(dm.get("matches", [])) > 0
    usb_resets = (ctx.usb or {}).get("resets", 0)
    slow = (ctx.speed or {}).get("slow_regions", 0)
    surf_bad = len((ctx.surface or {}).get("bad_blocks", []))
    trend_bad = bool((ctx.trend or {}).get("warnings"))
    lf_items = lf.get("file_count", 0)
    nearly_full = (ctx.dev.fsuse_pct or 0) >= CFG["warn_full_pct"]

    if verdict == "failing" or surf_bad:
        return ("critical",
                "The PHYSICAL DRIVE is failing (SMART/surface scan shows "
                "unreadable or reallocated media). Do NOT run repairs. Back "
                "up immediately — ideally a full ddrescue image to a healthy "
                "disk — then replace the drive. Filesystem repair on failing "
                "hardware makes data loss worse.")
    if trend_bad:
        return ("high",
                "Defect counters are GROWING between health snapshots — the "
                "drive is actively deteriorating even if today's absolute "
                "numbers look small. Refresh backups now, take a ddrescue "
                "image, and plan replacement. Repair only after imaging.")
    if verdict == "degraded" and fs_dirty:
        return ("high",
                "Early physical wear (reallocated/pending sectors) AND "
                "filesystem errors. Take a ddrescue image first, verify "
                "backups, then repair — keeping the image as your fallback.")
    if verdict == "degraded":
        return ("medium",
                "Filesystem is clean but the drive shows early physical "
                "wear. Refresh backups, watch the trend view weekly for "
                "counter growth, and budget for a replacement.")
    if fs_dirty and (usb_resets or (kernel_errs and slow == 0
                                    and verdict == "healthy")):
        return ("high",
                "Filesystem errors plus USB resets/kernel I/O errors while "
                "SMART is healthy — the classic signature of a bad CABLE, "
                "PORT or ENCLOSURE rather than the disk. Swap the cable/port "
                "(avoid hubs), back up, then repair. If errors continue on a "
                "known-good cable, suspect the enclosure's USB-SATA bridge.")
    if fs_dirty:
        return ("medium",
                "Filesystem-only corruption: SMART is healthy and the "
                "hardware signals are quiet, so this looks like software-"
                "level damage (unclean unmount, power loss). Safe to repair "
                "via the Repair option after backing up anything "
                "irreplaceable.")
    if slow:
        return ("medium",
                "SMART and fsck look fine, but read-speed sampling found "
                "regions dramatically slower than the rest of the disk — "
                "often sectors being retried before they officially fail. "
                "Back up, then run a SMART long self-test and a full surface "
                "scan to confirm.")
    if lf_items and nearly_full:
        return ("medium",
                "Checks are clean now, but lost+found contains recovered "
                "files from a previous fsck and the volume is over "
                f"{CFG['warn_full_pct']}% full. Review/salvage lost+found, "
                "delete the rest, and free space — ext4 resilience and "
                "performance degrade badly when nearly full.")
    if lf_items:
        return ("low",
                "Healthy drive and clean filesystem, but lost+found holds "
                "files from a past recovery. Review them, salvage anything "
                "useful, then clear the directory.")
    if nearly_full:
        return ("low",
                f"Everything is healthy, but the volume is over "
                f"{CFG['warn_full_pct']}% full. Free space to avoid "
                "fragmentation and write failures.")
    return ("ok", "Drive and filesystem are healthy. No action needed.")


_SEV_COLOR = {"critical": red, "high": red, "medium": yellow,
              "low": yellow, "ok": green}


# ==========================================================================
# 13. REPORT RENDERING + EXPORT
# ==========================================================================

LAST: dict = {"ctx": None, "report": None}


def print_report(ctx: ReportCtx) -> dict:
    dev, smart, dmesg, lf, fsck = ctx.dev, ctx.smart, ctx.dmesg, ctx.lf, ctx.fsck
    parent = dev.physical_parent()
    sev, rec = _recommendation(ctx)
    score, reasons = health_score(ctx)
    grade, gcol = _grade(score)

    print()
    print(bold(cyan("═" * 64)))
    print(bold(cyan(f"  DISKDOCTOR REPORT — {dev.path}")))
    if parent.model or parent.serial:
        print(dim(f"  {parent.model or ''}  "
                  f"{'S/N ' + parent.serial if parent.serial else ''}"))
    print(bold(cyan("═" * 64)))
    for n in ctx.notes:
        print(yellow(f"  note: {n}"))

    # HEALTH SCORE gauge
    barlen = score // 5
    print(bold("\n  HEALTH SCORE"))
    print(f"    {gcol('█' * barlen + '░' * (20 - barlen))}  "
          f"{gcol(f'{score}/100  (grade {grade})')}")
    for r in reasons[:8]:
        print(dim("      " + r))

    # DEVICE HEALTH
    print(bold(f"\n  DEVICE HEALTH (SMART) — physical disk {parent.path}"))
    if smart.get("available"):
        h = smart.get("overall_health") or "?"
        hcol = green if h in ("PASSED", "OK") else red
        print(f"    Overall health:        {hcol(h)}")
        for label, key in (("Reallocated sectors", "reallocated_sectors"),
                           ("Pending sectors", "pending_sectors"),
                           ("Uncorrectable errors", "uncorrectable_errors"),
                           ("Power-on hours", "power_on_hours")):
            v = smart.get(key)
            if v is None:
                print(f"    {label + ':':<23}{dim('n/a')}")
            else:
                col = green if (v == 0 or key == "power_on_hours") else \
                    (red if key == "uncorrectable_errors" or v >= 50 else yellow)
                print(f"    {label + ':':<23}{col(str(v))}")
        t = smart.get("temperature_c")
        if t is not None:
            tcol = red if t >= CFG["temp_crit_c"] else \
                yellow if t >= CFG["temp_warn_c"] else green
            print(f"    Temperature:           {tcol(str(t) + '°C')}")
        vcol = {"healthy": green, "degraded": yellow,
                "failing": red}.get(smart["verdict"], dim)
        print(f"    Verdict:               {vcol(smart['verdict'].upper())}")
    else:
        print(yellow("    SMART data unavailable "
                     f"({'; '.join(smart.get('notes', [])) or 'unknown'})"))

    # TREND
    if ctx.trend and ctx.trend.get("snapshots", 0) >= 2:
        print(bold("\n  HEALTH TREND"))
        if ctx.trend["warnings"]:
            for w in ctx.trend["warnings"][:4]:
                print(red("    ⚠ " + w))
        else:
            print(green("    ✓ No counter growth since previous snapshots "
                        f"({ctx.trend['snapshots']} on file)."))

    # KERNEL LOG + USB
    print(bold("\n  KERNEL LOG (dmesg)"))
    if dmesg.get("available"):
        n = len(dmesg["matches"])
        if n == 0:
            print(green("    No recent I/O / ATA / ext4 errors for this "
                        "device."))
        else:
            print(red(f"    {n} recent error line(s):"))
            for line in dmesg["matches"][-6:]:
                print(dim("      " + line[:110]))
    else:
        print(yellow("    " + "; ".join(dmesg.get("notes", ["unavailable"]))))

    if ctx.usb is not None:
        print(bold("\n  CONNECTION LAYER"))
        tr = ctx.usb.get("transport") or "?"
        print(f"    Transport:             {tr.upper() if tr else '?'}"
              + (dim(f"   driver: {ctx.usb.get('driver')}")
                 if ctx.usb.get("driver") else ""))
        r = ctx.usb.get("resets", 0)
        if tr == "usb":
            if r:
                print(red(f"    USB resets/disconnects: {r} recent event(s)"))
                print(yellow("      Flaky USB links corrupt filesystems while "
                             "the disk itself is fine.\n      Try: different "
                             "cable, different port (no hub), powered "
                             "enclosure."))
            else:
                print(green("    USB link stable — no resets logged."))

    # SPEED
    if ctx.speed is not None and ctx.speed.get("median_mbps") is not None:
        print(bold("\n  READ-SPEED SAMPLING"))
        vals = [s["mbps"] for s in ctx.speed["samples"] if s.get("mbps")]
        if vals:
            print(f"    median {ctx.speed['median_mbps']} MB/s   "
                  f"min {min(vals):.1f}   max {max(vals):.1f}   "
                  f"({len(vals)} samples)")
        else:
            print(f"    median {ctx.speed['median_mbps']} MB/s")
        if ctx.speed["slow_regions"]:
            print(red(f"    ⚠ {ctx.speed['slow_regions']} slow/erroring "
                      "region(s) — possible pending-sector retries."))
        else:
            print(green("    ✓ Uniform across the disk."))

    # SUPERBLOCK
    if ctx.sb is not None:
        print_superblock(ctx.sb)

    # FILESYSTEM HEALTH
    print(bold("\n  FILESYSTEM HEALTH (fsck dry-run)"))
    if fsck.get("clean") is True:
        print(green("    Clean — e2fsck found nothing to fix."))
    elif fsck.get("clean") is False:
        print(red(f"    NOT clean — e2fsck would make "
                  f"{len(fsck['would_fix'])} change(s), e.g.:"))
        for line in fsck["would_fix"][:8]:
            print(dim("      " + line[:110]))
    else:
        print(yellow("    Not checked ("
                     + "; ".join(fsck.get("notes", ["skipped"])) + ")"))
    if fsck.get("clean") is not None:
        for n in fsck.get("notes", []):
            print(yellow("    note: " + n))

    # SURFACE
    if ctx.surface and ctx.surface.get("completed"):
        print(bold("\n  SURFACE SCAN (read-only badblocks)"))
        bb = ctx.surface["bad_blocks"]
        print(red(f"    {len(bb)} unreadable block(s): {bb[:8]}") if bb
              else green(f"    Clean ({ctx.surface['mode']} scan)."))

    # RECOVERY ARTIFACTS
    print(bold("\n  RECOVERY ARTIFACTS (lost+found)"))
    if lf.get("checked") and not lf.get("readable", True):
        print(yellow(f"    lost+found EXISTS at {lf['path']} but is "
                     "unreadable without root —\n    re-run diskdoctor with "
                     "sudo to see what's inside."))
    elif lf.get("checked") and lf.get("file_count", 0) > 0:
        print(yellow(f"    {lf['file_count']} item(s), "
                     f"{human_size(lf['total_bytes'])} in {lf['path']}"))
        print(dim("      Menu 8 inspects & categorizes these."))
    elif lf.get("checked"):
        print(green(f"    lost+found is empty ({lf['path']})."))
    else:
        print(dim("    " + "; ".join(lf.get("notes", ["not checked"]))))
    if lf.get("checked"):
        for n in lf.get("notes", []):
            print(dim("    note: " + n))

    # CAPACITY
    if dev.fsuse_pct is not None:
        pct = dev.fsuse_pct
        col = red if pct >= CFG["crit_full_pct"] else \
            yellow if pct >= CFG["warn_full_pct"] else green
        bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
        print(bold("\n  CAPACITY"))
        print(f"    {col(bar)}  {col(str(pct) + '% used')}"
              + (yellow(f"  ⚠ over {CFG['warn_full_pct']}% — free space soon")
                 if pct >= CFG["warn_full_pct"] else ""))

    # RECOMMENDATION
    print(bold("\n  RECOMMENDATION"))
    print(_SEV_COLOR[sev](f"    [{sev.upper()}] ") + rec)
    print(bold(cyan("═" * 64)) + "\n")

    report = {
        "timestamp": _dt.datetime.now().isoformat(timespec="seconds"),
        "device": dev.path, "physical_disk": parent.path,
        "model": parent.model, "serial": parent.serial,
        "fstype": dev.fstype, "mountpoint": dev.mountpoint,
        "fsuse_pct": dev.fsuse_pct,
        "luks": dev.is_unlocked_luks or dev.is_luks_container,
        "health_score": score, "grade": grade, "score_reasons": reasons,
        "smart": smart, "trend": ctx.trend,
        "dmesg_errors": dmesg.get("matches", []),
        "usb": ctx.usb, "speed": ctx.speed, "superblock": ctx.sb,
        "surface": ctx.surface, "lost_found": lf, "fsck": fsck,
        "severity": sev, "recommendation": rec,
    }
    LAST["ctx"], LAST["report"] = ctx, report
    LOG.write(f"REPORT {dev.path}: score={score} severity={sev}")
    return report


def export_report(fmt: str) -> None:
    if not LAST["report"]:
        print(yellow("  Run a diagnosis first (menu 2 or 3)."))
        return
    out_dir = BASE_DIR / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    if fmt == "json":
        p = out_dir / f"report-{stamp}.json"
        p.write_text(json.dumps(LAST["report"], indent=2))
        print(green(f"  ✓ JSON report: {p}"))
    else:
        global _USE_COLOR
        buf = io.StringIO()
        saved = _USE_COLOR
        _USE_COLOR = False
        try:
            with contextlib.redirect_stdout(buf):
                print_report(LAST["ctx"])
        finally:
            _USE_COLOR = saved
        p = out_dir / f"report-{stamp}.txt"
        p.write_text(strip_ansi(buf.getvalue()))
        print(green(f"  ✓ Text report: {p}"))


# ==========================================================================
# 14. INVENTORY + DIAGNOSIS PIPELINES
# ==========================================================================

def print_inventory(disks: list[Device]) -> list[dict]:
    rows: list[dict] = []
    print()
    print(bold(cyan("  # ") + cyan(f"{'DEVICE':<26}{'TYPE':<7}{'TRAN':<8}"
                                   f"{'FS':<13}{'SIZE':<9}{'USE%':<7}"
                                   f"{'MOUNTPOINT'}")))
    print(dim("  " + "─" * 88))
    idx = 0
    for disk in disks:
        for dev in disk.flat():
            idx += 1
            if dev.is_luks_container:
                unlocked = any(c.is_unlocked_luks for c in dev.children)
                plain = f"{'LUKS open' if unlocked else 'LUKS locked':<13}"
                fs = green(plain) if unlocked else red(plain)
            else:
                fs = f"{(dev.fstype or '-'):<13}"
            use = f"{dev.fsuse_pct}%" if dev.fsuse_pct is not None else "-"
            use = f"{use:<7}"                    # pad BEFORE coloring (ANSI
            usec = (red(use) if (dev.fsuse_pct or 0) >= CFG["crit_full_pct"]  # codes break width specs)
                    else yellow(use) if (dev.fsuse_pct or 0)
                    >= CFG["warn_full_pct"] else use)
            warn = yellow(f" ⚠ >{CFG['warn_full_pct']}% full") \
                if (dev.fsuse_pct or 0) >= CFG["warn_full_pct"] else ""
            print(f"  {idx:<2}{dev.path:<26}{dev.dtype:<7}"
                  f"{(dev.tran or '-'):<8}{fs}{(dev.size or '-'):<9}"
                  f"{usec}{dev.mountpoint or '-'}{warn}")
            rows.append({"index": idx, "path": dev.path, "type": dev.dtype,
                         "tran": dev.tran, "fstype": dev.fstype,
                         "size": dev.size, "fsuse_pct": dev.fsuse_pct,
                         "mountpoint": dev.mountpoint,
                         "model": dev.model, "serial": dev.serial,
                         "luks_container": dev.is_luks_container,
                         "luks_mapped": dev.is_unlocked_luks})
    print()
    return rows


def _indexed_devices(disks: list[Device]) -> list[Device]:
    out: list[Device] = []
    for d in disks:
        out.extend(d.flat())
    return out


def _locked_ctx(target: Device, notes: list[str], smart: dict,
                dm: dict) -> ReportCtx:
    return ReportCtx(
        dev=target, smart=smart, dmesg=dm, notes=notes,
        lf={"checked": False, "notes": ["volume locked"], "file_count": 0,
            "total_bytes": 0, "path": None},
        fsck={"device": target.path, "mode": "dry-run", "clean": None,
              "would_fix": [], "exit_code": None,
              "notes": ["volume locked — unlock to check the filesystem"]})


def diagnose(dev: Device, deep: bool = False) -> dict:
    """Quick = SMART + trend + dmesg + USB + lost+found + fsck -n.
    Deep adds superblock forensics + read-speed sampling
    (+ optional quick surface scan when interactive)."""
    target, notes = resolve_target(dev)
    smart = smart_check(target)
    trend = HistoryStore(target).trend()
    dm = dmesg_check(target)
    usb = usb_layer_check(target, dm)

    if target.is_luks_container:                      # locked volume
        ctx = _locked_ctx(target, notes, smart, dm)
        ctx.usb, ctx.trend = usb, trend
        return print_report(ctx)

    lf = lostfound_check(target)
    sb = superblock_info(target) if deep else None
    speed = read_speed_test(target) if deep else None
    surface = None
    if deep and sys.stdin.isatty() and \
            confirm("  Also run a QUICK read-only surface scan "
                    f"(first {CFG['surface_quick_mb']} MiB)?"):
        surface = surface_scan(target, quick=True)
    fsck = fsck_dry_run(target)
    ctx = ReportCtx(dev=target, smart=smart, dmesg=dm, lf=lf, fsck=fsck,
                    notes=notes, usb=usb, speed=speed, sb=sb,
                    surface=surface, trend=trend)
    return print_report(ctx)


# ==========================================================================
# 15. INTERACTIVE MENUS  (numbered options — the default UX)
# ==========================================================================

def pick_device(disks: list[Device]) -> Device | None:
    devs = _indexed_devices(disks)
    if not devs:
        print(red("No block devices found."))
        return None
    raw = ask("  Select a device by # (or q to cancel): ").lower()
    if raw in ("q", ""):
        return None
    if not raw.isdigit() or not (1 <= int(raw) <= len(devs)):
        print(yellow("  Invalid selection."))
        return None
    return devs[int(raw) - 1]


def _pick(disks_needed: bool = True) -> Device | None:
    disks = scan_devices()
    print_inventory(disks)
    return pick_device(disks)


def smart_menu(dev: Device) -> None:
    while True:
        p = dev.physical_parent()
        print(bold(f"\n  SMART TOOLS — {p.path} ({p.model or 'unknown'})"))
        print("   1) Read attributes now  " + dim("[read-only, snapshots history]"))
        print("   2) Start SHORT self-test  " + dim("(~2 min, safe)"))
        print("   3) Start LONG self-test  " + dim("(full surface, hours)"))
        print("   4) Self-test progress")
        print("   5) Self-test log")
        print("   6) Drive error log")
        print("   7) Health history & trend")
        print("   b) Back")
        c = ask("  Choose: ").lower()
        if c == "1":
            s = smart_check(dev)
            for k in ("overall_health", "reallocated_sectors",
                      "pending_sectors", "uncorrectable_errors",
                      "temperature_c", "power_on_hours"):
                print(f"    {k:<22} {s.get(k)}")
            print(f"    verdict: {s['verdict']}")
        elif c == "2":
            smart_selftest(dev, "short")
        elif c == "3":
            smart_selftest(dev, "long")
        elif c == "4":
            smart_progress(dev)
        elif c == "5":
            smart_selftest_log(dev)
        elif c == "6":
            smart_error_log(dev)
        elif c == "7":
            show_history(dev)
        elif c == "b":
            return
        else:
            print(yellow("  Unknown option."))


def interactive_menu() -> None:
    print(bold(cyan("\n  ╔════════════════════════════════════════════════╗")))
    print(bold(cyan("  ║   diskdoctor v2 — external drive triage suite  ║")))
    print(bold(cyan("  ╚════════════════════════════════════════════════╝")))
    print(dim("  Read-only by default. Only menu 11 (Repair) can write to a "
              "disk,\n  and it asks y/N first. Audit log: " + str(LOG.path)))
    if not is_root():
        print(dim("  Running unprivileged — smartctl/fsck/etc. will use sudo "
                  "and may prompt.\n"))

    while True:
        print(bold("\n  MAIN MENU"))
        print("   1)  Scan & list all drives            " + dim("[safe]"))
        print("   2)  Quick diagnosis                    "
              + dim("[SMART+trend+dmesg+USB+lost+found+fsck -n]"))
        print("   3)  DEEP diagnosis                     "
              + dim("[adds superblock, read-speed, optional surface scan]"))
        print("   4)  SMART tools ▸                      "
              + dim("[self-tests, logs, history]"))
        print("   5)  Surface scan (read-only badblocks)")
        print("   6)  LUKS tools ▸                       "
              + dim("[header info & backup]"))
        print("   7)  ext4 tools ▸                       "
              + dim("[superblock, e2image, backups]"))
        print("   8)  lost+found inspector")
        print("   9)  Space analyzer                     "
              + dim("[what's eating the drive]"))
        print("   10) Health history & trends")
        print("   11) " + red("REPAIR filesystem")
              + dim("  [the only write path — guarded]"))
        print("   12) Export last report (text / JSON)")
        print("   q)  Quit")
        c = ask("\n  Choose an option: ").lower()

        if c == "q":
            print(dim("  Bye. Log: " + str(LOG.path)))
            return
        if c == "1":
            print_inventory(scan_devices())
            continue
        if c == "12":
            f = ask("  Format — 1) text  2) json : ")
            export_report("json" if f == "2" else "text")
            continue
        if c not in {"2", "3", "4", "5", "6", "7", "8", "9", "10", "11"}:
            print(yellow("  Unknown option."))
            continue

        dev = _pick()
        if dev is None:
            continue
        if c == "2":
            diagnose(dev, deep=False)
        elif c == "3":
            diagnose(dev, deep=True)
        elif c == "4":
            smart_menu(dev)
        elif c == "5":
            target, notes = resolve_target(dev)
            for n in notes:
                print(yellow("  note: " + n))
            if not target.is_luks_container:
                mode = ask("  1) quick (first "
                           f"{CFG['surface_quick_mb']} MiB)   2) full : ")
                surface_scan(target, quick=(mode != "2"))
        elif c == "6":
            luks_menu(dev)
        elif c == "7":
            ext4_menu(dev)
        elif c == "8":
            target, notes = resolve_target(dev)
            for n in notes:
                print(yellow("  note: " + n))
            if not target.is_luks_container:
                lostfound_inspect(target)
        elif c == "9":
            target, _ = resolve_target(dev)
            if not target.is_luks_container:
                space_report(target)
        elif c == "10":
            show_history(dev)
        elif c == "11":
            target, notes = resolve_target(dev)
            for n in notes:
                print(yellow("  note: " + n))
            if not target.is_luks_container:
                smart = smart_check(target)
                fsck_repair(target, smart)


# ==========================================================================
# 16. CLI ENTRY POINT
# ==========================================================================

def main() -> int:
    ap = argparse.ArgumentParser(
        prog="diskdoctor",
        description="Advanced diagnosis & safe repair for external drives "
                    "(LUKS-encrypted ext4 friendly). Read-only by default; "
                    "run with no arguments for the interactive menu.",
        epilog="Examples:\n"
               "  diskdoctor                       interactive numbered menu\n"
               "  diskdoctor --scan                list all drives\n"
               "  diskdoctor --device /dev/sdb1    quick diagnosis\n"
               "  diskdoctor --device /dev/sdb1 --deep --json > r.json\n"
               "  diskdoctor --device /dev/mapper/luks-X --fix   repair\n"
               "  diskdoctor --device /dev/sdb --selftest short\n"
               "  diskdoctor --device /dev/sdb --history",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scan", action="store_true",
                    help="list all block devices, LUKS status, usage%%")
    ap.add_argument("--device", metavar="/dev/sdX",
                    help="device to work on (partition or /dev/mapper node)")
    ap.add_argument("--deep", action="store_true",
                    help="deep diagnosis (superblock + read-speed sampling)")
    ap.add_argument("--fix", action="store_true",
                    help="allow WRITE repairs (still asks y/N)")
    ap.add_argument("--selftest", choices=["short", "long"],
                    help="start a SMART self-test on the physical disk")
    ap.add_argument("--history", action="store_true",
                    help="show SMART health history & trend")
    ap.add_argument("--json", action="store_true",
                    help="emit the report as JSON on stdout")
    ap.add_argument("--verbose", action="store_true",
                    help="reserved for extra output")
    args = ap.parse_args()

    if not (args.scan or args.device):
        if not sys.stdin.isatty():
            ap.print_help()
            return 2
        try:
            interactive_menu()
        except KeyboardInterrupt:
            print(dim("\n  Interrupted. Log: " + str(LOG.path)))
        return 0

    if args.scan:
        rows = print_inventory(scan_devices())
        if args.json:
            print(json.dumps(rows, indent=2))
        return 0

    disks = scan_devices()
    dev = find_device(disks, args.device)
    if dev is None:
        print(red(f"Device '{args.device}' not found. Run --scan to list."))
        return 1

    if args.selftest:
        smart_selftest(dev, args.selftest)
        return 0
    if args.history:
        show_history(dev)
        return 0

    report = diagnose(dev, deep=args.deep)

    if args.fix:
        target, _ = resolve_target(dev)
        if target.is_luks_container:
            print(red("Cannot repair a locked LUKS container — unlock it "
                      "first."))
            return 1
        fsck_repair(target, report.get("smart", {}))

    if args.json:
        print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
