"""Wrappers around Kali binary-analysis tools: checksec, readelf, objdump, strings."""

import re
import subprocess
import tempfile
import os
from contextlib import contextmanager
from typing import Iterator
from elftools.elf.elffile import ELFFile


@contextmanager
def open_elf(path: str) -> Iterator[ELFFile]:
    """Safely open an ELFFile via context manager — always closes the fd."""
    f = None
    try:
        f = open(path, 'rb')
        elf = ELFFile(f)
        yield elf
    finally:
        if f:
            f.close()


def run(cmd, timeout=15):
    """Run a shell command, return (retcode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return -1, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -2, "", "timeout"


# ── checksec ──────────────────────────────────────────────────────────

def parse_checksec(path):
    """Return dict with keys: canary, nx, pie, relro, rwx.
    Values: True/False for booleans, or string for relro ('none'/'partial'/'full')."""
    info = {"canary": False, "nx": False, "pie": False, "relro": "none", "rwx": False}
    rc, out, _ = run(["checksec", "--file=" + path])
    if rc != 0:
        return info
    # checksec output: "RELRO           STACK CANARY      NX            PIE             RPATH    RUNPATH      Symbols         FORTIFY Fortified  Fortifiable   FILE"
    for line in out.splitlines():
        if "No RELRO" in line:
            info["relro"] = "none"
        if "Partial RELRO" in line:
            info["relro"] = "partial"
        if "Full RELRO" in line:
            info["relro"] = "full"
        if "Canary found" in line:
            info["canary"] = True
        if "NX enabled" in line:
            info["nx"] = True
        if "PIE enabled" in line:
            info["pie"] = True
        if "RWX" in line and "has" in line.lower():
            info["rwx"] = True
    return info


def checksec_has_canary(path):
    rc, out, _ = run(["checksec", "--file=" + path])
    return "Canary found" in out if rc == 0 else False


# ── readelf ───────────────────────────────────────────────────────────

def readelf_arch(path):
    """Return 'x86' or 'x64' or None."""
    rc, out, _ = run(["readelf", "-h", path])
    if rc != 0:
        return None
    if "ELF64" in out:
        return "x64"
    if "ELF32" in out:
        return "x86"
    return None


def readelf_sections(path):
    """Return list of (name, size) tuples. Handles one-line and two-line readelf output."""
    rc, out, _ = run(["readelf", "-S", path])
    if rc != 0:
        return []
    sections = []
    lines = out.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r'\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+\S+\s+\S+', line)
        if m:
            name = m.group(1)
            # Try to read size from same line (6th column)
            m2 = re.match(r'\s*\[\s*\d+\]\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)', line)
            if m2:
                size_str = m2.group(1)
            elif i + 1 < len(lines):
                # Size on next line, first hex value
                size_m = re.match(r'\s+([0-9a-fA-F]+)', lines[i + 1])
                size_str = size_m.group(1) if size_m else "0"
            else:
                size_str = "0"
            try:
                size = int(size_str, 16)
            except ValueError:
                size = 0
            sections.append((name, size))
        i += 1
    return sections


def readelf_segments(path):
    """Return list of segment type strings."""
    rc, out, _ = run(["readelf", "-l", path])
    if rc != 0:
        return []
    segs = []
    for line in out.splitlines():
        m = re.match(r'\s+(GNU_STACK|GNU_RELRO|LOAD|INTERP|DYNAMIC)\s', line)
        if m:
            segs.append(m.group(1))
    return segs


def has_rwx_segment(path):
    """Check if any LOAD segment is RWX."""
    rc, out, _ = run(["readelf", "-l", path])
    if rc != 0:
        return False
    in_load = False
    for line in out.splitlines():
        if "LOAD" in line:
            in_load = True
        elif in_load and line.strip() and not line.startswith("  "):
            in_load = False
        if in_load and "RWE" in line:
            return True
    return False


def is_static_binary(path):
    """Check if binary is statically linked."""
    rc, out, _ = run(["readelf", "-d", path])
    if rc != 0:
        return True  # no dynamic section → static
    return "There is no dynamic section" in out


# ── objdump ──────────────────────────────────────────────────────────

def objdump_plt_functions(path):
    """Return set of function names found in .plt section."""
    rc, out, _ = run(["objdump", "-d", "-j", ".plt", path])
    if rc != 0:
        return set()
    funcs = set()
    for line in out.splitlines():
        m = re.search(r'<([^>]+)@plt>', line)
        if m:
            funcs.add(m.group(1))
    return funcs


def objdump_function_count(path):
    """Count the number of functions (symbols in .text)."""
    rc, out, _ = run(["objdump", "-t", path])
    if rc != 0:
        return 0
    count = 0
    for line in out.splitlines():
        if " .text" in line and " F " in line:
            count += 1
    return count


# ── strings ──────────────────────────────────────────────────────────

def strings_has_binsh(path):
    """Check if binary contains '/bin/sh' string."""
    rc, out, _ = run(["strings", path])
    if rc != 0:
        return False
    return "/bin/sh" in out


def strings_all(path, min_len=4):
    """Return list of all printable strings >= min_len."""
    rc, out, _ = run(["strings", "-n", str(min_len), path])
    return out.splitlines() if rc == 0 else []


# ── file size ────────────────────────────────────────────────────────

def file_size_kb(path):
    try:
        return os.path.getsize(path) // 1024
    except OSError:
        return 0
