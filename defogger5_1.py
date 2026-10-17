#!/usr/bin/env python3
"""Extract QuartzLine-style statically encoded endpoint fragments from an x64 PE.

The current QuartzLine sample calls a short decoder with:
  RCX = address of encoded bytes
  EDX = encoded byte count

The decoder applies a rolling 8-bit additive key:
  plain[i] = (cipher[i] + 0xED + 0xF5 * i) & 0xff

This script identifies the x64 instruction pattern:
  lea rcx, [rip + <encoded-data>]
  mov edx, <length>
  call <decoder>

It reports both the exact declared decode and the printable prefix obtained when
walking past a packed-fragment boundary.  The latter is evidence only; it is not
treated as a complete URL without validating the record layout in the sample.

Use --auto-additive to identify direct-call targets that implement the observed
rolling-additive decoder shape. The mode extracts the embedded key start/step
constants and retains only decoders with at least one printable declared
fragment. It does not brute-force keys or assert that a decoded label is a C2.

Verified Caira profile:
  --decoder-va 0x16a2fcd49 --key-start 0xe9 --key-step 0xf3
  --scheme https --suffix com

Verified DuskReader profile (2026-10):
  decoder sub_140022532: start=0xF3, step=0xF9
  RDX encoded pointer / R8D length; separate updatedrun + com decoder calls.

Verified Pageglass profile (2026-10):
  decoder sub_14B65D1F0: start=0xF3, step=0xF9
  3 x 48-byte endpoint records, assembled from decoded labels + suffix.

Verified GridDesk / ReportLab profile:
  GridDesk: --decoder-va 0x160ba1451 --key-start 0xef --key-step 0xf9
  ReportLab: --decoder-va 0x17c0d1451 --key-start 0xef --key-step 0xf9
  --scheme https --suffix com
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit
from pathlib import Path


IMAGE_SCN_MEM_EXECUTE = 0x20000000
CALL_PATTERN_SIZE = 17
PRINTABLE_LABEL = re.compile(rb"^[A-Za-z0-9-]{3,}$")


@dataclass(frozen=True)
class Section:
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int


@dataclass(frozen=True)
class Fragment:
    call_va: int
    encoded_va: int
    declared_length: int
    declared_hex: str
    declared_decoded: str
    printable_prefix: str


class PEFormatError(ValueError):
    """Raised when the supplied file is not a supported PE image."""


class PortableExecutable:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = path.read_bytes()
        self.image_base, self.sections = self._parse_headers()

    def _parse_headers(self) -> tuple[int, list[Section]]:
        if self.data[:2] != b"MZ":
            raise PEFormatError("missing MZ header")

        pe_offset = self._u32(0x3C)
        if self.data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise PEFormatError("missing PE signature")

        file_header = pe_offset + 4
        section_count = self._u16(file_header + 2)
        optional_size = self._u16(file_header + 16)
        optional = file_header + 20
        magic = self._u16(optional)

        if magic != 0x20B:
            raise PEFormatError("only PE32+ (x64) images are supported")

        image_base = self._u64(optional + 24)
        section_offset = optional + optional_size
        sections = []

        for index in range(section_count):
            offset = section_offset + index * 40
            sections.append(
                Section(
                    virtual_address=self._u32(offset + 12),
                    virtual_size=self._u32(offset + 8),
                    raw_offset=self._u32(offset + 20),
                    raw_size=self._u32(offset + 16),
                    characteristics=self._u32(offset + 36),
                )
            )

        return image_base, sections

    def _u16(self, offset: int) -> int:
        return struct.unpack_from("<H", self.data, offset)[0]

    def _u32(self, offset: int) -> int:
        return struct.unpack_from("<I", self.data, offset)[0]

    def _u64(self, offset: int) -> int:
        return struct.unpack_from("<Q", self.data, offset)[0]

    def va_to_offset(self, va: int) -> int:
        rva = va - self.image_base
        for section in self.sections:
            size = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + size:
                return section.raw_offset + rva - section.virtual_address
        raise PEFormatError(f"VA 0x{va:X} is outside mapped PE sections")

    def read_va(self, va: int, size: int) -> bytes:
        offset = self.va_to_offset(va)
        end = offset + size
        # Reject virtual reads spilling into the next on-disk section or overlay.
        section = next((sec for sec in self.sections if
                        sec.raw_offset <= offset < sec.raw_offset + sec.raw_size), None)
        if section is None or end > min(section.raw_offset + section.raw_size, len(self.data)):
            raise PEFormatError(f"read beyond file-backed section at VA 0x{va:X}")
        return self.data[offset:end]

    def executable_ranges(self) -> list[tuple[int, int]]:
        ranges = []
        for section in self.sections:
            if not section.characteristics & IMAGE_SCN_MEM_EXECUTE:
                continue
            start = section.raw_offset
            end = min(start + section.raw_size, len(self.data))
            ranges.append((start, end))
        return ranges

    def offset_to_va(self, offset: int) -> int:
        for section in self.sections:
            start = section.raw_offset
            end = start + section.raw_size
            if start <= offset < end:
                return self.image_base + section.virtual_address + offset - start
        raise PEFormatError(f"file offset 0x{offset:X} is outside PE sections")


def decode_additive(ciphertext: bytes, key_start: int, key_step: int) -> bytes:
    key = key_start
    plaintext = bytearray()
    for value in ciphertext:
        plaintext.append((value + key) & 0xFF)
        key = (key + key_step) & 0xFF
    return bytes(plaintext)


def render_bytes(value: bytes) -> str:
    return value.decode("utf-8", errors="backslashreplace")


def printable_prefix(value: bytes) -> str:
    prefix = bytearray()
    for byte in value:
        if 0x20 <= byte <= 0x7E:
            prefix.append(byte)
        else:
            break
    return prefix.decode("ascii")


def endpoint_label(fragment: Fragment) -> str | None:
    """Return an exact decoded label, falling back to a printable-prefix label."""
    declared = fragment.declared_decoded.encode("utf-8")
    if PRINTABLE_LABEL.fullmatch(declared):
        return fragment.declared_decoded
    if PRINTABLE_LABEL.fullmatch(fragment.printable_prefix.encode()):
        return fragment.printable_prefix
    return None


DECODER_PROLOGUE = bytes.fromhex(
    "4156565755534883ec404889d64889cf488d5c2428"
)
DECODER_LOOP = bytes.fromhex(
    "40b5ed4531f6428a04374000"
)


def find_additive_decoders(pe: PortableExecutable) -> list[int]:
    """Find the recovered QuartzLine additive-decoder implementation."""
    candidates = []
    for start, end in pe.executable_ranges():
        search_start = start
        while True:
            offset = pe.data.find(DECODER_PROLOGUE, search_start, end)
            if offset < 0:
                break
            window = pe.data[offset : min(offset + 96, end)]
            if DECODER_LOOP in window:
                candidates.append(pe.offset_to_va(offset))
            search_start = offset + 1
    return candidates


def find_rolling_additive_decoders(
    pe: PortableExecutable, max_fragment: int
) -> list[tuple[int, int, int]]:
    """Identify called rolling-additive routines by byte-key setup and update.

    Rust's generated code need not put `xor index,index` immediately after
    `mov bpl,key`. Require key update, a plausible byte-reading loop, and
    at least one exact-length ASCII label at a caller. This is deliberately
    structural, rather than assuming a fixed function prologue.
    """
    executable = pe.executable_ranges()
    call_targets: set[int] = set()
    for start, end in executable:
        for offset in range(start, end - 5):
            if pe.data[offset] != 0xE8:
                continue
            call_va = pe.offset_to_va(offset)
            target = call_va + 5 + struct.unpack_from("<i", pe.data, offset + 1)[0]
            try:
                target_offset = pe.va_to_offset(target)
            except PEFormatError:
                continue
            if any(begin <= target_offset < finish for begin, finish in executable):
                call_targets.add(target)

    profiles: list[tuple[int, int, int]] = []
    for target in sorted(call_targets):
        try:
            window = pe.read_va(target, 0x220)
        except PEFormatError:
            continue
        for match in re.finditer(rb"\x40\xb5([\x00-\xff])", window):
            key_start = match.group(1)[0]
            # add bpl, imm8 -- allow intervening byte-load, allocation,
            # and UTF-8 emission code. Limit distance to this function.
            key_offset = match.start()
            step_markers = [window.find(prefix, key_offset + 3) for prefix in (b"\x40\x80\xc5", b"\x48\x80\xc5")]
            step_marker = min((pos for pos in step_markers if pos >= 0), default=-1)
            if step_marker < 0 or step_marker + 4 > len(window):
                continue
            key_step = window[step_marker + 3]
            # movzx byte input followed by add to a rolling byte key.
            # Avoid recognizing arbitrary functions that happen to modify BPL.
            # Backward loop branch: source byte load can occur AFTER the
            # key update in file order, as in the Pageglass decoder.
            neighborhood = window[max(0, key_offset - 32):min(len(window), step_marker + 112)]
            if b"\x0f\xb6" not in neighborhood and b"\x8a" not in neighborhood:
                continue
            fragments = find_decoder_calls(pe, target, max_fragment, key_start, key_step)
            if any(PRINTABLE_LABEL.fullmatch(f.declared_decoded.encode("utf-8"))
                   for f in fragments):
                profiles.append((target, key_start, key_step))
            break
    return profiles


def find_decoder_calls(
    pe: PortableExecutable,
    decoder_va: int,
    max_fragment: int,
    key_start: int,
    key_step: int,
) -> list[Fragment]:
    fragments: list[Fragment] = []

    for start, end in pe.executable_ranges():
        for offset in range(start, end - CALL_PATTERN_SIZE):
            # lea rcx, [rip + disp32]; mov edx, imm32; call rel32
            if pe.data[offset : offset + 3] != b"\x48\x8D\x0D":
                continue
            if pe.data[offset + 7] != 0xBA or pe.data[offset + 12] != 0xE8:
                continue

            call_va = pe.offset_to_va(offset + 12)
            target = call_va + 5 + struct.unpack_from("<i", pe.data, offset + 13)[0]
            if target != decoder_va:
                continue

            lea_va = pe.offset_to_va(offset)
            encoded_va = lea_va + 7 + struct.unpack_from("<i", pe.data, offset + 3)[0]
            declared_length = struct.unpack_from("<I", pe.data, offset + 8)[0]
            if declared_length == 0 or declared_length > max_fragment:
                continue

            try:
                ciphertext = pe.read_va(encoded_va, declared_length)
                # An expanded prefix is optional; do not discard an otherwise
                # valid declared fragment at the end of an on-disk section.
                try:
                    expanded_data = pe.read_va(encoded_va, max_fragment)
                except PEFormatError:
                    expanded_data = ciphertext
            except PEFormatError:
                continue
            declared = decode_additive(ciphertext, key_start, key_step)
            expanded = decode_additive(expanded_data, key_start, key_step)
            fragments.append(
                Fragment(
                    call_va=call_va,
                    encoded_va=encoded_va,
                    declared_length=declared_length,
                    declared_hex=ciphertext.hex(),
                    declared_decoded=render_bytes(declared),
                    printable_prefix=printable_prefix(expanded),
                )
            )

    # DuskReader-style ABI: LEA RDX,[RIP+encoded]; ... MOV R8D,length;
    # MOV RCX,destination; CALL decoder. The encoded bytes and length
    # are set within the same small basic block, but not adjacent to CALL.
    # Validate the actual rel32 call target before accepting a fragment.
    known = {(f.call_va, f.encoded_va) for f in fragments}
    for start, end in pe.executable_ranges():
        data = pe.data
        for call_offset in range(start, end - 4):
            if data[call_offset] != 0xE8:
                continue
            call_va = pe.offset_to_va(call_offset)
            target = call_va + 5 + struct.unpack_from('<i', data, call_offset + 1)[0]
            if target != decoder_va:
                continue
            # Find the closest MOV R8D, imm32 (41 B8 xx xx xx xx).
            # Search backwards in the same short call-preparation sequence.
            lower = max(start, call_offset - 45)
            length_candidates = [i for i in range(lower, call_offset - 5)
                                 if data[i:i+2] == b'\x41\xb8']
            if not length_candidates:
                continue
            length_off = length_candidates[-1]
            declared_length = struct.unpack_from('<I', data, length_off + 2)[0]
            if not 1 <= declared_length <= max_fragment:
                continue
            # Encoded LEA RDX must precede length assignment, otherwise it
            # might belong to a different call's arguments.
            data_candidates = [i for i in range(lower, length_off)
                               if data[i:i+3] == b'\x48\x8d\x15']
            if not data_candidates:
                continue
            lea_off = data_candidates[-1]
            encoded_va = pe.offset_to_va(lea_off) + 7 + struct.unpack_from('<i', data, lea_off + 3)[0]
            if (call_va, encoded_va) in known:
                continue
            try:
                ciphertext = pe.read_va(encoded_va, declared_length)
                try:
                    expanded_data = pe.read_va(encoded_va, max_fragment)
                except PEFormatError:
                    expanded_data = ciphertext
            except PEFormatError:
                continue
            decoded = decode_additive(ciphertext, key_start, key_step)
            # The declared bytes must be a printable string. This guards
            # against coincidental matches inside unrelated x64 instructions.
            if not decoded or not all(0x20 <= c <= 0x7e for c in decoded):
                continue
            fragments.append(Fragment(
                call_va=call_va, encoded_va=encoded_va,
                declared_length=declared_length,
                declared_hex=ciphertext.hex(),
                declared_decoded=render_bytes(decoded),
                printable_prefix=printable_prefix(decode_additive(expanded_data, key_start, key_step)),
            ))
            known.add((call_va, encoded_va))
    return sorted(fragments, key=lambda f: f.call_va)


# Pageglass-specific independent signature: four verified ciphertext fragments
# appear with these offsets in .rdata. This path is intentionally narrow and
# does not infer that the reconstructed domains were contacted at runtime.
PAGEGLASS_FRAGMENTS = (
    (0x00, "sparksetuptechnology"),
    (0x14, "com"),
    (0x1C, "supporterupdate"),
    (0x2B, "biggerskills"),
)


def find_pageglass_cluster(pe: PortableExecutable) -> tuple[list[Fragment], list[dict]]:
    start_key, step_key = 0xF3, 0xF9
    first = PAGEGLASS_FRAGMENTS[0][1]
    signature = bytes((ord(c) - start_key - step_key * i) & 255
                      for i, c in enumerate(first))
    fragments, endpoints = [], []
    for section in pe.sections:
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE:
            continue
        begin = section.raw_offset
        end = min(begin + section.raw_size, len(pe.data))
        at = begin
        while begin < end:
            at = pe.data.find(signature, at, end)
            if at < 0:
                break
            try:
                base_va = pe.offset_to_va(at)
                verified = []
                for delta, expected in PAGEGLASS_FRAGMENTS:
                    cipher = pe.read_va(base_va + delta, len(expected))
                    if decode_additive(cipher, start_key, step_key) != expected.encode():
                        break
                    verified.append((base_va + delta, expected, cipher))
                if len(verified) == len(PAGEGLASS_FRAGMENTS):
                    for address, label, cipher in verified:
                        fragments.append(Fragment(
                            call_va=0, encoded_va=address, declared_length=len(cipher),
                            declared_hex=cipher.hex(), declared_decoded=label,
                            printable_prefix=label))
                    for address, stem, _ in (verified[0], verified[2], verified[3]):
                        endpoints.append({
                            "domain": stem + ".com",
                            "evidence": "verified Pageglass ciphertext cluster; three 48-byte endpoint records in disassembly",
                            "encoded_va": f"0x{address:X}",
                            "decoder_call_va": None,
                            "status": "statically reconstructed candidate (not independently confirmed C2)",
                        })
            except PEFormatError:
                pass
            at += 1
    return fragments, endpoints


def reconstruct_endpoint_domains(pe: PortableExecutable, fragments: list[Fragment],
                                 key_start: int, key_step: int) -> list[dict]:
    """Recognize Pageglass-style three-record endpoint initialization.

    Direct LEA/MOV/CALL sites reveal three hostname stems. The shared `com`
    decoder calls load RCX via R12 instead of an immediate LEA, so they are
    *not* detected by find_decoder_calls. In this observed structure, the
    three-byte shared suffix blob begins right after the first 20-byte stem.
    Keep this association contextual, rather than treating all labels as IOCs.
    """
    ordered = sorted(fragments, key=lambda f: f.call_va)
    found = {}
    for i in range(len(ordered) - 2):
        chunk = ordered[i:i + 3]
        if chunk[-1].call_va - chunk[0].call_va > 0x200:
            continue
        stems = [endpoint_label(fragment) for fragment in chunk]
        if not all(stems) or len(set(stems)) != 3:
            continue
        if not (chunk[0].declared_length >= 12 and
                chunk[1].declared_length >= 8 and
                chunk[2].declared_length >= 8):
            continue
        # The first label and the suffix are separate packed `.rdata` fragments.
        # Check the known source-layout pattern, not arbitrary TLD guessing.
        if chunk[1].encoded_va <= chunk[0].encoded_va + chunk[0].declared_length:
            continue
        try:
            suffix_bytes = pe.read_va(chunk[0].encoded_va + chunk[0].declared_length, 3)
        except PEFormatError:
            continue
        suffix_raw = decode_additive(suffix_bytes, key_start, key_step)
        if suffix_raw not in (b"com", b"net", b"org"):
            continue
        suffix = suffix_raw.decode("ascii")
        for stem, frag in zip(stems, chunk):
            domain = f"{stem}.{suffix}".lower()
            found[domain] = {
                "domain": domain,
                "evidence": "three clustered decoded hostname stems and adjacent encoded DNS suffix",
                "encoded_va": f"0x{frag.encoded_va:X}",
                "decoder_call_va": f"0x{frag.call_va:X}",
                "status": "statically reconstructed candidate (not independently confirmed C2)",
            }
    return list(found.values())



def reconstruct_split_hostnames(fragments: list[Fragment], key_start: int, key_step: int) -> list[dict]:
    """Pair code-referenced stem + TLD decoded by consecutive calls.

    This handles DuskReader's two independent decoder invocations, each
    resetting the rolling key. Requiring both call/data proximity and the
    same decoder profile avoids blindly combining unrelated strings.
    """
    hits = {}
    ordered = sorted(fragments, key=lambda f: f.call_va)
    for a, b in zip(ordered, ordered[1:]):
        stem = a.declared_decoded.lower()
        tld = b.declared_decoded.lower()
        if not re.fullmatch(r'[a-z][a-z0-9-]{5,62}', stem):
            continue
        if tld not in {'com', 'net', 'org', 'io', 'co'}:
            continue
        if not (0 < b.call_va - a.call_va <= 0x80):
            continue
        if a.encoded_va + a.declared_length != b.encoded_va:
            continue
        domain = stem + '.' + tld
        hits[domain] = {
            'domain': domain,
            'evidence': 'adjacent separately decoded stem/TLD and nearby direct call sites',
            'encoded_va': f'0x{a.encoded_va:X}',
            'decoder_call_va': f'0x{a.call_va:X}',
            'status': 'statically reconstructed candidate (not independently confirmed C2)',
            'encoding': f'rolling additive start=0x{key_start:02X} step=0x{key_step:02X}',
        }
    return list(hits.values())



# Brute-force discovery is deliberately bounded. A printable decoded byte run
# by itself is weak evidence: arbitrary binary data has many false positives.
BRUTE_SEEDS = (b"https", b"http", b"spark", b"technology", b"support", b"update", b"setup", b"skills", b"config", b"download")
BRUTE_MAX_READ = 48


def brute_force_additive(pe: PortableExecutable, max_windows: int = 24,
                         max_candidates: int = 30) -> list[dict]:
    """Recover unseen byte keys/steps from candidate ciphertext in non-code sections.

    Pass 1: derive K/S for a known plaintext prefix at *any* byte offset and
    validate at least four consecutive bytes. This enumerates only equivalent
    members of the 65,536-key space, but covers every section offset.
    Pass 2: actually enumerate all 65,536 (K,S) possibilities on a bounded
    set of candidate windows referenced by RIP-relative LEA/MOV/CALL sites.
    Neither pass asserts that a candidate is a network destination.
    """
    sections = []
    for sec in pe.sections:
        if not sec.characteristics & IMAGE_SCN_MEM_EXECUTE:
            lo, hi = sec.raw_offset, min(len(pe.data), sec.raw_offset + sec.raw_size)
            if hi > lo:
                sections.append((lo, hi))
    hits: dict[tuple[int, int, int], dict] = {}

    def admit(offset: int, k: int, step: int, raw: bytes, method: str):
        if k == 0 and step == 0:
            return  # Identity is not a decoded/obfuscated string.
        if len(raw) < 8 or len(raw) > 48:
            return
        try:
            label = raw.decode('ascii')
        except UnicodeError:
            return
        # Require substantial alphabetic content to avoid numeric/random runs.
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{7,47}', label):
            return
        if sum(c.isalpha() for c in label) < 6:
            return
        try:
            va = pe.offset_to_va(offset)
        except PEFormatError:
            return
        record = {'encoded_va': f'0x{va:X}', 'decoded': label,
                  'key_start': k, 'key_step': step, 'method': method,
                  'confidence': 'heuristic; unverified'}
        hits.setdefault((offset, k, step), record)

    # Known-plaintext search: O(total non-code bytes * number of seeds).
    for lo, hi in sections:
        blob = pe.data
        for seed in BRUTE_SEEDS:
            a, b = seed[0], seed[1]
            signature = (seed[2] - 2 * seed[1] + seed[0]) & 255
            for pos in range(lo, hi - max(8, len(seed))):
                if (blob[pos + 2] - 2 * blob[pos + 1] + blob[pos]) & 255 != signature:
                    continue
                k = (a - blob[pos]) & 255
                step = (b - blob[pos + 1] - k) & 255
                if any(((blob[pos + i] + k + step * i) & 255) != expected
                       for i, expected in enumerate(seed[2:], 2)):
                    continue
                raw = bytearray(seed)
                # Extend exact decoded prefix until the first non-label byte.
                for i in range(len(seed), min(BRUTE_MAX_READ, hi - pos)):
                    v = (blob[pos + i] + k + step * i) & 255
                    if not (65 <= v <= 90 or 97 <= v <= 122 or
                            48 <= v <= 57 or v == 45):
                        break
                    raw.append(v)
                admit(pos, k, step, bytes(raw), 'known-plaintext')

    # Locate candidate encoded buffers with LEA RCX, [RIP+disp32], MOV EDX,
    # length, CALL rel32. Unusual variants may not have this exact call shape.
    windows = []
    for start, end in pe.executable_ranges():
        for off in range(start, end - CALL_PATTERN_SIZE + 1):
            if pe.data[off:off+3] != b'\x48\x8d\x0d' or pe.data[off+7] != 0xba or pe.data[off+12] != 0xe8:
                continue
            n = struct.unpack_from('<I', pe.data, off+8)[0]
            if not 10 <= n <= BRUTE_MAX_READ:
                continue
            va = pe.offset_to_va(off)
            data_va = va + 7 + struct.unpack_from('<i', pe.data, off+3)[0]
            try:
                data_off = pe.va_to_offset(data_va)
                if any(lo <= data_off and data_off+n <= hi for lo, hi in sections):
                    windows.append((data_off, pe.data[data_off:data_off+n]))
            except PEFormatError:
                pass
    windows = sorted(set(windows), key=lambda x: x[0])[:max_windows]
    for offset, cipher in windows:
        # Real exhaustive key enumeration, but only at bounded code-referenced
        # buffers, not across every offset in a large PE.
        for k in range(256):
            for step in range(256):
                raw = decode_additive(cipher, k, step)
                # Exact-length decoded strings only. No prefix trimming: a
                # random run of ASCII is much less convincing.
                admit(offset, k, step, raw, 'exhaustive-referenced-buffer')

    # Count and cap candidates rather than flooding users with noise.
    found = list(hits.values())
    found.sort(key=lambda h: (h['method'] != 'known-plaintext', -len(h['decoded']), h['encoded_va']))
    return found[:max_candidates]

# Static indicators are evidence of functionality, not proof of malware family.
INSTALLER_SWITCHES = (
    "--plan-file", "--download-url", "--download-path",
    "--task-xml-file", "--report-url", "--log-code",
)
INSTALLER_FIELDS = (
    "downloadUrl", "downloadPath", "reportUrl", "stagedExePath",
    "rolloutId", "taskExitCode", "uidInTask", "alreadyInstalled",
    "errorHResult", "complete.json",
)
TASK_INDICATORS = ("CreateScheduledTask", "TaskActionsCommand", "task-xml-file", "uidInTask")
NETWORK_INDICATORS = (
    "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
    "WinHttpReadData", "WinHttpQueryDataAvailable",
)
URL_ASCII_RE = re.compile(rb"https?://[^\x00-\x20\x7f\"'<>\\]{4,512}", re.I)
URL_UTF16_RE = re.compile(rb"(?:h\x00t\x00t\x00p\x00(?:s\x00)?):\x00/\x00/\x00(?:[\x21-\x7e]\x00){4,512}", re.I)


def plaintext_urls(pe: PortableExecutable) -> list[str]:
    """Find only literal HTTP(S) URLs in file-backed nonexecutable sections.

    These are embedded URL strings, not necessarily C2s. Do not reconstruct
    hosts from fragments or report scheme-less hostnames as confirmed C2.
    """
    matches = set()
    for section in pe.sections:
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE:
            continue
        start = section.raw_offset
        end = min(start + section.raw_size, len(pe.data))
        if not (0 <= start < end):
            continue
        blob = pe.data[start:end]
        literals = [m.group(0).decode("ascii", "ignore") for m in URL_ASCII_RE.finditer(blob)]
        literals += [m.group(0).decode("utf-16le", "ignore") for m in URL_UTF16_RE.finditer(blob)]
        for literal in literals:
            literal = literal.rstrip(".,;:)]}")
            try:
                parsed = urlsplit(literal)
                if parsed.scheme.lower() in ("http", "https") and parsed.hostname and "." in parsed.hostname:
                    matches.add(literal)
            except ValueError:
                pass
    return sorted(matches)


def static_indicators(pe: PortableExecutable) -> dict:
    """Conservative role triage based on raw embedded literal evidence."""
    # PE import names and Rust packed strings may have no NUL terminators.
    # Match distinctive tokens, but require multiple independent indicators.
    data = pe.data
    switches = [x for x in INSTALLER_SWITCHES if x.encode() in data]
    fields = [x for x in INSTALLER_FIELDS if x.encode() in data]
    tasks = [x for x in TASK_INDICATORS if x.encode() in data]
    network = [x for x in NETWORK_INDICATORS if x.encode() in data]
    if len(switches) >= 3 and (fields or tasks):
        role = "installer/updater candidate"
    elif switches or fields or tasks:
        role = "unclassified (installer-related indicators)"
    else:
        role = "unclassified"
    return {
        "role": role,
        "confidence": "moderate" if role == "installer/updater candidate" else "undetermined",
        "switches": switches,
        "plan_or_report_fields": fields,
        "task_indicators": tasks,
        "network_api_name_strings": network,
        "plaintext_urls": plaintext_urls(pe),
    }



# XOR decoder discovery: explicitly tied to a RIP-relative data operand, an
# immediate byte count, and a direct call to a routine with an XOR byte loop.
# This is not a raw brute-force XOR scan of every PE byte.
def decode_xor(ciphertext: bytes, key: int) -> bytes:
    return bytes(value ^ key for value in ciphertext)


def _xor_keys_in_decoder(pe: PortableExecutable, decoder_va: int) -> list[int]:
    try:
        code = pe.read_va(decoder_va, 160)
    except PEFormatError:
        return []
    # Require an observable indexed input read and a counted loop.  These
    # signatures cover e.g. movzx edx,[rdi+r14]; xor edx,imm8 and also
    # byte-register xor forms.  No inference from arbitrary printable output.
    if not (b"\x0f\xb6" in code or b"\x8a" in code):
        return []
    if not any(marker in code for marker in (b"\x75", b"\x0f\x85", b"\xe2")):
        return []
    keys = []
    # xor edx, signextended imm8; xor eax,imm8; xor al,imm8
    for pattern in (rb"\x83\xf2([\x00-\xff])", rb"\x80\xf2([\x00-\xff])",
                    rb"\x83\xf0([\x00-\xff])", rb"\x34([\x00-\xff])"):
        for match in re.finditer(pattern, code[:112]):
            key = match.group(1)[0]
            if key not in keys:
                keys.append(key)
    return keys


def find_xor_decoder_calls(pe: PortableExecutable, max_fragment: int = 64) -> tuple[list[dict], list[dict]]:
    """Discover call-linked constant-XOR fragments, with exact encoded VAs.

    Recognized x64 call preparation:
      lea rcx,[rip+disp32]; mov edx,imm32; call rel32
      lea rcx,[rip+disp32]; push imm8; pop rdx; call rel32
      lea rcx,[rip+disp32]; mov edx,imm8 (C7? not supported)
    """
    all_hits = []
    decoder_cache = {}
    for start, end in pe.executable_ranges():
        data = pe.data
        for offset in range(start, end - 16):
            if data[offset:offset+3] != b"\x48\x8d\x0d":
                continue
            va = pe.offset_to_va(offset)
            encoded_va = va + 7 + struct.unpack_from('<i', data, offset+3)[0]
            cursor = offset + 7
            if data[cursor:cursor+1] == b"\xba":
                length = struct.unpack_from('<I', data, cursor+1)[0]
                cursor += 5
            elif data[cursor:cursor+1] == b"\x6a" and data[cursor+2:cursor+3] == b"\x5a":
                length = data[cursor+1]
                cursor += 3
            elif data[cursor:cursor+1] == b"\x68" and data[cursor+5:cursor+6] == b"\x5a":
                length = struct.unpack_from('<I', data, cursor+1)[0]
                cursor += 6
            else:
                continue
            if length < 2 or length > max_fragment or data[cursor] != 0xE8:
                continue
            call_va = pe.offset_to_va(cursor)
            decoder_va = call_va + 5 + struct.unpack_from('<i', data, cursor+1)[0]
            if decoder_va not in decoder_cache:
                decoder_cache[decoder_va] = _xor_keys_in_decoder(pe, decoder_va)
            for key in decoder_cache[decoder_va]:
                try:
                    ciphertext = pe.read_va(encoded_va, length)
                except PEFormatError:
                    continue
                decoded = decode_xor(ciphertext, key)
                if not decoded or not all(32 <= ch < 127 for ch in decoded):
                    continue
                text = decoded.decode('ascii')
                # Suppress trivially readable source data masquerading as XOR.
                if all(32 <= ch < 127 for ch in ciphertext):
                    continue
                # Require an endpoint-like component or protocol token.
                if not re.fullmatch(r'[A-Za-z][A-Za-z0-9._/-]{1,63}', text):
                    continue
                all_hits.append({
                    'decoder_va': f'0x{decoder_va:X}',
                    'call_va': f'0x{call_va:X}',
                    'encoded_va': f'0x{encoded_va:X}',
                    'length': length,
                    'key': key,
                    'decoded': text,
                    'encoded_hex': ciphertext.hex(),
                    'evidence': 'direct LEA/length/CALL and XOR byte-loop',
                })
    all_hits = list({(h['call_va'], h['key']): h for h in all_hits}.values())
    all_hits.sort(key=lambda h: int(h['call_va'], 16))
    domains = {}
    for hit in all_hits:
        label = hit['decoded']
        if not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9-]{5,62}', label):
            continue
        for suffix_hit in all_hits:
            suffix = suffix_hit['decoded'].lower()
            if suffix not in ('com', 'net', 'org', 'io', 'co'):
                continue
            if (hit['decoder_va'] != suffix_hit['decoder_va'] or
                hit['key'] != suffix_hit['key']):
                continue
            nearby_code = abs(int(hit['call_va'], 16) - int(suffix_hit['call_va'], 16)) <= 0x100
            nearby_data = abs(int(hit['encoded_va'], 16) + hit['length'] - int(suffix_hit['encoded_va'], 16)) <= 16
            if not nearby_code or not nearby_data:
                continue
            domain = f'{label.lower()}.{suffix}'
            domains[domain] = {
                'domain': domain,
                'evidence': 'two nearby direct-call XOR decoded hostname fragments (stem and DNS suffix)',
                'encoded_va': hit['encoded_va'],
                'decoder_call_va': hit['call_va'],
                'status': 'statically reconstructed candidate (not independently confirmed C2)',
                'encoding': f'xor 0x{hit["key"]:02X}',
            }
    return all_hits, list(domains.values())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Defogger v5.1: rolling-additive (including split Rust ABI) and code-referenced XOR for x64 PEs."
    )
    parser.add_argument("sample", type=Path, help="Path to the PE sample")
    parser.add_argument(
        "--decoder-va",
        type=lambda value: int(value, 0),
        help="VA of the additive decoder; omit to discover the QuartzLine signature",
    )
    parser.add_argument(
        "--auto-additive",
        action="store_true",
        help=(
            "Detect called rolling-additive decoders and their key constants; "
            "does not brute-force keys"
        ),
    )
    parser.add_argument(
        "--max-fragment",
        type=int,
        default=64,
        help="Maximum encoded bytes to read for an expanded printable-prefix check",
    )
    parser.add_argument(
        "--key-start",
        type=lambda value: int(value, 0),
        default=0xED,
        help="Initial additive decoder byte (default: 0xED)",
    )
    parser.add_argument(
        "--key-step",
        type=lambda value: int(value, 0),
        default=0xF5,
        help="Per-byte additive decoder increment (default: 0xF5)",
    )
    parser.add_argument(
        "--scheme",
        help="Optional verified URL scheme used to render candidate endpoints",
    )
    parser.add_argument(
        "--suffix",
        help="Optional verified DNS suffix used to render candidate endpoints",
    )
    parser.add_argument("--bruteforce-additive", action="store_true",
                        help="Try previously unknown additive keys and steps on bounded candidate buffers")
    parser.add_argument("--bruteforce-windows", type=int, default=24,
                        help="Maximum code-referenced buffers for exhaustive search (default: 24)")
    parser.add_argument("--no-auto-xor", action="store_true", help="Disable automatic code-referenced XOR decoder discovery")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args()

    if not 0 <= args.bruteforce_windows <= 100:
        parser.error("--bruteforce-windows must be between 0 and 100")
    if args.max_fragment < 1:
        parser.error("--max-fragment must be positive")
    if not 0 <= args.key_start <= 0xFF or not 0 <= args.key_step <= 0xFF:
        parser.error("--key-start and --key-step must be byte values")
    if bool(args.scheme) != bool(args.suffix):
        parser.error("--scheme and --suffix must be supplied together")
    if args.auto_additive and args.decoder_va is not None:
        parser.error("--auto-additive cannot be combined with --decoder-va")

    try:
        pe = PortableExecutable(args.sample)
        profiles = (
            find_rolling_additive_decoders(pe, args.max_fragment)
            if args.auto_additive
            else [
                (decoder_va, args.key_start, args.key_step)
                for decoder_va in (
                    [args.decoder_va]
                    if args.decoder_va is not None
                    else find_additive_decoders(pe)
                )
            ]
        )
        xor_hits, xor_endpoints = (find_xor_decoder_calls(pe, args.max_fragment)
                                   if not args.no_auto_xor else ([], []))
        indicators = static_indicators(pe)
        bruteforce_hits = (brute_force_additive(pe, args.bruteforce_windows)
                           if args.bruteforce_additive else [])
        profile_fragments = [
            (
                decoder_va,
                key_start,
                key_step,
                find_decoder_calls(
                    pe, decoder_va, args.max_fragment, key_start, key_step
                ),
            )
            for decoder_va, key_start, key_step in profiles
        ]
        pg_fragments, pg_endpoints = find_pageglass_cluster(pe)
        if pg_fragments and not any(
            key == 0xF3 and step == 0xF9 and items
            for _, key, step, items in profile_fragments
        ):
            # Address is valid only for this exact known Pageglass image base.
            pg_decoder = 0x14B65D1F0 if pe.image_base == 0x14AF30000 else 0
            profile_fragments.append((pg_decoder, 0xF3, 0xF9, pg_fragments))
        fragments = [
            fragment for _, _, _, profile in profile_fragments for fragment in profile
        ]
        endpoints = list(pg_endpoints) + xor_endpoints
        for _, key_start, key_step, profile in profile_fragments:
            endpoints.extend(reconstruct_endpoint_domains(pe, profile, key_start, key_step))
            endpoints.extend(reconstruct_split_hostnames(profile, key_start, key_step))
        endpoints = list({item["domain"]: item for item in endpoints}.values())
    except (OSError, PEFormatError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({
            "sample": str(args.sample),
            "image_base": f"0x{pe.image_base:X}",
            "classification": indicators,
            "additive_decoder": {
                "status": "fragments found" if fragments else (
                    "decoder found; no compatible call fragments" if profiles else "not identified"
                ),
                "profiles": [
                    {"va": f"0x{va:X}", "key_start": key_start, "key_step": key_step,
                     "fragments": [asdict(f) for f in items]}
                    for va, key_start, key_step, items in profile_fragments
                ],
            },
            "decoded_endpoint_candidates": endpoints,
            "xor_decoder": {"enabled": not args.no_auto_xor, "fragments": xor_hits},
            "bruteforce_additive": {"enabled": args.bruteforce_additive,
                                    "candidates": bruteforce_hits},
            "c2_assessment": "Decoded endpoint candidates require runtime or behavioral corroboration",
        }, indent=2))
        return 0

    print(f"Sample: {args.sample}")
    print(f"Image base: 0x{pe.image_base:X}")
    print(f"Component: {indicators['role']} ({indicators['confidence']} confidence)")
    print(f"Auto-additive mode: {'yes' if args.auto_additive else 'no'}")
    print(f"Decoder profile(s) found: {len(profile_fragments)} additive, {len(set(h['decoder_va'] for h in xor_hits))} XOR")
    print(f"Decoder calls found: {len(fragments)} additive, {len(xor_hits)} XOR")
    if not profiles:
        print("Embedded additive decoder: not identified (not proof of absence)")
    for label, key in (
        ("CLI switches", "switches"), ("Plan/report fields", "plan_or_report_fields"),
        ("Task indicators", "task_indicators"), ("Network API names", "network_api_name_strings"),
    ):
        if indicators[key]:
            print(f"\n{label}: {', '.join(indicators[key])}")
    if indicators["plaintext_urls"]:
        print("\nEmbedded plaintext URL candidates (not confirmed C2):")
        for url in indicators["plaintext_urls"]:
            print(f"  {url}")
    else:
        print("\nEmbedded plaintext HTTP(S) URLs: none identified")

    if args.bruteforce_additive:
        print(f"\nBrute-force additive candidates: {len(bruteforce_hits)} (heuristic, not confirmed C2)")
        for hit in bruteforce_hits:
            print(f"  {hit['decoded']!r}  K=0x{hit['key_start']:02X} "
                  f"S=0x{hit['key_step']:02X}  {hit['encoded_va']}  [{hit['method']}]")

    if xor_hits:
        print(f"\nCode-referenced XOR fragments: {len(xor_hits)}")
        for hit in xor_hits:
            print(f"  {hit['decoded']!r}  XOR=0x{hit['key']:02X}  encoded={hit['encoded_va']}  call={hit['call_va']}  decoder={hit['decoder_va']}")

    if endpoints:
        print("\nReconstructed endpoint domains (static candidates, not confirmed C2):")
        for item in endpoints:
            print(f"  {item['domain']}  [source={item['encoded_va']}]")

    for decoder_va, key_start, key_step, profile in profile_fragments:
        print(
            f"\nDecoder VA: 0x{decoder_va:X} "
            f"(start=0x{key_start:02X} step=0x{key_step:02X})"
        )
        for fragment in profile:
            label_value = endpoint_label(fragment)
            label = " [candidate label]" if label_value else ""
            print(
                f"\ncall=0x{fragment.call_va:X} encoded=0x{fragment.encoded_va:X} "
                f"declared_length={fragment.declared_length}"
            )
            print(f"  declared decode: {fragment.declared_decoded!r}")
            print(f"  printable prefix: {fragment.printable_prefix!r}{label}")
            print(f"  encoded hex: {fragment.declared_hex}")
            if (
                args.scheme
                and args.suffix
                and label_value
                and label_value.casefold() != args.suffix.casefold()
            ):
                print(
                    "  rendered candidate: "
                    f"{args.scheme}://{label_value}.{args.suffix}"
                )

    print(
        "\nNote: Literal URLs and decoded labels are leads, not confirmed C2s. "
        "If URLs are supplied via CLI or JSON at runtime, static extraction cannot recover them."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

