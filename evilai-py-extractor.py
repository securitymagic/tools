#!/usr/bin/env python3
#Written by Luke Acha and ChatGPT for samples PDFly and Ziply
import argparse
import dis
import json
import marshal
import os
import re
import struct
import zlib
from typing import Optional, Tuple, List, Dict, Any

# --------------------------
# PE / Overlay helpers
# --------------------------

def u16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]

def u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]

def pe_overlay_offset(exe: bytes) -> int:
    if exe[:2] != b"MZ":
        raise ValueError("Not a PE (missing MZ)")
    e_lfanew = u32(exe, 0x3C)
    if exe[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
        raise ValueError("Not a PE (missing PE signature)")
    num_sections = u16(exe, e_lfanew + 6)
    opt_size = u16(exe, e_lfanew + 20)
    sect_table = e_lfanew + 24 + opt_size

    last_end = 0
    for i in range(num_sections):
        sh = sect_table + i * 40
        size_raw = u32(exe, sh + 16)
        ptr_raw  = u32(exe, sh + 20)
        end = ptr_raw + size_raw
        if end > last_end:
            last_end = end
    return last_end

# --------------------------
# zlib scanning / extraction
# --------------------------

def is_probable_zlib_header(buf: bytes, i: int) -> bool:
    if i + 2 > len(buf):
        return False
    cmf, flg = buf[i], buf[i+1]
    if (cmf & 0x0F) != 8:
        return False
    return ((cmf << 8) + flg) % 31 == 0

def decompress_zlib_at(data: bytes, off: int, max_out: int) -> Optional[Tuple[bytes, int]]:
    try:
        d = zlib.decompressobj(15)  # zlib wrapper
        out = d.decompress(data[off:], max_out + 1)
        if len(out) > max_out:
            return None
        if not d.eof:
            out += d.flush()
            if not d.eof:
                return None
        consumed = len(data[off:]) - len(d.unused_data)
        if consumed <= 2:
            return None
        return out, consumed
    except zlib.error:
        return None

# --------------------------
# marshal / code-object analysis
# --------------------------

def is_code_object(obj: Any) -> bool:
    return hasattr(obj, "co_code") and hasattr(obj, "co_filename") and hasattr(obj, "co_consts")

def walk_code(code, seen=None):
    if seen is None:
        seen = set()
    if id(code) in seen:
        return
    seen.add(id(code))
    yield code
    for c in getattr(code, "co_consts", ()):
        if is_code_object(c):
            yield from walk_code(c, seen)

def summarize_code(code) -> Dict[str, Any]:
    filenames = set()
    names = set()
    strings = []

    for co in walk_code(code):
        filenames.add(str(getattr(co, "co_filename", "")))
        names.add(str(getattr(co, "co_name", "")))
        for c in getattr(co, "co_consts", ()):
            if isinstance(c, str) and c:
                strings.append(c)

    # URLs
    url_re = re.compile(r"https?://[^\s\"']+")
    urls = sorted({m for s in strings for m in url_re.findall(s)})

    # interesting strings
    interesting = []
    for s in set(strings):
        sl = s.lower()
        if any(k in sl for k in [
            "http://", "https://", "powershell", "cmd.exe", "schtasks", "reg ",
            "winreg", "ctypes", "socket", "ssl", "encrypt", "decrypt", "key",
            "token", "api", "/compress", "/merge", "/convert", "_meipass", "pyi_",
            "startup", "appdata", "temp", "download", "upload"
        ]):
            interesting.append(s)

    filenames = [x for x in filenames if x]
    names = [x for x in names if x]

    return {
        "co_filename_samples": sorted(filenames)[:100],
        "co_name_samples": sorted(names)[:100],
        "urls": urls[:200],
        "interesting_strings": sorted(interesting)[:400],
    }

def try_marshal_load(buf: bytes, off: int) -> Optional[Any]:
    try:
        return marshal.loads(buf[off:])
    except Exception:
        return None

def find_code_objects_in_blob(blob: bytes,
                             max_hits: int = 10,
                             stride: int = 256) -> List[Tuple[int, Any]]:
    hits: List[Tuple[int, Any]] = []

    # 1) offset 0
    obj0 = try_marshal_load(blob, 0)
    if obj0 is not None and is_code_object(obj0):
        return [(0, obj0)]

    # 2) keyword-guided scan
    needles = [
        b"app.py", b"__main__", b"importlib", b"pyi_", b"_MEIPASS",
        b"Frozen", b"marshal", b"PYZ", b"base_library"
    ]
    candidate_offsets = set()
    for nd in needles:
        start = 0
        while True:
            idx = blob.find(nd, start)
            if idx == -1:
                break
            win_start = max(0, idx - 131072)
            for off in range(win_start, idx, 64):
                candidate_offsets.add(off)
            start = idx + 1

    for off in sorted(candidate_offsets):
        obj = try_marshal_load(blob, off)
        if obj is not None and is_code_object(obj):
            hits.append((off, obj))
            if len(hits) >= max_hits:
                return hits

    # 3) coarse stride scan
    for off in range(0, len(blob), stride):
        obj = try_marshal_load(blob, off)
        if obj is not None and is_code_object(obj):
            hits.append((off, obj))
            if len(hits) >= max_hits:
                break
    return hits

def write_disassembly(path: str, code) -> None:
    """
    Write disassembly for code object and all nested code objects.
    """
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        for idx, co in enumerate(walk_code(code)):
            f.write("=" * 90 + "\n")
            f.write(f"[{idx}] co_name: {getattr(co, 'co_name', '')}\n")
            f.write(f"    co_filename: {getattr(co, 'co_filename', '')}\n")
            f.write(f"    firstlineno: {getattr(co, 'co_firstlineno', '')}\n")
            f.write(f"    argcount: {getattr(co, 'co_argcount', '')}\n")
            f.write(f"    flags: {getattr(co, 'co_flags', '')}\n")
            f.write("-" * 90 + "\n")
            try:
                dis.dis(co, file=f)
            except Exception as e:
                f.write(f"[!] dis.dis failed: {e}\n")
            f.write("\n")

# --------------------------
# Main extraction flow
# --------------------------

def main():
    ap = argparse.ArgumentParser(description="Extract zlib overlay streams and recover marshalled Python code objects + disassembly (Python 3.13).")
    ap.add_argument("binary", help="Path to the EXE/binary")
    ap.add_argument("-o", "--out-dir", default="marshal_extract", help="Output directory")
    ap.add_argument("--max-out", type=int, default=250 * 1024 * 1024,
                    help="Max decompressed bytes per zlib stream (default 250MB)")
    ap.add_argument("--limit-streams", type=int, default=8000,
                    help="Safety cap on number of zlib streams to process")
    ap.add_argument("--stride", type=int, default=1,
                    help="Scan step for zlib headers in overlay (default 1). Increase to speed up but may miss streams.")
    ap.add_argument("--marshal-stride", type=int, default=256,
                    help="Stride for fallback marshal scanning inside blobs (default 256)")
    ap.add_argument("--max-hits-per-stream", type=int, default=5,
                    help="Max marshal code-object hits to save per stream (default 5)")
    ap.add_argument("--carve-bytes", type=int, default=2_000_000,
                    help="Bytes to carve starting at marshal object offset (default 2,000,000)")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    exe = open(args.binary, "rb").read()
    print(f"[+] Input: {args.binary}")
    print(f"[+] File size: {len(exe)} bytes")

    try:
        ov_off = pe_overlay_offset(exe)
        overlay = exe[ov_off:]
        print(f"[+] PE overlay offset: {ov_off} (0x{ov_off:08x})")
        print(f"[+] Overlay size: {len(overlay)} bytes")
    except Exception as e:
        print(f"[!] PE parse failed ({e}); treating entire file as 'overlay'")
        ov_off = 0
        overlay = exe

    overlay_path = os.path.join(args.out_dir, "overlay.bin")
    with open(overlay_path, "wb") as f:
        f.write(overlay)

    index: List[Dict[str, Any]] = []
    total_marshal_hits = 0
    stream_idx = 0
    i = 0

    while i < len(overlay) - 2 and stream_idx < args.limit_streams:
        if (i % args.stride) != 0:
            i += 1
            continue

        if i != 0 and not is_probable_zlib_header(overlay, i):
            i += 1
            continue

        dec = decompress_zlib_at(overlay, i, args.max_out)
        if dec is None:
            i += 1
            continue

        blob, consumed = dec
        blob_name = f"stream_{stream_idx:04d}_ov_{i:08x}_comp_{consumed}.bin"
        blob_path = os.path.join(args.out_dir, blob_name)
        with open(blob_path, "wb") as f:
            f.write(blob)

        has_app = (b"app.py" in blob)
        has_main = (b"__main__" in blob)

        hits = find_code_objects_in_blob(blob, max_hits=args.max_hits_per_stream, stride=args.marshal_stride)
        hit_summaries = []

        for h_idx, (hoff, code) in enumerate(hits[:args.max_hits_per_stream]):
            total_marshal_hits += 1
            summ = summarize_code(code)

            carve_name = f"marshal_stream_{stream_idx:04d}_hit_{h_idx:02d}_at_{hoff:08x}.bin"
            carve_path = os.path.join(args.out_dir, carve_name)
            with open(carve_path, "wb") as cf:
                cf.write(blob[hoff: min(len(blob), hoff + args.carve_bytes)])

            report_name = f"report_stream_{stream_idx:04d}_hit_{h_idx:02d}.txt"
            report_path = os.path.join(args.out_dir, report_name)
            with open(report_path, "w", encoding="utf-8", errors="replace") as rf:
                rf.write(f"stream_index: {stream_idx}\n")
                rf.write(f"overlay_offset: 0x{(ov_off + i):08x}\n")
                rf.write(f"zlib_offset_in_overlay: 0x{i:08x}\n")
                rf.write(f"marshal_offset_in_stream: 0x{hoff:08x}\n")
                rf.write(f"decompressed_len: {len(blob)}\n")
                rf.write("\n[co_filename_samples]\n")
                for s in summ["co_filename_samples"]:
                    rf.write("  " + s + "\n")
                rf.write("\n[co_name_samples]\n")
                for s in summ["co_name_samples"]:
                    rf.write("  " + s + "\n")
                rf.write("\n[urls]\n")
                for s in summ["urls"]:
                    rf.write("  " + s + "\n")
                rf.write("\n[interesting_strings]\n")
                for s in summ["interesting_strings"]:
                    rf.write("  " + s + "\n")

            dis_name = f"dis_stream_{stream_idx:04d}_hit_{h_idx:02d}.txt"
            dis_path = os.path.join(args.out_dir, dis_name)
            write_disassembly(dis_path, code)

            hit_summaries.append({
                "offset_in_stream": hoff,
                "carve_file": carve_name,
                "report_file": report_name,
                "dis_file": dis_name,
                "summary": summ,
            })

        rec = {
            "stream_index": stream_idx,
            "overlay_offset": ov_off + i,
            "overlay_offset_hex": f"0x{(ov_off + i):08x}",
            "zlib_offset_in_overlay": i,
            "compressed_len": consumed,
            "decompressed_len": len(blob),
            "blob_file": blob_name,
            "has_app_py": has_app,
            "has___main__": has_main,
            "marshal_code_hits": hit_summaries,
        }
        index.append(rec)

        print(f"[+] zlib stream {stream_idx:04d} @ overlay+0x{i:08x} "
              f"comp={consumed} decomp={len(blob)} app.py={has_app} __main__={has_main} "
              f"marshal_hits={len(hit_summaries)}")

        stream_idx += 1
        i += max(consumed, 1)

    out_index = os.path.join(args.out_dir, "index.json")
    with open(out_index, "w", encoding="utf-8") as jf:
        json.dump(index, jf, indent=2)

    print(f"[+] Done. Processed {stream_idx} zlib streams.")
    print(f"[+] Total marshal code object hits: {total_marshal_hits}")
    print(f"[+] Wrote: {out_index}")
    print(f"[+] Output dir: {args.out_dir}")

if __name__ == "__main__":
    main()

