#!/usr/bin/env python3
"""
Decrypt -> parse -> inflate helper for the container format you found.
Requires: pip install pycryptodome
Usage: python extract-systemshock.py resource
Outputs: stageX.bin and final_payload.bin
"""
#From sample: 54d1cde4842fdccc63b9beece056a9b617cbbe106d1cb47dd8d248971bf82bc2
#Written by Luke Acha and ChatGPT (Yes, I use AI to help, lets call it DefenderAI in opposition to EvilAI)

import sys
import struct
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

#Replace with key found in different sample
KEY = bytes([238, 114, 27, 61, 210, 85, 24, 191, 99, 203, 57, 228, 27, 109, 189, 117]) 
IV  = bytes([49, 224, 143, 95, 66, 240, 89, 208, 213, 164, 52, 107, 243, 148, 100, 213])

MAGIC_EXPECT = 0x007D7A7B  # little-endian 3-byte magic (0x7B 0x7A 0x7D)
# note: original code packs version in top byte: header = (version << 24) | (magic & 0xFFFFFF)

def read_le_u32(b, off):
    return struct.unpack_from('<I', b, off)[0]

def parse_container(data, depth=0):
    """
    Parse a container (smethod_2 style). Returns the unwrapped payload bytes if successful.
    If version==3 (AES), decrypts then recurses. If version==1 (deflate chunks), inflates and returns final payload.
    """
    indent = '  ' * depth
    if len(data) < 4:
        raise ValueError("Data too short for header")

    header = read_le_u32(data, 0)
    version = (header >> 24) & 0xFF
    magic = header & 0xFFFFFF
    print(f"{indent}Header: 0x{header:08X}  version={version}  magic=0x{magic:06X}")

    if magic != (MAGIC_EXPECT & 0xFFFFFF):
        raise ValueError(f"{indent}Unexpected magic: 0x{magic:06X}")

    # Version 1: deflate-chunk sequence
    if version == 1:
        # stream layout (from your decompilation):
        # int num3 = stream.method_3();   // total out len (4 bytes)
        # loop until written totalOut:
        #   int num4 = stream.method_3(); // chunk compressed size
        #   int num5 = stream.method_3(); // chunk output length
        #   read num4 bytes -> compressed chunk
        #
        # Note: method_3 reads 4-byte ints (method_3 did two method_2 calls i.e., 32-bit).
        off = 4
        if len(data) < off + 4:
            raise ValueError("Too short for totalOutLen")
        total_out_len = read_le_u32(data, off); off += 4
        print(f"{indent}Version1: total_out_len={total_out_len}")
        outbuf = bytearray(total_out_len)
        wrote = 0
        chunk_index = 0
        while wrote < total_out_len:
            if len(data) < off + 8:
                raise ValueError("Truncated chunk header")
            chunk_compressed_len = read_le_u32(data, off); off += 4
            chunk_out_len = read_le_u32(data, off); off += 4
            print(f"{indent} chunk[{chunk_index}] comp_len={chunk_compressed_len} out_len={chunk_out_len}")
            if len(data) < off + chunk_compressed_len:
                raise ValueError("Truncated chunk data")
            comp = data[off:off + chunk_compressed_len]; off += chunk_compressed_len

            # Inflate raw deflate (no zlib header). Use -15 window bits.
            try:
                dec_chunk = zlib.decompress(comp, -zlib.MAX_WBITS)
            except Exception as e:
                # If normal zlib wrapper present, try default
                try:
                    dec_chunk = zlib.decompress(comp)
                except Exception:
                    raise RuntimeError(f"{indent}Failed to decompress chunk[{chunk_index}]: {e}")
            if len(dec_chunk) != chunk_out_len:
                print(f"{indent} WARNING: decompressed len {len(dec_chunk)} != expected {chunk_out_len}")
            outbuf[wrote:wrote+len(dec_chunk)] = dec_chunk
            wrote += chunk_out_len if chunk_out_len <= len(dec_chunk) else len(dec_chunk)
            chunk_index += 1

        print(f"{indent}Done inflating. wrote {wrote}/{total_out_len} bytes")
        return bytes(outbuf)

    # Version 3: AES decrypt then recursively parse decrypted payload
    elif version == 3:
        # the decomp did: using ICryptoTransform t = smethod_0(key, iv, true); array = smethod_2(t.TransformFinalBlock(data, 4, len-4))
        print(f"{indent}Version3: AES-CBC decrypt (skip 4 bytes header), using provided key/iv")
        ct = data[4:]
        # AES-CBC with PKCS7 (AesCryptoServiceProvider default)
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        pt = cipher.decrypt(ct)
        # remove PKCS7 padding attempt
        try:
            pt = unpad(pt, AES.block_size)
        except Exception:
            # if unpad fails, keep raw (some implementations may not pad if outer length aligned)
            print(f"{indent}Warning: PKCS7 unpad failed; continuing with raw decrypted bytes")
        # write stage file for inspection
        stage_name = f"stage_depth{depth+1}.bin"
        with open(stage_name, "wb") as f:
            f.write(pt)
        print(f"{indent}Wrote {stage_name} (decrypted payload). Recursing into parse_container.")
        return parse_container(pt, depth+1)

    else:
        raise NotImplementedError(f"{indent}Unsupported version: {version}")

def main(path):
    with open(path, "rb") as f:
        data = f.read()
    try:
        final = parse_container(data, depth=0)
    except Exception as e:
        print("Error:", e)
        sys.exit(2)

    with open("final_payload.bin", "wb") as f:
        f.write(final)
    print("Wrote final_payload.bin (final result)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python decrypt_parse.py outer_blob.bin")
        sys.exit(1)
    main(sys.argv[1])
