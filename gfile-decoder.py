#Sample: https://app.any.run/tasks/5af1f789-d348-4172-b8c0-abae8173de84
import base64

def ror8(x, r):
    r &= 7
    return ((x >> r) | ((x << (8 - r)) & 0xFF)) & 0xFF

def seed_byte(seed_u32, i):
    # shifts: 8,16,24,0,8,16,24,0...
    shift = (8 * i) & 0x18
    return (seed_u32 >> shift) & 0xFF

def build_perm(seed_u32, n):
    # state = (uint32)seed XOR (uint32)n
    state = (seed_u32 ^ (n & 0xFFFFFFFF)) & 0xFFFFFFFF
    A = 0xA3BAD4F1
    C = 0x72F5FB69

    perm = list(range(n))
    while n > 1:
        state = (state * A + C) & 0xFFFFFFFF
        j = state % n
        perm[n-1], perm[j] = perm[j], perm[n-1]
        n -= 1
    return perm

def decode_blob_anylen(b64: str, expect_header: int = 0x01, verbose: bool = True) -> bytes:
    raw = base64.b64decode(b64 + "=" * ((-len(b64)) % 4))
    if len(raw) < 5:
        raise ValueError("Too short for header+seed")

    header = raw[0]
    seed_bytes = raw[1:5]
    seed_u32 = int.from_bytes(seed_bytes, "little")
    payload = raw[5:]
    n = len(payload)

    if expect_header is not None and header != expect_header:
        raise ValueError(f"Unexpected header: 0x{header:02x} (expected 0x{expect_header:02x})")

    if verbose:
        print(f"Header: 0x{header:02x}")
        print(f"Seed: {seed_bytes.hex()}  (u32_le=0x{seed_u32:08x})")
        print(f"Payload length: {n}")

    if n == 0:
        return b""

    # 1) rebuild permutation and unscatter: dst[perm[i]] = src[i] => src[i] = dst[perm[i]]
    perm = build_perm(seed_u32, n)
    src = bytearray(n)
    for i, p in enumerate(perm):
        src[i] = payload[p]

    # 2) undo rotate layer
    base = seed_u32 & 0xFF
    for i in range(n):
        rot = (base + i) & 7
        src[i] = ror8(src[i], rot)

    # 3) undo chaining
    pt = bytearray(n)
    pt[0] = src[0] ^ (seed_u32 & 0xFF) ^ 0xAB
    for i in range(1, n):
        pt[i] = src[i] ^ src[i-1] ^ (i & 0xFF) ^ seed_byte(seed_u32, i)

    return bytes(pt)

if __name__ == "__main__":
    b64 = "paste here"
    out = decode_blob_anylen(b64, verbose=True)
    print(out)
    try:
        print(out.decode("utf-8"))
    except UnicodeDecodeError:

        print(out.decode("utf-8", errors="replace"))
