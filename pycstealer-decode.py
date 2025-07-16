#Usage: after using pycdas on samples like de195ebb0f1cf3762d73f956b9d21b63de1a5bbe9626a78af623ed9f59ed760f, find XZ compressed data blob, and decompress/extract this to decodedfile.txt
import re
import base64
import codecs
import marshal

# Define decoding steps per variable
def decode_part1(s):
    # ROT13 then base64
    return base64.b64decode(codecs.decode(s, 'rot_13'))

def decode_part2(s):
    # Base64
    return base64.b64decode(s)

def decode_part3(s):
    # Reverse then base64
    return base64.b64decode(s[::-1])

def decode_part4(s):
    # Base64
    return base64.b64decode(s)

# Variable name to decoding function mapping
decoding_map = {
    '____': decode_part1,
    '_____': decode_part2,
    '______': decode_part3,
    '_______': decode_part4
}

# Read input file
with open("decodedfile.txt", "r", encoding="utf-8", errors="ignore") as f:
    data = f.read()

# Extract all matching variable assignments (e.g., ____="...")
pattern = re.compile(r'(?P<name>_{4,7})\s*=\s*"(?P<value>[^"]+)"')
matches = pattern.findall(data)

# Store decoded pieces
decoded_vars = {}
for name, value in matches:
    if name in decoding_map:
        try:
            decoded_vars[name] = decoding_map[name](value)
            print(f"[+] Decoded {name}: {len(decoded_vars[name])} bytes")
        except Exception as e:
            print(f"[!] Failed to decode {name}: {e}")

# Check all required variables were captured
required = ['____', '_____', '______', '_______']
missing = [v for v in required if v not in decoded_vars]
if missing:
    print(f"[!] Missing expected variable(s): {missing}")
    exit(1)

# Reconstruct final payload
# Order is explicitly: part1 + part2 + part3 + part4
final_payload = (
    decoded_vars['____'] +
    decoded_vars['_____'] +
    decoded_vars['______'] +
    decoded_vars['_______']
)


# Attempt to detect if the payload is marshal-loadable
try:
    if final_payload.startswith(b'c'):  # possible code object
        # Try loading to verify
        code_obj = marshal.loads(final_payload)

        # If successful, prepend Python 3.11 .pyc header
        magic = b'\xf3\r\r\n'             # Python 3.11 magic
        padding = b'\x00' * 12            # Timestamp/hash placeholder
        final_payload = magic + padding + final_payload
        print("[+] Valid marshal object detected; .pyc header prepended.")
    else:
        print("[!] Payload does not appear to start with marshal code object.")
except Exception as e:
    print(f"[!] Failed marshal check: {e}")

# Output to binary file
output_path = "final_payload.pyc"
with open(output_path, "wb") as f:
    f.write(final_payload)

print(f"[✓] Final payload written to: {output_path}")

