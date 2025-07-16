#pythonlzma-decode.py >> decodedfile.txt
import lzma
import codecs

# Paste your escaped string here
escaped_blob = (
    r"""\xfd7zXZ\x00\x00\x04\xe6\xd6\xb4F..........................""".strip() #replace with your compressed data code
)

# Step 1: Convert escaped string to raw bytes
blob_bytes = codecs.escape_decode(escaped_blob)[0]

# Step 2: Decompress using lzma
try:
    decompressed = lzma.decompress(blob_bytes, format=lzma.FORMAT_XZ)
    print("Decompressed Output:")
    print(decompressed.decode(errors='replace'))  # or just print(decompressed) for raw bytes
except lzma.LZMAError as e:
    print("Decompression failed:", e)
