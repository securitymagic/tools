# GIves a JSON output of simple text response to use in Fiddler AutoResponder against ConvertMate UpdateRetreiver file 4f6d977574cba1eaae21406d60a93e9c

import hashlib
import json
from Crypto.Cipher import AES
from datetime import datetime

def get_aes_key(install_date: str) -> bytes:
    return hashlib.sha256(install_date.encode('utf-8')).digest()

def get_aes_iv(current_date: str) -> bytes:
    return hashlib.md5(current_date.encode('utf-8')).digest()

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    padding = bytes([pad_len] * pad_len)
    return data + padding

def aes_encrypt_for_dotnet(plaintext: str, install_date: str, current_date: str) -> str:
    key = get_aes_key(install_date)
    iv = get_aes_iv(current_date)

    plaintext_bytes = plaintext.encode('utf-8')
    padded_bytes = pkcs7_pad(plaintext_bytes, 16)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_bytes)

    byte_array = list(ciphertext)
    return json.dumps(byte_array)

# === Usage ===

install_date = "2025-11-03 20:07:21"
current_date = datetime.utcnow().strftime("%Y%m%d%H%M%S")
# For exact matching:
# current_date = "20251104080940"

plaintext = '{"data":"decryption test success!"}'

encrypted_json = aes_encrypt_for_dotnet(plaintext, install_date, current_date)
print(encrypted_json)
