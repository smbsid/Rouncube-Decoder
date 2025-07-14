#!/usr/bin/python3
import argparse
from base64 import b64decode
from Crypto.Cipher import DES3

def fix_base64_padding(b64):
    b64 = b64.strip()
    remainder = len(b64) % 4

    if remainder == 1:
        raise ValueError("Invalid base64 input: appears truncated (missing character, not just padding). Make sure you copied the full string.")
    elif remainder == 2:
        b64 += '=='
    elif remainder == 3:
        b64 += '='

    return b64

def remove_pkcs7_padding(data):
    pad = data[-1]
    if 0 < pad <= 8:
        return data[:-pad]
    return data

def main():
    parser = argparse.ArgumentParser(
        description='Decrypt a DES3-encrypted base64 string from Roundcube config.',
        epilog="⚠️ If decryption fails, make sure the base64 string ends with a '/' or '==' — some characters may be missing when copy-pasting."
    )
    parser.add_argument('--key', required=True, help='24-byte encryption key as plain string (e.g., from Roundcube config).')
    parser.add_argument('--b64', required=True, help='Base64-encoded encrypted password (watch out for missing trailing characters like `/`).')

    args = parser.parse_args()
    key = args.key.encode()
    b64 = args.b64

    if len(key) != 24:
        print("[-] Error: The key must be exactly 24 bytes long.")
        return

    try:
        b64 = fix_base64_padding(b64)
        data = b64decode(b64)
    except Exception as e:
        print(f"[-] Failed to decode base64: {e}")
        return

    iv = data[:8]
    enc = data[8:]

    try:
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc)
        decrypted = remove_pkcs7_padding(decrypted)
        print(f'[+] Decrypted password: {decrypted.decode()}')
    except Exception as e:
        print(f"[-] Decryption failed: {e}")

if __name__ == '__main__':
    main()
