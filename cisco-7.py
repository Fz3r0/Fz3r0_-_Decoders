#!/usr/bin/env python3
import binascii

KEY = [
    0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f,
    0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72,
    0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53,
    0x55, 0x42
]

def decode_type7_verbose(enc: str) -> str:
    enc = enc.strip()

    if len(enc) < 4:
        raise ValueError("Too short for Type 7 (needs at least 2 offset chars + 1 byte).")

    if not enc[:2].isdigit():
        raise ValueError("First 2 chars must be digits (offset).")

    offset = int(enc[:2])
    hex_part = enc[2:]

    if len(hex_part) % 2 != 0:
        raise ValueError("Hex payload length must be even.")

    try:
        cipher_bytes = bytes.fromhex(hex_part)
    except ValueError:
        raise ValueError("Payload is not valid hex.")

    print("\n=== Cisco Type 7 Decode (Verbose) ===")
    print(f"Input:        {enc}")
    print(f"Offset:       {offset}")
    print(f"Cipher (hex): {hex_part}")
    print(f"Bytes:        {len(cipher_bytes)}\n")

    out_bytes = bytearray()

    print("idx | cipher | key_idx | key  | plain | ascii")
    print("----+--------+---------+------+-------+------")

    for i, b in enumerate(cipher_bytes):
        key_idx = (offset + i) % len(KEY)
        k = KEY[key_idx]
        p = b ^ k
        out_bytes.append(p)
        ascii_char = chr(p) if 32 <= p <= 126 else "."
        print(f"{i:>3} | 0x{b:02x}   |  {key_idx:>3}    | 0x{k:02x} | 0x{p:02x}  |  {ascii_char}")

    try:
        decoded = out_bytes.decode("utf-8", errors="replace")
    except Exception:
        decoded = out_bytes.decode("latin-1", errors="replace")

    print("\nDecoded text:", decoded)
    return decoded

if __name__ == "__main__":
    s = input("Paste Cisco Type 7 string: ")
    decode_type7_verbose(s)
