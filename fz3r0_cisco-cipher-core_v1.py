#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Decoderfy - Cisco Credential Auditor (Cisco-faithful)

Supports (Cisco IOS style):
- Type 0  : plaintext (no hashing)
- Type 4  : SHA256, unsalted, encoded with Cisco itoa64 (43 chars)  [enable secret 4 <hash>]
- Type 5  : MD5Crypt ($1$<salt>$<hash>)                             [enable secret 5 $1$...]
- Type 7  : Cisco reversible XOR obfuscation                         [password 7 <hex>]
- Type 8  : PBKDF2-HMAC-SHA256 ($8$<salt>$<hash>) rounds=20000       [enable secret 8 $8$...]
- Type 9  : scrypt ($9$<salt>$<hash>) N=16384 r=1 p=1               [enable secret 9 $9$...]

No passlib.
No system "crypt" module required (Python 3.13 removed it on many distros).

Notes:
- Type 7 is reversible (decode).
- Types 4/5/8/9 are one-way (verify only). Encode is supported.
"""

import os
import re
import sys
import hmac
import hashlib
import secrets

# ============================================================
# Cisco Type 7 XOR table
# ============================================================

TYPE7_KEY = [
    0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f,
    0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72,
    0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53,
    0x55, 0x42
]

# ============================================================
# Cisco itoa64 alphabet (same concept used by MD5Crypt + Cisco types 4/8/9)
# IMPORTANT: this is the alphabet used by hashcat modules for Cisco IOS type 4/8/9.
# ============================================================

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
ITOA64_INDEX = {c: i for i, c in enumerate(ITOA64)}

# ============================================================
# Helpers
# ============================================================

def pause():
    input("\nPress Enter to continue...")

def banner(verbose: bool):
    print("\n=== Decoderfy - Cisco Credential Auditor ===")
    print("Verbose:", "ON" if verbose else "OFF")
    print("Cisco Type4 (SHA256): OK")
    print("Cisco Type5 ($1$ md5crypt): OK (pure python)")
    print("Cisco Type8 ($8$ pbkdf2-sha256): OK (hashlib.pbkdf2_hmac)")
    print("Cisco Type9 ($9$ scrypt): OK (hashlib.scrypt)")
    print("Type7: OK (Cisco XOR)")

def normalize_input(s: str) -> str:
    """
    Accepts things like:
      '9 $9$....'
      '8 $8$....'
      '4 <hash>'
      'secret 9 $9$....'
    and returns the core hash/value.
    """
    s = s.strip()

    # strip common CLI prefixes
    s = re.sub(r"^(enable\s+secret|username\s+\S+\s+secret|password)\s+", "", s, flags=re.IGNORECASE).strip()

    # strip leading type number (e.g. "9 $9$...", "4 <hash>", "7 071B...")
    m = re.match(r"^(\d+)\s+(.*)$", s)
    if m:
        s = m.group(2).strip()

    return s

def is_hex_string(s: str) -> bool:
    return all(c in "0123456789abcdefABCDEF" for c in s)

def is_itoa64_string(s: str) -> bool:
    return all(c in ITOA64 for c in s)

# ============================================================
# Cisco itoa64 base64 (hashcat calls it base64b with itoa64 alphabet)
# This is NOT standard base64 alphabet and does NOT use '=' padding in Cisco strings.
# For 32 bytes input -> 43 chars output.
# ============================================================

def itoa64_encode(data: bytes) -> str:
    """
    Encode bytes into Cisco/crypt-style base64 using ITOA64 alphabet.
    Produces no '=' padding.
    """
    out = []
    i = 0
    n = len(data)

    while i + 3 <= n:
        v = (data[i] << 16) | (data[i+1] << 8) | data[i+2]
        out.append(ITOA64[(v >> 18) & 0x3f])
        out.append(ITOA64[(v >> 12) & 0x3f])
        out.append(ITOA64[(v >> 6) & 0x3f])
        out.append(ITOA64[v & 0x3f])
        i += 3

    rem = n - i
    if rem == 1:
        v = data[i] << 16
        out.append(ITOA64[(v >> 18) & 0x3f])
        out.append(ITOA64[(v >> 12) & 0x3f])
        # no padding chars in Cisco strings
    elif rem == 2:
        v = (data[i] << 16) | (data[i+1] << 8)
        out.append(ITOA64[(v >> 18) & 0x3f])
        out.append(ITOA64[(v >> 12) & 0x3f])
        out.append(ITOA64[(v >> 6) & 0x3f])
        # no padding chars

    return "".join(out)

def itoa64_decode(s: str) -> bytes:
    """
    Decode Cisco/crypt-style itoa64 string back into bytes.
    Used mainly for md5crypt internal steps if needed.
    """
    # Convert 4 chars -> 3 bytes, but the string may be non-multiple of 4.
    vals = []
    for ch in s:
        if ch not in ITOA64_INDEX:
            raise ValueError(f"Invalid itoa64 char: {ch!r}")
        vals.append(ITOA64_INDEX[ch])

    out = bytearray()
    i = 0
    while i < len(vals):
        chunk = vals[i:i+4]
        if len(chunk) >= 2:
            v = (chunk[0] << 18) | (chunk[1] << 12)
            b0 = (v >> 16) & 0xff
            out.append(b0)
        if len(chunk) >= 3:
            v |= (chunk[2] << 6)
            b1 = (v >> 8) & 0xff
            out.append(b1)
        if len(chunk) >= 4:
            v |= chunk[3]
            b2 = v & 0xff
            out.append(b2)
        i += 4
    return bytes(out)

def gen_salt_itoa64(length: int = 14) -> str:
    return "".join(secrets.choice(ITOA64) for _ in range(length))

# ============================================================
# Type 7 (Cisco reversible XOR)
# ============================================================

def encode_type7(plaintext: str, offset: int = 7, verbose: bool = False) -> str:
    if not (0 <= offset < len(TYPE7_KEY)):
        raise ValueError(f"Offset must be 0..{len(TYPE7_KEY)-1}")

    result = f"{offset:02d}"

    if verbose:
        print("\n=== TYPE 7 ENCODE ===")
        print("Plaintext:", plaintext)
        print("Offset:", offset)
        print("\nidx | plain | key_idx | key  | cipher")
        print("----+-------+---------+------+-------")

    for i, ch in enumerate(plaintext):
        key_index = (offset + i) % len(TYPE7_KEY)
        cipher = ord(ch) ^ TYPE7_KEY[key_index]
        result += f"{cipher:02X}"

        if verbose:
            print(f"{i:<3} | 0x{ord(ch):02x}  | {key_index:<7} | 0x{TYPE7_KEY[key_index]:02x} | 0x{cipher:02x}")

    return result

def decode_type7(ciphertext: str, verbose: bool = False) -> str:
    ciphertext = ciphertext.strip()
    if len(ciphertext) < 4:
        raise ValueError("Type 7 string too short.")
    offset = int(ciphertext[:2])
    hexdata = ciphertext[2:]
    if len(hexdata) % 2 != 0 or not is_hex_string(hexdata):
        raise ValueError("Type 7 hex payload invalid.")
    if not (0 <= offset < len(TYPE7_KEY)):
        raise ValueError("Type 7 offset out of range.")

    out = []

    if verbose:
        print("\n=== TYPE 7 DECODE ===")
        print("Input:", ciphertext)
        print("Offset:", offset)
        print("\nidx | cipher | key_idx | key  | plain | ascii")
        print("----+--------+---------+------+-------+------")

    for idx in range(0, len(hexdata), 2):
        byte = int(hexdata[idx:idx+2], 16)
        key_index = (offset + (idx // 2)) % len(TYPE7_KEY)
        plain = byte ^ TYPE7_KEY[key_index]
        out.append(chr(plain))

        if verbose:
            ch = chr(plain) if 32 <= plain <= 126 else "."
            print(f"{idx//2:<3} | 0x{byte:02x}   | {key_index:<7} | 0x{TYPE7_KEY[key_index]:02x} | 0x{plain:02x} |  {ch}")

    return "".join(out)

# ============================================================
# Type 4 (Cisco-IOS type 4 SHA256) - unsalted
# Stored as 43 chars itoa64 of sha256(password) digest (32 bytes)
# ============================================================

def encode_type4(password: str) -> str:
    d = hashlib.sha256(password.encode("utf-8")).digest()
    return itoa64_encode(d)[:43]

def verify_type4(stored_hash: str, candidate: str) -> bool:
    return hmac.compare_digest(stored_hash, encode_type4(candidate))

# ============================================================
# Type 8 (Cisco-IOS type 8 PBKDF2-SHA256)
# Format: $8$<14-char-salt>$<43-char-hash>
# Rounds: 20000, dklen=32
# ============================================================

TYPE8_ROUNDS = 20000
TYPE8_SALT_LEN = 14

def encode_type8(password: str, salt: str | None = None) -> str:
    if salt is None:
        salt = gen_salt_itoa64(TYPE8_SALT_LEN)
    if len(salt) != TYPE8_SALT_LEN or not is_itoa64_string(salt):
        raise ValueError("Type 8 salt must be 14 chars from Cisco itoa64 alphabet.")

    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), TYPE8_ROUNDS, dklen=32)
    h = itoa64_encode(dk)[:43]
    return f"$8${salt}${h}"

def verify_type8(stored: str, candidate: str) -> bool:
    m = re.match(r"^\$8\$(?P<salt>.{14})\$(?P<h>.{43})$", stored)
    if not m:
        return False
    salt = m.group("salt")
    h = m.group("h")
    if not is_itoa64_string(salt) or not is_itoa64_string(h):
        return False
    calc = encode_type8(candidate, salt=salt)
    return hmac.compare_digest(calc, stored)

# ============================================================
# Type 9 (Cisco-IOS type 9 scrypt)
# Format: $9$<14-char-salt>$<43-char-hash>
# Params: N=16384, r=1, p=1, dklen=32
# ============================================================

TYPE9_N = 2**14
TYPE9_R = 1
TYPE9_P = 1
TYPE9_SALT_LEN = 14

def encode_type9(password: str, salt: str | None = None) -> str:
    if salt is None:
        salt = gen_salt_itoa64(TYPE9_SALT_LEN)
    if len(salt) != TYPE9_SALT_LEN or not is_itoa64_string(salt):
        raise ValueError("Type 9 salt must be 14 chars from Cisco itoa64 alphabet.")

    dk = hashlib.scrypt(
        password=password.encode("utf-8"),
        salt=salt.encode("ascii"),
        n=TYPE9_N,
        r=TYPE9_R,
        p=TYPE9_P,
        dklen=32
    )
    h = itoa64_encode(dk)[:43]
    return f"$9${salt}${h}"

def verify_type9(stored: str, candidate: str) -> bool:
    m = re.match(r"^\$9\$(?P<salt>.{14})\$(?P<h>.{43})$", stored)
    if not m:
        return False
    salt = m.group("salt")
    h = m.group("h")
    if not is_itoa64_string(salt) or not is_itoa64_string(h):
        return False
    calc = encode_type9(candidate, salt=salt)
    return hmac.compare_digest(calc, stored)

# ============================================================
# Type 5 (MD5Crypt) - $1$<salt>$<hash>
# Pure python implementation of traditional md5crypt.
# ============================================================

_MD5_MAGIC = b"$1$"

def _md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()

def _to64(v: int, n: int) -> str:
    # crypt-style base64 for md5crypt uses the same itoa64 alphabet
    s = []
    for _ in range(n):
        s.append(ITOA64[v & 0x3f])
        v >>= 6
    return "".join(s)

def md5crypt(password: str, salt: str) -> str:
    """
    Return full md5crypt string: $1$<salt>$<hash>
    Salt max 8 chars in traditional md5crypt; Cisco commonly uses <=8.
    """
    pw = password.encode("utf-8")

    # salt rules
    salt = salt.split("$")[0]
    salt = salt[:8]
    salt_b = salt.encode("utf-8")

    # Initial context
    ctx = hashlib.md5()
    ctx.update(pw)
    ctx.update(_MD5_MAGIC)
    ctx.update(salt_b)

    # Alternate sum
    alt = _md5(pw + salt_b + pw)

    # Mix in alternate sum for length of password
    pw_len = len(pw)
    for i in range(pw_len):
        ctx.update(alt[i % 16:i % 16 + 1])

    # Weird XOR-like step
    i = pw_len
    while i:
        if i & 1:
            ctx.update(b"\x00")
        else:
            ctx.update(pw[:1])
        i >>= 1

    final = ctx.digest()

    # 1000 rounds
    for i in range(1000):
        ctx_i = hashlib.md5()
        if i & 1:
            ctx_i.update(pw)
        else:
            ctx_i.update(final)

        if i % 3:
            ctx_i.update(salt_b)
        if i % 7:
            ctx_i.update(pw)

        if i & 1:
            ctx_i.update(final)
        else:
            ctx_i.update(pw)

        final = ctx_i.digest()

    # Rearrangement + base64 encoding
    # This layout is standard md5crypt
    l = [
        (final[0] << 16) | (final[6] << 8) | final[12],
        (final[1] << 16) | (final[7] << 8) | final[13],
        (final[2] << 16) | (final[8] << 8) | final[14],
        (final[3] << 16) | (final[9] << 8) | final[15],
        (final[4] << 16) | (final[10] << 8) | final[5],
    ]
    out = ""
    out += _to64(l[0], 4)
    out += _to64(l[1], 4)
    out += _to64(l[2], 4)
    out += _to64(l[3], 4)
    out += _to64(l[4], 4)
    out += _to64(final[11], 2)

    return f"$1${salt}${out}"

def encode_type5(password: str, salt: str | None = None) -> str:
    if salt is None:
        # md5crypt salt typically 0-8 chars; use 8.
        salt = "".join(secrets.choice(ITOA64) for _ in range(8))
    # keep only allowed md5crypt salt chars and max 8
    salt = re.sub(r"[^./0-9A-Za-z]", "", salt)[:8]
    if not salt:
        raise ValueError("Invalid salt for type 5.")
    return md5crypt(password, salt)

def verify_type5(stored: str, candidate: str) -> bool:
    m = re.match(r"^\$1\$(?P<salt>[^$]{1,8})\$(?P<h>[^$]+)$", stored)
    if not m:
        return False
    salt = m.group("salt")
    calc = md5crypt(candidate, salt)
    return hmac.compare_digest(calc, stored)

# ============================================================
# Auto detect + verify dispatcher
# ============================================================

def auto_detect(value: str) -> str:
    """
    Returns: "0","4","5","7","8","9"
    """
    v = normalize_input(value)

    if v.startswith("$9$"):
        return "9"
    if v.startswith("$8$"):
        return "8"
    if v.startswith("$1$"):
        return "5"

    # Type 7: starts with 2 digits + hex payload
    if len(v) >= 4 and v[:2].isdigit() and is_hex_string(v[2:]) and (len(v[2:]) % 2 == 0):
        return "7"

    # Type 4: 43 chars, itoa64-only (Cisco stores it without "$4$")
    if len(v) == 43 and is_itoa64_string(v):
        return "4"

    # Otherwise treat as plaintext type 0
    return "0"

def verify_any(stored: str, candidate: str) -> tuple[bool, str]:
    v = normalize_input(stored)
    t = auto_detect(v)

    if t == "0":
        return (v == candidate, "0")
    if t == "4":
        return (verify_type4(v, candidate), "4")
    if t == "5":
        return (verify_type5(v, candidate), "5")
    if t == "7":
        try:
            return (decode_type7(v) == candidate, "7")
        except Exception:
            return (False, "7")
    if t == "8":
        return (verify_type8(v, candidate), "8")
    if t == "9":
        return (verify_type9(v, candidate), "9")

    return (False, "0")

# ============================================================
# CLI Menu
# ============================================================

def menu_decode(verbose: bool):
    value = input("Paste value: ").strip()
    value = normalize_input(value)
    t = auto_detect(value)
    print("Detected:", t)

    if t == "7":
        print("\nDecoded:", decode_type7(value, verbose=verbose))
    else:
        print("\nDecode is only available for Type 7 (reversible).")
    pause()

def menu_encode(verbose: bool):
    print("\n1) Type 7 (Cisco reversible)")
    print("2) Type 4 (Cisco SHA256, unsalted)")
    print("3) Type 5 (Cisco MD5Crypt $1$)")
    print("4) Type 8 (Cisco PBKDF2-SHA256 $8$)")
    print("5) Type 9 (Cisco scrypt $9$)")
    print("6) All supported types")
    choice = input("Select: ").strip()

    password = input("Plaintext: ")

    if choice == "1":
        print("Type7 ->", encode_type7(password, verbose=verbose))
    elif choice == "2":
        print("Type4 ->", encode_type4(password))
    elif choice == "3":
        print("Type5 ->", encode_type5(password))
    elif choice == "4":
        print("Type8 ->", encode_type8(password))
    elif choice == "5":
        print("Type9 ->", encode_type9(password))
    elif choice == "6":
        print("Type7 ->", encode_type7(password, verbose=verbose))
        print("Type4 ->", encode_type4(password))
        print("Type5 ->", encode_type5(password))
        print("Type8 ->", encode_type8(password))
        print("Type9 ->", encode_type9(password))
    else:
        print("Invalid option.")
    pause()

def menu_audit():
    stored = input("Paste stored hash/value: ").strip()
    stored_norm = normalize_input(stored)
    detected = auto_detect(stored_norm)
    print("Detected:", detected)

    print("\n1) Single password")
    print("2) Dictionary file")
    mode = input("Select: ").strip()

    if mode == "1":
        candidate = input("Enter candidate password: ")
        ok, t = verify_any(stored_norm, candidate)
        print("RESULT:", "MATCH" if ok else "NO MATCH")
    elif mode == "2":
        filename = input("Dictionary file path: ").strip()
        if not os.path.exists(filename):
            print("File not found.")
            pause()
            return
        with open(filename, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                cand = line.rstrip("\n")
                ok, _ = verify_any(stored_norm, cand)
                if ok:
                    print("MATCH FOUND:", cand)
                    break
            else:
                print("No match found.")
    else:
        print("Invalid option.")
    pause()

def menu_generate_type7_variants():
    password = input("Plaintext: ")
    for offset in range(len(TYPE7_KEY)):
        print(f"{offset:02d} -> {encode_type7(password, offset)}")
    pause()

def main():
    verbose = input("Verbose mode? (y/N): ").strip().lower() == "y"

    while True:
        banner(verbose)

        print("\n1) Decode")
        print("2) Encode")
        print("3) Audit / Verify")
        print("4) Generate all Type 7 variants")
        print("0) Exit")

        choice = input("\nSelect: ").strip()

        if choice == "1":
            menu_decode(verbose)
        elif choice == "2":
            menu_encode(verbose)
        elif choice == "3":
            menu_audit()
        elif choice == "4":
            menu_generate_type7_variants()
        elif choice == "0":
            sys.exit(0)
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
