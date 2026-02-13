#!/usr/bin/env python3

import os
import sys
import getpass

# =============================
# TYPE 7 TABLE
# =============================

KEY = [
    0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f,
    0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72,
    0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53,
    0x55, 0x42
]

# =============================
# PASSLIB IMPORT
# =============================

PASSLIB_OK = False

try:
    from passlib.hash import md5_crypt
    from passlib.hash import pbkdf2_sha256
    from passlib.hash import scrypt
    PASSLIB_OK = True
except Exception:
    PASSLIB_OK = False


# =============================
# UTIL
# =============================

def pause():
    input("\nPress Enter to continue...")


def banner(verbose):
    print("\n=== Decoderfy - Cisco Credential Auditor ===")
    print("Verbose:", "ON" if verbose else "OFF")
    print("Passlib:", "OK" if PASSLIB_OK else "NOT AVAILABLE")


# =============================
# TYPE 7
# =============================

def encode_type7(plaintext, offset=7, verbose=False):
    result = f"{offset:02d}"
    if verbose:
        print("\n=== TYPE 7 ENCODE ===")
        print("Plaintext:", plaintext)
        print("Offset:", offset)
        print("\nidx | plain | key_idx | key  | cipher")
        print("----+-------+---------+------+-------")

    for i, char in enumerate(plaintext):
        key_index = (offset + i) % len(KEY)
        cipher = ord(char) ^ KEY[key_index]
        result += f"{cipher:02X}"

        if verbose:
            print(f"{i:<3} | 0x{ord(char):02x}  | {key_index:<7} | 0x{KEY[key_index]:02x} | 0x{cipher:02x}")

    return result


def decode_type7(ciphertext, verbose=False):
    offset = int(ciphertext[:2])
    hexdata = ciphertext[2:]
    output = ""

    if verbose:
        print("\n=== TYPE 7 DECODE ===")
        print("Offset:", offset)
        print("\nidx | cipher | key_idx | key  | plain")
        print("----+--------+---------+------+-------")

    for i in range(0, len(hexdata), 2):
        byte = int(hexdata[i:i+2], 16)
        key_index = (offset + (i // 2)) % len(KEY)
        plain = byte ^ KEY[key_index]
        output += chr(plain)

        if verbose:
            print(f"{i//2:<3} | 0x{byte:02x}   | {key_index:<7} | 0x{KEY[key_index]:02x} | 0x{plain:02x}")

    return output


# =============================
# TYPE 5 / 8 / 9
# =============================

def encode_type5(password):
    return md5_crypt.hash(password)


def encode_type8(password):
    return pbkdf2_sha256.hash(password)


def encode_type9(password):
    return scrypt.hash(password)


def verify_hash(stored, candidate):

    if stored.startswith("$1$"):
        return md5_crypt.verify(candidate, stored)

    if stored.startswith("$pbkdf2-sha256$"):
        return pbkdf2_sha256.verify(candidate, stored)

    if stored.startswith("$scrypt$"):
        return scrypt.verify(candidate, stored)

    # TYPE 7
    if stored[:2].isdigit() and all(c in "0123456789ABCDEFabcdef" for c in stored):
        return decode_type7(stored) == candidate

    return False


# =============================
# AUTO DETECT
# =============================

def auto_detect(value):
    value = value.strip()

    if value.startswith("$1$"):
        return "5"
    if value.startswith("$pbkdf2-sha256$"):
        return "8"
    if value.startswith("$scrypt$"):
        return "9"
    if value[:2].isdigit() and all(c in "0123456789ABCDEFabcdef" for c in value):
        return "7"
    return "0"


# =============================
# MENU
# =============================

def main():
    verbose = input("Verbose mode? (y/N): ").lower() == "y"

    while True:
        banner(verbose)

        print("\n1) Decode")
        print("2) Encode")
        print("3) Audit / Verify")
        print("4) Generate all Type 7 variants")
        print("0) Exit")

        choice = input("\nSelect: ")

        # ------------------------
        # DECODE
        # ------------------------

        if choice == "1":
            value = input("Paste value: ").strip()
            t = auto_detect(value)
            print("Detected:", t)

            if t == "7":
                print("Decoded:", decode_type7(value, verbose))
            else:
                print("Only Type 7 reversible.")

            pause()

        # ------------------------
        # ENCODE
        # ------------------------

        elif choice == "2":
            print("\n1) Type 7")
            print("2) Type 5")
            print("3) Type 8")
            print("4) Type 9")
            print("5) All types")
            t = input("Select: ")

            password = input("Plaintext: ")
            print("Plaintext entered:", password)

            if t == "1":
                print("Type7 ->", encode_type7(password, verbose=verbose))

            elif t == "2" and PASSLIB_OK:
                print("Type5 ->", encode_type5(password))

            elif t == "3" and PASSLIB_OK:
                print("Type8 ->", encode_type8(password))

            elif t == "4" and PASSLIB_OK:
                print("Type9 ->", encode_type9(password))

            elif t == "5" and PASSLIB_OK:
                print("Type7 ->", encode_type7(password, verbose=verbose))
                print("Type5 ->", encode_type5(password))
                print("Type8 ->", encode_type8(password))
                print("Type9 ->", encode_type9(password))

            else:
                print("Passlib not available.")

            pause()

        # ------------------------
        # AUDIT
        # ------------------------

        elif choice == "3":
            stored = input("Paste stored hash: ").strip()
            print("Detected:", auto_detect(stored))

            print("\n1) Single password")
            print("2) Dictionary file")
            mode = input("Select: ")

            if mode == "1":
                candidate = input("Enter candidate password: ")
                print("RESULT:", "MATCH" if verify_hash(stored, candidate) else "NO MATCH")

            elif mode == "2":
                filename = input("Dictionary file path: ")
                if not os.path.exists(filename):
                    print("File not found.")
                else:
                    with open(filename) as f:
                        for line in f:
                            candidate = line.strip()
                            if verify_hash(stored, candidate):
                                print("MATCH FOUND:", candidate)
                                break
                        else:
                            print("No match found.")

            pause()

        # ------------------------
        # GENERATE ALL TYPE 7
        # ------------------------

        elif choice == "4":
            password = input("Plaintext: ")
            for offset in range(len(KEY)):
                print(f"{offset:02d} -> {encode_type7(password, offset)}")
            pause()

        elif choice == "0":
            sys.exit()

        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
