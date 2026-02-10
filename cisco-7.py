#!/usr/bin/env python3

KEY = [
    0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f,
    0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72,
    0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53,
    0x55, 0x42
]

def decode_type7(enc):
    offset = int(enc[:2])
    enc = enc[2:]
    out = ""

    for i in range(0, len(enc), 2):
        b = int(enc[i:i+2], 16)
        out += chr(b ^ KEY[(offset + i // 2) % len(KEY)])

    return out

if __name__ == "__main__":
    cipher = input("Agrega lo ofuscado en Cisco 7: ").strip()
    try:
        print("Texto claro:", decode_type7(cipher))
    except Exception as e:
        print("Error: entrada no válida")
