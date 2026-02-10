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

def auto_detect(value):
    value = value.strip()

    if value.isascii() and value.isprintable() and not value.startswith("$"):
        return "0"

    if value[:2].isdigit() and all(c in "0123456789ABCDEFabcdef" for c in value):
        return "7"

    if value.startswith("$1$"):
        return "5"

    if value.startswith("$8$"):
        return "8"

    if value.startswith("$9$"):
        return "9"

    return "unknown"

def audit_value(value, forced_type=None):
    t = forced_type or auto_detect(value)

    print("\nResultado de auditoría:\n")

    if t == "0":
        print("[TYPE 0] Texto plano  !!! CRÍTICO")
        print("Valor:", value)

    elif t == "7":
        print("[TYPE 7] Ofuscado reversible  !!! INSEGURO")
        print("Texto claro:", decode_type7(value))

    elif t == "5":
        print("[TYPE 5] Hash MD5  ⚠ LEGACY")
        print("No reversible (correcto)")

    elif t == "8":
        print("[TYPE 8] PBKDF2-SHA256  + BUENO")
        print("No reversible (correcto)")

    elif t == "9":
        print("[TYPE 9] scrypt  +++ BEST PRACTICE")
        print("No reversible (correcto)")

    else:
        print("[DESCONOCIDO]")
        print("Valor:", value)

def menu():
    print("""
Cisco Credential Auditor

1) Pegar valor (auto-detectar tipo)
2) Seleccionar tipo manualmente
0) Salir
""")

while True:
    menu()
    opt = input("Opción: ").strip()

    if opt == "0":
        break

    elif opt == "1":
        v = input("Pega el valor: ").strip()
        audit_value(v)

    elif opt == "2":
        print("""
Tipos disponibles:
0 = Texto plano
7 = Cisco type 7
5 = MD5
8 = PBKDF2-SHA256
9 = scrypt
""")
        t = input("Selecciona tipo: ").strip()
        v = input("Pega el valor: ").strip()
        audit_value(v, forced_type=t)

    else:
        print("Opción inválida")
