#!/usr/bin/env python3

import argparse, os, time, hashlib, matplotlib.pyplot as plt
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# ---------- Utility functions ----------
def read_file(path): 
    with open(path, "rb") as f: return f.read()

def write_file(path, data):
    with open(path, "wb") as f: f.write(data)

def pkcs7_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

# ---------- AES ----------
def generate_aes_key(bits):
    key = get_random_bytes(bits // 8)
    filename = f"aes_key_{bits}.bin"
    write_file(filename, key)
    print(f"[+] AES-{bits} key generated: {filename}")
    return key

def aes_encrypt(input_file, output_file, keysize, mode):
    keyfile = f"aes_key_{keysize}.bin"
    if not os.path.exists(keyfile):
        generate_aes_key(keysize)
    key = read_file(keyfile)
    data = read_file(input_file)

    if mode == "ecb":
        cipher = AES.new(key, AES.MODE_ECB)
        padded = pkcs7_pad(data)
        ct = cipher.encrypt(padded)
        write_file(output_file, ct)
        print(f"[+] AES-{keysize}-ECB encryption done → {output_file}")
    elif mode == "cfb":
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        ct = iv + cipher.encrypt(data)
        write_file(output_file, ct)
        print(f"[+] AES-{keysize}-CFB encryption done → {output_file}")
    else:
        print("[x] Unsupported mode. Use ecb or cfb.")

def aes_decrypt(input_file, output_file, keysize, mode):
    key = read_file(f"aes_key_{keysize}.bin")
    ct = read_file(input_file)
    if mode == "ecb":
        cipher = AES.new(key, AES.MODE_ECB)
        pt = pkcs7_unpad(cipher.decrypt(ct))
    elif mode == "cfb":
        iv, ciphertext = ct[:16], ct[16:]
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        pt = cipher.decrypt(ciphertext)
    write_file(output_file, pt)
    print(f"[+] AES-{keysize}-{mode.upper()} decryption done → {output_file}")

# ---------- RSA ----------
def rsa_generate(bits):
    key = RSA.generate(bits)
    write_file("private.pem", key.export_key())
    write_file("public.pem", key.publickey().export_key())
    print(f"[+] RSA-{bits} keypair generated → private.pem & public.pem")

def rsa_encrypt(input_file, output_file):
    pub = RSA.import_key(read_file("public.pem"))
    data = read_file(input_file)
    cipher = PKCS1_OAEP.new(pub)
    ct = cipher.encrypt(data)
    write_file(output_file, ct)
    print(f"[+] RSA encryption done → {output_file}")

def rsa_decrypt(input_file, output_file):
    priv = RSA.import_key(read_file("private.pem"))
    data = read_file(input_file)
    cipher = PKCS1_OAEP.new(priv)
    pt = cipher.decrypt(data)
    write_file(output_file, pt)
    print(f"[+] RSA decryption done → {output_file}")

def rsa_sign(input_file, output_file):
    priv = RSA.import_key(read_file("private.pem"))
    data = read_file(input_file)
    h = SHA256.new(data)
    signature = pkcs1_15.new(priv).sign(h)
    write_file(output_file, signature)
    print(f"[+] RSA signature created → {output_file}")

def rsa_verify(input_file, signature_file):
    pub = RSA.import_key(read_file("public.pem"))
    data = read_file(input_file)
    signature = read_file(signature_file)
    h = SHA256.new(data)
    try:
        pkcs1_15.new(pub).verify(h, signature)
        print("[✓] Signature verification successful")
    except (ValueError, TypeError):
        print("[✗] Signature verification failed")

# ---------- SHA-256 ----------
def sha256_hash(input_file):
    with open(input_file, "rb") as f:
        h = hashlib.sha256(f.read()).hexdigest()
    print(f"[+] SHA-256 hash of {input_file}:\n{h}")

# ---------- Timing ----------
def measure_aes():
    sizes = [128, 192, 256]
    data = b"A" * 1024 * 10
    times = []
    for s in sizes:
        key = get_random_bytes(s // 8)
        cipher = AES.new(key, AES.MODE_ECB)
        start = time.perf_counter()
        cipher.encrypt(pkcs7_pad(data))
        end = time.perf_counter()
        t = end - start
        times.append(t)
        print(f"AES-{s}: {t:.6f}s")
    plt.plot(sizes, times, marker='o')
    plt.title("AES Encryption Time vs Key Size")
    plt.xlabel("Key Size (bits)")
    plt.ylabel("Time (seconds)")
    plt.grid(True)
    plt.savefig("aes_time.png")
    plt.show()

def measure_rsa():
    sizes = [512, 1024, 2048, 3072, 4096]
    data = b"RSA test data"
    times = []
    for s in sizes:
        key = RSA.generate(s)
        cipher = PKCS1_OAEP.new(key.publickey())
        start = time.perf_counter()
        cipher.encrypt(data)
        end = time.perf_counter()
        t = end - start
        times.append(t)
        print(f"RSA-{s}: {t:.6f}s")
    plt.plot(sizes, times, marker='o')
    plt.title("RSA Encryption Time vs Key Size")
    plt.xlabel("Key Size (bits)")
    plt.ylabel("Time (seconds)")
    plt.grid(True)
    plt.savefig("rsa_time.png")
    plt.show()

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="Crypto Lab 4 Command Line Tool")
    sub = parser.add_subparsers(dest="cmd")

    aes = sub.add_parser("aes")
    aes.add_argument("--encrypt", action="store_true")
    aes.add_argument("--decrypt", action="store_true")
    aes.add_argument("--mode", choices=["ecb", "cfb"], required=True)
    aes.add_argument("--keysize", type=int, choices=[128, 192, 256], required=True)
    aes.add_argument("--input", required=True)
    aes.add_argument("--output", required=True)

    rsa = sub.add_parser("rsa")
    rsa.add_argument("--generate", action="store_true")
    rsa.add_argument("--keysize", type=int, default=2048)
    rsa.add_argument("--encrypt", action="store_true")
    rsa.add_argument("--decrypt", action="store_true")
    rsa.add_argument("--sign", action="store_true")
    rsa.add_argument("--verify", action="store_true")
    rsa.add_argument("--input")
    rsa.add_argument("--output")
    rsa.add_argument("--signature")

    h = sub.add_parser("hash")
    h.add_argument("--input", required=True)

    m = sub.add_parser("measure")
    m.add_argument("--algo", choices=["aes", "rsa"], required=True)

    args = parser.parse_args()

    if args.cmd == "aes":
        if args.encrypt: aes_encrypt(args.input, args.output, args.keysize, args.mode)
        elif args.decrypt: aes_decrypt(args.input, args.output, args.keysize, args.mode)
    elif args.cmd == "rsa":
        if args.generate: rsa_generate(args.keysize)
        elif args.encrypt: rsa_encrypt(args.input, args.output)
        elif args.decrypt: rsa_decrypt(args.input, args.output)
        elif args.sign: rsa_sign(args.input, args.output)
        elif args.verify: rsa_verify(args.input, args.signature)
    elif args.cmd == "hash":
        sha256_hash(args.input)
    elif args.cmd == "measure":
        measure_aes() if args.algo == "aes" else measure_rsa()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
