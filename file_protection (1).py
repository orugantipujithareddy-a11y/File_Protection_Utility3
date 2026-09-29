import argparse, getpass, hashlib, hmac, os, struct, sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC=b"FPU1"; KEY_SIZE=32; HMAC_SIZE=32; PBKDF2_ITERATIONS=600_000
HEADER=MAGIC+struct.pack(">I", PBKDF2_ITERATIONS)

def derive_keys(password, salt, iterations):
    kdf=PBKDF2HMAC(algorithm=hashes.SHA256(), length=64, salt=salt, iterations=iterations)
    material=kdf.derive(password.encode())
    return material[:32], material[32:]

def encrypt_bytes(data, password):
    salt=os.urandom(16); iv=os.urandom(16)
    aes_key, mac_key=derive_keys(password, salt, PBKDF2_ITERATIONS)
    padder=padding.PKCS7(algorithms.AES.block_size).padder()
    padded=padder.update(data)+padder.finalize()
    enc=Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ciphertext=enc.update(padded)+enc.finalize()
    body=HEADER+salt+iv+ciphertext
    tag=hmac.new(mac_key, body, hashlib.sha256).digest()
    return body+tag

def decrypt_bytes(blob, password):
    if len(blob)<40+HMAC_SIZE or blob[:4]!=MAGIC:
        raise ValueError("Invalid encrypted file format.")
    iterations=struct.unpack(">I", blob[4:8])[0]
    salt,iv,ciphertext,tag=blob[8:24],blob[24:40],blob[40:-32],blob[-32:]
    _,mac_key=derive_keys(password,salt,iterations)
    expected=hmac.new(mac_key,blob[:-32],hashlib.sha256).digest()
    if not hmac.compare_digest(tag,expected):
        raise ValueError("Integrity check failed: wrong password or file was modified.")
    aes_key,_=derive_keys(password,salt,iterations)
    dec=Cipher(algorithms.AES(aes_key),modes.CBC(iv)).decryptor()
    padded=dec.update(ciphertext)+dec.finalize()
    unpad=padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpad.update(padded)+unpad.finalize()

def get_password(confirm=False):
    p=getpass.getpass("Password: ")
    if confirm:
        q=getpass.getpass("Confirm password: ")
        if p!=q: raise ValueError("Passwords do not match.")
    if not p: raise ValueError("Password cannot be empty.")
    return p

def main():
    parser=argparse.ArgumentParser(description="AES-256 file encryption with PBKDF2 and HMAC-SHA256.")
    sub=parser.add_subparsers(dest="command",required=True)
    for name in ("encrypt","decrypt"):
        p=sub.add_parser(name); p.add_argument("input",type=Path); p.add_argument("output",type=Path)
    p=sub.add_parser("verify"); p.add_argument("input",type=Path)
    args=parser.parse_args()
    try:
        if args.command=="encrypt":
            if not args.input.is_file(): raise FileNotFoundError(args.input)
            args.output.write_bytes(encrypt_bytes(args.input.read_bytes(),get_password(True)))
            print(f"Encrypted: {args.input} -> {args.output}")
            print("AES-256-CBC encryption complete.")
            print("HMAC-SHA256 integrity tag added.")
        elif args.command=="decrypt":
            if not args.input.is_file(): raise FileNotFoundError(args.input)
            plaintext=decrypt_bytes(args.input.read_bytes(),get_password())
            args.output.write_bytes(plaintext)
            print("Integrity verified.")
            print(f"Decrypted: {args.input} -> {args.output}")
        else:
            if not args.input.is_file(): raise FileNotFoundError(args.input)
            decrypt_bytes(args.input.read_bytes(),get_password())
            print(f"Integrity verification PASSED: {args.input}")
        return 0
    except (OSError,ValueError) as e:
        print(f"ERROR: {e}",file=sys.stderr); return 1

if __name__=="__main__": raise SystemExit(main())
