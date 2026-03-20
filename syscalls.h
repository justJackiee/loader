#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <windows.h>

/*
 * VX_TABLE: Holds data for Hell's Gate / Halo's Gate SSN resolution
 */
typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 dwHash;
	WORD    wSSN;
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtAllocateVirtualMemory;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
	VX_TABLE_ENTRY NtWriteVirtualMemory;
	VX_TABLE_ENTRY NtOpenProcess;
	VX_TABLE_ENTRY NtCreateThreadEx;
} VX_TABLE, *PVX_TABLE;

/*
 * Hash values for the syscall names (DJB2 with seed 0x35)
 */
#define HASH_NtAllocateVirtualMemory 0x057254690c99987c
#define HASH_NtProtectVirtualMemory  0x47f621482c3151f8
#define HASH_NtWriteVirtualMemory    0x59116798b7d60ac2
#define HASH_NtOpenProcess           0x83fc6c6227545988
#define HASH_NtCreateThreadEx        0x6de5855f745c6c60

/*
 * NTSTATUS Definitions
 */
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _MY_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} MY_UNICODE_STRING, *PMY_UNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PMY_UNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

/*
 * Function Prototypes
 */
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);
BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry);
PVOID GetNtDllBase();
BOOL InitializeVxTable(PVX_TABLE pVxTable);

/*
 * NT System Call Wrappers
 */
NTSTATUS SysNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect, PVX_TABLE_ENTRY pEntry);
NTSTATUS SysNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection, PVX_TABLE_ENTRY pEntry);
NTSTATUS SysNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten, PVX_TABLE_ENTRY pEntry);
NTSTATUS SysNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId, PVX_TABLE_ENTRY pEntry);
NTSTATUS SysNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaxStackSize, PVOID AttributeList, PVX_TABLE_ENTRY pEntry);

/*
 * Assembly helper (HellDescent)
 * Sets EAX = SSN, R10 = RCX, then executes syscall
 */
extern NTSTATUS HellDescent();

#endif // SYSCALLS_H
