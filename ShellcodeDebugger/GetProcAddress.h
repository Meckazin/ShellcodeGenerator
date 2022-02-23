#pragma once
#include <windows.h>
#include <winternl.h>

typedef struct _MY_PEB_LDR_DATA {
	ULONG Length;
	BOOL Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, * PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, * PMY_LDR_DATA_TABLE_ENTRY;

HMODULE GetKernel32BaseAddress() {
	PPEB PebAddress;
	PMY_PEB_LDR_DATA pLdr;
	PMY_LDR_DATA_TABLE_ENTRY pDataTableEntry;
	PVOID pModuleBase;
	PIMAGE_NT_HEADERS pNTHeader;
	DWORD dwExportDirRVA;
	PIMAGE_EXPORT_DIRECTORY pExportDir;
	USHORT usOrdinalTableIndex;

	//PEB offset is always fixed depending or arch
#if defined(_WIN64)
	PebAddress = (PPEB)__readgsqword(0x60);
#else
	PebAddress = (PPEB)__readfsdword(0x30);
#endif

	pLdr = (PMY_PEB_LDR_DATA)PebAddress->Ldr;
	//First one is the current module
	pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pLdr->InLoadOrderModuleList.Flink;
	//Second will be ntdll.dll
	pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pDataTableEntry->InLoadOrderLinks.Flink;
	//And the third will be the Kernel32.dll
	pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pDataTableEntry->InLoadOrderLinks.Flink;

	return (HMODULE)pDataTableEntry->DllBase;
}

HANDLE GetProcAddressPEB()
{
	PPEB PebAddress;
	PMY_PEB_LDR_DATA pLdr;
	PMY_LDR_DATA_TABLE_ENTRY pDataTableEntry;
	PVOID pModuleBase;
	PIMAGE_NT_HEADERS pNTHeader;
	DWORD dwExportDirRVA;
	PIMAGE_EXPORT_DIRECTORY pExportDir;
	USHORT usOrdinalTableIndex;
	PDWORD pdwFunctionNameBase;
	char* pFunctionName;
	DWORD dwNumFunctions;

	//PEB offset is always fixed depending or arch
#if defined(_WIN64)
	PebAddress = (PPEB)__readgsqword(0x60);
#else
	PebAddress = (PPEB)__readfsdword(0x30);
#endif

	pLdr = (PMY_PEB_LDR_DATA)PebAddress->Ldr;
	//First one is the current module
	pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pLdr->InLoadOrderModuleList.Flink;
	//Second will be ntdll.dll
	pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pDataTableEntry->InLoadOrderLinks.Flink;
	//And the third will be the Kernel32.dll
	pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pDataTableEntry->InLoadOrderLinks.Flink;

	if (pDataTableEntry->DllBase != NULL)
	{
		pModuleBase = pDataTableEntry->DllBase; //Kernel32 base address, we need this for using GetProcAddress
		pNTHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pModuleBase + ((PIMAGE_DOS_HEADER)pModuleBase)->e_lfanew);
		dwExportDirRVA = pNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
		pExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pModuleBase + dwExportDirRVA);
		dwNumFunctions = pExportDir->NumberOfNames;
		pdwFunctionNameBase = (PDWORD)((PCHAR)pModuleBase + pExportDir->AddressOfNames);

		char getProcAddressArr[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0 };
		for (size_t i = 0; i < dwNumFunctions; i++)
		{
			pFunctionName = (char*)(*pdwFunctionNameBase + (ULONG_PTR)pModuleBase);
			if (strcmp(getProcAddressArr, pFunctionName) == 0)
			{
				usOrdinalTableIndex = *(PUSHORT)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfNameOrdinals) + (2 * i));
				return (HMODULE)((ULONG_PTR)pModuleBase + *(PDWORD)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfFunctions) + (4 * usOrdinalTableIndex)));
			}
			pdwFunctionNameBase++;
		}
	}

	// All modules have been exhausted and the function was not found.
	return NULL;
}
