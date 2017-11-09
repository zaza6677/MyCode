#include <stdio.h>
#include <windows.h>

#define STATUS_SUCCESS ((NTSTATUS)0L)

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7
} PROCESSINFOCLASS;

typedef struct _PROCESS_DEBUG_PORT_INFO {
	HANDLE DebugPort;
} PROCESS_DEBUG_PORT_INFO;

typedef NTSTATUS(NTAPI *ZW_QUERY_INFORMATION_PROCESS)(
	IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength);

FARPROC __stdcall MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName);
FARPROC __stdcall MyGetProcAddress_Ex(HMODULE hModule, LPCSTR lpProcName);

FARPROC __stdcall MyGetProcAddress(HMODULE hModule,  // handle to DLL module
	LPCSTR lpProcName // function name
) {
	int i = 0;
	char *pRet = NULL;
	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_NT_HEADERS pImageNtHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;

	pImageDosHeader = (PIMAGE_DOS_HEADER)hModule;
	pImageNtHeader =
		(PIMAGE_NT_HEADERS)((DWORD)hModule + pImageDosHeader->e_lfanew);
	pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(
		(DWORD)hModule +
		pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
		.VirtualAddress);

	DWORD dwExportRVA =
		pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
		.VirtualAddress;
	DWORD dwExportSize =
		pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
		.Size;

	DWORD *pAddressOfFunction =
		(DWORD *)(pImageExportDirectory->AddressOfFunctions + (DWORD)hModule);
	DWORD *pAddressOfNames =
		(DWORD *)(pImageExportDirectory->AddressOfNames + (DWORD)hModule);
	DWORD dwNumberOfNames = (DWORD)(pImageExportDirectory->NumberOfNames);
	DWORD dwBase = (DWORD)(pImageExportDirectory->Base);

	WORD *pAddressOfNameOrdinals =
		(WORD *)(pImageExportDirectory->AddressOfNameOrdinals + (DWORD)hModule);

	// two method find function address
	// 1.function name
	// 2.function number
	DWORD dwName = (DWORD)lpProcName;
	if ((dwName & 0xFFFF0000) == 0) {
		goto funcNum;
	}

	for (i = 0; i < (int)dwNumberOfNames; i++) {
		char *strFunction = (char *)(pAddressOfNames[i] + (DWORD)hModule);
		if (strcmp(strFunction, (char *)lpProcName) == 0) {
			pRet = (char *)(pAddressOfFunction[pAddressOfNameOrdinals[i]] +
				(DWORD)hModule);
			goto _exitt;
		}
	}
	// function number
funcNum:
	if (dwName < dwBase ||
		dwName > dwBase + pImageExportDirectory->NumberOfFunctions - 1) {
		return 0;
	}
	pRet = (char *)(pAddressOfFunction[dwName - dwBase] + (DWORD)hModule);

_exitt:
	if ((DWORD)pRet < dwExportRVA + (DWORD)hModule ||
		(DWORD)pRet > dwExportRVA + (DWORD)hModule + dwExportSize) {
		return (DWORD)pRet;
	} // over bound
	char pTempDll[100] = { 0 };
	char pTempFuction[100] = { 0 };
	lstrcpy(pTempDll, pRet);
	char *p = strchr(pTempDll, '.');
	if (!p) {
		return (DWORD)pRet;
	}
	*p = 0;
	lstrcpy(pTempFuction, p + 1);
	lstrcat(pTempDll, ".dll");
	HMODULE h = LoadLibrary(pTempDll);
	if (h == NULL) {
		return (DWORD)pRet;
	}
	return MyGetProcAddress(h, pTempFuction);
}

FARPROC __stdcall MyGetProcAddress_Ex(HMODULE hModule, LPCSTR lpProcName) {
	if (!hModule) {
		hModule = GetModuleHandle(0);
	}
	PBYTE pDest = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pImageDosDest;
	PIMAGE_NT_HEADERS pImageNtDest;
	PIMAGE_DATA_DIRECTORY pDirectory;
	PIMAGE_EXPORT_DIRECTORY pExport;
	DWORD i, *nameRef;
	WORD *ordinal;
	int idx = -1;
	pImageDosDest = (PIMAGE_DOS_HEADER)pDest;
	pImageNtDest = (PIMAGE_NT_HEADERS)&pDest[pImageDosDest->e_lfanew];
	pDirectory =
		&pImageNtDest->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (pDirectory->Size == 0)
		return NULL;
	pExport =
		(PIMAGE_EXPORT_DIRECTORY)((DWORD)pDest + pDirectory->VirtualAddress);

	if (pExport->NumberOfNames == 0 || pExport->NumberOfFunctions == 0)
		return NULL;
	ordinal = (WORD *)((DWORD)pDest + pExport->AddressOfNameOrdinals);
	if ((DWORD)(lpProcName) < 0x10000) {
		if ((DWORD)lpProcName >= pExport->NumberOfFunctions + pExport->Base ||
			(DWORD)lpProcName < pExport->Base)
			return NULL;
		idx = (DWORD)pDest +
			((DWORD *)((DWORD)pDest +
				pExport->AddressOfFunctions))[(DWORD)lpProcName -
			pExport->Base];
	}
	else {
		nameRef = (DWORD *)((DWORD)pDest + pExport->AddressOfNames);
		for (i = 0; i < pExport->NumberOfNames; i++, nameRef++, ordinal++) {
			// printf("%s--------------%s\n",name,(DWORD)pDest + (*nameRef));
			if (strcmp(lpProcName, (const char *)((DWORD)pDest + (*nameRef))) == 0) {
				idx = *ordinal;
				break;
			}
		}
	}
	if (idx == -1) {
		return NULL;
	}
	if ((DWORD)idx > pExport->NumberOfFunctions) {
		return NULL;
	}
	return (FARPROC)(
		(DWORD)hModule +
		(*(DWORD *)((DWORD)hModule + pExport->AddressOfFunctions + (idx * 4))));
}

int main(void) {
	HMODULE ntModule = LoadLibraryA("ntdll.dll"); // be sure
												  // LoadLibraryA("ntdll.dll") or
												  // LoadLibraryW(L"ntdll.dll")
	ZW_QUERY_INFORMATION_PROCESS ZwQueryInformationProcess;
	ZwQueryInformationProcess =
		(ZW_QUERY_INFORMATION_PROCESS)MyGetProcAddress( // MyGetProcAddress_Ex
			ntModule, "ZwQueryInformationProcess");
	if (ZwQueryInformationProcess) {
		PROCESS_DEBUG_PORT_INFO processInfo;
		if (STATUS_SUCCESS == ZwQueryInformationProcess(
			GetCurrentProcess(), (PROCESSINFOCLASS)0x0000001e,
			&processInfo, sizeof(processInfo), NULL)) {
			printf("OK!\n");

		}
		else {
			printf("ZwQueryInformationProcess failed\n");
		}
	}
	FreeLibrary(ntModule);
	getchar();
	return 0;
}
