#define  _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include "assert.h"
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

PIMAGE_NT_HEADERS AnalyaisImage(HMODULE hModule);
FARPROC __stdcall MyGetProcAddress(HMODULE hModule, LPCSTR name);
HMODULE LoadLibraryByFile(const char * pszDllPath);
HMODULE LoadLibraryByResource(WORD wResID, char *pszFileType);
DWORD GetPECodeEnd(HMODULE hModule);
DWORD GetPEImageEnd(HMODULE hModule);
DWORD GetPEImageSize(HMODULE hModule);
DWORD GetCodeSize(HMODULE hModule);

typedef BOOL(__stdcall * fnDllMain)(HINSTANCE hModule, DWORD dwReason, LPVOID lpvReserved);


PIMAGE_NT_HEADERS AnalyaisImage(HMODULE hModule)
{
	PBYTE pImage = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pImageDosHeader;
	PIMAGE_NT_HEADERS pImageNtHeader;
	pImageDosHeader = (PIMAGE_DOS_HEADER)pImage;
	if (pImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		pImageNtHeader = (PIMAGE_NT_HEADERS)&pImage[pImageDosHeader->e_lfanew];
		if (pImageNtHeader->Signature == IMAGE_NT_SIGNATURE)
		{
			return pImageNtHeader;
		}
	}
	return NULL;
}

FARPROC __stdcall MyGetProcAddress(HMODULE hModule, LPCSTR name)
{
	if (!hModule)
	{
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
	pDirectory = &pImageNtDest->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (pDirectory->Size == 0)
		return NULL;
	pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pDest + pDirectory->VirtualAddress);

	if (pExport->NumberOfNames == 0 || pExport->NumberOfFunctions == 0)
		return NULL;
	ordinal = (WORD *)((DWORD)pDest + pExport->AddressOfNameOrdinals);
	if ((DWORD)(name) < 0x10000)
	{
		if ((DWORD)name >= pExport->NumberOfFunctions + pExport->Base || (DWORD)name < pExport->Base)
			return NULL;
		idx = (DWORD)pDest + ((DWORD*)((DWORD)pDest + pExport->AddressOfFunctions))[(DWORD)name - pExport->Base];
	}
	else
	{
		nameRef = (DWORD *)((DWORD)pDest + pExport->AddressOfNames);
		for (i = 0; i < pExport->NumberOfNames; i++, nameRef++, ordinal++)
		{
			//printf("%s--------------%s\n",name,(DWORD)pDest + (*nameRef));
			if (strcmp(name, (const char *)((DWORD)pDest + (*nameRef))) == 0)
			{
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
	return (FARPROC)((DWORD)hModule + (*(DWORD *)((DWORD)hModule + pExport->AddressOfFunctions + (idx * 4))));
}
void CopySection(PBYTE pSrc, PBYTE pDest)
{
	unsigned int i, size;
	PIMAGE_DOS_HEADER pImageDosSrc;
	PIMAGE_NT_HEADERS pImageNtSrc;
	PIMAGE_DOS_HEADER pImageDosDest;
	PIMAGE_NT_HEADERS pImageNtDest;
	PIMAGE_SECTION_HEADER pSection;
	pImageDosSrc = (PIMAGE_DOS_HEADER)pSrc;
	pImageNtSrc = (PIMAGE_NT_HEADERS)&pSrc[pImageDosSrc->e_lfanew];

	pImageDosDest = (PIMAGE_DOS_HEADER)pDest;
	pImageNtDest = (PIMAGE_NT_HEADERS)&pDest[pImageDosDest->e_lfanew];
	pSection = IMAGE_FIRST_SECTION(pImageNtDest);
	for (i = 0; i < pImageNtDest->FileHeader.NumberOfSections; i++, pSection++)
	{
		if (pSection->SizeOfRawData == 0)
		{
			size = pImageNtSrc->OptionalHeader.SectionAlignment;
			if (size > 0)
			{
				pSection->Misc.PhysicalAddress = pSection->VirtualAddress + (DWORD)pDest;
				memset((PVOID)pSection->Misc.PhysicalAddress, 0, size);
			}
			continue;
		}
		pSection->Misc.PhysicalAddress = pSection->VirtualAddress + (DWORD)pDest;
		memcpy((PVOID)pSection->Misc.PhysicalAddress, (PVOID)((DWORD)pSrc + pSection->PointerToRawData), pSection->SizeOfRawData);
	}
}
void GetImportInfo(DWORD imgbase, DWORD impoff)
{
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(imgbase + impoff);
	HMODULE hModuleSys;
	DWORD i, p;
	PIMAGE_THUNK_DATA32 pimpthunk;
	PIMAGE_IMPORT_BY_NAME pimpname;
	FARPROC* pimpwrite;
	FARPROC pFunc;
	for (i = 0; pImport[i].Characteristics != 0; i++)
	{
		hModuleSys = LoadLibraryA((LPCSTR)(pImport[i].Name + imgbase));
		pimpthunk = (PIMAGE_THUNK_DATA32)(pImport[i].OriginalFirstThunk + imgbase);
		pimpwrite = (FARPROC*)(pImport[i].FirstThunk + imgbase);
		for (p = 0; pimpthunk[p].u1.AddressOfData != 0; p++)
		{
			pimpname = (PIMAGE_IMPORT_BY_NAME)((DWORD)pimpthunk[p].u1.AddressOfData + imgbase);
			if (IMAGE_SNAP_BY_ORDINAL32(pimpthunk[p].u1.AddressOfData))
			{
				pFunc = GetProcAddress(hModuleSys, (LPCSTR)IMAGE_ORDINAL(pimpthunk[p].u1.AddressOfData));
				pimpwrite[p] = pFunc;
			}
			else
			{
				pFunc = GetProcAddress(hModuleSys, (LPCSTR)&pimpname->Name);
				pimpwrite[p] = pFunc;
			}
		}
	}
}
void LoadImport(PBYTE pSrc, PBYTE pDest)
{
	PIMAGE_DOS_HEADER pImageDosSrc;
	PIMAGE_NT_HEADERS pImageNtSrc;
	PIMAGE_DOS_HEADER pImageDosDest;
	PIMAGE_NT_HEADERS pImageNtDest;
	PIMAGE_DATA_DIRECTORY pDirectory;
	pImageDosSrc = (PIMAGE_DOS_HEADER)pSrc;
	pImageNtSrc = (PIMAGE_NT_HEADERS)&pSrc[pImageDosSrc->e_lfanew];

	pImageDosDest = (PIMAGE_DOS_HEADER)pDest;
	pImageNtDest = (PIMAGE_NT_HEADERS)&pDest[pImageDosDest->e_lfanew];

	pDirectory = &pImageNtDest->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (!pDirectory->VirtualAddress)
		return;
	GetImportInfo((DWORD)pDest, pDirectory->VirtualAddress);
}

BOOL check_import(HMODULE hModule)
{
	PBYTE pImage = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pImageDos;
	PIMAGE_NT_HEADERS pImageNT;
	PIMAGE_DATA_DIRECTORY pDataDirectory;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
	pImageDos = (PIMAGE_DOS_HEADER)pImage;
	pImageNT = (PIMAGE_NT_HEADERS)&pImage[pImageDos->e_lfanew];

	pDataDirectory = &pImageNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (!pDataDirectory->VirtualAddress)
		return FALSE;
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)&pImage[pDataDirectory->VirtualAddress];

	for (int i = 0; pImportDescriptor[i].Characteristics != 0; i++)
	{
		HMODULE hCurrentModule = LoadLibraryA((LPCSTR)(&pImage[pImportDescriptor[i].Name]));
		PIMAGE_THUNK_DATA32 pCurrentImportThunk = (PIMAGE_THUNK_DATA32)(&pImage[pImportDescriptor[i].OriginalFirstThunk]);
		FARPROC* pCurrentImportList = (FARPROC*)(&pImage[pImportDescriptor[i].FirstThunk]);
		for (int m_imp = 0; pCurrentImportThunk[m_imp].u1.AddressOfData != 0; m_imp++)
		{
			if (IMAGE_SNAP_BY_ORDINAL32(pCurrentImportThunk[m_imp].u1.AddressOfData))
			{
				if (pCurrentImportList[m_imp] != GetProcAddress(hCurrentModule, (LPCSTR)IMAGE_ORDINAL(pCurrentImportThunk[m_imp].u1.AddressOfData)))
					return FALSE;
			}
			else
			{
				if (pCurrentImportList[m_imp] != GetProcAddress(hCurrentModule, (LPCSTR)&((PIMAGE_IMPORT_BY_NAME)&pImage[pCurrentImportThunk[m_imp].u1.AddressOfData])->Name))
					return FALSE;
			}
		}
	}
	return TRUE;
}
void FixupResource(PBYTE pDest)
{
	DWORD imagebase;
	PIMAGE_RESOURCE_DIRECTORY pRes;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry;
	DWORD nEntries;
	DWORD i;
	PIMAGE_RESOURCE_DIRECTORY pRes2;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry2;
	DWORD nEntries2;
	PIMAGE_RESOURCE_DIR_STRING_U pDirStr;
	PIMAGE_RESOURCE_DIRECTORY pRes3;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry3;
	DWORD nEntries3;
	DWORD j;
	DWORD k;
	PIMAGE_RESOURCE_DATA_ENTRY pData;
	PIMAGE_DOS_HEADER pImageDosDest;
	PIMAGE_NT_HEADERS pImageNtDest;

	pImageDosDest = (PIMAGE_DOS_HEADER)pDest;
	pImageNtDest = (PIMAGE_NT_HEADERS)&pDest[pImageDosDest->e_lfanew];
	imagebase = pImageNtDest->OptionalHeader.ImageBase;
	if (!pImageNtDest->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress)
		return;
	pRes = (PIMAGE_RESOURCE_DIRECTORY)(imagebase + pImageNtDest->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
	nEntries = pRes->NumberOfIdEntries + pRes->NumberOfNamedEntries;
	pEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pRes + sizeof(IMAGE_RESOURCE_DIRECTORY));
	for (i = 0; i < nEntries; ++i, ++pEntry) {

		if (IMAGE_RESOURCE_DATA_IS_DIRECTORY & pEntry->OffsetToData) {
			pRes2 = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pRes
				+ (~IMAGE_RESOURCE_DATA_IS_DIRECTORY & pEntry->OffsetToData));
			nEntries2 = pRes2->NumberOfIdEntries + pRes2->NumberOfNamedEntries;
			pEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pRes2 + sizeof(IMAGE_RESOURCE_DIRECTORY));

			for (j = 0; j < nEntries2; ++j, ++pEntry2) {
				if (IMAGE_RESOURCE_NAME_IS_STRING & pEntry2->Name) {

					pDirStr = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)pRes
						+ (~IMAGE_RESOURCE_NAME_IS_STRING & pEntry2->Name));
				}
				if (IMAGE_RESOURCE_DATA_IS_DIRECTORY & pEntry2->OffsetToData) {
					pRes3 = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pRes
						+ (~IMAGE_RESOURCE_DATA_IS_DIRECTORY & pEntry2->OffsetToData));
					nEntries3 = pRes3->NumberOfIdEntries + pRes3->NumberOfNamedEntries;
					pEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pRes3 + sizeof(IMAGE_RESOURCE_DIRECTORY));

					for (k = 0; k < nEntries3; ++k) {
						assert(~IMAGE_RESOURCE_DATA_IS_DIRECTORY & pEntry3->OffsetToData);

						pData = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)pRes + pEntry3->OffsetToData);
						pData->OffsetToData += (DWORD)imagebase;
					}
				}
			}

		}
	}
}
PVOID ReadData(IN LPCSTR lpFileName, OUT DWORD* ReadSize)
{
	PBYTE pLibrarySrc;
	HANDLE hFile = CreateFileA(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{

		char szSysDir[256] = { 0 };
		int nSysDirLen = 0;
		nSysDirLen = GetSystemDirectoryA(szSysDir, 256);
		printf("System Directory is %s\n", szSysDir);
		strcat(szSysDir, "\\");
		strcat(szSysDir, lpFileName);
		HANDLE hFile = CreateFileA(szSysDir, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		*ReadSize = GetFileSize(hFile, NULL);
		pLibrarySrc = (PBYTE)VirtualAlloc(0, *ReadSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!ReadFile(hFile, pLibrarySrc, *ReadSize, ReadSize, NULL))
		{
			CloseHandle(hFile);
			VirtualFree(pLibrarySrc, *ReadSize, MEM_DECOMMIT);
			return NULL;
		}
		CloseHandle(hFile);
		return (PVOID)pLibrarySrc;
	}
	return NULL;
}
BOOL CheckPEFile(PIMAGE_DOS_HEADER pImageDosDest, PIMAGE_NT_HEADERS* pImageNtDest)
{
	PBYTE pImage = (PBYTE)pImageDosDest;
	if (pImageDosDest->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;
	*pImageNtDest = (PIMAGE_NT_HEADERS)&pImage[pImageDosDest->e_lfanew];
	if ((*pImageNtDest)->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	return TRUE;
}
void LoadRelocation(PBYTE pSrc, PBYTE pDest)
{
	PIMAGE_DOS_HEADER pImageDosSrc;
	PIMAGE_NT_HEADERS pImageNtSrc;
	PIMAGE_DOS_HEADER pImageDosDest;
	PIMAGE_NT_HEADERS pImageNtDest;
	PIMAGE_DATA_DIRECTORY pDirectory;
	PIMAGE_BASE_RELOCATION pRelocation;
	DWORD dwOriginAddress;
	DWORD dwBaseDelta;
	PWORD pData;
	int i, size;
	DWORD* dwRelocationPointer;
	int iType;
	pImageDosSrc = (PIMAGE_DOS_HEADER)pSrc;
	pImageNtSrc = (PIMAGE_NT_HEADERS)&pSrc[pImageDosSrc->e_lfanew];

	pImageDosDest = (PIMAGE_DOS_HEADER)pDest;
	pImageNtDest = (PIMAGE_NT_HEADERS)&pDest[pImageDosDest->e_lfanew];
	pDirectory = (PIMAGE_DATA_DIRECTORY)&pImageNtDest->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!pDirectory->VirtualAddress)
		return;
	pRelocation = (PIMAGE_BASE_RELOCATION)(pDirectory->VirtualAddress + (DWORD)pDest);
	dwOriginAddress = pImageNtSrc->OptionalHeader.ImageBase;
	dwBaseDelta = (DWORD)pDest - dwOriginAddress;
	while (pRelocation->VirtualAddress != 0)
	{
		size = (pRelocation->SizeOfBlock - sizeof(IMAGE_DATA_DIRECTORY)) / 2;
		pData = (PWORD)((DWORD)pRelocation + 8);
		for (i = 0; i < size; i++)
		{
			iType = pData[i] >> 12;
			dwRelocationPointer = (DWORD*)((DWORD)pDest + ((pData[i] & 0x0fff) + pRelocation->VirtualAddress));
			switch (iType)
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			case IMAGE_REL_BASED_HIGH:
				*(PWORD)dwRelocationPointer = (WORD)(((dwBaseDelta + *(PWORD)dwRelocationPointer) >> 16) & 0xFFFF);
				break;
			case IMAGE_REL_BASED_LOW:
				*(PWORD)dwRelocationPointer = (WORD)((dwBaseDelta + *(PWORD)dwRelocationPointer) & 0xFFFF);
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				*dwRelocationPointer = *dwRelocationPointer + dwBaseDelta;
				break;
			default:
				break;
			}
		}
		pRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocation + pRelocation->SizeOfBlock);
	}
}

HMODULE LoadLibraryByResource(WORD wResID, char *pszFileType)
{
	DWORD dwReadSize;
	PBYTE pLibrarySrc;
	PBYTE pLibraryDest;
	PIMAGE_DOS_HEADER pImageDosSrc;
	PIMAGE_NT_HEADERS pImageNtSrc;
	PIMAGE_DOS_HEADER pImageDosDest;
	PIMAGE_NT_HEADERS pImageNtDest;

	HRSRC   hrsc = FindResourceA(NULL, MAKEINTRESOURCEA(wResID), pszFileType);
	HGLOBAL hG = LoadResource(NULL, hrsc);

	dwReadSize = SizeofResource(NULL, hrsc);
	pLibrarySrc = (PBYTE)hG;
	if (pLibrarySrc != NULL)
	{
		pImageDosSrc = (PIMAGE_DOS_HEADER)pLibrarySrc;
		if (!CheckPEFile(pImageDosSrc, &pImageNtSrc))
			return NULL;
		pLibraryDest = (PBYTE)VirtualAlloc(NULL, pImageNtSrc->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		//copy header 
		memcpy(pLibraryDest, pImageDosSrc, pImageDosSrc->e_lfanew + pImageNtSrc->OptionalHeader.SizeOfHeaders);
		pImageDosDest = (PIMAGE_DOS_HEADER)pLibraryDest;
		pImageNtDest = (PIMAGE_NT_HEADERS)&pLibraryDest[pImageDosDest->e_lfanew];
		pImageNtDest->OptionalHeader.ImageBase = (DWORD)pLibraryDest;

		CopySection(pLibrarySrc, pLibraryDest);
		LoadRelocation(pLibrarySrc, pLibraryDest);
		//FixupResource(pLibraryDest); 
		LoadImport(pLibrarySrc, pLibraryDest);
		if (pImageNtDest->OptionalHeader.AddressOfEntryPoint)
			((fnDllMain)(pImageNtDest->OptionalHeader.AddressOfEntryPoint + (DWORD)pLibraryDest))((HINSTANCE)pLibraryDest, DLL_PROCESS_ATTACH, NULL);
		//pImageDosDest->e_magic = 0; 
		//pImageNtDest->Signature = 0; 
		return (HMODULE)pLibraryDest;
	}
	return NULL;
}

HMODULE LoadLibraryByFile(const char * pszDllPath)
{
	DWORD dwReadSize;
	PBYTE pLibrarySrc;
	PBYTE pLibraryDest;
	PIMAGE_DOS_HEADER pImageDosSrc;
	PIMAGE_NT_HEADERS pImageNtSrc;
	PIMAGE_DOS_HEADER pImageDosDest;
	PIMAGE_NT_HEADERS pImageNtDest;
	pLibrarySrc = (PBYTE)ReadData(pszDllPath, &dwReadSize);
	if (pLibrarySrc != NULL)
	{
		pImageDosSrc = (PIMAGE_DOS_HEADER)pLibrarySrc;
		if (!CheckPEFile(pImageDosSrc, &pImageNtSrc))
		{
			VirtualFree(pLibrarySrc, dwReadSize, MEM_COMMIT);
			return NULL;
		}
		//pLibraryDest = (PBYTE)VirtualAlloc(NULL, pImageNtSrc->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		pLibraryDest = (PBYTE)VirtualAlloc((LPVOID)(pImageNtSrc->OptionalHeader.ImageBase), pImageNtSrc->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		//copy header 
		memcpy(pLibraryDest, pImageDosSrc, pImageDosSrc->e_lfanew + pImageNtSrc->OptionalHeader.SizeOfHeaders);

		pImageDosDest = (PIMAGE_DOS_HEADER)pLibraryDest;
		pImageNtDest = (PIMAGE_NT_HEADERS)&pLibraryDest[pImageDosDest->e_lfanew];
		pImageNtDest->OptionalHeader.ImageBase = (DWORD)pLibraryDest;

		CopySection(pLibrarySrc, pLibraryDest);
		LoadRelocation(pLibrarySrc, pLibraryDest);
		//FixupResource(pLibraryDest); 
		LoadImport(pLibrarySrc, pLibraryDest);
		VirtualFree(pLibrarySrc, dwReadSize, MEM_DECOMMIT);
		if (pImageNtDest->OptionalHeader.AddressOfEntryPoint)
			((fnDllMain)(pImageNtDest->OptionalHeader.AddressOfEntryPoint + (DWORD)pLibraryDest))((HINSTANCE)pLibraryDest, DLL_PROCESS_ATTACH, NULL);
		//pImageDosDest->e_magic = 0; 
		//pImageNtDest->Signature = 0; 
		return (HMODULE)pLibraryDest;
	}
	return NULL;
}


DWORD GetCodeSize(HMODULE hModule)
{
	PBYTE pInfo = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)pInfo;
	PIMAGE_NT_HEADERS pImgNt;
	if (pImgDos->e_magic == IMAGE_DOS_SIGNATURE)
	{
		pImgNt = (PIMAGE_NT_HEADERS)&pInfo[pImgDos->e_lfanew];
		if (pImgNt)
		{
			if (pImgNt->Signature == IMAGE_NT_SIGNATURE)
			{
				return pImgNt->OptionalHeader.SizeOfCode;
			}
		}
	}
	return (DWORD)NULL;
}
DWORD GetPEImageSize(HMODULE hModule)
{
	PBYTE pInfo = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)pInfo;
	PIMAGE_NT_HEADERS pImgNt;
	if (pImgDos->e_magic == IMAGE_DOS_SIGNATURE)
	{
		pImgNt = (PIMAGE_NT_HEADERS)&pInfo[pImgDos->e_lfanew];
		if (pImgNt)
		{
			if (pImgNt->Signature == IMAGE_NT_SIGNATURE)
			{
				return pImgNt->OptionalHeader.SizeOfImage;
			}
		}
	}
	return (DWORD)NULL;
}
DWORD GetPEImageEnd(HMODULE hModule)
{
	return ((DWORD)hModule + GetPEImageSize(hModule));
}
DWORD GetPECodeEnd(HMODULE hModule)
{
	return ((DWORD)hModule + GetCodeSize(hModule));
}

int main(void) {
	do {
		char ntllStr[] = "\x6E\x74\x64\x6C\x6C\x2E\x64\x6C\x6C";
		HMODULE ntModule = LoadLibraryByFile("ntdll.dll");//can be replaced by ntllStr
		if (ntModule == NULL) {
			printf("ntdll loaded error\n");
			break;
		}
		ZW_QUERY_INFORMATION_PROCESS ZwQueryInformationProcess;
		ZwQueryInformationProcess = (ZW_QUERY_INFORMATION_PROCESS)MyGetProcAddress(ntModule, "ZwQueryInformationProcess");
		if (ZwQueryInformationProcess)
		{
			PROCESS_DEBUG_PORT_INFO ProcessInfo;
			//DWORD dwProcessId = GetCurrentProcessId();
			//HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
			if (STATUS_SUCCESS == ZwQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)0x0000001e, &ProcessInfo, sizeof(ProcessInfo), NULL))
			{
				printf("OK!\n");

			}
			else
			{
				printf("Failed\n");
			}
		}
		FreeLibrary(ntModule);

	} while (0);

	getchar();
	return 0;

}