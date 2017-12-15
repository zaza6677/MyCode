#include "header.h"
#include <psapi.h>
#include "stdio.h"
#include <DbgHelp.h>
#pragma comment (lib, "imagehlp.lib")

extern  VOID medium(VOID);
extern	VOID hook(DWORD64 R10, DWORD64 RAX/* ... */);

DWORD64 counter = 0;

BOOL flag = FALSE;

VOID hook(DWORD64 R10, DWORD64 RAX/* ... */) {

	// This flag is there for prevent recursion
	if (!flag) {
		flag = TRUE;

		counter++;

		CHAR buffer[sizeof(SYMBOL_INFO) + 2000] = { 0 };
		PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
		pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		pSymbol->MaxNameLen = 2000;
		DWORD64 Displacement;

		// MSDN: Retrieves symbol information for the specified address.
		BOOLEAN result = SymFromAddr(GetCurrentProcess(), R10, &Displacement, pSymbol);

		if (result) {
			printf("Function: %s Return value: 0x%llx\n", pSymbol->Name, RAX);
		}

		flag = TRUE;
	}


}

pNtSetInformationProcess NtSetInformationProcess;
//= (pNtSetInformationProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
	//"NtSetInformationProcess");


int main()
{
	// The Rootkit Arsenal:
	// "An epilogue detour allows for post-procesing.
	// They are useful for filtering output parameters once
	// original routine has performed its duties."



	// TODO: setup for get symbols
	SymSetOptions(0x00000002);
	SymInitialize(GetCurrentProcess(), NULL, TRUE);

	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION nirvana;
	nirvana.Callback = (PVOID)(ULONG_PTR)medium;
	nirvana.Reserved = 0; // always 0
	nirvana.Version = 0; // 0 for x64, 1 for x86
	HMODULE ntDll = NULL;
	ntDll = GetModuleHandleW(L"ntdll.dll");
	if (ntDll == NULL) {
		printf("ntll is NULL\n");
		return 0;
	}
	NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(ntDll, "NtSetInformationProcess");

	NtSetInformationProcess(
		GetCurrentProcess(),
		(PROCESS_INFORMATION_CLASS)ProcessInstrumentationCallback,
		&nirvana,
		sizeof(nirvana) /*0x8*/);


	// sample calls
	CreateFile(L"X:", GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0);
	SetCurrentDirectory(L"C:/");
	// WinExec("calc.exe", 0);

	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms682623(v=vs.85).aspx

	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 1;
	}


	// Calculate how many process identifiers were returned.

	cProcesses = cbNeeded / sizeof(DWORD);

	// Print the name and process identifier for each process.

	for (i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0)
		{
			OpenProcess(PROCESS_QUERY_INFORMATION |
				PROCESS_VM_READ,
				FALSE, aProcesses[i]);
		}
	}


	// We can not hook RtlRandomEx, it does not crosses kernel
	typedef ULONG RtlRandomEx(
		_Inout_ PULONG Seed
	);
	RtlRandomEx* rand = (RtlRandomEx*)GetProcAddress(GetModuleHandle(L"ntdll"), "RtlRandomEx");
	ULONG seed = 1;
	ULONG rand_value = rand(&seed);
	getchar();


	return 0;
}

