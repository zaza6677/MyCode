//use windows vista above
#include "windows.h"
#include "Winternl.h"

#define THREAD_ALL_ACCESS_VISTA         (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
	0xFFFF)

//SOURCE: hxxp://processhacker.sourceforge.net/doc/ntpsapi_8h_source.html
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 // ?
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#define THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR 0x00000010 // ?
#define THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET 0x00000020 // ?
#define THREAD_CREATE_FLAGS_INITIAL_THREAD 0x00000080

typedef NTSTATUS (WINAPI *LPFUN_NtQueryInformationThread)(
	_In_      HANDLE          ThreadHandle,
	_In_      THREADINFOCLASS ThreadInformationClass,
	_Inout_   PVOID           ThreadInformation,
	_In_      ULONG           ThreadInformationLength,
	_Out_opt_ PULONG          ReturnLength
);

typedef struct _NtCreateThreadExBuffer {
	ULONG Size;
	ULONG Unknown1;
	ULONG Unknown2;
	PULONG Unknown3;
	ULONG Unknown4;
	ULONG Unknown5;
	ULONG Unknown6;
	PULONG Unknown7;
	ULONG Unknown8;
}NtCreateThreadExBuffer;

typedef NTSTATUS(WINAPI *LPFUN_NtCreateThreadEx) (
	PHANDLE hThread,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	BOOL CreateSuspended,
	ULONG StackZeroBits,
	ULONG SizeOfStackCommit,
	ULONG SizeOfStackReserve,
	LPVOID lpBytesBuffer
);

VOID ShowMessageBox(const char * format, ...);

LPFUN_NtQueryInformationThread fnNtQueryInformationThread;

VOID WINAPI ContinueExecution(LPVOID param)
{
	BOOLEAN check = FALSE;
	HMODULE hNtdll = NULL;
	hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (hNtdll == NULL) {
		return ;
	}
	fnNtQueryInformationThread = GetProcAddress(hNtdll, "NtQueryInformationThread");


	if (fnNtQueryInformationThread(GetCurrentThread(), (THREADINFOCLASS)0x11, &check, sizeof(BOOLEAN), 0) >= 0)
	{
		if (!check)
		{
			ShowMessageBox("Anti-Anti-Debug Tool detected!\n");
			//Anti-Anti-Debug Tool detected!\n
		}
		else
		{
			//Everything ok
			ShowMessageBox("Everything ok!\n");
			
		}
	}
	else
	{
		//Query ThreadHideFromDebugger not available
		ShowMessageBox("Query ThreadHideFromDebugger not available!\n");
		
	}
}

LPFUN_NtCreateThreadEx funNtCreateThreadEx;

INT AntiDebuggerByNtCreateThreadEx()
{
	HANDLE hThread = NULL;
	HMODULE hNtdll = NULL;
	NtCreateThreadExBuffer ntbuffer = { 0 };

	hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (hNtdll == NULL) {
		return -1;
	}

	funNtCreateThreadEx = GetProcAddress(hNtdll, "NtCreateThreadEx");

	if (funNtCreateThreadEx == NULL) {
		return -1;
	}

	funNtCreateThreadEx(
		&hThread,//&hRemoteThread
		THREAD_ALL_ACCESS_VISTA,//0x1FFFFF
		0,//NULL
		GetCurrentProcess(),//hProcess
		(LPTHREAD_START_ROUTINE)ContinueExecution,//pfnThreadRtn
		0,//(LPVOID)pszLibFileRemote
		THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
		0, 0, 0, 0
	);

	WaitForSingleObject(hThread, INFINITE);
	return 0;

}

char text[0x1000] = { 0 };

VOID ShowMessageBox(const char * format, ...)
{
	va_list va_alist;
	va_start(va_alist, format);

	wvsprintfA(text, format, va_alist);

	MessageBoxA(0, text, "Text", 0);
}

BOOLEAN AdjustPrivileges() {
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	TOKEN_PRIVILEGES oldtp;
	DWORD dwSize = sizeof(TOKEN_PRIVILEGES);
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		if (GetLastError() == ERROR_CALL_NOT_IMPLEMENTED) 
			return TRUE;
		else return FALSE;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		CloseHandle(hToken);
		return FALSE;
	}
	ZeroMemory(&tp, sizeof(tp));
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	/* Adjust Token Privileges */
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &oldtp, &dwSize)) {
		CloseHandle(hToken);
		return FALSE;
	}
	// close handles
	CloseHandle(hToken);
	return TRUE;
}

int main()
{
	AdjustPrivileges();
	AntiDebuggerByNtCreateThreadEx();
	getchar();
	return 0;

}


