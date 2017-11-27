#include <stdio.h>
#include <Windows.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS       ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef void* (__fastcall *LPFN_KernelBaseGetGlobalData)(void);
typedef LONG(__stdcall *fnRtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation);

BOOL WINAPI InjectDllExW(DWORD dwPID, PCWSTR pwszProxyFile)
{
	BOOL ret = FALSE;
	HANDLE hToken = NULL;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	FARPROC pfnThreadRtn = NULL;
	PWSTR pwszPara = NULL;
	PVOID pRemoteShellcode = NULL;
	CLIENT_ID Cid = { 0 };
	UCHAR* pGlobalData = NULL;
	UCHAR* pMisc = NULL;
	LONG PatchOffset = 0;
	fnRtlGetVersion pRtlGetVersion;
	HMODULE hNtdll;
	RTL_OSVERSIONINFOW VersionInformation = { 0 };
	hNtdll = GetModuleHandleW(L"ntdll.dll");
	pRtlGetVersion = (fnRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
	pRtlGetVersion(&VersionInformation);
	//Get patch position by build number
	switch (VersionInformation.dwBuildNumber) {
		/*
		KERNELBASE!CreateRemoteThreadEx+0x224:
		000007fe`fdb1b184 803db156050000  cmp     byte ptr [KERNELBASE!KernelBaseGlobalData+0x5c (000007fe`fdb7083c)],0
		*/
	case 7600:
	{
		PatchOffset = 0x5C;
		break;
	}
	case 7601:
	{
		PatchOffset = 0x5C;
		break;
	}
	/*
	KERNELBASE!CreateRemoteThreadEx+0x1a8:
	000007fa`7859ef28 44380d35470b00  cmp     byte ptr [KERNELBASE!KernelBaseGlobalData+0x4 (000007fa`78653664)],r9b
	*/
	case 9200:
	{
		PatchOffset = 0x4;
		break;
	}
	/*
	cmp     byte ptr [KERNELBASE!KernelBaseGlobalData+0x4 (00007fff`40117ea4)],sil
	00007fff`3ff482fd 0f8526010000    jne     KERNELBASE!CreateRemoteThreadEx+0x2f9 (00007fff`3ff48429)

	*/
	case 14393:
	{
		PatchOffset = 0x4;
		break;
	}

	case 15063:
	{
		PatchOffset = 0x4;
		break;
	}
	default:
		PatchOffset = -1;
		break;
	}
	if (PatchOffset < 0) {
		return FALSE;
	}
	//inject dll 3 steps
	//1.open process 
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	if (!hProcess)
		return FALSE;
	pfnThreadRtn = GetProcAddress(GetModuleHandleW(L"Kernel32.dll"), "LoadLibraryW");
	size_t iProxyFileLen = wcslen(pwszProxyFile) * sizeof(WCHAR);
	//2.VirtualAlloc a space
	pwszPara = (PWSTR)VirtualAllocEx(hProcess, NULL, iProxyFileLen, MEM_COMMIT, PAGE_READWRITE);
	if (!pwszPara)
		return FALSE;
	//3. Write process
	WriteProcessMemory(hProcess, pwszPara, (PVOID)pwszProxyFile, iProxyFileLen, NULL);
	//start patch
	LPFN_KernelBaseGetGlobalData pKernelBaseGetGlobalData = NULL;
	
	pKernelBaseGetGlobalData = (LPFN_KernelBaseGetGlobalData)GetProcAddress(LoadLibraryW(L"KernelBase.dll"), "KernelBaseGetGlobalData");

	pGlobalData = (UCHAR*)pKernelBaseGetGlobalData();

	pMisc = pGlobalData + PatchOffset;
	*pMisc = 1;
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pfnThreadRtn, pwszPara, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, pwszPara, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	return TRUE;
}


typedef long(__fastcall *RTLADJUSTPRIVILEGE64)(ULONG, ULONG, ULONG, PVOID);
RTLADJUSTPRIVILEGE64 RtlAdjustPrivilege;

int main(void)
{
	WCHAR dllName[MAX_PATH] = { 0 };
	DWORD dwPID = 0, dwRetVal = 0;
	RtlAdjustPrivilege = (RTLADJUSTPRIVILEGE64)GetProcAddress(LoadLibraryW(L"ntdll.dll"), "RtlAdjustPrivilege");
	RtlAdjustPrivilege(20, 1, 0, &dwRetVal);//debug privilege
	printf("input pid: ");
	scanf("%ld", &dwPID);
	printf("input dll full path: ");
	scanf("%ws", dllName);
	InjectDllExW(dwPID, dllName);
	getchar();
	return 0;
}