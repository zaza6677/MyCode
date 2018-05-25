// mod by xjun

#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <vector>
#include "crc32.h"

#include "../../common/ntdll/ntdll.h"

#pragma comment(lib,"../../common/ntdll_x86.lib")

typedef struct _CRCPAGE_HASH
{
	PVOID		m_startAddr;
	DWORD		m_size;
	DWORD		m_hash;
}CRCPAGE_HASH, *PCRCPAGE_HASH;

std::vector<CRCPAGE_HASH>	g_crcPage;

VOID _CRCheck()
{
    DWORD	start,size;

	//1.更早的 计算一遍页面CRC
	PVOID		imagebase = GetModuleHandle(NULL);

	PIMAGE_DOS_HEADER	pDosHead = (PIMAGE_DOS_HEADER)imagebase;
	PIMAGE_NT_HEADERS	pNtHead;
	PIMAGE_SECTION_HEADER	pSec;
	CRCPAGE_HASH	ctx;

	if (pDosHead->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return;
	}
	pNtHead = (PIMAGE_NT_HEADERS)((ULONG_PTR)imagebase + pDosHead->e_lfanew);
	if (pNtHead->Signature != IMAGE_NT_SIGNATURE)
	{
		return;
	}
	pSec = IMAGE_FIRST_SECTION(pNtHead);

	g_crcPage.clear();
	for (int i = 0; i < pNtHead->FileHeader.NumberOfSections; i++)
	{
		if (pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			//
			// start 计算CRC起始地址 size 计算CRC大小
			//

			start = (ULONG_PTR)imagebase + pSec->VirtualAddress;
			size = (ULONG_PTR)pSec->Misc.VirtualSize;


			ctx.m_startAddr = (PVOID)start;
			ctx.m_size = size;

			ctx.m_hash =crc32((const void*)start, size);

			g_crcPage.push_back(ctx);

		}

		pSec++;
	}

}

int main(void)
{
    while (TRUE)
	{
		for (auto ctx : g_crcPage)
		{
			if (crc32(ctx.m_startAddr,ctx.m_size) != ctx.m_hash)
			{
				printf("PAGE modified Addr = %08X Size = %08X\n",
					 ctx.m_startAddr,
					 ctx.m_size);
                return 0;
			}
		}

		//getchar();
	}
}

