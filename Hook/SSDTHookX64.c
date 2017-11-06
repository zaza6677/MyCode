/*
Based on TeslaAngel's && lamgublin  SSDT Hook Code
Modified by zaza6677@Kshom
2017/09/02

x86 SSDT: Getting ServiceTableBase Address could get every Service Function
Address
x64 SSDT: ServiceTablebase storage the offset address like ServiceTable[Index]
>> 4
The Service Function Address is ServiceTable[Index] >> 4 + ServiceTableBase

*/

#include <ntddk.h>
#include <ntifs.h>
#include <windef.h>

#pragma warning(disable : 4305)
#pragma warning(disable : 4152)

/*cli
cli
mov rax,cr0
mov rcx,rax
and eax,0fffeffffh
mov cr0,rax
mov rax,rcx
ret
*/
UCHAR shellcode[20] = "\xFA"                 // 0
                      "\x0F\x20\xC0"         // 3
                      "\x48\x8B\xC8"         // 6
                      "\x25\xFF\xFF\xFE\xFF" // 11
                      "\x0F\x22\xC0"         // 14
                      "\x48\x8B\xC1"         // 17
                      "\xC3";                // 18

KIRQL WPOFFx64() {
  KIRQL irql = KeRaiseIrqlToDpcLevel();
  UINT64 cr0 = __readcr0();
  cr0 &= 0xfffffffffffeffff;
  __writecr0(cr0);
  _disable();
  return irql;
}

/*
mov cr0,rcx
sti
ret
*/
UCHAR shellcode1[6] = "\x0F\x22\xC1" // 2
                      "\xFB"         // 3
                      "\xC3";        // 4

/*
  mov rax,0ffffffffffffffffh
  jmp rax
*/
UCHAR shellcode3[13] = "\x48\xB8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" // 9
                       "\xFF\xE0";                                // 11

void WPONx64(KIRQL irql) {
  UINT64 cr0 = __readcr0();
  cr0 |= 0x10000;
  _enable();
  __writecr0(cr0);
  KeLowerIrql(irql);
}

typedef ULONG (*CLOSEINTERUPT)();
typedef VOID (*OPENINTERUPT)(ULONG old_cr0);

// x64-->__fastcall x86-->__stdcall
typedef NTSTATUS(__fastcall *OldNtCreateFile)(
    _Out_ PHANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize, _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess, _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions, _In_opt_ PVOID EaBuffer, _In_ ULONG EaLength);
OldNtCreateFile old_NtCreateFile;

typedef struct ServiceDescriptorEntry {
  PVOID ServiceTableBase;
  PVOID ServiceCounterTableBase;
  ULONGLONG NumberOfServices;
  PVOID ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;

ULONGLONG GetKeServiceDescriptorTable64();
int FindServiceId(PVOID address);
ULONG GetAddressOffset(PServiceDescriptorTableEntry_t enterAddress,
                       ULONGLONG address, CHAR paramCount);
PVOID ChangeSsdt(PServiceDescriptorTableEntry_t address, int serviceId);
ULONG CloseInterupt();
void StartInterupt(ULONG old_cr0);

NTSTATUS __fastcall MyNtCreateFileFunc(
    _Out_ PHANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize, _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess, _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions, _In_opt_ PVOID EaBuffer, _In_ ULONG EaLength);

VOID ResetSsdt(PServiceDescriptorTableEntry_t address, int service_id);

PServiceDescriptorTableEntry_t ent;

NTSTATUS DriverUnload(PDRIVER_OBJECT driver) {
  UNREFERENCED_PARAMETER(driver);
  UNICODE_STRING func = RTL_CONSTANT_STRING(L"ZwCreateFile");
  PVOID funcAddress = MmGetSystemRoutineAddress(&func);
  ResetSsdt(ent, FindServiceId(funcAddress));
  return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING str) {
  UNREFERENCED_PARAMETER(driver);
  UNREFERENCED_PARAMETER(str);
  // DbgBreakPoint();
  driver->DriverUnload = DriverUnload;
  UNICODE_STRING func = RTL_CONSTANT_STRING(L"ZwCreateFile");
  PVOID funcAddress = MmGetSystemRoutineAddress(&func);
  int serviceId = FindServiceId(funcAddress);
  DbgPrint("ServiceId:%x\n", serviceId);
  ULONGLONG address = GetKeServiceDescriptorTable64();
  DbgPrint("0x%p\n", address);
  ent = (PServiceDescriptorTableEntry_t)address;
  DbgPrint("SSDT Entry:0x%p\n", ent->ServiceTableBase);
  DbgPrint("number of service:%d\n", ent->NumberOfServices);
  ChangeSsdt(ent, serviceId);
  return STATUS_SUCCESS;
}

ULONGLONG GetKeServiceDescriptorTable64() {
  PUCHAR StatrtSearchAddr = (PUCHAR)__readmsr(0xc0000082);
  PUCHAR EndSearchAddr = StatrtSearchAddr + 0x500;
  PUCHAR i = NULL;
  UCHAR b1 = 0, b2 = 0, b3 = 0;
  ULONG templong = 0;
  ULONGLONG addr = 0;

  for (i = StatrtSearchAddr; i < EndSearchAddr; i++) {
    if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) &&
        MmIsAddressValid(i + 2)) {
      b1 = *i;
      b2 = *(i + 1);
      b3 = *(i + 2);

      // fffff800`01ad0772 4c8d15c7202300  lea
      // r10,[nt!KeServiceDescriptorTable (fffff800`01d02840)]
      if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15) {
        memcpy(&templong, i + 3, 4);
        addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
        return addr;
      }
    }
  }
  return 0;
}

int FindServiceId(PVOID address) {
  UCHAR i1, i2 = 0;
  PUCHAR temp = address;
  for (; MmIsAddressValid(temp) && MmIsAddressValid(temp + 1); temp++) {
    i1 = *temp;
    i2 = *(temp + 1);
    if (i1 == 0xb8) // hard code
    {
      break;
    }
  }
  return i2;
}

PVOID ChangeSsdt(PServiceDescriptorTableEntry_t address, int serviceId) {
  ULONG old_cr0 = 0;
  ULONGLONG add;
  ULONGLONG ssdtEntry = (ULONGLONG)address->ServiceTableBase;
  PULONG serviceTableAddr = (PULONG)address->ServiceTableBase;
  LONG temp1 = serviceTableAddr[serviceId];
  temp1 = temp1 >> 4;
  add = ssdtEntry + temp1;
  old_NtCreateFile = (OldNtCreateFile)add;
  ULONGLONG myFuncAddress = (ULONGLONG)MyNtCreateFileFunc;
  DbgPrint("%p\n", myFuncAddress);
  memcpy(shellcode3 + 2, &myFuncAddress, 8);
  old_cr0 = CloseInterupt();
  memcpy(KeBugCheckEx, shellcode3, 13);
  serviceTableAddr[serviceId] =
      GetAddressOffset(address, (INT64)KeBugCheckEx, 11);
  StartInterupt(old_cr0);
  return (PVOID)add;
}

VOID ResetSsdt(PServiceDescriptorTableEntry_t address, int serviceId) {
  ULONG old_cr0 = 0;
  PULONG serviceTableAddr = (PULONG)address->ServiceTableBase;
  old_cr0 = CloseInterupt();
  memcpy(KeBugCheckEx, shellcode3, 13);
  serviceTableAddr[serviceId] = (ULONG)((ULONGLONG)old_NtCreateFile -
                                        (ULONGLONG)address->ServiceTableBase);
  StartInterupt(old_cr0);
}

ULONG CloseInterupt() {
  ULONG old_cr0;
  CLOSEINTERUPT func = ExAllocatePool(NonPagedPool, 20);
  memcpy(func, shellcode, 20);
  old_cr0 = func();
  ExFreePool(func);
  return old_cr0;
}

void StartInterupt(ULONG old_cr0) {
  OPENINTERUPT func = ExAllocatePool(NonPagedPool, 6);
  memcpy(func, shellcode1, 6);
  func(old_cr0);
  ExFreePool(func);
}

NTSTATUS __fastcall MyNtCreateFileFunc(
    _Out_ PHANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize, _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess, _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions, _In_opt_ PVOID EaBuffer, _In_ ULONG EaLength) {
  return NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                      IoStatusBlock, AllocationSize, FileAttributes,
                      ShareAccess, CreateDisposition, CreateOptions, EaBuffer,
                      EaLength);
}

#define SETBIT(x, y) x |= (1 << y)  //将X的第Y位置1
#define CLRBIT(x, y) x &= ~(1 << y) //将X的第Y位清0
#define GETBIT(x, y) (x & (1 << y)) //取X的第Y位，返回0或非0

ULONG GetAddressOffset(PServiceDescriptorTableEntry_t enterAddress,
                       ULONGLONG address, CHAR paramCount) {
  // wrong
  /*ULONG offset = (ULONG)(address - (INT64)enteraddress->ServiceTableBase);
  return offset << 4;
  */

  // correct
  LONG dwtmp = 0, i;
  CHAR b = 0, bits[4] = {0};
  PULONG ServiceTableBase = NULL;
  ServiceTableBase = (PULONG)enterAddress->ServiceTableBase;
  dwtmp = (LONG)(address - (ULONGLONG)ServiceTableBase);
  dwtmp = dwtmp << 4;
  //处理参数
  if (paramCount > 4)
    paramCount = paramCount - 4;
  else
    paramCount = 0;
  //获得dwtmp的第一个字节
  memcpy(&b, &dwtmp, 1);
  //处理低四位，填写参数个数
  for (i = 0; i < 4; i++) {
    bits[i] = GETBIT(paramCount, i);
    if (bits[i])
      SETBIT(b, i);
    else
      CLRBIT(b, i);
  }
  //把数据复制回去
  memcpy(&dwtmp, &b, 1);
  return dwtmp;
}