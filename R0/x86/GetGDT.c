//#include<wdm.h>
#include<ntifs.h>
#include<ntimage.h>

#pragma warning(disable:4055)
#pragma warning(disable:4152)
#pragma warning(disable:4214)

UCHAR shellcode[]={
    "\x48\x8b\xc1"
    "\x0f\x01\x00"
    "\xc3"
}

#pragma pack(push,1)
typedef struct _IA32_SYS_TR
{
    USHORT talbeLimit;
    LONG64 tableBase;
}IA32_SYS_TR,*PIA32_SYS_TR;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct _GDTable
{
    USHORT seglimit1;
    USHORT baseAddress1;
    UCHAR baseAddress2;
    UCHAR type : 4;
    UCHAR s : 1;
    UCHAR dpl : 2;
    UCHAR p : 1;
    UCHAR seglimit2 : 4;
    UCHAR avl : 1;
    UCHAR l : 1;
    UCHAR DB : 1;
    UCAHR G : 1;
    UCHAR baseAddress3;
}GDT,*PGDT;
#pragma pack(pop)

typedef VOID (*Shell)(PIA32_SYS_TR);


NTSTATUS DriverUnload(PDRVIER_OBJECT drv)
{
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRVIER_OBJECT drv,PUNICODE_STRING regPath)
{
    drv->DriverUnload=DriverUnload;
    IA32_SYS_TR slbk;
    Shell function;
    function=(Shell)ExAllocatePool(NonPagedPool,8);
    memcpy(function,shellcode,8);
    function(&slbk);
    int num=(slbk.tableLimit+1)/8;
    DbgPrint("table limit is %d\ttalbe base is %d\t\n",slbk.tableLimit,slbk.tableBase);
    DbgPrint("GDT Descriptor Number is %d\n",num);
    PGDT gdt=(PGDT)slbk.tablebase;
    for(int i=0;i<num;i++){
        DbgPrint("DPL : %x\n",gdt->dpl);
        DbgPrint("limit : %x\t%x\n",gdt->seglimit2,gdt->seglimit1);
        gdt++;
    }
    ExFreePool(function);
    return STATUS_SUCCESS;
}

