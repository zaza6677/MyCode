#ifdef _MSC_VER
    #include <stdint.h>
#else
    #include <inttypes.h>
#endif

#include <stdio.h>
#include <wchar.h>


//used in Kronos malware
bool is_system64_bit()
{
    uint32_t flag = 0;
#ifdef _MSC_VER
    __asm {
        xor eax, eax
        mov ax, cs
        shr eax, 5
        mov flag, eax
    };
#else
     __asm__ volatile (
        "xor %%eax, %%eax \n"
        "mov %%cs, %%ax \n"
        "shr $5, %%eax \n"
        "mov %%eax, %0 \n"
        :"=r"(flag) /* flag is output operand */
        :           /* no input operand */
        :"%eax");   /* %eax is clobbered */
#endif
    return (flag > 0);
}

bool detectArch_ES() {
#if defined(_MSC_VER)
    _asm {
        xor eax, eax
        mov ax, es
        ror ax, 0x3
        and eax, 0x1            
    }
#elif defined(__GNUC__)        
asm(  
        ".intel_syntax noprefix;"
        "xor eax, eax;"
        "mov ax, es;"
        "ror ax, 0x3;"
        "and eax, 0x1;"
            
    );
#endif
}

bool detectArch_ES() {
#if defined(_MSC_VER)
    _asm {
        xor eax, eax
        mov ax, es
        ror ax, 0x3
        and eax, 0x1            
    }
#elif defined(__GNUC__)        
asm(  
        ".intel_syntax noprefix;"
        "xor eax, eax;"
        "mov ax, es;"
        "ror ax, 0x3;"
        "and eax, 0x1;"
            
    );
#endif
}

bool detectArch_TEB() {
#if defined(_MSC_VER)
    _asm {
        xor eax, eax
        mov eax, fs:[0xc0]

    }
#elif defined(__GNUC__)        
    asm(
        ".intel_syntax noprefix;"
        "xor eax, eax;"
        "mov eax, fs:[0xc0];"
        );
#endif
}


int main()
{
    bool is64bit = is_system64_bit();
    if (is64bit) {
        printf("64 bit\n");	
    } else {
        printf("32 bit\n");
    }
   /* 
     wprintf(
        !detectArch_ES() ? 
        L"You are Running 32-bit\n" :
        L"You are Running 64-bit\n"
        );

    
    wprintf(
        !detectArch_GS() ?
        L"You are Running 32-bit\n" :
        L"You are Running 64-bit\n"
        );
        
    wprintf(
        !detectArch_TEB() ?
        L"You are Running 32-bit\n" :
        L"You are Running 64-bit\n"
        ); 
    */ 
    return is64bit;
}