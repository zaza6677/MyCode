//used in Kronos malware
#ifdef _MSC_VER
    #include <stdint.h>
#else
    #include <inttypes.h>
#endif

#include <stdio.h>

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

int main()
{
    bool is64bit = is_system64_bit();
    if (is64bit) {
        printf("64 bit\n");	
    } else {
        printf("32 bit\n");
    }
    return is64bit;
}