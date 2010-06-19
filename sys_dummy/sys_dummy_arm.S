#include <asm/unistd.h>

#define __NR_dummy 366

data:
    .long  0xAABBCCDD
    .long  0x00112233
    .long  0xDEADBEEF
    .long  0xDEADC0DE
    .long  0x00FA7CA7

len:
    .long  . - data

.global main
    /* EABI syscall style */
main:
    ldr     r7, =__NR_dummy
    adr     r0, data
    ldr     r1, len
    swi     0

    /* exit(O) */
    mov     r7, #__NR_exit
    mov     r0, #0
    swi     0