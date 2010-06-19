#include <asm/unistd.h>

#define __NR_dummy 338

.data
data:
    .long  0xAABBCCDD
    .long  0x00112233
    .long  0xDEADBEEF
    .long  0xDEADC0DE
    .long  0x00FA7CA7

    len = . - data

.text

.global main
main:
    movl $__NR_dummy, %eax
    movl $data, %ebx
    movl $len, %ecx
    int $0x80

    /* exit(O) */
    movl $__NR_exit, %eax
    movl $0, %ebx
    int $0x80