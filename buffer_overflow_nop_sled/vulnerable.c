#include <string.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    unsigned int esp, ebp;
    char buf[512];

    __asm__ volatile ("movl %%esp, %0   \n"
                      "movl %%ebp, %1   \n"
                      : "=r"(esp), "=r"(ebp) : );

    printf("esp: 0x%08X\n", esp);
    printf("ebp: 0x%08X\n", ebp);
    printf("esp-ebp: %d\n", (int)esp - (int)ebp);
    printf("&buf: 0x%08X\n", &buf);

    if (argc > 1) {
        strcpy(buf, argv[1]);
    }

    return 0;
}
