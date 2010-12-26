#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifdef _arm_
#define __NR_dummy 366
#else
#define __NR_dummy 338
#endif

int main(int argc, char **argv)
{
    unsigned int dummy_data[] = {0xAABBCCDD,
                                 0x00112233,
                                 0xDEADBEEF,
                                 0xDEADC0DE,
                                 0x00FA7CA7};
    int dummy_len = sizeof(dummy_data);

    printf("calling sys_dummy, #%d with %d long data\n", __NR_dummy, dummy_len);
    if (syscall(__NR_dummy, (const char *)dummy_data, dummy_len))
        printf("Error: %s\n", strerror(errno));

    printf("calling sys_dummy, #%d with NULL data\n", __NR_dummy);
    if (syscall(__NR_dummy, NULL, 0))
        printf("Error: %s\n", strerror(errno));

    return 0;
}
