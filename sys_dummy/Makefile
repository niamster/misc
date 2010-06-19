CC=gcc
CCARM=arm-generic-linux-uclibcgnueabi-gcc

all:
	@echo "Available targets: x86, arm"

x86:
	@$(CC) sys_dummy.c -o sys_dummy_x86_c
	@$(CC) sys_dummy_x86_int80.S -o sys_dummy_x86_int80_S

arm:
	@$(CCARM) -march=armv5te -D_arm_=1 sys_dummy.c -o sys_dummy_arm_c
	@$(CCARM) -march=armv5te sys_dummy_arm.S -o sys_dummy_arm_S

clean:
	@rm -f sys_dummy_arm_S sys_dummy_x86_int80_S sys_dummy_arm_c sys_dummy_x86_c