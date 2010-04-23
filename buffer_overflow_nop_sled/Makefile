all:
	@echo Disable VA space randomization
	@sudo sh -c 'echo 0 > /proc/sys/kernel/randomize_va_space'
	@gcc -g vulnerable.c -o vulnerable -fno-stack-protector -z execstack
	@gcc shellcode.c -o shellcode