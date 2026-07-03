// ROP 链: 无 system 无 execve, 需要构造 execve syscall
// gcc -no-pie -fno-stack-protector -z noexecstack -m64
// 保护: No Canary, No PIE, NX
#include <stdio.h>
#include <unistd.h>

void vulnerable() {
    char buf[16];
    printf("ROP me: ");
    read(0, buf, 128);  // 溢出!
}

int main() {
    vulnerable();
    return 0;
}
