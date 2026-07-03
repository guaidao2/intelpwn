// ret2libc: 无 backdoor 函数, 需要 leak libc
// gcc -no-pie -fno-stack-protector -z noexecstack -m64
// 保护: No Canary, No PIE, NX
#include <stdio.h>
#include <unistd.h>

void vulnerable() {
    char buf[64];
    printf("Hello, World!\n");
    printf("输入: ");
    read(0, buf, 256);  // 溢出!
    write(1, "收到了\n", 12);
}

int main() {
    vulnerable();
    return 0;
}
