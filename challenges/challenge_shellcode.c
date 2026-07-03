// shellcode 注入 (无 NX)
// gcc -no-pie -fno-stack-protector -z execstack -m64
// 保护: No Canary, No PIE, Executable Stack
#include <stdio.h>
#include <unistd.h>

void vulnerable() {
    char buf[128];
    printf("缓冲区地址: %p\n", buf);
    printf("输入 shellcode: ");
    read(0, buf, 256);  // 溢出!
}

int main() {
    vulnerable();
    return 0;
}
