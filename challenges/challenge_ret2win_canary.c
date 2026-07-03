// 栈溢出 + Canary: 需要先 leak canary
// gcc -no-pie -fstack-protector-strong -z noexecstack -m64
// 保护: Canary, No PIE, NX
#include <stdio.h>
#include <unistd.h>

void win() {
    printf("🎉 You beat the canary!\n");
    execve("/bin/sh", NULL, NULL);
}

void vulnerable() {
    char buf[64];
    printf("缓冲区地址: %p\n", buf);
    printf("win 函数地址: %p\n", &win);
    printf("输入: ");
    read(0, buf, 256);  // 溢出!
    printf("你说: %s\n", buf);
}

int main() {
    vulnerable();
    return 0;
}
