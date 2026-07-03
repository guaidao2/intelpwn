// 最简单的栈溢出: ret2win
// gcc -no-pie -fno-stack-protector -z execstack -m64
// 保护: No Canary, No PIE, No NX
#include <stdio.h>
#include <unistd.h>

void win() {
    printf("🎉 You win! Shell incoming...\n");
    execve("/bin/sh", NULL, NULL);
}

void vulnerable() {
    char buf[64];
    printf("缓冲区地址: %p\n", buf);
    printf("win 函数地址: %p\n", &win);
    printf("输入: ");
    read(0, buf, 256);  // 溢出!
}

int main() {
    vulnerable();
    return 0;
}
