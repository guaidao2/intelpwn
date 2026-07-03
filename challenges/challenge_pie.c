// PIE 开启的栈溢出: 需要先 leak 基址
// gcc -pie -fpie -fno-stack-protector -z noexecstack -m64
// 保护: No Canary, PIE, NX
#include <stdio.h>
#include <unistd.h>

void win() {
    printf("🎉 PIE bypassed!\n");
    execve("/bin/sh", NULL, NULL);
}

void vulnerable() {
    char buf[64];
    printf("缓冲区: %p\n", buf);
    printf("win: %p\n", &win);
    printf("输入: ");
    read(0, buf, 256);  // 溢出!
}

int main() {
    vulnerable();
    return 0;
}
