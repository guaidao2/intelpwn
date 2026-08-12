// challenge_ret2text — ret2text 靶子 (win 函数名非标准, 需代码模式扫描)
//
// 参考 /root/Desktop/pwntest/pwn1 (2021 编译): win 函数叫 func 不在标准名单,
// 内部 float 校验通过才走 system("cat /flag")。正确打法是 ret 到
// "mov edi, cat_flag; call system" 序列起点 (跳过校验)。
// 仓库内 challenge_ret2text 二进制为原 pwn1, 本源码为行为重构。
//
// 编译: gcc -no-pie -fno-stack-protector -o challenge_ret2text challenge_ret2text.c
#include <stdio.h>
#include <stdlib.h>

void func(void) {
    float f = 0.0;
    puts("input:");
    char buf[0x30];
    gets(buf);
    if (f == 0.0) {
        system("cat /flag");
    } else {
        puts("no");
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    func();
    return 0;
}
