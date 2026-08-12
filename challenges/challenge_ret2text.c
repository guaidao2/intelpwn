// challenge_ret2text — ret2text 靶子 (自编, 非比赛题目)
//
// 与 pwn1 同模式: win 函数名非标准 + system 命令调用, 需代码模式扫描
// (符号表 6 名名单找不到, 但 .text 里有 "mov edi, flag_str; call system" 序列)。
// 字符串用 "cat flag" (无路径前缀) — 验证命令特征对无斜杠变体也生效。
//
// 编译: gcc -no-pie -fno-stack-protector -o challenge_ret2text challenge_ret2text.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* glibc 2.16+ 不再默认声明 gets (已从 POSIX 移除), 显式声明使用 */
extern char *gets(char *s);

void backdoor_area(void) {
    char buf[0x30];
    puts("gimme:");
    gets(buf);                  // 栈溢出
    if (buf[0] == 'A') {
        system("cat flag");     // 命令执行目标 (代码模式扫描应命中)
    } else {
        puts("nope");
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    backdoor_area();
    return 0;
}
