// challenge_angr_hidden — 静态模式匹配漏检, 需 angr 符号执行主动发现
//
// 漏洞: vuln 的栈缓冲 buf[0x20] 传入 copy_user, 其中 strcpy(dst, src) 无界拷贝
// 静态检测: copy_user 函数内无 lea [rbp-X] (src 是全局), 无界写目标未与栈链接
//           → 静态漏检; vuln 调 copy_user (非危险函数) → 也不报
// angr 主动发现: 跟踪 rdi 指向栈区 + strcpy 无界写 → 发现溢出, 算出 padding
//
// 编译: gcc -no-pie -fno-stack-protector -o challenge_angr_hidden challenge_angr_hidden.c
#include <stdio.h>
#include <unistd.h>
#include <string.h>

void win(void) {
    write(1, "PWNED\n", 6);
    _exit(0);
}

char src[0x100];  // 全局输入缓冲 — copy_user 无栈局部变量

void copy_user(char *dst) {
    read(0, src, 0x100);   // 用户输入到全局
    strcpy(dst, src);      // 无界拷贝到调用者的栈缓冲 → 溢出
}

void vuln(void) {
    char buf[0x20];        // 栈缓冲
    copy_user(buf);
}

int main(void) {
    setbuf(stdout, NULL);
    printf("win: %p\n", win);
    vuln();
    return 0;
}
