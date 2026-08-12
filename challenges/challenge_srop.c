// challenge_srop — SROP (sigreturn) 利用靶子
//
// 保护: NX 开, 无 canary, 无 PIE
// 内嵌 gadgets: pop rdi; ret / pop rsi; ret / pop rdx; ret / syscall; ret
// /bin/sh 字符串在 .data (地址固定)
// 漏洞: read(0, buf, 0x400) 栈溢出
//
// 编译: gcc -no-pie -fno-stack-protector -o challenge_srop challenge_srop.c
#include <stdio.h>
#include <unistd.h>

__attribute__((naked)) void gadget_pop_rdi(void) { __asm__("pop %rdi; ret"); }
__attribute__((naked)) void gadget_pop_rsi(void) { __asm__("pop %rsi; ret"); }
__attribute__((naked)) void gadget_pop_rdx(void) { __asm__("pop %rdx; ret"); }
__attribute__((naked)) void gadget_syscall(void)  { __asm__("syscall; ret"); }

char binsh[] = "/bin/sh";

void vuln(void) {
    char buf[0x40];
    printf("binsh: %p\n", binsh);
    read(0, buf, 0x400);
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
