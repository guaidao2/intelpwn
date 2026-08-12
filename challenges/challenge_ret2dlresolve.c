// challenge_ret2dlresolve — ret2dlresolve 利用靶子 (无 libc 泄露路径)
//
// 注意: glibc>=2.40 的 ld.so 加固已使经典 ret2dlresolve 失效
//       (Kali 2026 = glibc 2.42, 本靶子用于 glibc<2.40 环境验证模板)
// 保护: NX 开, 无 canary, 无 PIE, partial RELRO (默认)
// PLT 无 system — 需通过 read + 可写 .bss 伪造 dl 解析结构动态解析 system
// 内嵌 gadgets: pop rdi/rsi/rdx; ret (pwntools ROP 需要)
// 漏洞: read(0, buf, 0x200) 栈溢出
//
// 编译: gcc -no-pie -fno-stack-protector -o challenge_ret2dlresolve challenge_ret2dlresolve.c
#include <stdio.h>
#include <unistd.h>

__attribute__((naked)) void gadget_pop_rdi(void) { __asm__("pop %rdi; ret"); }
__attribute__((naked)) void gadget_pop_rsi(void) { __asm__("pop %rsi; ret"); }
__attribute__((naked)) void gadget_pop_rdx(void) { __asm__("pop %rdx; ret"); }

void vuln(void) {
    char buf[0x40];
    puts("ret2dlresolve");
    read(0, buf, 0x200);
}

int main(void) {
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
