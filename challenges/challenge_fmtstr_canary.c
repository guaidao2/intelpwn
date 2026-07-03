// 格式化字符串 + Canary
// gcc -no-pie -fstack-protector-strong -z noexecstack -m64
// 保护: Canary, No PIE, NX
#include <stdio.h>

void vulnerable() {
    char buf[256];
    printf("输入: ");
    fgets(buf, 256, stdin);
    printf(buf);  // 格式化字符串漏洞!
    printf("\n");
}

int main() {
    vulnerable();
    return 0;
}
