// 格式化字符串漏洞
// gcc -no-pie -fno-stack-protector -z noexecstack -m64
// 保护: No Canary, No PIE, NX
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
