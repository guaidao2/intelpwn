#include <stdio.h>
#include <stdlib.h>
/* 32 位靶子: gets 栈溢出 → ret2win (win) / ret2system (system@plt + /bin/sh) */
extern char *gets(char *);  /* glibc 2.4x 移除 gets, 显式声明 */
void win() { system("/bin/sh"); }
void vulnerable() {
    char buf[40];
    gets(buf);
}
int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("Input:");
    vulnerable();
    return 0;
}
