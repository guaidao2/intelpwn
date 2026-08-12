// challenge_tcache — 现代 glibc UAF + tcache poisoning 堆靶子
//
// glibc >= 2.32: tcache safe-linking + double-free 检测, __free_hook 在 2.34 移除
// 利用路径 (本靶子可打):
//   1. show 泄露堆地址 (解码 safe-linking) → heap base
//   2. UAF (free 后不置空) → tcache poisoning: 伪造 fd = free@got ^ (heap>>12)
//   3. malloc 返回 free@got → edit 写入 system@plt (system 已导入)
//   4. free(含 "/bin/sh" 的 chunk) → system("/bin/sh")
//
// 保护: NX, 无 canary, 无 PIE, partial RELRO (GOT 可写)
//
// 编译: gcc -no-pie -fno-stack-protector -o challenge_tcache challenge_tcache.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void *chunks[8];
size_t sizes[8];
int count = 0;

void alloc(void) {
    if (count >= 8) { puts("full"); return; }
    char buf[16];
    printf("size: ");
    fgets(buf, sizeof buf, stdin);
    size_t sz = strtoul(buf, NULL, 0);
    int idx = count++;
    chunks[idx] = malloc(sz);
    sizes[idx] = sz;
    printf("chunk[%d] @ %p (heap 泄露, 用于 safe-linking 解码)\n", idx, chunks[idx]);
    printf("data: ");
    read(0, chunks[idx], sz);
}

void free_chunk(void) {
    char buf[8];
    printf("idx: ");
    fgets(buf, sizeof buf, stdin);
    int idx = atoi(buf);
    if (idx < 0 || idx >= count || !chunks[idx]) { puts("invalid"); return; }
    free(chunks[idx]);
    // UAF: 不置空 chunks[idx], 之后 show/edit 仍可访问
}

void show(void) {
    char buf[8];
    printf("idx: ");
    fgets(buf, sizeof buf, stdin);
    int idx = atoi(buf);
    if (idx < 0 || idx >= count || !chunks[idx]) { puts("invalid"); return; }
    write(1, chunks[idx], sizes[idx]);
}

void edit(void) {
    char buf[8];
    printf("idx: ");
    fgets(buf, sizeof buf, stdin);
    int idx = atoi(buf);
    if (idx < 0 || idx >= count || !chunks[idx]) { puts("invalid"); return; }
    printf("data: ");
    read(0, chunks[idx], sizes[idx]);
}

int main(void) {
    setbuf(stdout, NULL);
    system("clear");  // system 导入进 PLT, 作为 GOT 覆写目标
    char buf[4];
    while (1) {
        printf("[1]alloc [2]free [3]show [4]edit [5]exit\n> ");
        fgets(buf, sizeof buf, stdin);
        switch (buf[0]) {
            case '1': alloc(); break;
            case '2': free_chunk(); break;
            case '3': show(); break;
            case '4': edit(); break;
            default: return 0;
        }
    }
}
