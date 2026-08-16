// challenge_tcache_dup — tcache poisoning 教学题 (Partial RELRO / NoPIE / NoCanary)
// 漏洞: delete 释放后不置 NULL → UAF (edit 可写 freed chunk) → tcache poisoning
// 菜单: 1.add(size+data) 2.delete(idx) 3.show(idx) 4.edit(idx+data) 5.exit
// show 用 write 原始字节 (泄露 safe-linking 编码的 fd)
// 编译: gcc -o challenge_tcache_dup challenge_tcache_dup.c -no-pie -fno-stack-protector
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void *chunks[0x10];
unsigned int sizes[0x10];
int cnt = 0;

void add() {
    if (cnt >= 0x10) { puts("full"); return; }
    printf("size: ");
    unsigned int size; scanf("%u", &size); getchar();
    if (size > 0x100) { puts("too big"); return; }
    chunks[cnt] = malloc(size);
    sizes[cnt] = size;
    printf("data: ");
    read(0, chunks[cnt], size);
    cnt++;
    printf("done\n");
}

void delete() {
    printf("idx: ");
    unsigned int idx; scanf("%u", &idx); getchar();
    if (idx >= 0x10) return;
    free(chunks[idx]);   // 不置 NULL → UAF / double-free 原语
    printf("done\n");
}

void show() {
    printf("idx: ");
    unsigned int idx; scanf("%u", &idx); getchar();
    if (idx >= 0x10) return;
    puts(chunks[idx]);   // puts 参数 = chunk 指针 (可控) — poisoning 覆写 puts@got 后触发 system
}

void edit() {
    printf("idx: ");
    unsigned int idx; scanf("%u", &idx); getchar();
    if (idx >= 0x10) return;
    printf("data: ");
    read(0, chunks[idx], sizes[idx]);    // UAF 写 freed chunk
    printf("done\n");
}

// 生成 system@plt (教学: tcache poisoning 覆写 puts@got = system@plt)
void hidden_backdoor(void) {
    system("echo backdoor");
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    while (1) {
        printf("%s", "1. add\n2. delete\n3. show\n4. edit\n5. exit\n");   // printf 菜单 (覆写 puts@got 不影响)
        printf("choice: ");
        int c; scanf("%d", &c); getchar();
        if (c == 1) add();
        else if (c == 2) delete();
        else if (c == 3) show();
        else if (c == 4) edit();
        else break;
    }
    return 0;
}
