/* mini_configd - 模拟固件配置解析模块（key=value 文件 → 结构体数组） */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_ITEMS 8
#define MAX_KEY   16
#define MAX_VAL   32

typedef struct {
    char key[MAX_KEY];     // 16 字节
    char value[MAX_VAL];   // 32 字节
} item_t;

static item_t items[MAX_ITEMS];
static int count = 0;

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
    return s;
}

static int parse_line(char *line) {
    char *eq = strchr(line, '=');
    if (!eq) return -1;
    *eq = '\0';
    char *k = trim(line);
    char *v = trim(eq + 1);
    /* ← 漏洞在这：> 应为 >=。strlen(k)==16 时放行，
           strcpy 拷 16 字符 + '\0' = 17 字节 → 溢出 1 字节到 value[0] */
    if (strlen(k) > MAX_KEY || strlen(v) > MAX_VAL) {
        printf("field too long\n");
        return -1;
    }
    if (count >= MAX_ITEMS) return -1;
    strcpy(items[count].key, k);    // strlen(k)==16 时溢出（off-by-one）
    strcpy(items[count].value, v);
    count++;
    return 0;
}

static int load(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    char line[128];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';
        parse_line(line);
    }
    fclose(fp);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    load(argv[1]);
    printf("%d items loaded\n", count);
    return 0;
}

