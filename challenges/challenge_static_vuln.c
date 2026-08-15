#include <stdio.h>
#include <stdlib.h>
extern char *gets(char *);
void win() { system("/bin/sh"); }
void vulnerable() { char buf[64]; gets(buf); }
int main() { setvbuf(stdout, NULL, _IONBF, 0); puts("Input:"); vulnerable(); return 0; }
