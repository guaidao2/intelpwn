#!/bin/sh
# R4/R5 研究: PIE 变体 + tcache clear 串
cd /tmp
cat > /tmp/pie_test.c <<'CEOF'
#include <stdlib.h>
#include <unistd.h>
int main() { char b[64]; read(0, b, 64); system("/bin/sh"); }
CEOF
gcc -fPIE -pie -o /tmp/pie_test /tmp/pie_test.c 2>&1 | head -2
gcc -no-pie -o /tmp/nopie_test /tmp/pie_test.c 2>&1 | head -2
echo "=== PIE: call system 站点 ==="
objdump -d /tmp/pie_test | grep -aB5 'call.*<system@plt>' | head -8
echo "=== no-PIE: call system 站点 ==="
objdump -d /tmp/nopie_test | grep -aB5 'call.*<system@plt>' | head -8
echo "=== tcache: clear 字符串确认 ==="
strings /root/Desktop/intelpwn/challenges/challenge_tcache | grep -aE '^clear$|cat |/bin/sh'
