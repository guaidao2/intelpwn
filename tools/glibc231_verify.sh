#!/bin/bash
# 老 glibc (2.31) 验证环境搭建 + tcache poisoning 完整链实测
# 用途: Kali (glibc 2.42, 无 docker) 上验证"经典 GOT→system"路径 — 2.34+ 被移除的
#       __free_hook/无 safe-linking 场景用 2.31 环境复现。
#
# 用法: bash tools/glibc231_verify.sh
# 产出: /tmp/glibc231/ (ld-2.31.so + libc-2.31.so) + /tmp/ctc231 (2.31 重链接靶子)
# 验证: python tools/glibc231_pwn.py   # 完整 tcache poisoning → GOT 覆写 → system 执行

set -e
L=/tmp/glibc231/extracted/lib/x86_64-linux-gnu

if [ ! -f "$L/ld-2.31.so" ]; then
    echo "[*] 下载 Ubuntu focal (20.04) libc6 2.31 ..."
    mkdir -p /tmp/glibc231 && cd /tmp/glibc231
    curl -sO "http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.31-0ubuntu9.18_amd64.deb"
    dpkg-deb -x libc6_2.31-0ubuntu9.18_amd64.deb extracted/
    echo "[+] ld-2.31.so + libc-2.31.so 就绪"
fi

if [ ! -f /tmp/ctc231 ]; then
    echo "[*] 用 2.31 libc 重新链接 challenge_tcache_dup (规避 __isoc23_scanf@2.38) ..."
    gcc -o /tmp/ctc231 challenges/challenge_tcache_dup.c -no-pie -fno-stack-protector \
        -std=c11 -U_GNU_SOURCE -D_POSIX_C_SOURCE=200809L \
        -Xlinker -rpath -Xlinker "$L" \
        -Xlinker --dynamic-linker -Xlinker "$L/ld-2.31.so" \
        "$L/libc.so.6"
    echo "[+] /tmp/ctc231 就绪 (2.31 环境)"
fi

echo "[*] 验证 2.31 运行:"
echo "0" | "$L/ld-2.31.so" --library-path "$L" /tmp/ctc231 | head -3
echo ""
echo "[*] 下一步: python tools/glibc231_pwn.py  # tcache poisoning 完整链"
