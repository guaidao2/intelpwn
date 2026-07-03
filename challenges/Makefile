# Challenge编译脚本
# make all     — 编译全部
# make clean   — 清理
# make test    — 编译 + 用 intelpwn 分析

CC = gcc
CFLAGS = -Wall -no-pie -fno-stack-protector -z execstack -m64 -o

# 带保护的 flag 集
NOPIE  = -no-pie
PIE    = -pie -fpie
NOCAN  = -fno-stack-protector
CANARY = -fstack-protector-strong
NX     = -z noexecstack
EXEC   = -z execstack
X86    = -m32

all: \
	challenge_ret2win \
	challenge_ret2win_canary \
	challenge_ret2libc \
	challenge_fmtstr \
	challenge_shellcode \
	challenge_rop \
	challenge_pie \
	challenge_fmtstr_canary

# ── 1. 最简单的 ret2win ──
challenge_ret2win: challenge_ret2win.c
	$(CC) $(CFLAGS) $@ $< $(NOPIE) $(NOCAN) $(NX)

# ── 2. ret2win + canary (需要 leak canary) ──
challenge_ret2win_canary: challenge_ret2win_canary.c
	$(CC) $(CFLAGS) $@ $< $(NOPIE) $(CANARY) $(NX)

# ── 3. ret2libc (无 backdoor 函数) ──
challenge_ret2libc: challenge_ret2libc.c
	$(CC) $(CFLAGS) $@ $< $(NOPIE) $(NOCAN) $(NX)

# ── 4. 格式化字符串 ──
challenge_fmtstr: challenge_fmtstr.c
	$(CC) $(CFLAGS) $@ $< $(NOPIE) $(NOCAN) $(NX)

# ── 5. shellcode 注入 (无 NX) ──
challenge_shellcode: challenge_shellcode.c
	$(CC) $(CFLAGS) $@ $< $(NOPIE) $(NOCAN) $(EXEC)

# ── 6. ROP 链 (无 system, 需要 execve syscall) ──
challenge_rop: challenge_rop.c
	$(CC) $(CFLAGS) $@ $< $(NOPIE) $(NOCAN) $(NX)

# ── 7. PIE 开启 ──
challenge_pie: challenge_pie.c
	$(CC) $(CFLAGS) $@ $< $(PIE) $(NOCAN) $(NX)

# ── 8. 格式化字符串 + canary ──
challenge_fmtstr_canary: challenge_fmtstr_canary.c
	$(CC) $(CFLAGS) $@ $< $(NOPIE) $(CANARY) $(NX)

# ── 测试 ──
test: all
	@echo "===== 测试 IntelPwn 分析 ====="
	python3 ../intelpwn.py analyze challenge_ret2win -q
	python3 ../intelpwn.py analyze challenge_fmtstr -q
	python3 ../intelpwn.py analyze challenge_shellcode -q
	python3 ../intelpwn.py analyze challenge_ret2libc -q
	python3 ../intelpwn.py analyze challenge_pie -q

clean:
	rm -f challenge_ret2win challenge_ret2win_canary \
	      challenge_ret2libc challenge_fmtstr \
	      challenge_shellcode challenge_rop \
	      challenge_pie challenge_fmtstr_canary
	rm -rf ../reports
