#!/usr/bin/env python3
"""
示例：CallBackup —— log 参数 + 调原函数 + log 返回值（类似 Frida onEnter+onLeave）

测试对 test_apk 的某个 native 函数做 hook。这里以 libc 的 strlen 为例
（简单、有确定返回值、几乎所有 app 都调用）。

场景：
  1. Hook strlen in libc.so
  2. 拦截每次调用，记录 X0 (字符串指针) 和返回值
  3. 调用原 strlen 保持程序行为正常
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ptehook


sess = ptehook.attach("com.ptehook.demo")

def on_open_enter(regs):
    # open(const char *path, int flags, ...)
    # X0 = path pointer, X1 = flags
    print(f"  [open] → x0=0x{regs[0]:x} flags=0x{regs[1]:x}")

def on_open_leave(pre_regs, ret_x0, ret_x1):
    # ret_x0 = file descriptor or -errno
    fd = ret_x0 if ret_x0 < 0x80000000 else ret_x0 - (1 << 64)
    print(f"  [open] ← fd={fd}")

sess.native_hook(
    "libc.so",
    symbol="malloc",
    action=ptehook.CallBackup(on_call=on_open_enter, on_return=on_open_leave),
)

print("[*] malloc() called very frequently. Ctrl+C to stop.")
try:
    sess.run(poll_hz=10)   # 快一点采样
finally:
    print("\nClean up:")
    sess.close()
