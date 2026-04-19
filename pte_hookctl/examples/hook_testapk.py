#!/usr/bin/env python3
"""
示例：hook test_apk 的 Secret.checkLicense + libc strcmp

用法：
    cd pte_hookctl
    ADB_SERIAL=<your-device-serial> python3 examples/hook_testapk.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ptehook


# 1. 附着到目标进程
sess = ptehook.attach("com.ptehook.demo")

# 2. Java hook - 让 checkLicense 返回 999
sess.java_hook(
    "Lcom/ptehook/demo/Secret;",
    "checkLicense",
    "(I)I",
    replace=999,
)

# 3. Java hook - 拦截+log 参数
def on_check_called(regs):
    # regs = [X0..X7] (整数)
    # X0 = ArtMethod*, X1 = userId
    print(f"  [JAVA] checkLicense called: userId_register=0x{regs[1]:x}")

# （第二个 hook 会覆盖第一个 — 同一 ArtMethod；用户只该装一个）
# sess.java_hook(
#     "Lcom/ptehook/demo/Secret;",
#     "checkLicense",
#     "(I)I",
#     on_call=on_check_called,
# )

# 4. Native hook - libc strcmp 监控
def on_strcmp(regs):
    print(f"  [NATIVE] strcmp x0=0x{regs[0]:x} x1=0x{regs[1]:x}")

# 注意: libc 里 strcmp 可能不存在，换成 strcpy 或其他常用函数
# sess.native_hook(
#     "libc.so",
#     symbol="strcmp",
#     on_call=on_strcmp,
# )

# 5. 启动事件循环 - Ctrl+C 退出
try:
    sess.run(poll_hz=5)
finally:
    print("\nClean up:")
    sess.close()
