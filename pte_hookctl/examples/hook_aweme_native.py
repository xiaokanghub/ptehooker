#!/usr/bin/env python3
"""
示例：aweme native hook —— 监控 libmetasec_ml.so 里的函数调用

目标场景：等 aweme 的签名 native 函数被调用，log 出参数。

注意：libmetasec_ml.so 用 RegisterNatives 动态绑定 JNI 函数，
所以我们不能直接按 JNI 名 hook。可以：
  - hook JNI_OnLoad 观察它做了什么
  - hook 具体的偏移（从 IDA 反编译得出）

这里演示 hook JNI_OnLoad — app 启动后应该马上被调用一次。
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ptehook


sess = ptehook.attach("com.ss.android.ugc.aweme")

def on_jni_onload(regs):
    # JNI_OnLoad 签名: jint JNI_OnLoad(JavaVM* vm, void* reserved)
    # X0 = JavaVM* , X1 = reserved
    print(f"  [LIBMETASEC] JNI_OnLoad called!  JavaVM* = 0x{regs[0]:x}")

# JNI_OnLoad 通常只在 .so 加载时调用一次，所以可能 aweme 已经装过了
# 如果 hook 后没看到事件，可能 aweme 早就加载过 libmetasec_ml 了
sess.native_hook(
    "libmetasec_ml.so",
    symbol="JNI_OnLoad",
    on_call=on_jni_onload,
)

print("[*] Navigate in aweme (swipe, login, post video) to trigger signing")
print("[*] Ctrl+C to stop")
try:
    sess.run(poll_hz=4)
finally:
    print("\nClean up:")
    sess.close()
