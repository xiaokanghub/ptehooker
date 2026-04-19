"""
ptehook - 类 Frida 的上层 hook 框架

用户只写 Python 脚本声明 hook 目标和行为，框架负责：
- 拉目标 APK、DEX parse 找 method_idx
- 跨进程扫 ArtMethod / 解析 .so 符号
- 生成 shellcode 并安装 KPM hook
- 轮询 ghost log buffer，触发用户 Python 回调

Usage:
    import ptehook

    sess = ptehook.attach("com.target.app")

    # Java hook - 替换返回值
    sess.java_hook("Lcom/target/Foo;", "bar", "(I)I", replace=42)

    # Java hook - 拦截参数 + 原返回
    sess.java_hook("Lcom/target/Foo;", "baz", "()V",
                    on_call=lambda args: print(f"baz called args={args}"))

    # Native hook
    sess.native_hook("libc.so", "strcmp",
                      on_call=lambda args: print(f"strcmp x0=0x{args[0]:x}"))

    # 启动事件循环（阻塞读 log）
    sess.run()
"""

from .session import Session, attach
from .actions import ReturnConst, LogArgs, Noop, CallBackup, CallBackupJava

__all__ = ["Session", "attach", "ReturnConst", "LogArgs", "Noop",
           "CallBackup", "CallBackupJava"]
