#!/usr/bin/env python3
"""
aweme MSManager.frameSign 实战示例 —— 展示完整的 production 用法：
  - java_hook_all 处理多 ClassLoader
  - jit_watch=True 处理 ART tier 升级
  - unsafe_bridge=True 允许 bridge 页安装（演示，真实场景看威胁模型）
  - close() 自动清 UXN + ghost + watcher

用法：
    adb -s $ADB_SERIAL shell "monkey -p com.ss.android.ugc.aweme -c android.intent.category.LAUNCHER 1"
    # 等 aweme 起来
    ADB_SERIAL=<your-device-serial> python3 examples/hook_aweme_frameSign.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ptehook
import kpm_client as K


def main():
    sess = ptehook.attach("com.ss.android.ugc.aweme")

    def on_called(regs):
        # MSManager.frameSign(String, int) 虚方法：
        # X0 = ArtMethod*, X1 = this, X2 = String ref (compressed), X3 = int
        print(f"  frameSign called: this=0x{regs[1]:x} "
              f"str_ref=0x{regs[2]:x} int={regs[3] & 0xFFFFFFFF}")

    installed = sess.java_hook_all(
        "Lcom/bytedance/mobsec/metasec/ml/MSManager;",
        "frameSign",
        "(Ljava/lang/String;I)Ljava/util/Map;",
        on_call=on_called,            # 改 replace=0 可以让 app 拿到 null
        unsafe_bridge=True,
        jit_watch=True,
    )

    if not installed:
        print("[-] 没装上任何 hook —— aweme 可能没启动或 frameSign 类未加载")
        return 1

    print(f"[+] 装了 {len(installed)} 个 hook，等事件 ...")
    print("    提示：aweme 正常用时（登录/发视频/评论）会调 frameSign 签名")

    try:
        sess.run(poll_hz=5)
    except KeyboardInterrupt:
        print("\n[*] Ctrl+C, 清理 ...")
    finally:
        # 进程仍活时会把 UXN 都撤、PTE 都清；进程死了也 OK（KPM reap）
        sess.close()
        print("[+] done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
