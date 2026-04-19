#!/usr/bin/env python3
"""
⚠️ 废弃示例 —— 7.2 trap 模式不兼容 CallBackupJava。

旧路径（改 ArtMethod.entry_point + ACC_NATIVE）依赖 temp-unhook 技巧，
在 trap 模式下不适用。新代码请走下面两种之一：

  1. 需要 onEnter（仅 pre-call）：用 `on_call=` 回调
  2. 需要 onEnter + onLeave：目前 Java 侧还不支持，用 Native CallBackup 代替
     或退回 legacy 路径（legacy_entry_patch=True）牺牲 stealth

保留此文件以示标识，真跑 demo 见 `hook_testapk.py` / `hook_aweme_frameSign.py`。
"""
import sys

print(__doc__)
sys.exit(0)
