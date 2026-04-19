# ptehooker

**ARM64 Android 无痕 Hook 框架** — 基于 KernelPatch KPM + PTE UXN 陷阱 + VMA-less ghost 内存，
实现跨进程零字节修改、零 `.so` 注入、零 `TracerPid` 的 hook。

- 发想来自看雪论坛 [thread-290718](https://bbs.kanxue.com/thread-290718.htm) 第 7.2 节"方案 C"骨架的工程落地
- 对付常见用户态反作弊（CRC 扫描、`/proc/maps` 扫描、TracerPid 检查、ArtMethod 字段扫描等）都能过
- 面向 ARM64 Android，API 30-35，kernel 4.9 / 5.4 / 5.10

## 快速开始

```python
import ptehook

sess = ptehook.attach("com.target.app")

sess.java_hook(
    "Lcom/target/License;", "isVIP", "()Z",
    replace=1,              # 让 isVIP() 恒返回 true
    unsafe_bridge=True,     # DBI 修好后安全
    wait_jit=True,          # entry_point 迁至 JIT 私有页，stealth 最优
    jit_watch=True,         # UAF 修好后可用，自动应对 ART tier 升级
)
sess.run()
sess.close()
```

## 完整文档

**→ [`docs/ARCHITECTURE_AND_USAGE.md`](docs/ARCHITECTURE_AND_USAGE.md)** — 技术架构 / 威胁模型 / 构建部署 / API 参考 / 排错 / 对比 Frida

## 仓库结构

```
ptehooker/
├── test_kmod/                KPM 内核模块
│   ├── ptehook_planc_v2.c      主文件：ctl 命令 + fault handler
│   ├── dbi_kern.{c,h}          ARM64 DBI 重编译引擎
│   ├── ghost_mm.{c,h}          VMA-less 物理页分配
│   └── Makefile.planc
│
├── pte_hookctl/              Python host + 设备侧 C 工具
│   ├── ptehook/                类 Frida 高层 API (Session, Action)
│   ├── kpm_client.py           ctl 命令封装
│   ├── shellcode.py            ARM64 shellcode 生成
│   ├── dex_parser.py           APK → method_idx
│   ├── art_offsets.py          per-Android-API 的 ArtMethod 偏移表
│   ├── device_scanner.c        设备侧 C 程序（编译成 pte_scan）
│   ├── examples/               使用示例
│   └── tests/                  29 个单元测试
│
└── docs/                     架构和使用文档
```

## 构建与依赖

### 依赖

- Android 设备 + Root + [APatch](https://github.com/bmax121/APatch) v0.12.2+
- Android NDK r21+（有 `aarch64-linux-android29-clang`）
- Python 3.8+
- 本仓库作为 [KernelPatch](https://github.com/bmax121/KernelPatch) 的下游 KPM，需要本地有 KernelPatch 源码

### 构建 KPM

```bash
export KP_DIR=/path/to/KernelPatch                # 必填
export NDK_DIR=/path/to/android-ndk-r21/toolchains/llvm/prebuilt/linux-x86_64   # 必填
cd test_kmod
make -f Makefile.planc
# 产出: ptehook_planc_v2.kpm
```

### 构建设备侧工具

```bash
$NDK_DIR/bin/aarch64-linux-android29-clang -O2 -static \
    -o pte_scan pte_hookctl/device_scanner.c
```

### 部署到设备

```bash
export ADB_SERIAL=<your-device-serial>

# 一次性准备 superkey
adb -s $ADB_SERIAL shell "su -c 'mkdir -p /data/adb/ptehook && \
    echo YOUR_APATCH_SUPERKEY > /data/adb/ptehook/superkey && \
    chmod 600 /data/adb/ptehook/superkey'"

# 推送
adb -s $ADB_SERIAL push test_kmod/ptehook_planc_v2.kpm pte_scan /data/local/tmp/
adb -s $ADB_SERIAL shell "su -c 'chmod 755 /data/local/tmp/pte_scan'"

# 加载 KPM
SK=$(adb -s $ADB_SERIAL shell "su -c 'cat /data/adb/ptehook/superkey'")
adb -s $ADB_SERIAL shell "su -c '/data/adb/kpatch $SK kpm load /data/local/tmp/ptehook_planc_v2.kpm'"
```

### 运行 hook 脚本

```bash
cd pte_hookctl
ADB_SERIAL=<your-device-serial> python3 examples/hook_testapk.py
```

### 跑单元测试

```bash
python3 pte_hookctl/tests/test_shellcode.py
# Ran 29 tests in 0.006s / OK
```

## 和 Frida / LSPlant / wxshadow 的差异

| 维度 | Frida | LSPlant | wxshadow | **ptehooker** |
|---|---|---|---|---|
| 目标进程注入 .so | ✅ | ✅ Zygisk | ✅ | **❌** |
| ptrace 目标 | ✅ | ❌ | ✅ spawn | **❌** |
| 改代码段字节 | ✅ | ✅ | ✅ 隐 | **❌** |
| 改 ArtMethod 字节 | — | ✅ | — | **❌ (默认)** |
| `/proc/maps` 留痕 | ✅ | ✅ | ✅ | **❌ VMA-less** |
| JS 热更 | ✅ | ❌ | ✅ | ❌ |
| Java onEnter+onLeave | ✅ | ✅ | ✅ | ⚠️ 仅 Native |
| `/proc/pagemap` PFN 一致 | ❌ | ❌ | ❌ | **✅** |

不做 Frida 能做的所有事，**做 Frida 做不到的 stealth**。如需 JS 热更 / spawn 注入 / 完整 Java onLeave —— 用 Frida。

## 已知限制

- **ART 13 Nterp-only 方法无法 hook** — Nterp fast path 不读 entry_point。需要 `wait_jit=True` 等 ART 自然 JIT。
- **Kernel 6.1+ maple tree 下 `hide-vma` 未实现** — 核心 hook 路径（UXN/DBI/ghost）不受影响。
- **Java `onEnter+onLeave`** — 7.2 trap 模式下不支持（需要 LSPlant 式 ArtMethod clone，工程量大）。

详见 [`docs/ARCHITECTURE_AND_USAGE.md`](docs/ARCHITECTURE_AND_USAGE.md#十已知限制--诊断指南)。

## License

GPL-2.0（KernelPatch 框架本身 GPL-2.0，下游 KPM 必须兼容）。见 [`LICENSE`](LICENSE)。

## 致谢

- 看雪 [@kilozl](https://bbs.kanxue.com/thread-290718.htm) 师傅的"方案 C"方向性启发
- [@bmax121](https://github.com/bmax121) 的 APatch / KernelPatch 框架
- 所有在 ART / ARM64 / Linux kernel mm 领域留下公开资料的研究者
