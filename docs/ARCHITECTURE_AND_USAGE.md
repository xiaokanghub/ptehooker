# ptehook 技术架构与使用说明

> **版本**：2026-04-18 更新
> **设备基线**：Xiaomi M2102K1AC (Android 13 / Kernel 5.4 / APatch)
> **目标**：ARM64 Android，API 11-15（尾部版本靠自动 fallback），Kernel 4.9-6.x（hide-vma 限 <6.1）

---

## 一、项目定位

### 1.1 它是什么

`ptehook` 是一个**跨进程、内核态驱动、零字节修改**的 Android ARM64 hook 框架。核心价值是 **stealth**（隐身）：

- **不注入 `.so`** —— 目标进程 `/proc/pid/maps` 里没有任何我们的 VMA
- **不 ptrace** —— 没有 `TracerPid`
- **不改 ArtMethod 字节**（默认 7.2 trap 模式）—— 反作弊扫结构体扫不到
- **Ghost 内存无 VMA backing** —— 我们的 shellcode 页在 PTE 层存在但 VMA 层不可见

与 Frida、LSPlant、wxshadow 的关键区别：我们**不走字节 patch**这条路。hook 机制是**内核在 PTE 层拉异常陷阱**（ARM64 `UXN` bit），CPU 取指时 kernel fault handler 把 PC 重定向到 ghost shellcode。

### 1.2 它不是什么

- **不是 Frida 替代品**：QuickJS 脚本、eBPF trace、Stalker 指令级追踪一概没有
- **不是入门工具**：需要 Root + APatch + KernelPatch，不是 MagiskModule 即插即用
- **不是稳定生产框架**：DBI 引擎对复杂 ART 辅助函数仍有已知崩溃（`artInvokeInterfaceTrampoline` 类）
- **不做反检测全覆盖**：`/proc/self/pagemap` 级别的 kernel-forensic 对抗需要额外工作

### 1.3 威胁模型

适合的对抗面：

| 检测手段 | ptehook 表现 |
|---|---|
| 扫 `/proc/pid/maps` | ✅ 完全看不见 |
| 扫 TracerPid / ptrace_scope | ✅ 完全看不见 |
| `dl_iterate_phdr` 遍历 `.so` | ✅ 看不见 |
| CRC/MD5 of code pages | ✅ 字节未改 |
| 扫 ArtMethod.entry_point 是否在合法 oat 段 | ✅ 7.2 模式字段未改 |
| 扫 `ArtMethod.access_flags` ACC_NATIVE bit | ✅ 7.2 模式未改 |
| `/proc/self/pagemap` PFN 对比 | ✅ 只翻 UXN bit，PFN 不变 |
| Kernel-level PTE scan | ❌ UXN bit 可读 |
| 时序检测（`clock_gettime` + baseline） | ⚠️ 首次 fault 有 μs 级开销 |

如果目标反作弊会扫 PTE 或读 PMC，本框架**无法隐身**。其余场景基本免疫。

---

## 二、核心技术机制

### 2.1 "7.2 trap" —— UXN bit + PTE 陷阱

名字来自看雪论坛"方案 C"的 7.2 节：**查名片、布设隐形陷阱**。

核心流程：
```
1. 用户指定 target ArtMethod*（Java）或 symbol addr（Native）
2. 读 ArtMethod.entry_point_from_quick_compiled_code_（+0x18 on A13）——【只读】
3. 得到 entry_point 指向的原生代码页 VA
4. 在该 VA 所在 4KB 页的 PTE 上拉起 UXN bit（bit 54 = Unprivileged eXecute Never）
5. CPU 后续取指该页 → 触发 Instruction Abort → 内核 do_mem_abort 被 hook
6. KPM 的 fault handler 根据 FAR 分发：
     FAR == target_addr  → PC ← 我们的 shellcode (Pass 2)
     FAR 在同页其他 offset → PC ← DBI 重编译版本 (Pass 3)
```

优势：
- **ArtMethod 字节不动**
- **代码段字节不动**
- 只翻一个 PTE bit，通过 KernelPatch supercall 完成

### 2.2 Ghost 内存 —— VMA-less 物理页分配

我们要把 shellcode / DBI 重编译代码放在目标进程**可执行**的内存里，但又不能占用 VMA（否则 `/proc/maps` 暴露）。

实现：
```
KPM 侧：
  1. kernel 分配 N 个连续物理页 (__get_free_pages)
  2. 在目标进程 mm 找到一个 4KB 空洞 VA
  3. apply_to_page_range 直接在该 VA 安装 PTE，指向我们分配的 PFN
  4. 不调 mmap，不经过 VMA 系统
  5. PTE 配置：继承自邻近 libart r-xp 的模板，但清掉：
       - bit 7 (AP[2], RO)    → 变 RW（写 shellcode）
       - bit 50 (GP, Guarded Page) → 免 BTI 检查
       - bit 54 (UXN)         → 可执行
```

结果：
- `/proc/pid/maps` 扫 VMA：看不见
- `cat /proc/pid/mem > /tmp/dump`：读不到（无 VMA 无法遍历）
- CPU 从此 VA 取指：正常执行

### 2.3 DBI 重编译 —— 让整页代码能从另一 VA 执行

UXN 陷阱触发时，非目标地址要 fallthrough 执行原页代码。但原页已经 UXN=1 不能执行。方案：把整页代码重编译到 ghost 页，修复 PC-relative 指令（B/BL/ADR/ADRP/LDR literal）。

处理的指令类：
```
B / BL       → 若 ghost 到原 target 距离 ≤ ±128MB 保留，否则展成 MOV+BR/BLR
B.cond       → 范围内保留；超范围反转条件 + 跳转
CBZ/CBNZ     → 同上
TBZ/TBNZ     → 同上
ADRP / ADR   → 替换成 MOVZ+MOVK 绝对地址加载
LDR literal  → 替换成 MOV+LDR via 临时寄存器 X17
其它指令     → 直接 passthrough
```

维护一个 `offset_map[target_word_idx] = ghost_word_idx` 让 fault handler 能做 PC 映射。

### 2.4 KernelPatch supercall + KPM 模块

所有跨进程操作通过 KernelPatch 的 `supercall` 机制（syscall 45 + superkey 鉴权）下发给 KPM：

```
Python host (kpm_client.py)
  │
  │ adb shell su
  ↓
ptehook_ctl (设备侧 userspace binary)
  │
  │ syscall 45 with superkey + ctl command string
  ↓
KernelPatch kernel patch (EL1)
  │
  │ 分发到我们注册的 KPM
  ↓
ptehook-planc-v2.kpm (planc2_ctl0)
  │
  │ 解析命令 → 操作目标进程 mm / PTE
```

所有"跨进程"语义都在 EL1 完成，不经过目标进程的 user code。

---

## 三、整体架构

### 3.1 分层图

```
┌────────────────────────────────────────────────────────────────────┐
│  Host 侧 (Linux / macOS 开发机)                                     │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Python 用户脚本                                              │  │
│  │    import ptehook                                            │  │
│  │    sess.java_hook(...) / sess.native_hook(...)               │  │
│  └──────────────────────────────────────────────────────────────┘  │
│           │                                                        │
│  ┌────────┴──────┐  ┌──────────────┐  ┌────────────┐  ┌─────────┐  │
│  │ ptehook/       │  │ kpm_client.py │  │ shellcode   │  │ dex_    │  │
│  │  session.py    │  │  (ctl wrapper)│  │  generator  │  │ parser  │  │
│  │  actions.py    │  │               │  │ (ARM64 enc)│  │         │  │
│  └────────┬──────┘  └──────┬───────┘  └────────────┘  └─────────┘  │
│           │                │                                        │
└───────────┼────────────────┼────────────────────────────────────────┘
            │ adb shell su   │
            ↓                ↓
┌────────────────────────────────────────────────────────────────────┐
│  Android 设备侧 userspace                                           │
│                                                                    │
│  /data/local/tmp/ptehook_ctl       /data/local/tmp/pte_scan         │
│   ↑ supercall 45 + superkey          ↑ process_vm_readv +           │
│                                        ArtMethod pattern scan       │
└────────────┼────────────────────────────────────────────────────────┘
             │
             ↓ supercall
┌────────────────────────────────────────────────────────────────────┐
│  Kernel (EL1)                                                       │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  KernelPatch patch                                           │  │
│  │   ↓ KPM ctl dispatch                                         │  │
│  │  ┌────────────────────────────────────────────────────────┐  │  │
│  │  │  ptehook-planc-v2.kpm                                  │  │  │
│  │  │                                                        │  │  │
│  │  │   planc2_ctl0 (命令解析)                                │  │  │
│  │  │      │                                                │  │  │
│  │  │      ├─ cmd_uxn_hook ──→ alloc DBI ghost, set UXN PTE  │  │  │
│  │  │      ├─ cmd_ghost_alloc → alloc shellcode ghost       │  │  │
│  │  │      ├─ cmd_proc_patch → 跨进程写字节                   │  │  │
│  │  │      ├─ cmd_hide_vma   → unlink VMA (kernel <6.1)      │  │  │
│  │  │      └─ ...                                            │  │  │
│  │  │                                                        │  │  │
│  │  │   before_do_mem_abort (fault handler)                  │  │  │
│  │  │      Pass 2: exact FAR 匹配 → PC ← replace_addr        │  │  │
│  │  │      Pass 3: 同页其他 offset → PC ← DBI ghost          │  │  │
│  │  │                                                        │  │  │
│  │  │   planc2_exit → cleanup_all_state (清 PTE + 物理页)    │  │  │
│  │  └────────────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  Target process mm (目标进程虚拟地址空间)                             │
│     libart.so VMA │ ghost (无 VMA，PTE 级存在) │ other VMAs          │
└────────────────────────────────────────────────────────────────────┘
```

### 3.2 代码布局

```
ptehook/
├── test_kmod/                          # KPM (内核模块)
│   ├── ptehook_planc_v2.c              # 主文件，含 ctl 命令 / fault handler
│   ├── ghost_mm.{c,h}                  # VMA-less ghost 分配
│   ├── dbi_kern.{c,h}                  # ARM64 DBI 重编译引擎
│   └── Makefile.planc                  # 构建 → ptehook_planc_v2.kpm
│
├── pte_hookctl/                        # Python host + 设备侧工具
│   ├── ptehook/                        # 高层 API
│   │   ├── __init__.py                 # 公共导出 (attach, Session, Action)
│   │   ├── session.py                  # Session 类 + 全部 hook 方法
│   │   └── actions.py                  # ReturnConst, LogArgs, CallBackup, ...
│   ├── kpm_client.py                   # ptehook_ctl 封装 + ctl 命令 API
│   ├── shellcode.py                    # ARM64 shellcode 生成器
│   ├── dex_parser.py                   # DEX 文件解析（+ APK cache）
│   ├── art_offsets.py                  # ART / ArtMethod 偏移表（per-API 版本）
│   ├── sym_resolver.py                 # .so 符号解析
│   ├── artmethod_scan.py               # host 侧 ArtMethod pattern 检测辅助
│   ├── art_introspect.py               # Runtime→ClassLinker→DexCache 遍历
│   ├── device_scanner.c                # 设备侧 ArtMethod 扫描器（编译成 pte_scan）
│   ├── examples/                       # 用例脚本
│   │   ├── README.md                   # 用户向 API 文档
│   │   ├── hook_testapk.py             # demo 测试
│   │   └── hook_aweme_frameSign.py     # aweme 实战
│   └── tests/
│       └── test_shellcode.py           # 25 个 unit tests
│
├── docs/
│   └── ARCHITECTURE_AND_USAGE.md       # 本文件
│
├── KernelPatch/                        # KernelPatch 框架（子模块）
└── scripts/                            # 构建 / 部署 helpers
```

### 3.3 组件职责一览

| 组件 | 语言 | 位置 | 职责 |
|---|---|---|---|
| `ptehook-planc-v2.kpm` | C | kernel EL1 | PTE 操作、跨进程读写、fault handler、ghost 分配、DBI |
| `ptehook_ctl` | C | 设备 /data/local/tmp/ | supercall 45 进入 KPM，把 ctl 命令字符串下传 |
| `pte_scan` | C | 设备 /data/local/tmp/ | process_vm_readv 扫 LinearAlloc 找 ArtMethod |
| `kpm_client.py` | Python | host | 封装 ctl_raw → 各命令 |
| `session.py` | Python | host | 高层 Session API，处理 scanner 消歧、JIT watcher、close 生命周期 |
| `actions.py` | Python | host | ReturnConst / LogArgs / CallBackup 等 action 类 |
| `shellcode.py` | Python | host | ARM64 指令编码、生成 hook shellcode |
| `dex_parser.py` | Python | host | APK 里找 (class, method, sig) → method_idx + 相邻方法 |
| `art_offsets.py` | Python | host | 按 Android API 版本返回 ArtMethod 偏移 |
| `device_scanner.c` | C | 设备侧 | 在 LinearAlloc 里按 pattern 找 ArtMethod 候选 |

---

## 四、完整安装 Hook 的流程

以 `sess.java_hook("Lcom/foo/Bar;", "baz", "(I)I", replace=42, wait_jit=True)` 为例：

```
Step 1  attach(package)
         host: 读 pidof via adb，构造 Session
         host: 拉 APK 到 /tmp/ptehook_lib_cache/<pkg>.apk

Step 2  DEX parser
         host: 在 APK 各 classes*.dex 找 "Lcom/foo/Bar;.baz(I)I"
              → method_idx = N
              → adjacent_idxs = Bar 类的其他方法 idx
              → access_flags = DEX 原始值
         （首次 ~6s，后续 hot cache ~20ms）

Step 3  ArtMethod scanner
         host → 设备：
           adb shell su -c "/data/local/tmp/pte_scan <pid> <N> <adj_csv>"
         pte_scan（设备 C 程序）：
           process_vm_readv 扫 [anon:dalvik-LinearAlloc] VMAs
           过滤：dex_method_idx==N, decl!=0, access!=0xFFFFFFFF
           带 adjacent 时还检查 ±ARTMETHOD_SIZE 邻居 idx 和同 decl
         host: 拿到候选列表

Step 4  消歧
         host:
           1) access_flags 低 16 bit 和 DEX 匹配
           2) cluster size 精确等于 len(adj)+1
           3) 仍多候选 → 抛异常要求 artmethod="0x..."

Step 5  entry_point 检查
         host: 读 ArtMethod.entry_point @ +_ep_offset()
         若 ep 指向 libart.so 且未开 wait_jit/unsafe_bridge → 拒绝

Step 6  wait_jit (若启用)
         host: 轮询 ArtMethod+0x18
         等用户触发调用 → ART JIT 编译 → entry_point 搬到 JIT 私有页

Step 7  Alloc ghost（用户 shellcode）
         host → 设备 → KPM:
           ghost-alloc-at <pid> <big_bounded_gap_addr> 0x1000
         KPM:
           - find_hole_near 在目标 mm 找 1 页空洞
           - __get_free_pages 分配物理页
           - 探测邻居 VMA 的 PTE 作模板
           - apply_to_page_range 装 PTE (清 UXN/GP/AP[2])

Step 8  UXN hook
         host → KPM:
           uxn-hook <pid> <entry_point> <ghost_addr>
         KPM:
           - 再 alloc 一个 DBI ghost（给 Pass 3 用）
           - DBI 引擎重编译整页代码到 DBI ghost
           - 计算 offset_map
           - 在 target PTE 设 UXN=1 + TLB invalidate
           - 记录 slot (uxn_hooks[N])
           - 如果是首次 hook：hook_wrap3 挂 do_mem_abort handler

Step 9  写 shellcode 到用户 ghost
         host: shellcode.java_uxn_filter(art_method, action_code, backup_addr)
               → ARM64 字节
         host → KPM:
           ghost-write <pid> <ghost_addr> 0 <hex>

Step 10 (可选) jit_watch 线程启动
         host: Session._watcher_thread → 每 0.5s 读 entry_point
               变化 → 自动 uxn_unhook + uxn_hook 新 ep

Step 11 session.run() 事件循环
         host: 每 200ms 读 ghost 里 log buffer (若 Action.needs_log)
               把 X0-X7 + marker + counter 解码成事件
               调用户 on_call(regs)

Step 12 sess.close()
         host: stop watcher → uxn_unhook all → ghost_free all
         若进程已死 KPM reap，不报错
```

### 4.1 调用目标方法时的 fault 分发

```
Caller (目标进程某处)
  │
  │ BLR entry_point  （CPU 取指该页）
  ↓
UXN bit = 1 → Instruction Abort exception
  │
  ↓
Kernel do_mem_abort
  │
  ↓ (KPM hook_wrap3)
before_do_mem_abort:
  │
  ├─ 检查 ESR：EC=0x20 (IL low EL), IFSC=0x0C-0x0F (perm fault)
  ├─ 若不是 → 放行给 kernel 正常处理
  │
  ├─ Pass 2: 遍历 uxn_hooks[]
  │     对 (cur_pid, s->pid) 匹配 + (FAR == s->target_addr)
  │     → *pc_ptr = s->replace_addr  (我们的 shellcode)
  │     → skip_origin = 1, return
  │
  ├─ Pass 3: 遍历 uxn_hooks[] 找同页的 slot
  │     → new_pc = DBI_offset_map[FAR - target_page]
  │     → *pc_ptr = new_pc  (DBI ghost 里对应位置)
  │     → return
  │
  └─ 都没匹配 → 放行，正常 kernel SIGSEGV 处理
```

Pass 2 命中 = 我们的 hook 触发。Pass 3 命中 = 其他方法调用了同页的非 target 地址，DBI 保证它们仍能跑。

---

## 五、构建与部署

### 5.1 准备

**必需**：
- Android 设备已 root 并安装 APatch（KernelPatch 提供商）
- APatch v0.12.2+（已含 ptehook-planc-v2 kpm 依赖接口）
- 设备 ARM64 CPU
- Host Linux / macOS（开发环境）

**Android NDK**：r21+（clang）。本 session 验证用的是 `android-ndk-r21e` 里的 `aarch64-linux-android29-clang`。

**Python**：3.8+

### 5.2 构建 KPM

```bash
cd test_kmod
make -f Makefile.planc
# 产出：ptehook_planc_v2.kpm
```

### 5.3 构建设备侧 binary

```bash
NDK=/path/to/android-ndk-r21/toolchains/llvm/prebuilt/linux-x86_64/bin
$NDK/aarch64-linux-android29-clang -O2 -static \
    -o /tmp/pte_scan \
    <repo>/pte_hookctl/device_scanner.c

$NDK/aarch64-linux-android29-clang -O2 -static \
    -o /tmp/ptehook_ctl \
    <repo>/pte_hookctl/ptehook_ctl.c  # 若存在
# 或用仓库里预编译的 /data/local/tmp/ptehook_ctl
```

### 5.4 推送到设备

```bash
export ADB_SERIAL=<your_device_serial>

adb -s $ADB_SERIAL push ptehook_planc_v2.kpm /data/local/tmp/
adb -s $ADB_SERIAL push /tmp/pte_scan /data/local/tmp/
adb -s $ADB_SERIAL shell "su -c 'chmod 755 /data/local/tmp/pte_scan'"

# 首次：创建 superkey 文件（APatch 会提示）
adb -s $ADB_SERIAL shell "su -c 'mkdir -p /data/adb/ptehook && \
    echo YOUR_APATCH_SUPERKEY > /data/adb/ptehook/superkey && \
    chmod 600 /data/adb/ptehook/superkey'"
```

### 5.5 加载 KPM

```bash
SK=$(adb -s $ADB_SERIAL shell "su -c 'cat /data/adb/ptehook/superkey'")
adb -s $ADB_SERIAL shell "su -c '/data/adb/kpatch $SK kpm load /data/local/tmp/ptehook_planc_v2.kpm'"
adb -s $ADB_SERIAL shell "su -c '/data/adb/kpatch $SK kpm list'"
# 应看到 ptehook-planc-v2
```

重新加载（改代码后）：
```bash
adb -s $ADB_SERIAL shell "su -c '/data/adb/kpatch $SK kpm unload ptehook-planc-v2 && \
    /data/adb/kpatch $SK kpm load /data/local/tmp/ptehook_planc_v2.kpm'"
```

---

## 六、使用指南

### 6.1 最简单的例子：让 Java 方法返回常量

```python
# hook_return_const.py
import ptehook

sess = ptehook.attach("com.target.app")

sess.java_hook(
    "Lcom/target/License;", "isVIP", "()Z",
    replace=1,           # 让 isVIP() 始终返回 true
    wait_jit=True,       # 推荐：等 JIT 编译后再装陷阱
)

# 保持运行直到 Ctrl+C
sess.run()
sess.close()
```

**解读**：
- `attach` 按包名拿 PID，可选 `pid=int` 直接给 PID
- `wait_jit=True` 是 **stealth 最优** 的安装方式 —— 等 ART 把该方法从 Nterp 升级到 JIT 后装陷阱，此时 ArtMethod 字节完全不动
- `sess.run()` 进事件循环，按 5Hz 轮询 ghost log buffer（如果 action 不需要 log 可省略）

### 6.2 拦截参数 + on_call 回调

```python
import ptehook

sess = ptehook.attach("com.target.app")

def on_login(regs):
    # regs = [X0..X7]，实例方法的布局：
    #   X0 = ArtMethod*
    #   X1 = this 对象
    #   X2 = 第一个参数（String 引用，压缩的）
    #   X3 = 第二个参数
    user = regs[2] & 0xFFFFFFFF   # String compressed ref
    print(f"login(user={user:x})")

sess.java_hook(
    "Lcom/target/Auth;", "login", "(Ljava/lang/String;Ljava/lang/String;)Z",
    on_call=on_login,
    wait_jit=True,
    jit_watch=True,     # 监测 JIT 漂移，entry_point 变化自动重装
)

sess.run(poll_hz=10)    # 10Hz 轮询，高频函数建议调高
sess.close()
```

### 6.3 Native hook + onEnter/onLeave

```python
import ptehook

sess = ptehook.attach("com.target.app")

def on_enter(regs):
    print(f"strcmp({regs[0]:x}, {regs[1]:x})")

def on_leave(pre_regs, ret_x0, ret_x1):
    print(f"  → {ret_x0}")

sess.native_hook(
    "libc.so", symbol="strcmp",
    action=ptehook.CallBackup(on_call=on_enter, on_return=on_leave),
)
sess.run()
sess.close()
```

### 6.4 Multi-candidate Hook（多 ClassLoader 场景）

抖音类 app 把关键类在多个 ClassLoader 加载，每个 ClassLoader 有自己的 ArtMethod 副本。装一个 hook 抓不全：

```python
installed = sess.java_hook_all(
    "Lcom/bytedance/mobsec/metasec/ml/MSManager;",
    "frameSign",
    "(Ljava/lang/String;I)Ljava/util/Map;",
    replace=0,
    unsafe_bridge=True,
    jit_watch=True,
)
print(f"装了 {len(installed)} 个 hook")
```

每个候选独立 ghost、独立 uxn slot。日志里能看到：
```
[+] java_hook_all: 2 candidates
  [0] 0x77662b9f50 OK
  [1] 0x77c8d4be30 OK
```

### 6.5 完整参数表（java_hook）

```python
sess.java_hook(
    class_desc,                 # "Lcom/foo/Bar;"
    method,                     # "baz"
    sig,                        # "(I)I"
    *,
    # --- 部署模式（四选一） ---
    wait_jit=False,             # 推荐：等 JIT 编译后再装（stealth 最优，Nterp 抓不到）
    unsafe_bridge=False,        # 强制在 bridge 页装（Nterp 抓不到 + DBI 崩溃风险）
    force_acc_native=False,     # 打 ACC_NATIVE 强制 entry_point 分发（字节污染）
    legacy_entry_patch=False,   # 退路：ACC_NATIVE + 改 ep（污染 ArtMethod，能抓 Nterp）

    # --- Action 选一 ---
    replace=None,               # int → 返回常量
    on_call=None,               # func → 拦截时回调
    action=None,                # 显式 Action 实例

    # --- 可靠性 ---
    jit_watch=False,            # 后台监测 JIT 漂移，自动 rehook
    jit_watch_interval=0.5,     # 轮询间隔秒

    # --- 高级 ---
    artmethod=None,             # "0x..." 手动指定 ArtMethod，跳过 scanner
    warmup_timeout=30.0,        # wait_jit 超时
)
```

#### 各模式对比

| 模式 | ArtMethod 改动 | 能抓 Nterp 方法 | DBI 崩溃风险 | 推荐场景 |
|---|---|---|---|---|
| `wait_jit=True` | 无 | ✅ JIT 后能 | 低 | **默认首选** |
| （default） | 无 | ❌ bridge 拒绝装 | 低 | ep 已在 AOT/JIT 的框架方法 |
| `unsafe_bridge=True` | 无 | ❌ | **高** | 调试；研究 DBI 行为 |
| `force_acc_native=True` | +4 bit 改动 | ❌ Nterp 仍 fast path | 低 | 基本没用 |
| `legacy_entry_patch=True` | +4 and +0x18 改动 | ✅ | 低 | 非 stealth 场景 |

### 6.6 诊断命令

```python
# 看所有 UXN slot 状态
import kpm_client as K
for r in K.uxn_list():
    print(f"slot={r['slot']} pid={r['pid']} target=0x{r['target']:x} "
          f"hits={r['hits']} pass3={r.get('pass3', 0)}")
# hits 包含 Pass 2 exact match + Pass 3 fallthrough
# pass3 单独是 Pass 3 fallthrough（同页非目标）
# 如果 hits=0 → 该方法没被调用；或走 Nterp 绕过了 entry_point

# 看全局 KPM 状态
print(K.ctl_raw("stat"))
# 输出：kern.linked_list_vma / kern.vma_off / hook_installed 等

# 读 ghost 字节（debug DBI 或 shellcode）
ghost_bytes = K.ghost_read(pid, ghost_vaddr, 1024)
# 自动 chunk，支持任意长度
```

### 6.7 清理与重置

**session.close()** 正常走：
```python
try:
    sess.run()
finally:
    sess.close()   # 自动 uxn_unhook + ghost_free + 恢复 ACC_NATIVE
```

**KPM unload 也清干净**（session 2026-04-18 修）：
```bash
adb shell "su -c '/data/adb/kpatch $SK kpm unload ptehook-planc-v2'"
# 自动遍历所有 slot，清 PTE、释放物理页
```

**极端情况（KPM 崩 / app 挂）**：
```bash
adb shell "am force-stop com.target.app"   # 重启目标进程
# process 死后 KPM reap_dead_uxn_slots 会清理 slot
```

---

## 七、API 参考

### 7.1 `ptehook.attach(package=None, pid=None) -> Session`

构造 `Session`。指定包名或 PID 之一。

### 7.2 `Session.java_hook(...)`

见 6.5 节参数表。返回 `InstalledHook`。

### 7.3 `Session.java_hook_all(...) -> list[InstalledHook]`

多候选 spray 版本。跳过 cluster 消歧，在所有 access_flags 匹配的候选上装 hook。

### 7.4 `Session.native_hook(lib_name, symbol=None, offset=None, **kw)`

按 .so 名 + 符号 / 偏移定位。其余同 java_hook。

### 7.5 `Session.run(poll_hz=5)` / `Session.close()`

事件循环 / 清理。

### 7.6 Action 类（`ptehook.*`）

| 类 | 用途 | Native | Java |
|---|---|---|---|
| `ReturnConst(n)` | 让方法直接返回常量 | ✅ | ✅ |
| `Noop()` | 返回 0 | ✅ | ✅ |
| `LogArgs(on_call)` | 记录 X0-X7 + 回调 | ✅ | ✅ |
| `CallBackup(on_call, on_return)` | onEnter+onLeave | ✅ | ❌(trap 不兼容) |
| `CallBackupJava(...)` | 已废弃（7.2 trap 抛 NotImplementedError） | - | - |

### 7.7 `kpm_client` 底层 API

```python
import kpm_client as K

K.ctl_raw(args)                     # 任意 KPM ctl 命令
K.proc_read(pid, addr, length)      # 跨进程读字节
K.proc_read_u32(pid, addr)
K.proc_read_u64(pid, addr)
K.proc_patch(pid, addr, bytes)      # 跨进程写
K.ghost_alloc(pid, near, size, exact=False)
K.ghost_free(pid, vaddr)
K.ghost_write(pid, vaddr, offset, bytes)
K.ghost_read(pid, vaddr, length)    # 自动 chunk
K.uxn_hook(pid, target, ghost, force=True)  # 重试 "already hooked"
K.uxn_unhook(pid, target)
K.uxn_list() -> list[dict]          # 所有 UXN slot
K.uxn_reap_pid(pid)                 # 清某 pid 全部 slot
K.untag(ptr)                        # 去 ARM64 TBI tag
K.read_maps(pid) -> list            # /proc/pid/maps
K.find_lib(pid, name)
K.lib_rx_base(pid, name)
K.find_large_gap(pid, min_size=...)
```

---

## 八、已知限制 + 诊断指南

### 8.1 装了 hook 但 `hits = 0`

**症状**：`uxn_list()` 里某 slot `hits=0`，说明 UXN 陷阱没触发过。

**可能原因**：

1. **目标方法没被调用过** —— 等用户操作或 adb 触发
2. **Nterp 走优化路径不经 entry_point**（ART 13 最常见）：
   - 症状：`ep = 0x...400090`（`ExecuteNterpImpl`）
   - 解法：`wait_jit=True`（等 JIT 升级）
   - 或接受用 `legacy_entry_patch=True` 破坏 stealth
3. **Scanner 选错 ArtMethod**（多 ClassLoader）：
   - 用 `java_hook_all` 全装
   - 或显式 `artmethod="0x..."` 

### 8.2 `ghost_alloc: -28` (ENOSPC)

**症状**：装 hook 时 KPM 报 `-28`。

**原因**：目标进程内存稠密，没有足够大的 VMA-bounded gap。

**排查**：
```python
maps = K.read_maps(pid)
# 看所有 VMA bounded gap
for i in range(len(maps)-1):
    s, e = maps[i][1], maps[i+1][0]
    if e > s and e-s > 0x10000:
        print(f"gap 0x{s:x}-0x{e:x} size={e-s:#x}")
```

**解法**：
- 重启目标 app（清孤儿 PTE 累积）
- KPM 卸载重载（清 slot 状态）
- 当前框架已自动选 "bounded gap"（Task #80 修复），极罕见情况才会触发

### 8.3 `artInvokeInterfaceTrampoline` 类 DBI 崩溃

**症状**：app 崩溃，tombstone 显示 SEGV_MAPERR，LR 在 ghost 区。

**原因**：DBI 引擎对某些 libart 辅助函数页重编译有已知 bug（Task #69 未根治）。

**解法**：
- 用 `wait_jit=True` 让 hook 落到 JIT 私有页，避开 libart bridge 的复杂代码
- 默认 `unsafe_bridge=False` 已帮你挡住 90% 场景

### 8.4 Scanner 早期 cluster 误匹配

**症状**：同一 PID 多次运行 `java_hook` 拿到不同 ArtMethod。

**原因**：app 刚启动 LinearAlloc 尚未填满，某候选的 decl cluster 还没长齐。

**解法**（Task #73 已修）：`_resolve_artmethod` 内置 3 次 × 0.5s 重试。若仍然不稳定，让 app 充分运行后再 hook。

### 8.5 KPM 状态错乱

偶发症状：`uxn-list` 里残留陌生 PID 的 slot 等。

**快速重置**：
```bash
SK=$(adb shell "su -c 'cat /data/adb/ptehook/superkey'")
adb shell "su -c '/data/adb/kpatch $SK kpm unload ptehook-planc-v2 && \
    /data/adb/kpatch $SK kpm load /data/local/tmp/ptehook_planc_v2.kpm'"
# 卸载时自动 cleanup_all_state (Task #69 已修)
```

---

## 九、与 Frida / LSPlant / wxshadow 的对比

| 维度 | Frida | LSPlant | wxshadow+rustFrida | **ptehook** |
|---|---|---|---|---|
| 注入 .so 到目标进程 | ✅ libfrida-agent.so | ✅ Zygisk | ✅ libagent.so | **❌ 不注入** |
| ptrace 目标 | ✅ | ❌ | ✅ spawn | **❌** |
| 改代码段字节 | ✅ inline patch | ✅ inline patch | ✅ (隐在 shadow 页) | **❌** |
| 改 ArtMethod 字节 | N/A | ✅ entry_point | N/A | **❌ (默认 7.2)** |
| `/proc/maps` 可见 shellcode | ✅ | ✅ ghost 有 VMA | ✅ | **❌ VMA-less** |
| JS 脚本热更 | ✅ | ❌ | ✅ QuickJS | ❌ Python 改完重跑 |
| onEnter + onLeave (Java) | ✅ | ✅ | ✅ | ⚠️ Native 支持，Java 仅 onEnter |
| 改 Java 入参 | ✅ | ✅ | ✅ | ❌ |
| Throw / CreateObject | ✅ | ✅ | ✅ | ❌ |
| Nterp-tier 方法 hook | ✅ | ✅ | ✅ | ⚠️ 需 wait_jit 或 legacy |
| Spawn-time 注入 | ✅ | ✅ | ✅ | ❌ 只能 attach |
| PTE pagemap 隐身 | ❌ | ❌ | ❌ (shadow PFN 不一致) | **✅ 只改 UXN bit** |
| 安装复杂度 | 中 | 中 | 高（多层 shellcode） | 中（KPM + APatch） |
| **对抗强反作弊**（TikTok/游戏） | 常被检测 | 部分检测 | 部分检测 | **目前最强 stealth** |

**总结**：**ptehook 是一个 stealth-first 的框架**，放弃了 Frida 的一些花活（JS、spawn、onLeave 方便实现），换回了 Frida/LSPlant/wxshadow 都做不到的"零字节修改 + 零 .so 注入 + 零 VMA 痕迹"。

---

## 十、开发路线图

### 已完成（2026-04-18 session）

- S1-S13：基础 KPM + 各 ctl 命令 + 7.2 trap + ghost mm
- Tasks #65-82 本 session 16 个修复/优化：稳定性、可用性、兼容层

### 计划中（优先级高→低）

1. **Shadow page 路径**（解决 Nterp）—— 作为 UXN trap 的第二路径，但要配套做 `pagemap` / `smaps` hook 避免新检测面
2. **Host-side JS 脚本引擎**（hot reload）
3. **Spawn-time 注入**（zygote fork 内核 hook）
4. **Android 14/15 layout 验证**（有对应设备时）
5. **Maple-tree kernel 下的 hide-vma** 实现
6. **DBI 引擎根因调查**（Task #69）—— 需稳定复现用例
7. **Java `CallBackup`（onLeave）** —— 要复刻 LSPlant ArtMethod clone，~9 天工作
8. **Field hook / Throw / NewObject**（JNI ops）—— 每个操作一个 shellcode 模板

### 不做

- QBDI 级指令 trace（时间特征暴露）
- QuickJS 注入到目标进程（扩大检测面）
- Frida 级生态全覆盖（偏离 stealth-first 设计）

---

## 十一、关键源码索引

| 想了解 | 读这个 |
|---|---|
| UXN 陷阱怎么工作 | `test_kmod/ptehook_planc_v2.c::before_do_mem_abort` |
| Ghost 如何分配 | `test_kmod/ghost_mm.c::ghost_alloc` / `find_hole_near` |
| DBI 重编译每类指令 | `test_kmod/dbi_kern.c::recomp_*` |
| shellcode 生成 | `pte_hookctl/shellcode.py::java_uxn_filter` |
| Java hook 安装流程 | `pte_hookctl/ptehook/session.py::_install_java` |
| ArtMethod 扫描消歧 | `pte_hookctl/ptehook/session.py::_resolve_artmethod` |
| JIT 漂移监测 | `pte_hookctl/ptehook/session.py::_jit_watch_loop` |
| KPM 状态清理 | `test_kmod/ptehook_planc_v2.c::cleanup_all_state` |
| 跨 Android 版本 ArtMethod 偏移 | `pte_hookctl/art_offsets.py::_OFFSETS_BY_API` |
| 跨 kernel 版本 VMA 布局 | `test_kmod/ptehook_planc_v2.c::probe_kern_layout` |

---

## 十二、附录：KPM 全部 ctl 命令

```
install <pid> <addr>                  # legacy 单 hook 安装（已不推荐）
remove                                # 卸载 legacy hook
stat                                  # 全局状态 + kernel layout

ghost-alloc <pid> <near> <size>       # 分配 ghost 页（near libart）
ghost-alloc-at <pid> <exact> <size>   # 指定 VA 分配
ghost-free <pid> <vaddr>
ghost-write <pid> <vaddr> <off> <hex>
ghost-read <pid> <vaddr> <len>        # 单次 ≤1536 字节

java-hook <pid> <art_method> <entry_off> <new_ep>   # legacy 改 ep
java-unhook <pid> <art_method> <entry_off>

proc-patch <pid> <addr> <hex>         # 跨进程写
proc-read <pid> <addr> <len>

uxn-hook <pid> <target> <replace>     # 7.2 trap 安装
uxn-unhook <pid> <target>
uxn-list                              # 所有 UXN slot（+pass3_hits）
uxn-add-redirect <pid> <target> <replace>
uxn-del-redirect <pid> <target>

hide-vma <pid> <vaddr>                # kernel <6.1 only
hide-range <pid> <start> <end>
watch <pid> <so_name> <offset>        # .so 加载触发后自动 hook

```

---

**最后更新**：2026-04-18。Session 完整变更列表参见 `~/.claude/projects/-home-xkang-ptehook/memory/project_ptehook_scope.md`。
