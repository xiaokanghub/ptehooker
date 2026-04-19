# ptehook — 类 Frida 的高层 hook 框架

用户只写 Python 脚本声明 hook 目标 + 行为。Framework 负责 ArtMethod 扫描、
ghost 分配、UXN 陷阱、DBI 重编译、JIT 漂移监测、close 清理等。

## 环境

```bash
export ADB_SERIAL=<your-device-serial>   # 你的测试设备
# 设备上要有 /data/local/tmp/ptehook_ctl 和 /data/local/tmp/pte_scan
# KPM ptehook-planc-v2 要加载
```

## 最小示例

### Java hook — 让方法返回常量（7.2 trap 模式）

默认走 7.2「查名片、布设隐形陷阱」：**不改 ArtMethod 字节**，在 entry_point
指向的代码页拉 UXN 陷阱。反作弊扫 ArtMethod 看不到改动。

```python
import ptehook

sess = ptehook.attach("com.target.app")

sess.java_hook(
    "Lcom/target/Foo;", "bar", "(I)I",
    replace=42,
    wait_jit=True,   # ★ 推荐：等 JIT 编译后 entry_point 走私有页，陷阱才稳
)

sess.run()   # Ctrl+C 退出
sess.close()  # 最终清理
```

### Java hook — 拦截参数

```python
def on_login(regs):
    # regs = [X0..X7]
    # 静态: X0=ArtMethod*, X1=arg1, ...
    # 虚方法: X0=ArtMethod*, X1=this, X2=arg1, ...
    print(f"login: X1=0x{regs[1]:x}")

sess.java_hook(
    "Lcom/target/LoginMgr;", "login", "(Ljava/lang/String;)Z",
    on_call=on_login,
    wait_jit=True,
    jit_watch=True,   # ★ 后台线程监测 JIT 漂移，ep 变了自动重装
)

sess.run()
```

### Multi-candidate spray（aweme 类多 ClassLoader）

同一个类被多个 ClassLoader 加载时，scanner 能看到多个 ArtMethod。`java_hook`
默认只取最佳候选，漏掉其他。用 `java_hook_all` 全部装：

```python
installed = sess.java_hook_all(
    "Lcom/target/Foo;", "bar", "(I)I",
    replace=0,
    unsafe_bridge=True,   # 接受 bridge 页 DBI 风险
)
print(f"装了 {len(installed)} 个 hook")
```

### Native hook

```python
sess.native_hook("libssl.so", symbol="SSL_write",
                  on_call=lambda r: print(f"SSL_write fd={r[0]}"))

sess.native_hook("libapp.so", offset=0x12340, replace=1)
```

### Native onEnter/onLeave (CallBackup)

```python
def on_enter(regs):
    print(f"strcmp(0x{regs[0]:x}, 0x{regs[1]:x})")

def on_leave(pre, ret_x0, ret_x1):
    print(f"  → return {ret_x0}")

sess.native_hook(
    "libc.so", symbol="strcmp",
    action=ptehook.CallBackup(on_call=on_enter, on_return=on_leave),
)
```

### Java onEnter/onLeave

**7.2 trap 模式不支持**（ACC_NATIVE temp-unhook 技巧不兼容）。退路：
`legacy_entry_patch=True` 走旧路径（改 ArtMethod 字节，失去 stealth）。

## API 参考

### `attach(package=None, pid=None) -> Session`
附着到进程。指定包名或 PID 之一。

### `sess.java_hook(class, method, sig, **kwargs) -> InstalledHook`

核心参数：
- `replace`: int — 让方法返回常量（≤65535 最简）
- `on_call`: `callable(regs)` — 拦截时 host 侧回调
- `action`: 显式 `Action` 实例（覆盖 replace / on_call）
- `artmethod`: `"0x..."` 手动指定候选（scanner 消歧失败时）

**部署模式（按 stealth 需求选）**：
| kwarg | 行为 | stealth | 抓 Nterp 方法 |
|---|---|---|---|
| `wait_jit=True` | 等 JIT 编译后再装，entry_point 变私有代码，UXN 陷阱可靠触发 | ✅ 完美 | ✅ |
| (default) | 直接 UXN 陷阱 | ✅ 完美 | ❌ (ep 在 libart 默认拒绝) |
| `unsafe_bridge=True` | 强制在 bridge 页装 | ✅ 完美 | ❌ |
| `force_acc_native=True` | 打 ACC_NATIVE 强制走 entry_point | ⚠️ af+4 可见改动 | ⚠️ Nterp 优化路径仍绕过 |
| `legacy_entry_patch=True` | 旧路径：改 ArtMethod entry_point 指向 ghost | ❌ 字节污染 | ✅ 对 Nterp 也有效 |

**可靠性**：
- `jit_watch=True` + `jit_watch_interval=0.5` —— 后台线程轮询 entry_point，
  ART 升级 tier 时自动 uxn_unhook + 重装。避免 hook 悄悄失效。

### `sess.java_hook_all(class, method, sig, **kwargs) -> list[InstalledHook]`

在 scanner 所有合格候选上 spray，跳过 cluster 消歧。aweme 类多 ClassLoader
场景必用。每个候选独立 ghost。

### `sess.native_hook(lib_name, symbol=None, offset=None, **kwargs) -> InstalledHook`

### `sess.run(poll_hz=5)` / `sess.close()`

## 常见问题

### 装了但 hits=0（hook 没触发）
几种情况：
1. **entry_point 在 `ExecuteNterpImpl`** —— ART 13 Nterp 对 Java→Java 调用
   短路优化**不走 entry_point**。解法：`wait_jit=True` 等 JIT 编译
2. **ArtMethod 选错了**（多 ClassLoader 场景） —— 改用 `java_hook_all`
3. **接口 dispatch 调到真实 impl 不是 wrapper**（aweme MSManager → `ms.bd.c.f2`）
   —— `java_hook_all` 或 hook 底层 C 函数

### Scanner 报"无法自动消歧"
```
3 候选无法自动消歧 (expected cluster=2):
  0x7d0b9954b0  access=0x10280009  decl=0x...  ep=0x...
  0x7d1ce10438  access=0x10280009  decl=0x...  ep=0x...
```
- 看哪个 decl 和 ep 靠谱（ep 在 oat/boot.art 常是 AOT 编译的正主）
- 传 `artmethod='0x7d1ce10438'` 锁定
- 或直接 `java_hook_all` 全部装

### `-28 ghost_alloc` 失败
密集进程（aweme 类 7000+ VMA）容易触发。已修过但极端情况仍可能：
- 目标进程重启（清孤儿 PTE）
- KPM 卸载重载（走 `cleanup_all_state`）

### DBI Pass 3 崩溃
已知 `artInvokeInterfaceTrampoline` 类 ART 辅助函数在 DBI 重编译后会 SEGV。
默认 `unsafe_bridge=False` 挡住。解法：`wait_jit=True` 让陷阱迁到 JIT 页。

## 设计哲学

- **零字节修改**（7.2 trap）—— ArtMethod / 代码段一个 bit 都不动
- **零 .so 注入** —— 目标进程不加载任何我们的文件
- **零 ptrace / TracerPid** —— 所有跨进程操作通过 KPM 内核态完成
- **ghost 内存无 VMA backing** —— `/proc/pid/maps` 看不到我们的 shellcode 页

详细 vs Frida/LSPlant/wxshadow 对比见 `project_ptehook_scope.md`。
