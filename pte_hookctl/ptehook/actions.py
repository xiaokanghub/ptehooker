"""
Hook actions — 用户可以声明的 hook 行为。Framework 转成 shellcode 部署。

每个 Action 负责：
- build_shellcode(ctx) -> bytes    生成 ARM64 shellcode
- has_log_buffer() -> bool         是否需要 log buffer（for on_call 回调）
- parse_event(log_bytes) -> dict   将 log 字节翻译成用户看到的事件
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import shellcode as SC


class Action:
    """基类"""
    needs_log = False

    def build(self, log_buf_addr: int = 0) -> bytes:
        raise NotImplementedError

    def parse_event(self, data: bytes) -> dict:
        return {}


class ReturnConst(Action):
    """让方法直接返回一个小常量（<= 65535）。shellcode: BTI jc; MOV X0; RET."""
    def __init__(self, value: int):
        self.value = value

    def build(self, log_buf_addr=0) -> bytes:
        return SC.const_return(self.value)


class Noop(Action):
    """空实现：返回 0。"""
    def build(self, log_buf_addr=0) -> bytes:
        return SC.const_return(0)


class LogArgs(Action):
    """记录 X0-X7 + 调用计数。每次调用写 log buffer，host 侧异步读。
    返回值被强制为 0（不调用原函数）。"""
    needs_log = True
    MARKER = 0xC0DE1A57

    def __init__(self, on_call=None):
        """on_call(args: list[int]) — 用户回调，参数是 X0-X7 的整数值。
        Framework 在主线程轮询时调用。"""
        self.on_call = on_call
        self.last_counter = 0

    def build(self, log_buf_addr=0) -> bytes:
        if log_buf_addr == 0:
            raise ValueError("LogArgs requires log_buf_addr")
        return SC.log_trampoline_clean(log_buf_addr, self.MARKER)

    def parse_event(self, data: bytes) -> dict:
        """data: 80 bytes (X0-X7 + marker + counter)"""
        if len(data) < 80:
            return {}
        regs = [int.from_bytes(data[i*8:(i+1)*8], "little") for i in range(8)]
        marker = int.from_bytes(data[64:72], "little")
        counter = int.from_bytes(data[72:80], "little")
        new_calls = counter - self.last_counter
        self.last_counter = counter
        return dict(regs=regs, marker=marker, counter=counter,
                    new_calls=new_calls, valid=(marker == self.MARKER))


class CallBackupJava(Action):
    """Java hook 的 onEnter + onLeave 语义（**实验性**）。

    ⚠️ **已知限制**：
    能成功捕获 onEnter 一次，但调用原方法后 ART 触发
    `tlsPtr_.method_verifier == verifier` DCHECK 崩溃。原因：ART 依赖
    线程 TLS 里特定的 verifier 状态穿过方法 dispatch，我们 shellcode
    里的 BLR 到 art_quick_to_interpreter_bridge 破坏该不变量。

    完整支持 Java onEnter+onLeave 需要复刻 LSPlant 的 ArtMethod 克隆：
    新建一个 ArtMethod 副本在 ART heap / LinearAlloc 里（让 ART GC 和
    stack walker 都能识别），把方法指针替换为副本，BLR 副本的
    entry_point。这要求能调 ART::AllocArtMethod 或类似 API (≈LSPlant 所做)。

    当前可用：onEnter 能捕获首次调用的参数。on_return 不可靠。
    """
    needs_log = True
    MARKER = 0xC0DE1A57
    NEEDS_JAVA_BACKUP = True  # Session 要提供原 entry_point

    def __init__(self, on_call=None, on_return=None):
        self.on_call = on_call
        self.on_return = on_return
        self.last_pre = 0
        self.last_post = 0
        self._orig_entry_point = None
        self._ghost_self = None

    def set_backup_info(self, orig_entry_point: int, ghost_self: int):
        self._orig_entry_point = orig_entry_point
        self._ghost_self = ghost_self

    def build(self, log_buf_addr=0) -> bytes:
        if log_buf_addr == 0:
            raise ValueError("needs log_buf")
        if self._orig_entry_point is None:
            raise ValueError("needs orig_entry_point set via set_backup_info")
        return SC.log_and_call_java_v2(
            log_buf_addr, self.MARKER,
            self._orig_entry_point, self._ghost_self,
            acc_native_bit=0x100, entry_offset=0x18)

    def parse_event(self, data: bytes) -> dict:
        if len(data) < 104:
            return {}
        pre_regs = [int.from_bytes(data[i*8:(i+1)*8], "little") for i in range(8)]
        marker = int.from_bytes(data[64:72], "little")
        pre_counter = int.from_bytes(data[72:80], "little")
        post_x0 = int.from_bytes(data[80:88], "little")
        post_x1 = int.from_bytes(data[88:96], "little")
        post_counter = int.from_bytes(data[96:104], "little")
        new_pre = pre_counter - self.last_pre
        new_post = post_counter - self.last_post
        self.last_pre = pre_counter
        self.last_post = post_counter
        return dict(
            pre_regs=pre_regs, marker=marker,
            pre_counter=pre_counter, post_counter=post_counter,
            post_x0=post_x0, post_x1=post_x1,
            new_pre=new_pre, new_post=new_post,
            valid=(marker == self.MARKER),
        )


class CallBackup(Action):
    """记录 args → 调 backup（原函数）→ 记录返回值 → 返回。

    仅 native hook 可用（KPM uxn-hook 提供 backup 地址）。对 Java hook
    调用 backup 更复杂（需要重置 ACC_NATIVE 等），暂不支持。

    Log buffer 布局：
      +0..+63:  pre-call X0-X7
      +64:      marker 0xC0DE1A57
      +72:      pre_counter
      +80:      post-call X0 (主返回值)
      +88:      post-call X1
      +96:      post_counter
    """
    needs_log = True
    MARKER = 0xC0DE1A57
    BACKUP_REQUIRED = True  # Session 会把 uxn_hook 返回的 backup 传进来

    def __init__(self, on_call=None, on_return=None):
        """
        on_call(args): 调用前触发，参数是 X0-X7 的 pre-call 快照
        on_return(args, ret_x0, ret_x1): 调用后触发
        """
        self.on_call = on_call
        self.on_return = on_return
        self.last_pre = 0
        self.last_post = 0
        self._backup = None

    def set_backup(self, backup_addr: int):
        self._backup = backup_addr

    def build(self, log_buf_addr=0) -> bytes:
        if log_buf_addr == 0:
            raise ValueError("CallBackup requires log_buf_addr")
        if self._backup is None:
            raise ValueError("CallBackup requires backup addr (set via set_backup)")
        return SC.log_and_call(log_buf_addr, self.MARKER, self._backup)

    def parse_event(self, data: bytes) -> dict:
        """data: 104 bytes (pre X0-X7 + marker + pre_counter + post X0/X1 + post_counter)"""
        if len(data) < 104:
            return {}
        pre_regs = [int.from_bytes(data[i*8:(i+1)*8], "little") for i in range(8)]
        marker = int.from_bytes(data[64:72], "little")
        pre_counter = int.from_bytes(data[72:80], "little")
        post_x0 = int.from_bytes(data[80:88], "little")
        post_x1 = int.from_bytes(data[88:96], "little")
        post_counter = int.from_bytes(data[96:104], "little")
        new_pre = pre_counter - self.last_pre
        new_post = post_counter - self.last_post
        self.last_pre = pre_counter
        self.last_post = post_counter
        return dict(
            pre_regs=pre_regs, marker=marker,
            pre_counter=pre_counter, post_counter=post_counter,
            post_x0=post_x0, post_x1=post_x1,
            new_pre=new_pre, new_post=new_post,
            valid=(marker == self.MARKER),
        )
