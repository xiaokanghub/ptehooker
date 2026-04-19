"""
kpm_client.py - 封装 /data/local/tmp/ptehook_ctl 命令，通过 adb shell su 下发到 KPM。
所有通信走 superkey + supercall 45。

性能：通过常驻 `adb shell su` 进程复用，免除每次起 adb 子进程的 ~150ms 开销。
环境变量 `PTEHOOK_NO_PERSIST=1` 可关闭常驻模式（debug）。
"""
import subprocess
import re
import os
import threading
import atexit
import uuid
from typing import Optional, Tuple


ADB_SERIAL = os.environ.get("ADB_SERIAL", "")
PTEHOOK_CTL = "/data/local/tmp/ptehook_ctl"
SUPERKEY_PATH = "/data/adb/ptehook/superkey"
# 默认关闭 —— `adb shell` 无 TTY 时 stdout 会块缓冲，ctl 命令的 sentinel
# 可能吞在缓冲里导致超时。开启 `PTEHOOK_PERSIST=1` 走常驻模式；仍是
# 实验特性。完整解法需要 PTY，暂未实现。
_USE_PERSIST = os.environ.get("PTEHOOK_PERSIST") == "1"


class _PersistentShell:
    """常驻 `adb -s $SERIAL shell` 进程，su + SK 缓存，命令末尾加 markers
    定位 stdout 片段。线程安全（互斥锁 + per-call 唯一 token）。"""

    def __init__(self, serial: str):
        self.serial = serial
        self.proc: Optional[subprocess.Popen] = None
        self.lock = threading.Lock()
        self._start()

    def _start(self):
        self.proc = subprocess.Popen(
            ["adb", "-s", self.serial, "shell"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
        # Elevate + cache SK. Use a sentinel to confirm ready.
        token = uuid.uuid4().hex[:8]
        init_cmd = (
            f"su\n"
            f"SK=$(cat {SUPERKEY_PATH})\n"
            f"echo __READY_{token}__\n"
        )
        assert self.proc.stdin is not None
        self.proc.stdin.write(init_cmd)
        self.proc.stdin.flush()
        self._read_until(f"__READY_{token}__")

    def _read_until(self, marker: str, timeout: float = 30.0) -> str:
        assert self.proc is not None and self.proc.stdout is not None
        import select
        lines = []
        deadline = None if timeout is None else (
            __import__("time").monotonic() + timeout)
        while True:
            if deadline is not None:
                remain = deadline - __import__("time").monotonic()
                if remain <= 0:
                    raise RuntimeError(f"shell timeout waiting for {marker}")
                r, _, _ = select.select([self.proc.stdout], [], [], remain)
                if not r:
                    continue
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError(
                    "persistent adb shell died; set PTEHOOK_NO_PERSIST=1 "
                    "to fall back to per-call mode")
            if marker in line:
                # Return everything BEFORE the marker line
                return "".join(lines)
            lines.append(line)

    def run(self, cmd: str, timeout: float = 30.0) -> str:
        """Send command, return stdout up to the sentinel. Thread-safe."""
        token = uuid.uuid4().hex[:12]
        marker = f"__END_{token}__"
        # Wrap so we see EXIT and any unsolicited output before it
        with self.lock:
            assert self.proc is not None and self.proc.stdin is not None
            self.proc.stdin.write(f"{cmd}\necho {marker}\n")
            self.proc.stdin.flush()
            return self._read_until(marker, timeout=timeout)

    def close(self):
        if self.proc is not None:
            try:
                assert self.proc.stdin is not None
                self.proc.stdin.write("exit\nexit\n")  # su, then shell
                self.proc.stdin.flush()
            except Exception:
                pass
            try:
                self.proc.wait(timeout=2.0)
            except Exception:
                self.proc.kill()
            self.proc = None


_shell: Optional[_PersistentShell] = None
_shell_lock = threading.Lock()


def _get_shell() -> _PersistentShell:
    global _shell
    with _shell_lock:
        if _shell is None:
            _shell = _PersistentShell(ADB_SERIAL)
            atexit.register(_shell.close)
        return _shell


def _run(cmd: str, timeout: float = 30.0) -> str:
    """Execute `cmd` as root on device. `cmd` may reference `$SK`
    (persistent shell caches it; fallback subprocess sets it inline)."""
    if _USE_PERSIST:
        return _get_shell().run(cmd, timeout=timeout)
    wrapped = f"SK=$(cat {SUPERKEY_PATH}); {cmd}"
    full = ["adb", "-s", ADB_SERIAL, "shell", f"su -c '{wrapped}'"]
    p = subprocess.run(full, capture_output=True, text=True,
                        timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError(f"adb cmd failed: {p.stderr}\n  cmd: {cmd}")
    return p.stdout


def ctl_raw(args: str) -> str:
    """发送 raw ctl0 给 ptehook-planc-v2 KPM，返回 stdout。"""
    return _run(f"{PTEHOOK_CTL} $SK raw {args}")


def parse_ok(output: str) -> bool:
    return "[OK]" in output


def parse_fail_msg(output: str) -> Optional[str]:
    m = re.search(r"\[FAIL\]\s*(.+)", output)
    return m.group(1).strip() if m else None


def proc_read(pid: int, addr: int, length: int) -> bytes:
    """跨进程读 length 字节内存。返回 bytes。"""
    out = ctl_raw(f"proc-read {pid} 0x{addr:x} {length}")
    m = re.search(r"\[OK\]\s*\d+\s*bytes:\s*([0-9a-fA-F]+)", out)
    if not m:
        raise RuntimeError(f"proc-read failed: {out}")
    hex_str = m.group(1)
    return bytes.fromhex(hex_str[: length * 2])


def proc_read_u64(pid: int, addr: int) -> int:
    """读 8 字节小端 u64。"""
    b = proc_read(pid, addr, 8)
    return int.from_bytes(b, "little")


def proc_read_u32(pid: int, addr: int) -> int:
    b = proc_read(pid, addr, 4)
    return int.from_bytes(b, "little")


def proc_patch(pid: int, addr: int, data: bytes) -> None:
    """跨进程写 data 到目标地址。"""
    hex_str = data.hex()
    # chunk 1KB 每次
    CHUNK = 1024
    for i in range(0, len(data), CHUNK):
        part = hex_str[i * 2 : (i + CHUNK) * 2]
        out = ctl_raw(f"proc-patch {pid} 0x{addr + i:x} {part}")
        if not parse_ok(out):
            raise RuntimeError(f"proc-patch failed: {out}")


def ghost_alloc(pid: int, near_or_exact: int, size: int, exact: bool = False) -> int:
    """分配 ghost 页。exact=True 走 ghost-alloc-at，否则 ghost-alloc。返回 vaddr。"""
    subcmd = "ghost-alloc-at" if exact else "ghost-alloc"
    out = ctl_raw(f"{subcmd} {pid} 0x{near_or_exact:x} 0x{size:x}")
    m = re.search(r"ghost=0x([0-9a-fA-F]+)", out)
    if not m:
        msg = parse_fail_msg(out) or "unknown"
        raise RuntimeError(f"{subcmd} failed: {msg}\n{out}")
    return int(m.group(1), 16)


def ghost_free(pid: int, vaddr: int) -> None:
    out = ctl_raw(f"ghost-free {pid} 0x{vaddr:x}")
    if not parse_ok(out):
        raise RuntimeError(f"ghost-free failed: {out}")


def ghost_read(pid: int, vaddr: int, length: int) -> bytes:
    """读 ghost 字节。KPM 单次上限 1536 字节，自动 chunk 长请求。
    支持 ghost_pool slot 和 uxn_hooks slot 两种 ghost。"""
    CHUNK = 1024  # stay well under KPM 1536 cap
    out = bytearray()
    remaining = length
    cur = vaddr
    while remaining > 0:
        n = min(remaining, CHUNK)
        resp = ctl_raw(f"ghost-read {pid} 0x{cur:x} {n}")
        m = re.search(r"\[OK\][^:]+:\s*([0-9a-fA-F]+)", resp)
        if not m:
            raise RuntimeError(f"ghost-read failed: {resp}")
        chunk = bytes.fromhex(m.group(1))
        if not chunk:
            raise RuntimeError(f"ghost-read empty response: {resp}")
        out += chunk
        cur += len(chunk)
        remaining -= len(chunk)
        if len(chunk) < n:
            break  # KPM clipped (end of ghost region)
    return bytes(out)


def ghost_write(pid: int, vaddr: int, offset: int, data: bytes) -> None:
    hex_str = data.hex()
    CHUNK = 1024
    for i in range(0, len(data), CHUNK):
        part = hex_str[i * 2 : (i + CHUNK) * 2]
        out = ctl_raw(f"ghost-write {pid} 0x{vaddr:x} {offset + i} {part}")
        if not parse_ok(out):
            raise RuntimeError(f"ghost-write failed: {out}")


def uxn_hook(pid: int, target: int, replace: int, force: bool = True) -> int:
    """UXN hook。返回 backup 地址（可调原函数）。

    force=True（默认）：遇到 "already hooked" 时自动 unhook 然后重试一次。
    成因多是上一次 session 崩溃/异常退出留下的孤儿 slot，或 PID 被回收后
    被新进程复用。force=False 则保持原语义（失败抛错）。"""
    def _once():
        return ctl_raw(f"uxn-hook {pid} 0x{target:x} 0x{replace:x}")

    out = _once()
    if force and "[FAIL] already hooked" in out:
        # Try to recover: unhook then retry.
        unhook_out = ctl_raw(f"uxn-unhook {pid} 0x{target:x}")
        if parse_ok(unhook_out):
            out = _once()
    m = re.search(r"backup=0x([0-9a-fA-F]+)", out)
    if not m:
        raise RuntimeError(f"uxn-hook failed: {out}")
    return int(m.group(1), 16)


def uxn_unhook(pid: int, target: int) -> None:
    out = ctl_raw(f"uxn-unhook {pid} 0x{target:x}")
    if not parse_ok(out):
        raise RuntimeError(f"uxn-unhook failed: {out}")


def uxn_list() -> list:
    """列出所有已用的 UXN slot。返回 [{slot, pid, target, page, replace,
    ghost, hits}, ...]。KPM 新命令（旧 KPM 会返回 help 字符串）。"""
    out = ctl_raw("uxn-list")
    rows = []
    for line in out.splitlines():
        m = re.match(
            r"slot=(\d+) pid=(\d+) target=0x([0-9a-f]+) page=0x([0-9a-f]+) "
            r"replace=0x([0-9a-f]+) ghost=0x([0-9a-f]+) hits=(\d+)"
            r"(?:\s+pass3=(\d+) last_far=0x([0-9a-f]+) last_new_pc=0x([0-9a-f]+))?",
            line.strip())
        if m:
            row = dict(
                slot=int(m.group(1)), pid=int(m.group(2)),
                target=int(m.group(3), 16), page=int(m.group(4), 16),
                replace=int(m.group(5), 16), ghost=int(m.group(6), 16),
                hits=int(m.group(7)))
            if m.group(8):
                row['pass3'] = int(m.group(8))
                row['last_far'] = int(m.group(9), 16)
                row['last_new_pc'] = int(m.group(10), 16)
            rows.append(row)
    return rows


def uxn_reap_pid(pid: int) -> int:
    """辅助：清掉给定 pid 的所有 UXN slot（进程死了之后或测试之间）。
    返回清理的数量。需要 KPM 支持 uxn-list。"""
    n = 0
    for row in uxn_list():
        if row["pid"] == pid:
            try:
                uxn_unhook(pid, row["target"])
                n += 1
            except Exception:
                pass
    return n


def java_hook(pid: int, art_method: int, entry_offset: int, new_entry: int) -> None:
    """改写 ArtMethod+entry_offset 的 entry_point 字段。"""
    out = ctl_raw(f"java-hook {pid} 0x{art_method:x} {entry_offset} 0x{new_entry:x}")
    if not parse_ok(out):
        raise RuntimeError(f"java-hook failed: {out}")


def java_unhook(pid: int, art_method: int, entry_offset: int) -> None:
    out = ctl_raw(f"java-unhook {pid} 0x{art_method:x} {entry_offset}")
    if not parse_ok(out):
        raise RuntimeError(f"java-unhook failed: {out}")


def stat() -> str:
    return ctl_raw("stat")


def untag(ptr: int) -> int:
    """清除 ARM64 TBI pointer tag（top byte ignore）。"""
    return ptr & 0x00FFFFFFFFFFFFFF


def get_pid(package: str) -> int:
    """通过 adb shell pidof 查 package PID。"""
    full = ["adb", "-s", ADB_SERIAL, "shell", f"pidof {package}"]
    p = subprocess.run(full, capture_output=True, text=True, timeout=10)
    s = p.stdout.strip()
    if not s:
        raise RuntimeError(f"process {package} not running")
    return int(s.split()[0])


def read_maps(pid: int) -> list:
    """读 /proc/PID/maps，返回 [(start, end, perms, off, path), ...]"""
    out = _run(f"cat /proc/{pid}/maps")
    result = []
    for line in out.splitlines():
        m = re.match(
            r"([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+\S+\s+\d+\s*(.*)",
            line,
        )
        if not m:
            continue
        result.append(
            (
                int(m.group(1), 16),
                int(m.group(2), 16),
                m.group(3),
                int(m.group(4), 16),
                m.group(5).strip(),
            )
        )
    return result


def find_lib(pid: int, lib_name: str) -> list:
    """找一个 .so 的所有 VMA。返回 [(start, end, perms, file_off, path)]。"""
    maps = read_maps(pid)
    return [m for m in maps if lib_name in m[4]]


def lib_rx_base(pid: int, lib_name: str) -> Tuple[int, int]:
    """返回 .so 的 (linker_base, rx_file_off) — 用于 ELF VA → mem addr 换算。
    linker_base = 第一个 r-*p 映射的 start - file_off。"""
    segs = find_lib(pid, lib_name)
    if not segs:
        raise RuntimeError(f"lib {lib_name} not mapped in pid {pid}")
    first = segs[0]
    linker_base = first[0] - first[3]
    return linker_base, first[3]


def find_large_gap(pid: int, min_size: int = 0x1000,
                    max_vaddr: int = 0x8_0000_0000_0000,
                    max_size: int = 0x1_0000_0000) -> int:
    """找合适的空洞起始地址，用于 ghost-alloc-at。

    约束：
      1) 两侧都挨 VMA（左 VMA 的 PTE 可作模板）
      2) gap size 在 [min_size, max_size] —— 太小装不下 ghost；太大则紧邻
         左 VMA 的位置可能 probe 不到右侧模板，而且 aweme 这种进程有
         >300GB 的 no-VMA 空洞，选中它等于选无人区
      3) prev_end 在 max_vaddr 以下（过滤 ARM64 TBI 虚假地址）

    返回 gap_start + 4KB —— 紧靠左侧 VMA。
    """
    maps = read_maps(pid)
    maps.sort()
    best_start, best_size = 0, 0
    for i in range(len(maps) - 1):
        prev_end = maps[i][1]
        next_start = maps[i+1][0]
        if next_start <= prev_end:
            continue
        gap = next_start - prev_end
        if prev_end > max_vaddr:
            continue
        if gap > max_size:
            continue  # no-VMA wasteland, PTE probe would fail
        if gap > best_size:
            best_start, best_size = prev_end, gap
    if best_size < min_size:
        raise RuntimeError(
            f"no VMA-bounded gap in [{min_size:#x}, {max_size:#x}] in pid {pid}")
    return best_start + 0x1000
