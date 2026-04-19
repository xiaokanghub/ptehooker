"""
Session - 主入口，管理一个目标进程的所有 hook。
"""
import os
import sys
import time
import threading
import subprocess
import signal

# make imports work whether run as module or installed
_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import kpm_client as K
import sym_resolver as S
import dex_parser as DP
import shellcode as SC
import art_offsets as AO
from . import actions


def _ep_offset():
    """ArtMethod.entry_point_from_quick_compiled_code_ offset for target device's API."""
    return AO.get_offsets().get("ARTMETHOD_ENTRY_QUICK", 0x18)


def _af_offset():
    """ArtMethod.access_flags_ offset."""
    return AO.get_offsets().get("ARTMETHOD_ACCESS_FLAGS", 0x04)


def _scanner_flags():
    """CLI flags to pass to device_scanner for current API's ArtMethod layout."""
    o = AO.get_offsets()
    size = o.get("ARTMETHOD_SIZE", 0x20)
    decl = o.get("ARTMETHOD_DECLARING_CLASS", 0x00)
    af = o.get("ARTMETHOD_ACCESS_FLAGS", 0x04)
    midx = o.get("ARTMETHOD_DEX_METHOD_INDEX", 0x08)
    # Only emit flags if they differ from scanner's built-in defaults (so we
    # stay compatible with old scanner binaries that don't know these flags).
    parts = []
    if size != 0x20: parts.append(f"--size={size}")
    if decl != 0x00: parts.append(f"--off-decl={decl}")
    if af != 0x04: parts.append(f"--off-af={af}")
    if midx != 0x08: parts.append(f"--off-midx={midx}")
    return " ".join(parts)


LIB_CACHE = "/tmp/ptehook_lib_cache"


def _adb(*args):
    return subprocess.check_output(
        ["adb", "-s", K.ADB_SERIAL] + list(args), text=True)


def _adb_root(cmd):
    return _adb("shell", f"su -c '{cmd}'")


def _ensure_local_so(device_path: str) -> str:
    os.makedirs(LIB_CACHE, exist_ok=True)
    local = os.path.join(LIB_CACHE, os.path.basename(device_path))
    if not os.path.exists(local):
        tmp = "/data/local/tmp/_so_probe_" + os.path.basename(device_path)
        _adb_root(f"cp {device_path} {tmp} && chmod 644 {tmp}")
        subprocess.check_call(
            ["adb", "-s", K.ADB_SERIAL, "pull", tmp, local],
            stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    return local


def _ensure_apk(package: str) -> str:
    """Pull target APK to host, return local path."""
    os.makedirs(LIB_CACHE, exist_ok=True)
    local = os.path.join(LIB_CACHE, f"{package}.apk")
    if os.path.exists(local):
        return local
    out = _adb("shell", f"pm path {package}").strip()
    dev_path = out.split(":", 1)[1] if ":" in out else out
    tmp = "/data/local/tmp/_apk_probe.apk"
    _adb_root(f"cp {dev_path} {tmp} && chmod 644 {tmp}")
    subprocess.check_call(
        ["adb", "-s", K.ADB_SERIAL, "pull", tmp, local],
        stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    return local


class InstalledHook:
    """Represents one live hook for lifecycle management."""
    def __init__(self, kind, action, meta):
        self.kind = kind          # "java" or "native"
        self.action = action
        self.meta = meta          # {target_addr, ghost, log_buf, ...}


class Session:
    def __init__(self, pid: int, package: str = None):
        self.pid = pid
        self.package = package
        self.hooks = []           # list[InstalledHook]
        self._apk_path = None
        self._stop = False
        self._watcher_thread = None
        self._watcher_stop = threading.Event()
        self._watcher_lock = threading.Lock()

    @property
    def apk(self) -> str:
        if self._apk_path is None:
            if not self.package:
                raise RuntimeError("no package set; can't resolve APK")
            self._apk_path = _ensure_apk(self.package)
        return self._apk_path

    # ------------------------------------------------------------------
    # Java hook
    # ------------------------------------------------------------------
    def java_hook(self, class_desc, method, sig, *,
                   replace=None, on_call=None, action=None,
                   artmethod=None, wait_jit=False, warmup_timeout=30.0,
                   unsafe_bridge=False, force_acc_native=False,
                   legacy_entry_patch=False, jit_watch=False,
                   jit_watch_interval=0.5):
        """
        class_desc: DEX descriptor e.g. "Lcom/foo/Bar;"
        method:     method name
        sig:        method signature e.g. "(I)I"
        replace:    int → return this const
        on_call:    callable(args) → log + call user (args = [X0..X7] ints)
        action:    explicit Action instance (overrides replace/on_call)
        artmethod: hex str, force specific candidate
        wait_jit:   若 True 且 entry_point 初始指向 libart bridge，轮询等到
                    ART JIT 把 entry_point 迁到私有代码段再装陷阱。期间
                    **用户需要自己触发方法调用**（点按钮 / adb 触发等）。
                    ART 13 默认阈值约 10 次。
        warmup_timeout: wait_jit 超时秒数
        unsafe_bridge: entry_point 在 libart.so 时默认拒绝安装（因为 Pass 3
                    DBI fallthrough 在 ART 复杂辅助函数上有已知崩溃）。设为
                    True 强制继续，风险自负。建议用 wait_jit=True 替代。
        force_acc_native: 在 ArtMethod.access_flags 打上 ACC_NATIVE (0x100)。
                    ART 13 Nterp 对纯 Java 方法的 Nterp→Nterp 调用**不走
                    entry_point**（Nterp 内部循环解释），所以 UXN 陷阱抓不到。
                    ACC_NATIVE 强制 ART 把该方法视为 native，必须通过
                    entry_point 分发 → 陷阱能命中。副作用：ArtMethod 字节有
                    可见修改（低 16 bit 多了 0x100）。stealth 要求高时不要用。
                    实测 ART 13 Nterp 即使 ACC_NATIVE 也走 fast path，该开关
                    可能效果有限 —— 确认方法被 JIT 编译前优先 wait_jit=True。
        legacy_entry_patch: **最后的退路** —— 走旧路径：ACC_NATIVE + 改写
                    ArtMethod.entry_point 指向 ghost。能抓 Nterp-dispatched
                    方法（因为 Nterp 读 ACC_NATIVE 走 entry_point）但 ArtMethod
                    字节被污染（+4 处 0x100、+0x18 指向 ghost 段），反作弊扫
                    ArtMethod 就会看到。仅在 7.2 trap 模式抓不到（uncompiled
                    + Nterp-only）且能接受字节污染时使用。
        jit_watch:  装 hook 后启动后台线程轮询 ArtMethod.entry_point。若 ART
                    升级 tier（Nterp → JIT baseline → JIT optimized）导致
                    entry_point 变化，自动 uxn_unhook 旧地址 + uxn_hook 新地址
                    + 重写 shellcode。避免 hook 悄悄失效。有少量 poll 开销。
        jit_watch_interval: 轮询间隔秒（默认 0.5s）
        """
        if action is None:
            if replace is not None:
                action = actions.ReturnConst(int(replace))
            elif on_call is not None:
                action = actions.LogArgs(on_call=on_call)
            else:
                action = actions.Noop()

        # DEX parse
        info = DP.find_method_in_apk(self.apk, class_desc, method, sig)
        if not info:
            raise RuntimeError(
                f"method {class_desc}.{method}{sig} not found in APK")
        print(f"[+] DEX: {info['dex_name']} method_idx={info['method_idx']}")

        # Scan ArtMethod
        target = self._resolve_artmethod(info, artmethod)
        print(f"[+] ArtMethod @ 0x{target:x}")

        if wait_jit:
            self._wait_for_jit(target, warmup_timeout)
        elif not unsafe_bridge and not force_acc_native and not legacy_entry_patch:
            # Default safety: reject libart bridge entry_points to avoid
            # the known DBI Pass 3 crash (artInvokeInterfaceTrampoline etc.)
            ep = K.untag(K.proc_read_u64(self.pid, target + _ep_offset()))
            maps = K.read_maps(self.pid)
            in_libart = any(s <= ep < e and "libart.so" in p
                             for s, e, _, _, p in maps)
            if in_libart:
                raise RuntimeError(
                    f"entry_point 0x{ep:x} 在 libart.so（bridge / Nterp / "
                    f"trampoline）—— 默认拒绝安装。解法：\n"
                    f"  1) wait_jit=True（推荐）—— 先触发 JIT，让 entry_point "
                    f"迁出 libart，最安全\n"
                    f"  2) legacy_entry_patch=True —— 退回旧路径（改 "
                    f"ArtMethod 字节），能抓 Nterp 但放弃 stealth\n"
                    f"  3) unsafe_bridge=True —— 风险自负强制 7.2 陷阱")

        if force_acc_native:
            af_addr = target + _af_offset()
            orig_af = K.proc_read_u32(self.pid, af_addr)
            if not (orig_af & 0x100):
                new_af = orig_af | 0x100
                K.proc_patch(self.pid, af_addr,
                              new_af.to_bytes(4, "little"))
                self._pending_af_restore = (af_addr, orig_af)
                print(f"[!] force_acc_native: access_flags "
                      f"0x{orig_af:x} → 0x{new_af:x} (ACC_NATIVE set)")

        # Alloc ghost + install
        if legacy_entry_patch:
            meta = self._install_java_legacy(target, action)
        else:
            meta = self._install_java(target, action)
        if force_acc_native and hasattr(self, "_pending_af_restore"):
            meta["orig_af"] = self._pending_af_restore[1]
            meta["af_addr"] = self._pending_af_restore[0]
            del self._pending_af_restore
        if jit_watch and not legacy_entry_patch:
            # Only 7.2 trap mode supports re-hook; legacy uses java_hook KPM cmd
            # which doesn't need ghost/backup rebuild on drift (entry_point is
            # always our ghost).
            meta["watch"] = True
        ih = InstalledHook("java", action, meta)
        self.hooks.append(ih)
        if meta.get("watch"):
            self._start_jit_watcher(jit_watch_interval)
        print(f"[+] java hook installed ({info['method_name']}{info['signature']})")
        return ih

    def java_hook_all(self, class_desc, method, sig, *,
                       replace=None, on_call=None, action=None,
                       wait_jit=False, warmup_timeout=30.0,
                       unsafe_bridge=True, force_acc_native=False,
                       legacy_entry_patch=False, jit_watch=False):
        """
        在 scanner 所有合格候选上 hook —— 覆盖多 ClassLoader 场景（aweme 类）：
        同一 class 被不同 ClassLoader 加载，每次都是一份独立 ArtMethod，
        不全部 hook 会漏调用。

        通过 access_flags 过滤后**不做 cluster 消歧**，每个候选都装。
        返回 list[InstalledHook]。

        unsafe_bridge 默认 True（因为 spray 场景通常包括 bridge entry_point
        的多候选，用户已经知道有 DBI 风险）。
        """
        import shellcode as SC

        if action is None:
            if replace is not None:
                action = actions.ReturnConst(int(replace))
            elif on_call is not None:
                action = actions.LogArgs(on_call=on_call)
            else:
                action = actions.Noop()

        info = DP.find_method_in_apk(self.apk, class_desc, method, sig)
        if not info:
            raise RuntimeError(
                f"method {class_desc}.{method}{sig} not found in APK")
        print(f"[+] DEX: {info['dex_name']} method_idx={info['method_idx']}")

        # Run scanner; collect candidates filtered by access_flags only
        adj_csv = ",".join(str(x) for x in info["adjacent_idxs"])
        out = _adb_root(
            f"/data/local/tmp/pte_scan {self.pid} {info['method_idx']} {adj_csv} {_scanner_flags()}")
        cands = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("0x"):
                cands.append(int(line.split()[0], 16))
        if not cands:
            raise RuntimeError("scanner returned no candidates")

        dex_af = info.get("access_flags")
        if dex_af is not None:
            filt = []
            for c in cands:
                try:
                    af = K.proc_read_u32(self.pid, c + 4)
                except Exception:
                    continue
                if (af & 0xFFFF) == (dex_af & 0xFFFF):
                    filt.append(c)
            if filt:
                cands = filt

        print(f"[+] java_hook_all: {len(cands)} candidates")
        installed = []
        for i, target in enumerate(cands):
            # Use a fresh action instance per hook (they may have internal state)
            import copy
            per_action = copy.copy(action)
            # Re-init counters if present
            for attr in ("last_counter", "last_pre", "last_post"):
                if hasattr(per_action, attr):
                    setattr(per_action, attr, 0)
            try:
                if force_acc_native:
                    af_addr = target + _af_offset()
                    orig_af = K.proc_read_u32(self.pid, af_addr)
                    if not (orig_af & 0x100):
                        K.proc_patch(self.pid, af_addr,
                                      (orig_af | 0x100).to_bytes(4, "little"))
                        self._pending_af_restore = (af_addr, orig_af)
                if legacy_entry_patch:
                    meta = self._install_java_legacy(target, per_action)
                else:
                    meta = self._install_java(target, per_action)
                if force_acc_native and hasattr(self, "_pending_af_restore"):
                    meta["orig_af"] = self._pending_af_restore[1]
                    meta["af_addr"] = self._pending_af_restore[0]
                    del self._pending_af_restore
                if jit_watch and not legacy_entry_patch:
                    meta["watch"] = True
                ih = InstalledHook("java", per_action, meta)
                self.hooks.append(ih)
                installed.append(ih)
                print(f"  [{i}] 0x{target:x} OK")
            except Exception as e:
                print(f"  [{i}] 0x{target:x} FAILED: {e}")
        if any(h.meta.get("watch") for h in installed):
            self._start_jit_watcher(0.5)
        print(f"[+] {len(installed)}/{len(cands)} hooks installed")
        return installed

    def _start_jit_watcher(self, interval: float):
        """Idempotent — multiple java_hook calls share one watcher thread."""
        if self._watcher_thread is not None:
            return
        self._watcher_stop.clear()
        self._watcher_interval = interval
        self._watcher_thread = threading.Thread(
            target=self._jit_watch_loop, daemon=True,
            name=f"ptehook-jitwatch-{self.pid}")
        self._watcher_thread.start()
        print(f"[+] JIT drift watcher started (interval={interval}s)")

    def _jit_watch_loop(self):
        """Poll each watched hook's ArtMethod.entry_point; re-install on change."""
        import shellcode as SC
        while not self._watcher_stop.wait(self._watcher_interval):
            with self._watcher_lock:
                for h in list(self.hooks):
                    if h.kind != "java" or not h.meta.get("watch"):
                        continue
                    self._rehook_if_drifted(h, SC)

    def _rehook_if_drifted(self, h, SC):
        am = h.meta["target"]
        installed_ep = h.meta.get("orig_ep")
        if installed_ep is None:
            return
        try:
            current_ep = K.untag(K.proc_read_u64(self.pid, am + _ep_offset()))
        except Exception:
            return  # process may have died, let close() handle
        if current_ep == installed_ep:
            return
        print(f"\n[!] JIT drift on 0x{am:x}: ep 0x{installed_ep:x} "
              f"→ 0x{current_ep:x}, rehooking")
        ghost = h.meta["ghost"]
        log_buf = h.meta["log_buf"]
        # Tear down old UXN
        try:
            K.uxn_unhook(self.pid, installed_ep)
        except Exception as e:
            print(f"    (old unhook failed: {e}; continuing)")
        # Install UXN at new entry_point
        try:
            new_backup = K.uxn_hook(self.pid, current_ep, ghost)
        except Exception as e:
            print(f"[!] rehook failed uxn_hook: {e}")
            return
        # Rebuild filter shellcode with new backup
        action = h.action
        if getattr(action, "BACKUP_REQUIRED", False):
            action.set_backup(new_backup)
        try:
            action_code = action.build(log_buf)
            full = SC.java_uxn_filter(am, action_code, new_backup)
            K.ghost_write(self.pid, ghost, 0, full)
        except Exception as e:
            print(f"[!] rehook failed shellcode rewrite: {e}")
            K.uxn_unhook(self.pid, current_ep)
            return
        h.meta["orig_ep"] = current_ep
        h.meta["backup"] = new_backup
        print(f"[+] rehook OK: 0x{current_ep:x} backup=0x{new_backup:x}")

    def _wait_for_jit(self, target_addr, timeout=30.0, poll=0.5):
        """轮询 ArtMethod.entry_point 直到它离开 libart.so（JIT 编译完成）。
        Returns 最新的 entry_point。在 timeout 之前 JIT 未触发会抛异常。"""
        maps = K.read_maps(self.pid)
        libart_ranges = [(s, e) for s, e, _, _, p in maps if "libart.so" in p]

        def in_libart(ep):
            return any(s <= ep < e for s, e in libart_ranges)

        first_ep = K.untag(K.proc_read_u64(self.pid, target_addr + _ep_offset()))
        if not in_libart(first_ep):
            print(f"[+] entry_point 0x{first_ep:x} 已在 JIT/AOT 段，跳过 warm-up")
            return first_ep

        print(f"[*] entry_point 在 libart bridge (0x{first_ep:x})；"
              f"等 JIT 编译（最多 {timeout:.0f}s）")
        print(f"[*] 请在这期间反复调用目标方法 —— ART 13 默认 JIT 阈值 ~10 次")

        start = time.time()
        while time.time() - start < timeout:
            time.sleep(poll)
            ep = K.untag(K.proc_read_u64(self.pid, target_addr + _ep_offset()))
            if not in_libart(ep):
                elapsed = time.time() - start
                print(f"[+] JIT 完成 ({elapsed:.1f}s): "
                      f"0x{first_ep:x} → 0x{ep:x}")
                return ep
        raise TimeoutError(
            f"JIT warm-up {timeout}s 超时；entry_point 仍在 libart.so。"
            f"目标方法调用次数是否足够？或被 ART 标记不可 JIT？")

    def _resolve_artmethod(self, info, artmethod_override):
        """将 DEX 方法解析成目标进程里的 ArtMethod*。

        过滤链（从强到弱）：
          1) 扫描器已过滤 dex_method_idx（+8） 精确匹配
          2) access_flags（+4）低 16 bit ⊇ DEX access_flags
          3) 同类 cluster size 匹配 expected = len(adj)+1
          4) 上述都平局 → 重试（app 刚启动可能 cluster 未满）
          5) 仍平局 → 列出候选，要求显式 artmethod= 消歧
        """
        if artmethod_override:
            return int(artmethod_override, 0)
        # Retry on ambiguity — LinearAlloc populates incrementally during
        # app init; neighboring ArtMethods may not exist yet on first scan.
        last_error = None
        for attempt in range(3):
            try:
                return self._resolve_artmethod_once(info)
            except RuntimeError as e:
                msg = str(e)
                if "无法自动消歧" not in msg and "no candidates" not in msg:
                    raise
                last_error = e
                if attempt < 2:
                    print(f"[*] scanner ambiguous (try {attempt+1}/3), "
                          f"等 LinearAlloc 稳定 0.5s 重试...")
                    time.sleep(0.5)
        raise last_error

    def _resolve_artmethod_once(self, info):
        idx = info["method_idx"]
        adj = info["adjacent_idxs"]
        dex_af = info.get("access_flags", None)
        adj_csv = ",".join(str(x) for x in adj)
        out = _adb_root(
            f"/data/local/tmp/pte_scan {self.pid} {idx} {adj_csv} {_scanner_flags()}")
        cands = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("0x"):
                cands.append(int(line.split()[0], 16))
        if not cands:
            raise RuntimeError("scanner returned no candidates")

        # Filter 1: access_flags match (low 16 bits).
        if dex_af is not None and len(cands) > 1:
            filtered = []
            for c in cands:
                try:
                    af = K.proc_read_u32(self.pid, c + 4)
                except Exception:
                    continue
                if (af & 0xFFFF) == (dex_af & 0xFFFF):
                    filtered.append(c)
            if filtered:
                if len(filtered) < len(cands):
                    print(f"[+] access_flags 过滤: {len(cands)} → "
                          f"{len(filtered)} 候选")
                cands = filtered

        if len(cands) == 1:
            return cands[0]

        # Filter 2: cluster size for multi-method classes
        expected = len(adj) + 1
        cluster_matches = []
        for c in cands:
            cand_decl = K.proc_read_u32(self.pid, c)
            n_same = 1
            for k in range(1, 20):
                try:
                    d = K.proc_read_u32(self.pid, c + k * 0x20)
                    if d == cand_decl: n_same += 1
                    else: break
                except Exception:
                    break
            for k in range(1, 20):
                try:
                    d = K.proc_read_u32(self.pid, c - k * 0x20)
                    if d == cand_decl: n_same += 1
                    else: break
                except Exception:
                    break
            if n_same == expected or n_same == expected - 2:
                cluster_matches.append((c, n_same))

        if len(cluster_matches) == 1:
            return cluster_matches[0][0]
        if len(cluster_matches) > 1:
            cands = [c for c, _ in cluster_matches]

        # Ambiguity — show candidates, raise (caller may retry).
        lines = []
        for c in cands:
            try:
                af = K.proc_read_u32(self.pid, c + 4)
                decl = K.proc_read_u32(self.pid, c)
                ep = K.untag(K.proc_read_u64(self.pid, c + 0x18))
            except Exception:
                af = decl = ep = 0
            lines.append(f"  0x{c:x}  access=0x{af:08x}  decl=0x{decl:x}  "
                         f"ep=0x{ep:x}")
        raise RuntimeError(
            f"{len(cands)} 候选无法自动消歧 (expected cluster={expected}):\n"
            + "\n".join(lines)
            + f"\n  传 artmethod='0x...' 手动指定。")

    def _install_java_legacy(self, target_addr, action):
        """旧路径：打 ACC_NATIVE + 改 entry_point 指向 ghost shellcode。
        优点：Nterp dispatch 经 entry_point 能命中。
        缺点：ArtMethod 字节可见修改（+4 = ACC_NATIVE bit, +0x18 = ghost addr）。
        反作弊扫 ArtMethod 会发现。"""
        ghost = self._alloc_ghost(0x1000)
        log_buf = ghost + 0x800 if action.needs_log else 0

        if getattr(action, "NEEDS_JAVA_BACKUP", False):
            raise NotImplementedError("legacy + CallBackupJava 暂未支持")

        code = action.build(log_buf)
        K.ghost_write(self.pid, ghost, 0, code)

        # Set ACC_NATIVE
        af_addr = target_addr + _af_offset()
        orig_af = K.proc_read_u32(self.pid, af_addr)
        new_af = orig_af | 0x100
        K.proc_patch(self.pid, af_addr, new_af.to_bytes(4, "little"))

        # Patch entry_point via KPM java-hook command
        K.java_hook(self.pid, target_addr, _ep_offset(), ghost)

        return dict(target=target_addr, ghost=ghost, log_buf=log_buf,
                    orig_ep=None, backup=None, legacy=True,
                    orig_af=orig_af, af_addr=af_addr)

    def _install_java(self, target_addr, action):
        """7.2「查名片、布设隐形陷阱」路径：

        - 读 ArtMethod.entry_point_from_quick_compiled_code_ (offset 0x18)，**不写**
        - 不改 access_flags（不打 ACC_NATIVE 标志）
        - 在 entry_point 指向的代码页拉 UXN 陷阱
        - shellcode 里过滤 X0（=ArtMethod*）保证只对目标方法生效
          （同一页上其他方法/共享 bridge 的调用，经 backup DBI 跑原逻辑）
        """
        if getattr(action, "NEEDS_JAVA_BACKUP", False):
            raise NotImplementedError(
                "CallBackupJava 用的 temp-unhook 技巧依赖旧 java_hook 路径；"
                "7.2 trap 模式下请改用 CallBackup Action（无 temp-unhook，"
                "直接 BLR DBI 的 backup）。")

        orig_ep = K.proc_read_u64(self.pid, target_addr + _ep_offset())
        orig_ep = K.untag(orig_ep)
        print(f"[+] entry_point (untagged) = 0x{orig_ep:x}")

        # Diagnose where entry_point lives (AOT / JIT / bridge / 死指针)
        maps = K.read_maps(self.pid)
        ep_path = None
        ep_perms = None
        for s, e, perms, _, path in maps:
            if s <= orig_ep < e:
                ep_path = path
                ep_perms = perms
                break
        if ep_path is None:
            # entry_point falls in an unmapped gap — almost certainly a stale
            # ghost address left by the legacy java_hook path. The ArtMethod's
            # ACC_NATIVE bit is likely still set from that run too. Abort with
            # a clear recovery instruction.
            orig_af = K.proc_read_u32(self.pid, target_addr + _af_offset())
            raise RuntimeError(
                f"entry_point 0x{orig_ep:x} 指向未映射地址 —— ArtMethod 0x"
                f"{target_addr:x} 被上一次旧 java_hook 路径污染 "
                f"(access_flags=0x{orig_af:x}, ACC_NATIVE="
                f"{'set' if orig_af & 0x100 else 'clear'}). "
                f"无法安全恢复；请 `adb shell am force-stop <pkg>` 重启 app 取得干净 ArtMethod。")
        if "libart.so" in ep_path:
            print(f"[!] entry_point 位于 libart.so ({ep_perms}) —— 方法未编译，"
                  f"指向 art_quick_*_bridge 或 trampoline。")
            print(f"[!] 风险：bridge 页调用密集，同页非目标方法走 Pass 3 DBI "
                  f"fallthrough；当前 DBI 在 ART 复杂辅助函数处有已知崩溃。")
            print(f"[!] 建议：先多次调用目标方法触发 JIT，让 entry_point 切到 "
                  f"JIT 私有代码后再装 hook。")
        elif "x" in (ep_perms or ""):
            print(f"[+] entry_point 在可执行段: {ep_path} ({ep_perms})")
        else:
            print(f"[!] entry_point 在非可执行段 ({ep_perms}) {ep_path} —— 异常状态")

        ghost = self._alloc_ghost(0x1000)
        log_buf = ghost + 0x800 if action.needs_log else 0

        # For CallBackup on Java: need backup before building shellcode.
        # uxn_hook gives us backup regardless of action type, and our filter
        # always needs it for the mismatch path. So: install UXN first, then
        # build + write shellcode.
        backup = K.uxn_hook(self.pid, orig_ep, ghost)
        print(f"[+] uxn-hook @ 0x{orig_ep:x} → ghost 0x{ghost:x} "
              f"backup 0x{backup:x}")

        if getattr(action, "BACKUP_REQUIRED", False):
            action.set_backup(backup)
        action_code = action.build(log_buf)

        full = SC.java_uxn_filter(target_addr, action_code, backup)
        K.ghost_write(self.pid, ghost, 0, full)

        return dict(target=target_addr, ghost=ghost, log_buf=log_buf,
                    orig_ep=orig_ep, backup=backup)

    # ------------------------------------------------------------------
    # Native hook
    # ------------------------------------------------------------------
    def native_hook(self, lib_name, symbol=None, offset=None, *,
                     replace=None, on_call=None, action=None):
        if action is None:
            if replace is not None:
                action = actions.ReturnConst(int(replace))
            elif on_call is not None:
                action = actions.LogArgs(on_call=on_call)
            else:
                action = actions.Noop()

        # Resolve addr
        maps = K.read_maps(self.pid)
        segs = [m for m in maps if lib_name in m[4]]
        if not segs:
            raise RuntimeError(f"lib {lib_name} not mapped in pid {self.pid}")
        first = segs[0]
        linker_base = first[0] - first[3]
        dev_path = first[4]
        if symbol:
            so_local = _ensure_local_so(dev_path)
            va = S.resolve_symbol(so_local, symbol)
            target = linker_base + va
            print(f"[+] native target {symbol} @ ELF 0x{va:x} mem 0x{target:x}")
        elif offset is not None:
            target = linker_base + int(offset, 0) \
                if isinstance(offset, str) else linker_base + offset
            print(f"[+] native target offset 0x{offset:x} → mem 0x{target:x}")
        else:
            raise ValueError("need symbol or offset")

        meta = self._install_native(target, action)
        ih = InstalledHook("native", action, meta)
        self.hooks.append(ih)
        print(f"[+] native hook installed on {lib_name}")
        return ih

    def _install_native(self, target_addr, action):
        ghost = self._alloc_ghost(0x1000)
        log_buf = ghost + 0x800 if action.needs_log else 0
        # For CallBackup: uxn-hook FIRST to get backup addr, then build shellcode
        if getattr(action, "BACKUP_REQUIRED", False):
            backup = K.uxn_hook(self.pid, target_addr, ghost)
            action.set_backup(backup)
            code = action.build(log_buf)
            K.ghost_write(self.pid, ghost, 0, code)
        else:
            code = action.build(log_buf)
            K.ghost_write(self.pid, ghost, 0, code)
            backup = K.uxn_hook(self.pid, target_addr, ghost)
        return dict(target=target_addr, ghost=ghost, log_buf=log_buf,
                    backup=backup)

    # ------------------------------------------------------------------
    def _alloc_ghost(self, size):
        """User shellcode ghost. Tries:
          1) In a LARGE gap (prevents contention with KPM's DBI ghost which
             also wants near-libart space — on dense processes like aweme,
             the only near-libart gap gets eaten by one party and the other
             fails ENOSPC).
          2) Fall back to near-libart if no large gap found.
        """
        maps = K.read_maps(self.pid)
        libart = [(s, e) for s, e, p, _, path in maps
                   if "libart.so" in path and "r-xp" in p]
        if not libart:
            raise RuntimeError("libart r-xp not found")
        near = libart[0][0]

        # Prefer large-gap allocation (keeps near-libart free for KPM DBI).
        try:
            gap = K.find_large_gap(self.pid, min_size=0x10000)
            return K.ghost_alloc(self.pid, gap, size, exact=True)
        except Exception:
            pass

        # Fallback: near libart (dense process may not have large gap with
        # valid PTE template nearby).
        try:
            return K.ghost_alloc(self.pid, near, size, exact=False)
        except Exception as e:
            raise RuntimeError(
                f"ghost_alloc failed in both large-gap and near-libart: {e}")

    # ------------------------------------------------------------------
    # Event loop
    # ------------------------------------------------------------------
    def run(self, poll_hz: float = 5):
        """Poll each hook's log buffer; fire on_call/on_return callbacks.
        Blocks; Ctrl+C to stop."""
        def handler(*_):
            self._stop = True
        signal.signal(signal.SIGINT, handler)

        interval = 1.0 / poll_hz
        print(f"[*] event loop @ {poll_hz}Hz (Ctrl+C to stop)")
        import re
        try:
            while not self._stop:
                for h in self.hooks:
                    if not h.action.needs_log:
                        continue
                    buf = h.meta.get("log_buf", 0)
                    if not buf:
                        continue
                    try:
                        # CallBackup/CallBackupJava need 104 bytes; LogArgs only 80
                        need = 104 if h.action.__class__.__name__ in ("CallBackup", "CallBackupJava") else 80
                        out = K.ctl_raw(f"ghost-read {self.pid} 0x{buf:x} {need}")
                        m = re.search(
                            r"\[OK\].*?bytes[^:]*:\s*([0-9a-fA-F]+)", out)
                        if not m:
                            continue
                        data = bytes.fromhex(m.group(1))
                    except Exception:
                        continue
                    event = h.action.parse_event(data)
                    if not event.get("valid"):
                        continue
                    # LogArgs: fires on_call
                    if event.get("new_calls", 0) > 0 and getattr(h.action, 'on_call', None):
                        for _ in range(event["new_calls"]):
                            h.action.on_call(event["regs"])
                    # CallBackup: fires on_call (pre) and on_return (post)
                    if event.get("new_pre", 0) > 0 and getattr(h.action, 'on_call', None):
                        for _ in range(event["new_pre"]):
                            h.action.on_call(event["pre_regs"])
                    if event.get("new_post", 0) > 0 and getattr(h.action, 'on_return', None):
                        for _ in range(event["new_post"]):
                            h.action.on_return(event["pre_regs"],
                                               event["post_x0"],
                                               event["post_x1"])
                time.sleep(interval)
        finally:
            print(f"\n[*] stopping; {len(self.hooks)} hooks remain installed")

    def close(self):
        """Unhook all and free ghosts. NOT done automatically — user must call
        explicitly or rely on process exit."""
        # Stop JIT watcher first so it doesn't race with unhook
        if self._watcher_thread is not None:
            self._watcher_stop.set()
            self._watcher_thread.join(timeout=2.0)
            self._watcher_thread = None
        with self._watcher_lock:
            self._close_locked()

    def _close_locked(self):
        # Check if target process still alive — if dead, KPM state was already
        # reaped via reap_dead_uxn_slots. Everything else is best-effort.
        proc_alive = os.path.exists(f"/proc/{self.pid}") or self._pid_alive()

        errors = []
        for h in self.hooks:
            g = h.meta.get("ghost")
            try:
                if h.kind == "java":
                    if h.meta.get("legacy"):
                        K.java_unhook(self.pid, h.meta["target"], _ep_offset())
                    else:
                        ep = h.meta["orig_ep"]
                        K.uxn_unhook(self.pid, ep)
                    if "orig_af" in h.meta and "af_addr" in h.meta and proc_alive:
                        K.proc_patch(
                            self.pid, h.meta["af_addr"],
                            h.meta["orig_af"].to_bytes(4, "little"))
                elif h.kind == "native":
                    K.uxn_unhook(self.pid, h.meta["target"])
            except Exception as e:
                # If process died, KPM reaped on its own — expected
                if proc_alive:
                    errors.append(f"{h.kind} unhook: {e}")
            # Free ghost regardless (KPM handles dead-process case)
            if g is not None:
                try:
                    K.ghost_free(self.pid, g)
                except Exception as e:
                    if proc_alive:
                        errors.append(f"ghost_free 0x{g:x}: {e}")
        self.hooks.clear()
        if errors:
            # Surface real issues rather than silently swallowing
            raise RuntimeError(
                "close() had errors:\n  " + "\n  ".join(errors))

    def _pid_alive(self) -> bool:
        try:
            subprocess.check_output(
                ["adb", "-s", K.ADB_SERIAL, "shell",
                 f"test -d /proc/{self.pid}"], stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False


def attach(package: str = None, pid: int = None) -> Session:
    """Attach to a running process by package name OR PID."""
    if pid is None and package is None:
        raise ValueError("need package or pid")
    if pid is None:
        pid = K.get_pid(package)
    sess = Session(pid, package)
    print(f"[*] attached to pid {pid}"
          + (f" ({package})" if package else ""))
    return sess
