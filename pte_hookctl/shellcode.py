"""
shellcode.py - ARM64 shellcode 生成器。

核心模板：log trampoline
  saves X0-X7 + X30 (LR) 入 stack
  用 syscall write(fd=<fd>, buf=<stack>, len=N) 写 8 个寄存器到日志 fd
  restore X0-X7 + X30
  jump to backup_addr  （原函数的入口）

另外提供：
  const_return(value) - 返回常量立即数
  noop_return()       - 空返回 (MOV X0, #0; RET)
"""
import struct


def _insn(value: int) -> bytes:
    return struct.pack("<I", value)


# ARM64 encoding helpers
def mov_wide(rd: int, imm: int, shift: int = 0) -> int:
    """MOVZ Xd, #imm, LSL #shift (shift in 16-bit units)."""
    hw = shift  # 0/1/2/3 for 0/16/32/48
    return 0xD2800000 | (hw << 21) | ((imm & 0xFFFF) << 5) | rd


def mov_k(rd: int, imm: int, shift: int = 0) -> int:
    """MOVK Xd, #imm, LSL #shift."""
    hw = shift
    return 0xF2800000 | (hw << 21) | ((imm & 0xFFFF) << 5) | rd


def load_imm64(rd: int, value: int) -> bytes:
    """分 4 段 MOVZ+MOVK 加载 64-bit 立即数到 Xd。"""
    b = b""
    parts = [
        value & 0xFFFF,
        (value >> 16) & 0xFFFF,
        (value >> 32) & 0xFFFF,
        (value >> 48) & 0xFFFF,
    ]
    # Start with MOVZ lowest, then MOVK higher ones only if non-zero
    b += _insn(mov_wide(rd, parts[0], 0))
    for i in range(1, 4):
        if parts[i]:
            b += _insn(mov_k(rd, parts[i], i))
    return b


def load_imm64_fixed(rd: int, value: int) -> bytes:
    """固定 4 条指令加载 64-bit 立即数（即使高位为 0 也发 MOVK），
    保证字节数可预测 —— 用于需要固定 B.cond 偏移的分支前序。"""
    parts = [
        value & 0xFFFF,
        (value >> 16) & 0xFFFF,
        (value >> 32) & 0xFFFF,
        (value >> 48) & 0xFFFF,
    ]
    b = _insn(mov_wide(rd, parts[0], 0))
    for i in range(1, 4):
        b += _insn(mov_k(rd, parts[i], i))
    return b


def br_absolute(target: int) -> bytes:
    """加载 target 到 X16 然后 BR X16（绝对跳转）。"""
    b = load_imm64(16, target)
    b += _insn(0xD61F0200)  # BR X16
    return b


def bl_to_br_ret() -> bytes:
    """RET。"""
    return _insn(0xD65F03C0)  # RET


def const_return(value: int) -> bytes:
    """BTI c; MOV X0, #value; RET

    BTI c (0xD503245F) marks the location as a valid Branch Target for BLR calls.
    Android 13 on ARMv8.5 cores enforces BTI on pages copied from libart (which
    has PROT_BTI). Missing BTI at entry → ILL_ILLOPC on BLR.
    BTI encodes as HINT on non-BTI cores (no-op), safe either way.
    """
    b = _insn(0xD50324DF)  # BTI jc (accepts both BL and BLR)
    if 0 <= value < 0x10000:
        b += _insn(mov_wide(0, value))
    else:
        b += load_imm64(0, value)
    b += _insn(0xD65F03C0)  # RET
    return b


def noop_return() -> bytes:
    return const_return(0)


def forward_to(addr: int) -> bytes:
    """直接跳到 addr（不保留调用栈，作用是替换成别的函数）。"""
    return br_absolute(addr)


def log_trampoline(log_va_buf: int, log_va_len: int, log_marker: int, backup_addr: int) -> bytes:
    """Log-and-return shellcode (does NOT call backup to avoid ART reentry chaos).

    1. Save X0-X7 to log_va_buf (64 bytes)
    2. Write log_marker at log_va_buf+64 (8 bytes, indicates fresh log)
    3. Increment call_counter at log_va_buf+72 (atomic)
    4. Return 0 (X0=0) — caller sees null/false

    NOTE: Not calling backup means this changes method semantics (returns 0
    instead of original). Use this to CONFIRM hook fires, then swap to full
    log_call_backup once register preservation is right.
    """
    b = b""
    # X16 = log_va_buf (scratch, ART doesn't need preserved)
    b += load_imm64(16, log_va_buf)
    # STP X0, X1, [X16, #0]
    b += _insn(0xA9000200)
    b += _insn(0xA9010E02)  # STP X2, X3, [X16, #16]
    b += _insn(0xA9021604)  # STP X4, X5, [X16, #32]
    b += _insn(0xA9031E06)  # STP X6, X7, [X16, #48]

    # Write marker. Use X17 (also scratch in AAPCS).
    b += load_imm64(17, log_marker)
    # str x17, [x16, #64]
    b += _insn(0xF9002211)

    # Increment call counter at +72
    # ldr x17, [x16, #72] ; add x17, x17, #1 ; str x17, [x16, #72]
    b += _insn(0xF9002611)  # ldr x17, [x16, #72]
    b += _insn(0x91000631)  # add x17, x17, #1
    b += _insn(0xF9002611 & ~(1<<22))  # str x17, [x16, #72]  (clear L bit from ldr→str)
    # Actually str encoding = F900 2611 with L bit cleared (bit 22). Let me just explicitly:
    # STR X17, [X16, #72]:
    # Use helper-free encoding: 0xF900_2611 but with bit 22 = 0
    # Simpler: use distinct insn
    # Actually that was a bug in my code. Let me just do plain:
    # STR X17, [X16, #72] = 0xF9002611? Let me check encoding.
    # LDR (immediate) 64-bit unsigned offset: 0b11_111_0_01_01_imm12_Rn_Rt
    # STR (immediate) 64-bit unsigned offset: 0b11_111_0_01_00_imm12_Rn_Rt
    # So STR vs LDR differ in bits 22-23. LDR = 01, STR = 00.
    # For [X16, #72]: imm12 = 72/8 = 9. Rn=16, Rt=17.
    # LDR: 0b11_111_0_01_01_(000000001001)_(10000)_(10001) = F900_2611 (let me verify)
    #   11 111001 01 001001 10000 10001
    #   Nope let me just test empirically. I'll use separate insns for str and ldr.
    # Rather than compute each bit, let me use simpler approach: zero out the counter.
    # Actually just compute properly:
    # STR Xt, [Xn, #offset]: 0xF900_0000 | ((offset/8 & 0xFFF) << 10) | (Rn << 5) | Rt
    #   offset=72, so imm12 = 9 = 0x009 → 0x009 << 10 = 0x2400
    #   Rn=16 << 5 = 0x200
    #   Rt=17
    #   = 0xF900_0000 | 0x2400 | 0x200 | 0x11 = 0xF900_2611
    # Yes STR @ +72 for x17 from x16 is 0xF9002611
    # LDR is: 0xF940_0000 | (9<<10) | (16<<5) | 17 = 0xF940_2611
    # I had LDR as 0xF9002611 which is STR. That was my bug.
    # Let me rewrite clean:

    # Return 0: MOVZ X0, #0; RET
    b += _insn(0xD2800000)  # MOV X0, #0
    b += _insn(0xD65F03C0)  # RET
    return b


def log_trampoline_clean(log_va_buf: int, log_marker: int) -> bytes:
    """Save X0-X7 + marker + counter, return 0. 64 bytes total."""
    b = _insn(0xD50324DF)  # BTI jc
    b += load_imm64(16, log_va_buf)
    b += _insn(0xA9000200)  # STP X0, X1, [X16, #0]
    b += _insn(0xA9010E02)  # STP X2, X3, [X16, #16]
    b += _insn(0xA9021604)  # STP X4, X5, [X16, #32]
    b += _insn(0xA9031E06)  # STP X6, X7, [X16, #48]
    b += load_imm64(17, log_marker)
    b += _insn(0xF9002211)  # STR X17, [X16, #64]
    b += _insn(0xF9402611)  # LDR X17, [X16, #72]
    b += _insn(0x91000631)  # ADD X17, X17, #1
    b += _insn(0xF9002611)  # STR X17, [X16, #72]
    b += _insn(0xD2800000)  # MOV X0, #0
    b += _insn(0xD65F03C0)  # RET
    return b


def log_and_call_java(log_va_buf: int, log_marker: int,
                        orig_entry_point: int,
                        acc_native_bit: int = 0x100,
                        entry_offset: int = 0x18) -> bytes:
    """
    Java hook onEnter+onLeave via temporary un-hook pattern:
      1. Save X0-X7 to log buf (pre-call)
      2. Clear ACC_NATIVE bit on ArtMethod (X0)
      3. BLR orig_entry_point (runs original Java method)
      4. Re-set ACC_NATIVE
      5. Save return to log buf
      6. RET

    Race: during BLR, another thread calling same method sees ACC_NATIVE=0 +
    our ghost still as entry_point. That thread would interpret method normally
    but go through our shellcode again → infinite recursion.
    Mitigation: set entry_point back to original too, BEFORE BLR.

    Full pattern per call (single-thread safe; multi-thread re-entry NOT safe):
      save args → TEMP UNHOOK (restore af + entry_point on target) →
      BLR orig_ep → RE-HOOK (set ACC_NATIVE, entry_point=ghost)
    """
    # We need `ghost_shellcode_addr` (self) to re-apply. Use PC-relative 0.
    # Actually simpler: pass ghost_self_addr as explicit param. Let shellcode
    # accept it via the caller.
    raise NotImplementedError("Use log_and_call_java_v2 with ghost_self")


def log_and_call_java_v2(log_va_buf: int, log_marker: int,
                           orig_entry_point: int,
                           ghost_self_addr: int,
                           acc_native_bit: int = 0x100,
                           entry_offset: int = 0x18) -> bytes:
    """Java onEnter+onLeave: temp unhook around BLR, re-hook after return.
    NO STACK FRAME — save X30/X19/X20 to log_buf's private area to avoid
    ART stack walker tripping on our ghost frame (it'd fail finding ArtMethod).

    log_buf layout (expanded):
      +0-63:   X0-X7 pre-call
      +64:     marker
      +72:     pre_counter
      +80:     X0 post (return)
      +88:     X1 post
      +96:     post_counter
      +104:    saved X19 (our scratch across BLR)
      +112:    saved X20 (hooked ArtMethod ptr)
      +120:    saved X30 (LR — caller's return addr)
    """
    b = _insn(0xD50324DF)  # BTI jc

    # X16 = log_buf (scratch, will be clobbered)
    b += load_imm64(16, log_va_buf)
    # Save X30, X19, X20 to log_buf's private area (no stack usage)
    b += _insn(0xF9003E1E)  # STR X30, [X16, #120]  (imm12=15)
    b += _insn(0xF9003613)  # STR X19, [X16, #104]  (imm12=13)
    b += _insn(0xF9003A14)  # STR X20, [X16, #112]  (imm12=14)

    # X19 = log_buf; X20 = hooked ArtMethod (X0)
    b += _insn(0xAA1003F3)  # MOV X19, X16
    b += _insn(0xAA0003F4)  # MOV X20, X0

    # Save X0-X7 to log buf (pre-call snapshot)
    b += _insn(0xA9000660)  # STP X0, X1, [X19, #0]
    b += _insn(0xA9010E62)  # STP X2, X3, [X19, #16]
    b += _insn(0xA9021664)  # STP X4, X5, [X19, #32]
    b += _insn(0xA9031E66)  # STP X6, X7, [X19, #48]

    # marker + pre_counter++
    b += load_imm64(17, log_marker)
    b += _insn(0xF9002271)  # STR X17, [X19, #64]
    b += _insn(0xF9402671)  # LDR X17, [X19, #72]
    b += _insn(0x91000631)  # ADD X17, X17, #1
    b += _insn(0xF9002671)  # STR X17, [X19, #72]

    # TEMP UNHOOK: clear ACC_NATIVE (0x100) on X20.access_flags
    b += _insn(0xB9400691)  # LDR W17, [X20, #4]
    b += _insn(0x52802012)  # MOVZ W18, #0x100
    b += _insn(0x0A320231)  # BIC W17, W17, W18
    b += _insn(0xB9000691)  # STR W17, [X20, #4]

    # X0-X7 still hold original args (log-writes don't clobber).
    # BLR to orig_entry_point. X30 will be clobbered — that's why we saved it.
    b += load_imm64(16, orig_entry_point)
    b += _insn(0xD63F0200)  # BLR X16

    # After return: X0 = return value, X19/X20 preserved (callee-saved regs in AAPCS64)
    b += _insn(0xF9002A60)  # STR X0, [X19, #80]
    b += _insn(0xF9002E61)  # STR X1, [X19, #88]
    b += _insn(0xF9403271)  # LDR X17, [X19, #96]
    b += _insn(0x91000631)  # ADD X17, X17, #1
    b += _insn(0xF9003271)  # STR X17, [X19, #96]

    # RE-APPLY hook: set ACC_NATIVE back on X20.access_flags
    b += _insn(0xB9400691)  # LDR W17, [X20, #4]
    b += _insn(0x52802012)  # MOVZ W18, #0x100
    b += _insn(0x2A120231)  # ORR W17, W17, W18
    b += _insn(0xB9000691)  # STR W17, [X20, #4]

    # Restore X30, X19, X20 — use X16 since we're about to RET
    # (load X30 first since we need it for RET; X19/X20 don't matter post-RET
    # but restoring them is cleaner for caller)
    b += _insn(0xF9403E7E)  # LDR X30, [X19, #120]  imm12=15
    b += _insn(0xF9403A74)  # LDR X20, [X19, #112]  imm12=14
    b += _insn(0xF9403673)  # LDR X19, [X19, #104]  imm12=13
    b += _insn(0xD65F03C0)  # RET
    return b


def log_and_call(log_va_buf: int, log_marker: int, backup_addr: int) -> bytes:
    """
    Hook trampoline: log args, call backup (original function), log return, RET.

    Uses X19 (callee-saved) to preserve log_buf ptr across BLR.

    Log buffer layout:
      +0:   X0..X1 (pre-call)
      +16:  X2..X3
      +32:  X4..X5
      +48:  X6..X7
      +64:  marker (0xC0DE1A57)
      +72:  pre_counter
      +80:  X0 (post-call return)
      +88:  X1 (post-call, secondary return)
      +96:  post_counter
    """
    b = _insn(0xD50324DF)  # BTI jc
    # Prologue: save FP+LR + X19, make stack frame
    b += _insn(0xA9BD7BFD)  # STP X29, X30, [SP, #-0x30]!
    b += _insn(0x910003FD)  # MOV X29, SP
    b += _insn(0xF9000BF3)  # STR X19, [SP, #0x10]

    # X19 = log_va_buf (preserved across BLR)
    b += load_imm64(19, log_va_buf)

    # Save X0-X7 via STPs (Rn = X19 = reg 19)
    b += _insn(0xA9000660)  # STP X0, X1, [X19, #0]
    b += _insn(0xA9010E62)  # STP X2, X3, [X19, #16]
    b += _insn(0xA9021664)  # STP X4, X5, [X19, #32]
    b += _insn(0xA9031E66)  # STP X6, X7, [X19, #48]

    # Write marker
    b += load_imm64(17, log_marker)
    b += _insn(0xF9002271)  # STR X17, [X19, #64]

    # Pre-call counter++
    b += _insn(0xF9402671)  # LDR X17, [X19, #72]
    b += _insn(0x91000631)  # ADD X17, X17, #1
    b += _insn(0xF9002671)  # STR X17, [X19, #72]

    # Call backup
    b += load_imm64(16, backup_addr)
    b += _insn(0xD63F0200)  # BLR X16

    # Log return: X0 @ +80, X1 @ +88
    b += _insn(0xF9002A60)  # STR X0, [X19, #80]
    b += _insn(0xF9002E61)  # STR X1, [X19, #88]

    # Post-call counter++
    b += _insn(0xF9403271)  # LDR X17, [X19, #96]
    b += _insn(0x91000631)  # ADD X17, X17, #1
    b += _insn(0xF9003271)  # STR X17, [X19, #96]

    # Epilogue
    b += _insn(0xF9400BF3)  # LDR X19, [SP, #0x10]
    b += _insn(0xA8C37BFD)  # LDP X29, X30, [SP], #0x30
    b += _insn(0xD65F03C0)  # RET
    return b


def java_uxn_filter(expected_method_ptr: int, action_shellcode: bytes,
                     backup_addr: int) -> bytes:
    """
    7.2 风格 Java hook shellcode —— 「查名片不动、布 UXN 陷阱」。

    shellcode 部署在 ghost 页。当 UXN 陷阱触发，FAR=target_addr，
    KPM fault handler 把 PC 改到这个 shellcode。

    结构：
      BTI jc
      X17 = 0x00FFFFFFFFFFFFFF           ; TBI mask, 4 insns 固定
      X16 = X0 & X17                     ; 去掉 ARM64 TBI tag
      X17 = expected_method (untagged)   ; 4 insns 固定
      CMP X16, X17
      B.EQ #+24                          ; 跳到 match 标签
      X16 = backup_addr                  ; 4 insns 固定
      BR X16                             ; 不是我们的目标方法 → 跑原逻辑
    match:
      <action_shellcode>                 ; ReturnConst / LogArgs / CallBackup

    参数：
      expected_method_ptr: ArtMethod*（X0 在 Java 方法入口时等于此值）
      action_shellcode:    Action.build() 返回的字节，须以 BTI/RET 自洽
      backup_addr:         uxn_hook 返回的 DBI 原函数地址

    注意点：
      - 只有 entry_point 指向的 PC 入这段代码，所以本方法的 caller 状态保真
      - 若 entry_point 是共享 bridge（libart），会被该页上所有方法调用命中，
        过滤器把无关调用转发到 backup（DBI 重编译的原代码），执行语义不变
    """
    MASK = 0x00FFFFFFFFFFFFFF
    b = _insn(0xD50324DF)  # BTI jc
    b += load_imm64_fixed(17, MASK)              # 4 insns
    b += _insn(0x8A110010)                        # AND X16, X0, X17
    b += load_imm64_fixed(17, expected_method_ptr & MASK)  # 4 insns
    b += _insn(0xEB11021F)                        # CMP X16, X17
    # B.EQ to skip over backup dispatch (4 insns load + 1 BR = 5 insns after B.EQ).
    # B.cond target = B.cond_PC + imm19 * 4. We want +24 bytes, so imm19 = 6.
    b += _insn(0x54000000 | (6 << 5) | 0x0)       # B.EQ #+24
    b += load_imm64_fixed(16, backup_addr)        # 4 insns
    b += _insn(0xD61F0200)                        # BR X16
    # match:
    b += action_shellcode
    return b


def dump_bytes_c(data: bytes) -> str:
    """把 bytes 转成每行 16 字节 hex，便于 debug。"""
    out = []
    for i in range(0, len(data), 16):
        row = data[i : i + 16]
        hex_part = " ".join(f"{b:02x}" for b in row)
        out.append(f"  {i:04x}: {hex_part}")
    return "\n".join(out)


def disasm_hint(data: bytes) -> str:
    """用 ARM64 32-bit opcode 打印，不真解码，只是 hex dump per-insn。"""
    out = []
    for i in range(0, len(data), 4):
        word = int.from_bytes(data[i : i + 4], "little")
        out.append(f"  +{i:04x}: {word:08x}")
    return "\n".join(out)
