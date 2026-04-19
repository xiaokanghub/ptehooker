"""
sym_resolver.py - 解析本地 .so 的 symtab/dynsym，按名字找函数 ELF VA。
"""
import subprocess
import os


NDK = os.environ.get(
    "NDK", "$NDK_HOME"
)
LLVM_NM = f"{NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-nm"


def resolve_symbol(so_path: str, name: str) -> int:
    """在 .so 的 (dyn)symtab 查 name，返回 ELF VA。找不到抛 KeyError。
    自动 strip bionic 版本后缀 '@@LIBC' 等。"""
    for flags in ["-D", ""]:
        try:
            out = subprocess.check_output(
                [LLVM_NM, flags, so_path] if flags else [LLVM_NM, so_path],
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except Exception:
            continue
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            addr, typ, sym = parts[0], parts[1], " ".join(parts[2:])
            # Strip bionic version suffix: foo@@LIBC → foo
            bare = sym.split("@", 1)[0]
            # T/t = text, W/w = weak, i/I = ifunc (indirect, e.g. bionic strlen)
            if (sym == name or bare == name) and typ in ("T", "t", "W", "w", "i", "I"):
                try:
                    return int(addr, 16)
                except ValueError:
                    continue
    raise KeyError(f"symbol {name} not found in {so_path}")


def list_symbols(so_path: str, pattern: str = None) -> list:
    """列出匹配 pattern 的导出函数符号。pattern 是子串匹配。"""
    result = []
    for flags in ["-D", ""]:
        try:
            out = subprocess.check_output(
                [LLVM_NM, flags, so_path] if flags else [LLVM_NM, so_path],
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except Exception:
            continue
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            addr, typ, sym = parts[0], parts[1], " ".join(parts[2:])
            if typ not in ("T", "t", "W", "w"):
                continue
            if pattern and pattern not in sym:
                continue
            try:
                result.append((int(addr, 16), sym))
            except ValueError:
                continue
    # 去重
    seen = set()
    uniq = []
    for a, s in result:
        if (a, s) in seen:
            continue
        seen.add((a, s))
        uniq.append((a, s))
    return uniq


def elf_va_to_mem(linker_base: int, elf_va: int) -> int:
    """ELF VA → 进程内存地址。"""
    return linker_base + elf_va
