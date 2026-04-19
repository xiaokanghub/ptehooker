"""
art_offsets.py — ART 结构偏移。**按 Android API level 分版本表**。

核心表是 ArtMethod layout，跨版本有变化：
  API 30 (Android 11) / API 31 (Android 12): size=0x28, 带 dex_code_item_offset
  API 33 (Android 13) / API 34 (Android 14):  size=0x20, 去掉 dex_code_item_offset

Runtime / ClassLinker / DexCache 偏移是反汇编 libart.so 拿的，device-specific，
本文件的值来自 Xiaomi M2102K1AC (Android 13) 的 libart。切设备要重新提取。

Usage:
    import art_offsets as AO
    off = AO.get_offsets()   # auto-detect via `getprop ro.build.version.sdk`
    ep_offset = off["ARTMETHOD_ENTRY_QUICK"]
"""
import os
import subprocess

# ---- Per-API offset tables --------------------------------------------------

# Android 13 / 14 (API 33 / 34) — ART_VERSION 14 source confirmed same layout.
# ArtMethod empirically verified on Xiaomi M2102K1AC (A13).
_A13 = dict(
    ARTMETHOD_SIZE             = 0x20,
    ARTMETHOD_DECLARING_CLASS  = 0x00,   # GcRoot<Class>, compressed 4 bytes
    ARTMETHOD_ACCESS_FLAGS     = 0x04,   # std::atomic<uint32_t>
    ARTMETHOD_DEX_METHOD_INDEX = 0x08,   # uint32_t
    ARTMETHOD_METHOD_INDEX     = 0x0C,   # uint16_t + imt_index_ uint16_t
    ARTMETHOD_DATA             = 0x10,   # void* (ptr-sized)
    ARTMETHOD_ENTRY_QUICK      = 0x18,   # void* entry_point_from_quick_compiled_code_
)

# Android 11 / 12 (API 30 / 31) — pre-Nterp era, kept dex_code_item_offset
_A12 = dict(
    ARTMETHOD_SIZE             = 0x28,
    ARTMETHOD_DECLARING_CLASS  = 0x00,
    ARTMETHOD_ACCESS_FLAGS     = 0x04,
    ARTMETHOD_DEX_CODE_ITEM_OFFSET = 0x08,
    ARTMETHOD_DEX_METHOD_INDEX = 0x0C,
    ARTMETHOD_METHOD_INDEX     = 0x10,
    ARTMETHOD_DATA             = 0x18,
    ARTMETHOD_ENTRY_QUICK      = 0x20,
)

# Android 15 (API 35) — assuming same layout as 13/14 until verified.
# When a 15 device is tested, duplicate entry or override.
_A15 = dict(_A13)

_OFFSETS_BY_API = {
    30: _A12,   # Android 11
    31: _A12,   # Android 12
    32: _A12,   # Android 12L
    33: _A13,   # Android 13
    34: _A13,   # Android 14
    35: _A15,   # Android 15 (unverified, assume A13 layout)
}

# ---- Runtime / ClassLinker / DexCache (Android 13 specific, device-specific) -
# These came from reverse-engineering libart.so on the test device. When you
# switch devices or Android versions, re-extract via art_introspect.py.
#
# Runtime
RUNTIME_INSTANCE_ELF_VA = 0xA15D48   # art::Runtime::instance_ symbol offset
RUNTIME_CLASS_LINKER = 0x250          # Runtime::class_linker_

# ClassLinker
CL_DEX_CACHES = 0x38
CL_DEX_CACHES_BUCKET_PTR = 0x38
CL_DEX_CACHES_BUCKET_COUNT = 0x40
CL_DEX_CACHES_FIRST_NODE = 0x48
CL_DEX_CACHES_SIZE = 0x50
CL_CLASS_LOADERS_HEAD = 0x60

# hash_node
NODE_NEXT = 0x00
NODE_HASH = 0x08
NODE_KEY = 0x10
NODE_VALUE = 0x18

DCD_WEAK_DEX_CACHE = 0x00
DCD_REGISTRATION_INDEX = 0x08
DCD_CLASS_TABLE_INDEX = 0x0C

DEXFILE_BEGIN = 0x08
DEXFILE_SIZE = 0x10
DEXFILE_LOCATION_OFFSET = 0x28

CLASS_METHODS = 0x90  # tentative

# Access flag bits (stable across versions)
ACC_NATIVE = 0x100
ACC_STATIC = 0x008
ACC_ABSTRACT = 0x400
ACC_COMPILE_DONT_BOTHER = 0x10000000


# ---- Detection -------------------------------------------------------------

_CACHED_API = None
_CACHED_SERIAL = None


def detect_api_level(serial: str = None) -> int:
    """Read Android API level from device via `getprop ro.build.version.sdk`.
    Cached per-serial."""
    global _CACHED_API, _CACHED_SERIAL
    if serial is None:
        serial = os.environ.get("ADB_SERIAL", "")
    if _CACHED_API is not None and _CACHED_SERIAL == serial:
        return _CACHED_API

    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += ["shell", "getprop", "ro.build.version.sdk"]
    try:
        out = subprocess.check_output(cmd, text=True, timeout=5).strip()
        _CACHED_API = int(out)
        _CACHED_SERIAL = serial
    except Exception as e:
        print(f"[!] detect_api_level 失败: {e} — 默认 33 (Android 13)")
        _CACHED_API = 33
        _CACHED_SERIAL = serial
    return _CACHED_API


def get_offsets(api: int = None) -> dict:
    """返回指定 API level 的 ArtMethod 偏移 dict。
    默认从设备 auto-detect。未知版本时 fallback 到最近的已知版本。"""
    if api is None:
        api = detect_api_level()
    if api in _OFFSETS_BY_API:
        return _OFFSETS_BY_API[api]
    # Pick closest known API <= given
    below = [k for k in _OFFSETS_BY_API if k <= api]
    if below:
        closest = max(below)
    else:
        closest = min(_OFFSETS_BY_API)
    print(f"[!] API {api} 偏移未定义，fallback 到 API {closest}")
    return _OFFSETS_BY_API[closest]


# ---- Back-compat: module-level constants resolve at import time to A13 -----
# Existing code can keep using `ARTMETHOD_ENTRY_QUICK` directly; new code
# should call `get_offsets()` for proper per-device detection.

_DEFAULT = _A13
for _k, _v in _DEFAULT.items():
    globals()[_k] = _v


def untag(ptr: int) -> int:
    """Strip ARM64 TBI top byte."""
    return ptr & 0x00FFFFFFFFFFFFFF
