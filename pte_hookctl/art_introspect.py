"""
art_introspect.py - ART internal walker via proc-read.

Entry point: find_art_method(pid, class_descriptor, method_name, method_signature)
  Returns: the ArtMethod* address in target process, or raises RuntimeError.

Pipeline:
  1. Find libart linker_base via /proc/maps
  2. Read Runtime::instance_ @ libart_base + 0xa15d48
  3. Deref → Runtime*
  4. Read Runtime::class_linker_ @ Runtime+0x250 → ClassLinker*
  5. Walk ClassLinker::dex_caches_ hashmap (first_node linked list at CL+0x48)
  6. For each node, get DexFile* (key) + DexCacheData (value)
  7. Read DexFile to get location string; match target DEX
  8. Parse DEX to find class_idx + method_idx
  9. Read mirror::DexCache via DexCacheData.weak_dex_cache
  10. Read DexCache.resolved_methods_[method_idx] → ArtMethod*
"""
import sys
import os
import struct

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import kpm_client as K
import art_offsets as AO


def read_u64(pid, addr):
    return K.proc_read_u64(pid, addr)


def read_ptr(pid, addr):
    """Read u64 and strip ARM64 TBI tag."""
    return AO.untag(K.proc_read_u64(pid, addr))


def get_libart_base(pid):
    """Return linker base of libart.so in target process."""
    segs = K.find_lib(pid, "libart.so")
    if not segs:
        raise RuntimeError(f"libart.so not mapped in pid {pid}")
    # The linker base is the start of the very first segment minus its file_off (usually 0).
    # Verify by picking the /apex/com.android.art/lib64/libart.so specifically.
    art_segs = [s for s in segs if "/apex/com.android.art" in s[4]]
    if not art_segs:
        art_segs = segs
    art_segs.sort()
    first = art_segs[0]
    return first[0] - first[3]


def get_runtime(pid):
    base = get_libart_base(pid)
    instance_addr = base + AO.RUNTIME_INSTANCE_ELF_VA
    rt = read_ptr(pid, instance_addr)
    if rt == 0:
        raise RuntimeError(f"Runtime::instance_ is NULL at 0x{instance_addr:x}")
    return rt, base


def get_classlinker(pid, runtime):
    cl = read_ptr(pid, runtime + AO.RUNTIME_CLASS_LINKER)
    if cl == 0:
        raise RuntimeError("ClassLinker is NULL")
    return cl


def walk_dex_caches(pid, cl):
    """Iterate all (DexFile*, DexCacheData*) entries in ClassLinker::dex_caches_.
    Yields (dex_file_ptr, dex_cache_data_addr) tuples."""
    first_node = read_ptr(pid, cl + AO.CL_DEX_CACHES_FIRST_NODE)
    size = read_u64(pid, cl + AO.CL_DEX_CACHES_SIZE)
    print(f"  dex_caches size={size} first_node=0x{first_node:x}")

    node = first_node
    count = 0
    while node != 0 and count < size + 10:
        dex_file = read_ptr(pid, node + AO.NODE_KEY)
        # DexCacheData is the value, stored inline starting at node+0x18
        data_addr = node + AO.NODE_VALUE
        yield dex_file, data_addr
        next_node = read_ptr(pid, node + AO.NODE_NEXT)
        if next_node == node:
            break
        node = next_node
        count += 1


def read_cstr(pid, addr, maxlen=256):
    """Read a NUL-terminated C string from target mem."""
    # Read chunks until NUL found
    buf = b""
    while len(buf) < maxlen:
        chunk = K.proc_read(pid, addr + len(buf), min(64, maxlen - len(buf)))
        nul = chunk.find(b"\0")
        if nul >= 0:
            buf += chunk[:nul]
            return buf
        buf += chunk
    return buf


def read_libcxx_string(pid, str_addr):
    """Read a libc++ std::string. Returns the string bytes."""
    # libc++ string is 24 bytes:
    #   short: byte[0] LSB=0, len in byte[0]>>1, data at byte[1..22]
    #   long:  byte[0] LSB=1, size@+8, capacity@..., data_ptr@+16
    raw = K.proc_read(pid, str_addr, 24)
    first_byte = raw[0]
    if first_byte & 1:
        # Long string: data_ptr at +16
        data_ptr = int.from_bytes(raw[16:24], "little")
        size = int.from_bytes(raw[8:16], "little") & ~(1 << 63)  # top bit might be flag
        if size > 4096:
            size = 4096  # sanity cap
        if data_ptr == 0:
            return b""
        return K.proc_read(pid, AO.untag(data_ptr), size)
    else:
        # Short string: len in byte[0] >> 1
        size = first_byte >> 1
        return raw[1:1 + size]


def read_dexfile_location(pid, dex_file_ptr):
    """DexFile::location_ is a std::string at offset 0x28."""
    return read_libcxx_string(pid, dex_file_ptr + AO.DEXFILE_LOCATION_OFFSET)


def read_dexfile_begin_size(pid, dex_file_ptr):
    """Read DexFile::begin_ and size_."""
    begin = read_ptr(pid, dex_file_ptr + AO.DEXFILE_BEGIN)
    size = read_u64(pid, dex_file_ptr + AO.DEXFILE_SIZE)
    return begin, size


def dump_dex_caches(pid):
    """List all DexFiles in target process. For debugging."""
    rt, libart_base = get_runtime(pid)
    cl = get_classlinker(pid, rt)
    print(f"PID={pid}")
    print(f"libart_base=0x{libart_base:x}")
    print(f"Runtime=0x{rt:x}")
    print(f"ClassLinker=0x{cl:x}")

    for i, (dex_file, data_addr) in enumerate(walk_dex_caches(pid, cl)):
        try:
            loc = read_dexfile_location(pid, dex_file)
            loc_str = loc.decode("utf-8", errors="replace")
        except Exception as e:
            loc_str = f"<error: {e}>"
        try:
            begin, size = read_dexfile_begin_size(pid, dex_file)
        except Exception:
            begin, size = 0, 0
        print(f"[{i}] DexFile*=0x{dex_file:x}  data@0x{data_addr:x}")
        print(f"     location={loc_str}")
        print(f"     begin=0x{begin:x} size={size}")
        if i >= 20:
            print(f"  ... more ...")
            break


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["dump-dex-caches", "walk"])
    ap.add_argument("--pid")
    ap.add_argument("--pkg")
    args = ap.parse_args()

    pid = int(args.pid) if args.pid else K.get_pid(args.pkg)

    if args.cmd == "dump-dex-caches":
        dump_dex_caches(pid)
    elif args.cmd == "walk":
        dump_dex_caches(pid)
