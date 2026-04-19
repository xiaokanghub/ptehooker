#!/usr/bin/env python3
"""
pte_hookctl - 通用 Java/Native hook CLI for ptehook_planc_v2 KPM.

用法：
  pte_hookctl status

  pte_hookctl find-sym --pkg com.xxx --lib libxxx.so --pattern foo
  pte_hookctl native-hook --pkg com.xxx --lib libxxx.so --sym funcName --replace log

  pte_hookctl find-method --apk /path/to.apk --class "Lcom/xxx/Yyy;" --method foo --sig "(I)I"
  pte_hookctl java-hook --pkg com.xxx --apk /path/to.apk \
      --class "Lcom/xxx/Yyy;" --method foo --sig "(I)I" --replace log

Replace specs:
  noop          - MOV X0, #0; RET
  const:<value> - MOV X0, #value; RET (const return)
  log           - save X0-X7 to ghost+0x1000, then JMP to original backup
  forward:0xADDR - forward to an absolute address
"""
import argparse
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import kpm_client as K
import sym_resolver as S
import shellcode as SC
import dex_parser as DP
import subprocess


LIB_CACHE = "/tmp/pte_hookctl_libs"


def ensure_local_so(device_path: str) -> str:
    os.makedirs(LIB_CACHE, exist_ok=True)
    local = os.path.join(LIB_CACHE, os.path.basename(device_path))
    if not os.path.exists(local):
        tmp = "/data/local/tmp/_so_probe_" + os.path.basename(device_path)
        subprocess.check_call(
            ["adb", "-s", K.ADB_SERIAL, "shell", f"su -c 'cp {device_path} {tmp} && chmod 644 {tmp}'"]
        )
        subprocess.check_call(
            ["adb", "-s", K.ADB_SERIAL, "pull", tmp, local],
            stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        )
    return local


def find_lib_segments(pid, lib_name):
    segs = K.find_lib(pid, lib_name)
    if not segs:
        raise SystemExit(f"lib {lib_name} not mapped in pid {pid}")
    first = segs[0]
    return first[0] - first[3], first[4]


def resolve_pid(args):
    if getattr(args, "pid", None):
        return int(args.pid)
    if getattr(args, "pkg", None):
        return K.get_pid(args.pkg)
    raise SystemExit("need --pid or --pkg")


def install_replace(pid, target_addr, replace_spec, entry_offset=0x18, is_native=False):
    """Install hook: build shellcode per replace_spec, write to ghost, hook target.

    For native hook: UXN hook target → ghost.
    For Java hook: java-hook patches ArtMethod entry_point → ghost.

    Returns dict with ghost_addr, backup_addr (if native), etc.
    """
    # Find a `near` that is reliably mapped: libart.so r-xp base (always executable, demand-paged).
    maps = K.read_maps(pid)
    libart_rx = [(s, e) for s, e, p, _, path in maps
                 if "libart.so" in path and "r-xp" in p]
    if not libart_rx:
        raise RuntimeError("libart.so r-xp not found")
    near = libart_rx[0][0]
    print(f"  ghost-alloc near libart r-xp 0x{near:x}...")
    try:
        ghost = K.ghost_alloc(pid, near, 0x1000, exact=False)
        print(f"  ghost @ 0x{ghost:x}")
    except RuntimeError as e1:
        print(f"  near-libart failed: {e1}")
        gap = K.find_large_gap(pid, min_size=0x4000)
        print(f"  trying exact gap 0x{gap:x}")
        ghost = K.ghost_alloc(pid, gap, 0x2000, exact=True)
        print(f"  ghost @ 0x{ghost:x}")

    if replace_spec == "noop":
        code = SC.noop_return()
        K.ghost_write(pid, ghost, 0, code)
        if is_native:
            backup = K.uxn_hook(pid, target_addr, ghost)
            return dict(ghost=ghost, backup=backup, kind="uxn_noop")
        else:
            K.java_hook(pid, target_addr, entry_offset, ghost)
            return dict(ghost=ghost, kind="java_noop")

    elif replace_spec.startswith("const:"):
        val = int(replace_spec.split(":", 1)[1], 0)
        code = SC.const_return(val)
        print(f"  const shellcode {len(code)} bytes: {code.hex()}")
        K.ghost_write(pid, ghost, 0, code)
        print(f"  ghost-written {len(code)} bytes at 0x{ghost:x}")
        if is_native:
            backup = K.uxn_hook(pid, target_addr, ghost)
            return dict(ghost=ghost, backup=backup, kind="uxn_const")
        else:
            # For Java hook: set ACC_NATIVE (0x100) in access_flags so ART
            # treats it as native and uses entry_point directly (skipping
            # interpreter). Without this, fresh (non-JIT'd) methods are
            # interpreted and entry_point is ignored.
            ACC_NATIVE = 0x100
            af_addr = target_addr + 4
            orig_af = K.proc_read_u32(pid, af_addr)
            new_af = orig_af | ACC_NATIVE
            print(f"  access_flags {orig_af:#x} → {new_af:#x} (set ACC_NATIVE)")
            K.proc_patch(pid, af_addr, new_af.to_bytes(4, "little"))
            K.java_hook(pid, target_addr, entry_offset, ghost)
            return dict(ghost=ghost, kind="java_const")

    elif replace_spec == "log":
        # Simple log mode: save X0-X7, set marker, increment counter, return 0.
        # Does NOT call original — hook overrides method semantics.
        # Log buffer at offset 0x800 inside ghost (1 page shared for code+buf)
        log_buf = ghost + 0x800
        code = SC.log_trampoline_clean(log_va_buf=log_buf, log_marker=0xC0DE1A57)
        print(f"  log shellcode {len(code)} bytes: {code.hex()}")
        K.ghost_write(pid, ghost, 0, code)
        print(f"  ghost-written {len(code)} bytes at 0x{ghost:x}")
        if is_native:
            backup = K.uxn_hook(pid, target_addr, ghost)
            print(f"  backup: 0x{backup:x}")
            return dict(ghost=ghost, backup=backup, log_buf=log_buf, kind="log")
        else:
            # For Java hook: also set ACC_NATIVE for stable dispatch
            ACC_NATIVE = 0x100
            af_addr = target_addr + 4
            orig_af = K.proc_read_u32(pid, af_addr)
            new_af = orig_af | ACC_NATIVE
            print(f"  access_flags {orig_af:#x} → {new_af:#x} (set ACC_NATIVE)")
            K.proc_patch(pid, af_addr, new_af.to_bytes(4, "little"))
            K.java_hook(pid, target_addr, entry_offset, ghost)
            return dict(ghost=ghost, log_buf=log_buf, kind="log")

    elif replace_spec.startswith("forward:"):
        addr = int(replace_spec.split(":", 1)[1], 0)
        code = SC.forward_to(addr)
        K.ghost_write(pid, ghost, 0, code)
        if is_native:
            backup = K.uxn_hook(pid, target_addr, ghost)
            return dict(ghost=ghost, backup=backup, kind="uxn_forward")
        else:
            K.java_hook(pid, target_addr, entry_offset, ghost)
            return dict(ghost=ghost, kind="java_forward")

    else:
        raise SystemExit(f"unknown --replace spec: {replace_spec}")


def cmd_status(args):
    print(K.stat())


def cmd_find_sym(args):
    pid = resolve_pid(args)
    linker_base, dev_path = find_lib_segments(pid, args.lib)
    local_so = ensure_local_so(dev_path)
    print(f"pid={pid} lib={dev_path} linker_base=0x{linker_base:x}")
    syms = S.list_symbols(local_so, args.pattern)
    for va, sym in syms[:30]:
        print(f"  0x{va:08x} -> 0x{linker_base + va:x}  {sym}")


def cmd_find_method(args):
    res = DP.find_method_in_apk(args.apk, args.cls, args.method, args.sig)
    if not res:
        raise SystemExit("NOT FOUND")
    print(json.dumps(res, indent=2))


def cmd_native_hook(args):
    pid = resolve_pid(args)
    linker_base, dev_path = find_lib_segments(pid, args.lib)
    local_so = ensure_local_so(dev_path)
    if args.sym:
        va = S.resolve_symbol(local_so, args.sym)
        target = linker_base + va
    elif args.offset:
        off = int(args.offset, 0) if isinstance(args.offset, str) else args.offset
        target = linker_base + off
    else:
        raise SystemExit("need --sym or --offset")
    print(f"native-hook target=0x{target:x} ({args.sym or hex(off)}) replace={args.replace}")
    r = install_replace(pid, target, args.replace, is_native=True)
    print(f"✓ installed: {r}")
    if r.get("kind") == "log":
        print(f"\n  to read log:  pte_hookctl dump-log --pid {pid} --addr 0x{r['log_buf']:x}")


def cmd_java_hook(args):
    pid = resolve_pid(args)
    # 1. DEX parse to find method_idx
    info = DP.find_method_in_apk(args.apk, args.cls, args.method, args.sig)
    if not info:
        raise SystemExit(f"method not found in {args.apk}")
    print(f"DEX: {info['dex_name']} type_idx={info['type_idx']} method_idx={info['method_idx']}")
    print(f"  adjacent={info['adjacent_idxs']}")

    # 2. scan for ArtMethod
    adj_csv = ",".join(str(x) for x in info["adjacent_idxs"])
    scan_cmd = f"/data/local/tmp/pte_scan {pid} {info['method_idx']} {adj_csv}"
    out = K._run(scan_cmd)
    candidates = []
    for line in out.strip().splitlines():
        line = line.strip()
        if not line.startswith("0x"):
            continue
        parts = line.split()
        addr = int(parts[0], 16)
        candidates.append(addr)
    print(f"scanner found {len(candidates)} candidates: " + ", ".join(f"0x{c:x}" for c in candidates))

    if not candidates:
        raise SystemExit("scanner found no candidates; try different adjacency or disable filter")

    # If multiple: filter by expected cluster size. A class with N methods should
    # have exactly N contiguous ArtMethods with same decl; neighbors beyond should
    # have different decl or zero.
    expected_n = len(info["adjacent_idxs"]) + 1
    if args.artmethod:
        target = int(args.artmethod, 16)
    elif len(candidates) == 1:
        target = candidates[0]
    else:
        print(f"disambiguating by cluster size (expected={expected_n})...")
        best = None
        for cand in candidates:
            try:
                cand_decl = K.proc_read_u32(pid, cand)
                # Count how many adjacent ArtMethods share this decl
                n_same = 1
                # walk forward
                for k in range(1, 20):
                    d = K.proc_read_u32(pid, cand + k * 0x20)
                    if d == cand_decl: n_same += 1
                    else: break
                # walk backward
                for k in range(1, 20):
                    d = K.proc_read_u32(pid, cand - k * 0x20)
                    if d == cand_decl: n_same += 1
                    else: break
                print(f"  cand 0x{cand:x} decl=0x{cand_decl:x} cluster_size={n_same}")
                # Accept close matches (ART stores direct/virtual in separate arrays,
                # so cluster might show only virtuals)
                if (n_same == expected_n or
                    n_same == expected_n - 2 or  # virtuals only (exclude direct)
                    n_same == 2 and expected_n == 2):
                    if best is None:
                        best = cand
            except Exception as e:
                print(f"  cand 0x{cand:x}: {e}")
        if best is None:
            print("no candidate matches expected cluster size — pass --artmethod 0x... explicitly")
            raise SystemExit(1)
        target = best
        print(f"  picked 0x{target:x}")

    print(f"java-hook target ArtMethod=0x{target:x} replace={args.replace}")
    r = install_replace(pid, target, args.replace, entry_offset=0x18, is_native=False)
    print(f"✓ installed: {r}")
    if r.get("kind") == "log":
        print(f"\n  to read log:  pte_hookctl dump-log --pid {pid} --addr 0x{r['log_buf']:x}")


def cmd_dump_log(args):
    """Read ghost log buffer via KPM ghost-read (handles VMA-less ghost)."""
    pid = int(args.pid)
    addr = int(args.addr, 16)
    # Use ghost-read (finds containing ghost and reads via kernel kaddr)
    out = K.ctl_raw(f"ghost-read {pid} 0x{addr:x} 80")
    import re
    m = re.search(r"\[OK\].*?bytes[^:]*:\s*([0-9a-fA-F]+)", out)
    if not m:
        raise RuntimeError(f"ghost-read failed: {out}")
    data = bytes.fromhex(m.group(1))
    print(f"log buf @ 0x{addr:x}:")
    for i in range(8):
        v = int.from_bytes(data[i*8:(i+1)*8], "little")
        tag = "  (ArtMethod*)" if i == 0 else ""
        print(f"  X{i} = 0x{v:016x}  ({v if v < 1<<31 else ''}){tag}")
    marker = int.from_bytes(data[64:72], "little")
    counter = int.from_bytes(data[72:80], "little")
    print(f"  marker  = 0x{marker:x}  ({'valid' if marker == 0xC0DE1A57 else 'INVALID'})")
    print(f"  counter = {counter}  (hook fired this many times)")


def main():
    p = argparse.ArgumentParser(prog="pte_hookctl")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status").set_defaults(func=cmd_status)

    pf = sub.add_parser("find-sym")
    pf.add_argument("--pid"); pf.add_argument("--pkg")
    pf.add_argument("--lib", required=True)
    pf.add_argument("--pattern", default="")
    pf.set_defaults(func=cmd_find_sym)

    pfm = sub.add_parser("find-method")
    pfm.add_argument("--apk", required=True)
    pfm.add_argument("--class", dest="cls", required=True)
    pfm.add_argument("--method", required=True)
    pfm.add_argument("--sig", required=True)
    pfm.set_defaults(func=cmd_find_method)

    pn = sub.add_parser("native-hook")
    pn.add_argument("--pid"); pn.add_argument("--pkg")
    pn.add_argument("--lib", required=True)
    pn.add_argument("--sym"); pn.add_argument("--offset")
    pn.add_argument("--replace", required=True)
    pn.set_defaults(func=cmd_native_hook)

    pj = sub.add_parser("java-hook")
    pj.add_argument("--pid"); pj.add_argument("--pkg")
    pj.add_argument("--apk", required=True)
    pj.add_argument("--class", dest="cls", required=True)
    pj.add_argument("--method", required=True)
    pj.add_argument("--sig", required=True)
    pj.add_argument("--replace", required=True)
    pj.add_argument("--artmethod", help="override: explicit ArtMethod addr hex")
    pj.set_defaults(func=cmd_java_hook)

    pd = sub.add_parser("dump-log")
    pd.add_argument("--pid", required=True)
    pd.add_argument("--addr", required=True)
    pd.set_defaults(func=cmd_dump_log)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
