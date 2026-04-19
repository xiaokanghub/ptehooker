"""
artmethod_scan.py - Scan LinearAlloc regions for ArtMethod matching dex_method_index_.

Strategy:
  1. List [anon:dalvik-LinearAlloc] VMAs via /proc/PID/maps
  2. For each VMA, read in chunks (e.g. 64KB) and scan for ArtMethod pattern:
     - at offset +0xc, u32 == target_method_idx
     - at offset +0, declaring_class_ is non-zero
     - at +0x18, entry_point looks valid (in r-xp region OR in anon)
  3. For strong signal, also check adjacent ArtMethod at +0x28 or -0x28
     should have adjacent dex_method_index_ (target±1, ±2, etc)
"""
import sys
import os
import struct

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import kpm_client as K
import art_offsets as AO


LINEARALLOC_TAG = "[anon:dalvik-LinearAlloc]"


def linearalloc_vmas(pid):
    """Return list of (start, end, size) for [anon:dalvik-LinearAlloc]."""
    maps = K.read_maps(pid)
    return [(s, e, e - s) for s, e, _, _, p in maps if LINEARALLOC_TAG in p]


def read_chunk(pid, addr, size, max_try=3):
    """Read `size` bytes with retries."""
    for _ in range(max_try):
        try:
            return K.proc_read(pid, addr, size)
        except Exception:
            continue
    return None


def scan_for_method_idx(pid, target_idx, adjacent_idxs=(), verbose=False):
    """
    Return list of candidate ArtMethod addresses where:
      *(u32)(addr + 0x0c) == target_idx
      AND
      *(u32)(addr + 0x00) != 0  (declaring_class non-null)
      AND if adjacent_idxs provided:
        any of the adjacent method_idxs appears at addr ± 0x28 * k
    """
    candidates = []
    vmas = linearalloc_vmas(pid)
    print(f"scanning {len(vmas)} LinearAlloc VMAs, total {sum(v[2] for v in vmas)/1024:.0f} KB")

    for start, end, size in vmas:
        # Read in 8KB chunks
        CHUNK = 8 * 1024
        for off in range(0, size, CHUNK):
            chunk_size = min(CHUNK, size - off)
            addr = start + off
            data = read_chunk(pid, addr, chunk_size)
            if not data:
                continue
            # Scan 4-byte aligned positions (ArtMethod aligned to 4+ bytes)
            for i in range(0, chunk_size - AO.ARTMETHOD_SIZE, 4):
                decl = struct.unpack_from("<I", data, i + AO.ARTMETHOD_DECLARING_CLASS)[0]
                midx = struct.unpack_from("<I", data, i + AO.ARTMETHOD_DEX_METHOD_INDEX)[0]
                if midx != target_idx:
                    continue
                if decl == 0:
                    continue
                # access_flags sanity: not all 0xFFFFFFFF
                access = struct.unpack_from("<I", data, i + AO.ARTMETHOD_ACCESS_FLAGS)[0]
                if access == 0 or access == 0xFFFFFFFF:
                    continue
                cand = addr + i
                candidates.append(
                    dict(
                        addr=cand,
                        declaring_class=decl,
                        access_flags=access,
                        method_idx=midx,
                    )
                )
    print(f"found {len(candidates)} ArtMethod candidates with dex_method_index_={target_idx}")

    # Filter by adjacent method_idx if requested
    if adjacent_idxs and len(candidates) > 1:
        filtered = []
        for c in candidates:
            # Read adjacent method's dex_method_index_
            for delta in (AO.ARTMETHOD_SIZE, -AO.ARTMETHOD_SIZE):
                adj_addr = c["addr"] + delta
                adj_data = read_chunk(pid, adj_addr + AO.ARTMETHOD_DEX_METHOD_INDEX, 4)
                if adj_data and len(adj_data) == 4:
                    adj_idx = struct.unpack("<I", adj_data)[0]
                    if adj_idx in adjacent_idxs:
                        c["adjacent_hit"] = (delta, adj_idx)
                        filtered.append(c)
                        break
        if filtered:
            print(f"  filtered to {len(filtered)} via adjacency {adjacent_idxs}")
            return filtered

    return candidates


def dump_artmethod(pid, addr):
    """Read and pretty-print an ArtMethod at `addr`."""
    data = K.proc_read(pid, addr, AO.ARTMETHOD_SIZE)
    decl = struct.unpack_from("<I", data, 0)[0]
    access = struct.unpack_from("<I", data, 4)[0]
    dex_off = struct.unpack_from("<I", data, 8)[0]
    midx = struct.unpack_from("<I", data, 0xC)[0]
    mtab_idx = struct.unpack_from("<H", data, 0x10)[0]
    hot = struct.unpack_from("<H", data, 0x12)[0]
    dataptr = struct.unpack_from("<Q", data, 0x18)[0]
    print(f"  ArtMethod @ 0x{addr:x}")
    print(f"    declaring_class_={decl:#x}  access_flags_={access:#x}")
    print(f"    dex_code_item_offset_={dex_off:#x}  dex_method_index_={midx}")
    print(f"    method_index_={mtab_idx}  hotness_counter_={hot}")
    print(f"    entry_point=0x{AO.untag(dataptr):x}  raw=0x{dataptr:x}")
    return dict(
        addr=addr,
        declaring_class=decl,
        access_flags=access,
        dex_method_index=midx,
        method_index=mtab_idx,
        entry_point=AO.untag(dataptr),
    )


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", required=True)
    ap.add_argument("--method-idx", type=int, required=True)
    ap.add_argument("--adjacent", default="", help="comma-separated adjacent method_idxs to confirm")
    args = ap.parse_args()
    adj = tuple(int(x) for x in args.adjacent.split(",") if x) if args.adjacent else ()
    cands = scan_for_method_idx(int(args.pid), args.method_idx, adjacent_idxs=adj)
    for c in cands[:10]:
        dump_artmethod(int(args.pid), c["addr"])
