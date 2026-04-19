"""
dex_parser.py - Parse DEX files to map (class_descriptor, method_name, signature) → method_idx.

Handles multi-dex APKs. Returns a dict with:
  - class_idx (within the DEX)
  - method_idx (within the DEX)
  - adjacent_method_idxs (for cross-process ArtMethod scanning)
  - dex_filename (which dex has this class)
"""
import os
import struct
import zipfile
from typing import Optional


def _read_uleb(d, off):
    v, shift = 0, 0
    while True:
        b = d[off]
        off += 1
        v |= (b & 0x7F) << shift
        if b < 0x80:
            break
        shift += 7
    return v, off


def _read_mutf8(d, off):
    size, off = _read_uleb(d, off)
    end = d.index(b"\0", off)
    return d[off:end].decode("utf-8", errors="replace"), end + 1


class DexFile:
    def __init__(self, data: bytes, filename: str = ""):
        if data[:4] != b"dex\n":
            raise ValueError(f"bad DEX magic in {filename}")
        self.data = data
        self.filename = filename
        self.string_ids_size, self.string_ids_off = struct.unpack("<II", data[56:64])
        self.type_ids_size, self.type_ids_off = struct.unpack("<II", data[64:72])
        self.proto_ids_size, self.proto_ids_off = struct.unpack("<II", data[72:80])
        self.field_ids_size, self.field_ids_off = struct.unpack("<II", data[80:88])
        self.method_ids_size, self.method_ids_off = struct.unpack("<II", data[88:96])
        self.class_defs_size, self.class_defs_off = struct.unpack("<II", data[96:104])
        # Lazy indexes for O(1) class lookup after first call.
        self._type_to_idx = None
        self._type_idx_to_class_def = None

    def get_string(self, idx: int) -> str:
        sid = struct.unpack("<I", self.data[self.string_ids_off + idx * 4 : self.string_ids_off + idx * 4 + 4])[0]
        s, _ = _read_mutf8(self.data, sid)
        return s

    def get_type(self, type_idx: int) -> str:
        descriptor_idx = struct.unpack("<I", self.data[self.type_ids_off + type_idx * 4 : self.type_ids_off + type_idx * 4 + 4])[0]
        return self.get_string(descriptor_idx)

    def find_class(self, descriptor: str) -> Optional[int]:
        """Linear scan with result cache. Building a full descriptor→idx
        index up-front is ~1.5s per DEX on aweme; most runs only look up 1-2
        classes, so lazy + cache-on-hit is faster."""
        if self._type_to_idx is None:
            self._type_to_idx = {}
        if descriptor in self._type_to_idx:
            return self._type_to_idx[descriptor]
        for i in range(self.type_ids_size):
            s = self.get_type(i)
            if s == descriptor:
                self._type_to_idx[descriptor] = i
                return i
        self._type_to_idx[descriptor] = None  # negative cache
        return None

    def _build_class_def_index(self):
        d = self._type_idx_to_class_def = {}
        base = self.class_defs_off
        data = self.data
        for j in range(self.class_defs_size):
            off = base + j * 32
            ci = struct.unpack_from("<I", data, off)[0]
            d[ci] = j

    def find_class_def(self, type_idx: int) -> Optional[int]:
        """O(1) after first call (lazy builds type_idx→class_def_idx dict)."""
        if self._type_idx_to_class_def is None:
            self._build_class_def_index()
        return self._type_idx_to_class_def.get(type_idx)

    def has_class_descriptor_string(self, descriptor: str) -> bool:
        """Fast bytewise check: is `descriptor` present ANYWHERE in the DEX?
        If not, the class can't be here (prunes unrelated DEX early). May have
        false positives (descriptor appearing as substring of another), so
        caller must still verify via find_class."""
        return descriptor.encode("utf-8") in self.data

    def get_proto_sig(self, proto_idx: int) -> str:
        """Return method signature in Java format e.g. (I)Ljava/lang/String;"""
        proto_off = self.proto_ids_off + proto_idx * 12
        shorty_idx, return_type_idx, params_off = struct.unpack("<III", self.data[proto_off : proto_off + 12])
        # Build parameter list
        params = []
        if params_off != 0:
            n = struct.unpack("<I", self.data[params_off : params_off + 4])[0]
            for k in range(n):
                t_idx = struct.unpack("<H", self.data[params_off + 4 + k * 2 : params_off + 4 + k * 2 + 2])[0]
                params.append(self.get_type(t_idx))
        return_type = self.get_type(return_type_idx)
        return "(" + "".join(params) + ")" + return_type

    def list_methods(self, class_def_idx: int):
        """Parse class_data and return list of (method_idx, name, signature, access, is_virtual)."""
        off = self.class_defs_off + class_def_idx * 32
        _, _, _, _, _, _, class_data_off, _ = struct.unpack("<IIIIIIII", self.data[off : off + 32])
        if class_data_off == 0:
            return []
        d = self.data
        p = class_data_off
        sf, p = _read_uleb(d, p)
        inf, p = _read_uleb(d, p)
        dm, p = _read_uleb(d, p)
        vm, p = _read_uleb(d, p)
        # skip fields
        for _ in range(sf + inf):
            _, p = _read_uleb(d, p)
            _, p = _read_uleb(d, p)
        methods = []
        # direct methods
        cur = 0
        for _ in range(dm):
            diff, p = _read_uleb(d, p)
            af, p = _read_uleb(d, p)
            co, p = _read_uleb(d, p)
            cur += diff
            name = self.get_method_name(cur)
            sig = self.get_method_sig(cur)
            methods.append((cur, name, sig, af, False))
        # virtual methods
        cur = 0
        for _ in range(vm):
            diff, p = _read_uleb(d, p)
            af, p = _read_uleb(d, p)
            co, p = _read_uleb(d, p)
            cur += diff
            name = self.get_method_name(cur)
            sig = self.get_method_sig(cur)
            methods.append((cur, name, sig, af, True))
        return methods

    def get_method_name(self, method_idx: int) -> str:
        moff = self.method_ids_off + method_idx * 8
        cls, proto, name = struct.unpack("<HHI", self.data[moff : moff + 8])
        return self.get_string(name)

    def get_method_sig(self, method_idx: int) -> str:
        moff = self.method_ids_off + method_idx * 8
        cls, proto, name = struct.unpack("<HHI", self.data[moff : moff + 8])
        return self.get_proto_sig(proto)


# APK → list[DexFile] cache (so multiple find_method_in_apk calls don't re-parse)
_APK_DEX_CACHE = {}


def _get_apk_dexes(apk_path: str):
    """Return list of (name, DexFile) from APK, with caching. Lazy per-DEX."""
    if apk_path not in _APK_DEX_CACHE:
        entries = []
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in sorted(zf.namelist()):
                if not name.startswith("classes") or not name.endswith(".dex"):
                    continue
                entries.append(name)
        _APK_DEX_CACHE[apk_path] = {"names": entries, "loaded": {}}
    return _APK_DEX_CACHE[apk_path]


def _load_dex(apk_path: str, name: str):
    cache = _get_apk_dexes(apk_path)
    if name not in cache["loaded"]:
        with zipfile.ZipFile(apk_path, "r") as zf:
            data = zf.read(name)
        try:
            cache["loaded"][name] = DexFile(data, name)
        except ValueError:
            cache["loaded"][name] = None
    return cache["loaded"][name]


def find_method_in_apk(
    apk_path: str,
    class_descriptor: str,
    method_name: str,
    signature: str,
):
    """Search all classes*.dex in APK for class_descriptor+method_name+signature.
    Returns dict: {dex_name, class_idx, class_def_idx, method_idx, adjacent_idxs, access}

    Uses APK-level DEX cache: first call loads + indexes each DEX, subsequent
    calls are O(1) lookup per DEX.
    """
    cache = _get_apk_dexes(apk_path)
    for name in cache["names"]:
        dex = _load_dex(apk_path, name)
        if dex is None:
            continue
        # Fast-path: bytewise search for the class descriptor. If not present,
        # skip full parse. Essentially free (memchr in C).
        if not dex.has_class_descriptor_string(class_descriptor):
            continue
        type_idx = dex.find_class(class_descriptor)
        if type_idx is None:
            continue
        cdef = dex.find_class_def(type_idx)
        if cdef is None:
            continue
        methods = dex.list_methods(cdef)
        matching = [m for m in methods if m[1] == method_name and m[2] == signature]
        if not matching:
            print(f"[{name}] class found but no matching method. methods:")
            for m in methods[:20]:
                print(f"    midx={m[0]} {m[1]}{m[2]} acc=0x{m[3]:x}")
            continue
        method_idx, _, _, access, is_virtual = matching[0]
        adj = [m[0] for m in methods if m[0] != method_idx]
        return dict(
            dex_name=name,
            class_descriptor=class_descriptor,
            type_idx=type_idx,
            class_def_idx=cdef,
            method_idx=method_idx,
            method_name=method_name,
            signature=signature,
            access_flags=access,
            is_virtual=is_virtual,
            adjacent_idxs=adj,
        )
    return None


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("apk")
    ap.add_argument("class_desc")
    ap.add_argument("method")
    ap.add_argument("sig")
    args = ap.parse_args()
    res = find_method_in_apk(args.apk, args.class_desc, args.method, args.sig)
    if not res:
        print("NOT FOUND")
        raise SystemExit(1)
    import json
    print(json.dumps(res, indent=2))
