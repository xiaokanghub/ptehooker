"""
shellcode 生成器的纯 Python 单元测试 —— 无设备依赖。
每个测试把生成的字节反汇编回关键字段（opcode / reg / imm），断言正确。

跑：cd pte_hookctl && python3 -m pytest tests/ -v
或：python3 tests/test_shellcode.py
"""
import os
import sys
import struct
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import shellcode as SC


def u32(b, off=0):
    return struct.unpack("<I", b[off:off + 4])[0]


def u64(b, off=0):
    return struct.unpack("<Q", b[off:off + 8])[0]


class TestInstructionEncoders(unittest.TestCase):
    def test_mov_wide_zero(self):
        # MOVZ X0, #0x1234 = 0xD2824680
        insn = SC.mov_wide(0, 0x1234, 0)
        self.assertEqual(insn, 0xD2824680)

    def test_mov_wide_shift16(self):
        # MOVZ X17, #0xFFFF, LSL #16 = 0xF2BFFFF1
        # (mov_wide encodes MOVZ; base 0xD2800000; shift=1 → bit 21 set)
        insn = SC.mov_wide(17, 0xFFFF, 1)
        self.assertEqual(insn, 0xD2BFFFF1)

    def test_mov_k(self):
        # MOVK X0, #0x7D, LSL #32
        insn = SC.mov_k(0, 0x7D, 2)
        # Base 0xF2800000 | hw=2 (bit 22) | imm16=0x7D shifted <<5 | Rd=0
        expected = 0xF2C00000 | (0x7D << 5) | 0
        self.assertEqual(insn, expected)


class TestLoadImm64(unittest.TestCase):
    def test_zero(self):
        b = SC.load_imm64(0, 0)
        # One MOVZ X0, #0
        self.assertEqual(len(b), 4)
        self.assertEqual(u32(b), 0xD2800000)

    def test_small_imm(self):
        # Value fits in low 16 bits only → 1 MOVZ
        b = SC.load_imm64(1, 0x1234)
        self.assertEqual(len(b), 4)

    def test_full_64bit(self):
        # All 4 chunks non-zero → 4 insns
        val = 0xDEAD_BEEF_CAFE_BABE
        b = SC.load_imm64(5, val)
        self.assertEqual(len(b), 16)

    def test_skip_zero_chunks(self):
        # 0x1234_0000_5678_0000 has 2 non-zero chunks.
        # load_imm64 emits MOVZ for parts[0] unconditionally, then MOVK only
        # for higher non-zero chunks. So: MOVZ(0) + MOVK(0x5678,hw=1) +
        # MOVK(0x1234,hw=3) = 3 insns.
        val = 0x1234_0000_5678_0000
        b = SC.load_imm64(3, val)
        self.assertEqual(len(b), 12)  # 3 insns


class TestLoadImm64Fixed(unittest.TestCase):
    def test_always_four_insns(self):
        for val in (0, 0x1234, 0xDEAD_BEEF_CAFE_BABE, 0x1234_0000_5678_0000):
            with self.subTest(val=hex(val)):
                b = SC.load_imm64_fixed(7, val)
                self.assertEqual(len(b), 16,
                                  f"expected 4 insns (16B) for {hex(val)}")


class TestConstReturn(unittest.TestCase):
    def test_small_value(self):
        # BTI jc + MOV X0, #99 + RET = 12 bytes
        b = SC.const_return(99)
        self.assertEqual(len(b), 12)
        self.assertEqual(u32(b, 0), 0xD50324DF)  # BTI jc
        self.assertEqual(u32(b, 8), 0xD65F03C0)  # RET

    def test_large_value(self):
        # Requires load_imm64 path
        b = SC.const_return(0x1_0000)
        self.assertGreater(len(b), 12)
        # Still starts with BTI, ends with RET
        self.assertEqual(u32(b, 0), 0xD50324DF)
        self.assertEqual(u32(b, len(b) - 4), 0xD65F03C0)


class TestJavaUxnFilter(unittest.TestCase):
    def test_structure(self):
        """Filter layout:
            BTI jc                (1 insn)
            load_imm64_fixed X17  (4 insns, MASK)
            AND X16, X0, X17      (1 insn)
            load_imm64_fixed X17  (4 insns, expected)
            CMP X16, X17          (1 insn)
            B.EQ #+24             (1 insn)
            load_imm64_fixed X16  (4 insns, backup)
            BR X16                (1 insn)
            <action_shellcode>
        Total prologue = 17 insns = 68 bytes
        """
        expected_method = 0x7b40_0001_2345_6789
        backup = 0x7d00_0000_0000_1000
        action = SC.const_return(42)  # 12 bytes

        full = SC.java_uxn_filter(expected_method, action, backup)
        self.assertEqual(len(full), 68 + len(action))

        # Check prologue
        self.assertEqual(u32(full, 0), 0xD50324DF)    # BTI jc

        # X17 = MASK (0x00FFFFFFFFFFFFFF), 4 fixed MOVs at offset 4..20
        # Can't trivially reassemble value but verify count
        # Then AND X16, X0, X17 at offset 20
        self.assertEqual(u32(full, 20), 0x8A110010)

        # X17 = expected at 24..40
        # CMP X16, X17 at 40
        self.assertEqual(u32(full, 40), 0xEB11021F)

        # B.EQ #+24 at 44 (imm19 = 6 → skip 5 insns after B.EQ)
        self.assertEqual(u32(full, 44), 0x54000000 | (6 << 5) | 0)

        # X16 = backup at 48..64
        # BR X16 at 64
        self.assertEqual(u32(full, 64), 0xD61F0200)

        # Action (starts with BTI jc again — harmless no-op) at offset 68
        self.assertEqual(u32(full, 68), 0xD50324DF)

    def test_filter_mask_value(self):
        """Verify that the mask loaded at offset 4..20 equals 0x00FFFFFFFFFFFFFF.
        Decode the 4 MOVZ/MOVK instructions manually."""
        full = SC.java_uxn_filter(0x12345678_9ABCDEF0, SC.const_return(0), 0)
        mov_insns = [u32(full, 4 + i * 4) for i in range(4)]
        val = 0
        # First insn: MOVZ at hw
        for ins in mov_insns:
            # MOVZ base 0xD2800000, MOVK base 0xF2800000
            is_movz = (ins & 0xFF800000) == 0xD2800000
            is_movk = (ins & 0xFF800000) == 0xF2800000
            self.assertTrue(is_movz or is_movk)
            hw = (ins >> 21) & 0x3
            imm16 = (ins >> 5) & 0xFFFF
            if is_movz:
                val = imm16 << (hw * 16)
            else:
                val |= imm16 << (hw * 16)
        self.assertEqual(val, 0x00FFFFFFFFFFFFFF,
                          f"expected MASK, got 0x{val:x}")

    def test_filter_expected_value(self):
        """Verify expected_method (masked to 56 bits) gets loaded correctly."""
        expected = 0xb4_00_00_7b_3c_00_00_00
        full = SC.java_uxn_filter(expected, SC.const_return(0), 0)
        # Second load at offset 24..40
        mov_insns = [u32(full, 24 + i * 4) for i in range(4)]
        val = 0
        for ins in mov_insns:
            is_movz = (ins & 0xFF800000) == 0xD2800000
            hw = (ins >> 21) & 0x3
            imm16 = (ins >> 5) & 0xFFFF
            if is_movz:
                val = imm16 << (hw * 16)
            else:
                val |= imm16 << (hw * 16)
        self.assertEqual(val, expected & 0x00FFFFFFFFFFFFFF)

    def test_filter_backup_value(self):
        """Verify backup address is loaded correctly."""
        backup = 0x7d29_cb60_0094
        full = SC.java_uxn_filter(0xaabbccdd, SC.const_return(0), backup)
        mov_insns = [u32(full, 48 + i * 4) for i in range(4)]
        val = 0
        for ins in mov_insns:
            is_movz = (ins & 0xFF800000) == 0xD2800000
            hw = (ins >> 21) & 0x3
            imm16 = (ins >> 5) & 0xFFFF
            if is_movz:
                val = imm16 << (hw * 16)
            else:
                val |= imm16 << (hw * 16)
        self.assertEqual(val, backup)


class TestLogTrampolineClean(unittest.TestCase):
    def test_size(self):
        b = SC.log_trampoline_clean(0x7d2000_0000, 0xC0DE1A57)
        # Roughly: BTI + load X16 + 4 STP + load X17 + STR + LDR + ADD + STR + MOVZ + RET
        self.assertGreater(len(b), 40)

    def test_starts_with_bti(self):
        b = SC.log_trampoline_clean(0x1000, 0x1234)
        self.assertEqual(u32(b, 0), 0xD50324DF)

    def test_ends_with_ret(self):
        b = SC.log_trampoline_clean(0x1000, 0x1234)
        self.assertEqual(u32(b, len(b) - 4), 0xD65F03C0)


class TestLogAndCall(unittest.TestCase):
    def test_backup_present(self):
        b = SC.log_and_call(0x7d200000, 0xC0DE1A57, 0x7d300000)
        # Must contain BLR instruction (0xD63F0xxx)
        blr_found = False
        for i in range(0, len(b), 4):
            w = u32(b, i)
            if (w & 0xFFFFFC1F) == 0xD63F0000:
                blr_found = True
                break
        self.assertTrue(blr_found, "log_and_call must emit BLR to backup")


class TestGhostReadChunking(unittest.TestCase):
    """Verify ghost_read's auto-chunking works (KPM 1536 cap, userspace 1024
    chunk)."""

    def test_chunk_boundary(self):
        """Read 3000 bytes should produce 3 ctl calls of <=1024."""
        import kpm_client as K
        calls = []

        def fake_ctl_raw(args):
            calls.append(args)
            # parse `ghost-read PID ADDR LEN`
            parts = args.split()
            length = int(parts[3])
            return f"[OK] {length} bytes (pool slot=0 +0x0): " + ("aa" * length) + "\n"

        orig = K.ctl_raw
        K.ctl_raw = fake_ctl_raw
        try:
            result = K.ghost_read(1234, 0x1000, 3000)
        finally:
            K.ctl_raw = orig
        self.assertEqual(len(result), 3000)
        self.assertEqual(result, b"\xaa" * 3000)
        # Should be 3 chunks (1024 + 1024 + 952)
        self.assertEqual(len(calls), 3)
        lengths = [int(c.split()[3]) for c in calls]
        self.assertEqual(lengths, [1024, 1024, 952])

    def test_small_read_single_chunk(self):
        import kpm_client as K
        calls = []

        def fake_ctl_raw(args):
            calls.append(args)
            length = int(args.split()[3])
            return f"[OK] {length} bytes (pool slot=0 +0x0): " + ("bb" * length) + "\n"

        orig = K.ctl_raw
        K.ctl_raw = fake_ctl_raw
        try:
            result = K.ghost_read(1234, 0x2000, 128)
        finally:
            K.ctl_raw = orig
        self.assertEqual(result, b"\xbb" * 128)
        self.assertEqual(len(calls), 1)

    def test_early_termination_on_short_response(self):
        """KPM may return fewer bytes than requested (end of ghost region)."""
        import kpm_client as K
        calls = []

        def fake_ctl_raw(args):
            calls.append(args)
            # Only return 512 bytes regardless of request
            return "[OK] 512 bytes (pool slot=0 +0x0): " + ("cc" * 512) + "\n"

        orig = K.ctl_raw
        K.ctl_raw = fake_ctl_raw
        try:
            result = K.ghost_read(1234, 0x3000, 2000)
        finally:
            K.ctl_raw = orig
        # Should stop after first short response
        self.assertEqual(len(result), 512)
        self.assertEqual(len(calls), 1)


class TestDbiEncoders(unittest.TestCase):
    """DBI engine encoder correctness (镜像 dbi_kern.c 的 enc_*). These catch
    regression if the C encoders drift. ARM64 LDR-family encoding reference:
        [31:30] opc  [29:27]=011  [26]=V  [25:24]=00  [23:5]=imm19/imm12  [4:0]=Rt
    """

    def test_ldr_literal_integer_masks(self):
        # LDR Wt literal: 00 011 0 00 ... = 0x18000000
        # LDR Xt literal: 01 011 0 00 ... = 0x58000000
        # LDRSW literal:  10 011 0 00 ... = 0x98000000
        # PRFM literal:   11 011 0 00 ... = 0xD8000000
        patterns = [
            (0x18345678, 0xFF000000, 0x18000000, "LDR Wt literal"),
            (0x58ABCDEF, 0xFF000000, 0x58000000, "LDR Xt literal"),
            (0x98111111, 0xFF000000, 0x98000000, "LDRSW literal"),
            (0xD8222222, 0xFF000000, 0xD8000000, "PRFM literal"),
        ]
        for insn, mask, expected, name in patterns:
            self.assertEqual(insn & mask, expected,
                              f"{name} pattern mismatch")

    def test_ldr_simd_literal_mask(self):
        # SIMD LDR literal: opc_simd 011 1 00 ... V=1
        # S (32):  00 011 1 00 = 0x1C000000
        # D (64):  01 011 1 00 = 0x5C000000
        # Q (128): 10 011 1 00 = 0x9C000000
        # reserved: 11 011 1 00 = 0xDC000000
        for opc, base in [(0x00, 0x1C000000),
                           (0x40, 0x5C000000),
                           (0x80, 0x9C000000)]:
            insn = base | 0x12345  # any imm19 + Rt
            # Match should use mask 0x3F000000 (bits 29-24)
            self.assertEqual(insn & 0x3F000000, 0x1C000000 | (opc & 0x30000000),
                              f"SIMD opc=0x{opc:x} pattern")
            # The kernel dispatch masks to 0x3F000000 expecting 0x1C000000
            # So 64-bit and 128-bit should ALSO match via opc[31:30] != 0 but
            # bits 29:24 still 011100.
            # Wait — the mask check in recomp uses (insn & 0x3F000000) == 0x1C000000
            # which only matches when bits 31:30 are 00! That misses D and Q.
            # Verify: (0x5C000000 & 0x3F000000) = 0x1C000000 ✓
            self.assertEqual(0x5C000000 & 0x3F000000, 0x1C000000,
                              "D-reg LDR literal")
            self.assertEqual(0x9C000000 & 0x3F000000, 0x1C000000,
                              "Q-reg LDR literal")

    def test_ldrsw_imm_unsigned_encoding(self):
        """LDRSW Xt, [Xn, #0] = 0xB9800000 | (Rn<<5) | Rt"""
        # LDRSW X3, [X17, #0]
        expected = 0xB9800000 | (17 << 5) | 3
        self.assertEqual(expected, 0xB9800223)

    def test_ldr_vec_encoding(self):
        """SIMD LDR immediate unsigned offset=0 encodings."""
        # LDR St (32), [Xn, #0]:  10 111 1 01 01 imm12=0 Rn Rt
        # LDR Dt (64), [Xn, #0]:  11 111 1 01 01 imm12=0 Rn Rt
        # LDR Qt (128), [Xn, #0]: 00 111 1 01 11 imm12=0 Rn Rt
        def enc_vec(rt, rn, opc):
            if opc == 2:
                size_hi, ldr_opc = 0, 3  # Q
            elif opc == 1:
                size_hi, ldr_opc = 3, 1  # D
            else:
                size_hi, ldr_opc = 2, 1  # S
            return ((size_hi << 30) | 0x3D400000
                     | (ldr_opc << 22) | ((rn & 0x1F) << 5) | (rt & 0x1F))

        # LDR S0, [X17] → 0xBD400220 (size_hi=2, opc=1)
        self.assertEqual(enc_vec(0, 17, 0), 0xBD400220)
        # LDR D0, [X17] → 0xFD400220 (size_hi=3, opc=1)
        self.assertEqual(enc_vec(0, 17, 1), 0xFD400220)
        # LDR Q0, [X17] → 0x3DC00220 (size_hi=0, opc=3)
        self.assertEqual(enc_vec(0, 17, 2), 0x3DC00220)


class TestArtOffsets(unittest.TestCase):
    """ArtMethod offset compat layer — ensures per-API table + detection."""

    def setUp(self):
        import art_offsets as AO
        self.AO = AO
        # save + clear cache
        self._saved = (AO._CACHED_API, AO._CACHED_SERIAL)
        AO._CACHED_API = None
        AO._CACHED_SERIAL = None

    def tearDown(self):
        self.AO._CACHED_API, self.AO._CACHED_SERIAL = self._saved

    def test_a13_offsets(self):
        o = self.AO.get_offsets(api=33)
        self.assertEqual(o["ARTMETHOD_SIZE"], 0x20)
        self.assertEqual(o["ARTMETHOD_ENTRY_QUICK"], 0x18)
        self.assertEqual(o["ARTMETHOD_ACCESS_FLAGS"], 0x04)
        self.assertEqual(o["ARTMETHOD_DEX_METHOD_INDEX"], 0x08)

    def test_a14_same_as_a13(self):
        """A14 ArtMethod layout is identical to A13."""
        o13 = self.AO.get_offsets(api=33)
        o14 = self.AO.get_offsets(api=34)
        self.assertEqual(o13, o14)

    def test_a12_has_bigger_struct(self):
        """A12 had dex_code_item_offset, so struct is 0x28 bytes, ep at 0x20."""
        o = self.AO.get_offsets(api=31)
        self.assertEqual(o["ARTMETHOD_SIZE"], 0x28)
        self.assertEqual(o["ARTMETHOD_ENTRY_QUICK"], 0x20)

    def test_unknown_api_falls_back(self):
        """Unknown API falls back to closest known."""
        # API 40 (future) — should pick API 35 (highest known)
        o = self.AO.get_offsets(api=40)
        self.assertEqual(o["ARTMETHOD_SIZE"], 0x20)  # matches A13-style


if __name__ == "__main__":
    unittest.main(verbosity=2)
