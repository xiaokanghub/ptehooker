/* SPDX-License-Identifier: GPL-2.0 */
/*
 * dbi_kern.c - Kernel-side DBI engine for ARM64
 *
 * Port of ptehook/userspace/src/dbi_engine.c into KPM form.
 * Recompiles a single 4KB page of ARM64 code, fixing up PC-relative
 * branches and data references so the code can execute from a new
 * virtual address ("ghost page").
 *
 * Strategy:
 *   - Direct branches (B/BL)          : re-encode if ±128MB, else far-jump
 *   - Conditional branches            : re-encode if in range, else invert+far
 *   - ADR / ADRP                      : replace with MOVZ/MOVK absolute load
 *   - LDR literal                     : MOVZ/MOVK + LDR [X17]
 *   - Everything else                 : pass through unchanged
 *
 * Offset map records ghost word-index for every target word-index, so
 * the fault handler can redirect an arbitrary PC inside target_page to
 * the correct point inside ghost_page.
 */

#include <compiler.h>
#include <ktypes.h>
#include "dbi_kern.h"

/* ---------- Small helpers (no libc) ---------- */

static int64_t sign_extend64(uint64_t val, int bits)
{
    int64_t mask = 1LL << (bits - 1);
    return (int64_t)((val ^ mask) - mask);
}

static int in_range_s(int64_t v, int bits)
{
    int64_t lim = 1LL << (bits - 1);
    return (v >= -lim && v < lim);
}

/* ---------- Instruction encoders (subset of arm64_inst.c) ---------- */

static uint32_t enc_br(uint32_t rn)
{
    return 0xD61F0000 | ((rn & 0x1F) << 5);
}

static uint32_t enc_nop(void)
{
    return 0xD503201FU;
}

static int enc_b(int64_t offset, uint32_t *out)
{
    int64_t imm26 = offset / 4;
    if (imm26 < -(1LL << 25) || imm26 >= (1LL << 25)) return -1;
    *out = 0x14000000U | ((uint32_t)imm26 & 0x03FFFFFFU);
    return 0;
}

static int enc_bl(int64_t offset, uint32_t *out)
{
    int64_t imm26 = offset / 4;
    if (imm26 < -(1LL << 25) || imm26 >= (1LL << 25)) return -1;
    *out = 0x94000000U | ((uint32_t)imm26 & 0x03FFFFFFU);
    return 0;
}

static int enc_b_cond(uint32_t cond, int64_t offset, uint32_t *out)
{
    int64_t imm19 = offset / 4;
    if (imm19 < -(1LL << 18) || imm19 >= (1LL << 18)) return -1;
    *out = 0x54000000U | (((uint32_t)imm19 & 0x7FFFFU) << 5) | (cond & 0xFU);
    return 0;
}

static int enc_cbz(uint32_t sf, uint32_t rt, int64_t offset, int is_nz, uint32_t *out)
{
    int64_t imm19 = offset / 4;
    if (imm19 < -(1LL << 18) || imm19 >= (1LL << 18)) return -1;
    uint32_t op = is_nz ? 0x35000000U : 0x34000000U;
    *out = op | ((sf & 1U) << 31) | (((uint32_t)imm19 & 0x7FFFFU) << 5) | (rt & 0x1FU);
    return 0;
}

static int enc_tbz(uint32_t rt, uint32_t bit, int64_t offset, int is_nz, uint32_t *out)
{
    int64_t imm14 = offset / 4;
    if (imm14 < -(1LL << 13) || imm14 >= (1LL << 13)) return -1;
    uint32_t op = is_nz ? 0x37000000U : 0x36000000U;
    uint32_t b5  = (bit >> 5) & 1U;
    uint32_t b40 = bit & 0x1FU;
    *out = op | (b5 << 31) | (b40 << 19) |
           (((uint32_t)imm14 & 0x3FFFU) << 5) | (rt & 0x1FU);
    return 0;
}

static uint32_t enc_ldr_imm_unsigned(uint32_t rt, uint32_t rn, uint32_t size)
{
    /* LDR (unsigned immediate, offset=0): size 111 00 01 0 imm12=0 Rn Rt
     * size: 2 = 32bit, 3 = 64bit. We use offset 0. */
    return ((size & 3U) << 30) | 0x39400000U |
           ((rn & 0x1FU) << 5) | (rt & 0x1FU);
}

/* LDRSW (unsigned immediate, offset=0): loads 32-bit, sign-extends to 64-bit
 * into the target X register. Base encoding 0xB9800000. */
static uint32_t enc_ldrsw_imm_unsigned(uint32_t rt, uint32_t rn)
{
    return 0xB9800000U | ((rn & 0x1FU) << 5) | (rt & 0x1FU);
}

/* SIMD LDR (unsigned immediate, offset=0):
 *   size 111 1 01 opc imm12 Rn Rt
 * size=00 opc=01: 8-bit (Bt); 01: 16 (Ht); 10: 32 (St); 11: 64 (Dt).
 * For 128-bit (Qt), size=00 opc=11. We only support the 32/64/128 cases that
 * LDR-literal SIMD can express. `simd_opc` = 0b00|01|10 for 32/64/128. */
static uint32_t enc_ldr_vec_imm_unsigned(uint32_t rt, uint32_t rn,
                                           uint32_t simd_opc)
{
    uint32_t size_hi, opc;
    if (simd_opc == 2) {           /* 128-bit Qt */
        size_hi = 0; opc = 3;
    } else if (simd_opc == 1) {    /* 64-bit Dt */
        size_hi = 3; opc = 1;
    } else {                        /* 32-bit St */
        size_hi = 2; opc = 1;
    }
    return (size_hi << 30) | 0x3D400000U | (opc << 22) |
            ((rn & 0x1FU) << 5) | (rt & 0x1FU);
}

/*
 * Emit MOVZ + up to 3 MOVK for arbitrary 64-bit immediate.
 * Returns number of words written, or negative on error.
 */
static int emit_mov_imm64(uint32_t rd, uint64_t imm, uint32_t *out, int max_insns)
{
    int n = 0;
    int first = 1;
    int shift;

    for (shift = 0; shift < 64; shift += 16) {
        uint16_t chunk = (uint16_t)((imm >> shift) & 0xFFFFU);
        uint32_t hw = (uint32_t)(shift / 16);

        if (chunk == 0) {
            if (!first) continue;
            if (imm != 0) continue;
        }

        if (n >= max_insns) return -1;

        if (first) {
            /* MOVZ Xd, #chunk, LSL #(hw*16) */
            out[n++] = 0xD2800000U | (hw << 21) |
                       ((uint32_t)chunk << 5) | (rd & 0x1FU);
            first = 0;
        } else {
            /* MOVK Xd, #chunk, LSL #(hw*16) */
            out[n++] = 0xF2800000U | (hw << 21) |
                       ((uint32_t)chunk << 5) | (rd & 0x1FU);
        }
    }

    if (first) {
        /* imm == 0: emit MOVZ Xd, #0 */
        if (n >= max_insns) return -1;
        out[n++] = 0xD2800000U | (rd & 0x1FU);
    }

    return n;
}

/* ---------- Emit helpers on dbi_page_ctx ---------- */

static int emit(struct dbi_page_ctx *ctx, uint32_t insn)
{
    if (ctx->ghost_count >= ctx->ghost_capacity) return -1;
    ctx->ghost[ctx->ghost_count++] = insn;
    return 0;
}

static int ghost_off_bytes(const struct dbi_page_ctx *ctx)
{
    return ctx->ghost_count * 4;
}

static uint64_t ghost_cur_pc(const struct dbi_page_ctx *ctx)
{
    return ctx->ghost_page + (uint64_t)ghost_off_bytes(ctx);
}

/*
 * Emit a 5-instruction far-jump sequence (or shorter if imm has zero chunks):
 *   MOVZ X17, #imm0
 *   MOVK X17, #imm1, lsl #16
 *   MOVK X17, #imm2, lsl #32
 *   MOVK X17, #imm3, lsl #48
 *   BR X17                       ; far unconditional jump
 */
static int emit_far_jump(struct dbi_page_ctx *ctx, uint64_t target)
{
    uint32_t movs[4];
    int n = emit_mov_imm64(DBI_SCRATCH_REG, target, movs, 4);
    int i;
    if (n < 0) return -1;
    for (i = 0; i < n; i++) {
        if (emit(ctx, movs[i]) < 0) return -1;
    }
    return emit(ctx, enc_br(DBI_SCRATCH_REG));
}

/* Emit MOVZ/MOVK sequence to load an absolute 64-bit value into rd */
static int emit_load_addr(struct dbi_page_ctx *ctx, uint32_t rd, uint64_t addr)
{
    uint32_t movs[4];
    int n = emit_mov_imm64(rd, addr, movs, 4);
    int i;
    if (n < 0) return -1;
    for (i = 0; i < n; i++) {
        if (emit(ctx, movs[i]) < 0) return -1;
    }
    return 0;
}

/* ---------- Intra-page branch resolver ----------
 *
 * When a conditional branch (CBZ/B.cond/TBZ) or a direct branch (B/BL)
 * targets an address on the SAME hooked page, we should jump to the GHOST
 * equivalent of that address rather than the original VA. Two reasons:
 *
 *  1) No UXN bounce. Jumping to original VA would trigger the fault handler
 *     again; Pass 3 redirects to ghost anyway. Saves one fault round-trip.
 *
 *  2) **Correctness** for out-of-range conditional branches. Our current
 *     expansion for out-of-range CBZ is (inverted-cbz skip; MOV X17,target;
 *     BR X17). That clobbers X17. But ART trampolines (e.g., imt_conflict)
 *     pass meaningful state in X17 (the IMT key), so clobbering it breaks
 *     downstream `mov x0, x17` semantics, causing artInvokeInterface crash.
 *     Intra-page jumps via ghost VA are always in range (ghost ≤ 32KB ≪
 *     1MB CBZ range), so no expansion needed → no reg clobber.
 *
 * Forward refs: offset_map[target_tidx] isn't filled yet at emit time.
 * We emit a placeholder and queue a pending_branch for post-pass patch.
 * Backward refs: offset_map is already filled, emit directly.
 */

static int is_intra_page(const struct dbi_page_ctx *ctx, uint64_t target)
{
    return target >= ctx->target_page &&
           target <  ctx->target_page + DBI_TARGET_SIZE;
}

static uint64_t intra_page_ghost_target(const struct dbi_page_ctx *ctx,
                                          uint64_t orig_target)
{
    uint32_t tidx = (uint32_t)((orig_target - ctx->target_page) >> 2);
    return ctx->ghost_page + (uint64_t)ctx->offset_map[tidx] * 4;
}

static int queue_pending_branch(struct dbi_page_ctx *ctx, int ghost_idx,
                                 uint32_t enc_template, uint16_t target_tidx,
                                 uint8_t kind)
{
    if (ctx->n_pending >= DBI_MAX_PENDING_BRANCHES) return -1;
    ctx->pending[ctx->n_pending].ghost_idx = ghost_idx;
    ctx->pending[ctx->n_pending].enc_template = enc_template;
    ctx->pending[ctx->n_pending].target_tidx = target_tidx;
    ctx->pending[ctx->n_pending].kind = kind;
    ctx->n_pending++;
    return 0;
}

/* ---------- Per-category recompilation ---------- */

/* B (imm26) */
static int recomp_b(struct dbi_page_ctx *ctx, uint32_t insn, uint64_t orig_pc)
{
    int64_t imm26 = sign_extend64(insn & 0x03FFFFFFU, 26);
    uint64_t target = orig_pc + (imm26 << 2);
    uint32_t enc;

    /* Intra-page: jump to ghost equivalent of the target. Ghost region is
     * small (<32KB), always fits B's ±128MB range, and avoids the X17
     * clobber that far-jump expansion would need. This is CRITICAL for
     * ART trampolines (e.g. imt_conflict_trampoline) where X17 carries
     * the IMT key across the function body. */
    if (is_intra_page(ctx, target)) {
        uint32_t tidx = (uint32_t)((target - ctx->target_page) >> 2);
        uint32_t this_tidx = (uint32_t)((orig_pc - ctx->target_page) >> 2);
        if (tidx < this_tidx) {
            /* Backward — offset_map filled; emit direct B to ghost VA */
            uint64_t gtarget = intra_page_ghost_target(ctx, target);
            int64_t delta = (int64_t)(gtarget - ghost_cur_pc(ctx));
            if (enc_b(delta, &enc) == 0) {
                ctx->intra_page_fixed++;
                return emit(ctx, enc);
            }
        } else {
            /* Forward — queue backpatch with kind=3 (B imm26) */
            int ghost_idx = ctx->ghost_count;
            uint32_t tpl = 0x14000000U;  /* B, imm26=0 placeholder */
            if (emit(ctx, tpl) < 0) return -1;
            if (queue_pending_branch(ctx, ghost_idx, tpl, (uint16_t)tidx, 3) < 0)
                return -1;
            ctx->intra_page_fixed++;
            return 0;
        }
    }

    /* Inter-page or forward intra-page fallback */
    {
        uint64_t new_pc = ghost_cur_pc(ctx);
        int64_t delta = (int64_t)(target - new_pc);
        if (enc_b(delta, &enc) == 0) {
            ctx->fixed++;
            return emit(ctx, enc);
        }
    }
    ctx->expanded++;
    return emit_far_jump(ctx, target);
}

/* BL (imm26) — emit BL if in range, else MOV+BLR (scratch = target).
 * Note: BLR corrupts LR to point just after the BLR, same as BL would.
 */
static int recomp_bl(struct dbi_page_ctx *ctx, uint32_t insn, uint64_t orig_pc)
{
    int64_t imm26 = sign_extend64(insn & 0x03FFFFFFU, 26);
    uint64_t target = orig_pc + (imm26 << 2);
    uint64_t new_pc = ghost_cur_pc(ctx);
    int64_t delta = (int64_t)(target - new_pc);
    uint32_t enc;
    if (enc_bl(delta, &enc) == 0) {
        ctx->fixed++;
        return emit(ctx, enc);
    }
    ctx->expanded++;
    /* Fallback: MOVZ/MOVK X17 + BLR X17 */
    {
        uint32_t movs[4];
        int n = emit_mov_imm64(DBI_SCRATCH_REG, target, movs, 4);
        int i;
        if (n < 0) return -1;
        for (i = 0; i < n; i++) {
            if (emit(ctx, movs[i]) < 0) return -1;
        }
        /* BLR X17 */
        return emit(ctx, 0xD63F0000U | ((uint32_t)DBI_SCRATCH_REG << 5));
    }
}

/* B.cond imm19 */
static int recomp_bcond(struct dbi_page_ctx *ctx, uint32_t insn, uint64_t orig_pc)
{
    int64_t imm19 = sign_extend64((insn >> 5) & 0x7FFFFU, 19);
    uint64_t target = orig_pc + (imm19 << 2);
    uint32_t cond = insn & 0xFU;
    uint32_t enc;

    if (is_intra_page(ctx, target)) {
        uint32_t tidx = (uint32_t)((target - ctx->target_page) >> 2);
        uint32_t this_tidx = (uint32_t)((orig_pc - ctx->target_page) >> 2);
        if (tidx < this_tidx) {
            /* Backward — offset_map[tidx] is filled earlier this pass */
            uint64_t gtarget = intra_page_ghost_target(ctx, target);
            int64_t delta = (int64_t)(gtarget - ghost_cur_pc(ctx));
            if (enc_b_cond(cond, delta, &enc) == 0) {
                ctx->intra_page_fixed++;
                return emit(ctx, enc);
            }
        } else {
            /* Forward — queue backpatch. Template imm19=0. */
            int ghost_idx = ctx->ghost_count;
            uint32_t tpl = 0x54000000U | (cond & 0xFU);
            if (emit(ctx, tpl) < 0) return -1;
            if (queue_pending_branch(ctx, ghost_idx, tpl, (uint16_t)tidx, 0) < 0)
                return -1;
            ctx->intra_page_fixed++;
            return 0;
        }
    }

    /* Inter-page or in-page with unsatisfiable range — use original flow */
    {
        uint64_t new_pc = ghost_cur_pc(ctx);
        int64_t delta = (int64_t)(target - new_pc);
        if (enc_b_cond(cond, delta, &enc) == 0) {
            ctx->fixed++;
            return emit(ctx, enc);
        }
    }

    ctx->expanded++;
    {
        int bcond_idx = ctx->ghost_count;
        uint32_t placeholder = 0;
        int after_idx;
        int64_t skip_delta;
        if (emit(ctx, placeholder) < 0) return -1;
        if (emit_far_jump(ctx, target) < 0) return -1;
        after_idx = ctx->ghost_count;
        skip_delta = (int64_t)((after_idx - bcond_idx) * 4);
        if (enc_b_cond(cond ^ 1U, skip_delta, &enc) < 0) return -1;
        ctx->ghost[bcond_idx] = enc;
        return 0;
    }
}

/* CBZ / CBNZ imm19 */
static int recomp_cbz(struct dbi_page_ctx *ctx, uint32_t insn, uint64_t orig_pc)
{
    int is_nz = (insn & (1U << 24)) != 0;
    int sf = (insn >> 31) & 1U;
    uint32_t rt = insn & 0x1FU;
    int64_t imm19 = sign_extend64((insn >> 5) & 0x7FFFFU, 19);
    uint64_t target = orig_pc + (imm19 << 2);
    uint32_t enc;

    if (is_intra_page(ctx, target)) {
        uint32_t tidx = (uint32_t)((target - ctx->target_page) >> 2);
        uint32_t this_tidx = (uint32_t)((orig_pc - ctx->target_page) >> 2);
        if (tidx < this_tidx) {
            /* Backward — offset_map[tidx] is filled */
            uint64_t gtarget = intra_page_ghost_target(ctx, target);
            int64_t delta = (int64_t)(gtarget - ghost_cur_pc(ctx));
            if (enc_cbz(sf, rt, delta, is_nz, &enc) == 0) {
                ctx->intra_page_fixed++;
                return emit(ctx, enc);
            }
        } else {
            /* Forward — queue backpatch. Template: sf|op|01101|rt, imm19=0 */
            int ghost_idx = ctx->ghost_count;
            uint32_t op = is_nz ? 0x35000000U : 0x34000000U;
            uint32_t tpl = op | ((sf & 1U) << 31) | (rt & 0x1FU);
            if (emit(ctx, tpl) < 0) return -1;
            if (queue_pending_branch(ctx, ghost_idx, tpl, (uint16_t)tidx, 1) < 0)
                return -1;
            ctx->intra_page_fixed++;
            return 0;
        }
    }

    /* Original out-of-range flow */
    {
        uint64_t new_pc = ghost_cur_pc(ctx);
        int64_t delta = (int64_t)(target - new_pc);
        if (enc_cbz(sf, rt, delta, is_nz, &enc) == 0) {
            ctx->fixed++;
            return emit(ctx, enc);
        }
    }

    ctx->expanded++;
    {
        int pl_idx = ctx->ghost_count;
        int after_idx;
        int64_t skip_delta;
        if (emit(ctx, 0) < 0) return -1;
        if (emit_far_jump(ctx, target) < 0) return -1;
        after_idx = ctx->ghost_count;
        skip_delta = (int64_t)((after_idx - pl_idx) * 4);
        if (enc_cbz(sf, rt, skip_delta, !is_nz, &enc) < 0) return -1;
        ctx->ghost[pl_idx] = enc;
        return 0;
    }
}

/* TBZ / TBNZ imm14 */
static int recomp_tbz(struct dbi_page_ctx *ctx, uint32_t insn, uint64_t orig_pc)
{
    int is_nz = (insn & (1U << 24)) != 0;
    uint32_t rt = insn & 0x1FU;
    uint32_t b5 = (insn >> 31) & 1U;
    uint32_t b40 = (insn >> 19) & 0x1FU;
    uint32_t bit = (b5 << 5) | b40;
    int64_t imm14 = sign_extend64((insn >> 5) & 0x3FFFU, 14);
    uint64_t target = orig_pc + (imm14 << 2);
    uint32_t enc;

    if (is_intra_page(ctx, target)) {
        uint32_t tidx = (uint32_t)((target - ctx->target_page) >> 2);
        uint32_t this_tidx = (uint32_t)((orig_pc - ctx->target_page) >> 2);
        if (tidx < this_tidx) {
            uint64_t gtarget = intra_page_ghost_target(ctx, target);
            int64_t delta = (int64_t)(gtarget - ghost_cur_pc(ctx));
            if (enc_tbz(rt, bit, delta, is_nz, &enc) == 0) {
                ctx->intra_page_fixed++;
                return emit(ctx, enc);
            }
        } else {
            /* Forward — queue. TBZ template: op|b5|01101|b40|imm14=0|rt */
            int ghost_idx = ctx->ghost_count;
            uint32_t op = is_nz ? 0x37000000U : 0x36000000U;
            uint32_t tpl = op | (b5 << 31) | (b40 << 19) | (rt & 0x1FU);
            if (emit(ctx, tpl) < 0) return -1;
            if (queue_pending_branch(ctx, ghost_idx, tpl, (uint16_t)tidx, 2) < 0)
                return -1;
            ctx->intra_page_fixed++;
            return 0;
        }
    }

    /* Original flow */
    {
        uint64_t new_pc = ghost_cur_pc(ctx);
        int64_t delta = (int64_t)(target - new_pc);
        if (enc_tbz(rt, bit, delta, is_nz, &enc) == 0) {
            ctx->fixed++;
            return emit(ctx, enc);
        }
    }

    ctx->expanded++;
    {
        int pl_idx = ctx->ghost_count;
        int after_idx;
        int64_t skip_delta;
        if (emit(ctx, 0) < 0) return -1;
        if (emit_far_jump(ctx, target) < 0) return -1;
        after_idx = ctx->ghost_count;
        skip_delta = (int64_t)((after_idx - pl_idx) * 4);
        if (enc_tbz(rt, bit, skip_delta, !is_nz, &enc) < 0) return -1;
        ctx->ghost[pl_idx] = enc;
        return 0;
    }
}

/* ADRP: compute absolute page address = (pc & ~0xFFF) + (imm21 << 12) */
static int recomp_adrp(struct dbi_page_ctx *ctx, uint32_t insn, uint64_t orig_pc)
{
    uint32_t rd = insn & 0x1FU;
    uint64_t immlo = (insn >> 29) & 0x3U;
    uint64_t immhi = (insn >> 5) & 0x7FFFFU;
    int64_t imm21 = sign_extend64((immhi << 2) | immlo, 21);
    uint64_t target = (orig_pc & ~0xFFFULL) + ((uint64_t)imm21 << 12);
    ctx->expanded++;
    return emit_load_addr(ctx, rd, target);
}

/* ADR: compute PC + imm21 */
static int recomp_adr(struct dbi_page_ctx *ctx, uint32_t insn, uint64_t orig_pc)
{
    uint32_t rd = insn & 0x1FU;
    uint64_t immlo = (insn >> 29) & 0x3U;
    uint64_t immhi = (insn >> 5) & 0x7FFFFU;
    int64_t imm21 = sign_extend64((immhi << 2) | immlo, 21);
    uint64_t target = orig_pc + (uint64_t)imm21;
    ctx->expanded++;
    return emit_load_addr(ctx, rd, target);
}

/* LDR literal — integer register.
 *   variant 0: LDR Wt (32-bit unsigned load into Xt zero-extended)
 *   variant 1: LDR Xt (64-bit)
 *   variant 2: LDRSW Xt (32-bit sign-extended to 64-bit)
 * All three replaced by MOVZ/MOVK load addr → LDR/LDRSW [X17]. */
static int recomp_ldr_lit(struct dbi_page_ctx *ctx, uint32_t insn, uint64_t orig_pc,
                           int variant)
{
    uint32_t rt = insn & 0x1FU;
    int64_t imm19 = sign_extend64((insn >> 5) & 0x7FFFFU, 19);
    uint64_t data_addr = orig_pc + (imm19 << 2);
    uint32_t ldr;
    ctx->expanded++;
    if (emit_load_addr(ctx, DBI_SCRATCH_REG, data_addr) < 0) return -1;
    if (variant == 2)
        ldr = enc_ldrsw_imm_unsigned(rt, DBI_SCRATCH_REG);
    else if (variant == 0)
        ldr = enc_ldr_imm_unsigned(rt, DBI_SCRATCH_REG, 2);
    else
        ldr = enc_ldr_imm_unsigned(rt, DBI_SCRATCH_REG, 3);
    return emit(ctx, ldr);
}

/* LDR literal — SIMD&FP register. Opcode in bits[31:30]:
 *   00 → Sd (32-bit float / single)
 *   01 → Dd (64-bit double)
 *   10 → Qd (128-bit quad)
 *   11 → reserved (treat as fail)
 * Load PC-relative data addr into X17, then use SIMD unsigned-immediate LDR. */
static int recomp_ldr_vec_lit(struct dbi_page_ctx *ctx, uint32_t insn,
                                uint64_t orig_pc)
{
    uint32_t rt = insn & 0x1FU;
    uint32_t opc = (insn >> 30) & 0x3U;
    int64_t imm19 = sign_extend64((insn >> 5) & 0x7FFFFU, 19);
    uint64_t data_addr = orig_pc + (imm19 << 2);
    uint32_t ldr;
    if (opc == 3) return -1;  /* reserved encoding */
    ctx->expanded++;
    if (emit_load_addr(ctx, DBI_SCRATCH_REG, data_addr) < 0) return -1;
    ldr = enc_ldr_vec_imm_unsigned(rt, DBI_SCRATCH_REG, opc);
    return emit(ctx, ldr);
}

/* ---------- Main recompile loop ---------- */

int dbi_recompile_page(struct dbi_page_ctx *ctx)
{
    int i;
    if (!ctx || !ctx->orig || !ctx->ghost) return -1;
    if (ctx->ghost_capacity < DBI_TARGET_INSNS) return -1;

    ctx->ghost_count = 0;
    ctx->fixed = 0;
    ctx->expanded = 0;
    ctx->passthrough = 0;
    ctx->failed = 0;
    ctx->intra_page_fixed = 0;
    ctx->n_pending = 0;

    for (i = 0; i < DBI_TARGET_INSNS; i++) {
        uint32_t insn = ctx->orig[i];
        uint64_t orig_pc = ctx->target_page + (uint64_t)(i * 4);
        int rc = 0;
        int prev_ghost_idx = ctx->ghost_count;

        ctx->offset_map[i] = (uint16_t)prev_ghost_idx;

        /* NOP — pass through */
        if (insn == 0xD503201FU) {
            ctx->passthrough++;
            rc = emit(ctx, insn);
        }
        /* B (0) / BL (1) imm26 — top 6 bits 0b00010 1 or 1 00101 */
        else if ((insn & 0xFC000000U) == 0x14000000U) {
            rc = recomp_b(ctx, insn, orig_pc);
        }
        else if ((insn & 0xFC000000U) == 0x94000000U) {
            rc = recomp_bl(ctx, insn, orig_pc);
        }
        /* B.cond imm19 */
        else if ((insn & 0xFF000010U) == 0x54000000U) {
            rc = recomp_bcond(ctx, insn, orig_pc);
        }
        /* CBZ/CBNZ */
        else if ((insn & 0x7E000000U) == 0x34000000U) {
            rc = recomp_cbz(ctx, insn, orig_pc);
        }
        /* TBZ/TBNZ */
        else if ((insn & 0x7E000000U) == 0x36000000U) {
            rc = recomp_tbz(ctx, insn, orig_pc);
        }
        /* ADRP */
        else if ((insn & 0x9F000000U) == 0x90000000U) {
            rc = recomp_adrp(ctx, insn, orig_pc);
        }
        /* ADR */
        else if ((insn & 0x9F000000U) == 0x10000000U) {
            rc = recomp_adr(ctx, insn, orig_pc);
        }
        /* LDR (literal) 32-bit */
        else if ((insn & 0xFF000000U) == 0x18000000U) {
            rc = recomp_ldr_lit(ctx, insn, orig_pc, 0);
        }
        /* LDR (literal) 64-bit */
        else if ((insn & 0xFF000000U) == 0x58000000U) {
            rc = recomp_ldr_lit(ctx, insn, orig_pc, 1);
        }
        /* LDRSW literal — 32-bit load, sign-extend to 64-bit Xt.
         * Variant 2: use enc_ldrsw_imm_unsigned to preserve sign extension. */
        else if ((insn & 0xFF000000U) == 0x98000000U) {
            rc = recomp_ldr_lit(ctx, insn, orig_pc, 2);
        }
        /* PRFM literal — drop to NOP (prefetch is a hint, safe to omit) */
        else if ((insn & 0xFF000000U) == 0xD8000000U) {
            ctx->expanded++;
            rc = emit(ctx, enc_nop());
        }
        /* LDR SIMD literal — 32/64/128-bit float/double/Q load, PC-relative.
         * Encoding pattern (bits 31..24): opc[1:0] 0 1 1 1 0 0.
         * Check bits[29:24] = 011100 exactly. */
        else if ((insn & 0x3F000000U) == 0x1C000000U) {
            rc = recomp_ldr_vec_lit(ctx, insn, orig_pc);
        }
        /* Everything else — pass through */
        else {
            ctx->passthrough++;
            rc = emit(ctx, insn);
        }

        if (rc < 0) {
            ctx->failed++;
            /* rewind to pre-failure state */
            ctx->ghost_count = prev_ghost_idx;
            /* At minimum emit a NOP to keep offset_map consistent */
            if (emit(ctx, enc_nop()) < 0) return -1;
        }
    }

    /* Backpatch forward intra-page conditional branches with final ghost PC */
    {
        int p;
        for (p = 0; p < ctx->n_pending; p++) {
            struct dbi_pending_branch *b = &ctx->pending[p];
            uint64_t target_ghost = ctx->ghost_page +
                (uint64_t)ctx->offset_map[b->target_tidx] * 4;
            uint64_t patch_pc = ctx->ghost_page + (uint64_t)b->ghost_idx * 4;
            int64_t delta = (int64_t)(target_ghost - patch_pc);
            uint32_t enc;

            if (b->kind == 0) {
                /* B.cond: imm19 in bits[23:5] */
                int64_t imm19 = delta / 4;
                if (imm19 < -(1LL << 18) || imm19 >= (1LL << 18)) {
                    /* Shouldn't happen — ghost is tiny. Fall back to NOP
                     * (equivalent to skipping the branch; will misbehave). */
                    ctx->ghost[b->ghost_idx] = enc_nop();
                    ctx->failed++;
                    continue;
                }
                enc = b->enc_template |
                      (((uint32_t)imm19 & 0x7FFFFU) << 5);
            } else if (b->kind == 1) {
                /* CBZ/CBNZ: imm19 in bits[23:5] */
                int64_t imm19 = delta / 4;
                if (imm19 < -(1LL << 18) || imm19 >= (1LL << 18)) {
                    ctx->ghost[b->ghost_idx] = enc_nop();
                    ctx->failed++;
                    continue;
                }
                enc = b->enc_template |
                      (((uint32_t)imm19 & 0x7FFFFU) << 5);
            } else if (b->kind == 2) {
                /* TBZ/TBNZ: imm14 in bits[18:5] */
                int64_t imm14 = delta / 4;
                if (imm14 < -(1LL << 13) || imm14 >= (1LL << 13)) {
                    ctx->ghost[b->ghost_idx] = enc_nop();
                    ctx->failed++;
                    continue;
                }
                enc = b->enc_template |
                      (((uint32_t)imm14 & 0x3FFFU) << 5);
            } else {
                /* kind=3: B imm26 */
                int64_t imm26 = delta / 4;
                if (imm26 < -(1LL << 25) || imm26 >= (1LL << 25)) {
                    ctx->ghost[b->ghost_idx] = enc_nop();
                    ctx->failed++;
                    continue;
                }
                enc = b->enc_template | ((uint32_t)imm26 & 0x03FFFFFFU);
            }
            ctx->ghost[b->ghost_idx] = enc;
        }
    }

    return 0;
}

uint64_t dbi_target_to_ghost_pc(const struct dbi_page_ctx *ctx,
                                 uint64_t target_pc)
{
    uint64_t off;
    unsigned idx;
    if (target_pc < ctx->target_page) return 0;
    off = target_pc - ctx->target_page;
    if (off >= DBI_TARGET_SIZE) return 0;
    idx = (unsigned)(off >> 2);
    return ctx->ghost_page + ((uint64_t)ctx->offset_map[idx] << 2);
}

int dbi_patch_ghost(struct dbi_page_ctx *ctx,
                    unsigned target_off,
                    const uint32_t *patch,
                    int patch_count)
{
    unsigned idx;
    int ghost_idx;
    int i;
    if (target_off >= DBI_TARGET_SIZE) return -1;
    idx = target_off >> 2;
    ghost_idx = (int)ctx->offset_map[idx];
    if (ghost_idx + patch_count > ctx->ghost_capacity) return -1;
    for (i = 0; i < patch_count; i++) {
        ctx->ghost[ghost_idx + i] = patch[i];
    }
    return 0;
}
