/* SPDX-License-Identifier: GPL-2.0 */
/*
 * dbi_kern.h - Kernel-side Dynamic Binary Instrumentation for ARM64
 *
 * Recompiles a target 4KB code page into ghost memory, fixing up all
 * PC-relative instructions (B/BL, B.cond, CBZ, TBZ, ADR, ADRP, LDR literal).
 *
 * Uses an offset map so the fault handler can translate an arbitrary PC
 * within the target page to the corresponding PC within ghost (needed
 * because some instructions expand from 1 word to many).
 */

#ifndef _DBI_KERN_H
#define _DBI_KERN_H

#include <ktypes.h>

/*
 * Worst-case expansion factor per instruction:
 *   - ADRP / ADR     → up to 4 MOV insns
 *   - LDR literal    → 4 MOV + 1 LDR = 5 insns
 *   - B.cond/CBZ/TBZ → 1 B.cond + 5 far-jump = 6 insns
 * Budget 8 words per input word, so a 4KB page can need up to 32KB ghost.
 */
#define DBI_TARGET_SIZE      4096
#define DBI_TARGET_INSNS     (DBI_TARGET_SIZE / 4)   /* 1024 */
#define DBI_GHOST_MAX_INSNS  (DBI_TARGET_INSNS * 8)  /* 8192 worst case */
#define DBI_GHOST_MAX_BYTES  (DBI_GHOST_MAX_INSNS * 4)

/* Scratch register used for far jumps (X17 / IP1) */
#define DBI_SCRATCH_REG      17

/* Deferred backpatch entry for forward intra-page conditional branches.
 * At emit time we don't know the forward target's ghost position yet,
 * so we emit placeholder and finalize in a post-pass. */
struct dbi_pending_branch {
    int       ghost_idx;                        /* word slot in ghost to patch */
    uint32_t  enc_template;                     /* opcode bits WITHOUT imm19; imm19=0 */
    uint16_t  target_tidx;                      /* target word index in target_page */
    uint8_t   kind;                             /* 0=B.cond, 1=CBZ, 2=TBZ */
};

#define DBI_MAX_PENDING_BRANCHES 512

/*
 * dbi_page_ctx - state for recompiling one 4KB target page into ghost memory.
 *
 * The offset_map is dense: offset_map[i] == word-index in ghost where the
 * i-th original instruction was placed. Used by the fault handler to
 * redirect (target_pc → ghost_pc) on every fault.
 */
struct dbi_page_ctx {
    uint64_t  target_page;                      /* VA of target page in user mm */
    uint64_t  ghost_page;                       /* VA of ghost page in user mm */

    const uint32_t *orig;                       /* 1024 words of target code (kernel copy) */
    uint32_t *ghost;                            /* output buffer (kernel writable) */
    int       ghost_capacity;                   /* words */
    int       ghost_count;                      /* words actually used */

    uint16_t  offset_map[DBI_TARGET_INSNS];     /* target word idx → ghost word idx */

    struct dbi_pending_branch pending[DBI_MAX_PENDING_BRANCHES];
    int       n_pending;

    int       fixed;                            /* direct in-place fixups */
    int       expanded;                         /* expansions to multi-insn sequences */
    int       passthrough;                      /* no PC-rel, pass through */
    int       failed;                           /* gave up on some insn */
    int       intra_page_fixed;                 /* intra-page branch kept as single insn */
};

/*
 * dbi_recompile_page - recompile one 4KB target page into ghost.
 *
 * The target_page/ghost_page fields must already be set to the VAs where
 * the original code lives and where the ghost will live. orig/ghost
 * pointers are temporary kernel buffers for copying the bytes.
 *
 * Returns 0 on success, negative on error.
 */
int dbi_recompile_page(struct dbi_page_ctx *ctx);

/*
 * dbi_target_to_ghost_pc - translate a target PC to the corresponding
 *                          ghost PC, using the offset map.
 *
 * The far-address from a fault is floor-aligned to 4 bytes (instruction
 * boundary). If it's not within the target page, returns 0.
 */
uint64_t dbi_target_to_ghost_pc(const struct dbi_page_ctx *ctx,
                                 uint64_t target_pc);

/*
 * dbi_patch_ghost - overwrite a specific target-offset region in the ghost
 *                    with replacement instructions (e.g. MOV w0,#1; RET).
 *
 * @ctx:           recompiled context
 * @target_off:    byte offset within target page (the function entry)
 * @patch:         replacement instructions
 * @patch_count:   number of 32-bit words in @patch
 *
 * Uses the offset map to find the correct ghost offset, then writes the
 * patch at that location.  Returns 0 on success, -1 on error.
 */
int dbi_patch_ghost(struct dbi_page_ctx *ctx,
                    unsigned target_off,
                    const uint32_t *patch,
                    int patch_count);

#endif /* _DBI_KERN_H */
