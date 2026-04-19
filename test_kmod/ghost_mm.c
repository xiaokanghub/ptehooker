/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ghost_mm.c - VMA-less ghost page allocator (Plan C)
 *
 * Key idea: use apply_to_page_range() to force allocation of the PUD/PMD/PTE
 * hierarchy for an unused user VA, then fill the new PTE with our own
 * physical page. Since we never created a vm_area_struct, the ghost is
 * invisible to /proc/pid/maps, ptrace via access_process_vm, and other VMA
 * walkers.
 *
 * Kernel 5.4 compatible.
 */

#include <compiler.h>
#include <ktypes.h>
#include <linux/sched.h>
#include <barrier.h>
#include "ghost_mm.h"

/*
 * KP's linux headers give us an empty stub for vm_area_struct; the real
 * kernel layout (5.4 arm64) starts with vm_start/vm_end. Alias to that.
 */
struct vma_head {
    unsigned long vm_start;
    unsigned long vm_end;
};

/* Local errno codes (KP's ktypes doesn't pull in asm-generic/errno.h) */
#define EPERM       1
#define ENOMEM      12
#define EFAULT      14
#define EEXIST      17
#define EINVAL      22
#define ENOSPC      28
#define ENOSYS      38

#define GFP_KERNEL_FLAG   0xcc0  /* GFP_KERNEL = ___GFP_RECLAIM | __GFP_IO | __GFP_FS */
#define GFP_ZERO_FLAG     0x100  /* __GFP_ZERO */

#define ARM64_PFN_MASK    (0x0000FFFFFFFFF000UL)   /* bits [47:12] */

/* PTE bits - mirror of KP's pgtable.h, inlined to avoid linear_voffset dep */
#define PTE_VALID       (1UL << 0)
#define PTE_TYPE_PAGE   (3UL << 0)
#define PTE_AF          (1UL << 10)
#define PTE_UXN         (1UL << 54)

static struct ghost_mm_syms g_syms;

void ghost_mm_init(const struct ghost_mm_syms *syms)
{
    g_syms = *syms;
}

/* ---------- find_hole_near ---------- */

/*
 * Look for a 4KB hole in `mm` near `near`, within ±range bytes.
 * A "hole" here means: find_vma returns a VMA whose vm_start is past
 * (addr + PAGE_SIZE), OR find_vma returns NULL.
 *
 * We alternate +stride / -stride to stay as close to `near` as possible.
 */
/* Check if a given VA already has a valid PTE (user ghost or real VMA).
 * Returns 1 if occupied, 0 if free. */
static int pte_occupied_cb(void *pte, unsigned long addr, void *data)
{
    uint64_t *p = (uint64_t *)pte;
    int *out = (int *)data;
    if (*p & 1UL /* PTE_VALID */) *out = 1;
    return 0;
}

static int vaddr_is_occupied(struct mm_struct *mm, unsigned long va)
{
    int occupied = 0;
    if (g_syms.apply_to_page_range)
        g_syms.apply_to_page_range(mm, va, 0x1000,
                                     pte_occupied_cb, &occupied);
    return occupied;
}

/*
 * VMA-walk based gap finder: iterate through VMAs in [near-range, near+range],
 * picking the closest 4KB gap to near_page. O(VMAs_in_range) instead of
 * O(range/4KB). For dense processes (e.g. aweme with 7000+ VMAs) this is
 * orders of magnitude faster than the previous step-based scan.
 */
static unsigned long find_hole_near(struct mm_struct *mm,
                                     unsigned long near,
                                     unsigned long range,
                                     int num_pages)
{
    unsigned long need = (unsigned long)num_pages * 0x1000;
    unsigned long near_page = near & ~0xFFFUL;
    unsigned long lo = near_page > range ? near_page - range : 0;
    unsigned long hi = near_page + range;
    unsigned long best = 0, best_dist = ~0UL;
    unsigned long addr = lo;
    struct vma_head *vma;

    if (!g_syms.find_vma) return 0;
    if (num_pages <= 0) return 0;

    while (addr < hi) {
        unsigned long gap_start, gap_end, cand, d;

        vma = (struct vma_head *)g_syms.find_vma(mm, addr);
        if (!vma || vma->vm_start >= hi) {
            /* Tail gap from addr to hi */
            gap_start = addr;
            gap_end = hi;
        } else if (vma->vm_start > addr) {
            /* Gap before this VMA */
            gap_start = addr;
            gap_end = vma->vm_start;
        } else {
            /* addr is inside a VMA; jump past it */
            addr = vma->vm_end;
            continue;
        }

        /* Require gap to fit all num_pages contiguously */
        if (gap_end - gap_start >= need) {
            /* Candidate: closest page in gap to near_page, but leaving room
             * for all num_pages pages within the gap. */
            if (near_page >= gap_start && near_page + need <= gap_end)
                cand = near_page;
            else if (near_page < gap_start)
                cand = gap_start;
            else
                cand = gap_end - need;

            d = (cand > near_page) ? cand - near_page : near_page - cand;
            if (d < best_dist && !vaddr_is_occupied(mm, cand)) {
                best_dist = d;
                best = cand;
            }
        }

        if (!vma || vma->vm_start >= hi) break;
        addr = vma->vm_end;
    }
    return best;
}

/* ---------- PTE install callback ---------- */

struct install_ctx {
    uint64_t pte_val;       /* value to write into *pte */
    int      written;
};

static int install_pte_cb(void *pte, unsigned long addr, void *data)
{
    struct install_ctx *c = (struct install_ctx *)data;
    uint64_t *p = (uint64_t *)pte;

    /* Only write if empty (safety). If occupied we refuse. */
    if (*p != 0 && (*p & PTE_VALID)) {
        return -EEXIST;
    }

    *p = c->pte_val;
    c->written = 1;
    return 0;
}

struct clear_ctx {
    int cleared;
};

static int clear_pte_cb(void *pte, unsigned long addr, void *data)
{
    struct clear_ctx *c = (struct clear_ctx *)data;
    uint64_t *p = (uint64_t *)pte;
    *p = 0;
    c->cleared = 1;
    return 0;
}

/* ---------- Public API ---------- */

/* Compute allocation order from page count (must be power of 2) */
static int pages_to_order(int n)
{
    int order = 0;
    while ((1 << order) < n) order++;
    return order;
}

int ghost_alloc(struct task_struct *task,
                struct mm_struct   *mm,
                unsigned long       near,
                unsigned long       range,
                uint64_t            pte_template,
                int                 num_pages,
                struct ghost_page  *out)
{
    unsigned long kva;
    unsigned long vaddr;
    uint64_t pa_base;
    uint64_t new_pte;
    int order;
    int i, ret;

    if (!g_syms.get_free_pages || !g_syms.apply_to_page_range) return -ENOSYS;
    if (!out || num_pages <= 0) return -EINVAL;
    if (!g_syms.physvirt_offset_p) return -ENOSYS;

    order = pages_to_order(num_pages);

    /* Step 1: allocate 2^order contiguous physical pages */
    kva = g_syms.get_free_pages(GFP_KERNEL_FLAG | GFP_ZERO_FLAG, order);
    if (!kva) return -ENOMEM;
    pa_base = (uint64_t)((int64_t)kva + *g_syms.physvirt_offset_p);

    /* Step 2: find a contiguous hole for 2^order pages (rounded up from num_pages) */
    vaddr = find_hole_near(mm, near, range, 1 << order);
    if (!vaddr) {
        g_syms.free_pages(kva, order);
        return -ENOSPC;
    }

    /* Step 3+4: install PTEs for each page */
    for (i = 0; i < (1 << order); i++) {
        uint64_t page_pa = pa_base + (uint64_t)i * 0x1000;
        struct install_ctx ictx;

        new_pte = (pte_template & ~ARM64_PFN_MASK) | (page_pa & ARM64_PFN_MASK);
        new_pte |= PTE_VALID | PTE_TYPE_PAGE | PTE_AF;
        new_pte &= ~PTE_UXN;
        /* Clear GP (Guarded Page, bit 50) inherited from libart r-xp template.
         * BTI enforcement disabled on ghost. */
        new_pte &= ~(1UL << 50);  /* PTE_GP */
        /* Clear AP[2] (bit 7) to make ghost WRITABLE.
         * libart r-xp template has AP[2]=1 (RO). Shellcode that writes to
         * the ghost page (e.g. log buffer in second half) needs writable.
         * Ghost pages are purely ours, so full RWX is safe. */
        new_pte &= ~(1UL << 7);  /* PTE_RDONLY / AP[2] */

        ictx.pte_val = new_pte;
        ictx.written = 0;
        ret = g_syms.apply_to_page_range(mm, vaddr + (unsigned long)i * 0x1000,
                                          0x1000, install_pte_cb, &ictx);
        if (ret || !ictx.written) {
            /* Unwind already-installed PTEs */
            int j;
            for (j = 0; j < i; j++) {
                struct clear_ctx cc = { .cleared = 0 };
                g_syms.apply_to_page_range(mm, vaddr + (unsigned long)j * 0x1000,
                                            0x1000, clear_pte_cb, &cc);
            }
            g_syms.free_pages(kva, order);
            return ret ? ret : -EFAULT;
        }
    }

    /* Step 5: TLB flush */
    asm volatile(
        "dsb ishst\n\t"
        "tlbi vmalle1is\n\t"
        "dsb ish\n\t"
        "isb\n\t"
        ::: "memory"
    );

    out->task = task;
    out->mm = mm;
    out->vaddr = vaddr;
    out->kaddr = kva;
    out->pfn = pa_base >> 12;
    out->installed_pte = new_pte;
    out->order = order;
    out->alloc_size = (unsigned long)(1 << order) * 0x1000;
    out->installed = 1;
    return 0;
}

/* Noop IPI handler — we only need the side effect: all CPUs briefly take
 * interrupt, draining any in-progress user-mode execution in the ghost. */
static void ghost_free_drain_ipi(void *arg)
{
    (void)arg;
    asm volatile(
        "ic ialluis\n\t"      /* invalidate I-cache on this CPU (inner-shareable propagates) */
        "dsb ish\n\t"
        "isb\n\t"
        ::: "memory"
    );
}

int ghost_free(struct ghost_page *gp)
{
    int i, ret = 0;
    int page_count;

    if (!gp || !gp->installed) return 0;
    if (!g_syms.apply_to_page_range || !g_syms.free_pages) return -ENOSYS;

    page_count = 1 << gp->order;
    for (i = 0; i < page_count; i++) {
        struct clear_ctx cctx = { .cleared = 0 };
        g_syms.apply_to_page_range(gp->mm, gp->vaddr + (unsigned long)i * 0x1000,
                                    0x1000, clear_pte_cb, &cctx);
    }

    /* Step 1: TLB broadcast — future fetches can't re-enter ghost via PTE. */
    asm volatile(
        "dsb ishst\n\t"
        "tlbi vmalle1is\n\t"
        "dsb ish\n\t"
        "ic ialluis\n\t"         /* invalidate I-cache inner-shareable */
        "dsb ish\n\t"
        "isb\n\t"
        ::: "memory"
    );

    /* Step 2: Drain — IPI all CPUs synchronously. Each CPU handling the IPI
     * goes through exception entry, which on ARM64 guarantees it has
     * finished fetching the next user instruction from non-cached memory.
     * Combined with I-cache invalidation above, no CPU can be executing
     * from the ghost physical pages by the time on_each_cpu returns.
     *
     * If on_each_cpu isn't available, fall back to best-effort (a TLB
     * broadcast + ISB at least serialises the calling CPU; other CPUs may
     * still briefly hold stale I-cache lines). */
    if (g_syms.on_each_cpu) {
        g_syms.on_each_cpu(ghost_free_drain_ipi, NULL, 1);
    }

    /* Step 3: Safe to free physical pages */
    g_syms.free_pages(gp->kaddr, gp->order);

    gp->installed = 0;
    gp->kaddr = 0;
    gp->vaddr = 0;
    return 0;
}

int ghost_write(struct ghost_page *gp,
                unsigned offset,
                const void *src,
                unsigned len)
{
    const uint8_t *s = src;
    uint8_t *d;
    unsigned i;
    if (!gp || !gp->installed) return -EINVAL;
    if (offset + len > gp->alloc_size) return -EINVAL;
    d = (uint8_t *)(gp->kaddr + offset);
    for (i = 0; i < len; i++) d[i] = s[i];
    return 0;
}

void ghost_sync_icache(struct ghost_page *gp)
{
    unsigned long start, end, line;
    if (!gp || !gp->installed) return;
    /*
     * For a VA alias (kernel kaddr vs user vaddr pointing to same PFN),
     * we must:
     *   1. Clean D-cache line-by-line (by kaddr) to PoU → pushes writes
     *      from D-cache to the point where I-cache can see them.
     *   2. Invalidate I-cache globally (inner-shareable) so the user VA
     *      fetches the fresh code.
     *   3. Barrier + ISB to serialize.
     */
    start = gp->kaddr;
    end   = gp->kaddr + gp->alloc_size;
    /* Cache line size = 64 bytes on Cortex-A cores (safe assumption) */
    for (line = start & ~63UL; line < end; line += 64) {
        asm volatile("dc cvau, %0" :: "r"(line) : "memory");
    }
    asm volatile(
        "dsb ish\n\t"
        "ic ialluis\n\t"
        "dsb ish\n\t"
        "isb\n\t"
        ::: "memory"
    );
}
