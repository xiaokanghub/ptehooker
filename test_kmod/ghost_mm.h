/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ghost_mm.h - VMA-less ghost page allocation for Plan C
 *
 * Allocates a physical page in the kernel, then installs a PTE that
 * maps it into the TARGET PROCESS's address space at a user VA close
 * to the hook target - WITHOUT creating a vm_area_struct.
 *
 * Because there is no VMA:
 *   - /proc/pid/maps and smaps will not show the ghost page
 *   - get_user_pages / find_vma walks will not return it
 *   - fork's copy_page_range won't copy it (no VMA)
 *   - exit_mmap won't reap it (no VMA), so we MUST free it explicitly
 *
 * The ghost must be in ±128MB of the hook target so in-range B/BL
 * fixups succeed without needing full far-jump expansion.
 */

#ifndef _GHOST_MM_H
#define _GHOST_MM_H

#include <ktypes.h>

struct task_struct;
struct mm_struct;

struct ghost_page {
    struct task_struct *task;
    struct mm_struct   *mm;
    unsigned long       vaddr;         /* VA in target mm (user space) */
    unsigned long       kaddr;         /* Kernel VA for writes (linear map) */
    unsigned long       pfn;           /* physical page frame number */
    uint64_t            installed_pte; /* PTE value for first page */
    int                 order;         /* allocation order (0=4KB, 1=8KB, etc.) */
    unsigned long       alloc_size;    /* total bytes */
    int                 installed;
};

/*
 * Runtime kernel function pointers resolved via kallsyms_lookup_name.
 * ghost_mm needs these to do its work; the caller resolves them once
 * at module init and passes them in via ghost_mm_init.
 */
struct ghost_mm_syms {
    unsigned long (*get_free_pages)(unsigned int gfp_mask, unsigned int order);
    void          (*free_pages)(unsigned long addr, unsigned int order);
    void         *(*find_vma)(struct mm_struct *mm, unsigned long addr);
    int           (*apply_to_page_range)(struct mm_struct *mm,
                                         unsigned long addr,
                                         unsigned long size,
                                         int (*fn)(void *pte, unsigned long addr, void *data),
                                         void *data);
    /*
     * Pointer to the kernel's `physvirt_offset` variable (arm64 5.4+).
     * phys = kva + *physvirt_offset_p   (for linear-map VAs)
     */
    const int64_t *physvirt_offset_p;

    /* Optional: used by ghost_free to drain concurrent CPU execution in the
     * ghost before reclaiming physical pages. If NULL, ghost_free falls back
     * to a short udelay() which is best-effort only. */
    void (*on_each_cpu)(void (*fn)(void *), void *arg, int wait);
};

void ghost_mm_init(const struct ghost_mm_syms *syms);

/*
 * ghost_alloc - allocate a kernel page and install it as a no-VMA PTE
 *               in the target process's address space near `near`.
 *
 * @task:          target task_struct
 * @mm:            target mm_struct
 * @near:          preferred virtual address (typically target_page); the
 *                 allocator will search ±range for an empty slot
 * @range:         max search distance in bytes
 * @pte_template:  existing user-exec PTE value from the same process
 *                 (used to copy permission/attribute bits); the PFN
 *                 field of this value is replaced with the new page
 * @num_pages:     number of contiguous 4KB pages (1, 2, 4, 8 etc.)
 * @out:           filled on success
 *
 * Returns 0 on success, negative errno on failure.
 */
int ghost_alloc(struct task_struct *task,
                struct mm_struct   *mm,
                unsigned long       near,
                unsigned long       range,
                uint64_t            pte_template,
                int                 num_pages,
                struct ghost_page  *out);

/*
 * ghost_free - remove the ghost PTE and release the backing page.
 * Performs TLB flush automatically.
 */
int ghost_free(struct ghost_page *gp);

/*
 * ghost_write - memcpy `len` bytes from @src into the ghost at @offset
 *               (offset within the page). Uses the kernel linear VA so
 *               it's writable even though the user PTE is exec-only.
 */
int ghost_write(struct ghost_page *gp,
                unsigned offset,
                const void *src,
                unsigned len);

/*
 * ghost_sync_icache - flush I-cache for the ghost page after writing
 *                      new code, so CPU fetches the new instructions.
 */
void ghost_sync_icache(struct ghost_page *gp);

#endif /* _GHOST_MM_H */
