/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ptehook_planc_v2.c - Pure kernel Plan C hook framework
 *
 * Upgrade of ptehook_planc.c from Plan A (userspace DBI + mmap ghost)
 * to Plan C (kernel DBI + no-VMA ghost PTE injection).
 *
 * Demo does NOTHING except report the target function address; all the
 * heavy lifting happens in kernel:
 *
 *   1. Read 4KB of target page from user mm (access_process_vm)
 *   2. dbi_recompile_page() → relocated code in a kernel buffer
 *   3. ghost_alloc() → install no-VMA PTE in target mm, ±16MB from target
 *   4. memcpy recompiled code into the ghost page (via kernel VA)
 *   5. Overwrite entry instructions with MOV w0,#1; RET
 *   6. ghost_sync_icache()
 *   7. Set UXN on target PTE, TLB flush
 *   8. hook_wrap3(do_mem_abort) — already installed
 *
 * On fault, do_mem_abort before-hook redirects regs->pc:
 *   ghost_pc = dbi_target_to_ghost_pc(ctx, far)
 *
 * Commands (via kpm ctl0):
 *   install <pid> <addr>               — manual one-shot install
 *   watch <pid> <libname.so> <offset>  — auto-install when .so is mmaped
 *   remove                             — clear UXN + unhook
 *   stat                               — query state + fault counters
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <common.h>
#include <kputils.h>
#include <kallsyms.h>
#include <hook.h>
#include <stdarg.h>
#include <linux/sched.h>
#include <asm/current.h>

#include "dbi_kern.h"
#include "ghost_mm.h"

KPM_NAME("ptehook-planc-v2");
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("ptehook");
KPM_DESCRIPTION("Pure kernel Plan C: DBI + no-VMA ghost");

/* ---------- snprintf wrapper ---------- */

typedef int (*vsnprintf_t)(char *buf, size_t size, const char *fmt, va_list args);
static vsnprintf_t g_vsnprintf = 0;

static int my_snprintf(char *buf, size_t size, const char *fmt, ...)
{
    va_list ap;
    int ret = 0;
    if (!g_vsnprintf || size == 0) {
        if (size) buf[0] = 0;
        return 0;
    }
    va_start(ap, fmt);
    ret = g_vsnprintf(buf, size, fmt, ap);
    va_end(ap);
    return ret;
}
#define snprintf my_snprintf

/* ---------- Kernel symbols ---------- */

typedef void *(*find_vpid_t)(int);
typedef struct task_struct *(*pid_task_t)(void *, int);
typedef int (*access_process_vm_t)(struct task_struct *tsk,
                                    unsigned long addr,
                                    void *buf, int len,
                                    unsigned int gup_flags);
typedef struct mm_struct *(*get_task_mm_t)(struct task_struct *);
typedef void (*mmput_t)(struct mm_struct *);
typedef int (*pte_fn_t)(void *pte, unsigned long addr, void *data);
typedef int (*apply_to_page_range_t)(struct mm_struct *mm,
                                      unsigned long address,
                                      unsigned long size,
                                      pte_fn_t fn, void *data);
typedef unsigned long (*get_free_pages_t)(unsigned int, unsigned int);
typedef void (*free_pages_t)(unsigned long, unsigned int);
typedef void *(*find_vma_t)(struct mm_struct *, unsigned long);
typedef int (*task_pid_nr_ns_t)(struct task_struct *, int, void *);
typedef int (*schedule_work_t)(void *work);
typedef void (*rb_erase_t)(void *node, void *root);
typedef void (*on_each_cpu_t)(void (*fn)(void *), void *arg, int wait);

static find_vpid_t           fn_find_vpid;
static pid_task_t            fn_pid_task;
static access_process_vm_t   fn_access_process_vm;
static get_task_mm_t         fn_get_task_mm;
static mmput_t               fn_mmput;
static apply_to_page_range_t fn_apply_to_page_range;
static get_free_pages_t      fn_get_free_pages;
static free_pages_t          fn_free_pages;
static find_vma_t            fn_find_vma;
static const int64_t        *ptr_physvirt_offset;
static task_pid_nr_ns_t      fn_task_pid_nr_ns;
static schedule_work_t       fn_schedule_work;
static rb_erase_t            fn_rb_erase;
static on_each_cpu_t         fn_on_each_cpu;

static void *addr_do_mem_abort;
static void *addr_do_mmap;

#define FOLL_WRITE  0x01
#define FOLL_FORCE  0x10
#define PROT_EXEC   0x04

/*
 * struct file layout offsets for 5.4 arm64 (QCOM GKI):
 *   file + 16  → f_path (struct path)
 *   path + 8   → dentry
 *   dentry + 32 → d_name (struct qstr)
 *   qstr + 8   → name (const char *)
 */
#define OFF_FILE_FPATH   16
#define OFF_PATH_DENTRY   8
#define OFF_DENTRY_DNAME 32
#define OFF_QSTR_NAME     8

/* ---------- Hook state ---------- */

#define WATCH_SO_MAX  64

/*
 * Minimal work_struct compatible layout for 5.4 arm64:
 *   struct work_struct {
 *       atomic_long_t data;    // offset 0, size 8
 *       struct list_head entry; // offset 8, size 16
 *       work_func_t func;     // offset 24, size 8
 *   };
 * Total = 32 bytes
 */
struct mini_work {
    unsigned long data;
    unsigned long entry[2];
    void (*func)(struct mini_work *);
};

struct watch_state {
    int           active;
    int           target_pid;
    char          so_name[WATCH_SO_MAX];
    unsigned long func_offset;
    int           mmap_hooked;
    int           installed;
    /* Deferred install via work queue */
    int           pending_pid;
    unsigned long pending_addr;
    struct mini_work work;
};

#define GHOST_POOL_MAX  64
#define JAVA_HOOK_MAX   128
#define UXN_HOOK_MAX    16
#define REDIRECT_MAX    32

struct ghost_pool_entry {
    int                used;
    int                pid;
    struct ghost_page  gp;
};

struct java_hook_entry {
    int            used;
    int            pid;
    unsigned long  art_method;
    unsigned       entry_offset;
    uint64_t       orig_entry;
    uint64_t       new_entry;
};

/*
 * UXN-based inline hook slot (replaces byte-patch for libart.so internal hooks).
 *
 * When a target address is hooked:
 *   - Target 4KB page is DBI-recompiled into ghost (VMA-less)
 *   - Target PTE gets UXN set → exec fault on any access
 *   - fault handler: if far == target_addr → PC = replace_addr (hook fires)
 *                    if far != target_addr → PC = ghost pc (normal code runs)
 *   - backup (for LSPlant) = ghost_addr + target_offset_in_ghost
 *     LSPlant calls backup → jumps directly to ghost code (no UXN trigger),
 *     executes original function logic
 */
struct uxn_hook_slot {
    int               used;
    int               pid;
    unsigned long     target_addr;      /* exact hook point */
    unsigned long     target_page;      /* target_addr & ~0xFFF */
    unsigned long     replace_addr;     /* user's hook function */
    uint64_t          saved_pte;        /* original PTE for restore */

    /* DBI state for the target page */
    uint32_t          orig_buf[DBI_TARGET_INSNS];
    uint32_t          ghost_buf[DBI_GHOST_MAX_INSNS];
    struct dbi_page_ctx dbi;

    /* Ghost memory holding recompiled code */
    struct ghost_page gp;

    unsigned long     fault_hits;
    unsigned long     last_pass3_far;     /* Last FAR that hit Pass 3 (DBI fallthrough) */
    unsigned long     last_pass3_new_pc;  /* Corresponding ghost PC redirect */
    unsigned long     pass3_hits;         /* Count of Pass 3 redirects */
};

struct plan_c_v2 {
    int  hook_installed;   /* do_mem_abort hook_wrap3 installed */
    int  armed;            /* UXN set, fault handler active */

    int           pid;
    unsigned long target_addr;
    unsigned long target_page;
    uint64_t      saved_target_pte;

    /* Kernel DBI state */
    uint32_t           page_orig[DBI_TARGET_INSNS];
    uint32_t           page_ghost[DBI_GHOST_MAX_INSNS];
    struct dbi_page_ctx dbi;

    /* Ghost page (VMA-less) for native hook */
    struct ghost_page   gp;

    /* Extra ghost pool for LSPlant/Java hook (independent of UXN hook) */
    struct ghost_pool_entry ghost_pool[GHOST_POOL_MAX];

    /* Java hook table (ArtMethod.entry_point replacements) */
    struct java_hook_entry java_hooks[JAVA_HOOK_MAX];

    /* UXN inline hook table (for libart.so internal fn hooks) */
    struct uxn_hook_slot uxn_hooks[UXN_HOOK_MAX];

    /* Lightweight redirect table: extra (target→replace) entries that
     * ride on existing UXN-hooked pages (no new DBI/ghost needed). */
    struct redirect_entry {
        int used;
        int pid;
        unsigned long target_addr;
        unsigned long replace_addr;
    } redirects[REDIRECT_MAX];

    /* Auto-watch */
    struct watch_state  watch;

    /* Counters */
    unsigned long fault_hits;
    unsigned long fault_others;

    /* Debug (written from handler) */
    unsigned long dbg_far;
    unsigned long dbg_esr;
    unsigned long dbg_old_pc;
    unsigned long dbg_new_pc;
};

static struct plan_c_v2 g_h;

/* ---------- String parsing ---------- */

static unsigned long parse_num(const char **sp)
{
    unsigned long v = 0;
    const char *s = *sp;
    while (*s == ' ' || *s == '\t') s++;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
        while (*s) {
            if (*s >= '0' && *s <= '9') v = v * 16 + (*s - '0');
            else if (*s >= 'a' && *s <= 'f') v = v * 16 + (*s - 'a' + 10);
            else if (*s >= 'A' && *s <= 'F') v = v * 16 + (*s - 'A' + 10);
            else break;
            s++;
        }
    } else {
        while (*s >= '0' && *s <= '9') {
            v = v * 10 + (*s - '0'); s++;
        }
    }
    *sp = s;
    return v;
}

static int str_starts_with(const char *s, const char *prefix)
{
    while (*prefix) {
        if (*s != *prefix) return 0;
        s++; prefix++;
    }
    return 1;
}

/* ---------- File name extraction from struct file * ---------- */

static const char *file_get_name(void *filep)
{
    unsigned long dentry;
    unsigned long qstr_name_ptr;
    if (!filep) return 0;
    /* file->f_path.dentry */
    dentry = *(unsigned long *)((char *)filep + OFF_FILE_FPATH + OFF_PATH_DENTRY);
    if (!dentry) return 0;
    /* dentry->d_name.name */
    qstr_name_ptr = *(unsigned long *)((char *)dentry + OFF_DENTRY_DNAME + OFF_QSTR_NAME);
    return (const char *)qstr_name_ptr;
}

static int str_ends_with(const char *s, const char *suffix)
{
    int slen = 0, xlen = 0;
    const char *p;
    for (p = s; *p; p++) slen++;
    for (p = suffix; *p; p++) xlen++;
    if (xlen > slen) return 0;
    s += slen - xlen;
    while (*suffix) {
        if (*s++ != *suffix++) return 0;
    }
    return 1;
}

/* Forward declaration */
static int cmd_install(int pid, unsigned long addr, char *buf, int size);

/* Deferred install work function — runs outside mmap_sem */
static void deferred_install_work(struct mini_work *w)
{
    static char wbuf[4096];
    int pid = g_h.watch.pending_pid;
    unsigned long addr = g_h.watch.pending_addr;

    if (!pid || !addr || g_h.watch.installed) return;

    pr_info("ptehook-planc-v2: deferred install pid=%d addr=0x%lx\n", pid, addr);
    g_h.watch.installed = 1;
    cmd_install(pid, addr, wbuf, sizeof(wbuf));
    pr_info("ptehook-planc-v2: deferred result: %s\n", wbuf);
}

/* ---------- do_mmap after hook (auto-watch) ---------- */

/*
 * do_mmap(file, addr, len, prot, flags, vm_flags, pgoff, *populate, *uf)
 * After callback: fargs->ret = mapped addr (or error), fargs->arg0 = file
 */
static void before_do_mmap(hook_fargs9_t *fargs, void *udata) { }

static void after_do_mmap(hook_fargs9_t *fargs, void *udata)
{
    unsigned long ret_addr;
    unsigned long prot;
    void *filep;
    const char *fname;
    int cur_pid;

    if (!g_h.watch.active || g_h.watch.installed) return;

    ret_addr = (unsigned long)fargs->ret;
    /* IS_ERR_VALUE: top bits set → error */
    if (ret_addr > (unsigned long)-4096UL) return;

    filep = (void *)fargs->arg0;
    prot  = (unsigned long)fargs->arg3;
    if (!filep) return;

    /* Only care about executable mappings (code segment) */
    if (!(prot & PROT_EXEC)) return;

    (void)cur_pid;

    fname = file_get_name(filep);
    if (!fname) return;

    /* Match .so name */
    if (!str_ends_with(fname, g_h.watch.so_name)) return;

    /* HIT: can't install here (mmap_sem held → deadlock).
     * Save info and schedule deferred install via work queue. */
    {
        unsigned long func_addr = ret_addr + g_h.watch.func_offset;
        int real_pid = 0;

        if (fn_task_pid_nr_ns)
            real_pid = fn_task_pid_nr_ns(current, 0, 0);

        pr_info("ptehook-planc-v2: WATCH HIT! %s @ 0x%lx func=0x%lx pid=%d\n",
                 fname, ret_addr, func_addr, real_pid);

        g_h.watch.pending_pid = real_pid;
        g_h.watch.pending_addr = func_addr;
        /* Install will happen on next ctl0 call (avoids mmap_sem deadlock) */
    }
}

/* ---------- Fault handler ---------- */

static void after_do_mem_abort(hook_fargs3_t *fargs, void *udata) { }

static void before_do_mem_abort(hook_fargs3_t *fargs, void *udata)
{
    unsigned long far = fargs->arg0;
    unsigned long esr = fargs->arg1;
    void *regs_vp = (void *)fargs->arg2;
    unsigned int ec, ifsc;
    unsigned long *pc_ptr;
    uint64_t new_pc;
    unsigned long far_page;
    int i;

    ec = (esr >> 26) & 0x3F;
    if (ec != 0x20) return;  /* Not Instruction Abort from lower EL */

    ifsc = esr & 0x3F;
    if (ifsc < 0x0C || ifsc > 0x0F) return;  /* Not permission fault */

    far_page = far & ~0xFFFUL;
    pc_ptr = (unsigned long *)((char *)regs_vp + 0x100);

    /* Get current task's PID — only apply slots matching this pid.
     * Prevents stale state from a previous APP incarnation from being
     * applied to a new APP process (which may have remapped libart.so
     * at the same VA but with different ghost/mm state). */
    int cur_pid = 0;
    if (fn_task_pid_nr_ns)
        cur_pid = fn_task_pid_nr_ns(current, 0, 0);

    /* Pass 1: Redirect table (lightweight target→replace entries) */
    for (i = 0; i < REDIRECT_MAX; i++) {
        struct redirect_entry *r = &g_h.redirects[i];
        if (!r->used) continue;
        if (cur_pid && r->pid != cur_pid) continue;
        if ((far & ~3UL) == (r->target_addr & ~3UL)) {
            *pc_ptr = r->replace_addr;
            fargs->skip_origin = 1;
            return;
        }
    }

    /* Pass 2: UXN slots exact target match (hook trigger) */
    for (i = 0; i < UXN_HOOK_MAX; i++) {
        struct uxn_hook_slot *s = &g_h.uxn_hooks[i];
        if (!s->used) continue;
        if (cur_pid && s->pid != cur_pid) continue;
        if (s->target_page != far_page) continue;
        if ((far & ~3UL) == (s->target_addr & ~3UL)) {
            *pc_ptr = s->replace_addr;
            fargs->skip_origin = 1;
            s->fault_hits++;
            return;
        }
    }

    /* Pass 3: UXN slots same-page ghost redirect (normal code on hooked page) */
    for (i = 0; i < UXN_HOOK_MAX; i++) {
        struct uxn_hook_slot *s = &g_h.uxn_hooks[i];
        if (!s->used) continue;
        if (cur_pid && s->pid != cur_pid) continue;
        if (s->target_page != far_page) continue;
        new_pc = dbi_target_to_ghost_pc(&s->dbi, far);
        if (new_pc) {
            *pc_ptr = new_pc;
            fargs->skip_origin = 1;
            s->fault_hits++;
            s->pass3_hits++;
            s->last_pass3_far = far;
            s->last_pass3_new_pc = new_pc;
            return;
        }
    }

    /* Fallback to the legacy single-hook path */
    if (!g_h.armed) return;
    if (far_page != g_h.target_page) {
        g_h.fault_others++;
        return;
    }

    new_pc = dbi_target_to_ghost_pc(&g_h.dbi, far);
    if (!new_pc) {
        g_h.fault_others++;
        return;
    }

    g_h.dbg_far = far;
    g_h.dbg_esr = esr;
    g_h.dbg_old_pc = *pc_ptr;
    g_h.dbg_new_pc = new_pc;

    *pc_ptr = new_pc;
    fargs->skip_origin = 1;
    g_h.fault_hits++;
}

/* ---------- PTE read/set_uxn callback ---------- */

struct pte_op {
    int mode;                /* 0=read, 1=set_uxn, 2=restore */
    uint64_t *out_val;
    uint64_t orig_val;
};

static int pte_op_cb(void *pte, unsigned long addr, void *data)
{
    struct pte_op *ctx = (struct pte_op *)data;
    uint64_t *p = (uint64_t *)pte;
    uint64_t val = *p;
    if (ctx->out_val) *ctx->out_val = val;
    if (ctx->mode == 1)      *p = val | (1UL << 54);
    else if (ctx->mode == 2) *p = ctx->orig_val;
    return 0;
}

static struct task_struct *find_task(int pid)
{
    void *pidp;
    if (!fn_find_vpid || !fn_pid_task) return 0;
    pidp = fn_find_vpid(pid);
    if (!pidp) return 0;
    return fn_pid_task(pidp, 0);
}

/* ---------- Commands ---------- */

/*
 * install <pid> <addr>
 *   Read target page, DBI recompile, alloc ghost with PTE injection,
 *   copy recompiled code into ghost, patch entry with MOV w0,#1 RET,
 *   set UXN on target, hook do_mem_abort if not already.
 */
static int cmd_install(int pid, unsigned long addr, char *buf, int size)
{
    int off = 0;
    struct task_struct *task;
    struct mm_struct *mm;
    unsigned long target_page = addr & ~0xFFFUL;
    unsigned long page_off = addr & 0xFFFUL;
    struct pte_op pop;
    uint64_t tpte;
    int r;
    hook_err_t herr;
    uint32_t patch[2] = { 0x52800020U, 0xD65F03C0U };  /* MOV w0,#1; RET */

    off += snprintf(buf + off, size - off,
                     "=== INSTALL (Plan C v2) ===\n"
                     "pid=%d addr=0x%lx target_page=0x%lx offset=0x%lx\n\n",
                     pid, addr, target_page, page_off);

    if (g_h.armed) {
        off += snprintf(buf + off, size - off,
                         "[FAIL] already armed, remove first\n");
        return off;
    }

    task = find_task(pid);
    if (!task) return off + snprintf(buf + off, size - off, "[FAIL] task\n");

    mm = fn_get_task_mm(task);
    if (!mm) return off + snprintf(buf + off, size - off, "[FAIL] mm\n");

    /* 1. Read original target page into kernel buffer */
    r = fn_access_process_vm(task, target_page, g_h.page_orig,
                              DBI_TARGET_SIZE, FOLL_FORCE);
    if (r != DBI_TARGET_SIZE) {
        fn_mmput(mm);
        return off + snprintf(buf + off, size - off,
                               "[FAIL] read target page: %d\n", r);
    }
    off += snprintf(buf + off, size - off,
                     "[PASS] target page read (%d bytes)\n", r);

    /* 2. Read target's existing PTE to use as template */
    pop.mode = 0;
    pop.out_val = &tpte;
    r = fn_apply_to_page_range(mm, target_page, 0x1000, pte_op_cb, &pop);
    if (r) {
        fn_mmput(mm);
        return off + snprintf(buf + off, size - off,
                               "[FAIL] read target PTE: %d\n", r);
    }
    off += snprintf(buf + off, size - off,
                     "[PASS] target PTE = 0x%lx (UXN=%d)\n",
                     tpte, (int)((tpte >> 54) & 1));

    /* 3. Pre-recompile to figure out ghost size (into temp buffer first) */
    g_h.dbi.target_page = target_page;
    g_h.dbi.ghost_page  = 0; /* dummy, just need the count */
    g_h.dbi.orig        = g_h.page_orig;
    g_h.dbi.ghost       = g_h.page_ghost;
    g_h.dbi.ghost_capacity = DBI_GHOST_MAX_INSNS;
    r = dbi_recompile_page(&g_h.dbi);
    if (r) {
        fn_mmput(mm);
        return off + snprintf(buf + off, size - off,
                               "[FAIL] dbi pre-recompile: %d\n", r);
    }
    {
        int ghost_bytes = g_h.dbi.ghost_count * 4;
        int ghost_pages = (ghost_bytes + 0xFFF) >> 12;
        if (ghost_pages < 1) ghost_pages = 1;
        off += snprintf(buf + off, size - off,
                         "[PASS] DBI pre-scan: %d words = %d bytes → %d ghost pages\n",
                         g_h.dbi.ghost_count, ghost_bytes, ghost_pages);

        /* 3b. Allocate ghost pages near target (±16MB) */
        r = ghost_alloc(task, mm, target_page, 512UL << 20, tpte,
                        ghost_pages, &g_h.gp);
    if (r) {
        fn_mmput(mm);
        return off + snprintf(buf + off, size - off,
                               "[FAIL] ghost_alloc: %d\n", r);
    }
    off += snprintf(buf + off, size - off,
                     "[PASS] ghost @ user=0x%lx kva=0x%lx size=%lu\n",
                     g_h.gp.vaddr, g_h.gp.kaddr, g_h.gp.alloc_size);

    /* 4. Re-run DBI with ACTUAL ghost_page VA for correct PC-relative fixup */
    g_h.dbi.target_page = target_page;
    g_h.dbi.ghost_page  = g_h.gp.vaddr;
    g_h.dbi.orig        = g_h.page_orig;
    g_h.dbi.ghost       = g_h.page_ghost;
    g_h.dbi.ghost_capacity = DBI_GHOST_MAX_INSNS;
    r = dbi_recompile_page(&g_h.dbi);
    if (r) {
        ghost_free(&g_h.gp);
        fn_mmput(mm);
        return off + snprintf(buf + off, size - off,
                               "[FAIL] dbi_recompile: %d\n", r);
    }
    off += snprintf(buf + off, size - off,
                     "[PASS] DBI: fixed=%d expanded=%d pass=%d failed=%d ghost_words=%d\n",
                     g_h.dbi.fixed, g_h.dbi.expanded,
                     g_h.dbi.passthrough, g_h.dbi.failed,
                     g_h.dbi.ghost_count);
    }

    /* 5. Patch the entry with MOV w0,#1; RET */
    r = dbi_patch_ghost(&g_h.dbi, (unsigned)page_off, patch, 2);
    if (r) {
        ghost_free(&g_h.gp);
        fn_mmput(mm);
        return off + snprintf(buf + off, size - off,
                               "[FAIL] patch ghost: %d\n", r);
    }

    /* 6. Copy recompiled code into the ghost page */
    r = ghost_write(&g_h.gp, 0, g_h.page_ghost,
                    g_h.dbi.ghost_count * 4);
    if (r) {
        ghost_free(&g_h.gp);
        fn_mmput(mm);
        return off + snprintf(buf + off, size - off,
                               "[FAIL] ghost_write: %d\n", r);
    }
    off += snprintf(buf + off, size - off,
                     "[PASS] ghost code written (%d bytes)\n",
                     g_h.dbi.ghost_count * 4);

    /* 7. Sync I-cache */
    ghost_sync_icache(&g_h.gp);

    /* 8. Install do_mem_abort hook if not yet */
    if (!g_h.hook_installed) {
        g_h.armed = 0;
        asm volatile("dmb ish" ::: "memory");

        herr = hook_wrap3(addr_do_mem_abort, before_do_mem_abort,
                           after_do_mem_abort, 0);
        if (herr) {
            ghost_free(&g_h.gp);
            fn_mmput(mm);
            return off + snprintf(buf + off, size - off,
                                   "[FAIL] hook_wrap3: %d\n", (int)herr);
        }
        g_h.hook_installed = 1;
    }
    off += snprintf(buf + off, size - off,
                     "[PASS] do_mem_abort hooked\n");

    /* 9. Save state + activate handler */
    g_h.saved_target_pte = tpte;
    g_h.pid = pid;
    g_h.target_addr = addr;
    g_h.target_page = target_page;
    g_h.fault_hits = 0;
    g_h.fault_others = 0;
    g_h.armed = 1;
    asm volatile("dmb ish" ::: "memory");

    /* 10. Set UXN on target PTE */
    pop.mode = 1;
    pop.out_val = 0;
    r = fn_apply_to_page_range(mm, target_page, 0x1000, pte_op_cb, &pop);
    if (r) {
        g_h.armed = 0;
        ghost_free(&g_h.gp);
        fn_mmput(mm);
        return off + snprintf(buf + off, size - off,
                               "[FAIL] set UXN: %d\n", r);
    }

    /* 11. Flush TLB */
    asm volatile(
        "dsb ishst\n\t"
        "tlbi vmalle1is\n\t"
        "dsb ish\n\t"
        "isb\n\t"
        ::: "memory"
    );

    fn_mmput(mm);

    off += snprintf(buf + off, size - off,
                     "\n[OK] Plan C v2 armed\n"
                     "  target : 0x%lx  ghost : 0x%lx\n",
                     target_page, g_h.gp.vaddr);
    return off;
}

/* ---------- UXN-based inline hook (E.3: replaces byte-patch) ----------
 *
 * uxn-hook <pid> <target> <replace>
 *   1. Find free slot
 *   2. access_process_vm read 4KB target page → orig_buf
 *   3. ghost_alloc 8KB near target
 *   4. DBI recompile orig_buf → ghost_buf (offset_map)
 *   5. Write ghost_buf into ghost page via kaddr
 *   6. Read target PTE (template + save orig)
 *   7. Set UXN on target PTE + TLB flush
 *   8. Install do_mem_abort hook if not yet
 *
 * Return: on [OK] output includes backup=0x... (ghost + target offset in ghost).
 *   LSPlant calls backup → directly exec ghost (no UXN trigger) → original runs.
 */
static int find_uxn_slot(void)
{
    int i;
    for (i = 0; i < UXN_HOOK_MAX; i++)
        if (!g_h.uxn_hooks[i].used) return i;
    return -1;
}

static int find_uxn_slot_by_target(int pid, unsigned long target_addr)
{
    int i;
    for (i = 0; i < UXN_HOOK_MAX; i++) {
        if (g_h.uxn_hooks[i].used &&
            g_h.uxn_hooks[i].pid == pid &&
            g_h.uxn_hooks[i].target_addr == target_addr)
            return i;
    }
    return -1;
}

/* Reap stale UXN slots whose task no longer exists (e.g. old APP died). */
static void reap_dead_uxn_slots(void)
{
    int i;
    for (i = 0; i < UXN_HOOK_MAX; i++) {
        struct uxn_hook_slot *s = &g_h.uxn_hooks[i];
        if (!s->used) continue;
        struct task_struct *t = find_task(s->pid);
        if (!t) {
            /* Task is gone — ghost memory already reclaimed with the mm.
             * Just mark slot free, don't try to unmap anything. */
            s->used = 0;
        }
    }
}

/* Verify that a VA lies within an already UXN-hooked page (for pid).
 * Required because redirect entries only fire if the page is UXN'd. */
static int page_is_uxn_hooked(int pid, unsigned long addr)
{
    unsigned long page = addr & ~0xFFFUL;
    int i;
    for (i = 0; i < UXN_HOOK_MAX; i++) {
        struct uxn_hook_slot *s = &g_h.uxn_hooks[i];
        if (s->used && s->pid == pid && s->target_page == page) return 1;
    }
    return 0;
}

static int find_redirect_slot(void)
{
    int i;
    for (i = 0; i < REDIRECT_MAX; i++)
        if (!g_h.redirects[i].used) return i;
    return -1;
}

/* uxn-add-redirect <pid> <target> <replace>
 *   Adds a (target→replace) entry to the redirect table. target must lie
 *   within a page that's already UXN-hooked (so fault fires).
 *   Use case: ArtMethod.entry_point relocate to libart padding addr. */
static int cmd_uxn_add_redirect(int pid, unsigned long target,
                                 unsigned long replace,
                                 char *buf, int bsize)
{
    int off = 0;
    int slot;

    off += snprintf(buf + off, bsize - off,
                     "=== UXN-ADD-REDIRECT ===\n"
                     "pid=%d target=0x%lx replace=0x%lx\n",
                     pid, target, replace);

    if (!page_is_uxn_hooked(pid, target))
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] target page not UXN-hooked\n");

    slot = find_redirect_slot();
    if (slot < 0)
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] redirect table full\n");

    g_h.redirects[slot].used = 1;
    g_h.redirects[slot].pid = pid;
    g_h.redirects[slot].target_addr = target;
    g_h.redirects[slot].replace_addr = replace;

    return off + snprintf(buf + off, bsize - off,
                           "[OK] slot=%d\n", slot);
}

static int cmd_uxn_del_redirect(int pid, unsigned long target,
                                 char *buf, int bsize)
{
    int off = 0;
    int i, n = 0;
    off += snprintf(buf + off, bsize - off,
                     "=== UXN-DEL-REDIRECT ===\npid=%d target=0x%lx\n",
                     pid, target);
    for (i = 0; i < REDIRECT_MAX; i++) {
        struct redirect_entry *r = &g_h.redirects[i];
        if (r->used && r->pid == pid && r->target_addr == target) {
            r->used = 0;
            n++;
        }
    }
    return off + snprintf(buf + off, bsize - off,
                           "[OK] removed %d\n", n);
}

/* ---------- VMA hiding (unlink from process VMA tree/list) ----------
 *
 * Removes a VMA from mm->mmap list and mm->mm_rb rbtree WITHOUT freeing
 * PTEs or the vma struct itself. Effect:
 *   - /proc/<pid>/maps no longer shows the VMA
 *   - Existing PTEs remain valid → code pages still execute
 *   - find_vma won't find it (other kernel VMA walkers won't either)
 *
 * Limitations:
 *   - struct vma/pages leak until process exit (tiny amount)
 *   - If a code page gets swapped out, no VMA to re-fault → SIGSEGV (rare
 *     for .text pages which kernel usually keeps resident)
 *   - fork won't copy (child won't have the code)
 *   - mm->map_count becomes stale (may trigger kernel warnings, not fatal)
 *
 * mm_struct layout (5.4 ARM64):
 *   [+0x00] struct vm_area_struct *mmap
 *   [+0x08] struct rb_root mm_rb (one rb_node pointer)
 *
 * vm_area_struct layout (5.4 ARM64):
 *   [+0x00] unsigned long vm_start
 *   [+0x08] unsigned long vm_end
 *   [+0x10] struct vm_area_struct *vm_next
 *   [+0x18] struct vm_area_struct *vm_prev
 *   [+0x20] struct rb_node vm_rb (24 bytes)
 */
/* Kernel struct layout — default = 5.4 / 5.10 ARM64 (linked-list VMAs).
 * 6.1+ replaced linked-list + rbtree with maple tree; hide-vma cannot work
 * there without mt_erase support. Detection happens in planc2_init(). */
static struct {
    /* vm_area_struct */
    int off_vma_start;   /* stable across all versions (first field) */
    int off_vma_end;     /* stable */
    int off_vma_next;    /* removed in kernel 6.1 */
    int off_vma_prev;    /* removed in kernel 6.1 */
    int off_vma_rb;      /* removed in kernel 6.1 */
    /* mm_struct */
    int off_mm_mmap;     /* removed in 6.1 (replaced by mm_mt) */
    int off_mm_mm_rb;    /* removed in 6.1 */
    /* capability flags */
    int has_linked_list_vma;  /* 1 for <6.1; 0 for maple tree era */
} g_kl = {
    /* defaults for 5.4 ARM64 */
    .off_vma_start = 0x00,
    .off_vma_end   = 0x08,
    .off_vma_next  = 0x10,
    .off_vma_prev  = 0x18,
    .off_vma_rb    = 0x20,
    .off_mm_mmap   = 0x00,
    .off_mm_mm_rb  = 0x08,
    .has_linked_list_vma = 1,
};

#define OFF_MM_MMAP    g_kl.off_mm_mmap
#define OFF_MM_MM_RB   g_kl.off_mm_mm_rb
#define OFF_VMA_START  g_kl.off_vma_start
#define OFF_VMA_END    g_kl.off_vma_end
#define OFF_VMA_NEXT   g_kl.off_vma_next
#define OFF_VMA_PREV   g_kl.off_vma_prev
#define OFF_VMA_RB     g_kl.off_vma_rb

/* Probe kernel layout at init — detect maple tree vs linked list via
 * symbol presence. If `mt_erase` exists, we're on 6.1+ and hide-vma won't
 * work (would need maple tree ops). */
static void probe_kern_layout(void)
{
    if (!kallsyms_lookup_name) return;
    /* Maple tree erase function only exists in 6.1+ */
    if (kallsyms_lookup_name("mt_erase") != 0) {
        g_kl.has_linked_list_vma = 0;
        pr_info("ptehook-planc-v2: kernel >= 6.1 (maple tree) detected — "
                 "hide-vma will refuse; linked-list VMA fields invalid\n");
    } else {
        g_kl.has_linked_list_vma = 1;
        pr_info("ptehook-planc-v2: kernel < 6.1 (linked-list VMAs) — "
                 "5.4 offsets active\n");
    }
}

static int unlink_vma_raw(void *mm, void *vma)
{
    void *prev, *next;
    if (!fn_rb_erase) return -1;

    /* 1. Remove from rbtree */
    fn_rb_erase((char *)vma + OFF_VMA_RB,
                (char *)mm  + OFF_MM_MM_RB);

    /* 2. Unlink from doubly-linked list */
    prev = *(void **)((char *)vma + OFF_VMA_PREV);
    next = *(void **)((char *)vma + OFF_VMA_NEXT);

    if (prev) {
        *(void **)((char *)prev + OFF_VMA_NEXT) = next;
    } else {
        /* This VMA was the head of mm->mmap */
        *(void **)((char *)mm + OFF_MM_MMAP) = next;
    }
    if (next) {
        *(void **)((char *)next + OFF_VMA_PREV) = prev;
    }

    /* Leave vm_start/vm_end, vm_rb, vm_prev/vm_next — leaked, harmless */
    return 0;
}

/* hide-vma <pid> <vaddr>  — unlink the VMA containing vaddr */
static int cmd_hide_vma(int pid, unsigned long vaddr, char *buf, int bsize)
{
    int off = 0;
    struct task_struct *task;
    struct mm_struct *mm;
    void *vma;
    unsigned long vs, ve;

    off += snprintf(buf + off, bsize - off,
                     "=== HIDE-VMA ===\npid=%d vaddr=0x%lx\n", pid, vaddr);

    if (!g_kl.has_linked_list_vma)
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] kernel uses maple tree (>=6.1); "
                               "hide-vma not implemented for this layout\n");

    if (!fn_find_vma || !fn_rb_erase)
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] required syms missing\n");

    task = find_task(pid);
    if (!task) return off + snprintf(buf + off, bsize - off, "[FAIL] task\n");

    mm = fn_get_task_mm(task);
    if (!mm) return off + snprintf(buf + off, bsize - off, "[FAIL] mm\n");

    vma = fn_find_vma(mm, vaddr);
    if (!vma) {
        fn_mmput(mm);
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] no VMA at 0x%lx\n", vaddr);
    }

    vs = *(unsigned long *)((char *)vma + OFF_VMA_START);
    ve = *(unsigned long *)((char *)vma + OFF_VMA_END);

    if (vaddr < vs || vaddr >= ve) {
        fn_mmput(mm);
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] addr not in VMA [%lx-%lx]\n", vs, ve);
    }

    off += snprintf(buf + off, bsize - off,
                     "[INFO] VMA [%lx-%lx] vma_ptr=%lx\n",
                     vs, ve, (unsigned long)vma);

    unlink_vma_raw(mm, vma);
    fn_mmput(mm);

    off += snprintf(buf + off, bsize - off,
                     "[OK] unlinked (PTEs preserved)\n");
    return off;
}

/* hide-range <pid> <start> <end>  — hide all VMAs whose start/end falls in range */
static int cmd_hide_range(int pid, unsigned long start, unsigned long end,
                           char *buf, int bsize)
{
    int off = 0;
    struct task_struct *task;
    struct mm_struct *mm;
    void *vma;
    int n = 0;

    off += snprintf(buf + off, bsize - off,
                     "=== HIDE-RANGE ===\npid=%d [0x%lx-0x%lx]\n",
                     pid, start, end);

    if (!g_kl.has_linked_list_vma)
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] kernel uses maple tree (>=6.1); "
                               "hide-range not implemented\n");

    if (!fn_find_vma || !fn_rb_erase)
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] required syms missing\n");

    task = find_task(pid);
    if (!task) return off + snprintf(buf + off, bsize - off, "[FAIL] task\n");

    mm = fn_get_task_mm(task);
    if (!mm) return off + snprintf(buf + off, bsize - off, "[FAIL] mm\n");

    /* Walk: find_vma(start), unlink if in range, advance by saved vm_end */
    while ((vma = fn_find_vma(mm, start)) != NULL) {
        unsigned long vs = *(unsigned long *)((char *)vma + OFF_VMA_START);
        unsigned long ve = *(unsigned long *)((char *)vma + OFF_VMA_END);
        if (vs >= end) break;
        if (vs >= start && ve <= end) {
            off += snprintf(buf + off, bsize - off,
                             "  unlinking [%lx-%lx]\n", vs, ve);
            unlink_vma_raw(mm, vma);
            n++;
        }
        start = ve;
        if (start >= end) break;
    }
    fn_mmput(mm);

    off += snprintf(buf + off, bsize - off,
                     "[OK] unlinked %d VMAs\n", n);
    return off;
}

static int cmd_uxn_hook(int pid, unsigned long target, unsigned long replace,
                         char *buf, int bsize)
{
    int off = 0;
    int slot;
    struct task_struct *task;
    struct mm_struct *mm;
    struct uxn_hook_slot *s;
    unsigned long target_page = target & ~0xFFFUL;
    unsigned long page_offset = target & 0xFFFUL;
    struct pte_op pop;
    uint64_t tpte;
    hook_err_t herr;
    int r, ghost_pages;
    uint32_t patch[4];
    uint64_t backup_addr;

    off += snprintf(buf + off, bsize - off,
                     "=== UXN-HOOK ===\n"
                     "pid=%d target=0x%lx replace=0x%lx\n\n",
                     pid, target, replace);

    /* Reap any stale slots from dead processes */
    reap_dead_uxn_slots();

    /* Check for duplicate (same pid + target) */
    if (find_uxn_slot_by_target(pid, target) >= 0)
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] already hooked\n");

    slot = find_uxn_slot();
    if (slot < 0)
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] no free slot\n");
    s = &g_h.uxn_hooks[slot];

    task = find_task(pid);
    if (!task) return off + snprintf(buf + off, bsize - off, "[FAIL] task\n");

    mm = fn_get_task_mm(task);
    if (!mm) return off + snprintf(buf + off, bsize - off, "[FAIL] mm\n");

    /* 1. Read target page */
    r = fn_access_process_vm(task, target_page, s->orig_buf,
                              DBI_TARGET_SIZE, FOLL_FORCE);
    if (r != DBI_TARGET_SIZE) {
        fn_mmput(mm);
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] read target: %d\n", r);
    }

    /* 2. Read target PTE (save for restore + template for ghost) */
    pop.mode = 0;
    pop.out_val = &tpte;
    r = fn_apply_to_page_range(mm, target_page, 0x1000, pte_op_cb, &pop);
    if (r) {
        fn_mmput(mm);
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] pte read: %d\n", r);
    }

    /* 3. Pre-DBI to figure out size */
    s->dbi.target_page = target_page;
    s->dbi.ghost_page  = 0;  /* dummy */
    s->dbi.orig        = s->orig_buf;
    s->dbi.ghost       = s->ghost_buf;
    s->dbi.ghost_capacity = DBI_GHOST_MAX_INSNS;
    if (dbi_recompile_page(&s->dbi)) {
        fn_mmput(mm);
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] dbi pre: err\n");
    }
    ghost_pages = (s->dbi.ghost_count * 4 + 0xFFF) >> 12;
    if (ghost_pages < 1) ghost_pages = 1;

    /* 4. Alloc ghost — try near-libart first (±512MB keeps B/BL in-range,
     * avoids DBI expansion); fall back to wider (±8GB) if dense process
     * like aweme has no near gap. DBI will emit MOV+BLR for out-of-range. */
    r = ghost_alloc(task, mm, target_page, 512UL << 20, tpte,
                    ghost_pages, &s->gp);
    if (r == -28) {  /* -ENOSPC */
        r = ghost_alloc(task, mm, target_page, 8UL << 30, tpte,
                        ghost_pages, &s->gp);
    }
    if (r) {
        fn_mmput(mm);
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] ghost_alloc: %d\n", r);
    }

    /* 5. Re-DBI with real ghost addr */
    s->dbi.ghost_page = s->gp.vaddr;
    if (dbi_recompile_page(&s->dbi)) {
        ghost_free(&s->gp);
        fn_mmput(mm);
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] dbi final\n");
    }

    /* 6. Write ghost code */
    r = ghost_write(&s->gp, 0, s->ghost_buf, s->dbi.ghost_count * 4);
    if (r) {
        ghost_free(&s->gp);
        fn_mmput(mm);
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] ghost write\n");
    }

    /* backup addr: ghost + target's recompiled offset.
     * Needed by LSPlant: calling backup jumps directly to ghost code,
     * runs the original function (DBI-recompiled), returns normally.
     * NOTE: we do NOT patch the ghost with the replace redirect here;
     *       fault handler will redirect to replace_addr when far == target.
     */
    backup_addr = dbi_target_to_ghost_pc(&s->dbi, target);
    ghost_sync_icache(&s->gp);

    /* 7. Save slot state */
    s->used = 1;
    s->pid = pid;
    s->target_addr = target;
    s->target_page = target_page;
    s->replace_addr = replace;
    s->saved_pte = tpte;
    s->fault_hits = 0;
    s->pass3_hits = 0;
    s->last_pass3_far = 0;
    s->last_pass3_new_pc = 0;
    asm volatile("dmb ish" ::: "memory");

    /* 8. Install do_mem_abort hook if not yet */
    if (!g_h.hook_installed) {
        herr = hook_wrap3(addr_do_mem_abort, before_do_mem_abort,
                           after_do_mem_abort, 0);
        if (herr) {
            s->used = 0;
            ghost_free(&s->gp);
            fn_mmput(mm);
            return off + snprintf(buf + off, bsize - off,
                                   "[FAIL] hook_wrap3: %d\n", (int)herr);
        }
        g_h.hook_installed = 1;
    }

    /* 9. Set UXN on target PTE + flush TLB */
    pop.mode = 1;
    pop.out_val = 0;
    r = fn_apply_to_page_range(mm, target_page, 0x1000, pte_op_cb, &pop);
    if (r) {
        s->used = 0;
        ghost_free(&s->gp);
        fn_mmput(mm);
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] set UXN: %d\n", r);
    }

    asm volatile(
        "dsb ishst\n\t"
        "tlbi vmalle1is\n\t"
        "dsb ish\n\t"
        "isb\n\t"
        ::: "memory"
    );

    fn_mmput(mm);

    (void)patch; (void)page_offset;

    off += snprintf(buf + off, bsize - off,
                     "[OK] slot=%d ghost=0x%lx backup=0x%lx "
                     "dbi: fixed=%d expanded=%d\n",
                     slot, s->gp.vaddr, (unsigned long)backup_addr,
                     s->dbi.fixed, s->dbi.expanded);
    return off;
}

static int cmd_uxn_unhook(int pid, unsigned long target, char *buf, int bsize)
{
    int off = 0;
    int slot;
    struct uxn_hook_slot *s;
    struct task_struct *task;
    struct mm_struct *mm;
    struct pte_op pop;
    int r;

    off += snprintf(buf + off, bsize - off,
                     "=== UXN-UNHOOK ===\npid=%d target=0x%lx\n",
                     pid, target);

    slot = find_uxn_slot_by_target(pid, target);
    if (slot < 0)
        return off + snprintf(buf + off, bsize - off, "[FAIL] not hooked\n");
    s = &g_h.uxn_hooks[slot];

    /* Deactivate slot first */
    s->used = 0;
    asm volatile("dmb ish" ::: "memory");

    task = find_task(pid);
    if (task) {
        mm = fn_get_task_mm(task);
        if (mm) {
            /* Restore PTE */
            pop.mode = 2;
            pop.out_val = 0;
            pop.orig_val = s->saved_pte;
            r = fn_apply_to_page_range(mm, s->target_page, 0x1000,
                                         pte_op_cb, &pop);
            asm volatile(
                "dsb ishst\n\t"
                "tlbi vmalle1is\n\t"
                "dsb ish\n\t"
                "isb\n\t"
                ::: "memory"
            );
            (void)r;
            /* Free ghost */
            ghost_free(&s->gp);
            fn_mmput(mm);
        }
    }

    off += snprintf(buf + off, bsize - off,
                     "[OK] slot=%d hits=%lu\n", slot, s->fault_hits);
    return off;
}

/* uxn-list — dump all active UXN slots. Useful for spotting leaked/zombie
 * slots (e.g. from crashed sessions, PID reuse). */
static int cmd_uxn_list(char *buf, int bsize)
{
    int off = 0;
    int i, count = 0;
    off += snprintf(buf + off, bsize - off, "=== UXN-LIST ===\n");
    for (i = 0; i < UXN_HOOK_MAX; i++) {
        struct uxn_hook_slot *s = &g_h.uxn_hooks[i];
        if (!s->used) continue;
        off += snprintf(buf + off, bsize - off,
                         "slot=%d pid=%d target=0x%lx page=0x%lx "
                         "replace=0x%lx ghost=0x%lx hits=%lu "
                         "pass3=%lu last_far=0x%lx last_new_pc=0x%lx\n",
                         i, s->pid, s->target_addr, s->target_page,
                         s->replace_addr, s->gp.vaddr, s->fault_hits,
                         s->pass3_hits, s->last_pass3_far,
                         s->last_pass3_new_pc);
        count++;
    }
    off += snprintf(buf + off, bsize - off,
                     "[OK] %d/%d slots used\n", count, UXN_HOOK_MAX);
    return off;
}

/* ---------- Java-hook / Ghost-pool commands ----------
 *
 * These commands are for LSPlant-style Java method hooking:
 *   - ghost-alloc: reserve a VMA-less ghost page in target process
 *   - ghost-write: write bytes (e.g. trampoline code) into ghost via kaddr
 *   - java-hook : replace ArtMethod.entry_point with ghost addr
 *
 * They're independent of the UXN/DBI mechanism used by cmd_install.
 */

static int hex_to_bytes(const char *hex, uint8_t *out, int max)
{
    int n = 0;
    while (*hex && n < max) {
        uint8_t b = 0;
        int i;
        for (i = 0; i < 2 && *hex; i++, hex++) {
            char c = *hex;
            uint8_t nib;
            if (c >= '0' && c <= '9') nib = c - '0';
            else if (c >= 'a' && c <= 'f') nib = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') nib = c - 'A' + 10;
            else return n;
            b = (b << 4) | nib;
        }
        out[n++] = b;
    }
    return n;
}

static int find_free_ghost_slot(void)
{
    int i;
    for (i = 0; i < GHOST_POOL_MAX; i++)
        if (!g_h.ghost_pool[i].used) return i;
    return -1;
}

static int find_ghost_by_vaddr(unsigned long vaddr)
{
    int i;
    for (i = 0; i < GHOST_POOL_MAX; i++) {
        if (g_h.ghost_pool[i].used &&
            g_h.ghost_pool[i].gp.vaddr == vaddr) return i;
    }
    return -1;
}

/* ghost-alloc <pid> <near> <size> */
static int cmd_ghost_alloc(int pid, unsigned long near, unsigned long size,
                            char *buf, int bsize)
{
    int off = 0;
    struct task_struct *task;
    struct mm_struct *mm;
    struct pte_op pop;
    uint64_t tpte;
    int slot, num_pages, r;

    off += snprintf(buf + off, bsize - off,
                     "=== GHOST-ALLOC ===\n"
                     "pid=%d near=0x%lx size=%lu\n\n", pid, near, size);

    slot = find_free_ghost_slot();
    if (slot < 0)
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] ghost pool full\n");

    task = find_task(pid);
    if (!task) return off + snprintf(buf + off, bsize - off, "[FAIL] task\n");

    mm = fn_get_task_mm(task);
    if (!mm) return off + snprintf(buf + off, bsize - off, "[FAIL] mm\n");

    /* Need a template PTE for executable user page: read the page at `near`.
     * Caller should pass near= a known-exec user page (e.g. libart.so base). */
    pop.mode = 0;
    pop.out_val = &tpte;
    r = fn_apply_to_page_range(mm, near & ~0xFFFUL, 0x1000, pte_op_cb, &pop);
    if (r || !(tpte & 1UL)) {
        fn_mmput(mm);
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] read template PTE: %d tpte=0x%lx\n",
                               r, tpte);
    }

    num_pages = (size + 0xFFF) >> 12;
    if (num_pages < 1) num_pages = 1;

    r = ghost_alloc(task, mm, near & ~0xFFFUL, 512UL << 20, tpte,
                    num_pages, &g_h.ghost_pool[slot].gp);
    if (r) {
        fn_mmput(mm);
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] ghost_alloc: %d\n", r);
    }

    g_h.ghost_pool[slot].used = 1;
    g_h.ghost_pool[slot].pid = pid;
    fn_mmput(mm);

    off += snprintf(buf + off, bsize - off,
                     "[OK] ghost=0x%lx kaddr=0x%lx size=%lu slot=%d\n",
                     g_h.ghost_pool[slot].gp.vaddr,
                     g_h.ghost_pool[slot].gp.kaddr,
                     g_h.ghost_pool[slot].gp.alloc_size, slot);
    return off;
}

/* ghost-alloc-at <pid> <exact_addr> <size>
 * Userspace-guided variant: caller supplies an exact 4KB-aligned address
 * that is known to be a free hole (via /proc/PID/maps parsing). KPM still
 * needs a valid PTE template which it reads from libart or similar via a
 * small internal fallback (tries exact_addr first, then scans nearby for
 * any mapped exec page). No hole search is done in kernel.
 */
static int cmd_ghost_alloc_at(int pid, unsigned long exact_addr,
                                unsigned long size, char *buf, int bsize)
{
    int off = 0;
    struct task_struct *task;
    struct mm_struct *mm;
    struct pte_op pop;
    uint64_t tpte = 0;
    void *vma;
    int slot, num_pages, r;
    unsigned long probe = 0;
    unsigned long addr_aligned = exact_addr & ~0xFFFUL;
    unsigned long d;

    off += snprintf(buf + off, bsize - off,
                     "=== GHOST-ALLOC-AT ===\n"
                     "pid=%d addr=0x%lx size=%lu\n\n",
                     pid, addr_aligned, size);

    slot = find_free_ghost_slot();
    if (slot < 0)
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] ghost pool full\n");

    task = find_task(pid);
    if (!task) return off + snprintf(buf + off, bsize - off, "[FAIL] task\n");

    mm = fn_get_task_mm(task);
    if (!mm) return off + snprintf(buf + off, bsize - off, "[FAIL] mm\n");

    /* Verify the requested address is actually in a gap */
    if (fn_find_vma) {
        vma = fn_find_vma(mm, addr_aligned);
        if (vma) {
            unsigned long vm_start = *(unsigned long *)((char *)vma + OFF_VMA_START);
            if (vm_start < addr_aligned + 0x1000) {
                fn_mmput(mm);
                return off + snprintf(buf + off, bsize - off,
                                       "[FAIL] addr 0x%lx not in gap (VMA covers it)\n",
                                       addr_aligned);
            }
        }
    }

    /* Find a PTE template by probing nearby mapped pages. Scan ±128MB
     * stepping 1MB looking for any valid user-mapped page. */
    pop.mode = 0;
    pop.out_val = &tpte;
    /* Probe wider range (4GB) for PTE template - aweme-like dense processes
     * may have big gaps with no mapped pages within 128MB of a given addr. */
    for (d = 0x100000; d <= (4UL << 30); d += 0x100000) {
        unsigned long up = addr_aligned + d;
        unsigned long dn = addr_aligned - d;
        tpte = 0;
        r = fn_apply_to_page_range(mm, up, 0x1000, pte_op_cb, &pop);
        if (!r && (tpte & 1UL)) { probe = up; goto have_tpte; }
        tpte = 0;
        if (dn < addr_aligned) {
            r = fn_apply_to_page_range(mm, dn, 0x1000, pte_op_cb, &pop);
            if (!r && (tpte & 1UL)) { probe = dn; goto have_tpte; }
        }
    }
    fn_mmput(mm);
    return off + snprintf(buf + off, bsize - off,
                           "[FAIL] no template PTE within +/-128MB\n");

have_tpte:
    num_pages = (size + 0xFFF) >> 12;
    if (num_pages < 1) num_pages = 1;

    /* ghost_alloc's find_hole_near picks the closest gap to `near`. Since
     * we asked for this exact address AND verified it's in a gap, pass
     * range=4KB to restrict to the specific page. */
    r = ghost_alloc(task, mm, addr_aligned, 0x1000, tpte,
                    num_pages, &g_h.ghost_pool[slot].gp);
    if (r) {
        fn_mmput(mm);
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] ghost_alloc: %d (probe=0x%lx)\n",
                               r, probe);
    }

    g_h.ghost_pool[slot].used = 1;
    g_h.ghost_pool[slot].pid = pid;
    fn_mmput(mm);

    off += snprintf(buf + off, bsize - off,
                     "[OK] ghost=0x%lx kaddr=0x%lx size=%lu slot=%d probe=0x%lx\n",
                     g_h.ghost_pool[slot].gp.vaddr,
                     g_h.ghost_pool[slot].gp.kaddr,
                     g_h.ghost_pool[slot].gp.alloc_size, slot, probe);
    return off;
}

/* ghost-free <pid> <ghost> */
static int cmd_ghost_free(int pid, unsigned long vaddr, char *buf, int bsize)
{
    int off = 0;
    int slot = find_ghost_by_vaddr(vaddr);

    off += snprintf(buf + off, bsize - off,
                     "=== GHOST-FREE ===\npid=%d ghost=0x%lx\n", pid, vaddr);

    if (slot < 0)
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] ghost not found\n");

    ghost_free(&g_h.ghost_pool[slot].gp);
    g_h.ghost_pool[slot].used = 0;
    return off + snprintf(buf + off, bsize - off, "[OK] freed slot=%d\n", slot);
}

/* ghost-write <pid> <ghost> <offset> <hexbytes> */
static int cmd_ghost_write(int pid, unsigned long vaddr, unsigned long offset,
                            const char *hex, char *buf, int bsize)
{
    int off = 0;
    int slot = find_ghost_by_vaddr(vaddr);
    static uint8_t tmpbuf[4096];
    int n;

    off += snprintf(buf + off, bsize - off,
                     "=== GHOST-WRITE ===\n"
                     "pid=%d ghost=0x%lx off=0x%lx\n", pid, vaddr, offset);

    if (slot < 0)
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] ghost not found\n");

    n = hex_to_bytes(hex, tmpbuf, sizeof(tmpbuf));
    if (n <= 0)
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] bad hex\n");

    if (ghost_write(&g_h.ghost_pool[slot].gp, (unsigned)offset, tmpbuf, n))
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] ghost_write\n");

    ghost_sync_icache(&g_h.ghost_pool[slot].gp);
    return off + snprintf(buf + off, bsize - off,
                           "[OK] wrote %d bytes\n", n);
}

/* ghost-read <pid> <vaddr> <len>  - dump ghost bytes via kernel kaddr.
 * vaddr can be anywhere within an allocated ghost page range (not just base). */
static int cmd_ghost_read(int pid, unsigned long vaddr, unsigned len,
                           char *buf, int bsize)
{
    int off = 0;
    int slot = -1, i;
    unsigned delta = 0;
    uint8_t *d;

    off += snprintf(buf + off, bsize - off,
                     "=== GHOST-READ ===\n"
                     "pid=%d addr=0x%lx len=%u\n", pid, vaddr, len);

    /* Find ghost containing vaddr — search Java pool first, then UXN slots */
    int from_uxn = 0;
    for (i = 0; i < GHOST_POOL_MAX; i++) {
        struct ghost_pool_entry *s = &g_h.ghost_pool[i];
        if (!s->used || !s->gp.installed) continue;
        if (vaddr >= s->gp.vaddr &&
            vaddr < s->gp.vaddr + s->gp.alloc_size) {
            slot = i;
            delta = (unsigned)(vaddr - s->gp.vaddr);
            break;
        }
    }
    if (slot < 0) {
        for (i = 0; i < UXN_HOOK_MAX; i++) {
            struct uxn_hook_slot *u = &g_h.uxn_hooks[i];
            if (!u->used) continue;
            if (vaddr >= u->gp.vaddr &&
                vaddr < u->gp.vaddr + u->gp.alloc_size) {
                slot = i;
                delta = (unsigned)(vaddr - u->gp.vaddr);
                from_uxn = 1;
                break;
            }
        }
    }

    if (slot < 0)
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] ghost not found\n");

    {
        struct ghost_page *gp = from_uxn
            ? &g_h.uxn_hooks[slot].gp
            : &g_h.ghost_pool[slot].gp;
        if (delta + len > gp->alloc_size)
            len = gp->alloc_size - delta;
        /* Output is hex (2 char per byte) + ~80 byte header + newline, buf
         * is 4096. Max safe = (4096 - 128) / 2 = 1984 bytes. Round to 1536
         * for slack. Userspace chunks if larger. */
        if (len > 1536) len = 1536;

        off += snprintf(buf + off, bsize - off,
                         "[OK] %u bytes (%s slot=%d +0x%x): ",
                         len, from_uxn ? "uxn" : "pool", slot, delta);
        d = (uint8_t *)(gp->kaddr + delta);
    }
    for (i = 0; (unsigned)i < len && off < bsize - 3; i++) {
        off += snprintf(buf + off, bsize - off, "%02x", d[i]);
    }
    off += snprintf(buf + off, bsize - off, "\n");
    return off;
}

static int find_free_java_slot(void)
{
    int i;
    for (i = 0; i < JAVA_HOOK_MAX; i++)
        if (!g_h.java_hooks[i].used) return i;
    return -1;
}

static int find_java_hook(unsigned long art_method, unsigned offset)
{
    int i;
    for (i = 0; i < JAVA_HOOK_MAX; i++) {
        if (g_h.java_hooks[i].used &&
            g_h.java_hooks[i].art_method == art_method &&
            g_h.java_hooks[i].entry_offset == offset) return i;
    }
    return -1;
}

/* java-hook <pid> <art_method> <entry_offset> <new_entry>
 *   Writes new_entry into *(art_method + entry_offset), saves old.
 */
static int cmd_java_hook(int pid, unsigned long art_method, unsigned offset,
                          unsigned long new_entry, char *buf, int bsize)
{
    int off = 0;
    struct task_struct *task;
    uint64_t orig = 0;
    int slot, r;

    off += snprintf(buf + off, bsize - off,
                     "=== JAVA-HOOK ===\n"
                     "pid=%d art_method=0x%lx off=%u new_entry=0x%lx\n",
                     pid, art_method, offset, new_entry);

    slot = find_free_java_slot();
    if (slot < 0)
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] java_hook table full\n");

    task = find_task(pid);
    if (!task) return off + snprintf(buf + off, bsize - off, "[FAIL] task\n");

    /* Read current entry_point */
    r = fn_access_process_vm(task, art_method + offset, &orig, 8, FOLL_FORCE);
    if (r != 8)
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] read orig: %d\n", r);

    /* Write new entry_point */
    r = fn_access_process_vm(task, art_method + offset, &new_entry, 8,
                              FOLL_WRITE | FOLL_FORCE);
    if (r != 8)
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] write new: %d\n", r);

    g_h.java_hooks[slot].used = 1;
    g_h.java_hooks[slot].pid = pid;
    g_h.java_hooks[slot].art_method = art_method;
    g_h.java_hooks[slot].entry_offset = offset;
    g_h.java_hooks[slot].orig_entry = orig;
    g_h.java_hooks[slot].new_entry = new_entry;

    return off + snprintf(buf + off, bsize - off,
                           "[OK] slot=%d orig=0x%lx new=0x%lx\n",
                           slot, orig, new_entry);
}

/* java-unhook <pid> <art_method> <entry_offset> */
static int cmd_java_unhook(int pid, unsigned long art_method, unsigned offset,
                            char *buf, int bsize)
{
    int off = 0;
    struct task_struct *task;
    int slot, r;

    off += snprintf(buf + off, bsize - off,
                     "=== JAVA-UNHOOK ===\n"
                     "pid=%d art_method=0x%lx off=%u\n",
                     pid, art_method, offset);

    slot = find_java_hook(art_method, offset);
    if (slot < 0)
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] not hooked\n");

    task = find_task(pid);
    if (!task) return off + snprintf(buf + off, bsize - off, "[FAIL] task\n");

    /* Restore original entry_point */
    r = fn_access_process_vm(task, art_method + offset,
                              &g_h.java_hooks[slot].orig_entry, 8,
                              FOLL_WRITE | FOLL_FORCE);
    if (r != 8)
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] restore: %d\n", r);

    g_h.java_hooks[slot].used = 0;
    return off + snprintf(buf + off, bsize - off, "[OK] unhooked slot=%d\n", slot);
}

/* proc-patch <pid> <addr> <hexbytes>
 *   Writes bytes into target process memory via access_process_vm (COW on
 *   write, does NOT require mprotect → no VMA split in target).
 *   Also issues cache coherency so new code is seen by I-fetch.
 */
static int cmd_proc_patch(int pid, unsigned long addr, const char *hex,
                           char *buf, int bsize)
{
    int off = 0;
    struct task_struct *task;
    static uint8_t tmpbuf[4096];
    int n, r;

    off += snprintf(buf + off, bsize - off,
                     "=== PROC-PATCH ===\n"
                     "pid=%d addr=0x%lx\n", pid, addr);

    task = find_task(pid);
    if (!task) return off + snprintf(buf + off, bsize - off, "[FAIL] task\n");

    n = hex_to_bytes(hex, tmpbuf, sizeof(tmpbuf));
    if (n <= 0)
        return off + snprintf(buf + off, bsize - off, "[FAIL] bad hex\n");

    r = fn_access_process_vm(task, addr, tmpbuf, n, FOLL_WRITE | FOLL_FORCE);
    if (r != n)
        return off + snprintf(buf + off, bsize - off,
                               "[FAIL] write: got %d, want %d\n", r, n);

    /* Flush I-cache globally (inner shareable) so CPU fetches fresh bytes */
    asm volatile(
        "dsb ishst\n\t"
        "ic ialluis\n\t"
        "dsb ish\n\t"
        "isb\n\t"
        ::: "memory"
    );

    return off + snprintf(buf + off, bsize - off,
                           "[OK] wrote %d bytes\n", n);
}

/* proc-read <pid> <addr> <len> — read N bytes from target into output (hex) */
static int cmd_proc_read(int pid, unsigned long addr, unsigned len,
                          char *buf, int bsize)
{
    int off = 0;
    struct task_struct *task;
    static uint8_t tmpbuf[512];
    int r, i;

    if (len > sizeof(tmpbuf)) len = sizeof(tmpbuf);
    off += snprintf(buf + off, bsize - off,
                     "=== PROC-READ ===\npid=%d addr=0x%lx len=%u\n",
                     pid, addr, len);

    task = find_task(pid);
    if (!task) return off + snprintf(buf + off, bsize - off, "[FAIL] task\n");

    r = fn_access_process_vm(task, addr, tmpbuf, len, FOLL_FORCE);
    if (r <= 0)
        return off + snprintf(buf + off, bsize - off, "[FAIL] read %d\n", r);

    off += snprintf(buf + off, bsize - off, "[OK] %d bytes: ", r);
    for (i = 0; i < r && off < bsize - 4; i++) {
        off += snprintf(buf + off, bsize - off, "%02x", tmpbuf[i]);
    }
    off += snprintf(buf + off, bsize - off, "\n");
    return off;
}

static int cmd_remove(char *buf, int size)
{
    int off = 0;
    struct task_struct *task;
    struct mm_struct *mm;
    struct pte_op pop;
    int r;

    off += snprintf(buf + off, size - off, "=== REMOVE ===\n");

    if (!g_h.armed && !g_h.hook_installed && !g_h.gp.installed) {
        off += snprintf(buf + off, size - off, "[INFO] nothing to do\n");
        return off;
    }

    /* 1. Deactivate handler */
    g_h.armed = 0;
    asm volatile("dmb ish" ::: "memory");

    /* 2. Restore target PTE */
    if (g_h.saved_target_pte) {
        task = find_task(g_h.pid);
        if (task) {
            mm = fn_get_task_mm(task);
            if (mm) {
                pop.mode = 2;
                pop.out_val = 0;
                pop.orig_val = g_h.saved_target_pte;
                r = fn_apply_to_page_range(mm, g_h.target_page,
                                            0x1000, pte_op_cb, &pop);
                off += snprintf(buf + off, size - off,
                                 "[%s] restore target PTE: %d\n",
                                 r ? "FAIL" : "PASS", r);
                /* 3. Release ghost */
                if (g_h.gp.installed) {
                    r = ghost_free(&g_h.gp);
                    off += snprintf(buf + off, size - off,
                                     "[%s] ghost_free: %d\n",
                                     r ? "FAIL" : "PASS", r);
                }
                fn_mmput(mm);
            }
        }
    }

    /* TLB flush */
    asm volatile(
        "dsb ishst\n\t"
        "tlbi vmalle1is\n\t"
        "dsb ish\n\t"
        "isb\n\t"
        ::: "memory"
    );

    /* 4. Unhook do_mem_abort */
    if (g_h.hook_installed) {
        hook_unwrap(addr_do_mem_abort, before_do_mem_abort,
                     after_do_mem_abort);
        g_h.hook_installed = 0;
        off += snprintf(buf + off, size - off,
                         "[PASS] do_mem_abort unhooked\n");
    }

    off += snprintf(buf + off, size - off,
                     "\nstats: hits=%lu others=%lu\n",
                     g_h.fault_hits, g_h.fault_others);
    g_h.saved_target_pte = 0;
    return off;
}

static int cmd_stat(char *buf, int size)
{
    int off = 0;
    off += snprintf(buf + off, size - off,
                     "=== STATUS ===\n"
                     "hook_installed: %d\n"
                     "armed         : %d\n"
                     "ghost.installed: %d\n"
                     "kern.linked_list_vma: %d\n"
                     "kern.vma_off: start=0x%x end=0x%x next=0x%x rb=0x%x\n",
                     g_h.hook_installed, g_h.armed, g_h.gp.installed,
                     g_kl.has_linked_list_vma,
                     g_kl.off_vma_start, g_kl.off_vma_end,
                     g_kl.off_vma_next, g_kl.off_vma_rb);

    if (g_h.armed || g_h.hook_installed) {
        off += snprintf(buf + off, size - off,
                         "pid            : %d\n"
                         "target         : 0x%lx (page 0x%lx)\n"
                         "ghost user     : 0x%lx\n"
                         "ghost kaddr    : 0x%lx\n"
                         "saved tgt PTE  : 0x%lx\n"
                         "DBI: fixed=%d expanded=%d pass=%d failed=%d gwords=%d\n"
                         "fault hits     : %lu\n"
                         "fault others   : %lu\n"
                         "last far       : 0x%lx\n"
                         "last esr       : 0x%lx\n"
                         "last old_pc    : 0x%lx\n"
                         "last new_pc    : 0x%lx\n",
                         g_h.pid, g_h.target_addr, g_h.target_page,
                         g_h.gp.vaddr, g_h.gp.kaddr, g_h.saved_target_pte,
                         g_h.dbi.fixed, g_h.dbi.expanded,
                         g_h.dbi.passthrough, g_h.dbi.failed,
                         g_h.dbi.ghost_count,
                         g_h.fault_hits, g_h.fault_others,
                         g_h.dbg_far, g_h.dbg_esr,
                         g_h.dbg_old_pc, g_h.dbg_new_pc);
    }
    return off;
}

/* ---------- KPM entry points ---------- */

static long planc2_init(const char *args, const char *event, void *__user r)
{
    struct ghost_mm_syms gsyms;

    pr_info("ptehook-planc-v2: init args=%s\n", args);

    g_vsnprintf            = (vsnprintf_t)kallsyms_lookup_name("vsnprintf");
    fn_find_vpid           = (find_vpid_t)kallsyms_lookup_name("find_vpid");
    fn_pid_task            = (pid_task_t)kallsyms_lookup_name("pid_task");
    fn_access_process_vm   = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    fn_get_task_mm         = (get_task_mm_t)kallsyms_lookup_name("get_task_mm");
    fn_mmput               = (mmput_t)kallsyms_lookup_name("mmput");
    fn_apply_to_page_range = (apply_to_page_range_t)kallsyms_lookup_name("apply_to_page_range");
    fn_get_free_pages      = (get_free_pages_t)kallsyms_lookup_name("__get_free_pages");
    fn_free_pages          = (free_pages_t)kallsyms_lookup_name("free_pages");
    fn_find_vma            = (find_vma_t)kallsyms_lookup_name("find_vma");
    ptr_physvirt_offset    = (const int64_t *)kallsyms_lookup_name("physvirt_offset");
    addr_do_mem_abort      = (void *)kallsyms_lookup_name("do_mem_abort");
    addr_do_mmap           = (void *)kallsyms_lookup_name("do_mmap");
    fn_task_pid_nr_ns      = (task_pid_nr_ns_t)kallsyms_lookup_name("__task_pid_nr_ns");
    fn_schedule_work       = (schedule_work_t)kallsyms_lookup_name("schedule_work");
    fn_rb_erase            = (rb_erase_t)kallsyms_lookup_name("rb_erase");
    fn_on_each_cpu         = (on_each_cpu_t)kallsyms_lookup_name("on_each_cpu");

    /* Detect kernel layout (maple tree vs linked list VMAs) */
    probe_kern_layout();

    /* Init deferred work struct:
     * work_struct layout: { data=WORK_STRUCT_NO_POOL, entry={&entry,&entry}, func }
     * WORK_STRUCT_NO_POOL = 1<<2 | 1<<1 = 0x6  (atomic counter + flags) */
    {
        struct mini_work *w = &g_h.watch.work;
        w->data = 0;
        w->entry[0] = (unsigned long)&w->entry[0];
        w->entry[1] = (unsigned long)&w->entry[0];
        w->func = deferred_install_work;
    }

    pr_info("ptehook-planc-v2: syms: vsn=%lx vpid=%lx ptask=%lx apv=%lx "
             "gtm=%lx mp=%lx apr=%lx gfp=%lx frp=%lx fv=%lx pvo=%lx dma=%lx\n",
             (unsigned long)g_vsnprintf,
             (unsigned long)fn_find_vpid,
             (unsigned long)fn_pid_task,
             (unsigned long)fn_access_process_vm,
             (unsigned long)fn_get_task_mm,
             (unsigned long)fn_mmput,
             (unsigned long)fn_apply_to_page_range,
             (unsigned long)fn_get_free_pages,
             (unsigned long)fn_free_pages,
             (unsigned long)fn_find_vma,
             (unsigned long)ptr_physvirt_offset,
             (unsigned long)addr_do_mem_abort);

    if (!g_vsnprintf || !fn_find_vpid || !fn_pid_task ||
        !fn_access_process_vm || !fn_get_task_mm || !fn_mmput ||
        !fn_apply_to_page_range || !fn_get_free_pages ||
        !fn_free_pages || !fn_find_vma || !ptr_physvirt_offset ||
        !addr_do_mem_abort) {
        pr_err("ptehook-planc-v2: missing symbols\n");
        return -1;
    }

    pr_info("ptehook-planc-v2: physvirt_offset = 0x%llx\n",
             (long long)*ptr_physvirt_offset);

    /* Seed ghost_mm with resolved kernel calls */
    gsyms.get_free_pages      = fn_get_free_pages;
    gsyms.free_pages          = fn_free_pages;
    gsyms.find_vma            = fn_find_vma;
    gsyms.apply_to_page_range = fn_apply_to_page_range;
    gsyms.physvirt_offset_p   = ptr_physvirt_offset;
    gsyms.on_each_cpu         = fn_on_each_cpu;
    ghost_mm_init(&gsyms);

    return 0;
}

static long planc2_ctl0(const char *args, char *__user out_msg, int outlen)
{
    static char buf[4096];
    int off = 0;
    const char *p = args;

    pr_info("ptehook-planc-v2: ctl0 args=%s\n", args);

    /* Check for pending watch match → auto-install */
    if (g_h.watch.active && g_h.watch.pending_addr && !g_h.watch.installed) {
        off += snprintf(buf + off, sizeof(buf) - off,
                         "[AUTO] watch matched: pid=%d addr=0x%lx\n",
                         g_h.watch.pending_pid, g_h.watch.pending_addr);
        g_h.watch.installed = 1;
        off += cmd_install(g_h.watch.pending_pid, g_h.watch.pending_addr,
                           buf + off, sizeof(buf) - off);
        compat_copy_to_user(out_msg, buf, off < outlen ? off + 1 : outlen);
        return 0;
    }

    while (*p == ' ' || *p == '\t') p++;

    if (str_starts_with(p, "install")) {
        int pid;
        unsigned long addr;
        p += 7;
        while (*p == ' ' || *p == '\t') p++;
        pid = (int)parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        addr = parse_num(&p);
        off = cmd_install(pid, addr, buf, sizeof(buf));
    }
    else if (str_starts_with(p, "ghost-alloc-at")) {
        int pid;
        unsigned long addr, size;
        p += 14;
        while (*p == ' ' || *p == '\t') p++;
        pid = (int)parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        addr = parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        size = parse_num(&p);
        off = cmd_ghost_alloc_at(pid, addr, size, buf, sizeof(buf));
    }
    else if (str_starts_with(p, "ghost-alloc")) {
        int pid;
        unsigned long near, size;
        p += 11;
        while (*p == ' ' || *p == '\t') p++;
        pid = (int)parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        near = parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        size = parse_num(&p);
        off = cmd_ghost_alloc(pid, near, size, buf, sizeof(buf));
    }
    else if (str_starts_with(p, "ghost-free")) {
        int pid;
        unsigned long vaddr;
        p += 10;
        while (*p == ' ' || *p == '\t') p++;
        pid = (int)parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        vaddr = parse_num(&p);
        off = cmd_ghost_free(pid, vaddr, buf, sizeof(buf));
    }
    else if (str_starts_with(p, "ghost-read")) {
        int pid;
        unsigned long vaddr;
        unsigned len;
        p += 10;
        while (*p == ' ' || *p == '\t') p++;
        pid = (int)parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        vaddr = parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        len = (unsigned)parse_num(&p);
        off = cmd_ghost_read(pid, vaddr, len, buf, sizeof(buf));
    }
    else if (str_starts_with(p, "ghost-write")) {
        int pid;
        unsigned long vaddr, offset;
        p += 11;
        while (*p == ' ' || *p == '\t') p++;
        pid = (int)parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        vaddr = parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        offset = parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        off = cmd_ghost_write(pid, vaddr, offset, p, buf, sizeof(buf));
    }
    else if (str_starts_with(p, "java-hook")) {
        int pid;
        unsigned long art_method, entry_off, new_entry;
        p += 9;
        while (*p == ' ' || *p == '\t') p++;
        pid = (int)parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        art_method = parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        entry_off = parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        new_entry = parse_num(&p);
        off = cmd_java_hook(pid, art_method, (unsigned)entry_off,
                            new_entry, buf, sizeof(buf));
    }
    else if (str_starts_with(p, "hide-vma")) {
        int pid;
        unsigned long vaddr;
        p += 8;
        while (*p == ' ' || *p == '\t') p++;
        pid = (int)parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        vaddr = parse_num(&p);
        off = cmd_hide_vma(pid, vaddr, buf, sizeof(buf));
    }
    else if (str_starts_with(p, "hide-range")) {
        int pid;
        unsigned long s, e;
        p += 10;
        while (*p == ' ' || *p == '\t') p++;
        pid = (int)parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        s = parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        e = parse_num(&p);
        off = cmd_hide_range(pid, s, e, buf, sizeof(buf));
    }
    else if (str_starts_with(p, "uxn-list")) {
        off = cmd_uxn_list(buf, sizeof(buf));
    }
    else if (str_starts_with(p, "uxn-hook")) {
        int pid;
        unsigned long target, replace;
        p += 8;
        while (*p == ' ' || *p == '\t') p++;
        pid = (int)parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        target = parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        replace = parse_num(&p);
        off = cmd_uxn_hook(pid, target, replace, buf, sizeof(buf));
    }
    else if (str_starts_with(p, "uxn-add-redirect")) {
        int pid;
        unsigned long target, replace;
        p += 16;
        while (*p == ' ' || *p == '\t') p++;
        pid = (int)parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        target = parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        replace = parse_num(&p);
        off = cmd_uxn_add_redirect(pid, target, replace, buf, sizeof(buf));
    }
    else if (str_starts_with(p, "uxn-del-redirect")) {
        int pid;
        unsigned long target;
        p += 16;
        while (*p == ' ' || *p == '\t') p++;
        pid = (int)parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        target = parse_num(&p);
        off = cmd_uxn_del_redirect(pid, target, buf, sizeof(buf));
    }
    else if (str_starts_with(p, "uxn-unhook")) {
        int pid;
        unsigned long target;
        p += 10;
        while (*p == ' ' || *p == '\t') p++;
        pid = (int)parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        target = parse_num(&p);
        off = cmd_uxn_unhook(pid, target, buf, sizeof(buf));
    }
    else if (str_starts_with(p, "proc-patch")) {
        int pid;
        unsigned long addr;
        p += 10;
        while (*p == ' ' || *p == '\t') p++;
        pid = (int)parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        addr = parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        off = cmd_proc_patch(pid, addr, p, buf, sizeof(buf));
    }
    else if (str_starts_with(p, "proc-read")) {
        int pid;
        unsigned long addr, len;
        p += 9;
        while (*p == ' ' || *p == '\t') p++;
        pid = (int)parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        addr = parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        len = parse_num(&p);
        off = cmd_proc_read(pid, addr, (unsigned)len, buf, sizeof(buf));
    }
    else if (str_starts_with(p, "java-unhook")) {
        int pid;
        unsigned long art_method, entry_off;
        p += 11;
        while (*p == ' ' || *p == '\t') p++;
        pid = (int)parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        art_method = parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        entry_off = parse_num(&p);
        off = cmd_java_unhook(pid, art_method, (unsigned)entry_off,
                              buf, sizeof(buf));
    }
    else if (str_starts_with(p, "watch")) {
        int wpid;
        unsigned long woff;
        char soname[WATCH_SO_MAX];
        int si = 0;
        hook_err_t herr;

        p += 5;
        while (*p == ' ' || *p == '\t') p++;
        wpid = (int)parse_num(&p);
        while (*p == ' ' || *p == '\t') p++;
        /* Read so_name token */
        while (*p && *p != ' ' && *p != '\t' && si < WATCH_SO_MAX - 1)
            soname[si++] = *p++;
        soname[si] = 0;
        while (*p == ' ' || *p == '\t') p++;
        woff = parse_num(&p);

        off += snprintf(buf + off, sizeof(buf) - off,
                         "=== WATCH ===\n"
                         "pid=%d so=%s offset=0x%lx\n\n", wpid, soname, woff);

        if (!addr_do_mmap) {
            off += snprintf(buf + off, sizeof(buf) - off,
                             "[FAIL] do_mmap not resolved\n");
        } else {
            g_h.watch.target_pid = wpid;
            {
                int i;
                for (i = 0; soname[i] && i < WATCH_SO_MAX - 1; i++)
                    g_h.watch.so_name[i] = soname[i];
                g_h.watch.so_name[i] = 0;
            }
            g_h.watch.func_offset = woff;
            g_h.watch.installed = 0;

            if (!g_h.watch.mmap_hooked) {
                herr = hook_wrap9(addr_do_mmap,
                                   before_do_mmap, after_do_mmap, 0);
                if (herr) {
                    off += snprintf(buf + off, sizeof(buf) - off,
                                     "[FAIL] hook_wrap9 do_mmap: %d\n",
                                     (int)herr);
                } else {
                    g_h.watch.mmap_hooked = 1;
                    off += snprintf(buf + off, sizeof(buf) - off,
                                     "[PASS] do_mmap hooked\n");
                }
            } else {
                off += snprintf(buf + off, sizeof(buf) - off,
                                 "[INFO] do_mmap already hooked\n");
            }
            g_h.watch.active = 1;
            off += snprintf(buf + off, sizeof(buf) - off,
                             "[OK] Watching for %s in pid %d\n"
                             "     auto-install at base+0x%lx\n",
                             soname, wpid, woff);
        }
    }
    else if (str_starts_with(p, "remove")) {
        off = cmd_remove(buf, sizeof(buf));
    }
    else if (str_starts_with(p, "stat")) {
        off = cmd_stat(buf, sizeof(buf));
    }
    else {
        off = snprintf(buf, sizeof(buf),
                        "ptehook Plan C v2 commands:\n"
                        "  install <pid> <addr>\n"
                        "  watch <pid> <libname.so> <offset>\n"
                        "  ghost-alloc <pid> <near> <size>\n"
                        "  ghost-free <pid> <ghost>\n"
                        "  ghost-write <pid> <ghost> <offset> <hexbytes>\n"
                        "  java-hook <pid> <art_method> <entry_off> <new_entry>\n"
                        "  java-unhook <pid> <art_method> <entry_off>\n"
                        "  proc-patch <pid> <addr> <hexbytes>\n"
                        "  proc-read <pid> <addr> <len>\n"
                        "  uxn-hook <pid> <target> <replace>\n"
                        "  uxn-unhook <pid> <target>\n"
                        "  uxn-list\n"
                        "  hide-vma <pid> <vaddr>\n"
                        "  hide-range <pid> <start> <end>\n"
                        "  remove\n"
                        "  stat\n");
    }

    compat_copy_to_user(out_msg, buf, off < outlen ? off + 1 : outlen);
    return 0;
}

static long planc2_ctl1(void *a1, void *a2, void *a3) { return 0; }

/* Iterate every state table and invoke the per-slot teardown command.
 * Prevents orphan PTEs in target processes when KPM is unloaded — without
 * this, subsequent re-load + re-alloc at the same VA fails -ENOSPC because
 * the process still has live PTEs pointing at pages we already freed. */
static void cleanup_all_state(void)
{
    static char buf[512];
    int i, n_uxn = 0, n_ghost = 0, n_java = 0;

    /* UXN slots (includes DBI ghost for each) */
    for (i = 0; i < UXN_HOOK_MAX; i++) {
        struct uxn_hook_slot *s = &g_h.uxn_hooks[i];
        if (!s->used) continue;
        cmd_uxn_unhook(s->pid, s->target_addr, buf, sizeof(buf));
        n_uxn++;
    }

    /* Java hook slots (restore entry_point) */
    for (i = 0; i < JAVA_HOOK_MAX; i++) {
        struct java_hook_entry *j = &g_h.java_hooks[i];
        if (!j->used) continue;
        cmd_java_unhook(j->pid, j->art_method, j->entry_offset,
                         buf, sizeof(buf));
        n_java++;
    }

    /* User ghost pool (shellcode ghosts from cmd_ghost_alloc/alloc-at) */
    for (i = 0; i < GHOST_POOL_MAX; i++) {
        struct ghost_pool_entry *g = &g_h.ghost_pool[i];
        if (!g->used) continue;
        cmd_ghost_free(g->pid, g->gp.vaddr, buf, sizeof(buf));
        n_ghost++;
    }

    pr_info("ptehook-planc-v2: cleanup_all_state uxn=%d java=%d ghost=%d\n",
             n_uxn, n_java, n_ghost);
}

static long planc2_exit(void *__user r)
{
    static char buf[512];
    pr_info("ptehook-planc-v2: exit\n");

    /* Clean up per-slot state first (clears PTEs in target mm, frees pages).
     * Must happen BEFORE do_mem_abort hook is removed, because uxn_unhook
     * relies on the existing hook being active to safely unhook. */
    cleanup_all_state();

    /* Legacy single-hook path */
    if (g_h.armed || g_h.hook_installed || g_h.gp.installed) {
        cmd_remove(buf, sizeof(buf));
    }
    if (g_h.watch.mmap_hooked && addr_do_mmap) {
        g_h.watch.active = 0;
        hook_unwrap(addr_do_mmap, before_do_mmap, after_do_mmap);
        g_h.watch.mmap_hooked = 0;
    }
    return 0;
}

KPM_INIT(planc2_init);
KPM_CTL0(planc2_ctl0);
KPM_CTL1(planc2_ctl1);
KPM_EXIT(planc2_exit);
