/*
 * device_scanner.c - on-device scanner for ArtMethod patterns.
 *
 * Usage: device_scanner <pid> <method_idx> [adjacent_idx1,adjacent_idx2,...]
 *
 * Scans all [anon:dalvik-LinearAlloc] VMAs of target PID via process_vm_readv.
 * Prints candidate addresses where *(u32)(addr + 0xc) == method_idx and
 * *(u32)(addr + 0) != 0 (declaring_class non-null).
 *
 * If adjacent_idxs provided, also checks that addr ± 0x28 has matching idx.
 *
 * Build with NDK:
 *   aarch64-linux-android29-clang -O2 -static -o device_scanner device_scanner.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdint.h>

/* Default offsets — Android 13/14 ArtMethod. Overridable via CLI for other
 * versions. Android 11/12 has SIZE=0x28 and DEX_METHOD_INDEX at 0xc. */
static int cfg_artmethod_size = 0x20;
static int cfg_off_declaring_class = 0x00;
static int cfg_off_access_flags = 0x04;
static int cfg_off_dex_method_index = 0x08;
#define MAX_ADJ 8

static int adjacent[MAX_ADJ];
static int n_adjacent = 0;

static ssize_t vm_read(pid_t pid, uint64_t addr, void *buf, size_t len) {
    struct iovec lv = { .iov_base = buf, .iov_len = len };
    struct iovec rv = { .iov_base = (void *)(uintptr_t)addr, .iov_len = len };
    return process_vm_readv(pid, &lv, 1, &rv, 1, 0);
}

static int has_adjacent(pid_t pid, uint64_t cand_addr) {
    /* Require: neighbor at ±cfg_artmethod_size has one of the expected
     * method_idxs AND has the same declaring_class_ as cand. */
    uint32_t cand_decl;
    if (vm_read(pid, cand_addr + cfg_off_declaring_class, &cand_decl, 4) != 4) return 0;

    for (int d = 0; d < 2; d++) {
        uint64_t addr = cand_addr + (d == 0 ? cfg_artmethod_size : -cfg_artmethod_size);
        uint32_t adj_idx = 0, adj_decl = 0;
        if (vm_read(pid, addr + cfg_off_dex_method_index, &adj_idx, 4) != 4) continue;
        if (vm_read(pid, addr + cfg_off_declaring_class, &adj_decl, 4) != 4) continue;
        int idx_match = 0;
        for (int i = 0; i < n_adjacent; i++) {
            if ((int)adj_idx == adjacent[i]) { idx_match = 1; break; }
        }
        if (idx_match && adj_decl == cand_decl) return 1;
    }
    return 0;
}

static void scan_range(pid_t pid, uint64_t start, uint64_t end, uint32_t target_idx) {
    const size_t CHUNK = 64 * 1024;
    uint8_t *buf = malloc(CHUNK);
    if (!buf) return;

    for (uint64_t off = start; off < end; off += CHUNK) {
        size_t len = (end - off > CHUNK) ? CHUNK : (end - off);
        ssize_t got = vm_read(pid, off, buf, len);
        if (got <= 0) continue;

        for (ssize_t i = 0; i + cfg_artmethod_size <= got; i += 4) {
            uint32_t decl = *(uint32_t *)(buf + i + cfg_off_declaring_class);
            uint32_t midx = *(uint32_t *)(buf + i + cfg_off_dex_method_index);
            if (midx != target_idx) continue;
            if (decl == 0) continue;
            uint32_t access = *(uint32_t *)(buf + i + cfg_off_access_flags);
            if (access == 0 || access == 0xFFFFFFFF) continue;
            uint64_t cand = off + i;
            if (n_adjacent > 0 && !has_adjacent(pid, cand)) continue;
            /* App-class filter: mirror::Class compressed refs in dalvik-main
             * space land in low range; too-small (<0x10000) or too-big
             * (>0x40000000) usually indicate false positive or boot image. */
            if (decl < 0x10000 || decl > 0x40000000) continue;
            printf("  0x%" PRIx64 "  access=0x%x  decl=0x%x\n", cand, access, decl);
        }
    }

    free(buf);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr,
                "usage: %s <pid> <method_idx> [adj1,adj2,...] "
                "[--size=N] [--off-decl=N] [--off-af=N] [--off-midx=N]\n"
                "defaults: size=0x20 decl=0x0 af=0x4 midx=0x8 (Android 13/14)\n",
                argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    uint32_t target = (uint32_t)atoi(argv[2]);

    if (argc >= 4 && argv[3][0] != '-') {
        char *p = argv[3];
        while (*p && n_adjacent < MAX_ADJ) {
            adjacent[n_adjacent++] = atoi(p);
            p = strchr(p, ',');
            if (!p) break;
            p++;
        }
    }

    /* Optional offset overrides (Android 11/12 uses different layout). */
    for (int i = 3; i < argc; i++) {
        if (strncmp(argv[i], "--size=", 7) == 0)
            cfg_artmethod_size = (int)strtol(argv[i] + 7, NULL, 0);
        else if (strncmp(argv[i], "--off-decl=", 11) == 0)
            cfg_off_declaring_class = (int)strtol(argv[i] + 11, NULL, 0);
        else if (strncmp(argv[i], "--off-af=", 9) == 0)
            cfg_off_access_flags = (int)strtol(argv[i] + 9, NULL, 0);
        else if (strncmp(argv[i], "--off-midx=", 11) == 0)
            cfg_off_dex_method_index = (int)strtol(argv[i] + 11, NULL, 0);
    }

    /* Read /proc/PID/maps, find LinearAlloc VMAs */
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) { perror("open maps"); return 1; }

    char line[512];
    int total_vmas = 0, scanned = 0;
    size_t total_bytes = 0;
    while (fgets(line, sizeof(line), f)) {
        total_vmas++;
        if (!strstr(line, "[anon:dalvik-LinearAlloc]")) continue;
        uint64_t s, e;
        if (sscanf(line, "%" SCNx64 "-%" SCNx64, &s, &e) != 2) continue;
        scanned++;
        total_bytes += (e - s);
        scan_range(pid, s, e, target);
    }
    fclose(f);
    fprintf(stderr, "scanned %d LinearAlloc VMAs, %zu KB\n", scanned, total_bytes / 1024);
    return 0;
}
