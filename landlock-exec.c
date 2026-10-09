// landlock-exec — kernel-enforced filesystem confinement for a child command.
// Usage: landlock-exec [--rw DIR]... [--ro DIR]... -- CMD [ARGS...]
// Applies a Landlock ruleset (allow-list, irreversible) then execs CMD.
// Needs no capabilities and no user namespaces.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#endif

#define LL_CREATE_RULESET_VERSION (1U << 0)
#define LL_RULE_PATH_BENEATH 1

#define A_EXECUTE     (1ULL << 0)
#define A_WRITE_FILE  (1ULL << 1)
#define A_READ_FILE   (1ULL << 2)
#define A_READ_DIR    (1ULL << 3)
#define A_REMOVE_DIR  (1ULL << 4)
#define A_REMOVE_FILE (1ULL << 5)
#define A_MAKE_CHAR   (1ULL << 6)
#define A_MAKE_DIR    (1ULL << 7)
#define A_MAKE_REG    (1ULL << 8)
#define A_MAKE_SOCK   (1ULL << 9)
#define A_MAKE_FIFO   (1ULL << 10)
#define A_MAKE_BLOCK  (1ULL << 11)
#define A_MAKE_SYM    (1ULL << 12)
#define A_REFER       (1ULL << 13)
#define A_TRUNCATE    (1ULL << 14)
#define A_IOCTL_DEV   (1ULL << 15)

struct ll_ruleset_attr { unsigned long long handled_access_fs; };
struct ll_path_beneath { unsigned long long allowed_access; int parent_fd; } __attribute__((packed));

#define RO_ACCESS (A_EXECUTE | A_READ_FILE | A_READ_DIR)
#define RW_ACCESS (RO_ACCESS | A_WRITE_FILE | A_REMOVE_DIR | A_REMOVE_FILE | \
                   A_MAKE_CHAR | A_MAKE_DIR | A_MAKE_REG | A_MAKE_SOCK | \
                   A_MAKE_FIFO | A_MAKE_BLOCK | A_MAKE_SYM | A_REFER | \
                   A_TRUNCATE | A_IOCTL_DEV)

static int abi = 0;

static unsigned long long handled_mask(void) {
    unsigned long long m = A_EXECUTE|A_WRITE_FILE|A_READ_FILE|A_READ_DIR|A_REMOVE_DIR|
        A_REMOVE_FILE|A_MAKE_CHAR|A_MAKE_DIR|A_MAKE_REG|A_MAKE_SOCK|A_MAKE_FIFO|
        A_MAKE_BLOCK|A_MAKE_SYM|A_REFER;
    if (abi >= 2) m |= A_TRUNCATE;
    if (abi >= 5) m |= A_IOCTL_DEV;
    return m;
}

static int add_rule(int rfd, const char *path, unsigned long long access) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) { fprintf(stderr, "landlock-exec: cannot open %s: %s\n", path, strerror(errno)); return -1; }
    struct ll_path_beneath pb = { access, fd };
    int rc = syscall(__NR_landlock_add_rule, rfd, LL_RULE_PATH_BENEATH, &pb, 0);
    if (rc) fprintf(stderr, "landlock-exec: add_rule %s: %s\n", path, strerror(errno));
    close(fd);
    return rc;
}

static void usage(void) {
    fprintf(stderr, "usage: landlock-exec [--rw DIR]... [--ro DIR]... -- CMD [ARGS...]\n");
}

int main(int argc, char **argv) {
    const char *rw[128]; int n_rw = 0;
    const char *ro[128]; int n_ro = 0;
    int i = 1;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "--") ) { i++; break; }
        if (!strcmp(argv[i], "--rw") && i+1 < argc) { if (n_rw < 128) rw[n_rw++] = argv[++i]; else { usage(); return 2; } }
        else if (!strcmp(argv[i], "--ro") && i+1 < argc) { if (n_ro < 128) ro[n_ro++] = argv[++i]; else { usage(); return 2; } }
        else { usage(); return 2; }
    }
    if (i >= argc) { usage(); return 2; }

    abi = (int)syscall(__NR_landlock_create_ruleset, NULL, 0, LL_CREATE_RULESET_VERSION);
    if (abi < 1) { fprintf(stderr, "landlock-exec: FAIL-CLOSED, landlock unavailable: %s\n", strerror(errno)); return 3; }

    struct ll_ruleset_attr ra = { handled_mask() };
    int rfd = (int)syscall(__NR_landlock_create_ruleset, &ra, sizeof(ra), 0);
    if (rfd < 0) { fprintf(stderr, "landlock-exec: create_ruleset: %s\n", strerror(errno)); return 3; }

    static const char *defro[] = { "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc" };
    for (unsigned k = 0; k < sizeof(defro)/sizeof(*defro); k++) add_rule(rfd, defro[k], RO_ACCESS);
    for (int k = 0; k < n_ro; k++) add_rule(rfd, ro[k], RO_ACCESS);
    for (int k = 0; k < n_rw; k++) add_rule(rfd, rw[k], RW_ACCESS);

    // restrict_self requires no_new_privs. Without this it fails EPERM and the
    // "denied" tests pass VACUOUSLY (the command never runs at all) — which is
    // exactly how this bug hid the first time. Always test an ALLOWED case too.
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        fprintf(stderr, "landlock-exec: prctl no_new_privs: %s\n", strerror(errno)); return 3;
    }
    if (syscall(__NR_landlock_restrict_self, rfd, 0)) {
        fprintf(stderr, "landlock-exec: restrict_self: %s\n", strerror(errno)); return 3;
    }
    close(rfd);
    execvp(argv[i], &argv[i]);
    fprintf(stderr, "landlock-exec: exec %s: %s\n", argv[i], strerror(errno));
    return 127;
}