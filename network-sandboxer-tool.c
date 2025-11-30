// SPDX-License-Identifier: BSD-3-Clause
//
// Self-contained program that will stop a program from making any outgoing
// network connections. It will one one single TCP port so it can still
// take *incoming* connections.
//
// It's like reverse firewall.
//
// This is based off a sample here: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/samples/landlock/sandboxer.c
//
// This is more or less just a simplified version of that.
//
// (c) 2025 Mikko Juola
//

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifndef LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON
#define LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON 2
#endif

#ifndef landlock_create_ruleset
static inline int
landlock_create_ruleset(
        const struct landlock_ruleset_attr *const attr,
        const size_t size,
        const __u32 flags)
{
    return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd,
        const enum landlock_rule_type rule_type,
        const void *const rule_attr,
        const __u32 flags)
{
    return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(
        const int ruleset_fd,
        const __u32 flags)
{
    return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

int main(int argc, char** argv, char *const *const envp) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("Failed to restrict privileges, prctl(PR_SET_NO_NEW_PRIVS, ...)");
        exit(1);
    }

    if (argc <= 2) {
        fprintf(stderr, "network-sandboxer-tool: expected a port and a command to run.\n");
        exit(1);
    }

    const int portlen = strlen(argv[1]);
    if (portlen < 1 || portlen > 5) {
        fprintf(stderr, "network-sandboxer-tool: invalid port specified.\n");
        exit(1);
    }
    for (int i1 = 0; i1 < portlen; ++i1) {
        if (argv[1][i1] < '0' || argv[1][i1] > '9') {
            fprintf(stderr, "network-sandboxer-tool: invalid port specified.\n");
            exit(1);
        }
    }
    char* endport = 0;
    errno = 0;
    long port = strtol(argv[1], &endport, 10);
    if (endport != &argv[1][portlen]) {
        fprintf(stderr, "network-sandboxer-tool: cannot parse port.\n");
        exit(1);
    }

    int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        const int err = errno;
        perror("landlock_create_ruleset");
        if (err == ENOSYS) {
            fprintf(stderr, "ENOSYS, kernel likely does not support landlock.\n");
        } else if (err == EOPNOTSUPP) {
            fprintf(stderr, "EOPNOTSUPP, kernel is aware of landlock but it is disabled.\n");
        }
        exit(1);
    }
    if (abi < 4) {
        fprintf(stderr, "landlock support exists, but ABI version is not at least 4, cannot sandbox by networking.\n");
        exit(1);
    }

    struct landlock_ruleset_attr attr = {0};
    // ABI 7
    attr.handled_access_fs =
        LANDLOCK_ACCESS_FS_EXECUTE |
        LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_READ_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_CHAR |
        LANDLOCK_ACCESS_FS_MAKE_DIR |
        LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_SOCK |
        LANDLOCK_ACCESS_FS_MAKE_FIFO |
        LANDLOCK_ACCESS_FS_MAKE_BLOCK |
        LANDLOCK_ACCESS_FS_MAKE_SYM |
        LANDLOCK_ACCESS_FS_REFER |
        LANDLOCK_ACCESS_FS_TRUNCATE |
        LANDLOCK_ACCESS_FS_IOCTL_DEV;
    // ABI 4
    attr.handled_access_net =
        LANDLOCK_ACCESS_NET_BIND_TCP |
        LANDLOCK_ACCESS_NET_CONNECT_TCP;

    // logging
    // ABI 7
    int restrict_flags = LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON;

    // No fallthrough in this switch, intentionally.
    switch (abi) {
        case 4:
            attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;
        case 5:
            attr.scoped &= ~(LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL);
        case 6:
            restrict_flags &= ~LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON;
        case 7: // The last ABI this program is aware of
            break;
        default:
            fprintf(stderr, "Landlock ABI is higher than this sandboxer is aware of. It's possible this sandboxer restricts more than intended. ABI reported is %d, this sandboxer is ware of ABI up to %d.\n", abi, 7);
    }

    int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (ruleset_fd < 0) {
        perror("Failed to create a landlock ruleset with landlock_create_ruleset");
        exit(1);
    }
    // This tool only is concerned about network, so allow everything for
    // now.
    int root_fd = open("/", O_PATH | O_CLOEXEC);
    if (root_fd == -1) {
        fprintf(stderr, "network-sandboxer-tool: cannot open / for privilege settings.\n");
        exit(1);
    }

    struct landlock_path_beneath_attr path_beneath = {0};
    path_beneath.parent_fd = root_fd;
    path_beneath.allowed_access = attr.handled_access_fs;

    if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0)) {
        perror("Failed to add a filesystem rule with landlock_add_rule.\n");
        exit(1);
    }

    // Networking: this is what we care about.
    // And deny. By not adding rules.
    struct landlock_net_port_attr port_bind = {0};
    port_bind.port = port;
    port_bind.allowed_access = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;
    if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &port_bind, 0)) {
        perror("Failed to add a network rule with landlock_add_rule.\n");
        exit(1);
    }

    if (landlock_restrict_self(ruleset_fd, restrict_flags)) {
        perror("Failed to enforce landlock ruleset with landlock_restrict_self");
        exit(1);
    }
    close(ruleset_fd);

    fprintf(stderr, "network-sandboxer-tool: landlock self-restricting succeeded, execvpe()ing to child process...\n");
    execvpe(argv[2], &argv[2], envp);
    fprintf(stderr, "network-sandboxer-tool: execvpe failed to execute \"%s\": %s\n", argv[2], strerror(errno));

    exit(1);
}

