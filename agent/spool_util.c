/**
 * @file spool_util.c
 * @brief Shared spool directory helpers (F6).
 */

#define _POSIX_C_SOURCE 200809L

#include "cpe_spool.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

int cpe_spool_ensure_dir(const char *dir)
{
    char tmp[512];
    size_t len;
    size_t i;

    if (!dir || !dir[0]) {
        return -1;
    }
    len = strlen(dir);
    if (len >= sizeof(tmp)) {
        return -1;
    }
    memcpy(tmp, dir, len + 1);

    /* Skip leading slash; walk components. */
    for (i = 1; i < len; i++) {
        if (tmp[i] != '/') {
            continue;
        }
        tmp[i] = '\0';
        if (tmp[0] != '\0' && mkdir(tmp, 0755) != 0 && errno != EEXIST) {
            return -1;
        }
        tmp[i] = '/';
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

int cpe_spool_ensure_parent_dir(const char *file_path)
{
    char tmp[512];
    char *slash;
    size_t len;

    if (!file_path || !file_path[0]) {
        return -1;
    }
    len = strlen(file_path);
    if (len >= sizeof(tmp)) {
        return -1;
    }
    memcpy(tmp, file_path, len + 1);
    slash = strrchr(tmp, '/');
    if (!slash || slash == tmp) {
        return 0; /* cwd or root file */
    }
    *slash = '\0';
    return cpe_spool_ensure_dir(tmp);
}
