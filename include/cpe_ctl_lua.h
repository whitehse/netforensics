/**
 * @file cpe_ctl_lua.h
 * @brief Lua front-end for cpe_ctl that queries the cpe_agent daemon over UDS.
 */
#ifndef CPE_CTL_LUA_H
#define CPE_CTL_LUA_H

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cpe_ctl_lua cpe_ctl_lua_t;

/**
 * Create Lua state with global `cpe` table backed by IPC to @p sock_path.
 * Does not require a local cpe_agent_t.
 */
cpe_ctl_lua_t *cpe_ctl_lua_create(const char *sock_path);

void cpe_ctl_lua_destroy(cpe_ctl_lua_t *Lwrap);

int cpe_ctl_lua_dostring(cpe_ctl_lua_t *Lwrap, const char *src, char *err,
                         size_t err_len);

int cpe_ctl_lua_dofile(cpe_ctl_lua_t *Lwrap, const char *path, char *err,
                       size_t err_len);

int cpe_ctl_lua_repl(cpe_ctl_lua_t *Lwrap, const char *history_path);

void cpe_ctl_lua_print_help(FILE *fp);

#ifdef __cplusplus
}
#endif

#endif /* CPE_CTL_LUA_H */
