/**
 * @file cpe_agent_lua.h
 * @brief Embedded Lua runtime for cpe_agent tools / AI harness / REPL.
 *
 * When CPE_AGENT_HAVE_LUA is not defined, the APIs return -1 / NULL stubs.
 */
#ifndef CPE_AGENT_LUA_H
#define CPE_AGENT_LUA_H

#include "cpe_agent.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cpe_lua cpe_lua_t;

/**
 * Create a Lua state, open standard libraries, register the global
 * @c cpe table bound to @p agent. Does not take ownership of @p agent.
 */
cpe_lua_t *cpe_lua_create(cpe_agent_t *agent);

void cpe_lua_destroy(cpe_lua_t *Lwrap);

/** Underlying lua_State* (or NULL). For advanced embedding / harness. */
void *cpe_lua_state(cpe_lua_t *Lwrap);

/**
 * Execute a chunk of Lua source.
 * @return 0 ok, -1 error (message in @p err if provided).
 */
int cpe_lua_dostring(cpe_lua_t *Lwrap, const char *src, char *err, size_t err_len);

/**
 * Load and run a Lua file (tool script).
 * @return 0 ok, -1 error.
 */
int cpe_lua_dofile(cpe_lua_t *Lwrap, const char *path, char *err, size_t err_len);

/**
 * Interactive REPL: linenoise-style editing, up-arrow history.
 * Blocks until EOF / quit / exit. History file optional (may be NULL).
 * @return 0 normal exit, non-zero on fatal setup error.
 */
int cpe_lua_repl(cpe_lua_t *Lwrap, const char *history_path);

/** Print one-line help for the cpe.* table to @p fp (or stdout). */
void cpe_lua_print_help(FILE *fp);

#ifdef __cplusplus
}
#endif

#endif /* CPE_AGENT_LUA_H */
