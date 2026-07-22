/**
 * @file lua_repl.c
 * @brief Interactive Lua prompt with linenoise history (up-arrow).
 */

#include "cpe_agent_lua.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(CPE_AGENT_HAVE_LUA)

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include "linenoise.h"

static int is_exit_cmd(const char *line)
{
    char buf[32];
    size_t n;

    if (!line) {
        return 0;
    }
    while (*line && isspace((unsigned char)*line)) {
        line++;
    }
    n = 0;
    while (line[n] && !isspace((unsigned char)line[n]) && n + 1 < sizeof(buf)) {
        buf[n] = (char)tolower((unsigned char)line[n]);
        n++;
    }
    buf[n] = '\0';
    return strcmp(buf, "quit") == 0 || strcmp(buf, "exit") == 0 ||
           strcmp(buf, ".quit") == 0 || strcmp(buf, ".exit") == 0;
}

static void print_stack_top(lua_State *L)
{
    int t = lua_type(L, -1);

    switch (t) {
    case LUA_TNIL:
        printf("nil\n");
        break;
    case LUA_TBOOLEAN:
        printf("%s\n", lua_toboolean(L, -1) ? "true" : "false");
        break;
    case LUA_TNUMBER:
        if (lua_isinteger(L, -1)) {
            printf("%lld\n", (long long)lua_tointeger(L, -1));
        } else {
            printf("%.6g\n", (double)lua_tonumber(L, -1));
        }
        break;
    case LUA_TSTRING:
        printf("%s\n", lua_tostring(L, -1));
        break;
    case LUA_TTABLE:
        /* compact one-line table dump for sample tables */
        lua_getglobal(L, "cpe");
        if (lua_istable(L, -1)) {
            /* use a tiny pretty helper if present; else type name */
            lua_pop(L, 1);
        } else {
            lua_pop(L, 1);
        }
        {
            int printed = 0;
            lua_pushnil(L);
            printf("{");
            while (lua_next(L, -2) != 0) {
                if (printed) {
                    printf(", ");
                }
                if (lua_type(L, -2) == LUA_TSTRING) {
                    printf("%s=", lua_tostring(L, -2));
                } else {
                    printf("[%s]=", lua_typename(L, lua_type(L, -2)));
                }
                if (lua_type(L, -1) == LUA_TSTRING) {
                    printf("%s", lua_tostring(L, -1));
                } else if (lua_type(L, -1) == LUA_TNUMBER) {
                    if (lua_isinteger(L, -1)) {
                        printf("%lld", (long long)lua_tointeger(L, -1));
                    } else {
                        printf("%.3f", (double)lua_tonumber(L, -1));
                    }
                } else if (lua_type(L, -1) == LUA_TBOOLEAN) {
                    printf("%s", lua_toboolean(L, -1) ? "true" : "false");
                } else {
                    printf("<%s>", lua_typename(L, lua_type(L, -1)));
                }
                lua_pop(L, 1);
                printed = 1;
            }
            printf("}\n");
        }
        break;
    default:
        printf("<%s>\n", lua_typename(L, t));
        break;
    }
}

/**
 * Evaluate a line. Supports expression mode: if the chunk is an expression
 * that leaves a value, print it (like a simple lua REPL).
 */
static int eval_line(lua_State *L, const char *line)
{
    char expr[4096];
    int rc;
    int top0;
    size_t n;

    if (!line || !line[0]) {
        return 0;
    }

    top0 = lua_gettop(L);

    /* Prefer "return <line>" so bare expressions print results. */
    n = strlen(line);
    if (n + 16 < sizeof(expr)) {
        snprintf(expr, sizeof(expr), "return %s", line);
        rc = luaL_loadstring(L, expr);
        if (rc != LUA_OK) {
            lua_pop(L, 1);
            rc = luaL_loadstring(L, line);
        }
    } else {
        rc = luaL_loadstring(L, line);
    }

    if (rc != LUA_OK) {
        const char *msg = lua_tostring(L, -1);
        fprintf(stderr, "error: %s\n", msg ? msg : "load failed");
        lua_pop(L, 1);
        return -1;
    }

    rc = lua_pcall(L, 0, LUA_MULTRET, 0);
    if (rc != LUA_OK) {
        const char *msg = lua_tostring(L, -1);
        fprintf(stderr, "error: %s\n", msg ? msg : "runtime error");
        lua_pop(L, 1);
        return -1;
    }

    /* Print any returned values. */
    {
        int top1 = lua_gettop(L);
        int i;
        for (i = top0 + 1; i <= top1; i++) {
            lua_pushvalue(L, i);
            print_stack_top(L);
            lua_pop(L, 1);
        }
        lua_settop(L, top0);
    }
    return 0;
}

int cpe_lua_repl(cpe_lua_t *Lwrap, const char *history_path)
{
    char *line;
    const char *hist = history_path;
    lua_State *L;

    L = (lua_State *)cpe_lua_state(Lwrap);
    if (!Lwrap || !L) {
        fprintf(stderr, "cpe_agent: no Lua state for REPL\n");
        return 1;
    }

    if (!hist || !hist[0]) {
        const char *home = getenv("HOME");
        static char defhist[512];
        if (home && home[0]) {
            snprintf(defhist, sizeof(defhist), "%s/.cpe_agent_history", home);
        } else {
            snprintf(defhist, sizeof(defhist), "/tmp/cpe_agent_history");
        }
        hist = defhist;
    }

    linenoiseHistorySetMaxLen(256);
    linenoiseHistoryLoad(hist);
    linenoiseSetMultiLine(1);

    printf("cpe_agent Lua REPL  (type cpe.help()  ·  quit/exit/Ctrl-D to leave)\n");
    cpe_lua_print_help(stdout);
    printf("\n");

    while ((line = linenoise("cpe> ")) != NULL) {
        if (line[0] != '\0') {
            linenoiseHistoryAdd(line);
            linenoiseHistorySave(hist);
            if (is_exit_cmd(line)) {
                free(line);
                break;
            }
            (void)eval_line(L, line);
        }
        free(line);
    }

    linenoiseHistorySave(hist);
    printf("\n");
    return 0;
}

#endif /* CPE_AGENT_HAVE_LUA */
