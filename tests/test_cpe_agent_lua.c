/**
 * @file test_cpe_agent_lua.c
 * @brief Smoke tests for embedded Lua tools.
 */
#include "cpe_agent.h"
#include "cpe_agent_lua.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
#if !defined(CPE_AGENT_HAVE_LUA)
    printf("cpe_agent_lua: SKIP (not built with Lua)\n");
    return 0;
#else
    cpe_agent_t *a;
    cpe_lua_t *L;
    char err[256];
    cpe_perf_sample_t s;

    printf("cpe_agent_lua:\n");

    a = cpe_agent_create();
    assert(a);
    L = cpe_lua_create(a);
    assert(L);

    err[0] = '\0';
    assert(cpe_lua_dostring(L, "assert(type(cpe) == 'table')", err, sizeof(err)) ==
           0);
    printf("  PASS: cpe table present\n");

    err[0] = '\0';
    assert(cpe_lua_dostring(
               L, "local c = cpe.config(); assert(c.target ~= nil)", err,
               sizeof(err)) == 0);
    printf("  PASS: cpe.config()\n");

    err[0] = '\0';
    assert(cpe_lua_dostring(L, "cpe.set_target('8.8.8.8')", err, sizeof(err)) ==
           0);
    assert(strcmp(cpe_agent_config(a)->demo_target, "8.8.8.8") == 0);
    printf("  PASS: cpe.set_target\n");

    err[0] = '\0';
    assert(cpe_lua_dostring(
               L,
               "local s = cpe.demo_ping(); assert(s and s.rtt_ms ~= nil); "
               "assert(s.probe == 'ping')",
               err, sizeof(err)) == 0);
    assert(cpe_agent_last_sample(a, &s) == 0);
    assert(s.rtt_ms >= 0.0);
    printf("  PASS: cpe.demo_ping → sample\n");

    err[0] = '\0';
    assert(cpe_lua_dostring(
               L,
               "local j = cpe.ndjson(); assert(type(j) == 'string'); "
               "assert(j:find('cpe_perf', 1, true))",
               err, sizeof(err)) == 0);
    printf("  PASS: cpe.ndjson\n");

    err[0] = '\0';
    assert(cpe_lua_dostring(L, "assert(cpe.latency():find('available'))", err,
                            sizeof(err)) == 0);
    printf("  PASS: cpe.latency\n");

    err[0] = '\0';
    assert(cpe_lua_dostring(
               L,
               "local s = cpe.demo_arping('10.0.0.1'); "
               "assert(s and s.probe == 'arping'); assert(s.target == '10.0.0.1')",
               err, sizeof(err)) == 0);
    printf("  PASS: cpe.demo_arping\n");

    err[0] = '\0';
    assert(cpe_lua_dostring(L, "cpe.set_iface('br-lan'); "
                               "assert(cpe.config().iface == 'br-lan')",
                            err, sizeof(err)) == 0);
    printf("  PASS: cpe.set_iface\n");

    cpe_lua_destroy(L);
    cpe_agent_destroy(a);
    printf("all passed\n");
    return 0;
#endif
}
