/**
 * @file test_cpe_agent_lua.c
 * @brief Smoke tests for embedded Lua tools.
 *
 * Synthetic demo probes stay on the C API (fuzz / dialectic). Lua only
 * exposes live network tools; tests exercise binding + last_sample path.
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
    cpe_wifi_snapshot_t snap;

    printf("cpe_agent_lua:\n");

    a = cpe_agent_create();
    assert(a);
    L = cpe_lua_create(a);
    assert(L);

    err[0] = '\0';
    assert(cpe_lua_dostring(L, "assert(type(cpe) == 'table')", err, sizeof(err)) ==
           0);
    printf("  PASS: cpe table present\n");

    /* Demo surface must not be registered on the Lua table. */
    err[0] = '\0';
    assert(cpe_lua_dostring(
               L,
               "assert(cpe.set_demo == nil); "
               "assert(cpe.demo_ping == nil); "
               "assert(cpe.demo_arping == nil); "
               "assert(cpe.demo_wifi_stats == nil)",
               err, sizeof(err)) == 0);
    printf("  PASS: no demo_* / set_demo on cpe table\n");

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

    /* Seed last sample via C demo path (not Lua); Lua reads it back. */
    assert(cpe_agent_demo_ping_tick(a) == 0);
    assert(cpe_agent_last_sample(a, &s) == 0);
    assert(s.rtt_ms >= 0.0);

    err[0] = '\0';
    assert(cpe_lua_dostring(
               L,
               "local s = cpe.last_sample(); assert(s and s.rtt_ms ~= nil); "
               "assert(s.probe == 'ping')",
               err, sizeof(err)) == 0);
    printf("  PASS: cpe.last_sample (after C demo_ping_tick)\n");

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

    assert(cpe_agent_demo_arping(a, "10.0.0.1") == 0);
    assert(cpe_agent_last_sample(a, &s) == 0);
    assert(strcmp(s.probe, "arping") == 0);
    assert(strcmp(s.target, "10.0.0.1") == 0);
    err[0] = '\0';
    assert(cpe_lua_dostring(
               L,
               "local s = cpe.last_sample(); "
               "assert(s and s.probe == 'arping'); assert(s.target == '10.0.0.1')",
               err, sizeof(err)) == 0);
    printf("  PASS: last_sample after C demo_arping\n");

    err[0] = '\0';
    assert(cpe_lua_dostring(L, "cpe.set_iface('br-lan'); "
                               "assert(cpe.config().iface == 'br-lan')",
                            err, sizeof(err)) == 0);
    printf("  PASS: cpe.set_iface\n");

    assert(cpe_agent_demo_wifi_dump(a, 0, &snap) == 0);
    assert(snap.station_count >= 1);
    err[0] = '\0';
    assert(cpe_lua_dostring(
               L,
               "local w = cpe.last_wifi(); "
               "assert(w and w.stations and #w.stations >= 1); "
               "assert(w.stations[1].mac ~= nil)",
               err, sizeof(err)) == 0);
    printf("  PASS: cpe.last_wifi (after C demo_wifi_dump)\n");

    err[0] = '\0';
    assert(cpe_lua_dostring(
               L, "local t = cpe.wifi_list(); assert(type(t) == 'table')", err,
               sizeof(err)) == 0);
    printf("  PASS: cpe.wifi_list\n");

    /* Trace: Lua binds live tools; seed via C demo for last_trace. */
    err[0] = '\0';
    assert(cpe_lua_dostring(
               L,
               "assert(type(cpe.traceroute) == 'function'); "
               "assert(type(cpe.mtr) == 'function'); "
               "assert(type(cpe.last_trace) == 'function'); "
               "assert(cpe.demo_traceroute == nil)",
               err, sizeof(err)) == 0);
    printf("  PASS: traceroute/mtr on cpe table (no demo_traceroute)\n");

    {
        cpe_trace_result_t tr;
        assert(cpe_agent_demo_traceroute(a, "8.8.8.8", 4, &tr) == 0);
    }
    err[0] = '\0';
    assert(cpe_lua_dostring(
               L,
               "local t = cpe.last_trace(); "
               "assert(t and t.hops and #t.hops >= 1); "
               "assert(t.target == '8.8.8.8'); "
               "assert(t.hops[1].hop == 1); "
               "assert(t.reached == true)",
               err, sizeof(err)) == 0);
    printf("  PASS: cpe.last_trace (after C demo_traceroute)\n");

    cpe_lua_destroy(L);
    cpe_agent_destroy(a);
    printf("all passed\n");
    return 0;
#endif
}
