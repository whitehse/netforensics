/**
 * @file lua_bind.c
 * @brief Embed Lua and expose cpe.* network exploration tools.
 */

#include "cpe_agent_lua.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(CPE_AGENT_HAVE_LUA)

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

struct cpe_lua {
    lua_State   *L;
    cpe_agent_t *agent;
};

/* ---- helpers ---- */

static cpe_agent_t *l_agent(lua_State *L)
{
    cpe_agent_t *a;

    lua_getfield(L, LUA_REGISTRYINDEX, "cpe_agent_ptr");
    a = (cpe_agent_t *)lua_touserdata(L, -1);
    lua_pop(L, 1);
    return a;
}

static void push_sample(lua_State *L, const cpe_perf_sample_t *s)
{
    lua_createtable(L, 0, 6);
    lua_pushstring(L, s->probe);
    lua_setfield(L, -2, "probe");
    lua_pushstring(L, s->target);
    lua_setfield(L, -2, "target");
    lua_pushnumber(L, s->rtt_ms);
    lua_setfield(L, -2, "rtt_ms");
    lua_pushnumber(L, (lua_Number)s->loss);
    lua_setfield(L, -2, "loss");
    lua_pushstring(L, s->ts_iso);
    lua_setfield(L, -2, "ts");
    lua_pushstring(L, s->meta);
    lua_setfield(L, -2, "meta");
}

static int drain_events(cpe_agent_t *a)
{
    cpe_agent_event_t ev;
    int n = 0;

    while (cpe_agent_next_event(a, &ev) == 1) {
        n++;
    }
    return n;
}

/* ---- cpe.* bindings ---- */

static int l_help(lua_State *L)
{
    (void)L;
    cpe_lua_print_help(stdout);
    return 0;
}

static int l_config(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    const cpe_agent_config_t *c;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    c = cpe_agent_config(a);
    lua_createtable(L, 0, 10);
    lua_pushstring(L, c->router_id);
    lua_setfield(L, -2, "router_id");
    lua_pushstring(L, c->emit_mode);
    lua_setfield(L, -2, "emit_mode");
    lua_pushstring(L, c->spool_path);
    lua_setfield(L, -2, "spool_path");
    lua_pushstring(L, c->demo_target);
    lua_setfield(L, -2, "target");
    lua_pushstring(L, c->arping_if);
    lua_setfield(L, -2, "iface");
    lua_pushstring(L, c->wifi_if);
    lua_setfield(L, -2, "wifi_if");
    lua_pushboolean(L, c->demo_mode ? 1 : 0);
    lua_setfield(L, -2, "demo");
    lua_pushinteger(L, (lua_Integer)c->demo_interval_ms);
    lua_setfield(L, -2, "interval_ms");
    lua_pushinteger(L, (lua_Integer)c->probe_timeout_ms);
    lua_setfield(L, -2, "timeout_ms");
    lua_pushinteger(L, (lua_Integer)c->spool_max_lines);
    lua_setfield(L, -2, "spool_max_lines");
    lua_pushinteger(L, (lua_Integer)c->generation);
    lua_setfield(L, -2, "generation");
    return 1;
}

static int l_set_target(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    cpe_agent_config_t cfg;
    const char *target;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    target = luaL_checkstring(L, 1);
    if (strlen(target) >= CPE_CFG_TARGET_MAX) {
        return luaL_error(L, "target too long");
    }
    cfg = *cpe_agent_config(a);
    snprintf(cfg.demo_target, sizeof(cfg.demo_target), "%s", target);
    if (cpe_agent_apply_config(a, &cfg) != 0) {
        drain_events(a);
        return luaL_error(L, "apply_config failed for target");
    }
    drain_events(a);
    lua_pushboolean(L, 1);
    return 1;
}

static int l_set_demo(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    cpe_agent_config_t cfg;
    int demo;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    demo = lua_toboolean(L, 1);
    cfg = *cpe_agent_config(a);
    cfg.demo_mode = demo ? 1 : 0;
    if (cpe_agent_apply_config(a, &cfg) != 0) {
        drain_events(a);
        return luaL_error(L, "apply_config failed for demo");
    }
    drain_events(a);
    lua_pushboolean(L, 1);
    return 1;
}

static int l_set_router_id(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    cpe_agent_config_t cfg;
    const char *rid;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    rid = luaL_checkstring(L, 1);
    if (strlen(rid) >= CPE_CFG_ROUTER_ID_MAX) {
        return luaL_error(L, "router_id too long");
    }
    cfg = *cpe_agent_config(a);
    snprintf(cfg.router_id, sizeof(cfg.router_id), "%s", rid);
    if (cpe_agent_apply_config(a, &cfg) != 0) {
        drain_events(a);
        return luaL_error(L, "apply_config failed for router_id");
    }
    drain_events(a);
    lua_pushboolean(L, 1);
    return 1;
}

static int l_set_interval(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    cpe_agent_config_t cfg;
    lua_Integer ms;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    ms = luaL_checkinteger(L, 1);
    if (ms < 1 || ms > 3600000) {
        return luaL_error(L, "interval_ms out of range");
    }
    cfg = *cpe_agent_config(a);
    cfg.demo_interval_ms = (uint32_t)ms;
    cfg.sample_interval_ms = (uint32_t)ms;
    if (cpe_agent_apply_config(a, &cfg) != 0) {
        drain_events(a);
        return luaL_error(L, "apply_config failed for interval");
    }
    drain_events(a);
    lua_pushboolean(L, 1);
    return 1;
}

static int l_demo_ping(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    cpe_perf_sample_t s;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    if (cpe_agent_demo_ping_tick(a) != 0) {
        return luaL_error(L, "demo_ping failed");
    }
    (void)cpe_agent_emit_flush(a);
    drain_events(a);
    if (cpe_agent_last_sample(a, &s) != 0) {
        lua_pushnil(L);
        return 1;
    }
    push_sample(L, &s);
    return 1;
}

static int l_live_ping(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    cpe_perf_sample_t s;
    const char *target = NULL;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    if (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) {
        target = luaL_checkstring(L, 1);
        if (strlen(target) >= CPE_CFG_TARGET_MAX) {
            return luaL_error(L, "target too long");
        }
        {
            cpe_agent_config_t cfg = *cpe_agent_config(a);
            snprintf(cfg.demo_target, sizeof(cfg.demo_target), "%s", target);
            cfg.demo_mode = 0;
            if (cpe_agent_apply_config(a, &cfg) != 0) {
                drain_events(a);
                return luaL_error(L, "apply_config failed");
            }
            drain_events(a);
        }
    } else {
        cpe_agent_config_t cfg = *cpe_agent_config(a);
        if (cfg.demo_mode) {
            cfg.demo_mode = 0;
            if (cpe_agent_apply_config(a, &cfg) != 0) {
                drain_events(a);
                return luaL_error(L, "cannot disable demo for live_ping");
            }
            drain_events(a);
        }
    }
    if (cpe_agent_live_ping_tick(a) != 0) {
        return luaL_error(L, "live_ping failed (ICMP socket / capability?)");
    }
    (void)cpe_agent_emit_flush(a);
    drain_events(a);
    if (cpe_agent_last_sample(a, &s) != 0) {
        lua_pushnil(L);
        return 1;
    }
    push_sample(L, &s);
    return 1;
}

static int l_demo_arping(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    cpe_perf_sample_t s;
    const char *target = NULL;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    if (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) {
        target = luaL_checkstring(L, 1);
    }
    if (cpe_agent_demo_arping(a, target) != 0) {
        return luaL_error(L, "demo_arping failed");
    }
    (void)cpe_agent_emit_flush(a);
    drain_events(a);
    if (cpe_agent_last_sample(a, &s) != 0) {
        lua_pushnil(L);
        return 1;
    }
    push_sample(L, &s);
    return 1;
}

static int l_arping(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    cpe_perf_sample_t s;
    const char *target = NULL;
    const char *iface = NULL;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    if (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) {
        target = luaL_checkstring(L, 1);
        if (strlen(target) >= CPE_CFG_TARGET_MAX) {
            return luaL_error(L, "target too long");
        }
    }
    if (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) {
        iface = luaL_checkstring(L, 2);
        if (strlen(iface) >= CPE_CFG_IFACE_MAX) {
            return luaL_error(L, "iface too long");
        }
    }
    if (cpe_agent_arping(a, target, iface) != 0) {
        return luaL_error(
            L, "arping failed (AF_PACKET / CAP_NET_RAW / bad iface or IP?)");
    }
    (void)cpe_agent_emit_flush(a);
    drain_events(a);
    if (cpe_agent_last_sample(a, &s) != 0) {
        lua_pushnil(L);
        return 1;
    }
    push_sample(L, &s);
    return 1;
}

static int l_set_iface(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    cpe_agent_config_t cfg;
    const char *iface;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    iface = luaL_checkstring(L, 1);
    if (strlen(iface) >= CPE_CFG_IFACE_MAX) {
        return luaL_error(L, "iface too long");
    }
    cfg = *cpe_agent_config(a);
    snprintf(cfg.arping_if, sizeof(cfg.arping_if), "%s", iface);
    if (cpe_agent_apply_config(a, &cfg) != 0) {
        drain_events(a);
        return luaL_error(L, "apply_config failed for iface");
    }
    drain_events(a);
    lua_pushboolean(L, 1);
    return 1;
}

static int l_set_wifi_if(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    cpe_agent_config_t cfg;
    const char *iface;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    iface = luaL_checkstring(L, 1);
    if (strlen(iface) >= CPE_CFG_IFACE_MAX) {
        return luaL_error(L, "wifi iface too long");
    }
    cfg = *cpe_agent_config(a);
    snprintf(cfg.wifi_if, sizeof(cfg.wifi_if), "%s", iface);
    if (cpe_agent_apply_config(a, &cfg) != 0) {
        drain_events(a);
        return luaL_error(L, "apply_config failed for wifi_if");
    }
    drain_events(a);
    lua_pushboolean(L, 1);
    return 1;
}

static void push_wifi_iface(lua_State *L, const cpe_wifi_iface_state_t *i)
{
    lua_createtable(L, 0, 8);
    lua_pushstring(L, i->ifname);
    lua_setfield(L, -2, "ifname");
    lua_pushinteger(L, i->ifindex);
    lua_setfield(L, -2, "ifindex");
    lua_pushboolean(L, i->up ? 1 : 0);
    lua_setfield(L, -2, "up");
    lua_pushboolean(L, i->running ? 1 : 0);
    lua_setfield(L, -2, "running");
    lua_pushboolean(L, i->wireless ? 1 : 0);
    lua_setfield(L, -2, "wireless");
    lua_pushstring(L, i->operstate);
    lua_setfield(L, -2, "operstate");
    lua_pushstring(L, i->mac);
    lua_setfield(L, -2, "mac");
    lua_pushinteger(L, (lua_Integer)i->mtu);
    lua_setfield(L, -2, "mtu");
}

static void push_wifi_station(lua_State *L, const cpe_wifi_station_t *s)
{
    lua_createtable(L, 0, 12);
    lua_pushstring(L, s->mac);
    lua_setfield(L, -2, "mac");
    lua_pushinteger(L, (lua_Integer)s->signal_dbm);
    lua_setfield(L, -2, "rssi");
    lua_pushinteger(L, (lua_Integer)s->signal_avg_dbm);
    lua_setfield(L, -2, "rssi_avg");
    lua_pushinteger(L, (lua_Integer)s->snr_db);
    lua_setfield(L, -2, "snr");
    lua_pushinteger(L, (lua_Integer)s->mcs);
    lua_setfield(L, -2, "mcs");
    lua_pushinteger(L, (lua_Integer)s->tx_retries);
    lua_setfield(L, -2, "tx_retries");
    lua_pushinteger(L, (lua_Integer)s->tx_failed);
    lua_setfield(L, -2, "tx_failed");
    lua_pushinteger(L, (lua_Integer)s->rx_bytes);
    lua_setfield(L, -2, "rx_bytes");
    lua_pushinteger(L, (lua_Integer)s->tx_bytes);
    lua_setfield(L, -2, "tx_bytes");
    lua_pushinteger(L, (lua_Integer)s->freq_mhz);
    lua_setfield(L, -2, "freq_mhz");
    lua_pushboolean(L, s->has_signal ? 1 : 0);
    lua_setfield(L, -2, "has_signal");
    lua_pushboolean(L, s->has_mcs ? 1 : 0);
    lua_setfield(L, -2, "has_mcs");
}

static void push_wifi_snapshot(lua_State *L, const cpe_wifi_snapshot_t *snap)
{
    size_t i;

    lua_createtable(L, 0, 6);
    push_wifi_iface(L, &snap->iface);
    lua_setfield(L, -2, "iface");

    lua_createtable(L, (int)snap->station_count, 0);
    for (i = 0; i < snap->station_count; i++) {
        push_wifi_station(L, &snap->stations[i]);
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    lua_setfield(L, -2, "stations");

    lua_pushinteger(L, (lua_Integer)snap->station_count);
    lua_setfield(L, -2, "station_count");
    lua_pushboolean(L, snap->stations_valid ? 1 : 0);
    lua_setfield(L, -2, "stations_valid");
    lua_pushboolean(L, snap->demo ? 1 : 0);
    lua_setfield(L, -2, "demo");
    lua_pushstring(L, snap->ts_iso);
    lua_setfield(L, -2, "ts");
    if (snap->err[0]) {
        lua_pushstring(L, snap->err);
        lua_setfield(L, -2, "err");
    }
}

static int l_wifi_state(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    cpe_wifi_iface_state_t st;
    const char *iface = NULL;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    if (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) {
        iface = luaL_checkstring(L, 1);
    }
    if (cpe_agent_wifi_iface_state(a, iface, &st) != 0) {
        return luaL_error(L, "wifi iface not found");
    }
    push_wifi_iface(L, &st);
    return 1;
}

static int l_wifi_stats(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    cpe_wifi_snapshot_t snap;
    const char *iface = NULL;
    int emit = 0;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    if (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) {
        iface = luaL_checkstring(L, 1);
    }
    if (lua_gettop(L) >= 2) {
        emit = lua_toboolean(L, 2);
    }
    if (cpe_agent_wifi_dump(a, iface, emit, &snap) != 0) {
        return luaL_error(L, "wifi dump failed (iface missing?)");
    }
    drain_events(a);
    push_wifi_snapshot(L, &snap);
    return 1;
}

static int l_wifi_list(lua_State *L)
{
    char names[CPE_WIFI_STA_MAX][CPE_WIFI_IFNAME_MAX];
    int n;
    int i;

    /*
     * Convenience: cpe.wifi_list("ath0", true) is a common mix-up with
     * wifi_stats(iface, emit). If the first arg is a string, forward.
     */
    if (lua_gettop(L) >= 1 && lua_type(L, 1) == LUA_TSTRING) {
        fprintf(stderr,
                "cpe: note: wifi_list() takes no args; "
                "forwarding to wifi_stats(iface, emit)\n");
        return l_wifi_stats(L);
    }

    n = cpe_agent_wifi_list_ifaces(names, CPE_WIFI_STA_MAX);
    if (n < 0) {
        n = 0;
    }
    lua_createtable(L, n, 0);
    for (i = 0; i < n; i++) {
        lua_pushstring(L, names[i]);
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

static int l_demo_wifi_stats(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    cpe_wifi_snapshot_t snap;
    int emit = 1;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    if (lua_gettop(L) >= 1) {
        emit = lua_toboolean(L, 1);
    }
    if (cpe_agent_demo_wifi_dump(a, emit, &snap) != 0) {
        return luaL_error(L, "demo_wifi_dump failed");
    }
    drain_events(a);
    push_wifi_snapshot(L, &snap);
    return 1;
}

static int l_last_wifi(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    cpe_wifi_snapshot_t snap;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    if (cpe_agent_last_wifi(a, &snap) != 0) {
        lua_pushnil(L);
        return 1;
    }
    push_wifi_snapshot(L, &snap);
    return 1;
}

static int l_sample(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    cpe_perf_sample_t s;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    if (cpe_agent_sample_tick(a) != 0) {
        return luaL_error(L, "sample_tick failed");
    }
    (void)cpe_agent_emit_flush(a);
    drain_events(a);
    if (cpe_agent_last_sample(a, &s) != 0) {
        lua_pushnil(L);
        return 1;
    }
    push_sample(L, &s);
    return 1;
}

static int l_last_sample(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    cpe_perf_sample_t s;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    if (cpe_agent_last_sample(a, &s) != 0) {
        lua_pushnil(L);
        return 1;
    }
    push_sample(L, &s);
    return 1;
}

static int l_latency(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    char buf[512];
    int n;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    n = cpe_agent_get_local_latency_json(a, buf, sizeof(buf));
    if (n < 0) {
        return luaL_error(L, "latency json failed");
    }
    lua_pushlstring(L, buf, (size_t)n);
    return 1;
}

static int l_emit(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    int n;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    n = cpe_agent_emit_flush(a);
    if (n < 0) {
        return luaL_error(L, "emit_flush failed");
    }
    lua_pushinteger(L, n);
    return 1;
}

static int l_spool_depth(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);

    if (!a) {
        return luaL_error(L, "no agent");
    }
    lua_pushinteger(L, (lua_Integer)cpe_agent_spool_depth(a));
    return 1;
}

static int l_spool_drops(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);

    if (!a) {
        return luaL_error(L, "no agent");
    }
    lua_pushinteger(L, (lua_Integer)cpe_agent_spool_drops(a));
    return 1;
}

static int l_reload(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    const char *path = NULL;
    char err[160];

    if (!a) {
        return luaL_error(L, "no agent");
    }
    if (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) {
        path = luaL_checkstring(L, 1);
    }
    err[0] = '\0';
    if (cpe_agent_reload_config(a, path, NULL, err, sizeof(err)) != 0) {
        drain_events(a);
        return luaL_error(L, "reload failed: %s", err[0] ? err : "unknown");
    }
    drain_events(a);
    lua_pushboolean(L, 1);
    return 1;
}

static int l_dofile_tool(lua_State *L)
{
    cpe_lua_t *wrap;
    const char *path;
    char err[256];

    path = luaL_checkstring(L, 1);
    lua_getfield(L, LUA_REGISTRYINDEX, "cpe_lua_wrap");
    wrap = (cpe_lua_t *)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!wrap) {
        return luaL_error(L, "no lua wrap");
    }
    err[0] = '\0';
    if (cpe_lua_dofile(wrap, path, err, sizeof(err)) != 0) {
        return luaL_error(L, "%s", err[0] ? err : "dofile failed");
    }
    return 0;
}

static int l_ndjson(lua_State *L)
{
    cpe_agent_t *a = l_agent(L);
    cpe_perf_sample_t s;
    char line[CPE_NDJSON_LINE_MAX];
    const cpe_agent_config_t *c;
    int n;

    if (!a) {
        return luaL_error(L, "no agent");
    }
    if (cpe_agent_last_sample(a, &s) != 0) {
        lua_pushnil(L);
        return 1;
    }
    c = cpe_agent_config(a);
    n = cpe_perf_format_ndjson(c->router_id, &s, line, sizeof(line));
    if (n < 0) {
        return luaL_error(L, "format failed");
    }
    lua_pushlstring(L, line, (size_t)n);
    return 1;
}

static const luaL_Reg cpe_funcs[] = {
    {"help", l_help},
    {"config", l_config},
    {"set_target", l_set_target},
    {"set_demo", l_set_demo},
    {"set_router_id", l_set_router_id},
    {"set_interval", l_set_interval},
    {"set_iface", l_set_iface},
    {"set_wifi_if", l_set_wifi_if},
    {"demo_ping", l_demo_ping},
    {"live_ping", l_live_ping},
    {"demo_arping", l_demo_arping},
    {"arping", l_arping},
    {"wifi_list", l_wifi_list},
    {"wifi_state", l_wifi_state},
    {"wifi_stats", l_wifi_stats},
    {"demo_wifi_stats", l_demo_wifi_stats},
    {"last_wifi", l_last_wifi},
    {"sample", l_sample},
    {"last_sample", l_last_sample},
    {"latency", l_latency},
    {"emit", l_emit},
    {"spool_depth", l_spool_depth},
    {"spool_drops", l_spool_drops},
    {"reload", l_reload},
    {"dofile", l_dofile_tool},
    {"ndjson", l_ndjson},
    {NULL, NULL}
};

static void register_cpe(lua_State *L, cpe_agent_t *agent, cpe_lua_t *wrap)
{
    lua_pushlightuserdata(L, agent);
    lua_setfield(L, LUA_REGISTRYINDEX, "cpe_agent_ptr");
    lua_pushlightuserdata(L, wrap);
    lua_setfield(L, LUA_REGISTRYINDEX, "cpe_lua_wrap");

    luaL_newlib(L, cpe_funcs);
    lua_setglobal(L, "cpe");
}

void cpe_lua_print_help(FILE *fp)
{
    if (!fp) {
        fp = stdout;
    }
    fprintf(fp,
            "cpe_agent Lua tools (global table `cpe`):\n"
            "  cpe.help()                 -- this text\n"
            "  cpe.config()               -- current config table\n"
            "  cpe.set_target(ip)         -- probe destination (ping/arping)\n"
            "  cpe.set_demo(bool)         -- true=synthetic, false=live ICMP\n"
            "  cpe.set_router_id(id)\n"
            "  cpe.set_interval(ms)\n"
            "  cpe.set_iface(name)        -- L2 interface for arping\n"
            "  cpe.set_wifi_if(name)      -- Wi-Fi iface for nl80211 stats\n"
            "  cpe.demo_ping()            -- synthetic ICMP sample → table\n"
            "  cpe.live_ping([ip])        -- live ICMP sample → table + emit\n"
            "  cpe.demo_arping([ip])      -- synthetic ARP sample → table\n"
            "  cpe.arping([ip],[iface])   -- live ARP (CAP_NET_RAW) → table\n"
            "  cpe.wifi_list()            -- wireless-looking ifaces\n"
            "  cpe.wifi_state([iface])    -- operstate/up/mac/mtu table\n"
            "  cpe.wifi_stats([iface],[emit]) -- iface + station dump (nl80211)\n"
            "  cpe.demo_wifi_stats([emit])-- synthetic station snapshot\n"
            "  cpe.last_wifi()            -- last Wi-Fi snapshot or nil\n"
            "  cpe.sample()               -- one tick (demo or live per config)\n"
            "  cpe.last_sample()          -- last sample table or nil\n"
            "  cpe.latency()              -- JSON string (get_local_latency)\n"
            "  cpe.ndjson()               -- last sample as cpe_perf line\n"
            "  cpe.emit()                 -- flush spool per emit.mode\n"
            "  cpe.spool_depth() / cpe.spool_drops()\n"
            "  cpe.reload([path])         -- re-read YAML\n"
            "  cpe.dofile(path)           -- run a tool script\n"
            "\n"
            "REPL: quit | exit | Ctrl-D to leave. Up-arrow recalls history.\n"
            "AI harness: register tool scripts that call cpe.* and return tables.\n");
}

cpe_lua_t *cpe_lua_create(cpe_agent_t *agent)
{
    cpe_lua_t *wrap;
    lua_State *L;

    if (!agent) {
        return NULL;
    }
    wrap = (cpe_lua_t *)calloc(1, sizeof(*wrap));
    if (!wrap) {
        return NULL;
    }
    L = luaL_newstate();
    if (!L) {
        free(wrap);
        return NULL;
    }
    luaL_openlibs(L);
    wrap->L = L;
    wrap->agent = agent;
    register_cpe(L, agent, wrap);
    return wrap;
}

void cpe_lua_destroy(cpe_lua_t *Lwrap)
{
    if (!Lwrap) {
        return;
    }
    if (Lwrap->L) {
        lua_close(Lwrap->L);
        Lwrap->L = NULL;
    }
    free(Lwrap);
}

void *cpe_lua_state(cpe_lua_t *Lwrap)
{
    return Lwrap ? (void *)Lwrap->L : NULL;
}

int cpe_lua_dostring(cpe_lua_t *Lwrap, const char *src, char *err, size_t err_len)
{
    int rc;

    if (!Lwrap || !Lwrap->L || !src) {
        if (err && err_len) {
            snprintf(err, err_len, "bad args");
        }
        return -1;
    }
    rc = luaL_dostring(Lwrap->L, src);
    if (rc != LUA_OK) {
        const char *msg = lua_tostring(Lwrap->L, -1);
        if (err && err_len) {
            snprintf(err, err_len, "%s", msg ? msg : "lua error");
        }
        lua_pop(Lwrap->L, 1);
        return -1;
    }
    return 0;
}

int cpe_lua_dofile(cpe_lua_t *Lwrap, const char *path, char *err, size_t err_len)
{
    int rc;

    if (!Lwrap || !Lwrap->L || !path) {
        if (err && err_len) {
            snprintf(err, err_len, "bad args");
        }
        return -1;
    }
    rc = luaL_dofile(Lwrap->L, path);
    if (rc != LUA_OK) {
        const char *msg = lua_tostring(Lwrap->L, -1);
        if (err && err_len) {
            snprintf(err, err_len, "%s", msg ? msg : "lua error");
        }
        lua_pop(Lwrap->L, 1);
        return -1;
    }
    return 0;
}

#else /* !CPE_AGENT_HAVE_LUA */

struct cpe_lua {
    int unused;
};

void cpe_lua_print_help(FILE *fp)
{
    if (!fp) {
        fp = stdout;
    }
    fprintf(fp, "cpe_agent: Lua support not built (CPE_AGENT_WITH_LUA=OFF)\n");
}

cpe_lua_t *cpe_lua_create(cpe_agent_t *agent)
{
    (void)agent;
    return NULL;
}

void cpe_lua_destroy(cpe_lua_t *Lwrap)
{
    (void)Lwrap;
}

void *cpe_lua_state(cpe_lua_t *Lwrap)
{
    (void)Lwrap;
    return NULL;
}

int cpe_lua_dostring(cpe_lua_t *Lwrap, const char *src, char *err, size_t err_len)
{
    (void)Lwrap;
    (void)src;
    if (err && err_len) {
        snprintf(err, err_len, "Lua not built in");
    }
    return -1;
}

int cpe_lua_dofile(cpe_lua_t *Lwrap, const char *path, char *err, size_t err_len)
{
    (void)Lwrap;
    (void)path;
    if (err && err_len) {
        snprintf(err, err_len, "Lua not built in");
    }
    return -1;
}

int cpe_lua_repl(cpe_lua_t *Lwrap, const char *history_path)
{
    (void)Lwrap;
    (void)history_path;
    fprintf(stderr, "cpe_agent: Lua REPL not available (build with -DCPE_AGENT_WITH_LUA=ON)\n");
    return 1;
}

#endif /* CPE_AGENT_HAVE_LUA */
