/**
 * Track 2 remainder: harness tool, fuzz stubs, optional sim, nfct reuse.
 */
#include "cpe_agent.h"
#include "cpe_agent_fuzz.h"
#include "cpe_host_alloc.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#if defined(CPE_AGENT_HAVE_HARNESS)
#include "cpe_harness.h"
#include "harness.h"
#endif

#if defined(CPE_AGENT_HAVE_LIBSIM)
#include "cpe_agent_sim.h"
#endif

static void wr32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

static void wr16_be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xFF);
    p[1] = (uint8_t)(v & 0xFF);
}

static void test_get_local_latency(void)
{
    cpe_agent_t *a = cpe_agent_create();
    cpe_agent_config_t cfg;
    char json[512];
    int n;

    assert(a);
    cpe_agent_config_defaults(&cfg);
    assert(cpe_agent_apply_config(a, &cfg) == 0);
    while (cpe_agent_next_event(a, &(cpe_agent_event_t){0}) == 1) {
    }

    n = cpe_agent_get_local_latency_json(a, json, sizeof(json));
    assert(n > 0);
    assert(strstr(json, "\"available\":false") != NULL);

    assert(cpe_agent_demo_ping_tick(a) == 0);
    n = cpe_agent_get_local_latency_json(a, json, sizeof(json));
    assert(n > 0);
    assert(strstr(json, "\"available\":true") != NULL);
    assert(strstr(json, "\"rtt_ms\"") != NULL);
    assert(strstr(json, "\"probe\":\"ping\"") != NULL);

    cpe_agent_destroy(a);
    printf("  PASS: get_local_latency json\n");
}

#if defined(CPE_AGENT_HAVE_HARNESS)
static void test_harness_tool(void)
{
    harness_config_t hcfg;
    harness_ctx_t *h;
    cpe_agent_t *a = cpe_agent_create();
    cpe_agent_config_t cfg;
    char out[512];
    char tools[2048];
    size_t tlen = 0;

    assert(a);
    cpe_agent_config_defaults(&cfg);
    assert(cpe_agent_apply_config(a, &cfg) == 0);
    while (cpe_agent_next_event(a, &(cpe_agent_event_t){0}) == 1) {
    }
    assert(cpe_agent_demo_ping_tick(a) == 0);

    harness_config_init_defaults(&hcfg);
    hcfg.workspace_id = "ws_cpe";
    hcfg.session_id = "sess_cpe";
    hcfg.acting_peer_id = "agent_cpe";
    h = harness_create_with_config(HARNESS_ROLE_MAIN, &hcfg);
    assert(h);
    assert(cpe_harness_register_tools(h) == 0);
    assert(harness_tool_count(h) >= 1);
    assert(harness_tools_to_json(h, tools, sizeof(tools), &tlen) == 0);
    assert(strstr(tools, "get_local_latency") != NULL);

    assert(cpe_harness_invoke_local(a, "get_local_latency", "{}", out,
                                    sizeof(out)) == 0);
    assert(strstr(out, "\"available\":true") != NULL);
    assert(cpe_harness_invoke_local(a, "no_such_tool", "{}", out, sizeof(out)) ==
           -1);

    harness_destroy(h);
    cpe_agent_destroy(a);
    printf("  PASS: harness get_local_latency\n");
}
#endif

static void test_fuzz_stub(void)
{
    static const uint8_t empty[] = {0};
    static const uint8_t yamlish[] =
        "router_id: fuzz-1\n"
        "demo:\n"
        "  enabled: true\n"
        "  interval_ms: 100\n";
    uint8_t junk[64];
    size_t i;

    assert(cpe_agent_fuzz_config_and_ndjson(NULL, 0) == 0);
    assert(cpe_agent_fuzz_config_and_ndjson(empty, 0) == 0);
    assert(cpe_agent_fuzz_config_and_ndjson(yamlish, strlen((const char *)yamlish)) ==
           0);
    for (i = 0; i < sizeof(junk); i++) {
        junk[i] = (uint8_t)(i * 17u);
    }
    junk[4] = 1; /* force demo tick path */
    assert(cpe_agent_fuzz_config_and_ndjson(junk, sizeof(junk)) == 0);
    printf("  PASS: fuzz config+ndjson stubs\n");
}

#if defined(CPE_AGENT_HAVE_LIBSIM)
static void test_sim_drive(void)
{
    uint8_t stream[] = {3, 10, 0, 20, 0, 5, 0}; /* 3+1 ticks, delays */
    cpe_agent_t *a = cpe_agent_create();
    cpe_agent_config_t cfg;

    assert(a);
    cpe_agent_config_defaults(&cfg);
    cfg.demo_mode = 1;
    assert(cpe_agent_apply_config(a, &cfg) == 0);
    while (cpe_agent_next_event(a, &(cpe_agent_event_t){0}) == 1) {
    }
    assert(cpe_agent_sim_drive(a, stream, sizeof(stream)) == 0);
    assert(cpe_agent_spool_depth(a) >= 1);
    assert(cpe_agent_sim_drive_standalone(stream, sizeof(stream)) == 0);
    cpe_agent_destroy(a);
    printf("  PASS: libsim drive\n");
}
#endif

static void test_nfct_reuse(void)
{
    cpe_agent_t *a = cpe_agent_create();
    cpe_agent_config_t cfg;
    uint8_t synth[32];
    int n;
    char line[768];
    FILE *mem;
    char out[2048];
    size_t nout;

    assert(a);
    cpe_agent_config_defaults(&cfg);
    snprintf(cfg.router_id, sizeof(cfg.router_id), "cpe-nfct-1");
    assert(cpe_agent_apply_config(a, &cfg) == 0);
    while (cpe_agent_next_event(a, &(cpe_agent_event_t){0}) == 1) {
    }

    memset(synth, 0, sizeof(synth));
    wr32_be(synth, 0x4E464354u);
    synth[4] = 1;
    synth[5] = 6;
    wr32_be(synth + 8, 0xC0A80132u);
    wr16_be(synth + 12, 12345);
    wr32_be(synth + 14, 0x08080808u);
    wr16_be(synth + 18, 53);
    wr32_be(synth + 20, 0xCB007109u);
    wr16_be(synth + 24, 54321);
    wr32_be(synth + 26, 0x08080808u);
    wr16_be(synth + 30, 53);

    n = cpe_agent_feed_nfct(a, synth, sizeof(synth), 1700000000000ull);
    assert(n >= 1);
    assert(cpe_agent_nfct_obs_count(a) >= 1);
    assert(cpe_agent_spool_depth(a) >= 1);

    mem = tmpfile();
    assert(mem);
    assert(cpe_agent_spool_flush(a, mem) >= 1);
    rewind(mem);
    nout = fread(out, 1, sizeof(out) - 1, mem);
    out[nout] = '\0';
    fclose(mem);
    assert(strstr(out, "\"type\":\"cpe_nat\"") != NULL);
    assert(strstr(out, "cpe-nfct-1") != NULL);
    (void)line;

    cpe_agent_destroy(a);
    printf("  PASS: nfct path reuse\n");
}

int main(void)
{
    printf("cpe_agent_track2:\n");
    test_get_local_latency();
#if defined(CPE_AGENT_HAVE_HARNESS)
    test_harness_tool();
#else
    printf("  SKIP: harness (not linked)\n");
#endif
    test_fuzz_stub();
#if defined(CPE_AGENT_HAVE_LIBSIM)
    test_sim_drive();
#else
    printf("  SKIP: libsim (not linked)\n");
#endif
    test_nfct_reuse();
    printf("all passed\n");
    return 0;
}
