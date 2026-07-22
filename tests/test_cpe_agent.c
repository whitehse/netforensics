/**
 * Track 2: CPE agent config, NDJSON, spool, demo ping, host_alloc, HUP flag.
 */
#include "cpe_agent.h"
#include "cpe_agent_tls.h"
#include "cpe_host_alloc.h"
#include "cpe_spool.h"

#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void test_defaults_validate(void)
{
    cpe_agent_config_t c;
    char err[64];

    cpe_agent_config_defaults(&c);
    assert(cpe_agent_config_validate(&c, err, sizeof(err)) == 0);
    assert(c.demo_mode == 1);
    assert(strcmp(c.emit_mode, "stdout") == 0);

    c.router_id[0] = '\0';
    assert(cpe_agent_config_validate(&c, err, sizeof(err)) == -1);
    printf("  PASS: defaults + validate\n");
}

static void test_yaml_load(void)
{
    const char *yaml =
        "router_id: cpe-yaml-1\n"
        "emit:\n"
        "  mode: spool\n"
        "spool:\n"
        "  max_lines: 32\n"
        "demo:\n"
        "  enabled: true\n"
        "  target: \"8.8.8.8\"\n"
        "  interval_ms: 1000\n";
    cpe_agent_config_t cfg;
    char err[128];

    assert(cpe_agent_config_load_yaml_buf(yaml, strlen(yaml), &cfg, err,
                                          sizeof(err)) == 0);
    assert(strcmp(cfg.router_id, "cpe-yaml-1") == 0);
    assert(strcmp(cfg.emit_mode, "spool") == 0);
    assert(cfg.spool_max_lines == 32);
    assert(strcmp(cfg.demo_target, "8.8.8.8") == 0);
    assert(cfg.demo_interval_ms == 1000);
    assert(cfg.demo_mode == 1);
    printf("  PASS: yaml load\n");
}

static void test_ndjson_format(void)
{
    cpe_perf_sample_t s;
    char buf[512];
    int n;

    memset(&s, 0, sizeof(s));
    snprintf(s.probe, sizeof(s.probe), "ping");
    snprintf(s.target, sizeof(s.target), "1.1.1.1");
    s.rtt_ms = 12.4;
    s.loss = 0.0f;
    snprintf(s.ts_iso, sizeof(s.ts_iso), "2026-07-18T12:00:00.123Z");
    snprintf(s.meta, sizeof(s.meta), "{}");

    n = cpe_perf_format_ndjson("cpe-001", &s, buf, sizeof(buf));
    assert(n > 0);
    assert(strstr(buf, "\"type\":\"cpe_perf\"") != NULL);
    assert(strstr(buf, "\"router_id\":\"cpe-001\"") != NULL);
    assert(strstr(buf, "\"probe\":\"ping\"") != NULL);
    assert(strstr(buf, "\"target\":\"1.1.1.1\"") != NULL);
    assert(strstr(buf, "12.400") != NULL || strstr(buf, "12.4") != NULL);
    printf("  PASS: ndjson format\n");
}

static void test_demo_ping_and_spool(void)
{
    cpe_agent_t *a = cpe_agent_create();
    cpe_agent_config_t cfg;
    cpe_agent_event_t ev;
    cpe_perf_sample_t last;
    char line[512];
    FILE *mem;
    char out[2048];
    size_t nout;

    assert(a);
    cpe_agent_config_defaults(&cfg);
    cfg.demo_mode = 1;
    snprintf(cfg.router_id, sizeof(cfg.router_id), "cpe-test-1");
    assert(cpe_agent_apply_config(a, &cfg) == 0);
    assert(cpe_agent_next_event(a, &ev) == 1);
    assert(ev.type == CPE_AGENT_EVENT_CONFIG_APPLIED);
    assert(cpe_agent_config(a)->generation == 1);

    assert(cpe_agent_demo_ping_tick(a) == 0);
    assert(cpe_agent_spool_depth(a) >= 1);
    assert(cpe_agent_last_sample(a, &last) == 0);
    assert(strcmp(last.probe, "ping") == 0);
    assert(last.rtt_ms >= 0.0);

    assert(cpe_perf_format_ndjson(cfg.router_id, &last, line, sizeof(line)) > 0);
    assert(strstr(line, "cpe_perf") != NULL);

    mem = tmpfile();
    assert(mem);
    assert(cpe_agent_spool_flush(a, mem) >= 1);
    assert(cpe_agent_spool_depth(a) == 0);
    rewind(mem);
    nout = fread(out, 1, sizeof(out) - 1, mem);
    out[nout] = '\0';
    fclose(mem);
    assert(strstr(out, "\"type\":\"cpe_perf\"") != NULL);
    assert(strstr(out, "cpe-test-1") != NULL);

    /* drain SAMPLE_READY */
    while (cpe_agent_next_event(a, &ev) == 1) {
    }

    cpe_agent_destroy(a);
    printf("  PASS: demo ping + spool\n");
}

static void test_host_alloc_stats(void)
{
    void *p;

    cpe_host_alloc_reset_stats();
    p = cpe_host_alloc(64);
    assert(p);
    assert(cpe_host_alloc_count() == 1);
    assert(cpe_host_bytes_outstanding() >= 64);
    cpe_host_free(p);
    assert(cpe_host_free_count() == 1);
    printf("  PASS: host_alloc stats\n");
}

static void test_hup_flag(void)
{
    cpe_agent_hup_install();
    assert(cpe_agent_hup_take() == 0);
    raise(SIGHUP);
    assert(cpe_agent_hup_take() == 1);
    assert(cpe_agent_hup_take() == 0);
    printf("  PASS: HUP flag\n");
}

static void test_reject_keeps_generation(void)
{
    cpe_agent_t *a = cpe_agent_create();
    cpe_agent_config_t good;
    cpe_agent_config_t bad;
    cpe_agent_event_t ev;
    uint64_t gen;

    cpe_agent_config_defaults(&good);
    assert(cpe_agent_apply_config(a, &good) == 0);
    while (cpe_agent_next_event(a, &ev) == 1) {
    }
    gen = cpe_agent_config(a)->generation;

    cpe_agent_config_defaults(&bad);
    bad.router_id[0] = '\0';
    assert(cpe_agent_apply_config(a, &bad) == -1);
    assert(cpe_agent_next_event(a, &ev) == 1);
    assert(ev.type == CPE_AGENT_EVENT_CONFIG_REJECTED);
    assert(cpe_agent_config(a)->generation == gen);

    cpe_agent_destroy(a);
    printf("  PASS: reject keeps generation\n");
}

static void test_spool_mode_requires_path(void)
{
    cpe_agent_config_t c;
    char err[64];

    cpe_agent_config_defaults(&c);
    snprintf(c.emit_mode, sizeof(c.emit_mode), "spool");
    c.spool_path[0] = '\0';
    assert(cpe_agent_config_validate(&c, err, sizeof(err)) == -1);
    assert(strstr(err, "path") != NULL);
    printf("  PASS: spool mode requires path\n");
}

static void test_emit_flush_spool_file(void)
{
    cpe_agent_t *a = cpe_agent_create();
    cpe_agent_config_t cfg;
    char path[] = "/tmp/cpe_agent_test_spool_XXXXXX";
    int fd;
    FILE *fp;
    char buf[2048];
    size_t n;
    cpe_agent_event_t ev;

    assert(a);
    fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);

    cpe_agent_config_defaults(&cfg);
    snprintf(cfg.emit_mode, sizeof(cfg.emit_mode), "spool");
    snprintf(cfg.spool_path, sizeof(cfg.spool_path), "%s", path);
    snprintf(cfg.router_id, sizeof(cfg.router_id), "cpe-spool-1");
    assert(cpe_agent_apply_config(a, &cfg) == 0);
    while (cpe_agent_next_event(a, &ev) == 1) {
    }

    assert(cpe_agent_demo_ping_tick(a) == 0);
    assert(cpe_agent_emit_flush(a) >= 1);
    assert(cpe_agent_spool_depth(a) == 0);

    fp = fopen(path, "r");
    assert(fp);
    n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    unlink(path);

    assert(strstr(buf, "\"type\":\"cpe_perf\"") != NULL);
    assert(strstr(buf, "cpe-spool-1") != NULL);

    cpe_agent_destroy(a);
    printf("  PASS: emit_flush spool file\n");
}

static void test_reload_config_override(void)
{
    cpe_agent_t *a = cpe_agent_create();
    char err[128];
    char yaml_path[] = "/tmp/cpe_agent_reload_XXXXXX";
    int fd;
    FILE *fp;
    const char *yaml =
        "router_id: from-file\n"
        "emit:\n"
        "  mode: stdout\n"
        "demo:\n"
        "  enabled: true\n"
        "  target: \"9.9.9.9\"\n"
        "  interval_ms: 2000\n";
    cpe_agent_event_t ev;
    uint64_t gen1;

    assert(a);
    fd = mkstemp(yaml_path);
    assert(fd >= 0);
    fp = fdopen(fd, "w");
    assert(fp);
    fputs(yaml, fp);
    fclose(fp);

    err[0] = '\0';
    assert(cpe_agent_reload_config(a, yaml_path, "cli-router", err,
                                   sizeof(err)) == 0);
    while (cpe_agent_next_event(a, &ev) == 1) {
    }
    assert(strcmp(cpe_agent_config(a)->router_id, "cli-router") == 0);
    assert(strcmp(cpe_agent_config(a)->demo_target, "9.9.9.9") == 0);
    assert(cpe_agent_config(a)->demo_interval_ms == 2000);
    gen1 = cpe_agent_config(a)->generation;

    /* Simulate HUP: reload same file, override still wins. */
    assert(cpe_agent_reload_config(a, yaml_path, "cli-router", err,
                                   sizeof(err)) == 0);
    while (cpe_agent_next_event(a, &ev) == 1) {
    }
    assert(strcmp(cpe_agent_config(a)->router_id, "cli-router") == 0);
    assert(cpe_agent_config(a)->generation == gen1 + 1);

    unlink(yaml_path);
    cpe_agent_destroy(a);
    printf("  PASS: reload_config + router override\n");
}

static void test_sample_tick_demo(void)
{
    cpe_agent_t *a = cpe_agent_create();
    cpe_agent_config_t cfg;
    cpe_agent_event_t ev;

    assert(a);
    cpe_agent_config_defaults(&cfg);
    cfg.demo_mode = 1;
    assert(cpe_agent_apply_config(a, &cfg) == 0);
    while (cpe_agent_next_event(a, &ev) == 1) {
    }
    assert(cpe_agent_sample_tick(a) == 0);
    assert(cpe_agent_spool_depth(a) >= 1);
    cpe_agent_destroy(a);
    printf("  PASS: sample_tick demo\n");
}

static void test_live_ping_or_skip(void)
{
    cpe_agent_t *a = cpe_agent_create();
    cpe_agent_config_t cfg;
    cpe_agent_event_t ev;
    int rc;

    assert(a);
    cpe_agent_config_defaults(&cfg);
    cfg.demo_mode = 0;
    cfg.probe_timeout_ms = 200;
    snprintf(cfg.demo_target, sizeof(cfg.demo_target), "127.0.0.1");
    assert(cpe_agent_apply_config(a, &cfg) == 0);
    while (cpe_agent_next_event(a, &ev) == 1) {
    }
    rc = cpe_agent_live_ping_tick(a);
    /* May fail without ICMP capability; success enqueues a sample. */
    if (rc == 0) {
        assert(cpe_agent_spool_depth(a) >= 1);
        printf("  PASS: live_ping_tick (sample enqueued)\n");
    } else {
        printf("  PASS: live_ping_tick skipped (no ICMP socket / capability)\n");
    }
    cpe_agent_destroy(a);
}

static void test_demo_arping(void)
{
    cpe_agent_t *a = cpe_agent_create();
    cpe_agent_config_t cfg;
    cpe_agent_event_t ev;
    cpe_perf_sample_t s;

    assert(a);
    cpe_agent_config_defaults(&cfg);
    assert(cpe_agent_apply_config(a, &cfg) == 0);
    while (cpe_agent_next_event(a, &ev) == 1) {
    }
    assert(cpe_agent_demo_arping(a, "192.168.1.1") == 0);
    assert(cpe_agent_last_sample(a, &s) == 0);
    assert(strcmp(s.probe, "arping") == 0);
    assert(strcmp(s.target, "192.168.1.1") == 0);
    assert(strstr(s.meta, "demo\":true") != NULL ||
           strstr(s.meta, "\"demo\":true") != NULL);
    assert(cpe_agent_spool_depth(a) >= 1);
    cpe_agent_destroy(a);
    printf("  PASS: demo_arping\n");
}

static void test_demo_wifi(void)
{
    cpe_agent_t *a = cpe_agent_create();
    cpe_agent_config_t cfg;
    cpe_agent_event_t ev;
    cpe_wifi_snapshot_t snap;
    cpe_wifi_snapshot_t last;

    assert(a);
    cpe_agent_config_defaults(&cfg);
    assert(cpe_agent_apply_config(a, &cfg) == 0);
    while (cpe_agent_next_event(a, &ev) == 1) {
    }
    assert(cpe_agent_demo_wifi_dump(a, 0, &snap) == 0);
    assert(snap.demo == 1);
    assert(snap.stations_valid == 1);
    assert(snap.station_count >= 1);
    assert(snap.stations[0].mac[0] != '\0');
    assert(cpe_agent_last_wifi(a, &last) == 0);
    assert(last.station_count == snap.station_count);
    /* emit=1 flushes to stdout (spool ends empty); just ensure no crash */
    assert(cpe_agent_demo_wifi_dump(a, 1, &snap) == 0);
    cpe_agent_destroy(a);
    printf("  PASS: demo_wifi_dump\n");
}

static void test_tls_stub_or_build(void)
{
    char err[128];
    int avail = cpe_agent_tls_available();

    err[0] = '\0';
    if (!avail) {
        assert(cpe_agent_tls_post("https://example.invalid/x", "{}", 2, NULL,
                                  NULL, NULL, err, sizeof(err)) == -1);
        assert(strstr(err, "mbedTLS") != NULL || err[0] != '\0');
        printf("  PASS: tls stub (no mbedTLS)\n");
    } else {
        /* Built with mbedTLS; connect to invalid host should fail cleanly. */
        assert(cpe_agent_tls_post("https://127.0.0.1:1/nope", "{}", 2, NULL,
                                  NULL, NULL, err, sizeof(err)) == -1);
        printf("  PASS: tls built (connect fail expected)\n");
    }
}

static void test_spool_ensure_dir(void)
{
    char dir[] = "/tmp/cpe_spool_test_XXXXXX";
    char file[320];
    char *d;
    int fd;

    d = mkdtemp(dir);
    assert(d);
    snprintf(file, sizeof(file), "%s/sub/nested/perf.ndjson", d);
    assert(cpe_spool_ensure_parent_dir(file) == 0);
    fd = open(file, O_CREAT | O_WRONLY, 0644);
    assert(fd >= 0);
    close(fd);
    unlink(file);
    /* best-effort cleanup */
    rmdir(d); /* may fail if subdirs remain */
    printf("  PASS: spool ensure parent dir\n");
}

static void test_https_mode_requires_url(void)
{
    cpe_agent_config_t c;
    char err[64];

    cpe_agent_config_defaults(&c);
    snprintf(c.emit_mode, sizeof(c.emit_mode), "https");
    c.https_url[0] = '\0';
    assert(cpe_agent_config_validate(&c, err, sizeof(err)) == -1);
    printf("  PASS: https mode requires url\n");
}

static void test_spool_hard_cap(void)
{
    cpe_agent_config_t c;
    char err[64];

    cpe_agent_config_defaults(&c);
    c.spool_max_lines = CPE_SPOOL_MAX_LINES_HARD + 1;
    assert(cpe_agent_config_validate(&c, err, sizeof(err)) == -1);
    printf("  PASS: spool hard cap\n");
}

int main(void)
{
    printf("cpe_agent:\n");
    test_defaults_validate();
    test_yaml_load();
    test_ndjson_format();
    test_demo_ping_and_spool();
    test_host_alloc_stats();
    test_hup_flag();
    test_reject_keeps_generation();
    test_spool_mode_requires_path();
    test_emit_flush_spool_file();
    test_reload_config_override();
    test_sample_tick_demo();
    test_live_ping_or_skip();
    test_demo_arping();
    test_demo_wifi();
    test_tls_stub_or_build();
    test_spool_ensure_dir();
    test_https_mode_requires_url();
    test_spool_hard_cap();
    printf("all passed\n");
    return 0;
}
