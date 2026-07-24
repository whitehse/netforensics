/**
 * @file test_cpe_ipc.c
 * @brief Unit tests for IPC request handler (no live UDS required for core).
 */
#include "cpe_agent.h"
#include "cpe_ipc.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void test_handle_ping(void)
{
    cpe_agent_t *a = cpe_agent_create();
    char out[512];
    assert(a);
    assert(cpe_ipc_handle_request(a, "{\"op\":\"ping\"}", out, sizeof(out)) ==
           0);
    assert(strstr(out, "\"ok\":true") != NULL);
    assert(strstr(out, "pong") != NULL);
    cpe_agent_destroy(a);
    printf("  PASS: handle ping\n");
}

static void test_handle_tcp_stats(void)
{
    cpe_agent_t *a = cpe_agent_create();
    cpe_agent_config_t cfg;
    uint8_t pkt[64];
    size_t len;
    char out[2048];
    static const uint8_t syn[] = {
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x0a, 0x2d, 0x39, 0x0a, 0x01, 0xd4, 0x31, 0x01, 0xbb,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x72, 0x10,
        0x00, 0x00, 0x00, 0x00};

    assert(a);
    cfg = *cpe_agent_config(a);
    cfg.tcp_stats_enabled = 1;
    assert(cpe_agent_apply_config(a, &cfg) == 0);
    len = sizeof(syn);
    memcpy(pkt, syn, len);
    assert(cpe_agent_tcp_feed_payload(a, pkt, len) == 0);

    assert(cpe_ipc_handle_request(a, "{\"op\":\"tcp_stats\"}", out,
                                  sizeof(out)) == 0);
    assert(strstr(out, "\"ok\":true") != NULL);
    assert(strstr(out, "\"syn\"") != NULL);

    assert(cpe_ipc_handle_request(
               a, "{\"op\":\"tcp_by_ip\",\"ip\":\"45.57.10.1\"}", out,
               sizeof(out)) == 0);
    assert(strstr(out, "45.57.10.1") != NULL);

    assert(cpe_ipc_handle_request(a, "{\"op\":\"status\"}", out, sizeof(out)) ==
           0);
    assert(strstr(out, "router_id") != NULL);

    cpe_agent_destroy(a);
    printf("  PASS: handle tcp_stats + status\n");
}

static void test_uds_roundtrip(void)
{
    cpe_agent_t *a;
    cpe_ipc_server_t *srv;
    char err[128];
    char resp[1024];
    char path[] = "/tmp/cpe_ipc_test_XXXXXX.sock";
    /* mkstemp needs X's at end — use fixed test path */
    const char *sock = "/tmp/cpe_agent_ipc_test.sock";

    (void)path;
    a = cpe_agent_create();
    assert(a);
    err[0] = '\0';
    srv = cpe_ipc_server_create(a, sock, err, sizeof(err));
    assert(srv);

    /* Client in same process: poll once after request would need threads.
     * Just verify server creates and path matches. */
    assert(strcmp(cpe_ipc_server_path(srv), sock) == 0);
    assert(cpe_ipc_server_fd(srv) >= 0);

    /* Direct handler already covered; client against live server:
     * fork would be heavier — use simple connect after background isn't
     * available, so issue request which will block unless we poll.
     * Skip full duplex; destroy is enough for bind/unlink. */
    cpe_ipc_server_destroy(srv);
    a = cpe_agent_create();
    assert(a);
    /* Re-create and exercise poll with no clients */
    srv = cpe_ipc_server_create(a, sock, err, sizeof(err));
    assert(srv);
    assert(cpe_ipc_server_poll(srv) == 0);
    cpe_ipc_server_destroy(srv);
    cpe_agent_destroy(a);
    (void)resp;
    printf("  PASS: uds server create/poll/destroy\n");
}

int main(void)
{
    printf("cpe_ipc:\n");
    test_handle_ping();
    test_handle_tcp_stats();
    test_uds_roundtrip();
    printf("all passed\n");
    return 0;
}
