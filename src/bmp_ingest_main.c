/**
 * bmp_ingest_demo — document BMP ingest entrypoint (libbmp plumbing).
 *
 * Production: TCP accept/recv in a sidecar or gateway, feed to
 * nf_bmp_collect_stream, emit NDJSON to Vector → ClickHouse bgp_updates.
 */

#include "bmp_ingest.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static void wr32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

int main(void)
{
    bmp_ctx_t *ctx = bmp_create();
    uint8_t msg[6 + 42];
    nf_bmp_obs_t obs[4];
    char line[512];
    int n;

    printf("netforensics bmp_ingest_demo 0.1.0 (libbmp)\n");
    if (!ctx) {
        return 1;
    }

    memset(msg, 0, sizeof(msg));
    msg[0] = 3;
    wr32_be(msg + 1, (uint32_t)sizeof(msg));
    msg[5] = BMP_MSG_PEER_UP;
    wr32_be(msg + 6 + 26, 64512);
    wr32_be(msg + 6 + 30, 0x0A000001u);
    msg[6 + 10 + 12] = 203;
    msg[6 + 10 + 13] = 0;
    msg[6 + 10 + 14] = 113;
    msg[6 + 10 + 15] = 50;

    n = nf_bmp_collect(ctx, msg, sizeof(msg), "rr-core-1", obs, 4);
    printf("collected %d observation(s)\n", n);
    if (n > 0 && nf_bmp_obs_format(&obs[0], line, sizeof(line)) == 0) {
        printf("%s\n", line);
    }

    bmp_destroy(ctx);
    return 0;
}
