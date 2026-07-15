#include "bmp_ingest.h"

#include <assert.h>
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
    uint8_t msg[6 + 42 + 4];
    nf_bmp_obs_t obs[4];
    char line[512];
    int n;

    assert(ctx);
    memset(msg, 0, sizeof(msg));
    msg[0] = 3;
    wr32_be(msg + 1, (uint32_t)sizeof(msg));
    msg[5] = BMP_MSG_PEER_UP;
    wr32_be(msg + 6 + 26, 65001);
    wr32_be(msg + 6 + 30, 0x01020304u);
    msg[6 + 42] = 1;
    msg[6 + 42 + 1] = 2;

    n = nf_bmp_collect(ctx, msg, sizeof(msg), "rr-1", obs, 4);
    assert(n == 1);
    assert(strcmp(obs[0].event, "peer_up") == 0);
    assert(obs[0].peer_as == 65001);
    assert(obs[0].has_peer);
    assert(nf_bmp_obs_format(&obs[0], line, sizeof(line)) == 0);
    assert(strstr(line, "\"type\":\"bmp\"") != NULL);
    assert(strstr(line, "peer_up") != NULL);
    assert(strstr(line, "rr-1") != NULL);

    /* Stream path: split message */
    {
        uint8_t ini[6];
        ini[0] = 3;
        wr32_be(ini + 1, 6);
        ini[5] = BMP_MSG_INITIATION;
        n = nf_bmp_collect_stream(ctx, ini, 3, "rr-1", obs, 4);
        assert(n == 0);
        n = nf_bmp_collect_stream(ctx, ini + 3, 3, "rr-1", obs, 4);
        assert(n == 1);
        assert(strcmp(obs[0].event, "initiation") == 0);
    }

    bmp_destroy(ctx);
    printf("bmp_ingest tests PASSED\n");
    return 0;
}
