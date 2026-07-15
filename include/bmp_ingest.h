#ifndef NETFORENSICS_BMP_INGEST_H
#define NETFORENSICS_BMP_INGEST_H

#include <stddef.h>
#include <stdint.h>

#include "bmp.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Structured BMP observation for NDJSON / ClickHouse bgp_updates staging.
 * Nested NLRI decode is out of scope (libbmp ADR-008); route events carry
 * opaque payload length only.
 */
typedef struct {
    char     router_id[64];
    char     event[32];       /* initiation|termination|peer_up|peer_down|route|stats|… */
    uint64_t ts_ms;
    uint32_t peer_as;
    uint32_t peer_bgp_id;
    uint8_t  peer_addr[16];
    int      peer_is_ipv6;
    int      has_peer;
    size_t   payload_len;
    int      payload_truncated;
    char     peer_addr_str[48]; /* dotted or hex form for logs */
} nf_bmp_obs_t;

/** Map a libbmp event into an observation. Returns 0 on success, -1 skip/error. */
int nf_obs_from_bmp(const bmp_event_t *ev, const char *router_id, nf_bmp_obs_t *out);

/** NDJSON line for Vector / journal. */
int nf_bmp_obs_format(const nf_bmp_obs_t *obs, char *buf, size_t buflen);

/**
 * Feed one complete BMP message and collect observations into out[].
 * Returns number written, or negative on hard error.
 */
int nf_bmp_collect(bmp_ctx_t *ctx, const uint8_t *msg, size_t len,
                   const char *router_id, nf_bmp_obs_t *out, size_t max_out);

/**
 * Feed stream chunk (TCP); drain any complete events into out[].
 * Returns number of observations appended (0 if none yet).
 */
int nf_bmp_collect_stream(bmp_ctx_t *ctx, const uint8_t *data, size_t len,
                          const char *router_id, nf_bmp_obs_t *out, size_t max_out);

#ifdef __cplusplus
}
#endif

#endif /* NETFORENSICS_BMP_INGEST_H */
