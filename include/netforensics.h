#ifndef NETFORENSICS_H
#define NETFORENSICS_H

#include <stddef.h>
#include <stdint.h>

#include "ipfix.h"
#include "nfct.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Unified flow observation for correlation (CPE or core). */
typedef struct {
    uint64_t ts_ms;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint32_t wan_src_ip;   /* CPE NAT only */
    uint16_t wan_src_port;
    char     router_id[64];
    int      from_cpe;     /* 1 = NAT record, 0 = core IPFIX */
} nf_flow_obs_t;

/** Fill observation from IPFIX data record + optional router_id. */
int nf_obs_from_ipfix(const ipfix_data_record_t *rec, const char *router_id,
                      uint64_t fallback_ts_ms, nf_flow_obs_t *out);

/** Fill observation from nfct forensics tuple. */
int nf_obs_from_nfct(const nfct_event_t *ev, const char *router_id,
                     uint64_t ts_ms, nf_flow_obs_t *out);

/**
 * Match CPE NAT obs to core IPFIX obs on WAN 5-tuple window.
 * Returns 1 if match, 0 if not, negative on error.
 */
int nf_flows_correlate(const nf_flow_obs_t *cpe, const nf_flow_obs_t *core,
                       uint64_t max_skew_ms);

/** Format observation one-line for NDJSON emitters / logs. */
int nf_obs_format(const nf_flow_obs_t *obs, char *buf, size_t buflen);

/**
 * Feed one IPFIX message and pull flow observations into out[] (max n).
 * Returns number of observations written, or negative on error.
 */
int nf_ipfix_collect_flows(ipfix_ctx_t *ctx, const uint8_t *msg, size_t len,
                           const char *router_id, nf_flow_obs_t *out, size_t max_out);

#ifdef __cplusplus
}
#endif

#endif /* NETFORENSICS_H */
