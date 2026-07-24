/**
 * @file cpe_agent_config.h
 * @brief CPE agent runtime configuration (YAML-backed; P2.1–P2.2).
 */
#ifndef CPE_AGENT_CONFIG_H
#define CPE_AGENT_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CPE_CFG_ROUTER_ID_MAX  64
#define CPE_CFG_PATH_MAX       256
#define CPE_CFG_TARGET_MAX     64
#define CPE_CFG_IFACE_MAX      32
#define CPE_CFG_MODE_MAX       16
#define CPE_CFG_URL_MAX        256
#define CPE_CFG_USER_MAX       64
#define CPE_CFG_PASS_MAX       128
#define CPE_CFG_SPOOL_DEFAULT  256

typedef struct {
    char     router_id[CPE_CFG_ROUTER_ID_MAX];
    /**
     * stdout | spool | http | https — production still NDJSON (ADR-002 / N-A05).
     * http = plain TCP POST; https = mbedTLS when built (F5 / ADR-004).
     * Both accept optional Basic Auth (egress.username / password).
     */
    char     emit_mode[CPE_CFG_MODE_MAX];
    char     spool_path[CPE_CFG_PATH_MAX];
    size_t   spool_max_lines;       /* 0 → default 256; hard cap 1024 */
    char     demo_target[CPE_CFG_TARGET_MAX]; /* probe target (demo + live) */
    char     arping_if[CPE_CFG_IFACE_MAX];    /* L2 iface for arping; empty=auto */
    char     wifi_if[CPE_CFG_IFACE_MAX];      /* Wi‑Fi iface for nl80211; empty=auto */
    uint32_t demo_interval_ms;      /* sample period; 0 → 5000 */
    uint32_t sample_interval_ms;    /* alias; used by libuv timer */
    uint32_t probe_timeout_ms;      /* live ICMP/ARP wait; 0 → 1000 */
    int      demo_mode;             /* 1 = synthetic; 0 = live ICMP (F4) */
    /* HTTP(S) egress → edgehost /api/v1/telemetry/events or Vector */
    char     https_url[CPE_CFG_URL_MAX]; /* egress.url (http:// or https://) */
    char     egress_user[CPE_CFG_USER_MAX];
    char     egress_password[CPE_CFG_PASS_MAX];
    char     tls_ca_file[CPE_CFG_PATH_MAX];
    char     tls_cert_file[CPE_CFG_PATH_MAX];
    char     tls_key_file[CPE_CFG_PATH_MAX];
    int      egress_tls_insecure; /* 1 = skip peer verify (default without CA) */
    /**
     * TCP control-plane stats from NFLOG (SYN/FIN/RST).
     * Field path on Calix u6.3 / OpenWrt: iptables NFLOG group (default 5).
     */
    int      tcp_stats_enabled;     /* 0 = off (default); 1 = poll NFLOG */
    uint16_t tcp_nflog_group;       /* 0 → 5 */
    uint32_t tcp_nflog_size;        /* copy range bytes; 0 → 60 */
    uint32_t tcp_emit_interval_ms;  /* 0 → 10000; summary+top emit period */
    uint32_t tcp_emit_top_n;        /* 0 → 20; top remotes/prefixes per emit */
    uint8_t  tcp_prefix_len;        /* 0 → 24; IPv4 aggregation mask */
    /**
     * Per-flow bandwidth accounting from conntrack (nf_conntrack_acct=1).
     * Poll + optional dump every poll_interval_ms; sample top-N periodically.
     */
    int      flow_acct_enabled;       /* 0 = off (default) */
    int      flow_join_update;        /* 1 = also join UPDATE multicast */
    int      flow_emit_destroy;       /* 1 = emit cpe_flow on DESTROY */
    int      flow_emit_new;           /* 1 = emit cpe_flow on NEW (noisy) */
    uint32_t flow_poll_interval_ms;   /* 0 → 200 */
    uint32_t flow_dump_interval_ms;   /* 0 → 200; 0 disables active dump */
    uint32_t flow_sample_emit_ms;     /* 0 → 2000; top-N live samples */
    uint32_t flow_sample_top_n;       /* 0 → 32 */
    uint32_t flow_max_flows;          /* 0 → 1024; table cap */
    /**
     * Control-plane UDS for cpe_ctl (human/AI Lua front-end).
     * Empty → /var/run/netforensics/cpe_agent.sock. Set "off" to disable.
     */
    char     ipc_socket[CPE_CFG_PATH_MAX];
    /**
     * Optional edgehost proxy base URLs (CPE never talks to CH/PG directly).
     * egress.url remains the telemetry ingest path.
     * openai_proxy_url: e.g. http://edgehost:18080/api/v1/openai/...
     * postgres_proxy_url: reserved for future edgehost PG proxy.
     */
    char     openai_proxy_url[CPE_CFG_URL_MAX];
    char     postgres_proxy_url[CPE_CFG_URL_MAX];
    /**
     * Set by cpe_agent_apply_config on success (not loaded from YAML).
     */
    uint64_t generation;
} cpe_agent_config_t;

void cpe_agent_config_defaults(cpe_agent_config_t *c);

/**
 * Validate structural constraints.
 * @return 0 ok, -1 invalid (message in @p err if provided).
 */
int cpe_agent_config_validate(const cpe_agent_config_t *c, char *err,
                              size_t err_len);

/**
 * Load YAML from memory into @p out (starts from defaults).
 * @return 0 ok, -1 on parse failure.
 */
int cpe_agent_config_load_yaml_buf(const char *yaml, size_t yaml_len,
                                   cpe_agent_config_t *out, char *err,
                                   size_t err_len);

int cpe_agent_config_load_yaml_path(const char *path, cpe_agent_config_t *out,
                                    char *err, size_t err_len);

#ifdef __cplusplus
}
#endif

#endif /* CPE_AGENT_CONFIG_H */
