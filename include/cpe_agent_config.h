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
#define CPE_CFG_MODE_MAX       16
#define CPE_CFG_SPOOL_DEFAULT  256

typedef struct {
    char     router_id[CPE_CFG_ROUTER_ID_MAX];
    /** stdout | spool (file) — production still NDJSON lines (ADR-002 / N-A05). */
    char     emit_mode[CPE_CFG_MODE_MAX];
    char     spool_path[CPE_CFG_PATH_MAX];
    size_t   spool_max_lines;       /* 0 → default 256 */
    char     demo_target[CPE_CFG_TARGET_MAX];
    uint32_t demo_interval_ms;      /* synthetic sample period; 0 → 5000 */
    uint32_t sample_interval_ms;    /* alias; used by libuv timer */
    int      demo_mode;             /* 1 = no CAP_NET_ADMIN; synthetic ping */
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
