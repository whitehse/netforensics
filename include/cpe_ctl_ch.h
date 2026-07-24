/**
 * @file cpe_ctl_ch.h
 * @brief ClickHouse HTTP query helper for cpe_ctl historical flow list.
 *
 * Ops hosts query ClickHouse (or lab loopback 8123) directly. Field CPEs
 * normally do not open CH; use live flow_list via the daemon UDS instead.
 */
#ifndef CPE_CTL_CH_H
#define CPE_CTL_CH_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *url;       /**< e.g. http://127.0.0.1:8123 (no path) */
    const char *user;      /**< default "default" */
    const char *password;  /**< optional */
    const char *table;     /**< default "edgehost.cpe_flows" */
    const char *router_id; /**< optional filter */
    unsigned    limit;     /**< default 50 */
} cpe_ctl_ch_opts_t;

/**
 * Query recent flow rows as JSONEachRow text into @p out.
 * @return 0 ok, -1 on error (message in @p err).
 */
int cpe_ctl_ch_query_flows(const cpe_ctl_ch_opts_t *opt, char *out, size_t out_sz,
                           char *err, size_t err_len);

/**
 * Pretty-print JSONEachRow flow lines to stdout. Returns number of rows.
 */
int cpe_ctl_ch_print_flows(const char *json_each_row);

#ifdef __cplusplus
}
#endif

#endif /* CPE_CTL_CH_H */
