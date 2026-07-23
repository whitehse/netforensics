/**
 * @file cpe_agent_tls.h
 * @brief HTTP(S) NDJSON egress for CPE agent → edgehost / Vector / gateway.
 *
 * Supports:
 *   - plain HTTP (always available; lab / internal networks)
 *   - HTTPS via mbedTLS when built with CPE_AGENT_HAVE_MBEDTLS (ADR-004)
 *   - optional Basic Auth (username / password)
 *   - optional mTLS client certs; TLS verification optional (default soft)
 *
 * Production path remains NDJSON → Vector or edgehost telemetry proxy
 * (ADR-002 / N-A05). No native ClickHouse client on the CPE.
 */
#ifndef CPE_AGENT_TLS_H
#define CPE_AGENT_TLS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** 1 if linked with mbedTLS at build time (HTTPS available). */
int cpe_agent_tls_available(void);

/**
 * Optional credentials and TLS material for one HTTP(S) POST.
 * All pointers may be NULL / empty.
 */
typedef struct {
    const char *username;   /**< Basic auth user (optional) */
    const char *password;   /**< Basic auth password (optional) */
    const char *ca_file;    /**< PEM CA bundle; empty → soft verify */
    const char *cert_file;  /**< optional client cert (mTLS) */
    const char *key_file;   /**< optional client key (mTLS) */
    int         tls_insecure; /**< 1 = do not require peer cert (default lab) */
} cpe_agent_http_opts_t;

/**
 * POST @p body to @p url (http:// or https://).
 * Content-Type: application/x-ndjson.
 * @return 0 on HTTP 2xx, -1 on failure (message in @p err if provided).
 */
int cpe_agent_http_post(const char *url, const char *body, size_t body_len,
                        const cpe_agent_http_opts_t *opts, char *err,
                        size_t err_len);

/**
 * Legacy mTLS-oriented wrapper (https only). Prefer @c cpe_agent_http_post.
 * @return 0 ok, -1 on failure.
 */
int cpe_agent_tls_post(const char *url, const char *body, size_t body_len,
                       const char *ca_file, const char *cert_file,
                       const char *key_file, char *err, size_t err_len);

#ifdef __cplusplus
}
#endif

#endif /* CPE_AGENT_TLS_H */
