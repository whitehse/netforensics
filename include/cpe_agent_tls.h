/**
 * @file cpe_agent_tls.h
 * @brief Optional mbedTLS mTLS egress for CPE agent (F5 / ADR-004).
 *
 * Soft dependency: builds without mbedTLS provide stubs that return -1.
 * Production v1 can stay on stdout/spool → local Vector; HTTPS is optional.
 */
#ifndef CPE_AGENT_TLS_H
#define CPE_AGENT_TLS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** 1 if linked with mbedTLS at build time. */
int cpe_agent_tls_available(void);

/**
 * POST @p body (NDJSON or JSON) to @p url with optional client certs.
 * @p ca_file, @p cert_file, @p key_file may be NULL (server-auth only).
 * @return 0 ok, -1 on failure (not built, I/O, TLS, or HTTP non-2xx).
 */
int cpe_agent_tls_post(const char *url, const char *body, size_t body_len,
                       const char *ca_file, const char *cert_file,
                       const char *key_file, char *err, size_t err_len);

#ifdef __cplusplus
}
#endif

#endif /* CPE_AGENT_TLS_H */
