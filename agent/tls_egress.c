/**
 * @file tls_egress.c
 * @brief Optional mbedTLS HTTPS POST with client certs (F5).
 */

#include "cpe_agent_tls.h"

#include <stdio.h>
#include <string.h>

#if defined(CPE_AGENT_HAVE_MBEDTLS)

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <stdlib.h>

int cpe_agent_tls_available(void)
{
    return 1;
}

static int parse_https_url(const char *url, char *host, size_t host_sz,
                           char *port, size_t port_sz, char *path,
                           size_t path_sz)
{
    const char *p;
    const char *slash;
    const char *colon;
    size_t hlen;

    if (!url || strncmp(url, "https://", 8) != 0) {
        return -1;
    }
    p = url + 8;
    slash = strchr(p, '/');
    colon = strchr(p, ':');
    if (colon && (!slash || colon < slash)) {
        hlen = (size_t)(colon - p);
        if (hlen == 0 || hlen >= host_sz) {
            return -1;
        }
        memcpy(host, p, hlen);
        host[hlen] = '\0';
        {
            size_t plen = slash ? (size_t)(slash - colon - 1)
                               : strlen(colon + 1);
            if (plen == 0 || plen >= port_sz) {
                return -1;
            }
            memcpy(port, colon + 1, plen);
            port[plen] = '\0';
        }
    } else {
        hlen = slash ? (size_t)(slash - p) : strlen(p);
        if (hlen == 0 || hlen >= host_sz) {
            return -1;
        }
        memcpy(host, p, hlen);
        host[hlen] = '\0';
        snprintf(port, port_sz, "443");
    }
    if (slash) {
        if (strlen(slash) >= path_sz) {
            return -1;
        }
        snprintf(path, path_sz, "%s", slash);
    } else {
        snprintf(path, path_sz, "/");
    }
    return 0;
}

int cpe_agent_tls_post(const char *url, const char *body, size_t body_len,
                       const char *ca_file, const char *cert_file,
                       const char *key_file, char *err, size_t err_len)
{
    char host[256];
    char port[16];
    char path[512];
    char req_hdr[1024];
    int rc = -1;
    int ret;
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;
    mbedtls_pk_context pkey;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "cpe_agent_tls";
    unsigned char resp[512];
    size_t written;
    int hdr_len;

    if (err && err_len) {
        err[0] = '\0';
    }
    if (!url || !body) {
        if (err && err_len) {
            snprintf(err, err_len, "null args");
        }
        return -1;
    }
    if (parse_https_url(url, host, sizeof(host), port, sizeof(port), path,
                        sizeof(path)) != 0) {
        if (err && err_len) {
            snprintf(err, err_len, "bad https url");
        }
        return -1;
    }

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&clicert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0) {
        if (err && err_len) {
            snprintf(err, err_len, "ctr_drbg_seed %d", ret);
        }
        goto cleanup;
    }

    if (ca_file && ca_file[0]) {
        if (mbedtls_x509_crt_parse_file(&cacert, ca_file) != 0) {
            if (err && err_len) {
                snprintf(err, err_len, "parse ca_file");
            }
            goto cleanup;
        }
    }

    if (cert_file && cert_file[0] && key_file && key_file[0]) {
        if (mbedtls_x509_crt_parse_file(&clicert, cert_file) != 0) {
            if (err && err_len) {
                snprintf(err, err_len, "parse cert_file");
            }
            goto cleanup;
        }
        if (mbedtls_pk_parse_keyfile(&pkey, key_file, NULL,
                                     mbedtls_ctr_drbg_random,
                                     &ctr_drbg) != 0) {
            if (err && err_len) {
                snprintf(err, err_len, "parse key_file");
            }
            goto cleanup;
        }
    }

    if ((ret = mbedtls_net_connect(&server_fd, host, port,
                                   MBEDTLS_NET_PROTO_TCP)) != 0) {
        if (err && err_len) {
            snprintf(err, err_len, "connect %d", ret);
        }
        goto cleanup;
    }

    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        if (err && err_len) {
            snprintf(err, err_len, "ssl_config_defaults %d", ret);
        }
        goto cleanup;
    }
    if (ca_file && ca_file[0]) {
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    } else {
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    }
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (cert_file && cert_file[0] && key_file && key_file[0]) {
        if (mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey) != 0) {
            if (err && err_len) {
                snprintf(err, err_len, "own_cert");
            }
            goto cleanup;
        }
    }
    if (mbedtls_ssl_setup(&ssl, &conf) != 0) {
        if (err && err_len) {
            snprintf(err, err_len, "ssl_setup");
        }
        goto cleanup;
    }
    if (mbedtls_ssl_set_hostname(&ssl, host) != 0) {
        if (err && err_len) {
            snprintf(err, err_len, "set_hostname");
        }
        goto cleanup;
    }
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv,
                        NULL);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            if (err && err_len) {
                snprintf(err, err_len, "handshake %d", ret);
            }
            goto cleanup;
        }
    }

    hdr_len = snprintf(req_hdr, sizeof(req_hdr),
                       "POST %s HTTP/1.1\r\n"
                       "Host: %s\r\n"
                       "Content-Type: application/x-ndjson\r\n"
                       "Content-Length: %zu\r\n"
                       "Connection: close\r\n"
                       "\r\n",
                       path, host, body_len);
    if (hdr_len < 0 || (size_t)hdr_len >= sizeof(req_hdr)) {
        if (err && err_len) {
            snprintf(err, err_len, "hdr overflow");
        }
        goto cleanup;
    }

    written = 0;
    while (written < (size_t)hdr_len) {
        ret = mbedtls_ssl_write(&ssl, (const unsigned char *)req_hdr + written,
                                (size_t)hdr_len - written);
        if (ret <= 0) {
            if (err && err_len) {
                snprintf(err, err_len, "write hdr %d", ret);
            }
            goto cleanup;
        }
        written += (size_t)ret;
    }
    written = 0;
    while (written < body_len) {
        ret = mbedtls_ssl_write(&ssl, (const unsigned char *)body + written,
                                body_len - written);
        if (ret <= 0) {
            if (err && err_len) {
                snprintf(err, err_len, "write body %d", ret);
            }
            goto cleanup;
        }
        written += (size_t)ret;
    }

    ret = mbedtls_ssl_read(&ssl, resp, sizeof(resp) - 1);
    if (ret > 0) {
        resp[ret] = '\0';
        if (strstr((const char *)resp, "HTTP/1.1 2") != NULL ||
            strstr((const char *)resp, "HTTP/1.0 2") != NULL) {
            rc = 0;
        } else {
            if (err && err_len) {
                snprintf(err, err_len, "http non-2xx");
            }
        }
    } else {
        if (err && err_len) {
            snprintf(err, err_len, "read %d", ret);
        }
    }

cleanup:
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_x509_crt_free(&clicert);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return rc;
}

#else /* !CPE_AGENT_HAVE_MBEDTLS */

int cpe_agent_tls_available(void)
{
    return 0;
}

int cpe_agent_tls_post(const char *url, const char *body, size_t body_len,
                       const char *ca_file, const char *cert_file,
                       const char *key_file, char *err, size_t err_len)
{
    (void)url;
    (void)body;
    (void)body_len;
    (void)ca_file;
    (void)cert_file;
    (void)key_file;
    if (err && err_len) {
        snprintf(err, err_len, "not built with mbedTLS (CPE_AGENT_WITH_MBEDTLS)");
    }
    return -1;
}

#endif /* CPE_AGENT_HAVE_MBEDTLS */
