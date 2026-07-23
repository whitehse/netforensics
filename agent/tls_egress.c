/**
 * @file tls_egress.c
 * @brief HTTP(S) NDJSON POST egress (plain TCP + optional mbedTLS).
 */

#define _POSIX_C_SOURCE 200809L

#include "cpe_agent_tls.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- base64 (Basic Auth) ---- */

static const char b64_tbl[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_encode(const unsigned char *in, size_t in_len, char *out,
                      size_t out_sz)
{
    size_t o = 0;
    size_t i = 0;

    if (!out || out_sz == 0) {
        return -1;
    }
    while (i < in_len) {
        size_t left = in_len - i;
        unsigned int v = (unsigned int)in[i] << 16;

        if (left > 1) {
            v |= (unsigned int)in[i + 1] << 8;
        }
        if (left > 2) {
            v |= (unsigned int)in[i + 2];
        }
        if (o + 4 >= out_sz) {
            return -1;
        }
        out[o++] = b64_tbl[(v >> 18) & 63];
        out[o++] = b64_tbl[(v >> 12) & 63];
        out[o++] = (left > 1) ? b64_tbl[(v >> 6) & 63] : '=';
        out[o++] = (left > 2) ? b64_tbl[v & 63] : '=';
        i += (left > 3) ? 3 : left;
    }
    out[o] = '\0';
    return 0;
}

static int build_basic_auth(const char *user, const char *pass, char *hdr,
                            size_t hdr_sz)
{
    char raw[320];
    char enc[440];
    int n;

    if (!user || !user[0] || !hdr || hdr_sz < 16) {
        return -1;
    }
    n = snprintf(raw, sizeof(raw), "%s:%s", user, pass ? pass : "");
    if (n < 0 || (size_t)n >= sizeof(raw)) {
        return -1;
    }
    if (b64_encode((const unsigned char *)raw, (size_t)n, enc, sizeof(enc)) !=
        0) {
        return -1;
    }
    n = snprintf(hdr, hdr_sz, "Authorization: Basic %s\r\n", enc);
    return (n < 0 || (size_t)n >= hdr_sz) ? -1 : 0;
}

/* ---- URL parse ---- */

static int parse_url(const char *url, int *is_https, char *host, size_t host_sz,
                     char *port, size_t port_sz, char *path, size_t path_sz)
{
    const char *p;
    const char *slash;
    const char *colon;
    size_t hlen;

    if (!url || !is_https || !host || !port || !path) {
        return -1;
    }
    if (strncmp(url, "https://", 8) == 0) {
        *is_https = 1;
        p = url + 8;
    } else if (strncmp(url, "http://", 7) == 0) {
        *is_https = 0;
        p = url + 7;
    } else {
        return -1;
    }
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
            size_t plen =
                slash ? (size_t)(slash - colon - 1) : strlen(colon + 1);
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
        snprintf(port, port_sz, "%s", *is_https ? "443" : "80");
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

static int http_status_ok(const char *resp, size_t n)
{
    /* "HTTP/1.x 2xx" */
    if (n < 12) {
        return 0;
    }
    if ((strncmp(resp, "HTTP/1.1 ", 9) == 0 ||
         strncmp(resp, "HTTP/1.0 ", 9) == 0) &&
        resp[9] == '2') {
        return 1;
    }
    return 0;
}

/* ---- plain HTTP ---- */

static int tcp_connect(const char *host, const char *port, char *err,
                       size_t err_len)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *rp;
    int fd = -1;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        if (err && err_len) {
            snprintf(err, err_len, "getaddrinfo: %s", gai_strerror(rc));
        }
        return -1;
    }
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0 && err && err_len) {
        snprintf(err, err_len, "connect failed: %s", strerror(errno));
    }
    return fd;
}

static int plain_http_post(const char *host, const char *port, const char *path,
                           const char *body, size_t body_len,
                           const char *auth_hdr, char *err, size_t err_len)
{
    int fd;
    char hdr[1536];
    int hdr_len;
    size_t written;
    char resp[512];
    ssize_t nr;
    struct pollfd pfd;

    fd = tcp_connect(host, port, err, err_len);
    if (fd < 0) {
        return -1;
    }

    hdr_len = snprintf(hdr, sizeof(hdr),
                       "POST %s HTTP/1.1\r\n"
                       "Host: %s\r\n"
                       "Content-Type: application/x-ndjson\r\n"
                       "Content-Length: %zu\r\n"
                       "Connection: close\r\n"
                       "%s"
                       "\r\n",
                       path, host, body_len, auth_hdr ? auth_hdr : "");
    if (hdr_len < 0 || (size_t)hdr_len >= sizeof(hdr)) {
        close(fd);
        if (err && err_len) {
            snprintf(err, err_len, "hdr overflow");
        }
        return -1;
    }

    written = 0;
    while (written < (size_t)hdr_len) {
        ssize_t w = send(fd, hdr + written, (size_t)hdr_len - written, 0);
        if (w <= 0) {
            close(fd);
            if (err && err_len) {
                snprintf(err, err_len, "send hdr failed");
            }
            return -1;
        }
        written += (size_t)w;
    }
    written = 0;
    while (written < body_len) {
        ssize_t w = send(fd, body + written, body_len - written, 0);
        if (w <= 0) {
            close(fd);
            if (err && err_len) {
                snprintf(err, err_len, "send body failed");
            }
            return -1;
        }
        written += (size_t)w;
    }

    pfd.fd = fd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, 15000) <= 0) {
        close(fd);
        if (err && err_len) {
            snprintf(err, err_len, "response timeout");
        }
        return -1;
    }
    nr = recv(fd, resp, sizeof(resp) - 1, 0);
    close(fd);
    if (nr <= 0) {
        if (err && err_len) {
            snprintf(err, err_len, "no response");
        }
        return -1;
    }
    resp[nr] = '\0';
    if (!http_status_ok(resp, (size_t)nr)) {
        if (err && err_len) {
            snprintf(err, err_len, "http non-2xx");
        }
        return -1;
    }
    return 0;
}

#if defined(CPE_AGENT_HAVE_MBEDTLS)

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

int cpe_agent_tls_available(void)
{
    return 1;
}

static int mbedtls_https_post(const char *host, const char *port,
                              const char *path, const char *body,
                              size_t body_len, const char *auth_hdr,
                              const cpe_agent_http_opts_t *opts, char *err,
                              size_t err_len)
{
    char req_hdr[1536];
    int rc = -1;
    int ret;
    int hdr_len;
    size_t written;
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;
    mbedtls_pk_context pkey;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "cpe_agent_http";
    unsigned char resp[512];
    const char *ca_file = opts && opts->ca_file ? opts->ca_file : NULL;
    const char *cert_file = opts && opts->cert_file ? opts->cert_file : NULL;
    const char *key_file = opts && opts->key_file ? opts->key_file : NULL;
    int insecure = opts ? opts->tls_insecure : 1;

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

    if (ca_file && ca_file[0] && !insecure) {
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    } else if (ca_file && ca_file[0]) {
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
        mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    } else {
        /* TLS optional auth: connect without verifying peer (lab). */
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
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
                       "%s"
                       "\r\n",
                       path, host, body_len, auth_hdr ? auth_hdr : "");
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
        if (http_status_ok((const char *)resp, (size_t)ret)) {
            rc = 0;
        } else if (err && err_len) {
            snprintf(err, err_len, "http non-2xx");
        }
    } else if (err && err_len) {
        snprintf(err, err_len, "read %d", ret);
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

static int mbedtls_https_post(const char *host, const char *port,
                              const char *path, const char *body,
                              size_t body_len, const char *auth_hdr,
                              const cpe_agent_http_opts_t *opts, char *err,
                              size_t err_len)
{
    (void)host;
    (void)port;
    (void)path;
    (void)body;
    (void)body_len;
    (void)auth_hdr;
    (void)opts;
    if (err && err_len) {
        snprintf(err, err_len,
                 "HTTPS requires mbedTLS (CPE_AGENT_WITH_MBEDTLS)");
    }
    return -1;
}

#endif /* CPE_AGENT_HAVE_MBEDTLS */

int cpe_agent_http_post(const char *url, const char *body, size_t body_len,
                        const cpe_agent_http_opts_t *opts, char *err,
                        size_t err_len)
{
    int is_https = 0;
    char host[256];
    char port[16];
    char path[512];
    char auth_hdr[512];
    const char *auth_ptr = NULL;

    if (err && err_len) {
        err[0] = '\0';
    }
    if (!url || !body) {
        if (err && err_len) {
            snprintf(err, err_len, "null args");
        }
        return -1;
    }
    if (parse_url(url, &is_https, host, sizeof(host), port, sizeof(port), path,
                  sizeof(path)) != 0) {
        if (err && err_len) {
            snprintf(err, err_len, "bad url (need http:// or https://)");
        }
        return -1;
    }

    auth_hdr[0] = '\0';
    if (opts && opts->username && opts->username[0]) {
        if (build_basic_auth(opts->username, opts->password, auth_hdr,
                             sizeof(auth_hdr)) != 0) {
            if (err && err_len) {
                snprintf(err, err_len, "basic auth encode failed");
            }
            return -1;
        }
        auth_ptr = auth_hdr;
    }

    if (is_https) {
        return mbedtls_https_post(host, port, path, body, body_len, auth_ptr,
                                  opts, err, err_len);
    }
    return plain_http_post(host, port, path, body, body_len, auth_ptr, err,
                           err_len);
}

int cpe_agent_tls_post(const char *url, const char *body, size_t body_len,
                       const char *ca_file, const char *cert_file,
                       const char *key_file, char *err, size_t err_len)
{
    cpe_agent_http_opts_t opts;

    memset(&opts, 0, sizeof(opts));
    opts.ca_file = ca_file;
    opts.cert_file = cert_file;
    opts.key_file = key_file;
    opts.tls_insecure = (ca_file && ca_file[0]) ? 0 : 1;
    return cpe_agent_http_post(url, body, body_len, &opts, err, err_len);
}
