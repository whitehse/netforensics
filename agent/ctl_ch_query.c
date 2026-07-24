/**
 * @file ctl_ch_query.c
 * @brief Minimal ClickHouse HTTP client for cpe_ctl flow history.
 */

#define _POSIX_C_SOURCE 200809L

#include "cpe_ctl_ch.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

static int parse_base_url(const char *url, char *host, size_t host_sz,
                          char *port, size_t port_sz)
{
    const char *p;
    const char *h;
    const char *colon;
    const char *slash;
    size_t hlen;

    if (!url || !host || !port) {
        return -1;
    }
    if (strncmp(url, "http://", 7) == 0) {
        p = url + 7;
    } else if (strncmp(url, "https://", 8) == 0) {
        /* TLS not required for lab CH; reject to keep deps light. */
        return -2;
    } else {
        p = url;
    }
    h = p;
    slash = strchr(p, '/');
    colon = strchr(p, ':');
    if (colon && (!slash || colon < slash)) {
        hlen = (size_t)(colon - h);
        if (hlen == 0 || hlen >= host_sz) {
            return -1;
        }
        memcpy(host, h, hlen);
        host[hlen] = '\0';
        {
            const char *pe = slash ? slash : colon + strlen(colon);
            size_t plen = (size_t)(pe - (colon + 1));
            if (plen == 0 || plen >= port_sz) {
                return -1;
            }
            memcpy(port, colon + 1, plen);
            port[plen] = '\0';
        }
    } else {
        hlen = slash ? (size_t)(slash - h) : strlen(h);
        if (hlen == 0 || hlen >= host_sz) {
            return -1;
        }
        memcpy(host, h, hlen);
        host[hlen] = '\0';
        snprintf(port, port_sz, "8123");
    }
    return 0;
}

static int sql_ident_ok(const char *s)
{
    size_t i;
    if (!s || !s[0]) {
        return 0;
    }
    for (i = 0; s[i]; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-')) {
            return 0;
        }
    }
    return 1;
}

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
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        hints.ai_flags = 0;
        rc = getaddrinfo(host, port, &hints, &res);
    }
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
        snprintf(err, err_len, "connect %s:%s failed", host, port);
    }
    return fd;
}

static int http_post_sql(const char *host, const char *port, const char *user,
                         const char *password, const char *sql, char *out,
                         size_t out_sz, char *err, size_t err_len)
{
    int fd;
    char *req = NULL;
    size_t req_cap;
    size_t req_len;
    size_t written;
    char *resp = NULL;
    size_t resp_cap = out_sz + 8192;
    size_t resp_len = 0;
    char *body;
    int status = 0;
    int n;
    struct pollfd pfd;

    if (!host || !sql || !out || out_sz < 8) {
        return -1;
    }
    fd = tcp_connect(host, port, err, err_len);
    if (fd < 0) {
        return -1;
    }

    req_cap = strlen(sql) + 768;
    req = (char *)malloc(req_cap);
    resp = (char *)malloc(resp_cap);
    if (!req || !resp) {
        free(req);
        free(resp);
        close(fd);
        if (err && err_len) {
            snprintf(err, err_len, "oom");
        }
        return -1;
    }

    n = snprintf(req, req_cap,
                 "POST /?default_format=JSONEachRow HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "Content-Type: text/plain; charset=utf-8\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n",
                 host, strlen(sql));
    if (n < 0 || (size_t)n >= req_cap) {
        free(req);
        free(resp);
        close(fd);
        return -1;
    }
    req_len = (size_t)n;
    if (user && user[0]) {
        n = snprintf(req + req_len, req_cap - req_len, "X-ClickHouse-User: %s\r\n",
                     user);
        if (n < 0 || (size_t)n >= req_cap - req_len) {
            free(req);
            free(resp);
            close(fd);
            return -1;
        }
        req_len += (size_t)n;
    }
    if (password && password[0]) {
        n = snprintf(req + req_len, req_cap - req_len, "X-ClickHouse-Key: %s\r\n",
                     password);
        if (n < 0 || (size_t)n >= req_cap - req_len) {
            free(req);
            free(resp);
            close(fd);
            return -1;
        }
        req_len += (size_t)n;
    }
    n = snprintf(req + req_len, req_cap - req_len, "\r\n%s", sql);
    if (n < 0 || (size_t)n >= req_cap - req_len) {
        free(req);
        free(resp);
        close(fd);
        return -1;
    }
    req_len += (size_t)n;

    written = 0;
    while (written < req_len) {
        ssize_t w = send(fd, req + written, req_len - written, 0);
        if (w <= 0) {
            free(req);
            free(resp);
            close(fd);
            if (err && err_len) {
                snprintf(err, err_len, "send failed");
            }
            return -1;
        }
        written += (size_t)w;
    }
    free(req);
    req = NULL;

    for (;;) {
        pfd.fd = fd;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, 15000) <= 0) {
            break;
        }
        if (resp_len + 1 >= resp_cap) {
            break;
        }
        {
            ssize_t nr =
                recv(fd, resp + resp_len, resp_cap - resp_len - 1, 0);
            if (nr <= 0) {
                break;
            }
            resp_len += (size_t)nr;
        }
    }
    close(fd);
    resp[resp_len] = '\0';

    if (strncmp(resp, "HTTP/", 5) == 0) {
        char *sp = strchr(resp, ' ');
        if (sp) {
            status = atoi(sp + 1);
        }
    }
    body = strstr(resp, "\r\n\r\n");
    if (body) {
        body += 4;
    } else {
        body = strstr(resp, "\n\n");
        if (body) {
            body += 2;
        } else {
            body = resp;
        }
    }
    if (status != 200) {
        if (err && err_len) {
            snprintf(err, err_len, "HTTP %d: %.160s", status, body);
        }
        free(resp);
        return -1;
    }
    /* Dechunk if Transfer-Encoding: chunked (common from ClickHouse HTTP). */
    {
        int chunked = 0;
        const char *hdr_end = body;
        const char *h = resp;
        while (h + 17 < hdr_end) {
            if (strncasecmp(h, "Transfer-Encoding:", 17) == 0) {
                const char *v = h + 17;
                while (*v == ' ' || *v == '\t') {
                    v++;
                }
                if (strncasecmp(v, "chunked", 7) == 0) {
                    chunked = 1;
                }
                break;
            }
            {
                const char *nl = strstr(h, "\r\n");
                if (!nl || nl >= hdr_end) {
                    break;
                }
                h = nl + 2;
            }
        }
        /* Heuristic: body begins with hex chunk size then JSON. */
        if (!chunked && body[0]) {
            char *e = NULL;
            unsigned long csz = strtoul(body, &e, 16);
            if (e != body && csz > 0 &&
                ((*e == '\r' && e[1] == '\n' && e[2] == '{') ||
                 (*e == '\n' && e[1] == '{'))) {
                chunked = 1;
            }
        }
        if (chunked) {
            size_t o = 0;
            const char *p = body;
            while (*p && o + 1 < out_sz) {
                char *end = NULL;
                unsigned long chunk = strtoul(p, &end, 16);
                if (end == p) {
                    break;
                }
                if (*end == '\r') {
                    end++;
                }
                if (*end == '\n') {
                    end++;
                }
                p = end;
                if (chunk == 0) {
                    break;
                }
                if (o + chunk >= out_sz) {
                    chunk = (unsigned long)(out_sz - o - 1);
                }
                memcpy(out + o, p, (size_t)chunk);
                o += (size_t)chunk;
                p += chunk;
                if (*p == '\r') {
                    p++;
                }
                if (*p == '\n') {
                    p++;
                }
            }
            out[o] = '\0';
        } else {
            size_t blen = strlen(body);
            if (blen >= out_sz) {
                blen = out_sz - 1;
            }
            memcpy(out, body, blen);
            out[blen] = '\0';
        }
    }
    free(resp);
    return 0;
}

int cpe_ctl_ch_query_flows(const cpe_ctl_ch_opts_t *opt, char *out, size_t out_sz,
                           char *err, size_t err_len)
{
    char host[256];
    char port[16];
    char sql[768];
    char rid[96];
    const char *url;
    const char *user;
    const char *table;
    unsigned limit;
    int prc;
    int n;
    size_t i;
    size_t j;

    if (err && err_len) {
        err[0] = '\0';
    }
    if (!opt || !out || out_sz < 16) {
        if (err && err_len) {
            snprintf(err, err_len, "bad args");
        }
        return -1;
    }
    url = (opt->url && opt->url[0]) ? opt->url : "http://127.0.0.1:8123";
    user = (opt->user && opt->user[0]) ? opt->user : "default";
    table = (opt->table && opt->table[0]) ? opt->table : "edgehost.cpe_flows";
    limit = opt->limit ? opt->limit : 50;
    if (limit > 500) {
        limit = 500;
    }
    if (!sql_ident_ok(table)) {
        if (err && err_len) {
            snprintf(err, err_len, "invalid table name");
        }
        return -1;
    }

    prc = parse_base_url(url, host, sizeof(host), port, sizeof(port));
    if (prc == -2) {
        if (err && err_len) {
            snprintf(err, err_len, "https CH URL not supported in cpe_ctl; use http://");
        }
        return -1;
    }
    if (prc != 0) {
        if (err && err_len) {
            snprintf(err, err_len, "bad --ch-url");
        }
        return -1;
    }

    rid[0] = '\0';
    if (opt->router_id && opt->router_id[0]) {
        j = 0;
        for (i = 0; opt->router_id[i] && j + 1 < sizeof(rid); i++) {
            char c = opt->router_id[i];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
                rid[j++] = c;
            }
        }
        rid[j] = '\0';
    }

    if (rid[0]) {
        n = snprintf(
            sql, sizeof(sql),
            "SELECT router_id, ts, event, flow_id, proto, lan_ip, lan_port, "
            "wan_ip, wan_port, remote_ip, remote_port, bytes_up, bytes_down, "
            "rate_up_bps, rate_down_bps, duration_ms, state "
            "FROM %s WHERE router_id = '%s' ORDER BY ts DESC LIMIT %u",
            table, rid, limit);
    } else {
        n = snprintf(
            sql, sizeof(sql),
            "SELECT router_id, ts, event, flow_id, proto, lan_ip, lan_port, "
            "wan_ip, wan_port, remote_ip, remote_port, bytes_up, bytes_down, "
            "rate_up_bps, rate_down_bps, duration_ms, state "
            "FROM %s ORDER BY ts DESC LIMIT %u",
            table, limit);
    }
    if (n < 0 || (size_t)n >= sizeof(sql)) {
        if (err && err_len) {
            snprintf(err, err_len, "sql overflow");
        }
        return -1;
    }

    return http_post_sql(host, port, user, opt->password, sql, out, out_sz, err,
                         err_len);
}

static int json_get_str(const char *line, const char *key, char *out, size_t n)
{
    char pat[64];
    const char *p;
    size_t i = 0;
    int sn = snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    if (sn < 0 || (size_t)sn >= sizeof(pat) || !line || !out || n == 0) {
        return -1;
    }
    p = strstr(line, pat);
    if (!p) {
        out[0] = '\0';
        return -1;
    }
    p += strlen(pat);
    while (*p && *p != '"' && i + 1 < n) {
        if (*p == '\\' && p[1]) {
            p++;
        }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 0;
}

static int json_get_num(const char *line, const char *key, char *out, size_t n)
{
    char pat[64];
    const char *p;
    size_t i = 0;
    int sn = snprintf(pat, sizeof(pat), "\"%s\":", key);
    if (sn < 0 || (size_t)sn >= sizeof(pat) || !line || !out || n == 0) {
        return -1;
    }
    p = strstr(line, pat);
    if (!p) {
        out[0] = '\0';
        return -1;
    }
    p += strlen(pat);
    while (*p == ' ') {
        p++;
    }
    while (*p && *p != ',' && *p != '}' && i + 1 < n) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 0;
}

int cpe_ctl_ch_print_flows(const char *json_each_row)
{
    const char *p;
    int rows = 0;

    if (!json_each_row) {
        return 0;
    }
    printf("%-12s %-10s %-5s %-22s %-22s %12s %12s %-20s\n", "router_id",
           "event", "proto", "lan", "remote", "bytes_up", "bytes_down", "ts");
    printf("%-12s %-10s %-5s %-22s %-22s %12s %12s %-20s\n", "------------",
           "----------", "-----", "----------------------",
           "----------------------", "------------", "------------",
           "--------------------");

    p = json_each_row;
    while (*p) {
        const char *eol = strchr(p, '\n');
        size_t llen = eol ? (size_t)(eol - p) : strlen(p);
        char line[2048];
        char router[64], event[24], proto[12], lan_ip[64], remote_ip[64];
        char lan_port[16], remote_port[16], bup[24], bdn[24], ts[40];
        char lan[80], remote[80];

        if (llen >= sizeof(line)) {
            llen = sizeof(line) - 1;
        }
        memcpy(line, p, llen);
        line[llen] = '\0';
        while (llen > 0 &&
               (line[llen - 1] == '\r' || line[llen - 1] == ' ')) {
            line[--llen] = '\0';
        }
        if (line[0] == '{') {
            router[0] = event[0] = proto[0] = lan_ip[0] = remote_ip[0] = '\0';
            lan_port[0] = remote_port[0] = bup[0] = bdn[0] = ts[0] = '\0';
            (void)json_get_str(line, "router_id", router, sizeof(router));
            (void)json_get_str(line, "event", event, sizeof(event));
            (void)json_get_num(line, "proto", proto, sizeof(proto));
            (void)json_get_str(line, "lan_ip", lan_ip, sizeof(lan_ip));
            (void)json_get_num(line, "lan_port", lan_port, sizeof(lan_port));
            (void)json_get_str(line, "remote_ip", remote_ip, sizeof(remote_ip));
            (void)json_get_num(line, "remote_port", remote_port,
                               sizeof(remote_port));
            (void)json_get_num(line, "bytes_up", bup, sizeof(bup));
            (void)json_get_num(line, "bytes_down", bdn, sizeof(bdn));
            (void)json_get_str(line, "ts", ts, sizeof(ts));
            snprintf(lan, sizeof(lan), "%s:%s", lan_ip, lan_port);
            snprintf(remote, sizeof(remote), "%s:%s", remote_ip, remote_port);
            printf("%-12s %-10s %-5s %-22s %-22s %12s %12s %-20s\n", router,
                   event, proto, lan, remote, bup, bdn, ts);
            rows++;
        }
        if (!eol) {
            break;
        }
        p = eol + 1;
    }
    if (rows == 0) {
        printf("(no rows)\n");
    }
    return rows;
}
