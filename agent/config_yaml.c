/**
 * @file config_yaml.c
 * @brief Load cpe_agent_config_t from YAML via sibling libyaml (P2.2).
 */

#include "cpe_agent_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "yaml.h"

static int parse_bool(const char *s, int *out)
{
    if (!s || !out) {
        return -1;
    }
    if (strcmp(s, "1") == 0 || strcmp(s, "true") == 0 ||
        strcmp(s, "True") == 0 || strcmp(s, "yes") == 0 ||
        strcmp(s, "on") == 0) {
        *out = 1;
        return 0;
    }
    if (strcmp(s, "0") == 0 || strcmp(s, "false") == 0 ||
        strcmp(s, "False") == 0 || strcmp(s, "no") == 0 ||
        strcmp(s, "off") == 0) {
        *out = 0;
        return 0;
    }
    return -1;
}

static int parse_u32(const char *s, uint32_t *out)
{
    unsigned long v;
    char *end = NULL;

    if (!s || !out) {
        return -1;
    }
    v = strtoul(s, &end, 10);
    if (end == s || *end != '\0' || v > 0xffffffffu) {
        return -1;
    }
    *out = (uint32_t)v;
    return 0;
}

static int parse_size(const char *s, size_t *out)
{
    unsigned long long v;
    char *end = NULL;

    if (!s || !out) {
        return -1;
    }
    v = strtoull(s, &end, 10);
    if (end == s || *end != '\0') {
        return -1;
    }
    *out = (size_t)v;
    return 0;
}

static int copy_str(char *dst, size_t dst_sz, const char *src)
{
    size_t n;

    if (!dst || dst_sz == 0 || !src) {
        return -1;
    }
    n = strlen(src);
    if (n + 1 > dst_sz) {
        return -1;
    }
    memcpy(dst, src, n + 1);
    return 0;
}

static const char *lookup(yaml_ctx_t *ctx, const char *path)
{
    size_t len = 0;
    const char *v = yaml_lookup_scalar(ctx, path, &len);

    if (!v || len == 0) {
        return NULL;
    }
    return v;
}

static int apply_scalar(cpe_agent_config_t *c, const char *key, const char *val,
                        char *err, size_t err_len)
{
    int iv;
    uint32_t u32;
    size_t sz;

    if (!key || !val) {
        return 0;
    }

#define FAIL(msg)                                                              \
    do {                                                                       \
        if (err && err_len) {                                                  \
            snprintf(err, err_len, "%s: %s", key, msg);                        \
        }                                                                      \
        return -1;                                                             \
    } while (0)

    if (strcmp(key, "router_id") == 0) {
        if (copy_str(c->router_id, sizeof(c->router_id), val) != 0) {
            FAIL("too long");
        }
        return 0;
    }
    if (strcmp(key, "emit.mode") == 0 || strcmp(key, "emit_mode") == 0) {
        if (copy_str(c->emit_mode, sizeof(c->emit_mode), val) != 0) {
            FAIL("too long");
        }
        return 0;
    }
    if (strcmp(key, "emit.path") == 0 || strcmp(key, "spool.path") == 0 ||
        strcmp(key, "spool_path") == 0) {
        if (copy_str(c->spool_path, sizeof(c->spool_path), val) != 0) {
            FAIL("too long");
        }
        return 0;
    }
    if (strcmp(key, "spool.max_lines") == 0 ||
        strcmp(key, "spool_max_lines") == 0) {
        if (parse_size(val, &sz) != 0 || sz == 0) {
            FAIL("invalid");
        }
        c->spool_max_lines = sz;
        return 0;
    }
    if (strcmp(key, "demo.target") == 0 || strcmp(key, "demo_target") == 0) {
        if (copy_str(c->demo_target, sizeof(c->demo_target), val) != 0) {
            FAIL("too long");
        }
        return 0;
    }
    if (strcmp(key, "arping.if") == 0 || strcmp(key, "arping_if") == 0 ||
        strcmp(key, "arping.iface") == 0 || strcmp(key, "iface") == 0) {
        if (copy_str(c->arping_if, sizeof(c->arping_if), val) != 0) {
            FAIL("too long");
        }
        return 0;
    }
    if (strcmp(key, "demo.interval_ms") == 0 ||
        strcmp(key, "demo_interval_ms") == 0 ||
        strcmp(key, "sample.interval_ms") == 0 ||
        strcmp(key, "sample_interval_ms") == 0) {
        if (parse_u32(val, &u32) != 0 || u32 == 0) {
            FAIL("invalid");
        }
        c->demo_interval_ms = u32;
        c->sample_interval_ms = u32;
        return 0;
    }
    if (strcmp(key, "demo.enabled") == 0 || strcmp(key, "demo_mode") == 0) {
        if (parse_bool(val, &iv) != 0) {
            FAIL("invalid bool");
        }
        c->demo_mode = iv;
        return 0;
    }
    if (strcmp(key, "demo.timeout_ms") == 0 ||
        strcmp(key, "probe.timeout_ms") == 0 ||
        strcmp(key, "probe_timeout_ms") == 0) {
        if (parse_u32(val, &u32) != 0 || u32 == 0) {
            FAIL("invalid");
        }
        c->probe_timeout_ms = u32;
        return 0;
    }
    if (strcmp(key, "egress.url") == 0 || strcmp(key, "https_url") == 0) {
        if (copy_str(c->https_url, sizeof(c->https_url), val) != 0) {
            FAIL("too long");
        }
        return 0;
    }
    if (strcmp(key, "egress.ca_file") == 0 || strcmp(key, "tls_ca_file") == 0) {
        if (copy_str(c->tls_ca_file, sizeof(c->tls_ca_file), val) != 0) {
            FAIL("too long");
        }
        return 0;
    }
    if (strcmp(key, "egress.cert_file") == 0 ||
        strcmp(key, "tls_cert_file") == 0) {
        if (copy_str(c->tls_cert_file, sizeof(c->tls_cert_file), val) != 0) {
            FAIL("too long");
        }
        return 0;
    }
    if (strcmp(key, "egress.key_file") == 0 ||
        strcmp(key, "tls_key_file") == 0) {
        if (copy_str(c->tls_key_file, sizeof(c->tls_key_file), val) != 0) {
            FAIL("too long");
        }
        return 0;
    }
#undef FAIL
    return 0;
}

static const char *const g_paths[] = {
    "router_id",
    "emit.mode",
    "emit_mode",
    "emit.path",
    "spool.path",
    "spool_path",
    "spool.max_lines",
    "spool_max_lines",
    "demo.target",
    "demo_target",
    "arping.if",
    "arping_if",
    "arping.iface",
    "iface",
    "demo.interval_ms",
    "demo_interval_ms",
    "sample.interval_ms",
    "sample_interval_ms",
    "demo.enabled",
    "demo_mode",
    "demo.timeout_ms",
    "probe.timeout_ms",
    "probe_timeout_ms",
    "egress.url",
    "https_url",
    "egress.ca_file",
    "tls_ca_file",
    "egress.cert_file",
    "tls_cert_file",
    "egress.key_file",
    "tls_key_file",
    NULL
};

static int load_from_ctx(yaml_ctx_t *ctx, cpe_agent_config_t *c, char *err,
                         size_t err_len)
{
    size_t i;
    yaml_event_t ev;

    while (yaml_next_event(ctx, &ev)) {
        if (ev.type == YAML_EVENT_ERROR) {
            if (err && err_len) {
                snprintf(err, err_len, "yaml parse: %s",
                         ev.data.error.message[0] ? ev.data.error.message
                                                  : "error");
            }
            return -1;
        }
    }

    for (i = 0; g_paths[i]; i++) {
        const char *val = lookup(ctx, g_paths[i]);
        if (!val) {
            continue;
        }
        if (apply_scalar(c, g_paths[i], val, err, err_len) != 0) {
            return -1;
        }
    }
    return 0;
}

int cpe_agent_config_load_yaml_buf(const char *yaml, size_t yaml_len,
                                   cpe_agent_config_t *out, char *err,
                                   size_t err_len)
{
    yaml_ctx_t *ctx;
    size_t n;

    if (!out) {
        if (err && err_len) {
            snprintf(err, err_len, "null args");
        }
        return -1;
    }
    cpe_agent_config_defaults(out);
    if (!yaml || yaml_len == 0) {
        return 0;
    }

    ctx = yaml_create(YAML_ROLE_PARSER);
    if (!ctx) {
        if (err && err_len) {
            snprintf(err, err_len, "yaml_create failed");
        }
        return -1;
    }
    n = yaml_feed_input(ctx, (const uint8_t *)yaml, yaml_len);
    if (n == 0 && yaml_len > 0) {
        if (err && err_len) {
            snprintf(err, err_len, "yaml_feed_input consumed 0");
        }
        yaml_destroy(ctx);
        return -1;
    }
    if (load_from_ctx(ctx, out, err, err_len) != 0) {
        yaml_destroy(ctx);
        return -1;
    }
    yaml_destroy(ctx);
    return 0;
}

int cpe_agent_config_load_yaml_path(const char *path, cpe_agent_config_t *out,
                                    char *err, size_t err_len)
{
    FILE *fp;
    char *buf = NULL;
    size_t cap = 0;
    size_t len = 0;
    char chunk[4096];
    size_t nr;
    int rc;

    if (!path || !out) {
        if (err && err_len) {
            snprintf(err, err_len, "null args");
        }
        return -1;
    }
    fp = fopen(path, "rb");
    if (!fp) {
        if (err && err_len) {
            snprintf(err, err_len, "cannot open %s", path);
        }
        return -1;
    }
    while ((nr = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
        char *nb;
        if (len + nr + 1 > cap) {
            size_t ncap = cap ? cap * 2 : 8192;
            while (ncap < len + nr + 1) {
                ncap *= 2;
            }
            nb = (char *)realloc(buf, ncap);
            if (!nb) {
                free(buf);
                fclose(fp);
                if (err && err_len) {
                    snprintf(err, err_len, "oom reading config");
                }
                return -1;
            }
            buf = nb;
            cap = ncap;
        }
        memcpy(buf + len, chunk, nr);
        len += nr;
    }
    fclose(fp);
    if (!buf) {
        cpe_agent_config_defaults(out);
        return 0;
    }
    buf[len] = '\0';
    rc = cpe_agent_config_load_yaml_buf(buf, len, out, err, err_len);
    free(buf);
    return rc;
}
