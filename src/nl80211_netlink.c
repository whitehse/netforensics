/**
 * @file nl80211_netlink.c
 * @brief App-owned generic netlink for nl80211 station dumps.
 */

#define _GNU_SOURCE
#include "nl80211_netlink.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Subset of nl80211 commands/attrs */
#define NL80211_CMD_GET_STATION 17
#define NL80211_ATTR_IFINDEX    3

#ifndef NETLINK_GENERIC
#define NETLINK_GENERIC 16
#endif

static void wr16_le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static void wr32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static uint16_t rd16_le(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t rd32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int nf_if_nametoindex(const char *ifname)
{
    unsigned idx;
    if (!ifname || !ifname[0]) {
        return -1;
    }
    idx = if_nametoindex(ifname);
    return idx ? (int)idx : -1;
}

static int ctrl_resolve_family(int fd, const char *name, int *family_id,
                               char *err, size_t err_len)
{
    uint8_t req[128];
    uint8_t resp[512];
    struct nlmsghdr *nlh;
    struct genlmsghdr *gh;
    size_t name_len = strlen(name) + 1;
    size_t nla_len = 4 + name_len;
    size_t nla_total = (nla_len + 3u) & ~3u;
    size_t msg_len = NLMSG_HDRLEN + GENL_HDRLEN + nla_total;
    ssize_t n;
    size_t off;

    memset(req, 0, sizeof(req));
    nlh = (struct nlmsghdr *)req;
    nlh->nlmsg_len = (uint32_t)msg_len;
    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = 0;
    gh = (struct genlmsghdr *)(req + NLMSG_HDRLEN);
    gh->cmd = CTRL_CMD_GETFAMILY;
    gh->version = 1;
    {
        uint8_t *nla = req + NLMSG_HDRLEN + GENL_HDRLEN;
        wr16_le(nla, (uint16_t)nla_len);
        wr16_le(nla + 2, CTRL_ATTR_FAMILY_NAME);
        memcpy(nla + 4, name, name_len);
    }

    if (send(fd, req, msg_len, 0) < 0) {
        if (err && err_len) {
            snprintf(err, err_len, "genl GETFAMILY send: %s", strerror(errno));
        }
        return -1;
    }

    n = recv(fd, resp, sizeof(resp), 0);
    if (n < (ssize_t)NLMSG_HDRLEN) {
        if (err && err_len) {
            snprintf(err, err_len, "genl GETFAMILY recv: %s",
                     n < 0 ? strerror(errno) : "short");
        }
        return -1;
    }

    off = 0;
    while (off + NLMSG_HDRLEN <= (size_t)n) {
        uint32_t len = rd32_le(resp + off);
        uint16_t type = rd16_le(resp + off + 4);
        if (len < NLMSG_HDRLEN || off + len > (size_t)n) {
            break;
        }
        if (type == GENL_ID_CTRL && len >= NLMSG_HDRLEN + GENL_HDRLEN) {
            size_t aoff = off + NLMSG_HDRLEN + GENL_HDRLEN;
            size_t aend = off + len;
            while (aoff + 4 <= aend) {
                uint16_t alen = rd16_le(resp + aoff);
                uint16_t atype = rd16_le(resp + aoff + 2) & 0x3fffu;
                if (alen < 4 || aoff + alen > aend) {
                    break;
                }
                if (atype == CTRL_ATTR_FAMILY_ID && alen >= 6) {
                    *family_id = (int)rd16_le(resp + aoff + 4);
                    return 0;
                }
                aoff += (alen + 3u) & ~3u;
            }
        }
        off += (len + 3u) & ~3u;
    }
    if (err && err_len) {
        snprintf(err, err_len, "nl80211 family id not found");
    }
    return -1;
}

int nl80211_netlink_open(int *family_id_out, char *err, size_t err_len)
{
    int fd;
    struct sockaddr_nl sa;
    int family = 0;

    if (!family_id_out) {
        return -1;
    }
    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd < 0) {
        if (err && err_len) {
            snprintf(err, err_len, "socket NETLINK_GENERIC: %s", strerror(errno));
        }
        return -1;
    }
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        if (err && err_len) {
            snprintf(err, err_len, "bind genl: %s", strerror(errno));
        }
        close(fd);
        return -1;
    }
    if (ctrl_resolve_family(fd, "nl80211", &family, err, err_len) != 0) {
        close(fd);
        return -1;
    }
    *family_id_out = family;
    return fd;
}

void nl80211_netlink_close(int fd)
{
    if (fd >= 0) {
        close(fd);
    }
}

int nl80211_netlink_dump_stations(int fd, int family_id, int ifindex,
                                  char *err, size_t err_len)
{
    uint8_t req[64];
    struct nlmsghdr *nlh;
    struct genlmsghdr *gh;
    size_t msg_len;
    uint8_t *nla;
    uint32_t ifi = (uint32_t)ifindex;

    if (fd < 0 || family_id <= 0 || ifindex <= 0) {
        if (err && err_len) {
            snprintf(err, err_len, "bad args for dump_stations");
        }
        return -1;
    }

    memset(req, 0, sizeof(req));
    /* nlmsg + genl + nla(ifindex) */
    msg_len = NLMSG_HDRLEN + GENL_HDRLEN + 8;
    nlh = (struct nlmsghdr *)req;
    nlh->nlmsg_len = (uint32_t)msg_len;
    nlh->nlmsg_type = (uint16_t)family_id;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = 2;
    gh = (struct genlmsghdr *)(req + NLMSG_HDRLEN);
    gh->cmd = NL80211_CMD_GET_STATION;
    gh->version = 0;
    nla = req + NLMSG_HDRLEN + GENL_HDRLEN;
    wr16_le(nla, 8);
    wr16_le(nla + 2, NL80211_ATTR_IFINDEX);
    wr32_le(nla + 4, ifi);

    if (send(fd, req, msg_len, 0) < 0) {
        if (err && err_len) {
            snprintf(err, err_len, "dump stations send: %s", strerror(errno));
        }
        return -1;
    }
    return 0;
}

int nl80211_netlink_recv(int fd, void *buf, size_t buflen)
{
    ssize_t n;
    if (fd < 0 || !buf || buflen == 0) {
        return -1;
    }
    n = recv(fd, buf, buflen, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
    return (int)n;
}

int nl80211_netlink_set_nonblock(int fd)
{
    int flags;
    if (fd < 0) {
        return -1;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
