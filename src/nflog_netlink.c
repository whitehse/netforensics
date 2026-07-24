/**
 * @file nflog_netlink.c
 * @brief NETLINK_NETFILTER NFLOG socket open / bind / walk.
 *
 * App owns the socket (syscalls). No libmnl / libnetfilter_log dependency.
 */

#define _POSIX_C_SOURCE 200809L

#include "nflog_netlink.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/netfilter.h>

#ifndef NLA_F_NESTED
#define NLA_F_NESTED (1 << 15)
#endif
#ifndef NLA_TYPE_MASK
#define NLA_TYPE_MASK 0x3fff
#endif

/* Netlink attribute header (kernel nlattr). */
struct nflog_nlattr {
    uint16_t nla_len;
    uint16_t nla_type;
};

#define NFLOG_NLA_ALIGNTO 4
#define NFLOG_NLA_ALIGN(len)                                                   \
    (((len) + NFLOG_NLA_ALIGNTO - 1) & ~(NFLOG_NLA_ALIGNTO - 1))
#define NFLOG_NLA_HDRLEN ((int)NFLOG_NLA_ALIGN(sizeof(struct nflog_nlattr)))

static int nla_ok(const struct nflog_nlattr *nla, int remaining)
{
    return remaining >= (int)sizeof(*nla) && nla->nla_len >= sizeof(*nla) &&
           nla->nla_len <= remaining;
}

static struct nflog_nlattr *nla_next(const struct nflog_nlattr *nla,
                                     int *remaining)
{
    int len = NFLOG_NLA_ALIGN(nla->nla_len);
    *remaining -= len;
    return (struct nflog_nlattr *)((const char *)nla + len);
}

static const void *nla_data(const struct nflog_nlattr *nla)
{
    return (const char *)nla + NFLOG_NLA_HDRLEN;
}

static int nla_len(const struct nflog_nlattr *nla)
{
    return (int)nla->nla_len - NFLOG_NLA_HDRLEN;
}

static int nflog_send_cfg(int fd, uint16_t group, uint8_t cmd, uint8_t family,
                          const void *extra_attr, size_t extra_len)
{
    uint8_t buf[256];
    struct nlmsghdr *nlh;
    struct nfgenmsg *nfg;
    struct nflog_nlattr *nla;
    struct nfulnl_msg_config_cmd c;
    size_t off;
    struct sockaddr_nl sa;
    ssize_t wr;

    memset(buf, 0, sizeof(buf));
    nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type =
        (uint16_t)((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG);
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = 0;

    nfg = (struct nfgenmsg *)(buf + NLMSG_HDRLEN);
    nfg->nfgen_family = family;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = htons(group);

    off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct nfgenmsg));
    nla = (struct nflog_nlattr *)(buf + off);
    c.command = cmd;
    nla->nla_type = NFULA_CFG_CMD;
    nla->nla_len = (uint16_t)(NFLOG_NLA_HDRLEN + sizeof(c));
    memcpy((char *)nla + NFLOG_NLA_HDRLEN, &c, sizeof(c));
    off += NFLOG_NLA_ALIGN(nla->nla_len);

    if (extra_attr && extra_len > 0 && off + extra_len <= sizeof(buf)) {
        memcpy(buf + off, extra_attr, extra_len);
        off += NFLOG_NLA_ALIGN((int)extra_len);
    }

    nlh->nlmsg_len = (uint32_t)off;

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    wr = sendto(fd, buf, off, 0, (struct sockaddr *)&sa, sizeof(sa));
    if (wr < 0 || (size_t)wr != off) {
        return -1;
    }
    return 0;
}

static int nflog_set_mode(int fd, uint16_t group, uint32_t copy_range)
{
    uint8_t attrbuf[64];
    struct nflog_nlattr *nla;
    struct nfulnl_msg_config_mode mode;

    memset(attrbuf, 0, sizeof(attrbuf));
    nla = (struct nflog_nlattr *)attrbuf;
    memset(&mode, 0, sizeof(mode));
    mode.copy_range = htonl(copy_range ? copy_range : NFLOG_COPY_RANGE_DEFAULT);
    mode.copy_mode = NFULNL_COPY_PACKET;
    nla->nla_type = NFULA_CFG_MODE;
    nla->nla_len = (uint16_t)(NFLOG_NLA_HDRLEN + sizeof(mode));
    memcpy((char *)nla + NFLOG_NLA_HDRLEN, &mode, sizeof(mode));

    return nflog_send_cfg(fd, group, NFULNL_CFG_CMD_NONE, AF_UNSPEC, attrbuf,
                          nla->nla_len);
}

int nflog_netlink_open(uint16_t group, uint32_t copy_range, char *errbuf,
                       size_t errbuf_len)
{
    int fd;
    struct sockaddr_nl sa;
    int one = 1;
    int rcv;

    if (group == 0) {
        group = NFLOG_GROUP_DEFAULT;
    }

    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0) {
        if (errbuf && errbuf_len) {
            snprintf(errbuf, errbuf_len, "socket(NETLINK_NETFILTER): %s",
                     strerror(errno));
        }
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = 0;
    sa.nl_groups = 0;

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        if (errbuf && errbuf_len) {
            snprintf(errbuf, errbuf_len, "bind netlink: %s", strerror(errno));
        }
        close(fd);
        return -1;
    }

    /* Bind protocol families then the log group. */
    if (nflog_send_cfg(fd, 0, NFULNL_CFG_CMD_PF_BIND, AF_INET, NULL, 0) != 0) {
        if (errbuf && errbuf_len) {
            snprintf(errbuf, errbuf_len, "NFLOG PF_BIND IPv4: %s",
                     strerror(errno));
        }
        close(fd);
        return -1;
    }
    /* IPv6 optional — ignore failure on kernels without it. */
    (void)nflog_send_cfg(fd, 0, NFULNL_CFG_CMD_PF_BIND, AF_INET6, NULL, 0);

    if (nflog_send_cfg(fd, group, NFULNL_CFG_CMD_BIND, AF_UNSPEC, NULL, 0) !=
        0) {
        if (errbuf && errbuf_len) {
            snprintf(errbuf, errbuf_len,
                     "NFLOG BIND group %u: %s (need CAP_NET_ADMIN?)",
                     (unsigned)group, strerror(errno));
        }
        close(fd);
        return -1;
    }

    if (nflog_set_mode(fd, group, copy_range) != 0) {
        if (errbuf && errbuf_len) {
            snprintf(errbuf, errbuf_len, "NFLOG MODE: %s", strerror(errno));
        }
        close(fd);
        return -1;
    }

    rcv = 1 << 20; /* 1 MiB */
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    (void)setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof(one));

    return fd;
}

void nflog_netlink_close(int fd)
{
    if (fd >= 0) {
        close(fd);
    }
}

int nflog_netlink_set_nonblock(int fd)
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

int nflog_netlink_recv(int fd, uint8_t *buf, size_t buflen)
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
    if (n == 0) {
        return -1;
    }
    return (int)n;
}

static void walk_packet_attrs(const uint8_t *attr, int attrlen,
                              nflog_packet_cb cb, void *opaque)
{
    const struct nflog_nlattr *nla;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    uint16_t hw_protocol = 0;
    uint32_t mark = 0;
    uint64_t ts_sec = 0;
    uint64_t ts_usec = 0;
    int rem = attrlen;

    nla = (const struct nflog_nlattr *)attr;
    while (nla_ok(nla, rem)) {
        uint16_t type = nla->nla_type & NLA_TYPE_MASK;
        const uint8_t *d = (const uint8_t *)nla_data(nla);
        int dlen = nla_len(nla);

        switch (type) {
        case NFULA_PACKET_HDR:
            if (dlen >= (int)sizeof(struct nfulnl_msg_packet_hdr)) {
                const struct nfulnl_msg_packet_hdr *ph =
                    (const struct nfulnl_msg_packet_hdr *)d;
                hw_protocol = ntohs(ph->hw_protocol);
            }
            break;
        case NFULA_MARK:
            if (dlen >= 4) {
                uint32_t m;
                memcpy(&m, d, 4);
                mark = ntohl(m);
            }
            break;
        case NFULA_TIMESTAMP:
            if (dlen >= (int)sizeof(struct nfulnl_msg_packet_timestamp)) {
                const uint8_t *tb = d;
                /* big-endian 64-bit sec + usec */
                ts_sec = ((uint64_t)tb[0] << 56) | ((uint64_t)tb[1] << 48) |
                         ((uint64_t)tb[2] << 40) | ((uint64_t)tb[3] << 32) |
                         ((uint64_t)tb[4] << 24) | ((uint64_t)tb[5] << 16) |
                         ((uint64_t)tb[6] << 8) | (uint64_t)tb[7];
                ts_usec = ((uint64_t)tb[8] << 56) | ((uint64_t)tb[9] << 48) |
                          ((uint64_t)tb[10] << 40) | ((uint64_t)tb[11] << 32) |
                          ((uint64_t)tb[12] << 24) | ((uint64_t)tb[13] << 16) |
                          ((uint64_t)tb[14] << 8) | (uint64_t)tb[15];
            }
            break;
        case NFULA_PAYLOAD:
            if (dlen > 0) {
                payload = d;
                payload_len = (size_t)dlen;
            }
            break;
        default:
            break;
        }
        nla = nla_next(nla, &rem);
    }

    if (payload && payload_len > 0 && cb) {
        cb(opaque, payload, payload_len, hw_protocol, mark, ts_sec, ts_usec);
    }
}

int nflog_netlink_walk(const uint8_t *buf, size_t len, nflog_packet_cb cb,
                       void *opaque)
{
    const uint8_t *p = buf;
    size_t left = len;
    int count = 0;

    if (!buf || len < sizeof(struct nlmsghdr)) {
        return -1;
    }

    while (left >= sizeof(struct nlmsghdr)) {
        const struct nlmsghdr *nlh = (const struct nlmsghdr *)p;
        uint16_t type;
        uint16_t subsys;
        uint16_t msg;
        size_t msglen;

        if (nlh->nlmsg_len < sizeof(struct nlmsghdr) ||
            nlh->nlmsg_len > left) {
            break;
        }
        msglen = nlh->nlmsg_len;
        type = nlh->nlmsg_type;
        if (type == NLMSG_DONE || type == NLMSG_ERROR) {
            p += NLMSG_ALIGN(msglen);
            left -= NLMSG_ALIGN(msglen);
            continue;
        }

        subsys = (uint16_t)((type & 0xff00) >> 8);
        msg = (uint16_t)(type & 0x00ff);
        if (subsys == NFNL_SUBSYS_ULOG && msg == NFULNL_MSG_PACKET) {
            size_t hdr = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct nfgenmsg));
            if (msglen > hdr) {
                int before = count;
                walk_packet_attrs(p + hdr, (int)(msglen - hdr), cb, opaque);
                /* walk_packet_attrs invokes cb at most once; count via side
                 * effect — re-walk is awkward, so assume one payload/msg. */
                (void)before;
                count++;
            }
        }

        p += NLMSG_ALIGN(msglen);
        if (left < NLMSG_ALIGN(msglen)) {
            break;
        }
        left -= NLMSG_ALIGN(msglen);
    }

    return count;
}
