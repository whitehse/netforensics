/**
 * @file nfct_netlink.c
 * @brief NETLINK_NETFILTER socket for conntrack event multicast.
 *
 * App owns the socket (syscalls). Parsed payloads are fed into libnetdiag nfct.
 */

#include "nfct_netlink.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <netinet/in.h>

int nfct_netlink_open(int join_update, char *errbuf, size_t errbuf_len)
{
    int fd;
    struct sockaddr_nl sa;
    int groups[] = {
        NFNLGRP_CONNTRACK_NEW,
        NFNLGRP_CONNTRACK_DESTROY,
        NFNLGRP_CONNTRACK_UPDATE /* conditional */
    };
    int n_groups = join_update ? 3 : 2;
    int i;
    int one = 1;

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
    sa.nl_pid = 0; /* kernel assigns */
    sa.nl_groups = 0;

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        if (errbuf && errbuf_len) {
            snprintf(errbuf, errbuf_len, "bind netlink: %s", strerror(errno));
        }
        close(fd);
        return -1;
    }

    /* Prefer NETLINK_ADD_MEMBERSHIP per group (reliable across kernels). */
    for (i = 0; i < n_groups; i++) {
        if (setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                       &groups[i], sizeof(groups[i])) != 0) {
            if (errbuf && errbuf_len) {
                snprintf(errbuf, errbuf_len,
                         "NETLINK_ADD_MEMBERSHIP group %d: %s "
                         "(need CAP_NET_ADMIN?)",
                         groups[i], strerror(errno));
            }
            close(fd);
            return -1;
        }
    }

    /* Larger rcv buffer for busy CPE */
    {
        int rcv = 1 << 20; /* 1 MiB */
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    }
    (void)setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof(one));

    return fd;
}

void nfct_netlink_close(int fd)
{
    if (fd >= 0) {
        close(fd);
    }
}

int nfct_netlink_set_nonblock(int fd)
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

int nfct_netlink_recv(int fd, uint8_t *buf, size_t buflen)
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

int nfct_netlink_open_dump(char *errbuf, size_t errbuf_len)
{
    int fd;
    struct sockaddr_nl sa;

    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0) {
        if (errbuf && errbuf_len) {
            snprintf(errbuf, errbuf_len, "socket dump: %s", strerror(errno));
        }
        return -1;
    }
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        if (errbuf && errbuf_len) {
            snprintf(errbuf, errbuf_len, "bind dump: %s", strerror(errno));
        }
        close(fd);
        return -1;
    }
    {
        int rcv = 1 << 20;
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    }
    return fd;
}

int nfct_netlink_dump_request(int dump_fd)
{
    /* nlmsghdr + nfgenmsg — request full conntrack dump */
    struct {
        struct nlmsghdr nlh;
        struct nfgenmsg nf;
    } req;
    struct sockaddr_nl sa;
    ssize_t n;

    if (dump_fd < 0) {
        return -1;
    }
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = sizeof(req);
    /* NFNL_SUBSYS_CTNETLINK=1, IPCTNL_MSG_CT_GET=1 */
    req.nlh.nlmsg_type = (1 << 8) | 1;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1;
    req.nlh.nlmsg_pid = 0;
    req.nf.nfgen_family = AF_UNSPEC;
    req.nf.version = NFNETLINK_V0;
    req.nf.res_id = 0;

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    n = sendto(dump_fd, &req, sizeof(req), 0, (struct sockaddr *)&sa,
               sizeof(sa));
    if (n != (ssize_t)sizeof(req)) {
        return -1;
    }
    return 0;
}
