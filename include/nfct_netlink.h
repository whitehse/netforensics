#ifndef NFCT_NETLINK_H
#define NFCT_NETLINK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Open AF_NETLINK / NETLINK_NETFILTER and join conntrack multicast groups
 * NEW + DESTROY (and optionally UPDATE).
 *
 * Requires CAP_NET_ADMIN (or root). Returns fd >= 0 on success, -1 on error
 * (errno set; message in errbuf if provided).
 */
int nfct_netlink_open(int join_update, char *errbuf, size_t errbuf_len);

/** Close socket. Safe with fd < 0. */
void nfct_netlink_close(int fd);

/**
 * Blocking or non-blocking recv into buf.
 * Returns bytes read, 0 on EAGAIN/EWOULDBLOCK, -1 on error/EOF.
 */
int nfct_netlink_recv(int fd, uint8_t *buf, size_t buflen);

/**
 * Set O_NONBLOCK on fd. Returns 0 on success.
 */
int nfct_netlink_set_nonblock(int fd);

/**
 * Open a dedicated unicast netlink socket for conntrack table dumps
 * (IPCTNL_MSG_CT_GET + NLM_F_DUMP). Returns fd >= 0 or -1.
 */
int nfct_netlink_open_dump(char *errbuf, size_t errbuf_len);

/**
 * Send a dump request on @p dump_fd previously opened with
 * nfct_netlink_open_dump. Replies are read via nfct_netlink_recv.
 * @return 0 ok, -1 on error.
 */
int nfct_netlink_dump_request(int dump_fd);

#ifdef __cplusplus
}
#endif

#endif /* NFCT_NETLINK_H */
