/**
 * @file nflog_netlink.h
 * @brief Host-owned NFLOG (nfnetlink_log) socket for TCP control-plane stats.
 *
 * Binds to a configurable nflog group (default 5) matching iptables rules:
 *   iptables -I FORWARD 1 -p tcp --tcp-flags SYN SYN -m conntrack --ctstate NEW \
 *     -j NFLOG --nflog-group 5 --nflog-size 60
 *   iptables -I FORWARD 1 -p tcp --tcp-flags FIN FIN -j NFLOG --nflog-group 5 ...
 *   iptables -I FORWARD 1 -p tcp --tcp-flags RST RST -j NFLOG --nflog-group 5 ...
 *
 * Syscalls live here (app owns the socket). Payload parse is separate (tcp_stats).
 */
#ifndef NFLOG_NETLINK_H
#define NFLOG_NETLINK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NFLOG_GROUP_DEFAULT 5
#define NFLOG_COPY_RANGE_DEFAULT 60 /* match --nflog-size 60 */

/**
 * Open AF_NETLINK / NETLINK_NETFILTER, bind PF_INET (+ optional PF_INET6),
 * and join @p group (1..65535; typical field value is 5).
 *
 * Requires CAP_NET_ADMIN (or root). Returns fd >= 0 on success, -1 on error.
 */
int nflog_netlink_open(uint16_t group, uint32_t copy_range, char *errbuf,
                       size_t errbuf_len);

/** Close socket. Safe with fd < 0. */
void nflog_netlink_close(int fd);

/**
 * Blocking or non-blocking recv into buf.
 * Returns bytes read, 0 on EAGAIN/EWOULDBLOCK, -1 on error/EOF.
 */
int nflog_netlink_recv(int fd, uint8_t *buf, size_t buflen);

/** Set O_NONBLOCK on fd. Returns 0 on success. */
int nflog_netlink_set_nonblock(int fd);

/**
 * Walk one or more nfnetlink messages in @p buf and invoke @p cb for each
 * NFULNL_MSG_PACKET that carries a payload.
 *
 * @p cb receives: opaque, payload ptr/len, hw_protocol (host order ethertype
 * or 0), mark, timestamp sec/usec (0 if absent).
 * @return number of packets delivered to cb, or -1 on hard parse error.
 */
typedef void (*nflog_packet_cb)(void *opaque, const uint8_t *payload,
                                size_t payload_len, uint16_t hw_protocol,
                                uint32_t mark, uint64_t ts_sec,
                                uint64_t ts_usec);

int nflog_netlink_walk(const uint8_t *buf, size_t len, nflog_packet_cb cb,
                       void *opaque);

#ifdef __cplusplus
}
#endif

#endif /* NFLOG_NETLINK_H */
