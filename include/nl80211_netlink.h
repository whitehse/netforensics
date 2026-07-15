#ifndef NETFORENSICS_NL80211_NETLINK_H
#define NETFORENSICS_NL80211_NETLINK_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Resolve ifindex for interface name (e.g. "wlan0"). Returns >0 or -1.
 */
int nf_if_nametoindex(const char *ifname);

/**
 * Open a generic-netlink socket bound for nl80211 replies.
 * Writes family_id into *family_id_out. Returns fd or -1 with err message.
 */
int nl80211_netlink_open(int *family_id_out, char *err, size_t err_len);

void nl80211_netlink_close(int fd);

/**
 * Send NL80211_CMD_GET_STATION dump for ifindex. Replies are read with recv.
 * Returns 0 on success.
 */
int nl80211_netlink_dump_stations(int fd, int family_id, int ifindex,
                                  char *err, size_t err_len);

/**
 * Recv one netlink buffer (non-blocking ok). Returns bytes, 0 if EAGAIN, -1 err.
 */
int nl80211_netlink_recv(int fd, void *buf, size_t buflen);

int nl80211_netlink_set_nonblock(int fd);

#ifdef __cplusplus
}
#endif

#endif /* NETFORENSICS_NL80211_NETLINK_H */
