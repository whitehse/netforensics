/**
 * @file wifi_stats.c
 * @brief Wi‑Fi iface state + nl80211 station statistics for cpe_agent.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "cpe_agent.h"
#include "nl80211_netlink.h"
#include "nl80211_parse.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ---- agent-private last-wifi accessors (implemented in agent_core.c) ---- */
int  cpe_agent_set_last_wifi(cpe_agent_t *a, const cpe_wifi_snapshot_t *s);
/* cpe_agent_last_wifi is public */

static void iso_now(char *out, size_t n)
{
    struct timespec ts;
    struct tm tm;
    time_t sec;
    int ms;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        snprintf(out, n, "1970-01-01T00:00:00.000Z");
        return;
    }
    sec = ts.tv_sec;
    ms = (int)(ts.tv_nsec / 1000000);
    if (!gmtime_r(&sec, &tm)) {
        snprintf(out, n, "1970-01-01T00:00:00.000Z");
        return;
    }
    {
        int y = tm.tm_year + 1900;
        if (y < 0) {
            y = 0;
        }
        if (y > 9999) {
            y = 9999;
        }
        snprintf(out, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", y, tm.tm_mon + 1,
                 tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
    }
}

static void mac_fmt(char *out, size_t n, const uint8_t mac[6])
{
    snprintf(out, n, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2],
             mac[3], mac[4], mac[5]);
}

static int path_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

static int is_wireless_name(const char *ifname)
{
    char path[160];

    if (!ifname || !ifname[0]) {
        return 0;
    }
    snprintf(path, sizeof(path), "/sys/class/net/%s/wireless", ifname);
    if (path_exists(path)) {
        return 1;
    }
    snprintf(path, sizeof(path), "/sys/class/net/%s/phy80211", ifname);
    if (path_exists(path)) {
        return 1;
    }
    /* Common OpenWrt AP names */
    if (strncmp(ifname, "wlan", 4) == 0 || strncmp(ifname, "ath", 3) == 0 ||
        strncmp(ifname, "rai", 3) == 0 || strncmp(ifname, "rax", 3) == 0 ||
        strncmp(ifname, "wl", 2) == 0) {
        return 1;
    }
    return 0;
}

int cpe_agent_wifi_list_ifaces(char names[][CPE_WIFI_IFNAME_MAX], size_t max_names)
{
    DIR *d;
    struct dirent *de;
    size_t n = 0;

    if (!names || max_names == 0) {
        return -1;
    }
    d = opendir("/sys/class/net");
    if (!d) {
        return 0;
    }
    while ((de = readdir(d)) != NULL && n < max_names) {
        if (de->d_name[0] == '.') {
            continue;
        }
        if (!is_wireless_name(de->d_name)) {
            continue;
        }
        if (strlen(de->d_name) >= CPE_WIFI_IFNAME_MAX) {
            continue;
        }
        memcpy(names[n], de->d_name, strlen(de->d_name) + 1);
        n++;
    }
    closedir(d);
    return (int)n;
}

static int pick_wifi_if(cpe_agent_t *a, const char *ifname_opt, char *out,
                        size_t out_sz)
{
    const cpe_agent_config_t *cfg;
    char list[CPE_WIFI_STA_MAX][CPE_WIFI_IFNAME_MAX];
    int n;

    if (!out || out_sz < 2) {
        return -1;
    }
    if (ifname_opt && ifname_opt[0]) {
        snprintf(out, out_sz, "%s", ifname_opt);
        return 0;
    }
    cfg = a ? cpe_agent_config(a) : NULL;
    if (cfg && cfg->wifi_if[0]) {
        snprintf(out, out_sz, "%s", cfg->wifi_if);
        return 0;
    }
    n = cpe_agent_wifi_list_ifaces(list, CPE_WIFI_STA_MAX);
    if (n > 0) {
        snprintf(out, out_sz, "%s", list[0]);
        return 0;
    }
    snprintf(out, out_sz, "wlan0");
    return 0;
}

static int read_sysfs_str(const char *path, char *out, size_t out_sz)
{
    FILE *fp;
    size_t n;

    if (!path || !out || out_sz == 0) {
        return -1;
    }
    out[0] = '\0';
    fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }
    if (!fgets(out, (int)out_sz, fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    n = strlen(out);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' ||
                     out[n - 1] == ' ')) {
        out[--n] = '\0';
    }
    return 0;
}

int cpe_agent_wifi_iface_state(cpe_agent_t *a, const char *ifname_opt,
                               cpe_wifi_iface_state_t *out)
{
    char ifname[CPE_WIFI_IFNAME_MAX];
    char path[192];
    int fd;
    struct ifreq ifr;
    unsigned idx;

    if (!out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    if (pick_wifi_if(a, ifname_opt, ifname, sizeof(ifname)) != 0) {
        return -1;
    }
    snprintf(out->ifname, sizeof(out->ifname), "%s", ifname);

    idx = if_nametoindex(ifname);
    if (idx == 0) {
        return -1;
    }
    out->ifindex = (int)idx;
    out->wireless = is_wireless_name(ifname);

    snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", ifname);
    if (read_sysfs_str(path, out->operstate, sizeof(out->operstate)) != 0) {
        snprintf(out->operstate, sizeof(out->operstate), "unknown");
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return 0; /* still return operstate */
    }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
        out->up = (ifr.ifr_flags & IFF_UP) ? 1 : 0;
        out->running = (ifr.ifr_flags & IFF_RUNNING) ? 1 : 0;
    }
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        mac_fmt(out->mac, sizeof(out->mac),
                (const uint8_t *)ifr.ifr_hwaddr.sa_data);
    }
    if (ioctl(fd, SIOCGIFMTU, &ifr) == 0) {
        out->mtu = (uint32_t)ifr.ifr_mtu;
    }
    close(fd);
    return 0;
}

static void station_from_event(const nl80211_event_t *ev, cpe_wifi_station_t *s)
{
    memset(s, 0, sizeof(*s));
    if (!ev) {
        return;
    }
    if (ev->has_mac) {
        mac_fmt(s->mac, sizeof(s->mac), ev->client_mac);
    }
    s->signal_dbm = ev->signal_dbm;
    s->signal_avg_dbm = ev->signal_avg_dbm;
    s->snr_db = ev->snr_db;
    s->mcs = ev->has_mcs ? ev->mcs_index : 0xFF;
    s->tx_retries = ev->tx_retries;
    s->tx_failed = ev->tx_failed;
    s->rx_bytes = ev->rx_bytes;
    s->tx_bytes = ev->tx_bytes;
    s->freq_mhz = ev->frequency_mhz;
    s->has_signal = ev->has_signal;
    s->has_mcs = ev->has_mcs;
}

static int emit_wifi_ndjson(cpe_agent_t *a, const cpe_wifi_snapshot_t *snap)
{
    const cpe_agent_config_t *cfg;
    char line[CPE_NDJSON_LINE_MAX];
    size_t i;
    int n;

    if (!a || !snap) {
        return -1;
    }
    cfg = cpe_agent_config(a);
    if (!cfg) {
        return -1;
    }

    /* Summary line */
    n = snprintf(line, sizeof(line),
                 "{\"type\":\"cpe_wifi\",\"subtype\":\"iface\","
                 "\"ts\":\"%s\",\"router_id\":\"%s\",\"if\":\"%s\","
                 "\"ifindex\":%d,\"up\":%s,\"running\":%s,"
                 "\"operstate\":\"%s\",\"wireless\":%s,\"mac\":\"%s\","
                 "\"mtu\":%u,\"stations\":%u,\"demo\":%s}",
                 snap->ts_iso[0] ? snap->ts_iso : "",
                 cfg->router_id[0] ? cfg->router_id : "unknown",
                 snap->iface.ifname, snap->iface.ifindex,
                 snap->iface.up ? "true" : "false",
                 snap->iface.running ? "true" : "false", snap->iface.operstate,
                 snap->iface.wireless ? "true" : "false", snap->iface.mac,
                 (unsigned)snap->iface.mtu, (unsigned)snap->station_count,
                 snap->demo ? "true" : "false");
    if (n > 0 && (size_t)n < sizeof(line)) {
        (void)cpe_agent_spool_push_line(a, line);
    }

    for (i = 0; i < snap->station_count; i++) {
        const cpe_wifi_station_t *s = &snap->stations[i];
        n = snprintf(line, sizeof(line),
                     "{\"type\":\"cpe_wifi\",\"subtype\":\"station\","
                     "\"ts\":\"%s\",\"router_id\":\"%s\",\"if\":\"%s\","
                     "\"client_mac\":\"%s\",\"rssi\":%d,\"rssi_avg\":%d,"
                     "\"snr\":%d,\"mcs\":%u,\"tx_retries\":%u,\"tx_failed\":%u,"
                     "\"rx_bytes\":%u,\"tx_bytes\":%u,\"freq_mhz\":%u,"
                     "\"demo\":%s}",
                     snap->ts_iso[0] ? snap->ts_iso : "",
                     cfg->router_id[0] ? cfg->router_id : "unknown",
                     snap->iface.ifname, s->mac, (int)s->signal_dbm,
                     (int)s->signal_avg_dbm, (int)s->snr_db, (unsigned)s->mcs,
                     (unsigned)s->tx_retries, (unsigned)s->tx_failed,
                     (unsigned)s->rx_bytes, (unsigned)s->tx_bytes,
                     (unsigned)s->freq_mhz, snap->demo ? "true" : "false");
        if (n > 0 && (size_t)n < sizeof(line)) {
            (void)cpe_agent_spool_push_line(a, line);
        }
    }
    return 0;
}

static int dump_stations_live(const char *ifname, int ifindex,
                              cpe_wifi_snapshot_t *snap, char *err,
                              size_t err_len)
{
    int fd = -1;
    int family = 0;
    nl80211_parse_ctx *wifi = NULL;
    uint8_t buf[8192];
    int n;
    int rounds = 0;
    nl80211_event_t ev;

    snap->stations_valid = 0;
    snap->station_count = 0;

    fd = nl80211_netlink_open(&family, err, err_len);
    if (fd < 0) {
        return -1;
    }
    (void)nl80211_netlink_set_nonblock(fd);

    if (nl80211_netlink_dump_stations(fd, family, ifindex, err, err_len) != 0) {
        nl80211_netlink_close(fd);
        return -1;
    }

    wifi = nl80211_parse_create(NL80211_PARSE_ROLE_COLLECTOR);
    if (!wifi) {
        if (err && err_len) {
            snprintf(err, err_len, "nl80211_parse_create failed");
        }
        nl80211_netlink_close(fd);
        return -1;
    }

    /* Drain dump replies until idle (nonblock EAGAIN) or cap rounds. */
    for (rounds = 0; rounds < 64; rounds++) {
        n = nl80211_netlink_recv(fd, buf, sizeof(buf));
        if (n < 0) {
            if (err && err_len) {
                snprintf(err, err_len, "nl80211 recv: %s", strerror(errno));
            }
            break;
        }
        if (n == 0) {
            /* Give kernel a moment on first empty; then stop. */
            if (rounds == 0) {
                struct timespec ts;
                ts.tv_sec = 0;
                ts.tv_nsec = 20000000L; /* 20 ms */
                (void)nanosleep(&ts, NULL);
                continue;
            }
            break;
        }
        (void)nl80211_parse_feed_input(wifi, buf, (size_t)n);
        while (nl80211_parse_next_event(wifi, &ev) == 1) {
            if (ev.type == NL80211_EVENT_STATION && ev.has_mac &&
                snap->station_count < CPE_WIFI_STA_MAX) {
                station_from_event(&ev, &snap->stations[snap->station_count]);
                snap->station_count++;
            }
        }
    }

    nl80211_parse_destroy(wifi);
    nl80211_netlink_close(fd);
    snap->stations_valid = 1;
    (void)ifname;
    return 0;
}

int cpe_agent_wifi_dump(cpe_agent_t *a, const char *ifname_opt, int emit_ndjson,
                        cpe_wifi_snapshot_t *out_opt)
{
    cpe_wifi_snapshot_t snap;
    char err[96];

    if (!a) {
        return -1;
    }
    memset(&snap, 0, sizeof(snap));
    snap.demo = 0;
    iso_now(snap.ts_iso, sizeof(snap.ts_iso));

    if (cpe_agent_wifi_iface_state(a, ifname_opt, &snap.iface) != 0) {
        if (out_opt) {
            memset(out_opt, 0, sizeof(*out_opt));
            snprintf(out_opt->err, sizeof(out_opt->err), "wifi iface not found");
        }
        return -1;
    }

    err[0] = '\0';
    if (dump_stations_live(snap.iface.ifname, snap.iface.ifindex, &snap, err,
                           sizeof(err)) != 0) {
        snprintf(snap.err, sizeof(snap.err), "%s",
                 err[0] ? err : "nl80211 dump failed");
        snap.stations_valid = 0;
        snap.station_count = 0;
    }

    (void)cpe_agent_set_last_wifi(a, &snap);
    if (emit_ndjson) {
        (void)emit_wifi_ndjson(a, &snap);
        (void)cpe_agent_emit_flush(a);
    }
    if (out_opt) {
        *out_opt = snap;
    }
    return 0;
}

int cpe_agent_demo_wifi_dump(cpe_agent_t *a, int emit_ndjson,
                             cpe_wifi_snapshot_t *out_opt)
{
    cpe_wifi_snapshot_t snap;
    nl80211_parse_ctx *wifi;
    uint8_t wsynth[20];
    nl80211_event_t ev;
    const cpe_agent_config_t *cfg;

    if (!a) {
        return -1;
    }
    memset(&snap, 0, sizeof(snap));
    snap.demo = 1;
    iso_now(snap.ts_iso, sizeof(snap.ts_iso));
    cfg = cpe_agent_config(a);

    /* Prefer real iface state when present; else synthetic wlan0 */
    if (cpe_agent_wifi_iface_state(a, cfg && cfg->wifi_if[0] ? cfg->wifi_if : NULL,
                                   &snap.iface) != 0) {
        snprintf(snap.iface.ifname, sizeof(snap.iface.ifname), "wlan0");
        snap.iface.ifindex = 0;
        snap.iface.up = 1;
        snap.iface.running = 1;
        snap.iface.wireless = 1;
        snprintf(snap.iface.operstate, sizeof(snap.iface.operstate), "up");
        snprintf(snap.iface.mac, sizeof(snap.iface.mac), "02:00:00:00:00:10");
        snap.iface.mtu = 1500;
    }

    wifi = nl80211_parse_create(NL80211_PARSE_ROLE_COLLECTOR);
    if (!wifi) {
        return -1;
    }
    memset(wsynth, 0, sizeof(wsynth));
    /* magic '8211' BE */
    wsynth[0] = 0x38;
    wsynth[1] = 0x32;
    wsynth[2] = 0x31;
    wsynth[3] = 0x31;
    wsynth[4] = 0xaa;
    wsynth[5] = 0xbb;
    wsynth[6] = 0xcc;
    wsynth[7] = 0xdd;
    wsynth[8] = 0xee;
    wsynth[9] = 0xff;
    {
        uint32_t rssi = (uint32_t)(int32_t)-65;
        wsynth[10] = (uint8_t)((rssi >> 24) & 0xff);
        wsynth[11] = (uint8_t)((rssi >> 16) & 0xff);
        wsynth[12] = (uint8_t)((rssi >> 8) & 0xff);
        wsynth[13] = (uint8_t)(rssi & 0xff);
    }
    wsynth[14] = 25; /* mcs */
    wsynth[15] = 7;  /* snr */
    wsynth[16] = 0;
    wsynth[17] = 0;
    wsynth[18] = 0;
    wsynth[19] = 3; /* tx_retries */

    (void)nl80211_parse_feed_input(wifi, wsynth, sizeof(wsynth));
    while (nl80211_parse_next_event(wifi, &ev) == 1) {
        if (ev.type == NL80211_EVENT_STATION && ev.has_mac &&
            snap.station_count < CPE_WIFI_STA_MAX) {
            station_from_event(&ev, &snap.stations[snap.station_count]);
            /* demo: attach typical AP channel */
            if (snap.stations[snap.station_count].freq_mhz == 0) {
                snap.stations[snap.station_count].freq_mhz = 2437;
            }
            snap.station_count++;
        }
    }
    nl80211_parse_destroy(wifi);
    snap.stations_valid = 1;

    (void)cpe_agent_set_last_wifi(a, &snap);
    if (emit_ndjson) {
        (void)emit_wifi_ndjson(a, &snap);
        (void)cpe_agent_emit_flush(a);
    }
    if (out_opt) {
        *out_opt = snap;
    }
    return 0;
}
