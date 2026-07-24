/**
 * @file ipc_client.c
 * @brief Unix domain socket client for cpe_ctl → cpe_agent daemon.
 */

#define _POSIX_C_SOURCE 200809L

#include "cpe_ipc.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int cpe_ipc_client_request(const char *sock_path, const char *req, char *resp,
                           size_t resp_sz, char *err, size_t err_len)
{
    int fd = -1;
    struct sockaddr_un sa;
    char line[CPE_IPC_LINE_MAX];
    size_t req_len;
    size_t got = 0;
    ssize_t n;
    const char *path = sock_path && sock_path[0] ? sock_path : CPE_IPC_SOCK_DEFAULT;

    if (!req || !resp || resp_sz < 8) {
        if (err && err_len) {
            snprintf(err, err_len, "bad args");
        }
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        if (err && err_len) {
            snprintf(err, err_len, "socket: %s", strerror(errno));
        }
        return -1;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(sa.sun_path)) {
        if (err && err_len) {
            snprintf(err, err_len, "socket path too long");
        }
        close(fd);
        return -1;
    }
    memcpy(sa.sun_path, path, strlen(path) + 1);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        if (err && err_len) {
            snprintf(err, err_len, "connect %s: %s (is cpe_agent running?)",
                     path, strerror(errno));
        }
        close(fd);
        return -1;
    }

    req_len = strlen(req);
    if (req_len + 2 > sizeof(line)) {
        if (err && err_len) {
            snprintf(err, err_len, "request too long");
        }
        close(fd);
        return -1;
    }
    memcpy(line, req, req_len);
    if (req_len == 0 || line[req_len - 1] != '\n') {
        line[req_len++] = '\n';
    }
    if (send(fd, line, req_len, MSG_NOSIGNAL) < 0) {
        if (err && err_len) {
            snprintf(err, err_len, "send: %s", strerror(errno));
        }
        close(fd);
        return -1;
    }

    resp[0] = '\0';
    while (got + 1 < resp_sz) {
        n = recv(fd, resp + got, resp_sz - got - 1, 0);
        if (n < 0) {
            if (err && err_len) {
                snprintf(err, err_len, "recv: %s", strerror(errno));
            }
            close(fd);
            return -1;
        }
        if (n == 0) {
            break;
        }
        got += (size_t)n;
        resp[got] = '\0';
        if (memchr(resp, '\n', got)) {
            break;
        }
    }
    close(fd);

    /* Strip trailing newline */
    while (got > 0 && (resp[got - 1] == '\n' || resp[got - 1] == '\r')) {
        resp[--got] = '\0';
    }
    if (got == 0) {
        if (err && err_len) {
            snprintf(err, err_len, "empty response");
        }
        return -1;
    }
    return 0;
}
