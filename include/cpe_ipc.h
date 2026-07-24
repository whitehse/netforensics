/**
 * @file cpe_ipc.h
 * @brief Unix domain socket control plane between cpe_agent (daemon) and cpe_ctl.
 *
 * Protocol: one JSON object per line (NDJSON request/response).
 *   Request:  {"op":"tcp_stats"}\n
 *   Response: {"ok":true,"op":"tcp_stats","data":{...}}\n
 *
 * The daemon owns collection, egress to edgehost proxies, and privileged sockets.
 * cpe_ctl is an unprivileged human/AI front-end with Lua that queries via this IPC.
 */
#ifndef CPE_IPC_H
#define CPE_IPC_H

#include "cpe_agent.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CPE_IPC_SOCK_DEFAULT "/var/run/netforensics/cpe_agent.sock"
#define CPE_IPC_LINE_MAX     8192
#define CPE_IPC_CLIENTS_MAX  8

typedef struct cpe_ipc_server cpe_ipc_server_t;

/**
 * Create UDS server bound to @p path (unlink existing socket first).
 * Parent directories are created best-effort. @return NULL on error.
 */
cpe_ipc_server_t *cpe_ipc_server_create(cpe_agent_t *agent, const char *path,
                                        char *err, size_t err_len);

void cpe_ipc_server_destroy(cpe_ipc_server_t *s);

/** Listening socket fd, or -1. */
int cpe_ipc_server_fd(const cpe_ipc_server_t *s);

/**
 * Non-blocking: accept new clients + service readable clients.
 * Call from the agent timer/poll loop. @return number of requests handled.
 */
int cpe_ipc_server_poll(cpe_ipc_server_t *s);

/** Socket path in use (or empty). */
const char *cpe_ipc_server_path(const cpe_ipc_server_t *s);

/**
 * Client: connect to daemon UDS, send one JSON request line, read one response.
 * @p req must be a single JSON object (no newline required).
 * @return 0 ok (response in @p resp), -1 on error (message in err).
 */
int cpe_ipc_client_request(const char *sock_path, const char *req, char *resp,
                           size_t resp_sz, char *err, size_t err_len);

/**
 * Handle one request JSON into @p out response buffer (server-side helper / tests).
 * @return 0 ok, -1 hard error.
 */
int cpe_ipc_handle_request(cpe_agent_t *a, const char *req_json, char *out,
                           size_t out_sz);

#ifdef __cplusplus
}
#endif

#endif /* CPE_IPC_H */
