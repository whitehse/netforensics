/**
 * @file gateway_stub_main.c
 * @brief Optional pure-C NDJSON HTTP ingest stub (MODULE 2).
 *
 * Not a production Vector replacement. Accepts POST body lines on a simple
 * TCP listener and writes them to stdout for lab piping into ClickHouse or
 * files. Prefer Vector + reverse-proxy mTLS in production.
 *
 * Usage: gateway_stub [--listen 0.0.0.0:8787]
 */

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void usage(const char *a0)
{
    fprintf(stderr,
            "Usage: %s [--listen HOST:PORT]\n"
            "Lab-only NDJSON HTTP sink stub; production uses Vector.\n",
            a0);
}

static int parse_listen(const char *s, char *host, size_t hsz, int *port)
{
    const char *colon = strrchr(s, ':');
    size_t hlen;

    if (!colon) {
        return -1;
    }
    hlen = (size_t)(colon - s);
    if (hlen == 0 || hlen >= hsz) {
        return -1;
    }
    memcpy(host, s, hlen);
    host[hlen] = '\0';
    *port = atoi(colon + 1);
    return (*port > 0 && *port < 65536) ? 0 : -1;
}

int main(int argc, char **argv)
{
    char host[64] = "0.0.0.0";
    int port = 8787;
    int i;
    int srv, cli;
    struct sockaddr_in addr;
    char buf[8192];
    ssize_t n;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
            if (parse_listen(argv[++i], host, sizeof(host), &port) != 0) {
                fprintf(stderr, "bad --listen\n");
                return 1;
            }
            continue;
        }
        usage(argv[0]);
        return 1;
    }

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        perror("socket");
        return 1;
    }
    {
        int one = 1;
        (void)setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "bad host\n");
        close(srv);
        return 1;
    }
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        close(srv);
        return 1;
    }
    if (listen(srv, 16) != 0) {
        perror("listen");
        close(srv);
        return 1;
    }
    fprintf(stderr, "gateway_stub listening on %s:%d (lab only)\n", host, port);

    for (;;) {
        cli = accept(srv, NULL, NULL);
        if (cli < 0) {
            continue;
        }
        /* Extremely minimal: read once, find body after \\r\\n\\r\\n, print. */
        n = recv(cli, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            char *body;
            buf[n] = '\0';
            body = strstr(buf, "\r\n\r\n");
            if (body) {
                body += 4;
                fputs(body, stdout);
                if (body[0] && body[strlen(body) - 1] != '\n') {
                    fputc('\n', stdout);
                }
                fflush(stdout);
            }
            (void)send(cli, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
                       48, 0);
        }
        close(cli);
    }
}
