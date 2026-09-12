/*
 * b61_acas_client.h — acasd UDS client (worker/server共用).
 * ECM_REQ -> Ks応答。master/KCLは扱わない。Ksはメモリのみ・ログ禁止。
 */
#ifndef B61_ACAS_CLIENT_H
#define B61_ACAS_CLIENT_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "b61_net.h"

static inline int b61_acas_read_n(int fd, uint8_t *p, int n, int timeout_ms) {
    int off = 0;
    while (off < n) {
        struct pollfd pfd; pfd.fd = fd; pfd.events = POLLIN;
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr <= 0) return -1;
        ssize_t r = read(fd, p + off, (size_t)(n - off));
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        off += (int)r;
    }
    return 0;
}

static inline int b61_acas_write_n(int fd, const uint8_t *p, int n) {
    int off = 0;
    while (off < n) {
        ssize_t w = write(fd, p + off, (size_t)(n - off));
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        off += (int)w;
    }
    return 0;
}

/* Returns 0 on OK (odd/even + epoch filled), -1 on error. */
static inline int b61_acas_request(const char *sock_path,
                                   const uint8_t *ecm, int ecm_len,
                                   uint8_t odd[16], uint8_t even[16],
                                   uint32_t *epoch_out) {
    if (ecm_len < 0x1b || ecm_len > B61_ACAS_ECM_MAX) return -1;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un au;
    memset(&au, 0, sizeof(au));
    au.sun_family = AF_UNIX;
    snprintf(au.sun_path, sizeof(au.sun_path), "%s", sock_path);
    if (connect(fd, (struct sockaddr *)&au, sizeof(au)) < 0) {
        close(fd);
        return -1;
    }
    uint8_t req[3 + B61_ACAS_ECM_MAX];
    req[0] = B61_ACAS_VERSION;
    req[1] = (uint8_t)((ecm_len >> 8) & 0xFF);
    req[2] = (uint8_t)(ecm_len & 0xFF);
    memcpy(req + 3, ecm, (size_t)ecm_len);
    if (b61_acas_write_n(fd, req, 3 + ecm_len) < 0) { close(fd); return -1; }
    uint8_t rep[1 + 4 + 32];
    if (b61_acas_read_n(fd, rep, sizeof(rep), 5000) < 0) { close(fd); return -1; }
    close(fd);
    if (rep[0] != B61_ACAS_STATUS_OK) return -1;
    uint32_t ep = ((uint32_t)rep[1] << 24) | ((uint32_t)rep[2] << 16) |
                  ((uint32_t)rep[3] << 8) | rep[4];
    if (epoch_out) *epoch_out = ep;
    memcpy(odd, rep + 5, 16);
    memcpy(even, rep + 5 + 16, 16);
    return 0;
}

#endif /* B61_ACAS_CLIENT_H */
