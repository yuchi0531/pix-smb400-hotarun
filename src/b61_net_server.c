/*
 * b61_net_server.c — SMB400側 gateway (復号後fan-out).
 *
 * Upstream 1TCP (selector->server, full-duplex echo) + Fanout N-TCP
 * (server->viewers, one-way) を単一プロセス・pollで扱う。復号はSMB400内で
 * 完結し、master/KCL/Ksをネットワーク・ログに出さない (Ksはacasd UDSのみ)。
 *
 *  - チャネル単位×1TCP: 同時に1 upstreamのみ。2つ目は ERR BUSYで拒否。
 *    複数チャネルは複数プロセス/ポートで運用する。
 *  - 復号後fan-out: 復号済みTLVを echo (upstreamへ返送) + 全fanoutへ broadcast。
 *  - 遅client個別切断: fanout毎に 8MB有界キュー。超過・送信不能は当該のみ切断。
 *  - 背圧: echo pendingが8MB超過で upstream読取を一時停止 (dropしない)。
 *  - 先頭バッファリング: セッション開始後、最初のECM解決まで最大8MB/10s保持し
 *    ストリーム先頭から復号 (b61dec prescan相当、non-blocking版)。
 *  - stdin/stdoutは使わない。全ログstderr。Tokenは平文比較 (TLSは外側想定)。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include <openssl/evp.h>

#include "b61_tlv.h"
#include "b61_net.h"
#include "b61_acas_client.h"

static volatile int g_running = 1;
static void on_sig(int s) { (void)s; g_running = 0; }

static int g_verbose = 0;
static const char *g_acas_sock = NULL;

/* ---------- AES + decrypt (workerと同一) ---------- */
static EVP_CIPHER_CTX *g_ctx_odd, *g_ctx_even;
static uint8_t g_key_odd[16], g_key_even[16];
static int g_key_odd_set, g_key_even_set;

static int aes_init(void) {
    g_ctx_odd = EVP_CIPHER_CTX_new();
    g_ctx_even = EVP_CIPHER_CTX_new();
    return (g_ctx_odd && g_ctx_even) ? 0 : -1;
}
static void aes_dec(int is_odd, const uint8_t key[16], const uint8_t iv[16],
                    const uint8_t *in, uint8_t *out, int len) {
    EVP_CIPHER_CTX *ctx = is_odd ? g_ctx_odd : g_ctx_even;
    uint8_t *ck = is_odd ? g_key_odd : g_key_even;
    int *ks = is_odd ? &g_key_odd_set : &g_key_even_set;
    if (!*ks || memcmp(ck, key, 16) != 0) {
        memcpy(ck, key, 16); *ks = 1;
        EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    } else EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv);
    int o = 0; EVP_EncryptUpdate(ctx, out, &o, in, len);
}
static long g_scr = 0, g_dec = 0, g_ecm = 0;
static int decrypt_pkt(uint8_t *tlv, int len, const uint8_t *ok_, const uint8_t *ek) {
    if (len < 4 || tlv[1] != B61_TLV_TYPE_HC) return 0;
    int dl = (int)b61_u16be(tlv + 2);
    if (4 + dl != len || dl < 3) return 0;
    uint8_t hc = tlv[6];
    int off;
    if (hc == B61_HC_NO_COMP) off = 7;
    else if (hc == B61_HC_PART_V6) off = 4 + 0x2D;
    else return 0;
    const uint8_t *m = tlv + off;
    int ml = len - off;
    if (ml < B61_MMTP_OFF_ENC + 1) return 0;
    uint8_t fl = m[B61_MMTP_OFF_FLAGS];
    if (!((fl & 0x02)) || (fl & 0x20)) return 0;
    uint16_t mext = b61_u16be(m + B61_MMTP_OFF_MEXT_T);
    uint8_t eb = m[B61_MMTP_OFF_ENC];
    int ef = (eb & 0x18) >> 3;
    if ((mext & 0x7FFF) != 0x0001 || ef == B61_ENC_NONE) return 0;
    g_scr++;
    if (!ok_ || !ek) return 0;
    if ((m[B61_MMTP_OFF_TYPE] & 0x3F) != 0x00) return 0;
    uint8_t iv[16]; memset(iv, 0, 16);
    iv[0] = m[B61_MMTP_OFF_PKT_ID]; iv[1] = m[B61_MMTP_OFF_PKT_ID + 1];
    iv[2] = m[B61_MMTP_OFF_SEQ]; iv[3] = m[B61_MMTP_OFF_SEQ + 1];
    iv[4] = m[B61_MMTP_OFF_SEQ + 2]; iv[5] = m[B61_MMTP_OFF_SEQ + 3];
    int is_odd = (ef == B61_ENC_ODD);
    uint16_t el = b61_u16be(m + B61_MMTP_OFF_EXT_L);
    int po = 0x0C + (int)el + 4, es = po + 8, enl = ml - es;
    if (es > ml || enl <= 0) return 0;
    tlv[off + B61_MMTP_OFF_ENC] = eb & 0xE3;
    aes_dec(is_odd, is_odd ? ok_ : ek, iv, tlv + off + es, tlv + off + es, enl);
    g_dec++;
    return 1;
}

/* Ks cache (epoch+fingerprint) */
#define SC_N 16
#define SC_FP 27
struct sc_ent { int v; uint32_t ep; int l; uint8_t fp[SC_FP]; uint8_t o[16], e[16]; };
static struct sc_ent g_sc[SC_N];
static int g_spos = 0;
static uint32_t g_ep_seen = 0;
static int sc_lookup(const uint8_t *ecm, int l, uint32_t ep, uint8_t o[16], uint8_t e[16]) {
    int k; for (k = 0; k < SC_N; k++) {
        if (!g_sc[k].v || g_sc[k].l != l) continue;
        if (ep && g_sc[k].ep != ep) continue;
        int c = l < SC_FP ? l : SC_FP;
        if (memcmp(g_sc[k].fp, ecm, (size_t)c)) continue;
        memcpy(o, g_sc[k].o, 16); memcpy(e, g_sc[k].e, 16); return 1;
    } return 0;
}
static void sc_store(const uint8_t *ecm, int l, uint32_t ep, const uint8_t o[16], const uint8_t e[16]) {
    struct sc_ent *en = &g_sc[g_spos % SC_N]; g_spos++;
    en->v = 1; en->ep = ep; en->l = l; memset(en->fp, 0, SC_FP);
    memcpy(en->fp, ecm, (size_t)(l < SC_FP ? l : SC_FP));
    memcpy(en->o, o, 16); memcpy(en->e, e, 16);
}
static int resolve_ecm(const uint8_t *ecm, int l, uint8_t o[16], uint8_t e[16]) {
    if (sc_lookup(ecm, l, g_ep_seen, o, e)) return 0;
    uint8_t no[16], ne[16]; uint32_t ep = 0;
    if (b61_acas_request(g_acas_sock, ecm, l, no, ne, &ep) < 0) return -1;
    if (g_ep_seen && ep != g_ep_seen) {
        fprintf(stderr, "b61_net_server: epoch %u->%u clear cache\n", g_ep_seen, ep);
        memset(g_sc, 0, sizeof(g_sc)); g_spos = 0;
    }
    g_ep_seen = ep;
    sc_store(ecm, l, ep, no, ne);
    memcpy(o, no, 16); memcpy(e, ne, 16);
    memset(no, 0, 16); memset(ne, 0, 16);
    return 0;
}

/* ---------- socket helpers ---------- */
static int set_nb(int fd) {
    int f = fcntl(fd, F_GETFL, 0);
    if (f < 0) return -1;
    return fcntl(fd, F_SETFL, f | O_NONBLOCK);
}
static int listen_on(int port) {
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in6 a6; memset(&a6, 0, sizeof(a6));
    a6.sin6_family = AF_INET6; a6.sin6_port = htons((uint16_t)port);
    a6.sin6_addr = in6addr_any;
    if (bind(fd, (struct sockaddr *)&a6, sizeof(a6)) < 0) {
        struct sockaddr_in a4; memset(&a4, 0, sizeof(a4));
        close(fd);
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        a4.sin_family = AF_INET; a4.sin_port = htons((uint16_t)port);
        a4.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(fd, (struct sockaddr *)&a4, sizeof(a4)) < 0) { close(fd); return -1; }
    }
    if (listen(fd, 16) < 0) { close(fd); return -1; }
    set_nb(fd);
    return fd;
}
static int send_nb(int fd, const uint8_t *p, int len) {
    /* returns bytes sent (>0), 0=woulblock, -1=error */
    ssize_t n = send(fd, p, (size_t)len, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        if (errno == EINTR) return 0;
        return -1;
    }
    return (int)n;
}
static long long now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
/* blocking line read for handshake (5s) */
static int read_line_block(int fd, char *out, int max, int timeout_ms) {
    int pos = 0; long long dl = now_ms() + timeout_ms;
    while (pos + 1 < max) {
        long long left = dl - now_ms();
        if (left <= 0) return -1;
        struct pollfd p; p.fd = fd; p.events = POLLIN;
        int pr = poll(&p, 1, (int)left);
        if (pr <= 0) return -1;
        char c; ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0) return -1;
        out[pos++] = c;
        if (c == '\n') break;
    }
    out[pos] = 0; return pos;
}
static int send_all_b(int fd, const char *s) {
    int l = (int)strlen(s), o = 0;
    while (o < l) {
        ssize_t n = send(fd, s + o, (size_t)(l - o), MSG_NOSIGNAL);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        o += (int)n;
    } return 0;
}
static int token_ok(const char *got, const char *want) {
    if (!want || !*want || strcmp(want, "none") == 0) return 1;
    return strcmp(got ? got : "", want) == 0;
}
/* crude parsers: find "TOKEN x", "SERVICE n", "SID n" */
static void parse_hs(const char *line, char *tok, size_t tksz, long *svc, long *sid) {
    tok[0] = 0; *svc = 0; *sid = 1;
    const char *p = strstr(line, "TOKEN ");
    if (p) { p += 6; size_t k = 0; while (*p && *p != ' ' && *p != '\r' && *p != '\n' && k + 1 < tksz) tok[k++] = *p++; tok[k] = 0; }
    p = strstr(line, "SERVICE ");
    if (p) *svc = strtol(p + 8, NULL, 0);
    p = strstr(line, "SID ");
    if (p) *sid = strtol(p + 4, NULL, 0);
}

#define MAX_FANOUT 16
struct fanout_cli { int fd; uint8_t *pend; int len, cap, base; long long last_ok; };
struct server_state {
    int up_fd;
    int up_eof;
    long up_svc, up_sid;
    long long sess_start_ms;
    int prescan_done;
    uint8_t odd[16], even[16];
    int have_keys;
    uint8_t *up_buf; int up_len, up_base, up_cap;
    uint8_t *echo_buf; int echo_len, echo_base, echo_cap;
    struct fanout_cli fan[MAX_FANOUT];
    long n_up_pkt, n_dec_pkt;
};

static void fan_remove(struct server_state *s, int idx) {
    if (s->fan[idx].fd >= 0) close(s->fan[idx].fd);
    free(s->fan[idx].pend);
    memset(&s->fan[idx], 0, sizeof(s->fan[idx]));
    s->fan[idx].fd = -1;
}
static int fan_add(struct server_state *s, int fd) {
    int k; for (k = 0; k < MAX_FANOUT; k++) if (s->fan[k].fd < 0) {
        s->fan[k].fd = fd; s->fan[k].pend = NULL;
        s->fan[k].len = s->fan[k].base = s->fan[k].cap = 0;
        s->fan[k].last_ok = now_ms();
        return 0;
    }
    return -1;
}
static int fan_queue(struct server_state *s, const uint8_t *p, int pl) {
    int k;
    for (k = 0; k < MAX_FANOUT; k++) {
        if (s->fan[k].fd < 0) continue;
        struct fanout_cli *f = &s->fan[k];
        int need = (f->len - f->base) + pl;
        if (need > B61_NET_FANOUT_PER_CLIENT) {
            fprintf(stderr, "b61_net_server: fanout[%d] slow, disconnect (%d bytes pending)\n", k, need);
            fan_remove(s, k);
            continue;
        }
        if (need > f->cap) {
            int nc = need < 65536 ? 65536 : need * 2;
            if (nc > B61_NET_FANOUT_PER_CLIENT) nc = B61_NET_FANOUT_PER_CLIENT;
            uint8_t *np = (uint8_t *)realloc(f->pend, (size_t)nc);
            if (!np) { fan_remove(s, k); continue; }
            /* compact first if base>0 to avoid move after realloc? realloc keeps data; need compact */
            if (f->base > 0) {
                memmove(np, np + f->base, (size_t)(f->len - f->base));
                f->len -= f->base; f->base = 0;
            }
            f->pend = np; f->cap = nc;
        } else if (f->base > 0 && f->len + pl > f->cap) {
            memmove(f->pend, f->pend + f->base, (size_t)(f->len - f->base));
            f->len -= f->base; f->base = 0;
        }
        /* ensure compacted */
        if (f->base > 0 && f->len - f->base + pl <= f->cap) {
            memmove(f->pend, f->pend + f->base, (size_t)(f->len - f->base));
            f->len -= f->base; f->base = 0;
        }
        memcpy(f->pend + f->len, p, (size_t)pl);
        f->len += pl;
    }
    return 0;
}

static void usage(const char *p) {
    fprintf(stderr,
        "Usage: %s [--listen <port>] [--fanout <port|0>] [--acas-sock <p>]\n"
        "              [--token <t>] [-v]\n"
        "\n"
        "  --listen <port>  upstream port (default %d)\n"
        "  --fanout <port>  fanout port (default %d, 0=disable)\n"
        "  --acas-sock <p>  acasd UDS path\n"
        "  --token <t>      required token (default $B61_TOKEN or none=open)\n"
        "  -v               verbose\n"
        "\n"
        "One upstream (1TCP/channel) + N fanout. Decrypt inside, echo back to\n"
        "upstream and broadcast to fanouts. Slow fanouts are cut individually.\n",
        p, B61_NET_DEFAULT_PORT, B61_NET_DEFAULT_FANOUT);
}

int main(int argc, char **argv) {
    int listen_port = B61_NET_DEFAULT_PORT, fanout_port = B61_NET_DEFAULT_FANOUT;
    const char *token = NULL;
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) listen_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--fanout") == 0 && i + 1 < argc) fanout_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--acas-sock") == 0 && i + 1 < argc) g_acas_sock = argv[++i];
        else if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) token = argv[++i];
        else if (strcmp(argv[i], "-v") == 0) g_verbose = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "b61_net_server: unknown arg '%s'\n", argv[i]); usage(argv[0]); return 1; }
    }
    if (!token) { token = getenv("B61_TOKEN"); if (!token) token = "none"; }
    if (!g_acas_sock) {
        const char *e = getenv("B61_ACAS_SOCK");
        if (e && *e) g_acas_sock = e;
        else if (access("/vendor/lib/libstationtv_lt_px_stream.so", F_OK) == 0)
            g_acas_sock = B61_ACAS_SOCK_SMB400;
        else g_acas_sock = B61_ACAS_SOCK_TMP;
    }
    signal(SIGTERM, on_sig); signal(SIGINT, on_sig); signal(SIGPIPE, SIG_IGN);
    if (aes_init() < 0) { fprintf(stderr, "b61_net_server: EVP init failed\n"); return 1; }

    int ls_up = listen_on(listen_port);
    if (ls_up < 0) { fprintf(stderr, "b61_net_server: listen %d failed\n", listen_port); return 1; }
    int ls_fan = -1;
    if (fanout_port > 0) {
        ls_fan = listen_on(fanout_port);
        if (ls_fan < 0) { fprintf(stderr, "b61_net_server: fanout listen %d failed\n", fanout_port); return 1; }
    }
    fprintf(stderr, "b61_net_server: up=%d fanout=%d acas=%s token=%s\n",
            listen_port, fanout_port, g_acas_sock,
            (token && strcmp(token, "none") != 0) ? "set" : "open");

    struct server_state S;
    memset(&S, 0, sizeof(S));
    S.up_fd = -1;
    int k; for (k = 0; k < MAX_FANOUT; k++) S.fan[k].fd = -1;
    S.up_cap = B61_NET_UP_BUF_BYTES;
    S.up_buf = (uint8_t *)malloc((size_t)S.up_cap);
    S.echo_cap = B61_NET_ECHO_PENDING_MAX;
    S.echo_buf = (uint8_t *)malloc((size_t)S.echo_cap);
    if (!S.up_buf || !S.echo_buf) { perror("malloc"); return 1; }
    S.up_len = S.up_base = S.echo_len = S.echo_base = 0;

    while (g_running) {
        /* build poll set */
        struct pollfd pfds[2 + 1 + MAX_FANOUT];
        int nf = 0;
        pfds[nf].fd = ls_up; pfds[nf].events = POLLIN; nf++;
        if (ls_fan >= 0) { pfds[nf].fd = ls_fan; pfds[nf].events = POLLIN; nf++; }
        int up_idx = -1, echo_w = 0;
        if (S.up_fd >= 0) {
            /* read upstream if echo not full (backpressure) */
            int echo_pend = S.echo_len - S.echo_base;
            short ev = 0;
            if (!S.up_eof && echo_pend < B61_NET_ECHO_PENDING_MAX && S.up_len < S.up_cap) ev |= POLLIN;
            if (echo_pend > 0) ev |= POLLOUT;
            /* also POLLIN for EOF detection even if not reading? keep POLLIN when echo full? no, pause */
            pfds[nf].fd = S.up_fd; pfds[nf].events = ev; up_idx = nf; nf++;
            (void)echo_w;
        }
        int fan_idx[MAX_FANOUT];
        for (k = 0; k < MAX_FANOUT; k++) {
            fan_idx[k] = -1;
            if (S.fan[k].fd < 0) continue;
            short ev = POLLOUT;
            /* fanout is send-only; also POLLIN to detect close */
            ev |= POLLIN;
            if (S.fan[k].len - S.fan[k].base <= 0) ev &= ~POLLOUT;
            pfds[nf].fd = S.fan[k].fd; pfds[nf].events = ev; fan_idx[k] = nf; nf++;
        }
        int pr = poll(pfds, (nfds_t)nf, 500);
        if (pr < 0) { if (errno == EINTR) continue; perror("poll"); break; }

        /* accept upstream */
        if (pfds[0].revents & POLLIN) {
            int c = accept(ls_up, NULL, NULL);
            if (c >= 0) {
                char line[B61_NET_LINE_MAX];
                /* handshake uses blocking read (temporarily blocking) */
                int fl = fcntl(c, F_GETFL, 0);
                fcntl(c, F_SETFL, fl & ~O_NONBLOCK);
                int rl = read_line_block(c, line, sizeof(line), B61_NET_HANDSHAKE_TIMEOUT_MS);
                fcntl(c, F_SETFL, fl);
                set_nb(c);
                if (rl < 0 || strncmp(line, B61_NET_VERSION, 5) != 0 ||
                    strstr(line, "TOKEN ") == NULL) {
                    send_all_b(c, B61_NET_VERSION " ERR handshake\n");
                    close(c);
                } else {
                    char tok[B61_NET_TOKEN_MAX + 1]; long svc = 0, sid = 1;
                    parse_hs(line, tok, sizeof(tok), &svc, &sid);
                    if (!token_ok(tok, token)) {
                        fprintf(stderr, "b61_net_server: upstream token mismatch\n");
                        send_all_b(c, B61_NET_VERSION " ERR token\n");
                        close(c);
                    } else if (S.up_fd >= 0) {
                        fprintf(stderr, "b61_net_server: upstream busy, reject\n");
                        send_all_b(c, B61_NET_VERSION " ERR busy\n");
                        close(c);
                    } else {
                        send_all_b(c, B61_NET_VERSION " OK\n");
                        S.up_fd = c;
                        S.up_eof = 0;
                        S.up_svc = svc; S.up_sid = sid;
                        S.sess_start_ms = now_ms();
                        S.prescan_done = 0;
                        S.have_keys = 0;
                        S.up_len = S.up_base = S.echo_len = S.echo_base = 0;
                        memset(S.odd, 0, 16); memset(S.even, 0, 16);
                        fprintf(stderr, "b61_net_server: upstream up (svc=%ld sid=%ld)\n", svc, sid);
                    }
                }
            }
        }
        /* accept fanout */
        if (ls_fan >= 0 && nf > 1 && (pfds[1].revents & POLLIN)) {
            int c = accept(ls_fan, NULL, NULL);
            if (c >= 0) {
                int fl = fcntl(c, F_GETFL, 0);
                fcntl(c, F_SETFL, fl & ~O_NONBLOCK);
                char line[B61_NET_LINE_MAX];
                int rl = read_line_block(c, line, sizeof(line), B61_NET_HANDSHAKE_TIMEOUT_MS);
                fcntl(c, F_SETFL, fl);
                set_nb(c);
                if (rl < 0 || strncmp(line, B61_NET_VERSION, 5) != 0) {
                    send_all_b(c, B61_NET_VERSION " ERR handshake\n");
                    close(c);
                } else {
                    char tok[B61_NET_TOKEN_MAX + 1]; long svc = 0, sid = 1;
                    parse_hs(line, tok, sizeof(tok), &svc, &sid);
                    if (!token_ok(tok, token)) {
                        fprintf(stderr, "b61_net_server: fanout token mismatch\n");
                        send_all_b(c, B61_NET_VERSION " ERR token\n");
                        close(c);
                    } else if (fan_add(&S, c) < 0) {
                        send_all_b(c, B61_NET_VERSION " ERR full\n");
                        close(c);
                    } else {
                        send_all_b(c, B61_NET_VERSION " OK\n");
                        fprintf(stderr, "b61_net_server: fanout up (total svc=%ld)\n", svc);
                    }
                }
            }
        }
        /* upstream read/write */
        if (S.up_fd >= 0 && up_idx >= 0) {
            short rev = pfds[up_idx].revents;
            if (rev & (POLLERR | POLLHUP | POLLNVAL)) {
                fprintf(stderr, "b61_net_server: upstream hup/err\n");
                close(S.up_fd); S.up_fd = -1;
            } else {
                if ((rev & POLLIN) && S.up_len < S.up_cap) {
                    ssize_t n = recv(S.up_fd, S.up_buf + S.up_len,
                                     (size_t)(S.up_cap - S.up_len), 0);
                    if (n < 0) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                            perror("b61_net_server: recv");
                            close(S.up_fd); S.up_fd = -1;
                        }
                    } else if (n == 0) {
                        if (!S.up_eof) {
                            fprintf(stderr, "b61_net_server: upstream EOF, flush\n");
                            S.up_eof = 1;
                            shutdown(S.up_fd, SHUT_RD);
                        }
                        /* process remaining below, then close after echo drained */
                        /* mark EOF by shutdown read side: close after flush */
                        /* process loop will handle; then close */
                        /* Use flag: set up_fd to -2 pending? Simpler: process then close now
                         * after queueing decrypted to echo/fanouts. Echo will be sent
                         * before close? Need to drain echo first. So keep fd open for write.
                         * Implement: shutdown RD, keep WR for echo drain (half-close). */
                        /* fall through to packet processing */
                    } else {
                        S.up_len += (int)n;
                    }
                    /* check EOF via poll? recv==0 handled above; need to detect close:
                     * we shutdown RD, but still need to know when to close fully.
                     * Use ioctl? Simpler: if recv==0, set flag to close after flush. */

                }
                /* packet processing: extract complete TLVs from up_buf */
                {
                    int pos = S.up_base;
                    /* prescan timeout */
                    if (!S.prescan_done && now_ms() - S.sess_start_ms > 10000) {
                        fprintf(stderr, "b61_net_server: prescan timeout, emit without keys\n");
                        S.prescan_done = 1;
                    }
                    while (pos + 4 <= S.up_len) {
                        if (S.up_buf[pos] != B61_TLV_HEADER_BYTE) {
                            int j = pos + 1;
                            while (j < S.up_len && S.up_buf[j] != B61_TLV_HEADER_BYTE) j++;
                            if (j >= S.up_len) break;
                            pos = j; continue;
                        }
                        int dl = (int)b61_u16be(S.up_buf + pos + 2);
                        if (dl > B61_TLV_MAX_DATA) { pos++; continue; }
                        int pl = 4 + dl;
                        if (pos + pl > S.up_len) break;
                        /* copy to temp for decrypt (keep up_buf intact until advance) */
                        /* To avoid extra alloc per packet, decrypt in place in echo copy:
                         * copy packet to echo staging then decrypt there. */
                        const uint8_t *ecm_p = NULL; int ecm_l = 0;
                        /* ECM scan on encrypted copy before decrypt */
                        /* Need temp copy first */
                        uint8_t *tmp = (uint8_t *)malloc((size_t)pl);
                        if (!tmp) break;
                        memcpy(tmp, S.up_buf + pos, (size_t)pl);
                        b61_find_ecm(tmp, pl, &ecm_p, &ecm_l);
                        /* Prescan: buffer without emitting until first ECM.
                         * up_baseは進めない (先頭欠落防止)。バッファ全体を走査し、
                         * ECMがあれば解決して先頭から放出、なければ待つ。 */
                        if (!S.prescan_done) {
                            free(tmp);
                            int scan = S.up_base;
                            const uint8_t *f_ecm = NULL; int f_len = 0;
                            while (scan + 4 <= S.up_len) {
                                if (S.up_buf[scan] != B61_TLV_HEADER_BYTE) { scan++; continue; }
                                int sdl = (int)b61_u16be(S.up_buf + scan + 2);
                                if (sdl > B61_TLV_MAX_DATA) { scan++; continue; }
                                int spl = 4 + sdl;
                                if (scan + spl > S.up_len) break;
                                const uint8_t *se = NULL; int sl = 0;
                                b61_find_ecm(S.up_buf + scan, spl, &se, &sl);
                                if (se && sl >= 0x1b) { f_ecm = se; f_len = sl; break; }
                                scan += spl;
                            }
                            if (f_ecm) {
                                uint8_t ecm_copy[B61_ACAS_ECM_MAX];
                                int cplen = f_len > (int)sizeof(ecm_copy) ? (int)sizeof(ecm_copy) : f_len;
                                memcpy(ecm_copy, f_ecm, (size_t)cplen);
                                uint8_t no[16], ne[16];
                                g_ecm++;
                                if (resolve_ecm(ecm_copy, f_len, no, ne) == 0) {
                                    memcpy(S.odd, no, 16); memcpy(S.even, ne, 16);
                                    memset(no, 0, 16); memset(ne, 0, 16);
                                    S.have_keys = 1;
                                    S.prescan_done = 1;
                                    fprintf(stderr, "b61_net_server: prescan ECM ok, emit from start\n");
                                    pos = S.up_base;
                                    continue;
                                }
                                pos = S.up_base;
                                break;
                            }
                            if (S.up_len - S.up_base >= 8 * 1024 * 1024) {
                                fprintf(stderr, "b61_net_server: prescan full, emit without keys\n");
                                S.prescan_done = 1;
                                pos = S.up_base;
                                continue;
                            }
                            pos = S.up_base;
                            break;
                        }
                        /* normal: ECM update if present on non-decrypted packets */
                        /* decrypt temp */
                        int dec = decrypt_pkt(tmp, pl,
                                              S.have_keys ? S.odd : NULL,
                                              S.have_keys ? S.even : NULL);
                        (void)dec;
                        if (!dec) {
                            /* re-scan ECM (decrypt_pkt counted scr; if not decrypted, maybe ECM) */
                            const uint8_t *ep2 = NULL; int el2 = 0;
                            b61_find_ecm(tmp, pl, &ep2, &el2);
                            if (ep2 && el2 >= 0x1b) {
                                uint8_t no[16], ne[16];
                                /* local dedup via sc_lookup inside resolve */
                                uint8_t co[16], ce[16];
                                if (!sc_lookup(ep2, el2, g_ep_seen, co, ce)) {
                                    g_ecm++;
                                    if (resolve_ecm(ep2, el2, no, ne) == 0) {
                                        memcpy(S.odd, no, 16); memcpy(S.even, ne, 16);
                                        memset(no, 0, 16); memset(ne, 0, 16);
                                        S.have_keys = 1;
                                        /* retry decrypt with new keys */
                                        memcpy(tmp, S.up_buf + pos, (size_t)pl);
                                        decrypt_pkt(tmp, pl, S.odd, S.even);
                                    }
                                } else {
                                    memcpy(S.odd, co, 16); memcpy(S.even, ce, 16);
                                    S.have_keys = 1;
                                }
                            }
                        }
                        S.n_up_pkt++;
                        /* queue to echo (bounded) */
                        {
                            int pend = S.echo_len - S.echo_base;
                            if (pend + pl > B61_NET_ECHO_PENDING_MAX) {
                                /* backpressure: stop processing, wait drain */
                                free(tmp);
                                break;
                            }
                            if (S.echo_len + pl > S.echo_cap) {
                                /* compact */
                                if (S.echo_base > 0) {
                                    memmove(S.echo_buf, S.echo_buf + S.echo_base,
                                            (size_t)(S.echo_len - S.echo_base));
                                    S.echo_len -= S.echo_base; S.echo_base = 0;
                                }
                            }
                            if (S.echo_len + pl > S.echo_cap) {
                                free(tmp);
                                break;
                            }
                            memcpy(S.echo_buf + S.echo_len, tmp, (size_t)pl);
                            S.echo_len += pl;
                        }
                        fan_queue(&S, tmp, pl);
                        free(tmp);
                        pos += pl;
                    }
                    S.up_base = pos;
                    if (S.up_base > 0) {
                        if (S.up_base < S.up_len)
                            memmove(S.up_buf, S.up_buf + S.up_base,
                                    (size_t)(S.up_len - S.up_base));
                        S.up_len -= S.up_base; S.up_base = 0;
                    }
                    /* detect upstream EOF that was shutdown: if RD shutdown and no more
                     * incoming, we need to know peer closed. poll will keep signalling?
                     * Instead check: if shutdown RD done, try recv 0? Use MSG_PEEK:
                     * if peer sent FIN, recv returns 0. We already consumed FIN.
                     * After flush, if up_len==0, close upstream after echo drained.
                     * Track via flag: if shutdown RD and up_len==0, drain echo then close. */
                }
                /* echo send */
                {
                    int pend = S.echo_len - S.echo_base;
                    if (pend > 0 && (rev & POLLOUT)) {
                        int n = send_nb(S.up_fd, S.echo_buf + S.echo_base, pend);
                        if (n < 0) {
                            fprintf(stderr, "b61_net_server: echo send err, close upstream\n");
                            close(S.up_fd); S.up_fd = -1;
                            S.echo_len = S.echo_base = 0;
                        } else if (n > 0) {
                            S.echo_base += n;
                            if (S.echo_base == S.echo_len) S.echo_len = S.echo_base = 0;
                            else if (S.echo_base > S.echo_cap / 2) {
                                memmove(S.echo_buf, S.echo_buf + S.echo_base,
                                        (size_t)(S.echo_len - S.echo_base));
                                S.echo_len -= S.echo_base; S.echo_base = 0;
                            }
                        }
                    }
                }
                /* If upstream RD shutdown (EOF) and buffer empty and echo empty -> close.
                 * Detect RD shutdown by peeking: recv MSG_PEEK returns 0 if FIN received
                 * and all data consumed. */
                if (S.up_fd >= 0 && S.up_len == 0) {
                    char tmpc;
                    ssize_t pn = recv(S.up_fd, &tmpc, 1, MSG_PEEK | MSG_DONTWAIT);
                    if (pn == 0) {
                        /* peer EOF and all data processed; drain echo blocking then close */
                        int pend = S.echo_len - S.echo_base;
                        long long dl = now_ms() + 5000;
                        while (pend > 0 && now_ms() < dl) {
                            int n = send_nb(S.up_fd, S.echo_buf + S.echo_base, pend);
                            if (n < 0) break;
                            if (n == 0) { struct pollfd p; p.fd = S.up_fd; p.events = POLLOUT; poll(&p, 1, 200); continue; }
                            S.echo_base += n;
                            pend = S.echo_len - S.echo_base;
                        }
                        fprintf(stderr, "b61_net_server: upstream closed (up_pkt=%ld dec=%ld ecm=%ld)\n",
                                S.n_up_pkt, g_dec, g_ecm);
                        shutdown(S.up_fd, SHUT_WR);
                        close(S.up_fd); S.up_fd = -1;
                        S.echo_len = S.echo_base = 0;
                        S.n_up_pkt = 0;
                        /* keep fanouts for next session */
                    } else if (pn < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                        close(S.up_fd); S.up_fd = -1;
                    }
                }
            }
        }
        /* fanout sends + close detection */
        for (k = 0; k < MAX_FANOUT; k++) {
            if (S.fan[k].fd < 0 || fan_idx[k] < 0) continue;
            short rev = pfds[fan_idx[k]].revents;
            if (rev & (POLLERR | POLLHUP | POLLNVAL)) {
                fan_remove(&S, k);
                continue;
            }
            if (rev & POLLIN) {
                /* viewer should not send; if data or FIN, check */
                char t[64];
                ssize_t n = recv(S.fan[k].fd, t, sizeof(t), MSG_DONTWAIT);
                if (n == 0) { fan_remove(&S, k); continue; }
                /* ignore data */
            }
            int pend = S.fan[k].len - S.fan[k].base;
            if (pend > 0 && (rev & POLLOUT)) {
                int n = send_nb(S.fan[k].fd, S.fan[k].pend + S.fan[k].base, pend);
                if (n < 0) {
                    fprintf(stderr, "b61_net_server: fanout[%d] err, cut\n", k);
                    fan_remove(&S, k);
                } else if (n > 0) {
                    S.fan[k].base += n;
                    S.fan[k].last_ok = now_ms();
                    if (S.fan[k].base == S.fan[k].len) S.fan[k].len = S.fan[k].base = 0;
                } else {
                    if (now_ms() - S.fan[k].last_ok > B61_NET_SEND_TIMEOUT_MS && pend > 0) {
                        fprintf(stderr, "b61_net_server: fanout[%d] timeout, cut\n", k);
                        fan_remove(&S, k);
                    }
                }
            }
        }
    }

    if (S.up_fd >= 0) close(S.up_fd);
    for (k = 0; k < MAX_FANOUT; k++) if (S.fan[k].fd >= 0) fan_remove(&S, k);
    close(ls_up); if (ls_fan >= 0) close(ls_fan);
    free(S.up_buf); free(S.echo_buf);
    memset(S.odd, 0, 16); memset(S.even, 0, 16);
    if (g_ctx_odd) EVP_CIPHER_CTX_free(g_ctx_odd);
    if (g_ctx_even) EVP_CIPHER_CTX_free(g_ctx_even);
    fprintf(stderr, "b61_net_server: exit\n");
    return 0;
}
