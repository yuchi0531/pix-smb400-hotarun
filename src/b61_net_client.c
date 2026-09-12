/*
 * b61_net_client.c — 他サーバ側 network client (単体完結・Mirakurun decoder可).
 *
 * 使い方:
 *   recpt1 --channel XXX | b61_net_client --host SMB400 --channel XXX | 出力
 *   b61_net_client --host SMB400 --channel XXX < encrypted.tlv > decrypted.tlv
 *   b61_net_client < encrypted.tlv > decrypted.tlv   (既定 host=127.0.0.1:40773)
 *
 * Mirakurun decoder用法 (tuners.yml):
 *   command: <暗号化raw TLVを出すチューナー>
 *   decoder: b61_net_client --host <SMB400_IP> --channel <SID>
 *   Mirakurunが tuner stdout→decoder stdin→decoder stdout→配信 とパイプする。
 *   引数なしでも動く (既定 s=0,i=1,m=0, host=127.0.0.1:40773, token=none)。
 *   decoderは引数なし=全service素通し (s=0) のためチャネル固定不要。
 *
 * stdin=暗号化raw TLV -> (内蔵select-filter) -> TCP -> SMB400 -> TCP復号済みTLV
 * -> stdout. 順序はTCPに委譲、TLV境界はパケット単位転送で保持、
 * stdout純粋・ログstderr。既存 b61_select_filter と同一規則を内蔵し、
 * 重複実装ではなく b61_tlv.h のみ再利用する (外部filterを前置しても可)。
 * 送信は必要分のみ: 対象service MPU + ECM + NTP/TLV-SI/CAT/PLT/MPT等の
 * 必要MMT-SI。チャネル単位×1TCP (複数チャネルは複数プロセス)。
 *
 * 有界キュー背圧: ユーザ空間1MB + blocking send (相手が遅ければstdin側がblock)。
 * stdin EOFで SHUT_WR し、復号残を読み切って stdout EOF→exit 0 (互換IF)。
 *
 * 環境変数 (CLIが優先, 未指定時は環境→既定値):
 *   B61_HOST  server host (既定 127.0.0.1)
 *   B61_PORT  server port (既定 40773)
 *   B61_TOKEN auth token (既定 "none"=open試験用)
 *
 * 終了コード規約:
 *   0   正常 (stdin EOF→残出力→終了)
 *   1   異常 (接続失敗/ハンドシェイク拒否/Token不一致/送受信エラー/
 *       サーバ切断/下流write失敗/不正引数。自動再接続なし)
 *   143 SIGTERM受信で速やかに終了 (child kill+reap, ゾンビ残さない)
 *   130 SIGINT受信で速やかに終了 (同上)
 * SIGPIPEは無視し EPIPEエラーとして終了1 (stdout closeで速やかに終了)。
 *
 * Tokenは平文ハンドシェイク (TLS/WireGuardは外側で終端する想定):
 *   C: "B61/1 TOKEN <tok> SERVICE <s> SID <i>\n"
 *   S: "B61/1 OK\n" / "B61/1 ERR ...\n"
 * Token不一致は ERR で終了1。鍵素材はログに出さない。
 *
 * -s/-i/-m/-v は arib-b61-stream-test 互換 (既定 s=0,i=1,m=0)。
 * --channel は -s の別名 (service id 数値)。EMMは既定OFF (-m 0で落とす)。
 *
 * シグナル・切断・再接続:
 *  - MirakurunからのSIGTERM/SIGINTは親が子へ転送し両系速やかに終了する。
 *    親はstdinを500ms pollで監視し子死亡・シグナルを検出するためblockしない。
 *    終了時は必ずwaitpidでreapしゾンビを残さない。
 *  - 接続失敗/ハンドシェイク拒否/送受信エラー/サーバ切断は exit 1 (自動再接続なし)。
 *    再接続は上位 (Mirakurun/recpt1リトライ/EPGStation/シェルループ) に委譲する。
 *  - 下流30秒無受信は stderr に idle ログのみ出し待機を継続する (切断しない)。
 *  - サーバ側の振る舞い: 単一upstream (2つ目はBUSY拒否)、echo 8MB超過で
 *    upstream読取を一時停止 (dropなし)、fanout遅延は当該のみ個別切断。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "b61_tlv.h"
#include "b61_net.h"

#define CLI_BUFSZ (1 * 1024 * 1024)

/* Mirakurun decoder対応: SIGTERM/SIGINTでゾンビ化せず速やかに終了するため、
 * 親は500ms pollでstdinを監視しつつ子死亡・シグナルを検出する。 */
static int g_verbose = 0;
static volatile sig_atomic_t g_term_sig = 0;
static volatile pid_t g_child_pid = 0;
static int g_child_reaped = 0;
static int g_child_rc = 1;

static void on_term(int sig) {
    g_term_sig = sig;
    pid_t c = g_child_pid;
    if (c > 0) kill(c, SIGTERM);
}

static void usage(const char *p) {
    fprintf(stderr,
        "Usage: %s [-s <service>] [-i <sid>] [-m <0|1>] [-v]\n"
        "              [--host <h>] [--port <n>] [--token <t>] [--channel <id>]\n"
        "\n"
        "  -s <id>      service id for select+handshake (default 0 = all)\n"
        "  --channel <id>  alias of -s (e.g. --channel 100)\n"
        "  -i <id>      session id for handshake (default 1)\n"
        "  -m <0|1>     EMM handling: 0=drop (default), 1=keep\n"
        "  -v           verbose to stderr\n"
        "  --host <h>   server host (default $B61_HOST or 127.0.0.1)\n"
        "  --port <n>   server upstream port (default $B61_PORT or %d)\n"
        "  --token <t>  auth token (default $B61_TOKEN or \"none\")\n"
        "\n"
        "Reads encrypted raw TLV from stdin, selects target service MPU +\n"
        "ECM + necessary MMT-SI (order/TLV boundaries kept), sends over one\n"
        "TCP per channel, writes decrypted TLV from server to stdout.\n"
        "Full-duplex echo. No auto-reconnect (exit 1 on error; retry upstream).\n"
        "No args also works (defaults above). Logs to stderr only; stdout is\n"
        "pure TLV. On stdin EOF, SHUT_WR then drain remainder and exit 0.\n"
        "On SIGTERM/SIGINT, forward to child, reap, and exit 128+sig promptly.\n"
        "Exit codes: 0=EOF ok, 1=error/token-mismatch, 143=SIGTERM, 130=SIGINT.\n"
        "Mirakurun tuners.yml example (decoder pipes tuner stdout):\n"
        "  command: <encrypted-raw-TLV tuner>\n"
        "  decoder: b61_net_client --host <SMB400_IP> --channel 100\n"
        "Examples:\n"
        "  recpt1 --channel 100 | %s --host SMB400 --channel 100 | arib-mmt-decode\n"
        "  %s --host SMB400 --channel 100 < encrypted.tlv > decrypted.tlv\n"
        "  B61_HOST=SMB400 B61_TOKEN=xxx %s --channel 100 < enc.tlv > dec.tlv\n",
        p, B61_NET_DEFAULT_PORT, p, p, p);
}

static long parse_service_id(const char *s) {
    char *end = NULL;
    long v = strtol(s, &end, 0);
    if (!end || *end != '\0' || v < 0 || v > 0xFFFF) {
        fprintf(stderr, "b61_net_client: invalid service/channel id '%s'\n", s);
        exit(1);
    }
    return v;
}

static int send_all(int fd, const uint8_t *p, int len) {
    int off = 0;
    while (off < len) {
        ssize_t n = send(fd, p + off, (size_t)(len - off), 0);
        if (n < 0) {
            if (errno == EINTR) {
                if (g_term_sig) return -1;
                continue;
            }
            return -1;
        }
        if (n == 0) return -1;
        off += (int)n;
    }
    return 0;
}

/* Read a line (up to max-1 chars) with timeout. Returns len or -1. */
static int read_line_timeout(int fd, char *out, int max, int timeout_ms) {
    int pos = 0;
    while (pos + 1 < max) {
        struct pollfd pfd;
        pfd.fd = fd; pfd.events = POLLIN;
        int pr = poll(&pfd, 1, timeout_ms);
        if (pr <= 0) return -1;
        char c;
        ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0) return -1;
        out[pos++] = c;
        if (c == '\n') break;
    }
    out[pos] = '\0';
    return pos;
}

static int tcp_connect(const char *host, int port) {
    struct addrinfo hints, *res = NULL, *rp;
    char ps[16];
    snprintf(ps, sizeof(ps), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, ps, &hints, &res) != 0) return -1;
    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* Forward stdin -> sock with in-client select-filter, packet-aligned.
 * Same selection as b61_select_filter (b61_tlv.h reuse):
 *  - NTP/TLV-SI/CAT/PLT/MPT/ECM always kept, only scrambled MPU filtered by
 *    service (0=all), EMM dropped unless emm_keep. Order/boundaries kept.
 * On EOF, caller does SHUT_WR. Returns 0 ok, 1 error, 128+sig on signal.
 * Mirakurun対応: stdinを500ms pollで待ち、SIGTERM/SIGINTと子死亡を検出して
 * blockせず速やかに終了する (ゾンビ防止)。 */
static int pump_up(int sock, long service, int emm_keep, pid_t child) {
    uint8_t *buf = (uint8_t *)malloc(CLI_BUFSZ);
    if (!buf) return 1;
    int len = 0, base = 0, eof = 0;
    long n_in = 0, n_out = 0, n_drop_mpu = 0, n_drop_emm = 0;
    long n_scrambled = 0, n_ecm = 0;
    int rc = 0;
    while (!eof || base < len) {
        if (g_term_sig) {
            fprintf(stderr, "b61_net_client: terminated by signal %d\n",
                    (int)g_term_sig);
            rc = 128 + (int)g_term_sig;
            break;
        }
        if (child > 0 && !g_child_reaped) {
            int st = 0;
            pid_t w = waitpid(child, &st, WNOHANG);
            if (w == child) {
                g_child_reaped = 1;
                g_child_rc = WIFEXITED(st) ? WEXITSTATUS(st) : 1;
                fprintf(stderr,
                    "b61_net_client: downstream exited early rc=%d\n",
                    g_child_rc);
                /* 下流が先に死んだら上流送信は無意味。残がなく子が正常でも
                 * SHUT_WR前の早期終了は異常として扱い速やかに抜ける。 */
                if (!(eof && base >= len && g_child_rc == 0))
                    rc = 1;
                break;
            }
        }
        if (!eof && len < CLI_BUFSZ) {
            struct pollfd pfd;
            pfd.fd = STDIN_FILENO; pfd.events = POLLIN;
            int pr = poll(&pfd, 1, 500);
            if (pr < 0) {
                if (errno == EINTR) continue;
                perror("b61_net_client: poll stdin");
                rc = 1; break;
            }
            if (pr == 0) {
                /* timeout: バッファ済み分を下で処理するため抜けない */
            } else if (pfd.revents & (POLLERR | POLLNVAL)) {
                fprintf(stderr, "b61_net_client: stdin poll error\n");
                rc = 1; break;
            } else if (pfd.revents & POLLIN) {
                ssize_t n = read(STDIN_FILENO, buf + len, (size_t)(CLI_BUFSZ - len));
                if (n < 0) {
                    if (errno == EINTR) continue;
                    perror("b61_net_client: read stdin");
                    rc = 1; break;
                }
                if (n == 0) eof = 1;
                else len += (int)n;
            } else if (pfd.revents & POLLHUP) {
                eof = 1;
            } else {
                /* 処理すべき入力なし: バッファ済み分を下で処理 */
            }
        }
        int pos = base;
        int progressed = 0;
        while (pos + 4 <= len) {
            if (buf[pos] != B61_TLV_HEADER_BYTE) {
                int j = pos + 1;
                while (j < len && buf[j] != B61_TLV_HEADER_BYTE) j++;
                if (j >= len) break;
                pos = j;
                continue;
            }
            int dl = (int)b61_u16be(buf + pos + 2);
            if (dl > B61_TLV_MAX_DATA) { pos++; continue; }
            int pl = 4 + dl;
            if (pos + pl > len) break;
            const uint8_t *pkt = buf + pos;
            uint8_t tlv_type = pkt[1];
            n_in++;
            int keep = 1;
            const char *reason = "pass";
            if (!emm_keep && b61_contains_emm(pkt, pl)) {
                keep = 0; reason = "drop-emm";
                n_drop_emm++;
            } else if (tlv_type == B61_TLV_TYPE_NULL) {
                keep = 1; reason = "keep-null";
            } else if (tlv_type != B61_TLV_TYPE_HC) {
                keep = 1; reason = "keep-signal";
                const uint8_t *ep = NULL; int el = 0;
                b61_find_ecm(pkt, pl, &ep, &el);
                if (ep) { n_ecm++; reason = "keep-ecm"; }
            } else {
                const uint8_t *ep = NULL; int el = 0;
                b61_find_ecm(pkt, pl, &ep, &el);
                if (ep) {
                    n_ecm++;
                    keep = 1; reason = "keep-ecm";
                } else {
                    uint16_t pid = 0;
                    int scr = b61_is_scrambled_mpu(pkt, pl, &pid);
                    if (!scr) {
                        keep = 1; reason = "keep-hc-signal";
                    } else {
                        n_scrambled++;
                        if (service == 0) {
                            keep = 1; reason = "keep-mpu-all";
                        } else if (pid == (uint16_t)(service & 0xFFFF)) {
                            keep = 1; reason = "keep-mpu-hit";
                        } else {
                            keep = 0; reason = "drop-mpu";
                            n_drop_mpu++;
                        }
                    }
                }
            }
            if (g_verbose)
                fprintf(stderr, "b61_net_client: tlv=0x%02X len=%d %s\n",
                        tlv_type, pl, reason);
            if (keep) {
                if (send_all(sock, pkt, pl) < 0) {
                    if (g_verbose) perror("b61_net_client: send");
                    else fprintf(stderr, "b61_net_client: send failed\n");
                    rc = 1; goto out;
                }
                n_out++;
            }
            pos += pl;
            progressed = 1;
        }
        base = pos;
        if (base > 0) {
            if (base < len) memmove(buf, buf + base, (size_t)(len - base));
            len -= base; base = 0;
        }
        if (!eof && len == CLI_BUFSZ && !progressed) {
            memmove(buf, buf + 1, (size_t)(len - 1));
            len--;
        }
        if (eof) {
            if (len - base > 0) {
                int pl = b61_tlv_pkt_len(buf + base, len - base);
                if (pl < 0 || base + pl > len) {
                    fprintf(stderr,
                        "b61_net_client: drop %d trailing byte(s) at EOF\n",
                        len - base);
                    break;
                }
                if (!progressed) break;
            } else break;
        }
        if (eof && len == 0) break;
    }
out:
    free(buf);
    fprintf(stderr,
        "b61_net_client: upstream done in=%ld out=%ld ecm=%ld scrambled=%ld "
        "drop_mpu=%ld drop_emm=%ld rc=%d\n",
        n_in, n_out, n_ecm, n_scrambled, n_drop_mpu, n_drop_emm, rc);
    if (n_scrambled == 0 && n_ecm == 0 && n_in > 0)
        fprintf(stderr,
            "b61_net_client: WARNING: no scrambled MPU/ECM seen "
            "(input may already be decrypted)\n");
    if (service != 0 && n_scrambled > 0 && n_ecm == 0)
        fprintf(stderr,
            "b61_net_client: WARNING: scrambled MPU without ECM "
            "(ECM must be kept; decrypt would fail)\n");
    return rc;
}

/* Forward sock -> stdout, packet-aligned. Returns 0 ok. */
static int pump_down(int sock) {
    uint8_t *buf = (uint8_t *)malloc(CLI_BUFSZ);
    if (!buf) return 1;
    int len = 0, base = 0;
    long n_pkt = 0;
    int rc = 0;
    while (1) {
        if (len < CLI_BUFSZ) {
            struct pollfd pfd;
            pfd.fd = sock; pfd.events = POLLIN;
            int pr = poll(&pfd, 1, 30000);
            if (pr < 0) {
                if (errno == EINTR) continue;
                perror("b61_net_client: poll");
                rc = 1; break;
            }
            if (pr == 0) {
                fprintf(stderr, "b61_net_client: downstream idle 30s\n");
                continue;
            }
            ssize_t n = recv(sock, buf + len, (size_t)(CLI_BUFSZ - len), 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                perror("b61_net_client: recv");
                rc = 1; break;
            }
            if (n == 0) break; /* server close = EOF */
            len += (int)n;
        }
        int pos = base;
        int progressed = 0;
        while (pos + 4 <= len) {
            if (buf[pos] != B61_TLV_HEADER_BYTE) {
                int j = pos + 1;
                while (j < len && buf[j] != B61_TLV_HEADER_BYTE) j++;
                if (j >= len) break;
                pos = j;
                continue;
            }
            int dl = (int)b61_u16be(buf + pos + 2);
            if (dl > B61_TLV_MAX_DATA) { pos++; continue; }
            int pl = 4 + dl;
            if (pos + pl > len) break;
            if (b61_write_all(STDOUT_FILENO, buf + pos, pl) < 0) {
                perror("b61_net_client: write stdout");
                rc = 1; goto out;
            }
            n_pkt++;
            pos += pl;
            progressed = 1;
        }
        base = pos;
        if (base > 0) {
            if (base < len) memmove(buf, buf + base, (size_t)(len - base));
            len -= base; base = 0;
        }
        if (len == CLI_BUFSZ && !progressed) {
            memmove(buf, buf + 1, (size_t)(len - 1));
            len--;
        }
    }
    /* Flush trailing? Incomplete tail is dropped (log) */
    if (len - base > 0)
        fprintf(stderr, "b61_net_client: drop %d trailing byte(s) at close\n",
                len - base);
out:
    free(buf);
    if (g_verbose) fprintf(stderr, "b61_net_client: downstream done pkt=%ld rc=%d\n", n_pkt, rc);
    return rc;
}

int main(int argc, char **argv) {
    long service = 0, sess = 1;
    int emm_keep = 0;
    const char *host = NULL;
    const char *host_cli = NULL;
    int port = -1;
    int port_cli = -1;
    const char *token = NULL;
    const char *token_cli = NULL;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) service = parse_service_id(argv[++i]);
        else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) sess = strtol(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) emm_keep = atoi(argv[++i]) ? 1 : 0;
        else if (strcmp(argv[i], "-v") == 0) g_verbose = 1;
        else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) host_cli = argv[++i];
        else if (strncmp(argv[i], "--host=", 7) == 0) host_cli = argv[i] + 7;
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port_cli = atoi(argv[++i]);
        else if (strncmp(argv[i], "--port=", 7) == 0) port_cli = atoi(argv[i] + 7);
        else if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) token_cli = argv[++i];
        else if (strncmp(argv[i], "--token=", 8) == 0) token_cli = argv[i] + 8;
        else if (strcmp(argv[i], "--channel") == 0 && i + 1 < argc) service = parse_service_id(argv[++i]);
        else if (strncmp(argv[i], "--channel=", 10) == 0) service = parse_service_id(argv[i] + 10);
        else if (strcmp(argv[i], "--service") == 0 && i + 1 < argc) service = parse_service_id(argv[++i]);
        else if (strncmp(argv[i], "--service=", 10) == 0) service = parse_service_id(argv[i] + 10);
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "b61_net_client: unknown arg '%s'\n", argv[i]); usage(argv[0]); return 1; }
    }
    /* 優先度: CLI > 環境変数 > 既定値。引数なしでも動く。 */
    if (host_cli && *host_cli) host = host_cli;
    else {
        const char *e = getenv("B61_HOST");
        host = (e && *e) ? e : "127.0.0.1";
    }
    if (port_cli > 0) port = port_cli;
    else {
        const char *e = getenv("B61_PORT");
        port = (e && *e) ? atoi(e) : B61_NET_DEFAULT_PORT;
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "b61_net_client: invalid port '%s'\n", e);
            return 1;
        }
    }
    if (token_cli && *token_cli) token = token_cli;
    else {
        token = getenv("B61_TOKEN");
        if (!token || !*token) token = "none";
    }
    if ((int)strlen(token) > B61_NET_TOKEN_MAX) {
        fprintf(stderr, "b61_net_client: token too long\n");
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = on_term;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0; /* no SA_RESTART: poll/readをEINTRで起こし速やかに終了 */
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGINT, &sa, NULL);
    }

    int sock = tcp_connect(host, port);
    if (sock < 0) {
        fprintf(stderr, "b61_net_client: connect %s:%d failed: %s\n",
                host, port, strerror(errno));
        return 1;
    }
    fprintf(stderr, "b61_net_client: connected %s:%d (service=%ld sid=%ld emm=%s)\n",
            host, port, service, sess, emm_keep ? "keep" : "drop");

    char line[B61_NET_LINE_MAX];
    snprintf(line, sizeof(line), "%s TOKEN %s SERVICE %ld SID %ld\n",
             B61_NET_VERSION, token, service, sess);
    if (send_all(sock, (uint8_t *)line, (int)strlen(line)) < 0) {
        fprintf(stderr, "b61_net_client: handshake send failed\n");
        close(sock);
        return 1;
    }
    char resp[B61_NET_LINE_MAX];
    if (read_line_timeout(sock, resp, sizeof(resp), B61_NET_HANDSHAKE_TIMEOUT_MS) < 0) {
        fprintf(stderr, "b61_net_client: handshake reply timeout\n");
        close(sock);
        return 1;
    }
    if (strncmp(resp, B61_NET_VERSION " OK", 7) != 0) {
        fprintf(stderr, "b61_net_client: handshake rejected: %s", resp);
        close(sock);
        return 1;
    }
    fprintf(stderr, "b61_net_client: handshake OK\n");

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); close(sock); return 1; }
    if (pid == 0) {
        /* Child: sock -> stdout. SIGTERM/SIGINTは即時終了 (Mirakurun対応)。
         * 親の転送ハンドラは不要のため既定に戻し、SIGPIPEのみ無視継続。 */
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        g_child_pid = 0;
        int rc = pump_down(sock);
        /* _exit to avoid flushing parent stdio */
        _exit(rc);
    }
    /* Parent: stdin -> sock (with select-filter) */
    g_child_pid = pid;
    g_child_reaped = 0;
    g_child_rc = 1;
    int rc_up = pump_up(sock, service, emm_keep, pid);
    if (g_term_sig) {
        /* シグナル受信: 子へは既にSIGTERM転送済み。SHUT_WRしてreapし128+sigで終了。 */
        shutdown(sock, SHUT_WR);
        int st = 0;
        if (!g_child_reaped) {
            while (waitpid(pid, &st, 0) < 0 && errno == EINTR) { }
            if (WIFEXITED(st)) g_child_rc = WEXITSTATUS(st);
            else g_child_rc = 1;
            g_child_reaped = 1;
        }
        close(sock);
        int sigrc = 128 + (int)g_term_sig;
        fprintf(stderr, "b61_net_client: terminated by signal %d (up=%d down=%d)\n",
                (int)g_term_sig, rc_up, g_child_rc);
        return sigrc;
    }
    shutdown(sock, SHUT_WR);
    int st = 0;
    int rc_down;
    if (g_child_reaped) {
        rc_down = g_child_rc;
    } else {
        while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
            if (g_term_sig) {
                kill(pid, SIGTERM);
                continue;
            }
        }
        rc_down = (WIFEXITED(st) ? WEXITSTATUS(st) : 1);
        g_child_reaped = 1;
        g_child_rc = rc_down;
        if (g_term_sig) {
            close(sock);
            int sigrc = 128 + (int)g_term_sig;
            fprintf(stderr, "b61_net_client: terminated by signal %d (up=%d down=%d)\n",
                    (int)g_term_sig, rc_up, rc_down);
            return sigrc;
        }
    }
    close(sock);
    /* pump_upが128+sigを返したらシグナル終了としてそのまま返す (ゾンビなし)。 */
    if (rc_up >= 128) {
        fprintf(stderr, "b61_net_client: done up=%d down=%d\n", rc_up, rc_down);
        return rc_up;
    }
    fprintf(stderr, "b61_net_client: done up=%d down=%d\n", rc_up, rc_down);
    return (rc_up == 0 && rc_down == 0) ? 0 : 1;
}
