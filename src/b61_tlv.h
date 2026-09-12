/*
 * b61_tlv.h — TLV/MMTP shared helpers (host + SMB400).
 *
 * b61dec.c の TLV/ECM/復号判定 (lines 362-502 相当) から SCI/ACAS・復号実行を
 * 除いた纯粋なフレーミング/分類のみを切り出したもの。b61dec.c 自体は不変。
 * 秘密鍵・KCL・Ks は扱わない。ECM 実データも扱わない (パターン検出のみ)。
 *
 * TLV packet: [0]=0x7F [1]=type [2..3]=BE data_len + data_len bytes.
 *   total = 4 + data_len.  data_len <= 65535.
 */
#ifndef B61_TLV_H
#define B61_TLV_H

#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define B61_TLV_HEADER_BYTE  0x7FU
#define B61_TLV_TYPE_HC      0x03U   /* HeaderCompressed (MMT/IP) */
#define B61_TLV_TYPE_NULL    0xFFU   /* Null (keepalive) */
#define B61_TLV_MAX_DATA     65535
#define B61_TLV_MAX_PKT      (4 + 65535)

#define B61_HC_NO_COMP       0x61U
#define B61_HC_PART_V6       0x60U

/* MMTP offsets (no packet counter, same as b61dec.c) */
#define B61_MMTP_OFF_FLAGS   0x00
#define B61_MMTP_OFF_TYPE    0x01
#define B61_MMTP_OFF_PKT_ID  0x02
#define B61_MMTP_OFF_SEQ     0x08
#define B61_MMTP_OFF_EXT_L   0x0E
#define B61_MMTP_OFF_MEXT_T  0x10
#define B61_MMTP_OFF_ENC     0x14

/* ECM header pattern (broadcast, not secret) */
static const uint8_t B61_ECM_HDR[6] = { 0x00, 0x00, 0x93, 0x2D, 0x1E, 0x01 };
/* EMM heuristic prefix (broadcast CA message family,暂定). TLV select-filter
 * が EMM既定OFF (-m 0) で落とす判定に使う。実運用で誤判定があれば見直す。 */
static const uint8_t B61_EMM_PREFIX[4] = { 0x00, 0x00, 0x93, 0x2E };

#define B61_ENC_NONE  0
#define B61_ENC_EVEN  2
#define B61_ENC_ODD   3

static inline uint16_t b61_u16be(const uint8_t *b) {
    return (uint16_t)(((uint16_t)b[0] << 8) | b[1]);
}

/* TLV packet length from header (need >=4 bytes). Returns -1 if invalid. */
static inline int b61_tlv_pkt_len(const uint8_t *p, int avail) {
    if (avail < 4) return -1;
    if (p[0] != B61_TLV_HEADER_BYTE) return -1;
    int dl = (int)b61_u16be(p + 2);
    return 4 + dl;
}

/* Byte search for ECM header inside one TLV packet.
 * On success sets ecm_out and ecm_len (data starts 2B into pattern, max 148B). */
static inline void b61_find_ecm(const uint8_t *tlv, int len,
                                const uint8_t **ecm_out, int *ecm_len) {
    *ecm_out = NULL;
    *ecm_len = 0;
    int data_len = len - 4;
    if (data_len < 8) return;
    int i;
    for (i = 0; i < data_len - 5; i++) {
        if (memcmp(tlv + 4 + i, B61_ECM_HDR, 6) == 0) {
            const uint8_t *p = tlv + 4 + i + 2;
            int remain = data_len - i - 2;
            if (remain > 148) remain = 148;
            if (remain < 0x1b) return;
            *ecm_out = p;
            *ecm_len = remain;
            return;
        }
    }
}

/* Heuristic EMM detection inside one TLV packet (for -m 0 drop). */
static inline int b61_contains_emm(const uint8_t *tlv, int len) {
    int data_len = len - 4;
    if (data_len < 4) return 0;
    int i;
    for (i = 0; i + 4 <= data_len; i++) {
        if (memcmp(tlv + 4 + i, B61_EMM_PREFIX, 4) == 0) return 1;
    }
    return 0;
}

/* Parse HC/MMT header. Returns 0 on parseable HC, -1 otherwise.
 * Out: mmtp_off, enc_flag, pkt_id, is_mpu (type&0x3F==0x00), mext_ok. */
static inline int b61_parse_hc(const uint8_t *tlv, int len,
                               int *mmtp_off_out, int *enc_flag_out,
                               uint16_t *pkt_id_out, int *is_mpu_out,
                               int *mext_ok_out) {
    if (len < 4) return -1;
    if (tlv[1] != B61_TLV_TYPE_HC) return -1;
    int data_len = (int)b61_u16be(tlv + 2);
    if (4 + data_len != len) return -1;
    if (data_len < 3) return -1;
    uint8_t hc_type = tlv[6];
    int mmtp_off;
    if (hc_type == B61_HC_NO_COMP) mmtp_off = 7;
    else if (hc_type == B61_HC_PART_V6) mmtp_off = 4 + 0x2D;
    else return -1;
    const uint8_t *mmtp = tlv + mmtp_off;
    int mmtp_len = len - mmtp_off;
    if (mmtp_len < B61_MMTP_OFF_ENC + 1) return -1;
    uint8_t flags = mmtp[B61_MMTP_OFF_FLAGS];
    int has_ext = (flags & 0x02) != 0;
    int has_pcnt = (flags & 0x20) != 0;
    if (!has_ext || has_pcnt) return -1;
    uint16_t mext = b61_u16be(mmtp + B61_MMTP_OFF_MEXT_T);
    uint8_t enc_byte = mmtp[B61_MMTP_OFF_ENC];
    int enc_flag = (enc_byte & 0x18) >> 3;
    uint16_t pkt_id = b61_u16be(mmtp + B61_MMTP_OFF_PKT_ID);
    int is_mpu = ((mmtp[B61_MMTP_OFF_TYPE] & 0x3F) == 0x00);
    int mext_ok = ((mext & 0x7FFF) == 0x0001);
    if (mmtp_off_out) *mmtp_off_out = mmtp_off;
    if (enc_flag_out) *enc_flag_out = enc_flag;
    if (pkt_id_out) *pkt_id_out = pkt_id;
    if (is_mpu_out) *is_mpu_out = is_mpu;
    if (mext_ok_out) *mext_ok_out = mext_ok;
    return 0;
}

/* True if this HC packet is scrambled MPU video subject to service filter. */
static inline int b61_is_scrambled_mpu(const uint8_t *tlv, int len,
                                       uint16_t *pkt_id_out) {
    int mmtp_off = 0, enc_flag = 0, is_mpu = 0, mext_ok = 0;
    uint16_t pkt_id = 0;
    if (b61_parse_hc(tlv, len, &mmtp_off, &enc_flag, &pkt_id,
                     &is_mpu, &mext_ok) < 0) return 0;
    if (!mext_ok || !is_mpu) return 0;
    if (enc_flag == B61_ENC_NONE) return 0;
    if (pkt_id_out) *pkt_id_out = pkt_id;
    return 1;
}

/* Robust write_all (handles EINTR, partial writes). */
static inline int b61_write_all(int fd, const uint8_t *p, int len) {
    int off = 0;
    while (off < len) {
        ssize_t w = write(fd, p + off, (size_t)(len - off));
        if (w < 0) {
#ifdef EINTR
            extern int *__errno_location(void);
            if (*__errno_location() == 4) continue;
#endif
            return -1;
        }
        if (w == 0) return -1;
        off += (int)w;
    }
    return 0;
}

#endif /* B61_TLV_H */
