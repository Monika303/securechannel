#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <openssl/evp.h>
#include "session.h"

#define PROT_PORT   5000
#define TAG_LEN     16
#define CTRL_PORT   9000
#define DEV2_IP     "10.0.2.2"
#define SEEN_SIZE   (1u << 20)
#define SEEN_LIMIT  (SEEN_SIZE / 10)

typedef struct {
    session_t sess;
    uint64_t *seen;          /* nonces already used for encryption */
    uint32_t  seen_count;
} ctx_t;

typedef struct {
    struct iphdr  *ip;
    struct tcphdr *tcp;
    int ip_hl, tcp_hl, pay_len;
    uint8_t *pay;
} pkt_t;

/* ------------------------------------------------------------------ */
/* Packet parsing                                                      */
/* ------------------------------------------------------------------ */
static int parse(uint8_t *buf, int len, pkt_t *p) {
    if (len < (int)sizeof(struct iphdr)) return -1;
    struct iphdr *ip = (struct iphdr *)buf;
    if (ip->version != 4 || ip->protocol != IPPROTO_TCP) return -1;
    int ihl = ip->ihl * 4, tot = ntohs(ip->tot_len);
    if (ihl < 20 || tot > len || tot < ihl + 20) return -1;
    if (ip->frag_off & htons(IP_MF | IP_OFFMASK)) return -1;   /* fragments: unsupported */
    struct tcphdr *tcp = (struct tcphdr *)(buf + ihl);
    int thl = tcp->doff * 4;
    if (thl < 20 || ihl + thl > tot) return -1;
    p->ip = ip; p->tcp = tcp; p->ip_hl = ihl; p->tcp_hl = thl;
    p->pay = buf + ihl + thl;
    p->pay_len = tot - ihl - thl;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Checksums                                                           */
/* ------------------------------------------------------------------ */
static uint32_t csum_add(uint32_t sum, const void *data, int len) {
    const uint8_t *p = data;
    for (; len > 1; len -= 2, p += 2) sum += (uint32_t)(p[0] << 8 | p[1]);
    if (len) sum += (uint32_t)(p[0] << 8);
    return sum;
}

static uint16_t csum_fold(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return htons((uint16_t)~sum);
}

/* set IP total length, then recompute IP and TCP checksums */
static void fix_packet(uint8_t *b, int tot) {
    struct iphdr *ip = (struct iphdr *)b;
    int ihl = ip->ihl * 4;
    ip->tot_len = htons((uint16_t)tot);
    ip->check = 0;
    ip->check = csum_fold(csum_add(0, b, ihl));
    struct tcphdr *t = (struct tcphdr *)(b + ihl);
    int tl = tot - ihl;
    t->check = 0;
    uint32_t sum = 0;
    sum = csum_add(sum, &ip->saddr, 4);
    sum = csum_add(sum, &ip->daddr, 4);
    sum += IPPROTO_TCP;
    sum += (uint32_t)tl;
    sum = csum_add(sum, t, tl);
    t->check = csum_fold(sum);
}

/* ------------------------------------------------------------------ */
/* Nonce and AAD (both derived from header fields)                     */
/* ------------------------------------------------------------------ */
static void build_nonce(const pkt_t *p, const uint8_t salt[4], uint8_t n[12]) {
    uint16_t eph = (ntohs(p->tcp->dest) == PROT_PORT) ? p->tcp->source : p->tcp->dest;
    memcpy(n, salt, 4);
    memcpy(n + 4, &p->ip->id, 2);
    memcpy(n + 6, &p->tcp->seq, 4);
    memcpy(n + 10, &eph, 2);
}

#define AAD_LEN 21
static void build_aad(const pkt_t *p, uint8_t aad[AAD_LEN]) {
    memcpy(aad,      &p->ip->saddr, 4);
    memcpy(aad + 4,  &p->ip->daddr, 4);
    memcpy(aad + 8,  &p->tcp->source, 2);
    memcpy(aad + 10, &p->tcp->dest, 2);
    memcpy(aad + 12, &p->tcp->seq, 4);
    memcpy(aad + 16, &p->tcp->ack_seq, 4);
    aad[20] = ((uint8_t *)p->tcp)[13];            /* TCP flags */
}

/* remember the used nonce; 0 = new, 1 = already used, -1 = table full */
static int seen_insert(ctx_t *c, const uint8_t nonce[12]) {
    uint64_t k;
    memcpy(&k, nonce + 4, 8);                     /* the part that is not the salt */
    if (k == 0) return 1;
    if (c->seen_count >= SEEN_LIMIT) return -1;
    uint32_t i = (uint32_t)((k * 0x9E3779B97F4A7C15ull) >> 44) & (SEEN_SIZE - 1);
    while (c->seen[i]) {
        if (c->seen[i] == k) return 1;
        i = (i + 1) & (SEEN_SIZE - 1);
    }
    c->seen[i] = k;
    c->seen_count++;
    return 0;
}

/* ------------------------------------------------------------------ */
/* AES-256-GCM                                                         */
/* ------------------------------------------------------------------ */
static int gcm_encrypt(const uint8_t *key, const uint8_t *nonce,
                       const uint8_t *aad, int aad_len,
                       const uint8_t *in, int len, uint8_t *out, uint8_t *tag) {
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    int l = 0, l2 = 0, ok = 0;
    if (!x) return -1;
    ok = EVP_EncryptInit_ex(x, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1
      && EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1
      && EVP_EncryptInit_ex(x, NULL, NULL, key, nonce) == 1
      && EVP_EncryptUpdate(x, NULL, &l, aad, aad_len) == 1
      && EVP_EncryptUpdate(x, out, &l, in, len) == 1
      && EVP_EncryptFinal_ex(x, out + l, &l2) == 1
      && EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) == 1;
    EVP_CIPHER_CTX_free(x);
    return ok ? 0 : -1;
}

static int gcm_decrypt(const uint8_t *key, const uint8_t *nonce,
                       const uint8_t *aad, int aad_len,
                       const uint8_t *in, int len, const uint8_t *tag, uint8_t *out) {
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    int l = 0, l2 = 0, ok = 0;
    uint8_t t[TAG_LEN];
    if (!x) return -1;
    memcpy(t, tag, TAG_LEN);
    ok = EVP_DecryptInit_ex(x, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1
      && EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1
      && EVP_DecryptInit_ex(x, NULL, NULL, key, nonce) == 1
      && EVP_DecryptUpdate(x, NULL, &l, aad, aad_len) == 1
      && EVP_DecryptUpdate(x, out, &l, in, len) == 1
      && EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_SET_TAG, TAG_LEN, t) == 1
      && EVP_DecryptFinal_ex(x, out + l, &l2) == 1;
    EVP_CIPHER_CTX_free(x);
    return ok ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Queue callbacks                                                     */
/* ------------------------------------------------------------------ */
static void hexs(const uint8_t *d, int n) {
    for (int i = 0; i < n; i++) printf("%02x", d[i]);
}

static int cb_encrypt(struct nfq_q_handle *qh, struct nfgenmsg *m, struct nfq_data *nfa, void *data) {
    (void)m;
    ctx_t *c = data;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = ph ? ntohl(ph->packet_id) : 0;
    uint8_t *buf = NULL;
    int len = nfq_get_payload(nfa, &buf);
    pkt_t p;
    static uint8_t out[65536];
    if (len < 0 || parse(buf, len, &p) < 0)
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    if (p.pay_len == 0)                                   /* SYN, ACK, FIN ...: nothing to encrypt */
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    int hdrs = p.ip_hl + p.tcp_hl;
    int newlen = hdrs + p.pay_len + TAG_LEN;
    if (newlen > 65535)
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    uint8_t nonce[12], aad[AAD_LEN];
    build_nonce(&p, c->sess.salt_tx, nonce);
    build_aad(&p, aad);
    int s = seen_insert(c, nonce);
    if (s != 0) {
        fprintf(stderr, "[ENC] %s -> packet dropped, restart to get a new session\n",
                s < 0 ? "nonce table full" : "nonce would be reused");
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    memcpy(out, buf, hdrs);                               /* headers unchanged */
    if (gcm_encrypt(c->sess.key_tx, nonce, aad, AAD_LEN,
                    p.pay, p.pay_len, out + hdrs, out + hdrs + p.pay_len) < 0)
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

    /* TEST ONLY: corrupt the first encrypted packet if TAMPER=1 is set */
    static int tampered = 0;
    if (!tampered && getenv("TAMPER")) {
        out[hdrs] ^= 0x01;          /* flip one bit of the ciphertext */
        tampered = 1;
        printf("[TEST] flipped one bit in the ciphertext\n");
    }

    fix_packet(out, newlen);
    printf("[ENC] seq=%u payload %d -> %d bytes  nonce=", ntohl(p.tcp->seq), p.pay_len, p.pay_len + TAG_LEN);
    hexs(nonce, 12); printf("\n"); fflush(stdout);
    return nfq_set_verdict(qh, id, NF_ACCEPT, (uint32_t)newlen, out);
}

static int cb_decrypt(struct nfq_q_handle *qh, struct nfgenmsg *m, struct nfq_data *nfa, void *data) {
    (void)m;
    ctx_t *c = data;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = ph ? ntohl(ph->packet_id) : 0;
    uint8_t *buf = NULL;
    int len = nfq_get_payload(nfa, &buf);
    pkt_t p;
    static uint8_t out[65536];
    if (len < 0 || parse(buf, len, &p) < 0)
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    if (p.pay_len == 0)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    if (p.pay_len < TAG_LEN) {
        fprintf(stderr, "[DEC] payload too short, dropped\n");
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    int hdrs = p.ip_hl + p.tcp_hl;
    int ct_len = p.pay_len - TAG_LEN;
    uint8_t nonce[12], aad[AAD_LEN];
    build_nonce(&p, c->sess.salt_rx, nonce);
    build_aad(&p, aad);
    memcpy(out, buf, hdrs);
    if (gcm_decrypt(c->sess.key_rx, nonce, aad, AAD_LEN,
                    p.pay, ct_len, p.pay + ct_len, out + hdrs) < 0) {
        fprintf(stderr, "[DEC] AUTHENTICATION FAILED, packet dropped (seq=%u)\n", ntohl(p.tcp->seq));
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    fix_packet(out, hdrs + ct_len);
    printf("[DEC] seq=%u payload %d -> %d bytes  tag OK\n", ntohl(p.tcp->seq), p.pay_len, ct_len);
    fflush(stdout);
    return nfq_set_verdict(qh, id, NF_ACCEPT, (uint32_t)(hdrs + ct_len), out);
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "dev1") && strcmp(argv[1], "dev2"))) {
        fprintf(stderr, "usage: %s dev1|dev2\n", argv[0]);
        return 1;
    }
    int is_dev1 = !strcmp(argv[1], "dev1");
    ctx_t *c = calloc(1, sizeof *c);
    c->seen = calloc(SEEN_SIZE, sizeof(uint64_t));
    if (!c || !c->seen) { perror("calloc"); return 1; }

    /* Step 3: handshake. Dev2 waits, Dev1 connects. */
    printf("Handshake ... \n"); fflush(stdout);
    int r = is_dev1 ? handshake_client(DEV2_IP, CTRL_PORT, &c->sess)
                    : handshake_server(DEV2_IP, CTRL_PORT, &c->sess);
    if (r < 0) { fprintf(stderr, "handshake failed\n"); return 1; }
    printf("Handshake OK, secure session established\n"); fflush(stdout);

    /* Steps 4 and 5: queue 0 = encrypt, queue 1 = decrypt */
    struct nfq_handle *h = nfq_open();
    if (!h) { perror("nfq_open"); return 1; }
    struct nfq_q_handle *q0 = nfq_create_queue(h, 0, &cb_encrypt, c);
    struct nfq_q_handle *q1 = nfq_create_queue(h, 1, &cb_decrypt, c);
    if (!q0 || !q1) { fprintf(stderr, "nfq_create_queue failed\n"); return 1; }
    nfq_set_mode(q0, NFQNL_COPY_PACKET, 0xffff);
    nfq_set_mode(q1, NFQNL_COPY_PACKET, 0xffff);

    printf("%s running: queue 0 = encrypt, queue 1 = decrypt\n", argv[1]);
    fflush(stdout);

    int fd = nfq_fd(h);
    static char rbuf[70000] __attribute__((aligned));
    for (;;) {
        ssize_t n = recv(fd, rbuf, sizeof rbuf, 0);
        if (n < 0) {
            if (errno == EINTR || errno == ENOBUFS) continue;
            perror("recv"); break;
        }
        nfq_handle_packet(h, rbuf, (int)n);
    }
    nfq_close(h);
    return 0;
}
