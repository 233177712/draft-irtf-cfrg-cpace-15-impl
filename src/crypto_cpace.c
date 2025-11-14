/* File: crypto_cpace.c
 * Implementation for crypto_cpace.h
 */

#include "crypto_cpace.h"
#include <string.h>
#include <stdlib.h>

/* Domain Separator Identifier */
static const unsigned char G_DSI[] = "CPaceRistretto255";
static const unsigned char LABEL_ISK[] = "_ISK";

/* --- small helper: varlen integer (LEB-like) encode for lv_cat --- */
static size_t leb128_encode_len(uint8_t *out, size_t len) {
    size_t idx = 0;
    uint64_t v = (uint64_t)len;
    do {
        uint8_t b = v & 0x7F;
        v >>= 7;
        if (v) b |= 0x80;
        out[idx++] = b;
    } while (v);
    return idx;
}

/* lv_cat: concatenate series of (length||value) into out, return total bytes written.
 * parts: array of pointers; part_lens: array of lengths; count: number of parts
 * Ensure out has enough capacity.
 */
static size_t lv_cat(const unsigned char **parts, const size_t *part_lens, int count, unsigned char *out) {
    size_t off = 0;
    for (int i = 0; i < count; i++) {
        uint8_t lenbuf[10];
        size_t lb = leb128_encode_len(lenbuf, part_lens[i]);
        memcpy(out + off, lenbuf, lb);
        off += lb;
        if (part_lens[i] > 0) {
            memcpy(out + off, parts[i], part_lens[i]);
            off += part_lens[i];
        }
    }
    return off;
}

/* build_transcript: transcript = lv_cat(Y_A, ADa) || lv_cat(Y_B, ADb)
 * out must be large enough (we use 2048 in callers)
 */
static size_t build_transcript(const unsigned char *YA, const unsigned char *ADa, size_t ADa_len,
                               const unsigned char *YB, const unsigned char *ADb, size_t ADb_len,
                               unsigned char *out) {
    const unsigned char *p1[2] = { YA, ADa };
    size_t l1[2] = { CRYPTO_CPACE_PUBLICBYTES, ADa_len };
    size_t off = lv_cat(p1, l1, 2, out);
    const unsigned char *p2[2] = { YB, ADb };
    size_t l2[2] = { CRYPTO_CPACE_PUBLICBYTES, ADb_len }; /* Y_B same size as public */
    off += lv_cat(p2, l2, 2, out + off);
    return off;
}

/* calculate_generator: per draft-15 Section 7.1-ish
 * gen_str = lv_cat(DSI, PRS, zero_pad, CI, sid) ; here CI and sid omitted (we drop client/server ids)
 * zero_pad chosen so that hash input length equals SHA512 block multiple heuristics used earlier.
 * Returns 0 on success, -1 on failure. G_out bytes length CRYPTO_CPACE_PUBLICBYTES.
 */
static int calculate_generator_from_prs(const unsigned char *PRS, size_t PRS_len, unsigned char *G_out) {
    /* zero_pad length selection: keep simple deterministic pad (could be zero) */
    /* We'll follow a conservative approach: use a small fixed zero pad to emulate draft padding needs */
    const size_t zero_pad_len = 16; /* small deterministic padding */
    unsigned char *parts[3];
    size_t lens[3];
    parts[0] = (unsigned char *)G_DSI; lens[0] = sizeof(G_DSI) - 1;
    parts[1] = (unsigned char *)PRS;   lens[1] = PRS_len;
    unsigned char zpad[zero_pad_len];
    memset(zpad, 0x00, zero_pad_len);
    parts[2] = zpad; lens[2] = zero_pad_len;
    /* Compute lv_cat into a temporary buffer */
    size_t buf_cap = lens[0] + lens[1] + lens[2] + 32;
    unsigned char *buf = (unsigned char *)sodium_malloc(buf_cap);
    if (!buf) return -1;
    size_t buflen = lv_cat((const unsigned char **)parts, lens, 3, buf);
    /* hash and map to ristretto */
    unsigned char h[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(h, buf, buflen);
    sodium_free(buf);
    if (crypto_core_ristretto255_from_hash(G_out, h) != 0) return -1;
    return 0;
}

/* compute_public_from_scalar: out_pub = scalar * G
 * scalar length CRYPTO_CPACE_SCALARBYTES, G length CRYPTO_CPACE_PUBLICBYTES
 */
static int compute_public_from_scalar(const unsigned char *scalar, const unsigned char *G, unsigned char *out_pub) {
    if (crypto_scalarmult_ristretto255(out_pub, scalar, G) != 0) return -1;
    return 0;
}

/* derive_shared_key: HASH( DSI || "_ISK" || K || transcript ) -> take first 32 bytes as shared key */
static int derive_shared_key_from_K_and_transcript(const unsigned char *K, size_t K_len,
                                                   const unsigned char *transcript, size_t trans_len,
                                                   unsigned char *shared_key_out) {
    crypto_hash_sha512_state sha;
    unsigned char prefix[64];
    size_t prefix_len = 0;
    size_t dsi_len = sizeof(G_DSI) - 1;
    if (dsi_len + (sizeof(LABEL_ISK) - 1) > sizeof(prefix)) return -1;
    memcpy(prefix + prefix_len, G_DSI, dsi_len); prefix_len += dsi_len;
    memcpy(prefix + prefix_len, LABEL_ISK, sizeof(LABEL_ISK) - 1); prefix_len += sizeof(LABEL_ISK) - 1;
    crypto_hash_sha512_init(&sha);
    crypto_hash_sha512_update(&sha, prefix, prefix_len);
    crypto_hash_sha512_update(&sha, K, K_len);
    crypto_hash_sha512_update(&sha, transcript, trans_len);
    unsigned char out48[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_final(&sha, out48);
    memcpy(shared_key_out, out48, CRYPTO_CPACE_SHAREDKEYBYTES);
    sodium_memzero(out48, sizeof(out48));
    return 0;
}

/* Public API implementations */

int crypto_cpace_init(void) {
    return sodium_init() < 0 ? -1 : 0;
}

int crypto_cpace_step1(crypto_cpace_state *ctx,
                       unsigned char *public_data,
                       const unsigned char *PRS, size_t PRS_len,
                       const unsigned char *ADa, size_t ADa_len,
                       const unsigned char *ADb, size_t ADb_len) {
    if (!ctx || !public_data) return -1;
    if (PRS_len > CRYPTO_CPACE_MAX_SECRET_LEN) return -1;
    if (ADa_len > CRYPTO_CPACE_MAX_AD_LEN || ADb_len > CRYPTO_CPACE_MAX_AD_LEN) return -1;

    /* store PRS and ADs */
    memcpy(ctx->PRS, PRS, PRS_len); ctx->PRS_len = PRS_len;
    if (ADa && ADa_len) { memcpy(ctx->ADa, ADa, ADa_len); ctx->ADa_len = ADa_len; } else { ctx->ADa_len = 0; }
    if (ADb && ADb_len) { memcpy(ctx->ADb, ADb, ADb_len); ctx->ADb_len = ADb_len; } else { ctx->ADb_len = 0; }

    /* calculate generator G */
    unsigned char G[CRYPTO_CPACE_PUBLICBYTES];
    if (calculate_generator_from_prs(ctx->PRS, ctx->PRS_len, G) != 0) return -1;

    /* generate scalar a and compute Y_A = a * G */
    crypto_core_ristretto255_scalar_random(ctx->scalar);
    if (compute_public_from_scalar(ctx->scalar, G, public_data) != 0) return -1;

    /* save public */
    memcpy(ctx->public, public_data, CRYPTO_CPACE_PUBLICBYTES);
    sodium_memzero(G, sizeof(G));
    return 0;
}

int crypto_cpace_step2(unsigned char *response,
                       const unsigned char *public_data,
                       crypto_cpace_shared_keys *shared_keys,
                       const unsigned char *PRS, size_t PRS_len,
                       const unsigned char *ADa, size_t ADa_len,
                       const unsigned char *ADb, size_t ADb_len) {
    if (!response || !public_data || !shared_keys) return -1;
    if (PRS_len > CRYPTO_CPACE_MAX_SECRET_LEN) return -1;
    if (ADa_len > CRYPTO_CPACE_MAX_AD_LEN || ADb_len > CRYPTO_CPACE_MAX_AD_LEN) return -1;

    /* server-local PRS/AD data (no persistent ctx needed for server in this simple API) */
    /* compute G from PRS */
    unsigned char G[CRYPTO_CPACE_PUBLICBYTES];
    if (calculate_generator_from_prs(PRS, PRS_len, G) != 0) return -1;

    /* random scalar b and Y_B = b * G */
    unsigned char b[CRYPTO_CPACE_SCALARBYTES];
    crypto_core_ristretto255_scalar_random(b);
    if (compute_public_from_scalar(b, G, response) != 0) return -1;

    /* compute shared point K = b * Y_A (Y_A is public_data) */
    unsigned char K[CRYPTO_CPACE_PUBLICBYTES];
    if (crypto_scalarmult_ristretto255(K, b, public_data) != 0) {
        sodium_memzero(G, sizeof(G));
        sodium_memzero(b, sizeof(b));
        return -1;
    }

    /* build transcript using provided ADa/ADb */
    unsigned char transcript[2048];
    size_t tlen = build_transcript(public_data, ADa, ADa_len, response, ADb, ADb_len, transcript);

    /* derive shared key */
    if (derive_shared_key_from_K_and_transcript(K, sizeof(K), transcript, tlen, shared_keys->shared_key) != 0) {
        sodium_memzero(G, sizeof(G));
        sodium_memzero(b, sizeof(b));
        sodium_memzero(K, sizeof(K));
        sodium_memzero(transcript, sizeof(transcript));
        return -1;
    }

    /* cleanup */
    sodium_memzero(G, sizeof(G));
    sodium_memzero(b, sizeof(b));
    sodium_memzero(K, sizeof(K));
    sodium_memzero(transcript, sizeof(transcript));
    return 0;
}

int crypto_cpace_step3(crypto_cpace_state *ctx,
                       crypto_cpace_shared_keys *shared_keys,
                       const unsigned char *response) {
    if (!ctx || !shared_keys || !response) return -1;

    /* recalc G from stored PRS */
    unsigned char G[CRYPTO_CPACE_PUBLICBYTES];
    if (calculate_generator_from_prs(ctx->PRS, ctx->PRS_len, G) != 0) return -1;

    /* compute K = a * Y_B (response) */
    unsigned char K[CRYPTO_CPACE_PUBLICBYTES];
    if (crypto_scalarmult_ristretto255(K, ctx->scalar, response) != 0) {
        sodium_memzero(G, sizeof(G));
        return -1;
    }

    /* build transcript using stored ADa/ADb */
    unsigned char transcript[2048];
    size_t tlen = build_transcript(ctx->public, ctx->ADa, ctx->ADa_len, response, ctx->ADb, ctx->ADb_len, transcript);

    /* derive shared key */
    if (derive_shared_key_from_K_and_transcript(K, sizeof(K), transcript, tlen, shared_keys->shared_key) != 0) {
        sodium_memzero(G, sizeof(G));
        sodium_memzero(K, sizeof(K));
        sodium_memzero(transcript, sizeof(transcript));
        return -1;
    }

    sodium_memzero(G, sizeof(G));
    sodium_memzero(K, sizeof(K));
    sodium_memzero(transcript, sizeof(transcript));
    return 0;
}
