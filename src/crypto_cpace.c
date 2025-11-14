/* File: crypto_cpace.c
 * Implementation for crypto_cpace.h
 *
 * Embedded references to draft-irtf-cfrg-cpace-15:
 *  - AD split usage and placement in transcript: draft-irtf-cfrg-cpace-15 3.1.
 *  - Protocol Step sequencing, generation of ephemeral scalars and exchange: draft-irtf-cfrg-cpace-15 6.2.
 *  - Generator derivation (generator_string, domain separation, hash-to-curve): draft-irtf-cfrg-cpace-15 7.1.
 *  - ISK (intermediate shared key) derivation: draft-irtf-cfrg-cpace-15 6.2 and key derivation notes in 7.2.
 *
 * Notes:
 *  - All uses of transcript, DSI, ISK labels are intended to follow draft wording/semantics from the listed sections.
 *  - No client_id/server_id fields are present per the requested simplification; generator derivation uses PRS and DSI as in 7.1.
 */

#include "crypto_cpace.h"
#include <string.h>
#include <stdlib.h>

/* Domain Separator Identifier (DSI) per draft-irtf-cfrg-cpace-15 7.1 */
static const unsigned char G_DSI[] = "CPaceRistretto255";
/* Label used in ISK derivation: DSI || "_ISK" per draft-irtf-cfrg-cpace-15 6.2 / 7.2 */
static const unsigned char LABEL_ISK[] = "_ISK";

/* --- small helper: varlen integer (LEB-like) encode for lv_cat --- */
/* lv_cat is used to construct transcripts exactly as described in draft-irtf-cfrg-cpace-15 3.1
 * transcript = lv_cat(Y_A, ADa) || lv_cat(Y_B, ADb)
 */
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
 * This aligns with draft-irtf-cfrg-cpace-15 section 3.1 which prescribes AD placement in transcript.
 */
static size_t build_transcript(const unsigned char *YA, const unsigned char *ADa, size_t ADa_len,
                               const unsigned char *YB, const unsigned char *ADb, size_t ADb_len,
                               unsigned char *out) {
    const unsigned char *p1[2] = { YA, ADa };
    size_t l1[2] = { CRYPTO_CPACE_PUBLICBYTES, ADa_len };
    size_t off = lv_cat(p1, l1, 2, out);
    const unsigned char *p2[2] = { YB, ADb };
    size_t l2[2] = { CRYPTO_CPACE_PUBLICBYTES, ADb_len };
    off += lv_cat(p2, l2, 2, out + off);
    return off;
}

/* calculate_generator_from_prs:
 * Implements generator derivation per draft-irtf-cfrg-cpace-15 7.1:
 *  - gen_str = lv_cat(DSI, PRS, zero_pad, CI, sid)
 *  - map hash(gen_str) -> curve point via hash-to-curve (here: crypto_core_ristretto255_from_hash)
 *
 * Simplified here: CI and sid omitted (client/server ids removed per request).
 * Zero-pad handling is deterministic; mapping uses SHA-512 as described in 7.1 for Ristretto target.
 */
static int calculate_generator_from_prs(const unsigned char *PRS, size_t PRS_len, unsigned char *G_out) {
    const size_t zero_pad_len = 16; /* deterministic small pad (satisfies gen_str uniqueness) */
    unsigned char *parts[3];
    size_t lens[3];
    parts[0] = (unsigned char *)G_DSI; lens[0] = sizeof(G_DSI) - 1; /* DSI per 7.1 */
    parts[1] = (unsigned char *)PRS;   lens[1] = PRS_len;          /* PRS included as in 7.1 */
    unsigned char zpad[zero_pad_len];
    memset(zpad, 0x00, zero_pad_len);
    parts[2] = zpad; lens[2] = zero_pad_len;
    size_t buf_cap = lens[0] + lens[1] + lens[2] + 32;
    unsigned char *buf = (unsigned char *)sodium_malloc(buf_cap);
    if (!buf) return -1;
    size_t buflen = lv_cat((const unsigned char **)parts, lens, 3, buf);
    unsigned char h[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(h, buf, buflen);
    sodium_free(buf);
    if (crypto_core_ristretto255_from_hash(G_out, h) != 0) return -1;
    return 0;
}

/* compute_public_from_scalar: out_pub = scalar * G
 * Per draft-irtf-cfrg-cpace-15 6.2: ephemeral scalar multiplication to derive Y_A/Y_B.
 */
static int compute_public_from_scalar(const unsigned char *scalar, const unsigned char *G, unsigned char *out_pub) {
    if (crypto_scalarmult_ristretto255(out_pub, scalar, G) != 0) return -1;
    return 0;
}

/* derive_shared_key_from_K_and_transcript:
 * Implements ISK = HASH( DSI || "_ISK" || K || transcript ) per draft-irtf-cfrg-cpace-15 6.2/7.2.
 * Output truncated to first 32 bytes as the single shared key.
 */
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
    unsigned char full[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_final(&sha, full);
    memcpy(shared_key_out, full, CRYPTO_CPACE_SHAREDKEYBYTES);
    sodium_memzero(full, sizeof(full));
    return 0;
}

/* --- Public API implementations --- */

int crypto_cpace_init(void) {
    return sodium_init() < 0 ? -1 : 0;
}

/* crypto_cpace_step1:
 * Client initial step: generate scalar a, compute Y_A = a·G where G derived from PRS as in 7.1.
 * Stores PRS and ADa/ADb in ctx to allow Step3 to re-derive G and transcript.
 * Follows draft-irtf-cfrg-cpace-15 6.2 (client initial generation).
 */
int crypto_cpace_step1(crypto_cpace_state *ctx,
                       unsigned char *public_data,
                       const unsigned char *PRS, size_t PRS_len,
                       const unsigned char *ADa, size_t ADa_len,
                       const unsigned char *ADb, size_t ADb_len) {
    if (!ctx || !public_data) return -1;
    if (PRS_len > CRYPTO_CPACE_MAX_SECRET_LEN) return -1;
    if (ADa_len > CRYPTO_CPACE_MAX_AD_LEN || ADb_len > CRYPTO_CPACE_MAX_AD_LEN) return -1;

    memcpy(ctx->PRS, PRS, PRS_len); ctx->PRS_len = PRS_len;
    if (ADa && ADa_len) { memcpy(ctx->ADa, ADa, ADa_len); ctx->ADa_len = ADa_len; } else { ctx->ADa_len = 0; }
    if (ADb && ADb_len) { memcpy(ctx->ADb, ADb, ADb_len); ctx->ADb_len = ADb_len; } else { ctx->ADb_len = 0; }

    unsigned char G[CRYPTO_CPACE_PUBLICBYTES];
    if (calculate_generator_from_prs(ctx->PRS, ctx->PRS_len, G) != 0) return -1;

    crypto_core_ristretto255_scalar_random(ctx->scalar);
    if (compute_public_from_scalar(ctx->scalar, G, public_data) != 0) {
        sodium_memzero(G, sizeof(G));
        return -1;
    }

    memcpy(ctx->public, public_data, CRYPTO_CPACE_PUBLICBYTES);
    sodium_memzero(G, sizeof(G));
    return 0;
}

/* crypto_cpace_step2:
 * Server step: derive G from PRS, sample b, compute Y_B=b·G, compute K=b·Y_A, construct transcript
 * as lv_cat(Y_A, ADa) || lv_cat(Y_B, ADb) per draft-irtf-cfrg-cpace-15 3.1 and 6.2, derive ISK.
 */
int crypto_cpace_step2(unsigned char *response,
                       const unsigned char *public_data,
                       crypto_cpace_shared_keys *shared_keys,
                       const unsigned char *PRS, size_t PRS_len,
                       const unsigned char *ADa, size_t ADa_len,
                       const unsigned char *ADb, size_t ADb_len) {
    if (!response || !public_data || !shared_keys) return -1;
    if (PRS_len > CRYPTO_CPACE_MAX_SECRET_LEN) return -1;
    if (ADa_len > CRYPTO_CPACE_MAX_AD_LEN || ADb_len > CRYPTO_CPACE_MAX_AD_LEN) return -1;

    unsigned char G[CRYPTO_CPACE_PUBLICBYTES];
    if (calculate_generator_from_prs(PRS, PRS_len, G) != 0) return -1;

    unsigned char b[CRYPTO_CPACE_SCALARBYTES];
    crypto_core_ristretto255_scalar_random(b);
    if (compute_public_from_scalar(b, G, response) != 0) {
        sodium_memzero(G, sizeof(G));
        return -1;
    }

    unsigned char K[CRYPTO_CPACE_PUBLICBYTES];
    if (crypto_scalarmult_ristretto255(K, b, public_data) != 0) {
        sodium_memzero(G, sizeof(G));
        sodium_memzero(b, sizeof(b));
        return -1;
    }

    unsigned char transcript[2048];
    size_t tlen = build_transcript(public_data, ADa, ADa_len, response, ADb, ADb_len, transcript);

    if (derive_shared_key_from_K_and_transcript(K, sizeof(K), transcript, tlen, shared_keys->shared_key) != 0) {
        sodium_memzero(G, sizeof(G));
        sodium_memzero(b, sizeof(b));
        sodium_memzero(K, sizeof(K));
        sodium_memzero(transcript, sizeof(transcript));
        return -1;
    }

    sodium_memzero(G, sizeof(G));
    sodium_memzero(b, sizeof(b));
    sodium_memzero(K, sizeof(K));
    sodium_memzero(transcript, sizeof(transcript));
    return 0;
}

/* crypto_cpace_step3:
 * Client finishes: re-derive G from stored PRS, compute K = a·Y_B, build transcript using stored ADa/ADb
 * per draft-irtf-cfrg-cpace-15 3.1 and 6.2, and derive ISK into shared_key.
 */
int crypto_cpace_step3(crypto_cpace_state *ctx,
                       crypto_cpace_shared_keys *shared_keys,
                       const unsigned char *response) {
    if (!ctx || !shared_keys || !response) return -1;

    unsigned char G[CRYPTO_CPACE_PUBLICBYTES];
    if (calculate_generator_from_prs(ctx->PRS, ctx->PRS_len, G) != 0) return -1;

    unsigned char K[CRYPTO_CPACE_PUBLICBYTES];
    if (crypto_scalarmult_ristretto255(K, ctx->scalar, response) != 0) {
        sodium_memzero(G, sizeof(G));
        return -1;
    }

    unsigned char transcript[2048];
    size_t tlen = build_transcript(ctx->public, ctx->ADa, ctx->ADa_len, response, ctx->ADb, ctx->ADb_len, transcript);

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
