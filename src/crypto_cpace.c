#include "crypto_cpace.h"
#include <string.h>
#include <stdlib.h>

/* Domain Separator Identifier (DSI) for generator derivation (draft-irtf-cfrg-cpace-15 7.1) */
static const unsigned char G_DSI[] = "CPaceRistretto255";
/* Label used in ISK derivation (draft-irtf-cfrg-cpace-15 6.2 / 7.2) */
static const unsigned char LABEL_ISK[] = "_ISK";

/* --- helper: LEB128 encode of a size_t length (for LV) (draft-irtf-cfrg-cpace-15 3.1 style LV) --- */
static size_t leb128_encode_len(uint8_t *out, size_t len) {
size_t idx = 0;
uint64_t v = (uint64_t)len;
do {
uint8_t b = (uint8_t)(v & 0x7F);
v >>= 7;
if (v) b |= 0x80;
out[idx++] = b;
} while (v);
return idx;
}

/* LV cat: writes LV(parts[i]) for i in [0..count) into out; returns bytes written (draft 3.1) */
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

/* LV total size calculator: how many bytes LV(parts) will occupy (length prefix + payload) */
static size_t lv_total_size(const size_t *part_lens, int count) {
size_t total = 0;
uint8_t tmp[10];
for (int i = 0; i < count; i++) {
total += leb128_encode_len(tmp, part_lens[i]);
total += part_lens[i];
}
return total;
}

/* build_transcript = LV(Y_A) || LV(ADa) || LV(Y_B) || LV(ADb) (draft-irtf-cfrg-cpace-15 3.1) */
static size_t build_transcript(const unsigned char *YA, const unsigned char *ADa, size_t ADa_len,
const unsigned char *YB, const unsigned char *ADb, size_t ADb_len,
unsigned char *out) {
const unsigned char *p[4] = { YA, ADa, YB, ADb };
size_t l[4] = { CRYPTO_CPACE_PUBLICBYTES, ADa_len, CRYPTO_CPACE_PUBLICBYTES, ADb_len };
return lv_cat(p, l, 4, out);
}

/* transcript size calculator for exact allocation */
static size_t transcript_size(size_t ADa_len, size_t ADb_len) {
size_t l[4] = { CRYPTO_CPACE_PUBLICBYTES, ADa_len, CRYPTO_CPACE_PUBLICBYTES, ADb_len };
return lv_total_size(l, 4);
}

/* calculate_generator_from_prs_with_sid

Generator derivation per draft-irtf-cfrg-cpace-15 7.1.
gen_str = LV(DSI) || LV(PRS) || zpad || LV(sid)
Note:
CI 省略（按当前 API 设计简化）。
zpad 保留与原实现一致的计算方式，以与 7.1 中“映射输入长度与分组大小对齐”的直觉一致；
这里我们后续以 SHA-512(gen_str) -> ristretto255_from_hash 进行“hash-to-group”映射。 */ static int calculate_generator_from_prs_with_sid(const unsigned char *PRS, size_t PRS_len, const unsigned char *sid, size_t sid_len, unsigned char *G_out) { if (!PRS || PRS_len == 0) return -1; if (!sid || sid_len == 0) return -1;
const unsigned char *DSI = G_DSI;
const size_t DSI_len = sizeof(G_DSI) - 1;

/* s_in_bytes = block size of SHA-512 (128) (draft 7.1) */
const size_t s_in_bytes = 128;

/* precompute LV header sizes */
uint8_t tmp[10];
const size_t preDSI_len  = leb128_encode_len(tmp, DSI_len);
const size_t prePRS_len  = leb128_encode_len(tmp, PRS_len);
const size_t presid_len  = leb128_encode_len(tmp, sid_len);

/* len_zpad = max(0, s_in_bytes - 1 - preDSI_len - prePRS_len - presid_len) */
size_t len_zpad = 0;
if (s_in_bytes > 1 + preDSI_len + prePRS_len + presid_len) {
len_zpad = s_in_bytes - 1 - preDSI_len - prePRS_len - presid_len;
}

/* allocate exact buffer: LV(DSI) + LV(PRS) + zpad + LV(sid) */
const size_t buf_cap = preDSI_len + DSI_len + prePRS_len + PRS_len + len_zpad + presid_len + sid_len;
unsigned char *buf = (unsigned char *)sodium_malloc(buf_cap);
if (!buf) return -1;

size_t off = 0;
uint8_t lenbuf[10];
size_t lb;

lb = leb128_encode_len(lenbuf, DSI_len);
memcpy(buf + off, lenbuf, lb); off += lb;
memcpy(buf + off, DSI, DSI_len); off += DSI_len;

lb = leb128_encode_len(lenbuf, PRS_len);
memcpy(buf + off, lenbuf, lb); off += lb;
memcpy(buf + off, PRS, PRS_len); off += PRS_len;

if (len_zpad) {
memset(buf + off, 0x00, len_zpad);
off += len_zpad;
}

lb = leb128_encode_len(lenbuf, sid_len);
memcpy(buf + off, lenbuf, lb); off += lb;
memcpy(buf + off, sid, sid_len); off += sid_len;

/* Hash and map to group (draft 7.1): SHA-512 -> ristretto255_from_hash */
unsigned char h[crypto_hash_sha512_BYTES];
crypto_hash_sha512(h, buf, off);
sodium_free(buf);

if (crypto_core_ristretto255_from_hash(G_out, h) != 0) {
sodium_memzero(h, sizeof h);
return -1;
}
sodium_memzero(h, sizeof h);
return 0;
}

/* ISK derivation (draft-irtf-cfrg-cpace-15 6.2/7.2)

ISK = H( DSI || "_ISK" || K || transcript ), then truncate to 32 bytes as shared_key.
*/
static int derive_shared_key_from_K_and_transcript(const unsigned char *K, size_t K_len,
const unsigned char *transcript, size_t trans_len,
unsigned char *shared_key_out) {
crypto_hash_sha512_state sha;
unsigned char prefix[64];
size_t prefix_len = 0;
const size_t dsi_len = sizeof(G_DSI) - 1;

if (dsi_len + (sizeof(LABEL_ISK) - 1) > sizeof(prefix)) {
return -1;
}
memcpy(prefix + prefix_len, G_DSI, dsi_len); prefix_len += dsi_len;
memcpy(prefix + prefix_len, LABEL_ISK, sizeof(LABEL_ISK) - 1); prefix_len += (sizeof(LABEL_ISK) - 1);

crypto_hash_sha512_init(&sha);
crypto_hash_sha512_update(&sha, prefix, prefix_len);
crypto_hash_sha512_update(&sha, K, K_len);
crypto_hash_sha512_update(&sha, transcript, trans_len);

unsigned char full[crypto_hash_sha512_BYTES];
crypto_hash_sha512_final(&sha, full);
memcpy(shared_key_out, full, CRYPTO_CPACE_SHAREDKEYBYTES);
sodium_memzero(full, sizeof(full));
sodium_memzero(prefix, sizeof(prefix));
return 0;
}

/* Sample a non-zero scalar (draft-irtf-cfrg-cpace-15 6.2) */
static void sample_nonzero_scalar(unsigned char out_scalar[CRYPTO_CPACE_SCALARBYTES]) {
for (;;) {
crypto_core_ristretto255_scalar_random(out_scalar);
/ All-zero check: extremely unlikely; loop defends against zero scalar */
unsigned char zero[CRYPTO_CPACE_SCALARBYTES] = {0};
if (sodium_memcmp(out_scalar, zero, sizeof(zero)) != 0) {
sodium_memzero(zero, sizeof(zero));
return;
}
}
}

int crypto_cpace_init(void) {
return sodium_init() < 0 ? -1 : 0;
}

/* Step1 (client) - draft-irtf-cfrg-cpace-15 6.2 */
int crypto_cpace_step1(crypto_cpace_state *ctx,
unsigned char *public_data,
const unsigned char *PRS, size_t PRS_len,
const unsigned char *ADa, size_t ADa_len,
const unsigned char *ADb, size_t ADb_len,
const unsigned char *sid, size_t sid_len) {
if (!ctx || !public_data || !PRS || PRS_len == 0 || !sid || sid_len == 0) return -1;
if (PRS_len > CRYPTO_CPACE_MAX_SECRET_LEN) return -1;
if (ADa_len > CRYPTO_CPACE_MAX_AD_LEN || ADb_len > CRYPTO_CPACE_MAX_AD_LEN) return -1;
if (sid_len > CRYPTO_CPACE_SID_MAX_BYTES) return -1;

/* Initialize/clear ctx small fields first to avoid stale lengths */
ctx->PRS_len = 0;
ctx->ADa_len = 0;
ctx->ADb_len = 0;
ctx->sid_len = 0;

/* Store PRS, ADs, sid (draft 3.1 / 9.6) */
memcpy(ctx->PRS, PRS, PRS_len); ctx->PRS_len = PRS_len;
if (ADa && ADa_len) { memcpy(ctx->ADa, ADa, ADa_len); ctx->ADa_len = ADa_len; }
if (ADb && ADb_len) { memcpy(ctx->ADb, ADb, ADb_len); ctx->ADb_len = ADb_len; }
memcpy(ctx->sid, sid, sid_len); ctx->sid_len = sid_len;

/* Derive generator G (draft 7.1) */
unsigned char G[CRYPTO_CPACE_PUBLICBYTES];
if (calculate_generator_from_prs_with_sid(ctx->PRS, ctx->PRS_len, ctx->sid, ctx->sid_len, G) != 0) {
sodium_memzero(G, sizeof(G));
return -1;
}

/* Sample scalar a != 0 and compute Y_A = a * G (draft 6.2) */
sample_nonzero_scalar(ctx->scalar);
if (crypto_scalarmult_ristretto255(public_data, ctx->scalar, G) != 0) {
sodium_memzero(G, sizeof(G));
return -1;
}

memcpy(ctx->public, public_data, CRYPTO_CPACE_PUBLICBYTES);
sodium_memzero(G, sizeof(G));
return 0;
}

/* Step2 (server) - draft-irtf-cfrg-cpace-15 6.2 */
int crypto_cpace_step2(unsigned char *response,
const unsigned char *public_data,
crypto_cpace_shared_keys *shared_keys,
const unsigned char *PRS, size_t PRS_len,
const unsigned char *ADa, size_t ADa_len,
const unsigned char *ADb, size_t ADb_len,
const unsigned char *sid, size_t sid_len) {
if (!response || !public_data || !shared_keys || !PRS || PRS_len == 0 || !sid || sid_len == 0) return -1;
if (PRS_len > CRYPTO_CPACE_MAX_SECRET_LEN) return -1;
if (ADa_len > CRYPTO_CPACE_MAX_AD_LEN || ADb_len > CRYPTO_CPACE_MAX_AD_LEN) return -1;
if (sid_len > CRYPTO_CPACE_SID_MAX_BYTES) return -1;

/* Validate Y_A is a valid group element (draft 6.2) */
if (crypto_core_ristretto255_is_valid_point(public_data) != 1) {
return -1;
}

/* Derive generator G (draft 7.1) */
unsigned char G[CRYPTO_CPACE_PUBLICBYTES];
if (calculate_generator_from_prs_with_sid(PRS, PRS_len, sid, sid_len, G) != 0) {
sodium_memzero(G, sizeof(G));
return -1;
}

/* Sample scalar b != 0, compute Y_B = b * G (draft 6.2) */
unsigned char b[CRYPTO_CPACE_SCALARBYTES];
sample_nonzero_scalar(b);
if (crypto_scalarmult_ristretto255(response, b, G) != 0) {
sodium_memzero(G, sizeof(G));
sodium_memzero(b, sizeof(b));
return -1;
}

/* Compute K = b * Y_A (draft 6.2) */
unsigned char K[CRYPTO_CPACE_PUBLICBYTES];
if (crypto_scalarmult_ristretto255(K, b, public_data) != 0) {
sodium_memzero(G, sizeof(G));
sodium_memzero(b, sizeof(b));
sodium_memzero(K, sizeof(K));
return -1;
}

/* Build transcript = LV(Y_A) || LV(ADa) || LV(Y_B) || LV(ADb) (draft 3.1) */
size_t tlen = transcript_size(ADa_len, ADb_len);
unsigned char *transcript = (unsigned char *)sodium_malloc(tlen);
if (!transcript) {
sodium_memzero(G, sizeof(G));
sodium_memzero(b, sizeof(b));
sodium_memzero(K, sizeof(K));
return -1;
}
(void)build_transcript(public_data, ADa, ADa_len, response, ADb, ADb_len, transcript);

/* Derive ISK as shared_key (draft 6.2 / 7.2) */
int rc = derive_shared_key_from_K_and_transcript(K, sizeof(K), transcript, tlen, shared_keys->shared_key);

sodium_memzero(G, sizeof(G));
sodium_memzero(b, sizeof(b));
sodium_memzero(K, sizeof(K));
sodium_memzero(transcript, tlen);
sodium_free(transcript);

return rc;
}

/* Step3 (client) - draft-irtf-cfrg-cpace-15 6.2 */
int crypto_cpace_step3(crypto_cpace_state *ctx,
crypto_cpace_shared_keys *shared_keys,
const unsigned char response) {
if (!ctx || !shared_keys || !response) return -1;
if (ctx->PRS_len == 0) return -1; / ensure Step1 stored PRS /
if (ctx->sid_len == 0) return -1; / sid must have been cached by Step1 */

/* Validate Y_B is a valid group element (draft 6.2) */
if (crypto_core_ristretto255_is_valid_point(response) != 1) {
return -1;
}

/* Compute K = a * Y_B (draft 6.2) */
unsigned char K[CRYPTO_CPACE_PUBLICBYTES];
if (crypto_scalarmult_ristretto255(K, ctx->scalar, response) != 0) {
sodium_memzero(K, sizeof(K));
return -1;
}

/* Build transcript = LV(Y_A) || LV(ADa) || LV(Y_B) || LV(ADb) (draft 3.1) */
size_t tlen = transcript_size(ctx->ADa_len, ctx->ADb_len);
unsigned char *transcript = (unsigned char *)sodium_malloc(tlen);
if (!transcript) {
sodium_memzero(K, sizeof(K));
return -1;
}
(void)build_transcript(ctx->public, ctx->ADa, ctx->ADa_len, response, ctx->ADb, ctx->ADb_len, transcript);

/* Derive ISK as shared_key (draft 6.2 / 7.2) */
int rc = derive_shared_key_from_K_and_transcript(K, sizeof(K), transcript, tlen, shared_keys->shared_key);

sodium_memzero(K, sizeof(K));
sodium_memzero(transcript, tlen);
sodium_free(transcript);
return rc;
}

/* securely clear context */
void crypto_cpace_clear(crypto_cpace_state *ctx) {
if (!ctx) return;
sodium_memzero(ctx->scalar, sizeof ctx->scalar);
sodium_memzero(ctx->public, sizeof ctx->public);
if (ctx->PRS_len) { sodium_memzero(ctx->PRS, ctx->PRS_len); ctx->PRS_len = 0; }
if (ctx->ADa_len) { sodium_memzero(ctx->ADa, ctx->ADa_len); ctx->ADa_len = 0; }
if (ctx->ADb_len) { sodium_memzero(ctx->ADb, ctx->ADb_len); ctx->ADb_len = 0; }
if (ctx->sid_len) { sodium_memzero(ctx->sid, ctx->sid_len); ctx->sid_len = 0; }
}
