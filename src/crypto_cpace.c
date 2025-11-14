
/* File: crypto_cpace.c

* Implementation for crypto_cpace.h
*
* Embedded references to draft-irtf-cfrg-cpace-15:
* * AD split usage and placement in transcript: draft-irtf-cfrg-cpace-15 3.1.
* * Protocol Step sequencing, generation of ephemeral scalars and exchange: draft-irtf-cfrg-cpace-15 6.2.
* * Generator derivation (generator_string, domain separation, hash-to-curve): draft-irtf-cfrg-cpace-15 7.1.
* * ISK (intermediate shared key) derivation: draft-irtf-cfrg-cpace-15 6.2 and key derivation notes in 7.2.
* * sid handling: caller-provided sid per draft-irtf-cfrg-cpace-15 9.6 / 9.1 guidance.
*
* Design: sid MUST be provided by the caller (Step1 client caches sid in ctx; Step2 server must provide same sid).
* There is NO automatic sid generation in this implementation.
  */

#include "crypto_cpace.h"
#include <string.h>
#include <stdlib.h>

/* Domain Separator Identifier (DSI) per draft-irtf-cfrg-cpace-15 7.1 */
static const unsigned char G_DSI[] = "CPaceRistretto255";
/* Label used in ISK derivation: DSI || "_ISK" per draft-irtf-cfrg-cpace-15 6.2 / 7.2 */
static const unsigned char LABEL_ISK[] = "_ISK";

/* --- small helper: LEB128 encode length (writes to out, returns bytes written) --- */
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

/* lv_cat: concatenates length-value encoded parts to out.

* parts: array of pointers to byte arrays
* part_lens: corresponding lengths
* count: number of parts
* returns total bytes written
*
* Used to construct transcripts exactly as described in draft-irtf-cfrg-cpace-15 3.1:
* transcript = lv_cat(Y_A, ADa) || lv_cat(Y_B, ADb)
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

* This aligns with draft-irtf-cfrg-cpace-15 section 3.1 which prescribes AD placement in transcript.
  */
  static size_t build_transcript(const unsigned char *YA, const unsigned char *ADa, size_t ADa_len,
  const unsigned char *YB, const unsigned char *ADb, size_t ADb_len,
  unsigned char *out) {
  const unsigned char *p1[2] = { YA, ADa };
  size_t l1[2] = { CRYPTO_CPACE_PUBLICBYTES, ADa_len };
  size_t off = lv_cat((const unsigned char **)p1, l1, 2, out);
  const unsigned char *p2[2] = { YB, ADb };
  size_t l2[2] = { CRYPTO_CPACE_PUBLICBYTES, ADb_len };
  off += lv_cat((const unsigned char **)p2, l2, 2, out + off);
  return off;
  }

/* calculate_generator_from_prs_with_sid:

* Implements generator derivation per draft-irtf-cfrg-cpace-15 7.1:
* * gen_str = lv_cat(DSI, PRS, zero_pad, optional CI, optional sid)
* Here CI omitted (per simplification request), but sid is required by caller in this implementation.
*
* NOTE: sid MUST be provided by the caller; function returns -1 if sid is NULL or sid_len==0.
*
* The zero-pad computation follows the guidance to make gen_str length deterministically meet s_in_bytes constraints.
  */
  static int calculate_generator_from_prs_with_sid(const unsigned char *PRS, size_t PRS_len,
  const unsigned char *sid, size_t sid_len,
  unsigned char *G_out) {
  if (!PRS || PRS_len == 0) return -1;
  if (!sid || sid_len == 0) return -1; /* sid is required in this design */

  const unsigned char *DSI = G_DSI;
  size_t DSI_len = sizeof(G_DSI) - 1;

  /* s_in_bytes chosen for zero-padding calculation: SHA-512 blocksize-related (128) */
  const size_t s_in_bytes = 128;

  /* compute prepend_len sizes */
  uint8_t tmp[10];
  size_t preDSI_len = leb128_encode_len(tmp, DSI_len);
  size_t prePRS_len = leb128_encode_len(tmp, PRS_len);
  size_t presid_len = leb128_encode_len(tmp, sid_len);

  /* len_zpad = max(0, s_in_bytes - 1 - preDSI_len - prePRS_len - presid_len) */
  size_t len_zpad = 0;
  if (s_in_bytes > 1 + preDSI_len + prePRS_len + presid_len) {
  len_zpad = s_in_bytes - 1 - preDSI_len - prePRS_len - presid_len;
  }

  /* allocate buffer precisely */
  size_t buf_cap = preDSI_len + DSI_len + prePRS_len + PRS_len + len_zpad + presid_len + sid_len;
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

  /* hash gen_str with SHA-512, then map to curve via ristretto-from-hash */
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

* Client initial step: generate scalar a, compute Y_A = a·G where G derived from PRS and caller-provided sid.
* Stores PRS and ADa/ADb and sid in ctx to allow Step3 to complete.
* Follows draft-irtf-cfrg-cpace-15 6.2 (client initial generation).
  */
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

  /* store PRS, ADs, sid */
  memcpy(ctx->PRS, PRS, PRS_len); ctx->PRS_len = PRS_len;
  if (ADa && ADa_len) { memcpy(ctx->ADa, ADa, ADa_len); ctx->ADa_len = ADa_len; } else { ctx->ADa_len = 0; }
  if (ADb && ADb_len) { memcpy(ctx->ADb, ADb, ADb_len); ctx->ADb_len = ADb_len; } else { ctx->ADb_len = 0; }
  memcpy(ctx->sid, sid, sid_len); ctx->sid_len = sid_len;

  unsigned char G[CRYPTO_CPACE_PUBLICBYTES];
  if (calculate_generator_from_prs_with_sid(ctx->PRS, ctx->PRS_len, ctx->sid, ctx->sid_len, G) != 0) return -1;

  /* generate ephemeral scalar and compute Y_A = a·G */
  crypto_core_ristretto255_scalar_random(ctx->scalar);
  if (crypto_scalarmult_ristretto255(public_data, ctx->scalar, G) != 0) {
  sodium_memzero(G, sizeof(G));
  return -1;
  }

  memcpy(ctx->public, public_data, CRYPTO_CPACE_PUBLICBYTES);
  sodium_memzero(G, sizeof(G));
  return 0;
  }

/* crypto_cpace_step2:

* Server step: derive G from PRS and caller-provided sid, sample b, compute Y_B=b·G, compute K=b·Y_A, construct transcript
* as lv_cat(Y_A, ADa) || lv_cat(Y_B, ADb) per draft-irtf-cfrg-cpace-15 3.1 and 6.2, derive ISK.
*
* sid is required and must match client-provided sid used in Step1.
  */
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

  unsigned char G[CRYPTO_CPACE_PUBLICBYTES];
  if (calculate_generator_from_prs_with_sid(PRS, PRS_len, sid, sid_len, G) != 0) return -1;

  unsigned char b[CRYPTO_CPACE_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(b);
  if (crypto_scalarmult_ristretto255(response, b, G) != 0) {
  sodium_memzero(G, sizeof(G));
  sodium_memzero(b, sizeof(b));
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

* Client finishes: uses cached sid in ctx (from Step1), re-derives K = a·Y_B, builds transcript using stored ADa/ADb
* per draft-irtf-cfrg-cpace-15 3.1 and 6.2, and derive ISK into shared_key.
*
* Note: Step3 does NOT accept sid parameter; it uses ctx->sid cached by Step1.
  */
  int crypto_cpace_step3(crypto_cpace_state *ctx,
  crypto_cpace_shared_keys *shared_keys,
  const unsigned char *response) {
  if (!ctx || !shared_keys || !response) return -1;
  if (ctx->PRS_len == 0) return -1; /* ensure Step1 stored PRS */
  if (ctx->sid_len == 0) return -1; /* sid must have been cached by Step1 */

  unsigned char G[CRYPTO_CPACE_PUBLICBYTES];
  if (calculate_generator_from_prs_with_sid(ctx->PRS, ctx->PRS_len, ctx->sid, ctx->sid_len, G) != 0) return -1;

  unsigned char K[CRYPTO_CPACE_PUBLICBYTES];
  if (crypto_scalarmult_ristretto255(K, ctx->scalar, response) != 0) {
  sodium_memzero(G, sizeof(G));
  sodium_memzero(K, sizeof(K));
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

/* securely clear context */
void crypto_cpace_clear(crypto_cpace_state *ctx) {
if (!ctx) return;
sodium_memzero(ctx->scalar, sizeof ctx->scalar);
sodium_memzero(ctx->public, sizeof ctx->public);
sodium_memzero(ctx->PRS, sizeof ctx->PRS);
ctx->PRS_len = 0;
if (ctx->ADa_len) { sodium_memzero(ctx->ADa, ctx->ADa_len); ctx->ADa_len = 0; }
if (ctx->ADb_len) { sodium_memzero(ctx->ADb, ctx->ADb_len); ctx->ADb_len = 0; }
if (ctx->sid_len) { sodium_memzero(ctx->sid, ctx->sid_len); ctx->sid_len = 0; }
}
