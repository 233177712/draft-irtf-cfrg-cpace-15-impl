/* File: crypto_cpace.h

* CPace PAKE (libsodium) - adjusted to draft-irtf-cfrg-cpace-15 references
*
* Conformance notes (referenced sections of the draft):
* * AD split into ADa / ADb per draft-irtf-cfrg-cpace-15 3.1.
* * Protocol flow (Step1/Step2/Step3) follows draft-irtf-cfrg-cpace-15 6.2.
* * Generator derivation and domain separation follows draft-irtf-cfrg-cpace-15 7.1.
* * ISK / key derivation follows draft-irtf-cfrg-cpace-15 6.2 and 7.2.
* * sid usage bound to caller: draft-irtf-cfrg-cpace-15 9.6 (sid as external input recommended).
*
* Design decisions:
* * sid MUST be provided by the caller to Step1 (client) and Step2 (server).
* Step1 caches sid in ctx->sid (client-side) and Step3 reads it from ctx (no sid parameter).
* There is NO automatic sid generation; caller is responsible for consistent sid bytes.
* (Per requested design alignment to draft-irtf-cfrg-cpace-15 9.6/9.1 semantics.)
*
* API:
* * crypto_cpace_init()
* * crypto_cpace_state (holds PRS, scalar, public, ADa, ADb, sid)
* * crypto_cpace_step1(...) -> produces Y_A (client), caches sid in ctx
* * crypto_cpace_step2(...) -> consumes Y_A, produces Y_B and shared_key (server must pass sid)
* * crypto_cpace_step3(...) -> consumes Y_B and ctx (client), produces shared_key (no sid param)
* * crypto_cpace_clear()
*
* Dependencies: libsodium
  */

#ifndef CRYPTO_CPACE_H
#define CRYPTO_CPACE_H

#include <sodium.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Sizes and limits (Ristretto255 + SHA-512 based choices per draft-irtf-cfrg-cpace-15) */
#define CRYPTO_CPACE_PUBLICBYTES    (crypto_core_ristretto255_BYTES)
#define CRYPTO_CPACE_SCALARBYTES    (crypto_core_ristretto255_SCALARBYTES)
#define CRYPTO_CPACE_SHAREDKEYBYTES 32U
#define CRYPTO_CPACE_MAX_SECRET_LEN 256
#define CRYPTO_CPACE_MAX_AD_LEN     256
#define CRYPTO_CPACE_SID_MAX_BYTES  (crypto_hash_sha512_BYTES) /* caller-provided sid max */

/* State structure

* * stores PRS (as in original user structure), scalar and public for client-side continuation (Step3).
* * stores ADa/ADb per draft-irtf-cfrg-cpace-15 3.1.
* * caches sid (provided by caller in Step1) - sid_len == 0 means no sid cached (caller MUST provide sid).
*
* NOTE: sid_present boolean removed per requested change; presence is determined by sid_len.
*
* draft refs:
* * draft-irtf-cfrg-cpace-15 3.1 (AD placement)
* * draft-irtf-cfrg-cpace-15 6.2 (step flow)
* * draft-irtf-cfrg-cpace-15 7.1 (generator derivation including optional CI/sid)
    */
    typedef struct {
    unsigned char scalar[CRYPTO_CPACE_SCALARBYTES]; /* a */
    unsigned char public[CRYPTO_CPACE_PUBLICBYTES]; /* Y_A */
    unsigned char PRS[CRYPTO_CPACE_MAX_SECRET_LEN];
    size_t PRS_len;
    unsigned char ADa[CRYPTO_CPACE_MAX_AD_LEN]; /* client's AD (per 3.1) */
    size_t ADa_len;
    unsigned char ADb[CRYPTO_CPACE_MAX_AD_LEN]; /* peer's AD (per 3.1) */
    size_t ADb_len;
    unsigned char sid[CRYPTO_CPACE_SID_MAX_BYTES]; /* cached sid bytes (public input) */
    size_t sid_len; /* 0 if not set; caller MUST provide sid to Step1/Step2 per design */
    } crypto_cpace_state;

/* single shared key (not split) - derived as ISK per draft-irtf-cfrg-cpace-15 6.2 */
typedef struct {
unsigned char shared_key[CRYPTO_CPACE_SHAREDKEYBYTES];
} crypto_cpace_shared_keys;

/* initialize libsodium */
int crypto_cpace_init(void);

/* Step1 (client)

* * outputs public_data (Y_A), length CRYPTO_CPACE_PUBLICBYTES
* * inputs PRS, ADa, ADb
* * inputs sid (required by caller) and caches it into ctx->sid for use in Step3
* * stores state in ctx for Step3
*
* Conforms to draft-irtf-cfrg-cpace-15 6.2 (client step) and uses generator derivation per 7.1.
  */
  int crypto_cpace_step1(crypto_cpace_state *ctx,
  unsigned char *public_data,
  const unsigned char *PRS, size_t PRS_len,
  const unsigned char *ADa, size_t ADa_len,
  const unsigned char *ADb, size_t ADb_len,
  const unsigned char *sid, size_t sid_len);

/* Step2 (server)

* * inputs public_data (Y_A)
* * outputs response (Y_B) and shared_keys (single shared key)
* * inputs PRS, ADa, ADb
* * inputs sid (required; must match client's sid)
*
* Conforms to draft-irtf-cfrg-cpace-15 6.2 (server step).
  */
  int crypto_cpace_step2(unsigned char *response,
  const unsigned char *public_data,
  crypto_cpace_shared_keys *shared_keys,
  const unsigned char *PRS, size_t PRS_len,
  const unsigned char *ADa, size_t ADa_len,
  const unsigned char *ADb, size_t ADb_len,
  const unsigned char *sid, size_t sid_len);

/* Step3 (client)

* * inputs ctx (from Step1 which cached sid) and response (Y_B)
* * outputs shared_keys
*
* Conforms to draft-irtf-cfrg-cpace-15 6.2 (client finishing step).
* Note: Step3 does NOT take sid parameter; it uses ctx->sid cached in Step1.
  */
  int crypto_cpace_step3(crypto_cpace_state *ctx,
  crypto_cpace_shared_keys *shared_keys,
  const unsigned char *response);

/* securely clear ctx */
void crypto_cpace_clear(crypto_cpace_state *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_CPACE_H */
