/* File: crypto_cpace.h
 * CPace PAKE (libsodium) - updated to draft-irtf-cfrg-cpace-15
 *
 * Conformance notes (referenced sections of the draft):
 *  - AD split into ADa / ADb per draft-irtf-cfrg-cpace-15 3.1.
 *  - Protocol flow (Step1/Step2/Step3) follows draft-irtf-cfrg-cpace-15 6.2.
 *  - Generator derivation and domain separation follows draft-irtf-cfrg-cpace-15 7.1.
 *  - Key derivation (ISK construction) follows draft-irtf-cfrg-cpace-15 6.2 and 7.2.
 *
 * API:
 *  - crypto_cpace_init()
 *  - crypto_cpace_state (holds PRS, scalar, public, ADa, ADb)
 *  - crypto_cpace_step1(...) -> produces Y_A
 *  - crypto_cpace_step2(...) -> consumes Y_A, produces Y_B and shared_key
 *  - crypto_cpace_step3(...) -> consumes Y_B and ctx, produces shared_key
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
/* added SID support per draft-irtf-cfrg-cpace-15 sections 3.1, 7.1 and 9.6 */
/* crypto_cpace.h — relevant excerpts reflecting forced sid input and caching */
#define CRYPTO_CPACE_SID_MAX_BYTES   (crypto_hash_sha512_BYTES) /* max sid bytes accepted */

/* State structure: client-side caches G and sid (public) */
typedef struct {
    unsigned char scalar[CRYPTO_CPACE_SCALARBYTES]; /* a */
    unsigned char public[CRYPTO_CPACE_PUBLICBYTES]; /* Y_A */
    unsigned char G[CRYPTO_CPACE_PUBLICBYTES];      /* derived generator (public) */
    int           G_present;
    /* cached sid provided at step1 (public, not secret) */
    unsigned char sid[CRYPTO_CPACE_SID_MAX_BYTES];
    size_t        sid_len;
    int           sid_present;
    unsigned char ADa[CRYPTO_CPACE_MAX_AD_LEN];
    size_t ADa_len;
    unsigned char ADb[CRYPTO_CPACE_MAX_AD_LEN];
    size_t ADb_len;
} crypto_cpace_state;

/* Shared key result — no sid_output, only single shared_key */
typedef struct {
    unsigned char shared_key[CRYPTO_CPACE_SHAREDKEYBYTES];
} crypto_cpace_shared_keys;

/* API:
 * - client step1 must provide sid (cached in ctx)
 * - server step2 must provide same sid
 * - client step3 reads sid from ctx (no sid param)
 */
int crypto_cpace_step1(crypto_cpace_state *ctx,
                       unsigned char *public_data,
                       const unsigned char *PRS, size_t PRS_len,
                       const unsigned char *ADa, size_t ADa_len,
                       const unsigned char *ADb, size_t ADb_len,
                       const unsigned char *sid, size_t sid_len);

int crypto_cpace_step2(unsigned char *response,
                       const unsigned char *public_data,
                       crypto_cpace_shared_keys *shared_keys,
                       const unsigned char *PRS, size_t PRS_len,
                       const unsigned char *ADa, size_t ADa_len,
                       const unsigned char *ADb, size_t ADb_len,
                       const unsigned char *sid, size_t sid_len);

/* note: step3 no longer takes sid; it uses ctx->sid */
int crypto_cpace_step3(crypto_cpace_state *ctx,
                       crypto_cpace_shared_keys *shared_keys,
                       const unsigned char *response);

/* clear ctx securely */
void crypto_cpace_clear(crypto_cpace_state *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_CPACE_H */
