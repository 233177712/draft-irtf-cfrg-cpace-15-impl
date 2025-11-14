/* File: crypto_cpace.h
 * CPace PAKE (libsodium) - updated to draft-irtf-cfrg-cpace-15
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

#define CRYPTO_CPACE_PUBLICBYTES    (crypto_core_ristretto255_BYTES)
#define CRYPTO_CPACE_SCALARBYTES    (crypto_core_ristretto255_SCALARBYTES)
#define CRYPTO_CPACE_SHAREDKEYBYTES 32U
#define CRYPTO_CPACE_MAX_SECRET_LEN 256
#define CRYPTO_CPACE_MAX_AD_LEN     256

typedef struct {
    unsigned char scalar[CRYPTO_CPACE_SCALARBYTES]; /* a */
    unsigned char public[CRYPTO_CPACE_PUBLICBYTES]; /* Y_A */
    unsigned char PRS[CRYPTO_CPACE_MAX_SECRET_LEN];
    size_t PRS_len;
    unsigned char ADa[CRYPTO_CPACE_MAX_AD_LEN];
    size_t ADa_len;
    unsigned char ADb[CRYPTO_CPACE_MAX_AD_LEN];
    size_t ADb_len;
} crypto_cpace_state;

/* single shared key (not split) */
typedef struct {
    unsigned char shared_key[CRYPTO_CPACE_SHAREDKEYBYTES];
} crypto_cpace_shared_keys;

/* initialize libsodium */
int crypto_cpace_init(void);

/* Step1 (client)
 * - outputs public_data (Y_A), length CRYPTO_CPACE_PUBLICBYTES
 * - inputs PRS, ADa, ADb (ADa is client's AD, ADb is peer's AD if known; can pass NULL/0)
 * - stores state in ctx for Step3
 */
int crypto_cpace_step1(crypto_cpace_state *ctx,
                       unsigned char *public_data,
                       const unsigned char *PRS, size_t PRS_len,
                       const unsigned char *ADa, size_t ADa_len,
                       const unsigned char *ADb, size_t ADb_len);

/* Step2 (server)
 * - inputs public_data (Y_A)
 * - outputs response (Y_B) and shared_keys (single shared key)
 * - inputs PRS, ADa, ADb
 */
int crypto_cpace_step2(unsigned char *response,
                       const unsigned char *public_data,
                       crypto_cpace_shared_keys *shared_keys,
                       const unsigned char *PRS, size_t PRS_len,
                       const unsigned char *ADa, size_t ADa_len,
                       const unsigned char *ADb, size_t ADb_len);

/* Step3 (client)
 * - inputs ctx (from Step1) and response (Y_B)
 * - outputs shared_keys
 */
int crypto_cpace_step3(crypto_cpace_state *ctx,
                       crypto_cpace_shared_keys *shared_keys,
                       const unsigned char *response);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_CPACE_H */
