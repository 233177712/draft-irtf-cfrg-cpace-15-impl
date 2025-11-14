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

/* State structure (revised)
 * - store ephemeral scalar & public (Y_A)
 * - store derived generator G (public) so client does NOT need to retain PRS
 * - ADa/ADb kept as before
 */
typedef struct {
    unsigned char scalar[CRYPTO_CPACE_SCALARBYTES]; /* a */
    unsigned char public[CRYPTO_CPACE_PUBLICBYTES]; /* Y_A */
    unsigned char G[CRYPTO_CPACE_PUBLICBYTES];      /* derived generator (public) */
    int           G_present;                       /* 0/1 flag */
    /* Optional: PRS removed to avoid keeping secret in memory. If application wants to keep PRS, add it explicitly. */
    unsigned char ADa[CRYPTO_CPACE_MAX_AD_LEN]; /* client's AD (per 3.1) */
    size_t ADa_len;
    unsigned char ADb[CRYPTO_CPACE_MAX_AD_LEN]; /* peer's AD (per 3.1) */
    size_t ADb_len;
} crypto_cpace_state;

/* single shared key (not split) - derived as ISK per draft-irtf-cfrg-cpace-15 6.2 */
typedef struct {
    unsigned char shared_key[CRYPTO_CPACE_SHAREDKEYBYTES];
} crypto_cpace_shared_keys;

void crypto_cpace_clear(crypto_cpace_state *ctx);
/* initialize libsodium */
int crypto_cpace_init(void);

/* Step1 (client)
 * - outputs public_data (Y_A), length CRYPTO_CPACE_PUBLICBYTES
 * - inputs PRS, ADa, ADb (ADa is client's AD, ADb is peer's AD if known)
 * - stores state in ctx for Step3
 *
 * Conforms to draft-irtf-cfrg-cpace-15 6.2 (client step) and uses generator derivation per 7.1.
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
 *
 * Conforms to draft-irtf-cfrg-cpace-15 6.2 (server step).
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
 *
 * Conforms to draft-irtf-cfrg-cpace-15 6.2 (client finishing step).
 */
int crypto_cpace_step3(crypto_cpace_state *ctx,
                       crypto_cpace_shared_keys *shared_keys,
                       const unsigned char *response);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_CPACE_H */
