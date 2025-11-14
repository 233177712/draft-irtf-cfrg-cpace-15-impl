#ifndef CRYPTO_CPACE_H
#define CRYPTO_CPACE_H

#include <sodium.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Sizes (Ristretto255 + SHA-512 per draft-irtf-cfrg-cpace-15) */
#define CRYPTO_CPACE_PUBLICBYTES    (crypto_core_ristretto255_BYTES)
#define CRYPTO_CPACE_SCALARBYTES    (crypto_core_ristretto255_SCALARBYTES)
#define CRYPTO_CPACE_SHAREDKEYBYTES 32U
#define CRYPTO_CPACE_MAX_SECRET_LEN 256
#define CRYPTO_CPACE_MAX_AD_LEN     256
#define CRYPTO_CPACE_SID_MAX_BYTES  (crypto_hash_sha512_BYTES) /* caller-provided SID max */

/* State structure (draft-irtf-cfrg-cpace-15 3.1 / 6.2 / 7.1 / 9.6) */
typedef struct {
unsigned char scalar[CRYPTO_CPACE_SCALARBYTES]; /* a */
unsigned char public[CRYPTO_CPACE_PUBLICBYTES]; /* Y_A */
unsigned char PRS[CRYPTO_CPACE_MAX_SECRET_LEN];
size_t PRS_len;
unsigned char ADa[CRYPTO_CPACE_MAX_AD_LEN]; /* client's AD (3.1) */
size_t ADa_len;
unsigned char ADb[CRYPTO_CPACE_MAX_AD_LEN]; /* peer's AD (3.1) */
size_t ADb_len;
unsigned char sid[CRYPTO_CPACE_SID_MAX_BYTES]; /* cached sid bytes (public input) */
size_t sid_len; /* 0 if not set; caller MUST provide sid to Step1/Step2 per design (9.6) */
} crypto_cpace_state;

/* single shared key (ISK-derived, draft-irtf-cfrg-cpace-15 6.2/7.2) */
typedef struct {
unsigned char shared_key[CRYPTO_CPACE_SHAREDKEYBYTES];
} crypto_cpace_shared_keys;

/* initialize libsodium */
int crypto_cpace_init(void);

/* Step1 (client) - draft-irtf-cfrg-cpace-15 6.2 */
int crypto_cpace_step1(crypto_cpace_state *ctx,
unsigned char *public_data,
const unsigned char *PRS, size_t PRS_len,
const unsigned char *ADa, size_t ADa_len,
const unsigned char *ADb, size_t ADb_len,
const unsigned char *sid, size_t sid_len);

/* Step2 (server) - draft-irtf-cfrg-cpace-15 6.2 */
int crypto_cpace_step2(unsigned char *response,
const unsigned char *public_data,
crypto_cpace_shared_keys *shared_keys,
const unsigned char *PRS, size_t PRS_len,
const unsigned char *ADa, size_t ADa_len,
const unsigned char *ADb, size_t ADb_len,
const unsigned char *sid, size_t sid_len);

/* Step3 (client) - draft-irtf-cfrg-cpace-15 6.2 */
int crypto_cpace_step3(crypto_cpace_state *ctx,
crypto_cpace_shared_keys *shared_keys,
const unsigned char *response);

/* securely clear ctx */
void crypto_cpace_clear(crypto_cpace_state *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_CPACE_H */
