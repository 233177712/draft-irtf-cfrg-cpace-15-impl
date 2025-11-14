/*
 * CPace PAKE implementation (libsodium + C) updated to draft-irtf-cfrg-cpace-15.
 * Dependencies: libsodium 1.0.18+ (支持 Ristretto255 和 SHA-512).
 */

#ifndef CRYPTO_CPACE_H
#define CRYPTO_CPACE_H

#include <sodium.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 输出长度参数 */
#define crypto_cpace_PUBLICDATABYTES 32U  /* Y_A 和 Y_B 的字节长度（Ristretto255 编码） */
#define crypto_cpace_RESPONSEBYTES   32U  /* Step2 响应数据长度 */
#define crypto_cpace_SHAREDKEYBYTES  32U  /* 单个共享密钥长度（256-bit） */

/* CPace 客户端状态：保存口令、身份、随机标量和公钥 */
typedef struct {
    unsigned char scalar[crypto_core_ristretto255_SCALARBYTES]; /* 客户端随机标量 a */
    unsigned char public[crypto_cpace_PUBLICDATABYTES];         /* 客户端公钥 Y_A = a·g */
    unsigned char PRS[256];    /* 共享口令/秘密，最大255字节 */
    size_t PRS_len;
    unsigned char client_id[256]; /* 客户端标识 (ID) */
    size_t client_id_len;
    unsigned char server_id[256]; /* 服务端标识 (ID) */
    size_t server_id_len;
    unsigned char ad[256];       /* 可选关联数据 (AD) */
    size_t ad_len;
} crypto_cpace_state;

/* 共享密钥结果：client_sk 从客户端视角的密钥，server_sk 从服务端视角的密钥 */
typedef struct {
    unsigned char client_sk[crypto_cpace_SHAREDKEYBYTES];
    unsigned char server_sk[crypto_cpace_SHAREDKEYBYTES];
} crypto_cpace_shared_keys;

/* 初始化函数：调用 sodium_init() */
int crypto_cpace_init(void);

/* Step1 (客户端):
 * 输入：PRS, client_id, server_id, AD
 * 输出：public_data (长度 crypto_cpace_PUBLICDATABYTES 的 Y_A)
 * 作用：生成随机 a, 计算 g = calculate_generator(...), Y_A = a·g，并保存状态 (scalar, 公钥等)。
 */
int crypto_cpace_step1(crypto_cpace_state *ctx,
                       unsigned char *public_data,
                       const unsigned char *PRS, size_t PRS_len,
                       const unsigned char *client_id, size_t client_id_len,
                       const unsigned char *server_id, size_t server_id_len,
                       const unsigned char *ad, size_t ad_len);

/* Step2 (服务端):
 * 输入：客户端公钥 public_data (Y_A), PRS, client_id, server_id, AD
 * 输出：response (长度 crypto_cpace_RESPONSEBYTES 的 Y_B) 和 shared_keys
 * 作用：生成随机 b, 计算 Y_B = b·g, 共享密钥 K = b·Y_A, 构造 transcript, 派生共享密钥对。
 */
int crypto_cpace_step2(unsigned char *response,
                       const unsigned char *public_data,
                       crypto_cpace_shared_keys *shared_keys,
                       const unsigned char *PRS, size_t PRS_len,
                       const unsigned char *client_id, size_t client_id_len,
                       const unsigned char *server_id, size_t server_id_len,
                       const unsigned char *ad, size_t ad_len);

/* Step3 (客户端):
 * 输入：ctx (包含 Step1 的输出状态), 服务端响应 response (Y_B)
 * 输出：shared_keys
 * 作用：计算共享密钥 K = a·Y_B, 构造 transcript, 派生共享密钥对。
 */
int crypto_cpace_step3(crypto_cpace_state *ctx,
                       crypto_cpace_shared_keys *shared_keys,
                       const unsigned char *response);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_CPACE_H */
