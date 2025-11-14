#include "crypto_cpace.h"
#include <string.h>
#include <sodium.h>

/* 域分隔标识 (Domain Separation Identifier) */
static const unsigned char G_DSI[] = "CPaceRistretto255";
/* 用于密钥派生时的标签 */
static const unsigned char LABEL_ISK[] = "_ISK";

/* --- 内部辅助函数：LEB128 编码 --- */
static size_t le128_encode(uint8_t *dest, size_t len) {
    size_t idx = 0;
    uint64_t value = (uint64_t)len;
    do {
        uint8_t byte = value & 0x7F;
        value >>= 7;
        if (value > 0) byte |= 0x80;
        dest[idx++] = byte;
    } while (value > 0);
    return idx;
}

/* lv_cat：将多个 (length||value) 串联到 out 中 */
static size_t lv_cat(const unsigned char **parts, const size_t *part_lens, int count, unsigned char *out) {
    size_t offset = 0;
    for (int i = 0; i < count; i++) {
        uint8_t lenbuf[10];
        size_t len = part_lens[i];
        size_t len_bytes = le128_encode(lenbuf, len);
        memcpy(out + offset, lenbuf, len_bytes);
        offset += len_bytes;
        memcpy(out + offset, parts[i], len);
        offset += len;
    }
    return offset;
}

/* 根据 draft-15 7.1节计算生成器 g = G.calculate_generator(...):
 * gen_str = lv_cat(DSI, PRS, zero_pad, CI, sid)，然后点化到曲线上。
 * 此处将 client_id||server_id 拼接作为 CI，sid 设置为空。
 */
static int calculate_generator(const crypto_cpace_state *ctx, unsigned char *G) {
    unsigned char zero_pad[512] = {0};
    size_t s_in = crypto_hash_sha512_BYTES; /* SHA-512 输出长度 */
    /* 计算零填充长度，使得 DSI||PRS 等填充到一个 Hash 块 */
    size_t len_zpad = 0;
    size_t DSI_len = sizeof(G_DSI) - 1;
    size_t PRS_len = ctx->PRS_len;
    if (s_in > 1 + (1 + PRS_len) + (1 + DSI_len)) {
        len_zpad = s_in - 1 - (1 + PRS_len) - (1 + DSI_len);
    }
    /* 构造 CI = client_id || server_id */
    size_t ci_len = ctx->client_id_len + ctx->server_id_len;
    unsigned char *ci = NULL;
    if (ci_len > 0) {
        ci = (unsigned char *)sodium_alloc(ci_len);
        if (!ci) return -1;
        memcpy(ci, ctx->client_id, ctx->client_id_len);
        memcpy(ci + ctx->client_id_len, ctx->server_id, ctx->server_id_len);
    }
    /* 准备 lv_cat 的输入部分 */
    const unsigned char *parts[5];
    size_t lengths[5];
    parts[0] = G_DSI;         lengths[0] = DSI_len;
    parts[1] = ctx->PRS;      lengths[1] = ctx->PRS_len;
    parts[2] = zero_pad;      lengths[2] = len_zpad;
    parts[3] = ci ? ci : (unsigned char *)""; lengths[3] = ci_len;
    parts[4] = (unsigned char *)"";         lengths[4] = 0; /* sid 为空 */
    /* 拼接生成器字符串 */
    size_t buf_len = lengths[0] + lengths[1] + lengths[2] + lengths[3] + 50;
    unsigned char *gen_str = (unsigned char *)sodium_alloc(buf_len);
    if (!gen_str) { if (ci) sodium_free(ci); return -1; }
    size_t gen_len = lv_cat(parts, lengths, 5, gen_str);
    /* 对 gen_str 取 SHA-512 哈希 */
    unsigned char hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(hash, gen_str, gen_len);
    /* 使用 Ristretto 哈希映射到群上 */
    if (crypto_core_ristretto255_from_hash(G, hash) != 0) {
        if (ci) sodium_free(ci);
        sodium_free(gen_str);
        return -1;
    }
    if (ci) sodium_free(ci);
    sodium_free(gen_str);
    return 0;
}

/* 构造 transcript_ir(Ya, ADa, Yb, ADb) */
static size_t build_transcript(const unsigned char *YA, const unsigned char *ADa, size_t ADa_len,
                               const unsigned char *YB, const unsigned char *ADb, size_t ADb_len,
                               unsigned char *out) {
    const unsigned char *parts1[2] = { YA, ADa };
    size_t len1[2] = { crypto_cpace_PUBLICDATABYTES, ADa_len };
    size_t off = lv_cat(parts1, len1, 2, out);
    const unsigned char *parts2[2] = { YB, ADb };
    size_t len2[2] = { crypto_cpace_RESPONSEBYTES, ADb_len };
    off += lv_cat(parts2, len2, 2, out + off);
    return off;
}

int crypto_cpace_init(void) {
    return sodium_init() < 0 ? -1 : 0;
}

int crypto_cpace_step1(crypto_cpace_state *ctx,
                       unsigned char *public_data,
                       const unsigned char *PRS, size_t PRS_len,
                       const unsigned char *client_id, size_t client_id_len,
                       const unsigned char *server_id, size_t server_id_len,
                       const unsigned char *ad, size_t ad_len) {
    if (!ctx || !public_data) return -1;
    /* 保存输入到 ctx */
    if (PRS_len > sizeof(ctx->PRS) || client_id_len > sizeof(ctx->client_id) ||
        server_id_len > sizeof(ctx->server_id) || ad_len > sizeof(ctx->ad)) {
        return -1;
    }
    memcpy(ctx->PRS, PRS, PRS_len);    ctx->PRS_len = PRS_len;
    memcpy(ctx->client_id, client_id, client_id_len); ctx->client_id_len = client_id_len;
    memcpy(ctx->server_id, server_id, server_id_len); ctx->server_id_len = server_id_len;
    memcpy(ctx->ad, ad, ad_len);       ctx->ad_len = ad_len;
    /* 计算生成器 G */
    unsigned char G[crypto_core_ristretto255_BYTES];
    if (calculate_generator(ctx, G) != 0) return -1;
    /* 生成随机标量 a 并计算 Y_A = a·G */
    crypto_core_ristretto255_scalar_random(ctx->scalar);
    if (crypto_scalarmult_ristretto255(public_data, ctx->scalar, G) != 0) {
        return -1;
    }
    /* 将 Y_A 存入上下文，供 Step3 使用 */
    memcpy(ctx->public, public_data, crypto_cpace_PUBLICDATABYTES);
    return 0;
}

int crypto_cpace_step2(unsigned char *response,
                       const unsigned char *public_data,
                       crypto_cpace_shared_keys *shared_keys,
                       const unsigned char *PRS, size_t PRS_len,
                       const unsigned char *client_id, size_t client_id_len,
                       const unsigned char *server_id, size_t server_id_len,
                       const unsigned char *ad, size_t ad_len) {
    if (!response || !public_data || !shared_keys) return -1;
    /* 临时构造服务端 ctx */
    crypto_cpace_state srv_ctx;
    if (PRS_len > sizeof(srv_ctx.PRS) || client_id_len > sizeof(srv_ctx.client_id) ||
        server_id_len > sizeof(srv_ctx.server_id) || ad_len > sizeof(srv_ctx.ad)) {
        return -1;
    }
    memcpy(srv_ctx.PRS, PRS, PRS_len);    srv_ctx.PRS_len = PRS_len;
    memcpy(srv_ctx.client_id, client_id, client_id_len); srv_ctx.client_id_len = client_id_len;
    memcpy(srv_ctx.server_id, server_id, server_id_len); srv_ctx.server_id_len = server_id_len;
    memcpy(srv_ctx.ad, ad, ad_len);       srv_ctx.ad_len = ad_len;
    /* 计算 G */
    unsigned char G[crypto_core_ristretto255_BYTES];
    if (calculate_generator(&srv_ctx, G) != 0) return -1;
    /* 随机标量 b，计算 Y_B = b·G */
    unsigned char b[crypto_core_ristretto255_SCALARBYTES];
    crypto_core_ristretto255_scalar_random(b);
    if (crypto_scalarmult_ristretto255(response, b, G) != 0) return -1;
    /* 计算共享秘密 K = b·Y_A */
    unsigned char K[crypto_core_ristretto255_BYTES];
    if (crypto_scalarmult_ristretto255(K, b, public_data) != 0) {
        return -1; /* 避免零元 */
    }
    /* 构造 transcript = lv_cat(Y_A, AD) || lv_cat(Y_B, AD) */
    unsigned char transcript[1024];
    size_t trans_len = build_transcript(public_data, ad, ad_len,
                                        response, ad, ad_len, transcript);
    /* 密钥派生：HASH( DSI || "_ISK" || K || transcript ) */
    unsigned char hash_input[128] = {0};
    size_t prefix_len = 0;
    /* 前缀 = DSI || "_ISK" */
    size_t dsi_len = sizeof(G_DSI) - 1;
    memcpy(hash_input, G_DSI, dsi_len);
    prefix_len += dsi_len;
    memcpy(hash_input + prefix_len, LABEL_ISK, sizeof(LABEL_ISK)-1);
    prefix_len += sizeof(LABEL_ISK)-1;
    /* 计算 SHA-512(hash_input || K || transcript) */
    crypto_hash_sha512_state sha;
    crypto_hash_sha512_init(&sha);
    crypto_hash_sha512_update(&sha, hash_input, prefix_len);
    crypto_hash_sha512_update(&sha, K, crypto_core_ristretto255_BYTES);
    crypto_hash_sha512_update(&sha, transcript, trans_len);
    unsigned char isk[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_final(&sha, isk);
    /* 分裂输出：前32字节为客户端密钥，后32字节为服务端密钥 */
    memcpy(shared_keys->client_sk, isk, crypto_cpace_SHAREDKEYBYTES);
    memcpy(shared_keys->server_sk, isk + crypto_cpace_SHAREDKEYBYTES, crypto_cpace_SHAREDKEYBYTES);
    return 0;
}

int crypto_cpace_step3(crypto_cpace_state *ctx,
                       crypto_cpace_shared_keys *shared_keys,
                       const unsigned char *response) {
    if (!ctx || !shared_keys || !response) return -1;
    /* 重新计算生成器 G */
    unsigned char G[crypto_core_ristretto255_BYTES];
    if (calculate_generator(ctx, G) != 0) return -1;
    /* 计算共享秘密 K = a·Y_B */
    unsigned char K[crypto_core_ristretto255_BYTES];
    if (crypto_scalarmult_ristretto255(K, ctx->scalar, response) != 0) return -1;
    /* 构造 transcript = lv_cat(Y_A, AD) || lv_cat(Y_B, AD) */
    unsigned char transcript[1024];
    size_t trans_len = build_transcript(ctx->public, ctx->ad, ctx->ad_len,
                                        response, ctx->ad, ctx->ad_len, transcript);
    /* 密钥派生同上 */
    unsigned char hash_input[128] = {0};
    size_t prefix_len = 0;
    size_t dsi_len = sizeof(G_DSI) - 1;
    memcpy(hash_input, G_DSI, dsi_len);
    prefix_len += dsi_len;
    memcpy(hash_input + prefix_len, LABEL_ISK, sizeof(LABEL_ISK)-1);
    prefix_len += sizeof(LABEL_ISK)-1;
    crypto_hash_sha512_state sha;
    crypto_hash_sha512_init(&sha);
    crypto_hash_sha512_update(&sha, hash_input, prefix_len);
    crypto_hash_sha512_update(&sha, K, crypto_core_ristretto255_BYTES);
    crypto_hash_sha512_update(&sha, transcript, trans_len);
    unsigned char isk[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_final(&sha, isk);
    memcpy(shared_keys->client_sk, isk, crypto_cpace_SHAREDKEYBYTES);
    memcpy(shared_keys->server_sk, isk + crypto_cpace_SHAREDKEYBYTES, crypto_cpace_SHAREDKEYBYTES);
    return 0;
}
