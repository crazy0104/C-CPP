//
// Created by iwall on 2019-11-18.
//
// Version: 1.1
// Author: Kong

#include "aes_crypto.h"
#include <string.h>

int aes_init(AES_CTX *ctx,
             const unsigned char *key,
             int keylen,
             const unsigned char *iv,
             const unsigned char *ecount,
             int mode,
             int enc)
{
    int rv = 0;
    if (ctx == NULL || key == NULL)
        return CRYPTO_ERR_AES_INVALID_INPUT;

    memset(ctx->ctx, 0x00, sizeof(aes_context));
    ctx->key      = (unsigned char *)key;
    ctx->num      = 0;
    switch (enc) {
        case CRYPTO_AES_ENCRYPT:
            ctx->encrypt = CRYPTO_AES_ENCRYPT;
            break;
        case CRYPTO_AES_DECRYPT:
            ctx->encrypt = CRYPTO_AES_DECRYPT;
            break;
        default:
            return CRYPTO_ERR_AES_INVALID_INPUT;
    }

    switch (mode) {
        case AES_ECB:
        case AES_CBC:
            if (enc)
                rv = aes_setkey_enc(ctx->ctx, key, keylen * 8);
            else
                rv = aes_setkey_dec(ctx->ctx, key, keylen * 8);
            break;
        case AES_CFB:
        case AES_OFB:
        case AES_CTR:
            rv = aes_setkey_enc(ctx->ctx, key, keylen * 8);
            break;
        default:
            return CRYPTO_ERR_AES_INVALID_INPUT;
    }
    ctx->mode     = mode;

    if (iv)
        memcpy(ctx->iv, iv, AES_MAX_IV_LENGTH);
    if (ecount)
        memcpy(ctx->ecount, iv, AES_MAX_COUNT_LENGTH);
    return rv;
}

int aes_update(AES_CTX *ctx,
               const unsigned char *in, int inlen,
               unsigned char *out, int *outlen)
{
    int rv = 0;
    unsigned int b = 0;
    int l = 0;
    if (ctx == NULL || in == NULL || out == NULL)
        return CRYPTO_ERR_AES_INVALID_INPUT;

    if (inlen < 0 || *outlen < 0)
        return CRYPTO_ERR_AES_INVALID_INPUT;

    if (*outlen < inlen)
        return CRYPTO_ERR_AES_BUFFER_TOO_SMALL;

    b = inlen % AES_BLOCK_SIZE;
    l = inlen - b;
    if (l >= AES_BLOCK_SIZE) {
        switch (ctx->mode) {
            case AES_ECB :
                b = inlen % AES_BLOCK_SIZE;
                rv = aes_crypt_ecb(ctx->ctx, ctx->encrypt, inlen - b, (unsigned char *)in, out);
                break;
            case AES_CBC:
                b = inlen % AES_BLOCK_SIZE;
                rv = aes_crypt_cbc(ctx->ctx, ctx->encrypt, inlen - b, ctx->iv, in, out);
                break;
            case AES_CFB:
                rv = aes_crypt_cfb(ctx->ctx, ctx->encrypt, inlen, ctx->iv, &ctx->num, in, out);
                break;
            case AES_OFB:
                rv = aes_crypt_ofb(ctx->ctx, ctx->encrypt, inlen, ctx->iv, &ctx->num, in, out);
                break;
            case AES_CTR:
                rv = aes_crypt_ctr128(ctx->ctx, ctx->encrypt, inlen, ctx->iv, ctx->ecount, &ctx->num, in, out);
                break;
            default:
                return CRYPTO_ERR_AES_INVALID_INPUT;
        }
    } else {
        rv = 0;
    }
    if (b)
        memcpy(ctx->buf, in + inlen - b, b);
    ctx->buf_len = b;
    *outlen = inlen - b;
    return rv;
}

int aes_final(AES_CTX *ctx, unsigned char *out, int *outlen)
{
    int rv = 0;
    int n, i, b, bl;

    if (ctx == NULL || out == NULL)
        return CRYPTO_ERR_AES_INVALID_INPUT;

    if (*outlen < 0)
        return CRYPTO_ERR_AES_INVALID_INPUT;

    b = AES_BLOCK_SIZE;
    bl = ctx->buf_len;

    n = b - bl;
    for (i = bl; i < b; ++i)
        ctx->buf[i] = n;

    if (ctx->encrypt == CRYPTO_AES_ENCRYPT) {
        switch (ctx->mode) {
            case AES_ECB :
                rv = aes_crypt_ecb(ctx->ctx, CRYPTO_AES_ENCRYPT, AES_BLOCK_SIZE, (unsigned char *) ctx->buf, out + *outlen);
                *outlen += b;
                break;
            case AES_CBC:
                rv = aes_crypt_cbc(ctx->ctx, CRYPTO_AES_ENCRYPT, AES_BLOCK_SIZE, ctx->iv, ctx->buf, out + *outlen);
                *outlen += b;
                break;
            case AES_CFB:
            case AES_OFB:
            case AES_CTR:
                rv = 0;
                break;
            default:
                return CRYPTO_ERR_AES_INVALID_INPUT;
        }
    } else {
        switch (ctx->mode) {
            case AES_ECB:
            case AES_CBC:
                bl = out[*outlen - 1];
                if (bl > b) {
                    return CRYPTO_ERR_AES_INVALID_INPUT;
                }
                for (i = *outlen - 1; i > *outlen - bl - 1; i--)
                    out[i] = 0x00;
                *outlen -= bl;
                break;
            case AES_CFB:
            case AES_OFB:
            case AES_CTR:
                break;
            default:
                return CRYPTO_ERR_AES_INVALID_INPUT;
        }
    }

    return rv;
}



int aes_encrypt_ecb(const unsigned char *key, int keylen,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen) {
    int rv = 0;

    AES_CTX ctx = {0};
    rv = aes_init(&ctx, key, keylen, NULL, NULL, AES_ECB, CRYPTO_AES_ENCRYPT);
    if (rv)
        return rv;
    rv = aes_update(&ctx, in, inlen, out, outlen);
    if (rv)
        return rv;
    rv = aes_final(&ctx, out, outlen);
    return rv;
}

int aes_decrypt_ecb(const unsigned char *key, int keylen,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen) {
    int rv = 0;
    AES_CTX ctx = {0};
    rv = aes_init(&ctx, key, keylen, NULL, NULL, AES_ECB, CRYPTO_AES_DECRYPT);
    if (rv)
        return rv;
    rv = aes_update(&ctx, in, inlen, out, outlen);
    if (rv)
        return rv;
    rv = aes_final(&ctx, out, outlen);
    return rv;
}

int aes_encrypt_cbc(const unsigned char *key, int keylen,
                    const unsigned char *iv,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen) {

    int rv = 0;
    AES_CTX ctx = {0};
    rv = aes_init(&ctx, key, keylen, iv, NULL, AES_CBC, CRYPTO_AES_ENCRYPT);
    if (rv)
        return rv;
    rv = aes_update(&ctx, in, inlen, out, outlen);
    if (rv)
        return rv;
    rv = aes_final(&ctx, out, outlen);
    return rv;
}

int aes_decrypt_cbc(const unsigned char *key, int keylen,
                    const unsigned char *iv,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen) {
    int rv = 0;
    AES_CTX ctx = {0};
    rv = aes_init(&ctx, key, keylen, iv, NULL, AES_CBC, CRYPTO_AES_DECRYPT);
    if (rv)
        return rv;
    rv = aes_update(&ctx, in, inlen, out, outlen);
    if (rv)
        return rv;
    rv = aes_final(&ctx, out, outlen);
    return rv;
}


int aes_encrypt_cfb(const unsigned char *key, int keylen,
                    const unsigned char *iv,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen) {
    int rv = 0;
    AES_CTX ctx = {0};
    rv = aes_init(&ctx, key, keylen, iv, NULL, AES_CFB, CRYPTO_AES_ENCRYPT);
    if (rv)
        return rv;
    rv = aes_update(&ctx, in, inlen, out, outlen);
    if (rv)
        return rv;
    rv = aes_final(&ctx, out, outlen);
    return rv;
}

int aes_decrypt_cfb(const unsigned char *key, int keylen,
                    const unsigned char *iv,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen) {
    int rv = 0;
    AES_CTX ctx = {0};
    rv = aes_init(&ctx, key, keylen, iv, NULL, AES_CFB, CRYPTO_AES_DECRYPT);
    if (rv)
        return rv;
    rv = aes_update(&ctx, in, inlen, out, outlen);
    if (rv)
        return rv;
    rv = aes_final(&ctx, out, outlen);
    return rv;
}

int aes_encrypt_ofb(const unsigned char *key, int keylen,
                    const unsigned char *iv,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen) {
    int rv = 0;
    AES_CTX ctx = {0};
    rv = aes_init(&ctx, key, keylen, iv, NULL, AES_OFB, CRYPTO_AES_ENCRYPT);
    if (rv)
        return rv;
    rv = aes_update(&ctx, in, inlen, out, outlen);
    if (rv)
        return rv;
    rv = aes_final(&ctx, out, outlen);
    return rv;

}

int aes_decrypt_ofb(const unsigned char *key, int keylen,
                    const unsigned char *iv,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen) {
    int rv = 0;
    AES_CTX ctx = {0};
    rv = aes_init(&ctx, key, keylen, iv, NULL, AES_OFB, CRYPTO_AES_DECRYPT);
    if (rv)
        return rv;
    rv = aes_update(&ctx, in, inlen, out, outlen);
    if (rv)
        return rv;
    rv = aes_final(&ctx, out, outlen);
    return rv;
}

int aes_encrypt_ctr(const unsigned char *key, int keylen,
                    const unsigned char *iv,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen) {
    int rv = 0;
    AES_CTX ctx = {0};
    rv = aes_init(&ctx, key, keylen, iv, iv, AES_CTR, CRYPTO_AES_ENCRYPT);
    if (rv)
        return rv;
    rv = aes_update(&ctx, in, inlen, out, outlen);
    if (rv)
        return rv;
    rv = aes_final(&ctx, out, outlen);
    return rv;
}

int aes_decrypt_ctr(const unsigned char *key, int keylen,
                    const unsigned char *iv,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen) {
    int rv = 0;
    AES_CTX ctx = {0};
    rv = aes_init(&ctx, key, keylen, iv, iv, AES_CTR, CRYPTO_AES_DECRYPT);
    if (rv)
        return rv;
    rv = aes_update(&ctx, in, inlen, out, outlen);
    if (rv)
        return rv;
    rv = aes_final(&ctx, out, outlen);
    return rv;
}