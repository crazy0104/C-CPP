//
// Created by iwall on 2019-11-18.
//
// Version: 1.1
// Author: Kong

#ifndef CRYPTO_SIMPLE_AES_CRYPTO_H
#define CRYPTO_SIMPLE_AES_CRYPTO_H

#define AES_MAX_BLOCK_LENGTH    16
#define AES_MAX_IV_LENGTH       16
#define AES_MAX_COUNT_LENGTH    16

#define AES_ECB                 1000
#define AES_CBC                 1001
#define AES_CFB                 1002
#define AES_OFB                 1003
#define AES_CTR                 1004

#include "aes.h"

#ifdef __cplusplus
extern "C" {
#endif

struct aes_ctx_st {
    aes_context    ctx[1];                             /* crypto context */
    int            encrypt;                            /* encrypt or decrypt */
    void           *key;                               /* key struct */
    unsigned char  iv[AES_MAX_IV_LENGTH];              /* working iv */
    int            num;                                /* working num */
    unsigned char  ecount[AES_MAX_COUNT_LENGTH];       /* working ecount */
    int            buf_len;                            /* number how many left */
    unsigned char  buf[AES_MAX_BLOCK_LENGTH];          /* partial block */
    int            mode;                               /* Encrypt Mode */
}; /* AES_CTX */

typedef struct aes_ctx_st AES_CTX;


int aes_init(AES_CTX *ctx,
             const unsigned char *key,
             int keylen,
             const unsigned char *iv,
             const unsigned char *ecount,
             int mode,
             int enc);

int aes_update(AES_CTX *ctx,
               const unsigned char *in, int inlen,
               unsigned char *out, int *outlen);

int aes_final(AES_CTX *ctx,
              unsigned char *out, int *outlen);

/*
* @abstract This function encrypt data with ecb mode
*
* @param key     [IN]  the AES key
* @param keylen  [IN]  the AES key length
* @param in      [IN]  the buffer holding the input data.
* @param inlen   [IN]  the input data len
* @param out     [OUT] the buffer holding the output data.
* @param outlen  [OUT] the output data len
*                      it must be the buffer length of the out
*
* @return 0 on success
*/
int aes_encrypt_ecb(const unsigned char *key, int keylen,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen);

/*
* @abstract This function decrypt data with ecb mode
*
* @param key     [IN]  the AES key
* @param keylen  [IN]  the AES key length
* @param in      [IN]  the buffer holding the input data.
* @param inlen   [IN]  the input data len
* @param out     [OUT] the buffer holding the output data.
* @param outlen  [OUT] the out data len
*                      it must be the buffer length of the out
*
* @return 0 on success
*/
int aes_decrypt_ecb(const unsigned char *key, int keylen,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen);


/*
* @abstract This function encrypt data with cbc mode
*
* @param key     [IN]  the AES key
* @param keylen  [IN]  the AES key length
* @param iv      [IN]  the Vector (update after use)
*                      it must be a readable and writeable buffer of 16 Bytes.
* @param in      [IN]  the buffer holding the input data.
* @param inlen   [IN]  the input data len
* @param out     [OUT] the buffer holding the output data.
* @param outlen  [OUT] the output data len
*                      it must be the buffer length of the out
*
* @return 0 on success
*/
int aes_encrypt_cbc(const unsigned char *key, int keylen,
                    const unsigned char *iv,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen);

/*
* @abstract This function decrypt data with cbc mode
*
* @param key     [IN]  the AES key
* @param keylen  [IN]  the AES key length
* @param iv      [IN]  the Vector (update after use)
*                      it must be a readable and writeable buffer of 16 Bytes.
* @param in      [IN]  the buffer holding the input data.
* @param inlen   [IN]  the input data len
* @param out     [OUT] the buffer holding the output data.
* @param outlen  [OUT] the output data len
*                      it must be the buffer length of the out

*
* @return 0 on success
*/
int aes_decrypt_cbc(const unsigned char *key, int keylen,
                    const unsigned char *iv,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen);


/*
* @abstract This function encrypt data with ofb mode
*
* @param key     [IN]  the AES key
* @param keylen  [IN]  the AES key length
* @param iv      [IN]  the Vector (update after use)
*                      it must be a readable and writeable buffer of 16 Bytes.
* @param in      [IN]  the buffer holding the input data.
* @param inlen   [IN]  the input data len
* @param out     [OUT] the buffer holding the output data.
* @param outlen  [OUT] the output data len
*                      it must be the buffer length of the out
*
* @return 0 on success
*/
int aes_encrypt_ofb(const unsigned char *key, int keylen,
                    const unsigned char *iv,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen);

/*
* @abstract This function decrypt data with ofb mode
*
* @param key     [IN]  the AES key
* @param keylen  [IN]  the AES key length
* @param iv      [IN]  the Vector (update after use)
*                      it must be a readable and writeable buffer of 16 Bytes.
* @param in      [IN]  the buffer holding the input data.
* @param inlen   [IN]  the input data len
* @param out     [OUT] the buffer holding the output data.
* @param outlen  [OUT] the output data len
*                      it must be the buffer length of the out
*
* @return 0 on success
*/
int aes_decrypt_ofb(const unsigned char *key, int keylen,
                    const unsigned char *iv,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen);

/*
* @abstract This function encrypt data with cfb mode
*
* @param key     [IN]  the AES key
* @param keylen  [IN]  the AES key length
* @param iv      [IN]  the Vector (update after use)
*                      it must be a readable and writeable buffer of 16 Bytes.
* @param in      [IN]  the buffer holding the input data.
* @param inlen   [IN]  the input data len
* @param out     [OUT] the buffer holding the output data.
* @param outlen  [OUT] the output data len
*                      it must be the buffer length of the out
*
* @return 0 on success
*/
int aes_encrypt_cfb(const unsigned char *key, int keylen,
                    const unsigned char *iv,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen);

/*
* @abstract This function decrypt data with cfb mode
*
* @param key     [IN]  the AES key
* @param keylen  [IN]  the AES key length
* @param iv      [IN]  the Vector (update after use)
*                      it must be a readable and writeable buffer of 16 Bytes.
* @param in      [IN]  the buffer holding the input data.
* @param inlen   [IN]  the input data len
* @param out     [OUT] the buffer holding the output data.
* @param outlen  [OUT] the output data len
*                      it must be the buffer length of the out
*
* @return 0 on success
*/
int aes_decrypt_cfb(const unsigned char *key, int keylen,
                    const unsigned char *iv,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen);

/*
* @abstract This function encrypt data with ctr mode
*
* @param key     [IN]  the AES key
* @param keylen  [IN]  the AES key length
* @param iv      [IN]  the Vector (update after use)
*                      it must be a readable and writeable buffer of 16 Bytes.
* @param in      [IN]  the buffer holding the input data.
* @param inlen   [IN]  the input data len
* @param out     [OUT] the buffer holding the output data.
* @param outlen  [OUT] the output data len
*                      it must be the buffer length of the out
*
* @return 0 on success
*/
int aes_encrypt_ctr(const unsigned char *key, int keylen,
                    const unsigned char *iv,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen);


/*
* @abstract This function decrypt data with ctr mode
*
* @param key     [IN]  the AES key
* @param keylen  [IN]  the AES key length
* @param iv      [IN]  the Vector (update after use)
*                      it must be a readable and writeable buffer of 16 Bytes.
* @param in      [IN]  the buffer holding the input data.
* @param inlen   [IN]  the input data len
* @param out     [OUT] the buffer holding the output data.
* @param outlen  [OUT] the output data len
*                      it must be the buffer length of the out
*
* @return 0 on success
*/
int aes_decrypt_ctr(const unsigned char *key, int keylen,
                    const unsigned char *iv,
                    const unsigned char *in, int inlen,
                    unsigned char *out, int *outlen);

#ifdef __cplusplus
}
#endif
#endif //CRYPTO_SIMPLE_AES_CRYPTO_H
