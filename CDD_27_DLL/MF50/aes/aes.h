//
// Created by iwall on 2019-11-04.
//
// Version: 1.0
// Author: Kong

#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H

#include <stddef.h>
#include <stdint.h>
#include <assert.h>

#define CIPHER_MODE_CBC
#define CIPHER_MODE_CFB
#define CIPHER_MODE_OFB
#define CIPHER_MODE_CTR

#define CRYPTO_AES_ENCRYPT            1  /* AES encryption */
#define CRYPTO_AES_DECRYPT            0  /* AES decryption */

#define CRYPTO_ERR_AES_INVALID_KEY_SIZE          -200
#define CRYPTO_ERR_AES_INVALID_INPUT             -201
#define CRYPTO_ERR_AES_INVALID_INPUT_LENGTH      -202
#define CRYPTO_ERR_AES_BUFFER_TOO_SMALL          -203

#define AES_VALIDATE_RET( cond )  \
    do {                                            \
        if( !(cond) )                               \
        {                                           \
            assert( cond );                         \
            return( CRYPTO_ERR_AES_INVALID_INPUT ); \
        }                                           \
    } while( 0 )

#ifdef __cplusplus
extern "C" {
#endif

#define AES_MAXNR 14
#define AES_BLOCK_SIZE 16
typedef struct AES_CONTEXT
{
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
    int rounds;
}aes_context;

/*
 * @abstract This function sets the encryption key
 *
 * @param ctx    The AES context.
 * @param key    The encryption key.
 * @param keylen The size of key in bits. 128, 192, 256.
 *
 * @return 0 on success.
 */
int aes_setkey_enc(aes_context *ctx,
                   const unsigned char *key,
                   unsigned int keybits);

/*
 * @abstract This function sets the decryption key
 *
 * @param ctx    The AES context
 * @param key    The encryption key
 * @param keylen The size of key in bits. 128, 192, 256.
 *
 * @return 0 on success
 */
int aes_setkey_dec(aes_context *ctx,
                   const unsigned char *key,
                   unsigned int keybits);


/*
 * @abstract This function crypt data with ecb mode
 *
 * @param ctx    The AES context
 * @param mode   The AES operation
 *               #CRYPTO_AES_ENCYRPT or #CRYPTO_AES_DECRYPT.
 * @param length Input value length
 * @param input  The buffer holding the input data.
 * @param output The buffer holding the output data.
 *
 * @return 0 on success
 */
int aes_crypt_ecb(aes_context *ctx,
                  int mode,
                  size_t length,
                  unsigned char *input,
                  unsigned char *output);


#if defined(CIPHER_MODE_CBC)
/*
 * @abstract This function crypt data with cbc mode
 *
 * @param ctx    The AES context.
 * @param mode   The AES operation
 *               #CRYPTO_AES_ENCYRPT or #CRYPTO_AES_DECRYPT.
 * @param length The length of the input data in Bytes.
 * @param iv     The Vector (update after use)
 *               It must be a readable and writeable buffer of 16 Bytes.
 * @param input  The buffer holding the input data.
 * @param output The buffer holding the output data.
 *
 * @return 0 on success
 */
int aes_crypt_cbc(aes_context *ctx,
                  int mode,
                  size_t length,
                  unsigned char iv[16],
                  const unsigned char *input,
                  unsigned char *output);
#endif


#if defined(CIPHER_MODE_CFB)
/*
 * @abstract This function crypt data with ctr mode
 *
 * @param ctx    The AES context.
 * @param mode   The AES operation
 *               #CRYPTO_AES_ENCYRPT or #CRYPTO_AES_DECRYPT.
 * @param length The length of the input data in Bytes.
 * @param iv     The Vector (update after use)
 *               It must be a readable and writeable buffer of 16 Bytes.
 * @param num    The num default value is 0
 * @param input  The buffer holding the input data.
 * @param output The buffer holding the output data.
 *
 * @return 0 on success
 */
int aes_crypt_cfb(aes_context *ctx,
                  int mode,
                  size_t length,
                  unsigned char iv[16],
                  int *num,
                  const unsigned char *input,
                  unsigned char *output);
#endif

#if defined(CIPHER_MODE_OFB)
/*
 * @abstract This function crypt data with ctr mode
 *
 * @param ctx    The AES context.
 * @param mode   The AES operation
 *               #CRYPTO_AES_ENCYRPT or #CRYPTO_AES_DECRYPT.
 * @param length The length of the input data in Bytes.
 * @param iv     The Vector (update after use)
 *               It must be a readable and writeable buffer of 16 Bytes.
 * @param num    The num default value is 0
 * @param input  The buffer holding the input data.
 * @param output The buffer holding the output data.
 *
 * @return 0 on success
 */
int aes_crypt_ofb(aes_context *ctx,
                  int mode,
                  size_t length,
                  unsigned char iv[16],
                  int *num,
                  const unsigned char *input,
                  unsigned char *output);
#endif

#if defined(CIPHER_MODE_CTR)
/*
 * @abstract This function crypt data with ctr mode
 *
 * @param ctx    The AES context.
 * @param mode   The AES operation
 *               #CRYPTO_AES_ENCYRPT or #CRYPTO_AES_DECRYPT.
 * @param length The length of the input data in Bytes.
 * @param iv     The Vector (update after use)
 *               It must be a readable and writeable buffer of 16 Bytes.
 * @param ecount_buf  The Count Buf
 *               It must be a readable and writeable buffer of 16 Bytes.
 * @param input  The buffer holding the input data.
 * @param output The buffer holding the output data.
 *
 * @return 0 on success
 */
int aes_crypt_ctr128(aes_context *ctx,
                     int mode,
                     size_t length,
                     unsigned char iv[16],
                     unsigned char ecount_buf[16],
                     int *num,
                     const unsigned char *input,
                     unsigned char *output);
#endif

#ifdef __cplusplus
}
#endif
#endif //CRYPTO_AES_H
