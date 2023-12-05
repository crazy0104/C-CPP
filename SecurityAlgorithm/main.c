#include "aes.h"
#include "aes_crypto.h"
#include "sha2.h"
#include "windows.h"
#include <stdio.h>
const uint8_t cryptFactor[16]  = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};
const uint8_t serverSeed[4]  = {0x68 , 0x16 , 0xB4 , 0xD5};
uint8_t serverKey[4]   = {0x68 , 0x16 , 0xB4 , 0xD5};
uint8_t decryptKey[4]   = {1 , 2 , 3 , 4};
uint8_t clientKey[48];
uint8_t hashRes[32];
uint8_t hashKey[16];
int finalKeyRes = 0;

//seed + sha256 ---> 32Bytes Seed'£º
//1D 26 CF 1A 69 00 5E 10 31 35 D4 D0 82 1A 67 3E 3E 15 84 05 E8 76 06 E7 AD 6B 5C 62 D6 BA 94 D8 

//Seed' + cryptFactor ---> 48 bytes res:
//1D 26 CF 1A 69 00 5E 10 31 35 D4 D0 82 1A 67 3E 3E 15 84 05 E8 76 06 E7 AD 6B 5C 62 D6 BA 94 D8 + 
//1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8

//res sha256 ---> hash': 
//9A 53 6A 10 AF 85 93 BD 79 67 D4 19 C4 2B 5E E0 2C 41 24 97 24 90 72 1D C6 1F FC FF 20 29 3C 39

//hash' 16 bytes ---> K:
//9A 53 6A 10 AF 85 93 BD 79 67 D4 19 C4 2B 5E E0
//9A536A10AF8593BD7967D419C42B5EE0
//seed + K -AES128_ECB --> Key'£º5A 9A 48 85 D4 F3 BE 60 00 47 98 C5 82 72 D3 2F

extern int SHA256_Init(SHA256_CTX *c);

SHA256_CTX sha256Temp;
int main()
{
    uint8_t* tempKey1 = NULL;
    uint8_t* tempKey2 = NULL;
    uint8_t* tempKey3 = NULL;
    int a[1] = {4};
////encrypt start
    tempKey1 = SHA256(serverSeed,4,tempKey1);
    memcpy(clientKey,tempKey1,32);
    memcpy(clientKey + 32 , cryptFactor,16);
    printf("clientKey:");
    for(int i=0;i<48;i++)
        printf("0x%x ",clientKey[i]);

    tempKey2 = SHA256(clientKey,48,tempKey1);  
    memcpy(hashRes,tempKey2,32);
    printf("\nhashRes:");
    for(int i=0;i<32;i++)
        printf("0x%x ",hashRes[i]);

    memcpy(hashKey,hashRes,16);
    printf("\nhashKey:");
    for(int i=0;i<16;i++)
        printf("0x%x ",hashKey[i]);

    finalKeyRes = aes_encrypt_ecb(hashKey,16,serverSeed,4,serverKey,a); 
    printf("\nserverKey:");
    for(int i=0;i<a[0];i++)
        printf("0x%x ",serverKey[i]);

////encrpt end
    finalKeyRes = aes_decrypt_ecb(hashKey,16,serverKey,16,decryptKey,a);
    printf("\ndecryptKey:");
    for(int i=0;i<a[0];i++)
        printf("0x%x ",decryptKey[i]);
////decrypt start
    system("pause");
    return 0;
}

