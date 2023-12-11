// KeyGeneration.cpp : Defines the entry point for the DLL application.
//

#include <windows.h>
#include "KeyGenAlgoInterfaceEx.h"
#include "aes\aes.h"
#include "aes\aes_crypto.h"
#include "sha\sha2.h"

#if 0   //left
const unsigned char SecurityFactor_App[16] = {0x2c,0x5f,0xb7,0xd6,0xe7,0x07,0xba,0x88,0x38,0xf8,0xb1,0xfa,0x3a,0x8d,0xa5,0xdc};
const unsigned char SecurityFactor_Boot[16] = { 0x33,0x80,0x16,0x41,0x15,0xEA,0x60,0xB4,0xE9,0xDC,0xF2,0x40,0x7C,0x43,0x2E,0xC9 };
#else
const unsigned char SecurityFactor_App[16] = { 0xE4, 0x4F, 0x76, 0x17, 0x8F, 0x52, 0xE8, 0x79, 0xD4, 0x18, 0x0C, 0xD3, 0xCE, 0x81, 0xC7, 0xA8 };
const unsigned char SecurityFactor_Boot[16] = { 0xDE, 0x70, 0x65, 0x32, 0x23, 0x2D, 0xF0, 0xF2, 0x92, 0x8C, 0xCD, 0xF1, 0xC4, 0x0B, 0xDA, 0xF9 };

#endif

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
    return TRUE;
}

KEYGENALGO_API VKeyGenResultEx GenerateKeyEx(
      const unsigned char*  iSeedArray,     /* Array for the seed [in] */
      unsigned int          iSeedArraySize, /* Length of the array for the seed [in] */
      const unsigned int    iSecurityLevel, /* Security level [in] */
      const char*           iVariant,       /* Name of the active variant [in] */
      unsigned char*        ioKeyArray,     /* Array for the key [in, out] */
      unsigned int          iKeyArraySize,  /* Maximum length of the array for the key [in] */
      unsigned int&         oSize           /* Length of the key [out] */
      )
{
	unsigned char seedHash[32] = {0,};
	unsigned char hashFactor[48] = { 0, };
	unsigned char hashFactorRes[32] = { 0, };

	uint8_t* tempKey1 = NULL;
	uint8_t* tempKey2 = NULL;

	int finalKeyRes = 0;
	int keyArraySize[1] = { 4 };
    //unsigned int seed = 0U;

    const unsigned char * KeyFactor = NULL;

    if (iSeedArraySize > iKeyArraySize)

        return KGRE_BufferToSmall;

    //解锁算法，确定不同的解锁等级选择不同的解锁算法

    if (iSecurityLevel == 0x01)
	{
		KeyFactor = SecurityFactor_App;//解锁的特殊值
    }
	else if (iSecurityLevel == 0x11)
    {
		KeyFactor = SecurityFactor_Boot;//解锁的特殊值
    }
	else
	{
		return KGRE_SecurityLevelInvalid;
	}

    //解锁算法（通过seed计算出key）
	tempKey1 = SHA256(iSeedArray, 4, tempKey1);
	memcpy(hashFactor, tempKey1, 32);
	memcpy(hashFactor + 32, KeyFactor, 16);   //Now we have obtained the data that needs to be encrypted

	tempKey2 = SHA256(hashFactor, 48, tempKey2);
	memcpy(hashFactorRes, tempKey2, 32);     //get the hash result that needs to encrypted

	finalKeyRes = aes_encrypt_ecb(hashFactorRes, 16, iSeedArray, 4, ioKeyArray, keyArraySize);

	if(finalKeyRes)
		return KGRE_UnspecifiedError;

	oSize = keyArraySize[0];
    return KGRE_Ok;

}

