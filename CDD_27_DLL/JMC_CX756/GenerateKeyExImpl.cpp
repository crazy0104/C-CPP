// KeyGeneration.cpp : Defines the entry point for the DLL application.
//

#include <windows.h>
#include "KeyGenAlgoInterfaceEx.h"


const unsigned int AppMaskValue = 0xFF368EF9;
const unsigned int BootMaskValue = 0xAFFAEF2D;

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
    return TRUE;
}

unsigned int GENERIC_ALGORITHM(unsigned int wSeed , unsigned int mask)
{
    unsigned int i;
    unsigned char byte_[4];
    unsigned int wort;

    wort = wSeed;

    for (i = 0; i < 35; i++)
    {
        if (wort & 0x80000000)
        {
            wort = wort << 1;
            wort = wort ^ mask;
        }
        else
        {
            wort = wort << 1;
        }
    }

    return(wort);
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

    unsigned int key = 0U;

    unsigned int seed = 0U;

    unsigned int i = 0;

    unsigned int ConstValue = 0U;

    if (iSeedArraySize > iKeyArraySize)

        return KGRE_BufferToSmall;

    //将ECU返回的Seed整合起来（将seed从byte型转换为int型）
//    seed = ((DWORD)iSeedArray[3] << 24) + ((DWORD)iSeedArray[2] << 16) + ((DWORD)iSeedArray[1] << 8) + (DWORD)iSeedArray[0];
 
    seed = iSeedArray[0];

    seed = seed | (iSeedArray[1] << 8);

    seed = seed | (iSeedArray[2] << 16);

    seed = seed | (iSeedArray[3] << 24);
   

    //解锁算法，确定不同的解锁等级选择不同的解锁算法

    if (iSecurityLevel == 0x01)

    {

        ConstValue = AppMaskValue;//解锁的特殊值

    }

    if (iSecurityLevel == 0x09)

    {

        ConstValue = BootMaskValue;//解锁的特殊值

    }

    //解锁算法（通过seed计算出key）
    key = GENERIC_ALGORITHM(seed, ConstValue);


    //将计算处的key转换为成byte类型并返回到27 2N + data填充

    ioKeyArray[3] = key & 0xff;

    ioKeyArray[2] = (key >> 8) & 0xff;

    ioKeyArray[1] = (key >> 16) & 0xff;

    ioKeyArray[0] = (key >> 24) & 0xff;

    oSize = 4;

    return KGRE_Ok;

}

