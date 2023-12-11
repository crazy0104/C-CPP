// KeyGeneration.cpp : Defines the entry point for the DLL application.
//

#include <windows.h>
#include "KeyGenAlgoInterfaceEx.h"

#define LEFT_OR_RIGHT  0            //1:left    1:right

#if (1 == LEFT_OR_RIGHT)
const unsigned int AppMaskValue = 0x48210647;
const unsigned int BootMaskValue = 0x50156295;
#else
const unsigned int AppMaskValue = 0x93759832;
const unsigned int BootMaskValue = 0x75859892;
#endif

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
    return TRUE;
}

unsigned int GENERIC_ALGORITHM(const unsigned char* wSeed , unsigned int mask, unsigned int cnt)
{
    unsigned int i;
    unsigned int wort;

    wort = wSeed[3];
    wort |= ((unsigned int)wSeed[2] << 8);
    wort |= ((unsigned int)wSeed[1] << 16);
    wort |= ((unsigned int)wSeed[0] << 24);

    if (wort != 0)
    {
        for (i = 0; i < cnt; i++)
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
    unsigned int count = 0U;

    unsigned int key = 0U;

    unsigned int seed = 0U;

    unsigned int i = 0;

    unsigned int ConstValue = 0U;

    if (iSeedArraySize > iKeyArraySize)

        return KGRE_BufferToSmall;

    //解锁算法，确定不同的解锁等级选择不同的解锁算法

    if (iSecurityLevel == 0x01)
    {
        ConstValue = AppMaskValue;//解锁的特殊值
        count = 35;
    }

    if (iSecurityLevel == 0x03)
    {
        ConstValue = BootMaskValue;//解锁的特殊值
        count = 40;
    }

    //解锁算法（通过seed计算出key）
    key = GENERIC_ALGORITHM(iSeedArray, ConstValue, count);


    //将计算处的key转换为成byte类型并返回到27 2N + data填充

    ioKeyArray[3] = key & 0xff;

    ioKeyArray[2] = (key >> 8) & 0xff;

    ioKeyArray[1] = (key >> 16) & 0xff;

    ioKeyArray[0] = (key >> 24) & 0xff;

    oSize = 4;

    return KGRE_Ok;

}

