#include "..\Includes\cdll.h"
#include "..\Includes\via.h"
#include "..\Includes\via_CDLL.h"
#include "..\Includes\XB_Includes.h"

#include <stdio.h>
#include <stdlib.h>
#include <map>


static uint32 AppMaskValue = 0x0;
static uint32 BootMaskValue = 0x0;
static uint32 BootSecurityLevel = 3;
static uint32 OEM_Type = 'D';
void CAPLEXPORT far CAPLPASCAL SetCustomType(uint32 type) {
	OEM_Type = type;
}

/// <summary>
/// set a mask vlaue ,app or boot
/// </summary>
/// <returns></returns>
void CAPLEXPORT far CAPLPASCAL SetMaskValue(uint32 value , uint32 type) {
    if (type == 'A') {
        AppMaskValue = value;
    }
    else if (type == 'B')
    {
        BootMaskValue = value;
    }
    else {

    }
}

void CAPLEXPORT far CAPLPASCAL SetBootSecurityLevel(uint32 value) {
    BootSecurityLevel = value;
}

static unsigned int GENERIC_ALGORITHM_DAYUN(uint32 u32seed, uint32 mask , uint32 cnt)
{
    uint32 i;
    uint32 wort;
    wort = u32seed;

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
static unsigned int GENERIC_ALGORITHM_JMC(uint32 u32seed, uint32 mask, uint32 cnt)
{
	uint32 i;
	uint32 wort;
	wort = u32seed;

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


 uint32 CAPLEXPORT far CAPLPASCAL SeedToKey(uint32 u32seed,
     uint32 u32SecurityLevel,uint32 u32Cnt)
{
	 uint32 ConstValue = 0;
	 uint32 caclCount = u32Cnt;
    //解锁算法，确定不同的解锁等级选择不同的解锁算法

    if (u32SecurityLevel == 0x01)
    {
        ConstValue = AppMaskValue;//解锁的特殊值
    }

    if (u32SecurityLevel == BootSecurityLevel)
    {
        ConstValue = BootMaskValue;//解锁的特殊值
    }

	if (OEM_Type == 'J') {
		return GENERIC_ALGORITHM_JMC(u32seed, ConstValue, caclCount);
	}
	else if (OEM_Type == 'D') {
		return GENERIC_ALGORITHM_DAYUN(u32seed, ConstValue, caclCount);
	}
	else
	{
		return GENERIC_ALGORITHM_JMC(u32seed, ConstValue, caclCount);
	}

}

