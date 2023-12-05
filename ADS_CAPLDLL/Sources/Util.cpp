#include "..\Includes\cdll.h"
#include "..\Includes\via.h"
#include "..\Includes\via_CDLL.h"
#include "..\Includes\XB_Includes.h"

#include <stdio.h>
#include <stdlib.h>
#include <map>

FileParams sHexParams[] = { {0,1},{1,2},{3,4},{7,2},{9,4} };
FileParams sSrec1Params[] = { {0,1},{1,1},{2,2},{4,4},{8,4} };
FileParams sSrec2Params[] = { {0,1},{1,1},{2,2},{4,6},{10,4} };
FileParams sSrec3Params[] = { {0,1},{1,1},{2,2},{4,8},{12,4} };

static uint32 baseAddr = 0;

static uint32 ArrayToHex(char buffer[], uint8 len , uint8 offset) {
	uint32 ret = 0;
	uint8 temp;
	uint8 i = 0;

	for (i = 0; i < len; i++) {
		temp = __ascii_toupper(buffer[offset + i]);
		if (temp >= 'A' && temp <= 'Z')
			ret = (ret << 4) + (temp - 'A' + 10);
		else
			ret = (ret << 4) + (temp - '0');
	}
	return ret;
}


static uint32 SrecTypeSel(SrecDataType srecNum , char lineDatas[]) {
	uint32 res = 0;
	switch (srecNum) {
	case SREC_TYPE_TWO_BYTE:
		res = ArrayToHex(lineDatas, sSrec1Params[SREC_ADDR].u8Len, sSrec1Params[SREC_ADDR].u8OffSet);
		break;
	case SREC_TYPE_THREE_BYTE:
		res = ArrayToHex(lineDatas, sSrec2Params[SREC_ADDR].u8Len, sSrec2Params[SREC_ADDR].u8OffSet);
		break;
	case SREC_TYPE_FOUR_BYTE:
		res = ArrayToHex(lineDatas, sSrec3Params[SREC_ADDR].u8Len, sSrec3Params[SREC_ADDR].u8OffSet);
		break;
	default:
		res = 0;
		break;
	}
	return res;
}
///-----------------------------------------------------------------------------------------------------
// @Brief  :  "If result equals 0xFFFFFF, it indicates obtaining a base address, 
//					or failing to obtain a valid address."
// @Param  :  
// @Author : XiaoBai
//
// Time:2023.11.25  11:56:12
//-----------------------------------------------------------------------------------------------------

uint32 CAPLEXPORT far CAPLPASCAL GetBaseAddress(char lineDatas[], uint32 len)
{
	uint32 temp = 0;
	uint32 result = 0xFFFFFFFF;
	baseAddr = 0;

	if (lineDatas[HEX_START] == ':') {   //it is hex mode
		if (len > 63)
			return result;

		temp = ArrayToHex(lineDatas, sHexParams[HEX_DATA_TYPE].u8Len, sHexParams[HEX_DATA_TYPE].u8OffSet);

		if (temp == HEX_TYPE_SEGMENT_ADDR ) {  //addr need cacl
			baseAddr = ArrayToHex(lineDatas, sHexParams[HEX_BASE_ADDR].u8Len, sHexParams[HEX_BASE_ADDR].u8OffSet);
			baseAddr = baseAddr << 8;
		}
		else if (temp == HEX_TYPE_LINER_ADDR) {  //addr need cacl
			baseAddr = ArrayToHex(lineDatas, sHexParams[HEX_BASE_ADDR].u8Len, sHexParams[HEX_BASE_ADDR].u8OffSet);
			baseAddr = baseAddr << 16;
		}
		else if(temp == HEX_TYPE_DATA){ //addr is addr datas in array
			result = ArrayToHex(lineDatas, sHexParams[HEX_ADDR].u8Len, sHexParams[HEX_ADDR].u8OffSet);
		}
		else {
		}
	}
	else if (lineDatas[SREC_START] == 'S')
	{
		if (len > 63)
			return result;

		temp = ArrayToHex(lineDatas, sSrec1Params[SREC_DATA_TYPE].u8Len, sSrec1Params[SREC_DATA_TYPE].u8OffSet);
		if (temp != 0) {
			result = baseAddr = SrecTypeSel((SrecDataType)temp, lineDatas);
		}	
	}
	return result;
}

uint32 CAPLEXPORT far CAPLPASCAL GetValidAddress(char lineDatas[], uint32 len)
{
	uint32 temp = 0;
	uint32 result = 0xFFFFFFFF;

	if (lineDatas[HEX_START] == ':') {   //it is hex mode
		if (len > 63)
			return result;

		temp = ArrayToHex(lineDatas, sHexParams[HEX_DATA_TYPE].u8Len, sHexParams[HEX_DATA_TYPE].u8OffSet);
		if (temp != HEX_TYPE_DATA)
			return result;

		temp = ArrayToHex(lineDatas, sHexParams[HEX_ADDR].u8Len, sHexParams[HEX_ADDR].u8OffSet);

		result = baseAddr + temp;

	}
	else if (lineDatas[SREC_START] == 'S')
	{
		if (len > 63)
			return result;

		temp = ArrayToHex(lineDatas, sSrec1Params[SREC_DATA_TYPE].u8Len, sSrec1Params[SREC_DATA_TYPE].u8OffSet);
		if (temp != 0) {
			result = baseAddr = SrecTypeSel((SrecDataType)temp, lineDatas);
		}
	}
	return result;
}
