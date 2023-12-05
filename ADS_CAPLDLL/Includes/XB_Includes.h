#ifndef __XIAOBAI_H
#define __XIAOBAI_H


#ifdef  __cplusplus
extern "C" {
#endif

	/*type define*/
	enum HexMode
	{
		HEX_START = 0,
		HEX_DATA_LEN,
		HEX_ADDR,
		HEX_DATA_TYPE,
		HEX_BASE_ADDR
	};

	struct FileParams
	{
		uint8 u8OffSet;
		uint8 u8Len;
	};

	enum HexDataType
	{
		HEX_TYPE_DATA = 0,
		HEX_TYPE_END = 0X01,
		HEX_TYPE_SEGMENT_ADDR = 0X02,
		HEX_TYPE_START_SEGMENT_ADDR = 0X03,
		HEX_TYPE_LINER_ADDR = 0X04,
		HEX_TYPE_START_LINER_ADDR = 0X05
	};

	enum SrecMode
	{
		SREC_START = 0,
		SREC_DATA_TYPE,
		SREC_DATA_LEN,
		SREC_ADDR,
		SREC_BASE_DATA
	};

	enum SrecDataType
	{
		SREC_TYPE = 0,
		SREC_TYPE_TWO_BYTE = 0X01,
		SREC_TYPE_THREE_BYTE = 0X02,
		SREC_TYPE_FOUR_BYTE = 0X03,
		SREC_TYPE_START_LINER_ADDR = 0X05
	};

	extern  void CAPLEXPORT far CAPLPASCAL SetCustomType(uint32 type);
	extern void CAPLEXPORT far CAPLPASCAL SetMaskValue(uint32 value, uint32 type);
	extern void CAPLEXPORT far CAPLPASCAL SetBootSecurityLevel(uint32 value);
	extern  uint32 CAPLEXPORT far CAPLPASCAL SeedToKey(uint32 u32seed, const uint32 u32SecurityLevel, uint32 u32Cnt);
	
	extern uint32 CAPLEXPORT far CAPLPASCAL GetBaseAddress(char lineDatas[], uint32 len);
	extern uint32 CAPLEXPORT far CAPLPASCAL GetValidAddress(char lineDatas[], uint32 len);

#ifdef  __cplusplus
}
#endif
#endif
