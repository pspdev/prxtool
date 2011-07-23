/***************************************************************
 * PRXTool : Utility for PSP executables.
 * (c) TyRaNiD 2k5
 *
 * VirtualMem.h - Definition of a class to create a virtual
 * memory space.
 ***************************************************************/

#ifndef __VIRTUALMEM_H__
#define __VIRTUALMEM_H__

#include "types.h"

enum MemEndian
{
	MEM_LITTLE_ENDIAN = 0,
	MEM_BIG_ENDIAN = 1
};

class CVirtualMem
{
	u8 *m_pData;
	u32 m_iSize;
	s32 m_iBaseAddr;
	MemEndian m_endian;
public:
	CVirtualMem();
	CVirtualMem(u8* pData, u32 iSize, u32 iBaseAddr, MemEndian endian);
	~CVirtualMem();

	u8    GetU8(u32 iAddr);
	u16   GetU16(u32 iAddr);
	u32   GetU32(u32 iAddr);
	s8    GetS8(u32 iAddr);
	s16   GetS16(u32 iAddr);
	s32   GetS32(u32 iAddr);
	void *GetPtr(u32 iAddr);
	u32   GetSize(u32 iAddr);
	u32   Copy(void *pDest, u32 iAddr, u32 iSize);
};

#endif
