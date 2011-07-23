/***************************************************************
 * PRXTool : Utility for PSP executables.
 * (c) TyRaNiD 2k5
 *
 * VirtualMem.C - An implementation of a class to virtualise
 * a memory space.
 ***************************************************************/

#include <stdio.h>
#include <string.h>
#include "VirtualMem.h"
#include "output.h"

#define CHECK_ADDR(addr, size) ((check_addr(addr, size, m_iBaseAddr, m_iSize)) && (m_pData != NULL))

inline bool check_addr(u32 addr, u32 size, u32 baseaddr, u32 basesize)
{
	if(addr >= baseaddr)
	{
		if((addr + size) < (baseaddr + basesize))
		{
			return true;
		}
	}

	return false;
}

CVirtualMem::CVirtualMem()
{
	m_pData = NULL;
	m_iSize = 0;
	m_iBaseAddr = 0;
	m_endian = MEM_LITTLE_ENDIAN;
}

CVirtualMem::CVirtualMem(u8 *pData, u32 iSize, u32 iBaseAddr, MemEndian endian)
{
	m_pData = pData;
	m_iSize = iSize;
	m_iBaseAddr = iBaseAddr;
	m_endian = endian;
	COutput::Printf(LEVEL_DEBUG, "pData %p, iSize %x, iBaseAddr 0x%08X, endian %d\n", 
			pData, iSize, iBaseAddr, endian);
}

CVirtualMem::~CVirtualMem()
{
	/* Do nothing */
}

u8 CVirtualMem::GetU8(u32 iAddr)
{
	if(CHECK_ADDR(iAddr, 1))
	{
		return m_pData[iAddr - m_iBaseAddr];
	}

	COutput::Printf(LEVEL_DEBUG, "Invalid memory address 0x%08X\n", iAddr);
	return 0;
}

u16   CVirtualMem::GetU16(u32 iAddr)
{
	if(CHECK_ADDR(iAddr, 2))
	{
		if(m_endian == MEM_LITTLE_ENDIAN)
		{
			return LH_LE(*((u16*) &m_pData[iAddr - m_iBaseAddr]));
		}
		else if(m_endian == MEM_BIG_ENDIAN)
		{
			return LH_BE(*((u16*) &m_pData[iAddr - m_iBaseAddr]));
		}
		else
		{
			COutput::Printf(LEVEL_DEBUG, "Invalid endian format\n");
		}
	}
	else
	{
		COutput::Printf(LEVEL_DEBUG, "Invalid memory address 0x%08X\n", iAddr);
	}

	return 0;
}

u32   CVirtualMem::GetU32(u32 iAddr_2)
{
	s32 iAddr = iAddr_2;

	if(CHECK_ADDR(iAddr, 4))
	{
		if(m_endian == MEM_LITTLE_ENDIAN)
		{
			return LW_LE(*((u32*) &m_pData[iAddr - m_iBaseAddr]));
		}
		else if(m_endian == MEM_BIG_ENDIAN)
		{
			return LW_BE(*((u32*) &m_pData[iAddr - m_iBaseAddr]));
		}
		else
		{
			COutput::Printf(LEVEL_DEBUG, "Invalid endian format\n");
		}
	}
	else
	{
		COutput::Printf(LEVEL_DEBUG, "Invalid memory address 0x%08X\n", iAddr);
	}

	return 0;
}

s8    CVirtualMem::GetS8(u32 iAddr)
{
	if(CHECK_ADDR(iAddr, 1))
	{
		return m_pData[iAddr - m_iBaseAddr];
	}

	COutput::Printf(LEVEL_DEBUG, "Invalid memory address 0x%08X\n", iAddr);

	return 0;
}

s16   CVirtualMem::GetS16(u32 iAddr)
{
	if(CHECK_ADDR(iAddr, 2))
	{
		if(m_endian == MEM_LITTLE_ENDIAN)
		{
			return LH_LE(*((u16*) &m_pData[iAddr - m_iBaseAddr]));
		}
		else if(m_endian == MEM_BIG_ENDIAN)
		{
			return LH_BE(*((u16*) &m_pData[iAddr - m_iBaseAddr]));
		}
		else
		{
			COutput::Printf(LEVEL_DEBUG, "Invalid endian format\n");
		}
	}
	else
	{
		COutput::Printf(LEVEL_DEBUG, "Invalid memory address 0x%08X\n", iAddr);
	}


	return 0;
}

s32   CVirtualMem::GetS32(u32 iAddr)
{
	if(CHECK_ADDR(iAddr, 4))
	{
		if(m_endian == MEM_LITTLE_ENDIAN)
		{
			return LW_LE(*((u32*) &m_pData[iAddr - m_iBaseAddr]));
		}
		else if(m_endian == MEM_BIG_ENDIAN)
		{
			return LW_BE(*((u32*) &m_pData[iAddr - m_iBaseAddr]));
		}
		else
		{
			COutput::Printf(LEVEL_DEBUG, "Invalid endian format\n");
		}
	}
	else
	{
		COutput::Printf(LEVEL_DEBUG, "Invalid memory address 0x%08X\n", iAddr);
	}

	return 0;
}

void *CVirtualMem::GetPtr(u32 iAddr)
{
	if(CHECK_ADDR(iAddr, 1))
	{
		return &m_pData[iAddr - m_iBaseAddr];
	}
	else
	{
		COutput::Printf(LEVEL_DEBUG, "Ptr out of region 0x%08X\n", iAddr);
	}

	return NULL;
}

/* Get the amount of data available from this address */
u32 CVirtualMem::GetSize(u32 iAddr)
{
	u32 iSizeLeft = 0;

	/* Check we have at least 1 byte left */
	if(CHECK_ADDR(iAddr, 1))
	{
		iSizeLeft = m_iSize - (iAddr - m_iBaseAddr);
	}

	return iSizeLeft;
}

u32 CVirtualMem::Copy(void *pDest, u32 iAddr, u32 iSize)
{
	u32 iCopySize;
	void *ptr;

	iCopySize = GetSize(iAddr);
	iCopySize = iCopySize > iSize ? iSize : iCopySize;

	if(iCopySize > 0)
	{
		ptr = GetPtr(iAddr);
		memcpy(pDest, ptr, iCopySize);
	}

	return iCopySize;
}
