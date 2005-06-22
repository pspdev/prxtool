/***************************************************************
 * PRXTool : Utility for PSP executables.
 * (c) TyRaNiD 2k5
 *
 * SerializePrx.C - Implementation of a class to serialize a 
 * loaded PRX.
 ***************************************************************/

#include <stdio.h>
#include <string.h>
#include "SerializePrx.h"
#include "output.h"

CSerializePrx::CSerializePrx()
{
	m_blStarted = false;
}

CSerializePrx::~CSerializePrx()
{
}

void CSerializePrx::DoSects(CProcessPrx &prx)
{
	ElfSection *pSections;
	u32 iSects;
	u32 iLoop;

	if(StartSects() == false)
	{
		throw false;
	}

	/* We already checked for NULL */
	pSections = prx.ElfGetSections(iSects);
			
	for(iLoop = 0; iLoop < iSects; iLoop++)
	{
		if(SerializeSect(iLoop, pSections[iLoop]) == false)
		{
			throw false;
		}
	}

	if(EndSects() == false)
	{
		throw false;
	}
}

void CSerializePrx::DoImports(CProcessPrx &prx)
{
	PspModule *pMod;
	PspLibImport *pImport;
	int iLoop;

	pMod = prx.GetModuleInfo();
	iLoop = 0;

	if(StartImports() == false)
	{
		throw false;
	}

	pImport = pMod->imp_head;
	while(pImport != NULL)
	{
		if(SerializeImport(iLoop, pImport) == false)
		{
			throw false;
		}

		iLoop++;
		pImport = pImport->next;
	}

	if(EndImports() == false)
	{
		throw false;
	}
}

void CSerializePrx::DoExports(CProcessPrx &prx, bool blDoSyslib)
{
	PspModule *pMod;
	PspLibExport *pExport;
	int iLoop;

	pMod = prx.GetModuleInfo();
	iLoop = 0;

	if(StartExports() == false)
	{
		throw false;
	}

	pExport = pMod->exp_head;
	while(pExport != NULL)
	{
		if((blDoSyslib) || (strcmp(pExport->name, PSP_SYSTEM_EXPORT) != 0))
		{
			if(SerializeExport(iLoop, pExport) == false)
			{
				throw false;
			}
			iLoop++;
		}

		pExport = pExport->next;
	}

	if(EndExports() == false)
	{
		throw false;
	}
}

void CSerializePrx::DoRelocs(CProcessPrx &prx)
{
	ElfReloc* pRelocs;
	int iCount;

	if(StartRelocs() == false)
	{
		throw false;
	}
			
	pRelocs = prx.GetRelocs(iCount);
	if(pRelocs != NULL)
	{
		/* Process the relocs a segment at a time */
		const char *pCurrSec;
		int iCurrCount;

		while(iCount > 0)
		{
			ElfReloc *pBase;

			pBase = pRelocs;
			pCurrSec = pRelocs->secname;
			iCurrCount = 0;
			while((iCount > 0) && (strcmp(pCurrSec, pRelocs->secname) == 0))
			{
				pRelocs++;
				iCurrCount++;
				iCount--;
			}

			if(iCurrCount > 0)
			{
				if(SerializeReloc(iCurrCount, pBase) == false)
				{
					throw false;
				}
			}
		}
	}

	if(EndRelocs() == false)
	{
		throw false;
	}
}

bool CSerializePrx::Begin()
{
	if(StartFile() == false)
	{
		return false;
	}

	m_blStarted = true;

	return true;
}

bool CSerializePrx::End()
{
	bool blRet = true;
	if(m_blStarted == true)
	{
		blRet = EndFile();
		m_blStarted = false;
	}

	return blRet;
}

bool CSerializePrx::SerializePrx(CProcessPrx &prx, u32 iSMask)
{
	bool blRet = false;

	if(m_blStarted == false)
	{
		if(Begin() != true)
		{
			COutput::Puts(LEVEL_ERROR, "Failed to begin the serialized output");
			return false;
		}
	}

	try
	{
		/* Let's check the prx so we don't have to in the future */
		PspModule *pMod;
		u32 iSectNum;

		m_currPrx = &prx;
		pMod = prx.GetModuleInfo();
		if(pMod == NULL)
		{
			COutput::Printf(LEVEL_ERROR, "Invalid module info pMod\n");
			throw false;
		}

		if((prx.ElfGetSections(iSectNum) == NULL) && (iSectNum > 0))
		{
			COutput::Printf(LEVEL_ERROR, "Invalid section header information\n");
			throw false;
		}

		if(StartPrx(prx.GetElfName(), pMod, iSMask) == false)
		{
			throw false;
		}

		if(iSMask & SERIALIZE_SECTIONS)
		{
			DoSects(prx);
		}

		if(iSMask & SERIALIZE_IMPORTS)
		{
			DoImports(prx);
		}

		if(iSMask & SERIALIZE_EXPORTS)
		{
			DoExports(prx, iSMask & SERIALIZE_DOSYSLIB ? true : false);
		}

		if(iSMask & SERIALIZE_RELOCS)
		{
			DoRelocs(prx);
		}

		if(EndPrx() == false)
		{
			throw false;
		}
	}
	catch(...)
	{
		/* Do nothing */
	}

	return blRet;
}
