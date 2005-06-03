#include <stdio.h>
#include "SerializePrx.h"
#include "output.h"

CSerializePrx::CSerializePrx()
{
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

void CSerializePrx::DoModule(CProcessPrx &prx)
{
	PspModule *pMod;

	if(StartModule() == false)
	{
		throw false;
	}

	pMod = prx.GetModuleInfo();

	if(SerializeModule(pMod) == false)
	{
		throw false;
	}

	if(EndModule() == false)
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

void CSerializePrx::DoExports(CProcessPrx &prx)
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
		if(SerializeExport(iLoop, pExport) == false)
		{
			throw false;
		}

		iLoop++;
		pExport = pExport->next;
	}

	if(EndExports() == false)
	{
		throw false;
	}

}

void CSerializePrx::DoRelocs(CProcessPrx &prx)
{
	/* Atm do nothing */
}

bool CSerializePrx::Serialize(CProcessPrx &prx)
{
	bool blRet = false;

	try
	{
		/* Let's check the prx so we don't have to in the future */
		PspModule *pMod;
		u32 iSectNum;

		pMod = prx.GetModuleInfo();
		if((pMod == NULL) || (pMod->exp_head == NULL) || (pMod->imp_head == NULL))
		{
			COutput::Printf(LEVEL_ERROR, "Invalid module info pMod %p, exp_head %p, imp_head %p\n", 
					pMod, pMod != NULL ? pMod->exp_head : NULL, pMod != NULL ? pMod->imp_head : NULL);
			throw false;
		}

		if((prx.ElfGetSections(iSectNum) == NULL) && (iSectNum > 0))
		{
			COutput::Printf(LEVEL_ERROR, "Invalid section header information\n");
			throw false;
		}

		if(StartFile("") == false)
		{
			throw false;
		}

		DoModule(prx);
		DoSects(prx);
		DoImports(prx);
		DoExports(prx);
		DoRelocs(prx);

		if(EndFile() == false)
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
