/***************************************************************
 * PRXTool : Utility for PSP executables.
 * (c) TyRaNiD 2k5
 *
 * ProcessPrx.C - Implementation of a class to manipulate a PRX
 ***************************************************************/

#include <stdio.h>
#include <string.h>
#include <cassert>
#include "ProcessPrx.h"
#include "VirtualMem.h"
#include "output.h"

static const char* g_szRelTypes[13] = 
{
	"R_NONE",
	"R_16",
	"R_32",
	"R_REL32",
	"R_26",
	"R_HI16",
	"R_LO16",
	"R_GPREL16",
	"R_LITERAL",
	"R_GOT16",
	"R_PC16",
	"R_CALL16",
	"R_GPREL32"
};

CProcessPrx::CProcessPrx()
	: CProcessElf()
	, m_defNidMgr()
	, m_pCurrNidMgr(&m_defNidMgr)
	, m_pElfRelocs(NULL)
	, m_iRelocCount(0)
{
	memset(&m_modInfo, 0, sizeof(PspModule));
	m_blPrxLoaded = false;
}

CProcessPrx::~CProcessPrx()
{
	FreeMemory();
}

void CProcessPrx::FreeMemory()
{
	/* Lets delete the export list */
	PspLibExport *pExport;
	PspLibImport *pImport;

	pExport = m_modInfo.exp_head;
	while(pExport != NULL)
	{
		PspLibExport *pNext;
		pNext = pExport->next;
		delete pExport;
		pExport = pNext;
	}

	pImport = m_modInfo.imp_head;
	while(pImport != NULL)
	{
		PspLibImport *pNext;
		pNext = pImport->next;
		delete pImport;
		pImport = pNext;
	}

	if(m_pElfRelocs != NULL)
	{
		delete m_pElfRelocs;
		m_pElfRelocs = NULL;
	}
	m_iRelocCount = 0;

	/* Check the import and export lists and free */
	memset(&m_modInfo, 0, sizeof(PspModule));
}

int CProcessPrx::LoadSingleImport(PspModuleImport *pImport, u32 addr)
{
	bool blError = true;
	int count = 0;
	int iLoop;
	u32 nidAddr;
	u32 funcAddr;
	PspLibImport *pLib = NULL;

	SAFE_ALLOC(pLib, PspLibImport);
	if(pLib != NULL)
	{
		do
		{
			memset(pLib, 0, sizeof(PspModuleImport));
			pLib->addr = addr;
			pLib->stub.name = LW(pImport->name);
			pLib->stub.flags = LW(pImport->flags);
			pLib->stub.counts = LW(pImport->counts);
			pLib->stub.nids = LW(pImport->nids);
			pLib->stub.funcs = LW(pImport->funcs);

			if(pLib->stub.name == 0)
			{
				/* Shouldn't be zero, although technically it could be */
				COutput::Puts(LEVEL_ERROR, "Import libraries must have a name");
				break;
			}
			else
			{
				char *pName = (char*) m_vMem.GetPtr(pLib->stub.name);
				if(pName == NULL)
				{
					COutput::Printf(LEVEL_ERROR, "Invalid memory address for import name (0x%08X)\n", pLib->stub.name);
					break;
				}

				/* Should use strncpy I guess */
				strcpy(pLib->name, pName);
			}

			COutput::Printf(LEVEL_DEBUG, "Found import library '%s'\n", pLib->name);
			COutput::Printf(LEVEL_DEBUG, "Flags %08X, counts %08X, nids %08X, funcs %08X\n", 
					pLib->stub.flags, pLib->stub.counts, pLib->stub.nids, pLib->stub.funcs);

			/* No idea how to resolve variable at this moment, it might just throw in a ptr */
			pLib->v_count = (pLib->stub.counts >> 8) & 0xFF;
			if(pLib->v_count > 0)
			{
				COutput::Printf(LEVEL_WARNING, "Import variable count for '%s' is not 0\n", pLib->name);
			}

			pLib->v_count = 0;
			pLib->f_count = (pLib->stub.counts >> 16) & 0xFF;
			count = pLib->stub.counts & 0xFF;
			nidAddr = pLib->stub.nids;
			funcAddr = pLib->stub.funcs;

			if(m_vMem.GetSize(nidAddr) < (sizeof(u32) * pLib->v_count))
			{
				COutput::Puts(LEVEL_ERROR, "Not enough space for library import nids");
				break;
			}

			if(m_vMem.GetSize(funcAddr) < (u32) (8 * pLib->v_count))
			{
				COutput::Puts(LEVEL_ERROR, "Not enough space for library functions");
				break;
			}

			for(iLoop = 0; iLoop < pLib->f_count; iLoop++)
			{
				pLib->funcs[iLoop].nid = m_vMem.GetU32(nidAddr);
				strcpy(pLib->funcs[iLoop].name, m_pCurrNidMgr->FindLibName(pLib->name, pLib->funcs[iLoop].nid));
				pLib->funcs[iLoop].type = PSP_ENTRY_FUNC;
				pLib->funcs[iLoop].addr = funcAddr;
				pLib->funcs[iLoop].nid_addr = nidAddr;
				COutput::Printf(LEVEL_DEBUG, "Found import nid:0x%08X func:0x%08X name:%s\n", 
								pLib->funcs[iLoop].nid, pLib->funcs[iLoop].addr, pLib->funcs[iLoop].name);
				nidAddr += 4;
				funcAddr += 8;
			}

			if(m_modInfo.imp_head == NULL)
			{
				pLib->next = NULL;
				pLib->prev = NULL;
				m_modInfo.imp_head = pLib;
			}
			else
			{
				// Search for the end of the list
				PspLibImport* pImport;

				pImport = m_modInfo.imp_head;
				while(pImport->next != NULL)
				{
					pImport = pImport->next;
				}

				pImport->next = pLib;
				pLib->prev = pImport;
				pLib->next = NULL;
			}

			blError = false;
		}
		while(false);
	}
	else
	{
		COutput::Puts(LEVEL_ERROR, "Could not allocate memory for import library");
	}

	if(blError == true)
	{
		count = 0;
		if(pLib != NULL)
		{
			delete pLib;
			pLib = NULL;
		}
	}

	return count;
}

bool CProcessPrx::LoadImports()
{
	bool blRet = true;
	u32 imp_base;
	u32 imp_end;

	assert(m_modInfo.imp_head == NULL);

	imp_base = m_modInfo.info.imports;
	imp_end =  m_modInfo.info.imp_end;

	if(imp_base != 0)
	{
		while((imp_end - imp_base) >= sizeof(PspModuleImport))
		{
			u32 count;
			PspModuleImport *pImport;

			pImport = (PspModuleImport*) m_vMem.GetPtr(imp_base);

			if(pImport != NULL)
			{
				count = LoadSingleImport(pImport, imp_base);
				if(count > 0)
				{
					imp_base += (count * sizeof(u32));
				}
				else
				{
					blRet = false;
					break;
				}
			}
			else
			{
				blRet = false;
				break;
			}
		}
	}

	return blRet;
}

int CProcessPrx::LoadSingleExport(PspModuleExport *pExport, u32 addr)
{
	bool blError = true;
	int count = 0;
	int iLoop;
	PspLibExport* pLib = NULL;
	u32 expAddr;

	assert(pExport != NULL);

	SAFE_ALLOC(pLib, PspLibExport);
	if(pLib != NULL)
	{
		do
		{
			memset(pLib, 0, sizeof(PspLibExport));
			pLib->addr = addr;
			pLib->stub.name = LW(pExport->name);
			pLib->stub.flags = LW(pExport->flags);
			pLib->stub.counts = LW(pExport->counts);
			pLib->stub.exports = LW(pExport->exports);

			if(pLib->stub.name == 0)
			{
				/* If 0 then this is the system, this should be the only one */
				strcpy(pLib->name, PSP_SYSTEM_EXPORT);
			}
			else
			{
				char *pName = (char*) m_vMem.GetPtr(pLib->stub.name);
				if(pName == NULL)
				{
					COutput::Printf(LEVEL_ERROR, "Invalid memory address for export name (0x%08X)\n", pLib->stub.name);
					break;
				}

				strcpy(pLib->name, pName);
			}

			COutput::Printf(LEVEL_DEBUG, "Found export library '%s'\n", pLib->name);
			COutput::Printf(LEVEL_DEBUG, "Flags %08X, counts %08X, exports %08X\n", 
					pLib->stub.flags, pLib->stub.counts, pLib->stub.exports);

			pLib->v_count = (pLib->stub.counts >> 8) & 0xFF;
			pLib->f_count = (pLib->stub.counts >> 16) & 0xFF;
			count = pLib->stub.counts & 0xFF;
			expAddr = pLib->stub.exports;

			if(m_vMem.GetSize(expAddr) < (sizeof(u32) * (pLib->v_count + pLib->f_count)))
			{
				COutput::Printf(LEVEL_ERROR, "Invalid memory address for exports (0x%08X)\n", pLib->stub.exports);
				break;
			}

			for(iLoop = 0; iLoop < pLib->f_count; iLoop++)
			{
				/* We will fix up the names later */
				pLib->funcs[iLoop].nid = m_vMem.GetU32(expAddr);
				strcpy(pLib->funcs[iLoop].name, m_pCurrNidMgr->FindLibName(pLib->name, pLib->funcs[iLoop].nid));
				pLib->funcs[iLoop].type = PSP_ENTRY_FUNC;
				pLib->funcs[iLoop].addr = m_vMem.GetU32(expAddr + (sizeof(u32) * (pLib->v_count + pLib->f_count)));
				pLib->funcs[iLoop].nid_addr = expAddr; 
				COutput::Printf(LEVEL_DEBUG, "Found export nid:0x%08X func:0x%08X name:%s\n", 
											pLib->funcs[iLoop].nid, pLib->funcs[iLoop].addr, pLib->funcs[iLoop].name);
				expAddr += 4;
			}

			for(iLoop = 0; iLoop < pLib->v_count; iLoop++)
			{
				/* We will fix up the names later */
				pLib->vars[iLoop].nid = m_vMem.GetU32(expAddr);
				strcpy(pLib->vars[iLoop].name, m_pCurrNidMgr->FindLibName(pLib->name, pLib->vars[iLoop].nid));
				pLib->vars[iLoop].type = PSP_ENTRY_FUNC;
				pLib->vars[iLoop].addr = m_vMem.GetU32(expAddr + (sizeof(u32) * (pLib->v_count + pLib->f_count)));
				pLib->vars[iLoop].nid_addr = expAddr; 
				COutput::Printf(LEVEL_DEBUG, "Found export nid:0x%08X var:0x%08X name:%s\n", 
											pLib->vars[iLoop].nid, pLib->vars[iLoop].addr, pLib->vars[iLoop].name);
				expAddr += 4;
			}

			if(m_modInfo.exp_head == NULL)
			{
				pLib->next = NULL;
				pLib->prev = NULL;
				m_modInfo.exp_head = pLib;
			}
			else
			{
				// Search for the end of the list
				PspLibExport* pExport;

				pExport = m_modInfo.exp_head;
				while(pExport->next != NULL)
				{
					pExport = pExport->next;
				}

				pExport->next = pLib;
				pLib->prev = pExport;
				pLib->next = NULL;
			}

			blError = false;

		}
		while(false);
	}
	else
	{
		COutput::Printf(LEVEL_ERROR, "Couldn't allocate memory for export\n");
	}

	if(blError)
	{
		count = 0;
		if(pLib != NULL)
		{
			delete pLib;
			pLib = NULL;
		}
	}

	return count;
}

bool CProcessPrx::LoadExports()
{
	bool blRet = true;
	u32 exp_base;
	u32 exp_end;

	assert(m_modInfo.exp_head == NULL);

	exp_base = m_modInfo.info.exports;
	exp_end =  m_modInfo.info.exp_end;
	if(exp_base != 0)
	{
		while((exp_end - exp_base) >= sizeof(PspModuleExport))
		{
			u32 count;
			PspModuleExport *pExport;

			pExport = (PspModuleExport*) m_vMem.GetPtr(exp_base);

			if(pExport != NULL)
			{
				count = LoadSingleExport(pExport, exp_base);
				if(count > 0)
				{
					exp_base += (count * sizeof(u32));
				}
				else
				{
					blRet = false;
					break;
				}
			}
			else
			{
				blRet = false;
				break;
			}
		}
	}

	return blRet;
}

bool CProcessPrx::FillModule(ElfSection *pInfoSect)
{
	bool blRet = false;
	assert(pInfoSect != NULL);

	if(pInfoSect->pData != NULL)
	{
		PspModuleInfo *pModInfo;

		pModInfo = (PspModuleInfo*) pInfoSect->pData;
		memcpy(m_modInfo.name, pModInfo->name, PSP_MODULE_MAX_NAME);
		m_modInfo.name[PSP_MODULE_MAX_NAME] = 0;
		m_modInfo.addr = pInfoSect->iAddr;
		memcpy(&m_modInfo.info, pModInfo, sizeof(PspModuleInfo));
		m_modInfo.info.flags = LW(m_modInfo.info.flags);
		m_modInfo.info.gp = LW(m_modInfo.info.gp);
		m_modInfo.info.exports = LW(m_modInfo.info.exports);
		m_modInfo.info.exp_end = LW(m_modInfo.info.exp_end);
		m_modInfo.info.imports = LW(m_modInfo.info.imports);
		m_modInfo.info.imp_end = LW(m_modInfo.info.imp_end);
		blRet = true;

		if(COutput::GetDebug())
		{
			COutput::Puts(LEVEL_DEBUG, "Module Info:");
			COutput::Printf(LEVEL_DEBUG, "Name: %s\n", m_modInfo.name);
			COutput::Printf(LEVEL_DEBUG, "Addr: 0x%08X\n", m_modInfo.addr);
			COutput::Printf(LEVEL_DEBUG, "Flags: 0x%08X\n", m_modInfo.info.flags);
			COutput::Printf(LEVEL_DEBUG, "GP: 0x%08X\n", m_modInfo.info.gp);
			COutput::Printf(LEVEL_DEBUG, "Exports: 0x%08X, Exp_end 0x%08X\n", m_modInfo.info.exports, m_modInfo.info.exp_end);
			COutput::Printf(LEVEL_DEBUG, "Imports: 0x%08X, Imp_end 0x%08X\n", m_modInfo.info.imports, m_modInfo.info.imp_end);
		}
	}

	return blRet;
}

void CProcessPrx::FixupNames()
{
	if(m_blPrxLoaded)
	{
	}
}

bool CProcessPrx::LoadRelocs()
{
	bool blRet = false;
	int  iRelocCount = 0;
	int  iLoop;

	for(iLoop = 0; iLoop < m_iSHCount; iLoop++)
	{
		if(m_pElfSections[iLoop].iType == SHT_PRXRELOC)
		{
			if(m_pElfSections[iLoop].iSize % sizeof(Elf32_Rel))
			{
				COutput::Printf(LEVEL_DEBUG, "Relocation section invalid\n");
			}

			iRelocCount += m_pElfSections[iLoop].iSize / sizeof(Elf32_Rel);
		}
	}

	COutput::Printf(LEVEL_DEBUG, "Relocation entries %d\n", iRelocCount);

	if(iRelocCount > 0)
	{
		SAFE_ALLOC(m_pElfRelocs, ElfReloc[iRelocCount]);
		if(m_pElfRelocs != NULL)
		{
			const Elf32_Rel *reloc;
			int iCurrRel = 0;
			u32 iRelLoop;

			memset(m_pElfRelocs, 0, sizeof(ElfReloc) * iRelocCount);
			for(iLoop = 0; iLoop < m_iSHCount; iLoop++)
			{
				if(m_pElfSections[iLoop].iType == SHT_PRXRELOC)
				{
					reloc = (Elf32_Rel*) m_pElfSections[iLoop].pData;
					m_pElfSections[m_pElfSections[iLoop].iInfo].pRelocs = &m_pElfRelocs[iCurrRel];
					m_pElfSections[m_pElfSections[iLoop].iInfo].iRelocCount = 
											m_pElfSections[iLoop].iSize / sizeof(Elf32_Rel);
					for(iRelLoop = 0; iRelLoop < (m_pElfSections[iLoop].iSize / sizeof(Elf32_Rel)); iRelLoop++)
					{
						m_pElfRelocs[iCurrRel].secname = m_pElfSections[iLoop].szName;
						m_pElfRelocs[iCurrRel].base = 0;
						m_pElfRelocs[iCurrRel].type = ELF32_R_TYPE(reloc->r_info);
						m_pElfRelocs[iCurrRel].symbol = ELF32_R_SYM(reloc->r_info);
						m_pElfRelocs[iCurrRel].offset = reloc->r_offset;
						iCurrRel++;
						reloc++;
					}
				}
			}

			m_iRelocCount = iCurrRel;
			
			if(COutput::GetDebug())
			{
				for(iLoop = 0; iLoop < m_iRelocCount; iLoop++)
				{
					if(m_pElfRelocs[iLoop].type < 13)
					{
						COutput::Printf(LEVEL_DEBUG, "Reloc %s:%d Type:%s Symbol:%d Offset %08X\n", 
								m_pElfRelocs[iLoop].secname, iLoop, g_szRelTypes[m_pElfRelocs[iLoop].type],
								m_pElfRelocs[iLoop].symbol, m_pElfRelocs[iLoop].offset);
					}
					else
					{
						COutput::Printf(LEVEL_DEBUG, "Reloc %s:%d Type:%d Symbol:%d Offset %08X\n", 
								m_pElfRelocs[iLoop].secname, iLoop, m_pElfRelocs[iLoop].type,
								m_pElfRelocs[iLoop].symbol, m_pElfRelocs[iLoop].offset);
					}
				}
			}
		}
	}

	blRet = true;

	return blRet;
}

bool CProcessPrx::LoadFromFile(const char *szFilename)
{
	bool blRet = false;

	if(CProcessElf::LoadFromFile(szFilename))
	{
		/* Do PRX specific stuff */
		ElfSection *pInfoSect;
		FreeMemory();
		m_blPrxLoaded = false;

		m_vMem = CVirtualMem(m_pElfBin, m_iBinSize, m_iBaseAddr, MEM_LITTLE_ENDIAN);

		pInfoSect = ElfFindSection(PSP_MODULE_INFO_NAME);
		if(pInfoSect != NULL)
		{
			if((FillModule(pInfoSect)) && (LoadExports()) && (LoadImports()) && (LoadRelocs()))
			{
				COutput::Printf(LEVEL_INFO, "Loaded PRX %s successfully\n", szFilename);
				blRet = true;
				m_blPrxLoaded = true;
			}
		}
	}

	return blRet;
}

PspModule* CProcessPrx::GetModuleInfo()
{
	if(m_blPrxLoaded)
	{
		return &m_modInfo;
	}

	return NULL;
}

void CProcessPrx::SetNidMgr(CNidMgr* nidMgr)
{
	if(nidMgr == NULL)
	{
		m_pCurrNidMgr = &m_defNidMgr;
	}
	else
	{
		m_pCurrNidMgr = nidMgr;
	}
}

bool CProcessPrx::FixupPrx(FILE *fp)
{
	u8 *pElfCopy;
	Elf32_Ehdr* pHeader;
	ElfSection* pDataSect;
	ElfSection* pTextSect;

	/* Fixup the elf file and output it to fp */
	if((fp == NULL) || (m_blPrxLoaded == false))
	{
		return false;
	}

	/* Uber hacks */
	pDataSect = ElfFindSection(".data");
	if(pDataSect == NULL)
	{
		return false;
	}

	pTextSect = ElfFindSection(".text");
	if(pTextSect == NULL)
	{
		return false;
	}

	pElfCopy = new u8[m_iElfSize];
	if(pElfCopy == NULL)
	{
		return false;
	}
	memcpy(pElfCopy, m_pElf, m_iElfSize);

	/* Patch header */
	pHeader = (Elf32_Ehdr*) pElfCopy;
	pHeader->e_type = 2;

	/* Check for relocs */
	if(m_pElfRelocs != NULL)
	{
		int iLoop;
		u32 *pData;
		u32 *pData_HiAddr;
		/* Any relocs with symbol == 256 fixup to base of .data */

		pData = NULL;
		pData_HiAddr = NULL;
		iLoop = 0;
		for(iLoop = 0; iLoop < m_iRelocCount; iLoop++)
		{
			if((m_pElfRelocs[iLoop].symbol == 256) && (m_pElfRelocs[iLoop].offset < pTextSect->iSize))
			{
				switch(m_pElfRelocs[iLoop].type)
				{
					case R_MIPS_HI16 : pData_HiAddr = (u32*) (pElfCopy + pTextSect->iOffset 
											   + m_pElfRelocs[iLoop].offset - pTextSect->iAddr);
									   COutput::Printf(LEVEL_DEBUG, "Reloc %d Ofs %08X\n", iLoop, m_pElfRelocs[iLoop].offset);
									break;
					case R_MIPS_LO16 : 	if(pData_HiAddr != NULL)
										{
											u32 hiinst;
											u32 loinst;
											u32 addr;
											int ori = 0;

											pData = (u32*) (pElfCopy + pTextSect->iOffset 
													+ m_pElfRelocs[iLoop].offset - pTextSect->iAddr);
										   COutput::Printf(LEVEL_DEBUG, "Reloc %d Ofs %08X\n", iLoop, m_pElfRelocs[iLoop].offset);
											hiinst = LW(*pData_HiAddr);
											loinst = LW(*pData);
											COutput::Printf(LEVEL_DEBUG, "%d: hi %08X, lo %08X\n", iLoop, hiinst, loinst);

											addr = (hiinst & 0xFFFF) << 16;
											/* ori */
											if((loinst >> 26) == 0XD)
											{
												COutput::Printf(LEVEL_DEBUG, "ori\n");
												addr = addr | (loinst & 0xFFFF);

												ori = 1;
											}
											else
											{
												/* Do signed addition */
												addr = (s32) addr + (s16) (loinst & 0xFFFF);
											}

											COutput::Printf(LEVEL_DEBUG, "%d: Address %08X\n", iLoop, addr);
											addr += pDataSect->iAddr;
											COutput::Printf(LEVEL_DEBUG, "%d: Address %08X\n", iLoop, addr);

											if((addr & 0x8000) && (!ori))
											{
												addr += 0x10000;
											}

											loinst &= ~0xFFFF;
											loinst |= (addr & 0xFFFF);
											hiinst &= ~0xFFFF;
											hiinst |= ((addr >> 16) & 0xFFFF);

											COutput::Printf(LEVEL_DEBUG, "%d: hi %08X, lo %08X\n", iLoop, hiinst, loinst);
											SW(*pData_HiAddr, hiinst);
											SW(*pData, loinst);
										}
										else
										{
											COutput::Printf(LEVEL_DEBUG, "No matching HIADDR for reloc %d\n", iLoop);
										}

									break;
					default:		COutput::Printf(LEVEL_DEBUG, "Unsupported relocation type:%d\n", m_pElfRelocs[iLoop].type);
									break;
				};
			}
		}
	}

	fwrite(pElfCopy, 1, m_iElfSize, fp);
	fflush(fp);

	delete pElfCopy;

	return true;
}

bool CProcessPrx::ElfToPrx(FILE *fp)
{
	u8 *pElfCopy;
	Elf32_Phdr* pProgram;
	ElfSection* pModInfoSect;

	/* Fixup the elf file and output it to fp */
	if((fp == NULL) || (m_blPrxLoaded == false))
	{
		return false;
	}

	if((m_elfHeader.iPhnum == 0) || (m_elfHeader.iPhentsize == 0) || (m_elfHeader.iPhoff == 0))
	{
		COutput::Puts(LEVEL_ERROR, "Invalid program header data\n");
		return false;
	}

	pModInfoSect = ElfFindSection(".rodata.sceModuleInfo");
	if(pModInfoSect == NULL)
	{
		COutput::Puts(LEVEL_ERROR, "Could not find the module info section\n");
		return false;
	}

	pElfCopy = new u8[m_iElfSize];
	if(pElfCopy == NULL)
	{
		return false;
	}
	memcpy(pElfCopy, m_pElf, m_iElfSize);
	pProgram = (Elf32_Phdr*) (pElfCopy + m_elfHeader.iPhoff);
	SW(pProgram->p_paddr, pModInfoSect->iOffset);

	fwrite(pElfCopy, 1, m_iElfSize, fp);
	fflush(fp);

	delete pElfCopy;

	return true;
}

ElfReloc* CProcessPrx::GetRelocs(int &iCount)
{
	iCount = m_iRelocCount;
	return m_pElfRelocs;
}

PspLibImport *CProcessPrx::GetImports()
{
	return m_modInfo.imp_head;
}
