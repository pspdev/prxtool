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
#include "disasm.h"

static const char* g_szRelTypes[16] = 
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
	"R_GPREL32",
	"X_HI16",
	"X_J26",
	"X_JAL26"
	
};

/* Flag indicates the reloc offset field is relative to the text section base */
#define RELOC_OFS_TEXT 0
/* Flag indicates the reloc offset field is relative to the data section base */
#define RELOC_OFS_DATA 1
/* Flag indicates the reloc'ed field should be fixed up relative to the data section base */
#define RELOC_REL_DATA 256

/* Minimum string size */
#define MINIMUM_STRING 4

CProcessPrx::CProcessPrx(u32 dwBase)
	: CProcessElf()
	, m_defNidMgr()
	, m_pCurrNidMgr(&m_defNidMgr)
	, m_pElfRelocs(NULL)
	, m_iRelocCount(0)
	, m_dwBase(dwBase)
	, m_blXmlDump(false)
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
	FreeSymbols(m_syms);
	FreeImms(m_imms);
}

int CProcessPrx::LoadSingleImport(PspModuleImport *pImport, u32 addr)
{
	bool blError = true;
	int count = 0;
	int iLoop;
	u32 nidAddr;
	u32 funcAddr;
	u32 varAddr;
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
			pLib->stub.vars = LW(pImport->vars);

			if(pLib->stub.name == 0)
			{
				/* Shouldn't be zero, although technically it could be */
				COutput::Puts(LEVEL_ERROR, "Import libraries must have a name");
				break;
			}
			else
			{
				char *pName = (char*) m_vMem.GetPtr(pLib->stub.name);
				const char *dep;
				if(pName == NULL)
				{
					COutput::Printf(LEVEL_ERROR, "Invalid memory address for import name (0x%08X)\n", pLib->stub.name);
					break;
				}

				/* Should use strncpy I guess */
				strcpy(pLib->name, pName);
				dep = m_pCurrNidMgr->FindDependancy(pName);
				if(dep)
				{
					const char *slash;
					
					/* Remove any path element */
					slash = strrchr(dep, '/');
					if(slash)
					{
						dep = slash + 1;
					}
					strcpy(pLib->file, dep);
				}
			}

			COutput::Printf(LEVEL_DEBUG, "Found import library '%s'\n", pLib->name);
			COutput::Printf(LEVEL_DEBUG, "Flags %08X, counts %08X, nids %08X, funcs %08X\n", 
					pLib->stub.flags, pLib->stub.counts, pLib->stub.nids, pLib->stub.funcs);

			pLib->v_count = (pLib->stub.counts >> 8) & 0xFF;
			pLib->f_count = (pLib->stub.counts >> 16) & 0xFFFF;
			count = pLib->stub.counts & 0xFF;
			nidAddr = pLib->stub.nids;
			funcAddr = pLib->stub.funcs;
			varAddr = pLib->stub.vars;

			if(m_vMem.GetSize(nidAddr) < (sizeof(u32) * pLib->f_count))
			{
				COutput::Puts(LEVEL_ERROR, "Not enough space for library import nids");
				break;
			}

			if(m_vMem.GetSize(funcAddr) < (u32) (8 * pLib->f_count))
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
			
			if (funcAddr > m_stubBottom) {
				m_stubBottom = funcAddr;
			}

			for(iLoop = 0; iLoop < pLib->v_count; iLoop++)
			{
				u32 varFixup;
				u32 varData;

				pLib->vars[iLoop].addr = m_vMem.GetU32(varAddr);
				pLib->vars[iLoop].nid = m_vMem.GetU32(varAddr+4);
				pLib->vars[iLoop].type = PSP_ENTRY_VAR;
				pLib->vars[iLoop].nid_addr = varAddr+4;
				strcpy(pLib->vars[iLoop].name, m_pCurrNidMgr->FindLibName(pLib->name, pLib->vars[iLoop].nid));
				COutput::Printf(LEVEL_DEBUG, "Found variable nid:0x%08X addr:0x%08X name:%s\n",
						pLib->vars[iLoop].nid, pLib->vars[iLoop].addr, pLib->vars[iLoop].name);
				varFixup = pLib->vars[iLoop].addr;
				while((varData = m_vMem.GetU32(varFixup)))
				{
					COutput::Printf(LEVEL_DEBUG, "Variable Fixup: addr:%08X type:%08X\n", 
							(varData & 0x3FFFFFF) << 2, varData >> 26);
					varFixup += 4;
				}
				varAddr += 8;
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
	m_stubBottom = 0;

	if(imp_base != 0)
	{
		while((imp_end - imp_base) >= PSP_IMPORT_BASE_SIZE)
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

	m_stubBottom += 4;
	COutput::Printf(LEVEL_DEBUG, "Stub bottom 0x%08X\n", m_stubBottom);

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
			pLib->f_count = (pLib->stub.counts >> 16) & 0xFFFF;
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

bool CProcessPrx::FillModule(u8 *pData, u32 iAddr)
{
	bool blRet = false;

	if(pData != NULL)
	{
		PspModuleInfo *pModInfo;

		pModInfo = (PspModuleInfo*) pData;
		memcpy(m_modInfo.name, pModInfo->name, PSP_MODULE_MAX_NAME);
		m_modInfo.name[PSP_MODULE_MAX_NAME] = 0;
		m_modInfo.addr = iAddr;
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

bool CProcessPrx::CreateFakeSections()
{
	/* If we have no section headers let's build some fake sections */
	if(m_iSHCount == 0)
	{
		if(m_iPHCount < 3)
		{
			COutput::Printf(LEVEL_ERROR, "Invalid number of program headers for newstyle PRX (%d)\n", 
					m_iPHCount);
			return false;
		}

		if (m_pElfPrograms[2].iType == PT_PRXRELOC) {
			m_iSHCount = 6;
		} else {
			m_iSHCount = 5;
		}

		SAFE_ALLOC(m_pElfSections, ElfSection[m_iSHCount]);
		if(m_pElfSections == NULL)
		{
			return false;
		}

		memset(m_pElfSections, 0, sizeof(ElfSection) * m_iSHCount);

		m_pElfSections[1].iType = SHT_PROGBITS;
		m_pElfSections[1].iFlags = SHF_ALLOC | SHF_EXECINSTR;
		m_pElfSections[1].iAddr = m_pElfPrograms[0].iVaddr;
		m_pElfSections[1].pData = m_pElf + m_pElfPrograms[0].iOffset;
		m_pElfSections[1].iSize = m_stubBottom;
		strcpy(m_pElfSections[1].szName, ".text");

		m_pElfSections[2].iType = SHT_PROGBITS;
		m_pElfSections[2].iFlags = SHF_ALLOC;
		m_pElfSections[2].iAddr = m_stubBottom;
		m_pElfSections[2].pData = m_pElf + m_pElfPrograms[0].iOffset + m_stubBottom;
		m_pElfSections[2].iSize = m_pElfPrograms[0].iMemsz - m_stubBottom;
		strcpy(m_pElfSections[2].szName, ".rodata");

		m_pElfSections[3].iType = SHT_PROGBITS;
		m_pElfSections[3].iFlags = SHF_ALLOC | SHF_WRITE;
		m_pElfSections[3].iAddr = m_pElfPrograms[1].iVaddr;
		m_pElfSections[3].pData = m_pElf + m_pElfPrograms[1].iOffset;
		m_pElfSections[3].iSize = m_pElfPrograms[1].iFilesz;
		strcpy(m_pElfSections[3].szName, ".data");


		m_pElfSections[4].iType = SHT_NOBITS;
		m_pElfSections[4].iFlags = SHF_ALLOC | SHF_WRITE;
		m_pElfSections[4].iAddr = m_pElfPrograms[1].iVaddr + m_pElfPrograms[1].iFilesz;
		m_pElfSections[4].pData = m_pElf + m_pElfPrograms[1].iOffset + m_pElfPrograms[1].iFilesz;
		m_pElfSections[4].iSize = m_pElfPrograms[1].iMemsz - m_pElfPrograms[1].iFilesz;
		strcpy(m_pElfSections[4].szName, ".bss");

		if (m_pElfPrograms[2].iType == PT_PRXRELOC) {
			m_pElfSections[5].iType = SHT_PRXRELOC;
			m_pElfSections[5].iFlags = 0;
			m_pElfSections[5].iAddr = 0;
			m_pElfSections[5].pData = m_pElf + m_pElfPrograms[2].iOffset;
			m_pElfSections[5].iSize = m_pElfPrograms[2].iFilesz;
			/* Bind to section 1, not that is matters */
			m_pElfSections[5].iInfo = 1;
			strcpy(m_pElfSections[5].szName, ".reloc");
		}

		if(COutput::GetDebug())
		{
			ElfDumpSections();
		}
	}
	
	return true;
}



int CProcessPrx::CountRelocs()
{
	int  iLoop;
	int  iRelocCount = 0;

	for(iLoop = 0; iLoop < m_iSHCount; iLoop++)
	{
		if((m_pElfSections[iLoop].iType == SHT_PRXRELOC) || (m_pElfSections[iLoop].iType == SHT_REL))
		{
			if(m_pElfSections[iLoop].iSize % sizeof(Elf32_Rel))
			{
				COutput::Printf(LEVEL_DEBUG, "Relocation section invalid\n");
			}

			iRelocCount += m_pElfSections[iLoop].iSize / sizeof(Elf32_Rel);
		}
	}

	for(iLoop = 0; iLoop < m_iPHCount; iLoop++)
	{
		if(m_pElfPrograms[iLoop].iType == PT_PRXRELOC2) {
			u8 *block1, block1s, part1s;
			u8 *block2, block2s, part2s;
			u8 *pos, *end;
			
			if (m_pElfPrograms[iLoop].pData[0] != 0 ||
			    m_pElfPrograms[iLoop].pData[1] != 0) {
				COutput::Printf(LEVEL_DEBUG, "Should start with 0x00 0x00\n");
				return 0;
			}
			
			part1s = m_pElfPrograms[iLoop].pData[2];
			part2s = m_pElfPrograms[iLoop].pData[3];
			block1s = m_pElfPrograms[iLoop].pData[4];
			block1 = &m_pElfPrograms[iLoop].pData[4];
			block2 = block1 + block1s;
			block2s = block2[0];
			pos = block2 + block2s;
			end = &m_pElfPrograms[iLoop].pData[m_pElfPrograms[iLoop].iFilesz];
			while (pos < end) {
				u32 cmd, part1, temp;
				cmd = pos[0] | (pos[1] << 16);
				pos += 2;
				temp = (cmd << (16 - part1s)) & 0xFFFF;
				temp = (temp >> (16 - part1s)) & 0xFFFF;
				if (temp >= block1s) {
					COutput::Printf(LEVEL_DEBUG, "Invalid cmd1 index\n");
					return 0;
				}
				part1 = block1[temp];
				pos += (part1 & 0x06);
				if ((part1 & 0x01) != 0) {
					if (part1 & 0x38 == 0x10) {
						pos += 2;
					} else if (part1 & 0x38 == 0x18) {
						pos += 4;
					}
				}
				iRelocCount++;
			}
		}
	}


	COutput::Printf(LEVEL_DEBUG, "Relocation entries %d\n", iRelocCount);
	return iRelocCount;
}

int CProcessPrx::LoadRelocsTypeA(struct ElfReloc *pRelocs)
{
	int i, count;
	const Elf32_Rel *reloc;
	int  iLoop, iCurrRel = 0;
	
	for(iLoop = 0; iLoop < m_iSHCount; iLoop++)
	{
		if((m_pElfSections[iLoop].iType == SHT_PRXRELOC) || (m_pElfSections[iLoop].iType == SHT_REL))
		{
			count = m_pElfSections[iLoop].iSize / sizeof(Elf32_Rel);
			reloc = (const Elf32_Rel *) m_pElfSections[iLoop].pData;
			for(i = 0; i < count; i++) {    
				pRelocs[iCurrRel].secname = m_pElfSections[iLoop].szName;
				pRelocs[iCurrRel].base = 0;
				pRelocs[iCurrRel].type = ELF32_R_TYPE(LW(reloc->r_info));
				pRelocs[iCurrRel].symbol = ELF32_R_SYM(LW(reloc->r_info));
				pRelocs[iCurrRel].info = LW(reloc->r_info);
				pRelocs[iCurrRel].offset = reloc->r_offset;
				reloc++;
				iCurrRel++;
			}
		}
	}

	return iCurrRel;
}

int CProcessPrx::LoadRelocsTypeB(struct ElfReloc *pRelocs)
{
	u8 *block1, *block2, *pos, *end;
	u32 block1s, block2s, part1s, part2s;
	u32 cmd, part1, part2, lastpart2;
	u32 addend = 0, offset = 0;
	u32 ofsbase = 0xFFFFFFFF, addrbase;
	u32 temp1, temp2;
	u32 nbits;
	int iLoop, iCurrRel = 0;
	
	for(iLoop = 0; iLoop < m_iPHCount; iLoop++)
	{
		if(m_pElfPrograms[iLoop].iType == PT_PRXRELOC2)
		{
			part1s = m_pElfPrograms[iLoop].pData[2];
			part2s = m_pElfPrograms[iLoop].pData[3];
			block1s =m_pElfPrograms[iLoop].pData[4];
			block1 = &m_pElfPrograms[iLoop].pData[4];
			block2 = block1 + block1s;
			block2s = block2[0];
			pos = block2 + block2s;
			end = &m_pElfPrograms[iLoop].pData[m_pElfPrograms[iLoop].iFilesz];
			
			for (nbits = 1; (1 << nbits) < iLoop; nbits++) {
				if (nbits >= 33) {
					COutput::Printf(LEVEL_DEBUG, "Invalid nbits\n");
					return 0;
				}
			}

	
			lastpart2 = block2s;
			while (pos < end) {
				cmd = pos[0] | (pos[1] << 8);
				pos += 2;
				temp1 = (cmd << (16 - part1s)) & 0xFFFF;
				temp1 = (temp1 >> (16 - part1s)) & 0xFFFF;
				if (temp1 >= block1s) {
					COutput::Printf(LEVEL_DEBUG, "Invalid part1 index\n");
					return 0;
				}
				part1 = block1[temp1];
				if ((part1 & 0x01) == 0) {
					ofsbase = (cmd << (16 - part1s - nbits)) & 0xFFFF;
					ofsbase = (ofsbase >> (16 - nbits)) & 0xFFFF;
					if (!(ofsbase < iLoop)) {
						COutput::Printf(LEVEL_DEBUG, "Invalid offset base\n");
						return 0;
					}

					if ((part1 & 0x06) == 0) {
						offset = cmd >> (part1s + nbits);
					} else if ((part1 & 0x06) == 4) {
						offset = pos[0] | (pos[1] << 8) | (pos[2] << 16) | (pos[3] << 24);
						pos += 4;
					} else {
						COutput::Printf(LEVEL_DEBUG, "Invalid size\n");
						return 0;
					}
				} else {
					temp2 = (cmd << (16 - (part1s + nbits + part2s))) & 0xFFFF;
					temp2 = (temp2 >> (16 - part2s)) & 0xFFFF;
					if (temp2 >= block2s) {
						COutput::Printf(LEVEL_DEBUG, "Invalid part2 index\n");
						return 0;
					}

					addrbase = (cmd << (16 - part1s - nbits)) & 0xFFFF;
					addrbase = (addrbase >> (16 - nbits)) & 0xFFFF;
					if (!(addrbase < iLoop)) {
						COutput::Printf(LEVEL_DEBUG, "Invalid address base\n");
						return 0;
					}
					part2 = block2[temp2];
					
					switch (part1 & 0x06) {
					case 0:
						temp1 = cmd;
						if (temp1 & 0x8000) {
							temp1 |= ~0xFFFF;
							temp1 >>= part1s + part2s + nbits;
							temp1 |= ~0xFFFF;
						} else {
							temp1 >>= part1s + part2s + nbits;
						}
						offset += temp1;
						break;
					case 2:
						temp1 = cmd;
						if (temp1 & 0x8000) temp1 |= ~0xFFFF;
						temp1 = (temp1 >> (part1s + part2s + nbits)) << 16;
						temp1 |= pos[0] | (pos[1] << 8);
						offset += temp1;
						pos += 2;
						break;
					case 4:
						offset = pos[0] | (pos[1] << 8) | (pos[2] << 16) | (pos[3] << 24);
						pos += 4;
						break;
					default:
						COutput::Printf(LEVEL_DEBUG, "invalid part1 size\n");
						return 0;
					}
					
					if (!(offset < m_pElfPrograms[ofsbase].iFilesz)) {
						COutput::Printf(LEVEL_DEBUG, "invalid relocation offset\n");
						return 0;
					}
					
					switch (part1 & 0x38) {
					case 0x00:
						addend = 0;
						break;
					case 0x08:
						if ((lastpart2 ^ 0x04) != 0) {
							addend = 0;
						}
						break;
					case 0x10:
						addend = pos[0] | (pos[1] << 8);
						pos += 2;
						break;
					case 0x18:
						addend = pos[0] | (pos[1] << 8) | (pos[2] << 16) | (pos[3] << 24);
						pos += 4;
						COutput::Printf(LEVEL_DEBUG, "invalid addendum size\n");
						return 0;
					default:
						COutput::Printf(LEVEL_DEBUG, "invalid addendum size\n");
						return 0;
					}

					lastpart2 = part2;
					pRelocs[iCurrRel].secname = NULL;
					pRelocs[iCurrRel].base = 0;
					pRelocs[iCurrRel].symbol = ofsbase | (addrbase << 8);
					pRelocs[iCurrRel].info = (ofsbase << 8) | (addrbase << 8);
					pRelocs[iCurrRel].offset = offset;

					switch (part2) {
					case 2:
						pRelocs[iCurrRel].type = R_MIPS_32;
						break;
					case 0:
						continue;
					case 3:
						pRelocs[iCurrRel].type = R_MIPS_26;
						break;
					case 6:
						pRelocs[iCurrRel].type = R_MIPS_X_J26;
						break;
					case 7:
						pRelocs[iCurrRel].type = R_MIPS_X_JAL26;
						break;
					case 4:
						pRelocs[iCurrRel].type = R_MIPS_X_HI16;
						pRelocs[iCurrRel].base = (s16) addend;
						break;
					case 1:
					case 5:
						pRelocs[iCurrRel].type = R_MIPS_LO16;
						break;
					default:
						COutput::Printf(LEVEL_DEBUG, "invalid relocation type\n");
						return 0;
					}
					temp1 = (cmd << (16 - part1s)) & 0xFFFF;
					temp1 = (temp1 >> (16 - part1s)) & 0xFFFF;
					temp2 = (cmd << (16 - (part1s + nbits + part2s))) & 0xFFFF;
					temp2 = (temp2 >> (16 - part2s)) & 0xFFFF;					
					COutput::Printf(LEVEL_DEBUG, "CMD=0x%04X I1=0x%02X I2=0x%02X PART1=0x%02X PART2=0x%02X\n", cmd, temp1, temp2, part1, part2);
					pRelocs[iCurrRel].info |= pRelocs[iCurrRel].type;
					iCurrRel++;
				}
			}
		}
	}
	return iCurrRel;
}


bool CProcessPrx::LoadRelocs()
{
	bool blRet = false;
	int  iRelocCount = 0;
	int  iCurrRel = 0;
	int  count;
	int  iLoop;

	iRelocCount = this->CountRelocs();

	if(iRelocCount > 0)
	{
		SAFE_ALLOC(m_pElfRelocs, ElfReloc[iRelocCount]);
		if(m_pElfRelocs != NULL)
		{

			memset(m_pElfRelocs, 0, sizeof(ElfReloc) * iRelocCount);
			
			COutput::Printf(LEVEL_DEBUG, "Loading Type A relocs\n");
			count = this->LoadRelocsTypeA (&m_pElfRelocs[iCurrRel]);
			if (count) {
				iCurrRel += count;
			} else {
			}

			COutput::Printf(LEVEL_DEBUG, "Loading Type B relocs\n");
			count = this->LoadRelocsTypeB (&m_pElfRelocs[iCurrRel]);
			if (count) {
				iCurrRel += count;
			} else {
			}
			m_iRelocCount = iCurrRel;
			
			if(COutput::GetDebug())
			{
				COutput::Printf(LEVEL_DEBUG, "Dumping relocs %d\n", m_iRelocCount);
				for(iLoop = 0; iLoop < m_iRelocCount; iLoop++)
				{
					if(m_pElfRelocs[iLoop].type < 16)
					{
						COutput::Printf(LEVEL_DEBUG, "Reloc %s:%d Type:%s Symbol:%d Offset %08X Info:%08X\n", 
								m_pElfRelocs[iLoop].secname, iLoop, g_szRelTypes[m_pElfRelocs[iLoop].type],
								m_pElfRelocs[iLoop].symbol, m_pElfRelocs[iLoop].offset, m_pElfRelocs[iLoop].info);
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
		u8 *pData = NULL;
		u32 iAddr = 0;

		FreeMemory();
		m_blPrxLoaded = false;

		m_vMem = CVirtualMem(m_pElfBin, m_iBinSize, m_iBaseAddr, MEM_LITTLE_ENDIAN);

		pInfoSect = ElfFindSection(PSP_MODULE_INFO_NAME);
		if(pInfoSect == NULL)
		{
			/* Get from program headers */
			if(m_iPHCount > 0)
			{
				iAddr = m_pElfPrograms[0].iVaddr + (m_pElfPrograms[0].iPaddr & 0x7FFFFFFF) - m_pElfPrograms[0].iOffset;
				pData = m_pElfBin + iAddr;
			}
		}
		else
		{
			pData = pInfoSect->pData;
			iAddr = pInfoSect->iAddr;
		}

		if(pData != NULL)
		{
			if((FillModule(pData, iAddr)) && (LoadExports()) && (LoadImports()) && (CreateFakeSections()) && (LoadRelocs()))
			{
				COutput::Printf(LEVEL_INFO, "Loaded PRX %s successfully\n", szFilename);
				blRet = true;
				m_blPrxLoaded = true;
				BuildMaps();
			}
		}
		else
		{
			COutput::Printf(LEVEL_ERROR, "Could not find module section\n");
		}
	}

	return blRet;
}

bool CProcessPrx::LoadFromBinFile(const char *szFilename, unsigned int dwDataBase)
{
	bool blRet = false;

	if(CProcessElf::LoadFromBinFile(szFilename, dwDataBase))
	{
		FreeMemory();
		m_blPrxLoaded = false;

		m_vMem = CVirtualMem(m_pElfBin, m_iBinSize, m_iBaseAddr, MEM_LITTLE_ENDIAN);

		COutput::Printf(LEVEL_INFO, "Loaded BIN %s successfully\n", szFilename);
		blRet = true;
		m_blPrxLoaded = true;
		BuildMaps();
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

void CProcessPrx::CalcElfSize(size_t &iTotal, size_t &iSectCount, size_t &iStrSize)
{
	int i;
	int iBinBase;

	/* Sect count 2 for NULL and string sections */
	iSectCount = 2;
	iTotal = 0;
	/* 1 for NUL for NULL section */
	iStrSize = 2 + strlen(".shstrtab"); 
	iBinBase = 0;

	for(i = 1; i < m_iSHCount; i++)
	{
		if(m_pElfSections[i].iFlags & SHF_ALLOC)
		{
			iSectCount++;
			iStrSize += strlen(m_pElfSections[i].szName) + 1;
		}
	}

	iTotal = sizeof(Elf32_Ehdr) + (sizeof(Elf32_Shdr)*iSectCount) + iStrSize;
}

bool CProcessPrx::OutputElfHeader(FILE *fp, size_t iSectCount)
{
	Elf32_Ehdr hdr;

	memset(&hdr, 0, sizeof(hdr));
	SW(hdr.e_magic, ELF_MAGIC);
	hdr.e_class = 1;
	hdr.e_data = 1;
	hdr.e_idver = 1;
	SH(hdr.e_type, ELF_MIPS_TYPE);
	SH(hdr.e_machine, 8); 
	SW(hdr.e_version, 1);
	SW(hdr.e_entry, m_dwBase + m_elfHeader.iEntry); 
	SW(hdr.e_phoff, 0);
	SW(hdr.e_shoff, sizeof(Elf32_Ehdr));
	SW(hdr.e_flags, 0x10a23001);
	SH(hdr.e_ehsize, sizeof(Elf32_Ehdr));
	SH(hdr.e_phentsize, sizeof(Elf32_Phdr));
	SH(hdr.e_phnum, 0);
	SH(hdr.e_shentsize, sizeof(Elf32_Shdr));
	SH(hdr.e_shnum, iSectCount);
	SH(hdr.e_shstrndx, iSectCount-1);

	if(fwrite(&hdr, 1, sizeof(hdr), fp) != sizeof(hdr))
	{
		return false;
	}

	return true;
}

bool CProcessPrx::OutputSections(FILE *fp, size_t iElfHeadSize, size_t iSectCount, size_t iStrSize)
{
	Elf32_Shdr shdr;
	size_t iStrPointer = 1;
	size_t iBinBase;
	int i;
	char *pStrings;

	pStrings = new char[iStrSize];
	if(pStrings == NULL)
	{
		return false;
	}
	memset(pStrings, 0, iStrSize);

	iBinBase = (iElfHeadSize + 15) & ~15;
	memset(&shdr, 0, sizeof(shdr));
	/* Write NULL section */
	if(fwrite(&shdr, 1, sizeof(shdr), fp) != sizeof(shdr))
	{
		return false;
	}

	for(i = 1; i < m_iSHCount; i++)
	{
		if(m_pElfSections[i].iFlags & SHF_ALLOC)
		{
			SW(shdr.sh_name, iStrPointer);
			SW(shdr.sh_type, m_pElfSections[i].iType);
			SW(shdr.sh_flags, m_pElfSections[i].iFlags);
			SW(shdr.sh_addr, m_pElfSections[i].iAddr + m_dwBase);
			if(m_pElfSections[i].iType == SHT_NOBITS)
			{
				SW(shdr.sh_offset, iBinBase + m_iElfSize);
			}
			else
			{
				SW(shdr.sh_offset, iBinBase + m_pElfSections[i].iAddr);
			}
			SW(shdr.sh_size, m_pElfSections[i].iSize);
			SW(shdr.sh_link, 0);
			SW(shdr.sh_info, 0);
			SW(shdr.sh_addralign, m_pElfSections[i].iAddralign);
			SW(shdr.sh_entsize, 0);
			if(fwrite(&shdr, 1, sizeof(shdr), fp) != sizeof(shdr))
			{
				return false;
			}
			strcpy(&pStrings[iStrPointer], m_pElfSections[i].szName);
			iStrPointer += strlen(m_pElfSections[i].szName) + 1;
		}
	}

	/* Write string section */
	SW(shdr.sh_name, iStrPointer);
	SW(shdr.sh_type, SHT_STRTAB);
	SW(shdr.sh_flags, 0);
	SW(shdr.sh_addr, 0);
	SW(shdr.sh_offset, sizeof(Elf32_Ehdr) + (sizeof(Elf32_Shdr)*iSectCount));
	SW(shdr.sh_size, iStrSize);
	SW(shdr.sh_link, 0);
	SW(shdr.sh_info, 0);
	SW(shdr.sh_addralign, 1);
	SW(shdr.sh_entsize, 0);
	if(fwrite(&shdr, 1, sizeof(shdr), fp) != sizeof(shdr))
	{
		return false;
	}

	strcpy(&pStrings[iStrPointer], ".shstrtab");
	iStrPointer += strlen(".shstrtab") + 1;

	assert(iStrSize == iStrPointer);

	if(fwrite(pStrings, 1, iStrSize, fp) != (unsigned) iStrSize)
	{
		return false;
	}

	delete pStrings;

	return true;
}

bool CProcessPrx::PrxToElf(FILE *fp)
{
	size_t iElfHeadSize = 0;
	size_t iSectCount = 0;
	size_t iStrSize = 0;
	size_t iAlign = 0;

	/* Fixup the elf file and output it to fp */
	if((fp == NULL) || (m_blPrxLoaded == false))
	{
		return false;
	}

	CalcElfSize(iElfHeadSize, iSectCount, iStrSize);
	COutput::Printf(LEVEL_INFO, "size: %d, sectcount: %d, strsize: %d\n", iElfHeadSize, iSectCount, iStrSize);
	if(!OutputElfHeader(fp, iSectCount))
	{
		COutput::Printf(LEVEL_INFO, "Could not write ELF header\n");
		return false;
	}

	if(!OutputSections(fp, iElfHeadSize, iSectCount, iStrSize))
	{
		COutput::Printf(LEVEL_INFO, "Could not write ELF sections\n");
		return false;
	}

	/* Align data size */
	iAlign = iElfHeadSize & 15;
	if(iAlign > 0)
	{
		char align[16];

		iAlign = 16 - iAlign;
		memset(align, 0, sizeof(align));
		if(fwrite(align, 1, iAlign, fp) != iAlign)
		{
			COutput::Printf(LEVEL_INFO, "Could not write alignment\n");
			return false;
		}
	}

	if(fwrite(m_pElfBin, 1, m_iElfSize, fp) != m_iElfSize)
	{
		COutput::Printf(LEVEL_INFO, "Could not write out binary image\n");
		return false;
	}

	fflush(fp);

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

PspLibExport *CProcessPrx::GetExports()
{
	return m_modInfo.exp_head;
}

ElfSymbol* CProcessPrx::GetSymbols(int &iCount)
{
	iCount = m_iSymCount;
	return m_pElfSymbols;
}

void CProcessPrx::BuildSymbols(SymbolMap &syms, u32 dwBase)
{
	/* First map in imports and exports */
	PspLibExport *pExport;
	PspLibImport *pImport;
	int iLoop;

	/* If we have a symbol table then no point building from imports/exports */
	if(m_pElfSymbols)
	{
		int i;

		for(i = 0; i < m_iSymCount; i++)
		{
			int iType;
			iType = ELF32_ST_TYPE(m_pElfSymbols[i].info);
			if((iType == STT_FUNC) || (iType == STT_OBJECT))
			{
				SymbolEntry *s;
				s = syms[m_pElfSymbols[i].value + dwBase];
				if(s == NULL)
				{
					s = new SymbolEntry;
					s->addr = m_pElfSymbols[i].value + dwBase;
					if(iType == STT_FUNC)
					{
						s->type = SYMBOL_FUNC;
					}
					else
					{
						s->type = SYMBOL_DATA;
					}
					s->size = m_pElfSymbols[i].size;
					s->name = m_pElfSymbols[i].symname; 
					syms[m_pElfSymbols[i].value + dwBase] = s;
				}
				else
				{
					if(strcmp(s->name.c_str(), m_pElfSymbols[i].symname))
					{
						s->alias.insert(s->alias.end(), m_pElfSymbols[i].symname);
					}
				}
			}
		}
	}
	else
	{
		pExport = m_modInfo.exp_head;
		pImport = m_modInfo.imp_head;

		while(pExport != NULL)
		{
			if(pExport->f_count > 0)
			{
				for(iLoop = 0; iLoop < pExport->f_count; iLoop++)
				{
					SymbolEntry *s;

					s = syms[pExport->funcs[iLoop].addr + dwBase];
					if(s)
					{
						if(strcmp(s->name.c_str(), pExport->funcs[iLoop].name))
						{
							s->alias.insert(s->alias.end(), pExport->funcs[iLoop].name);
						}
						s->exported.insert(s->exported.end(), pExport);
					}
					else
					{
						s = new SymbolEntry;
						s->addr = pExport->funcs[iLoop].addr + dwBase;
						s->type = SYMBOL_FUNC;
						s->size = 0;
						s->name = pExport->funcs[iLoop].name;
						s->exported.insert(s->exported.end(), pExport);
						syms[pExport->funcs[iLoop].addr + dwBase] = s;
					}
				}
			}

			if(pExport->v_count > 0)
			{
				for(iLoop = 0; iLoop < pExport->v_count; iLoop++)
				{
					SymbolEntry *s;

					s = syms[pExport->vars[iLoop].addr + dwBase];
					if(s)
					{
						if(strcmp(s->name.c_str(), pExport->vars[iLoop].name))
						{
							s->alias.insert(s->alias.end(), pExport->vars[iLoop].name);
						}
						s->exported.insert(s->exported.end(), pExport);
					}
					else
					{
						s = new SymbolEntry;
						s->addr = pExport->vars[iLoop].addr + dwBase;
						s->type = SYMBOL_DATA;
						s->size = 0;
						s->name = pExport->vars[iLoop].name;
						s->exported.insert(s->exported.end(), pExport);
						syms[pExport->vars[iLoop].addr + dwBase] = s;
					}
				}
			}

			pExport = pExport->next;
		}

		while(pImport != NULL)
		{
			if(pImport->f_count > 0)
			{
				for(iLoop = 0; iLoop < pImport->f_count; iLoop++)
				{
					SymbolEntry *s = new SymbolEntry;
					s->addr = pImport->funcs[iLoop].addr + dwBase;
					s->type = SYMBOL_FUNC;
					s->size = 0;
					s->name = pImport->funcs[iLoop].name;
					s->imported.insert(s->imported.end(), pImport);
					syms[pImport->funcs[iLoop].addr + dwBase] = s;
				}
			}

			if(pImport->v_count > 0)
			{
				for(iLoop = 0; iLoop < pImport->v_count; iLoop++)
				{
					SymbolEntry *s = new SymbolEntry;
					s->addr = pImport->vars[iLoop].addr + dwBase;
					s->type = SYMBOL_DATA;
					s->size = 0;
					s->name = pImport->vars[iLoop].name;
					s->imported.insert(s->imported.end(), pImport);
					syms[pImport->vars[iLoop].addr + dwBase] = s;
				}
			}

			pImport = pImport->next;
		}
	}
}

void CProcessPrx::FreeSymbols(SymbolMap &syms)
{
	SymbolMap::iterator start = syms.begin();
	SymbolMap::iterator end = syms.end();

	while(start != end)
	{
		SymbolEntry *p;
		p = syms[(*start).first];
		if(p)
		{
			delete p;
			syms[(*start).first] = NULL;
		}
		++start;
	}
}

void CProcessPrx::FreeImms(ImmMap &imms)
{
	ImmMap::iterator start = imms.begin();
	ImmMap::iterator end = imms.end();

	while(start != end)
	{
		ImmEntry *i;

		i = imms[(*start).first];
		if(i)
		{
			delete i;
			imms[(*start).first] = NULL;
		}
		++start;
	}
}

void CProcessPrx::FixupRelocs(u32 dwBase, ImmMap &imms)
{
	int iLoop;
	u32 *pData;
	u32 regs[32];

	/* Fixup the elf file and output it to fp */
	if((m_blPrxLoaded == false))
	{
		return;
	}

	if((m_elfHeader.iPhnum < 1) || (m_elfHeader.iPhentsize == 0) || (m_elfHeader.iPhoff == 0))
	{
		return;
	}

	/* We dont support ELF relocs as they are not very special */
	if(m_elfHeader.iType != ELF_PRX_TYPE)
	{
		return;
	}

	pData = NULL;
	for(iLoop = 0; iLoop < m_iRelocCount; iLoop++)
	{
		ElfReloc *rel = &m_pElfRelocs[iLoop];
		u32 dwRealOfs;
		u32 dwCurrBase;
		int iOfsPH;
		int iValPH;

		iOfsPH = rel->symbol & 0xFF;
		iValPH = (rel->symbol >> 8) & 0xFF;
		if((iOfsPH >= m_iPHCount) || (iValPH >= m_iPHCount))
		{
			COutput::Printf(LEVEL_DEBUG, "Invalid relocation PH sets (%d, %d)\n", iOfsPH, iValPH);
			continue;
		}
		dwRealOfs = rel->offset + m_pElfPrograms[iOfsPH].iVaddr;
		dwCurrBase = dwBase + m_pElfPrograms[iValPH].iVaddr;
		pData = (u32*) m_vMem.GetPtr(dwRealOfs);
		if(pData == NULL)
		{
			COutput::Printf(LEVEL_DEBUG, "Invalid offset for relocation (%08X)\n", dwRealOfs);
			continue;
		}

		switch(m_pElfRelocs[iLoop].type)
		{
			case R_MIPS_HI16: {
				u32 inst;
				int base = iLoop;
				int lowaddr, hiaddr, addr;
			  	int loinst;
			  	ImmEntry *imm;
			  	int ofsph = m_pElfPrograms[iOfsPH].iVaddr;
			  	
				inst = LW(*pData);
				addr = ((inst & 0xFFFF) << 16) + dwCurrBase;
				COutput::Printf(LEVEL_DEBUG, "Hi at (%08X) %d\n", dwRealOfs, iLoop);
			  	while (++iLoop < m_iRelocCount) {
			  		if (m_pElfRelocs[iLoop].type != R_MIPS_HI16) break;
			  	}
				COutput::Printf(LEVEL_DEBUG, "Matching low at %d\n", iLoop);
			  	if (iLoop < m_iRelocCount) {
					loinst = LW(*((u32*) m_vMem.GetPtr(m_pElfRelocs[iLoop].offset+ofsph)));
				} else {
					loinst = 0;
				}

				addr = (s32) addr + (s16) (loinst & 0xFFFF);
				lowaddr = addr & 0xFFFF;
				hiaddr = (((addr >> 15) + 1) >> 1) & 0xFFFF;
				while (base < iLoop) {
					inst = LW(*((u32*)m_vMem.GetPtr(m_pElfRelocs[base].offset+ofsph)));
					inst = (inst & ~0xFFFF) | hiaddr;
					SW(*((u32*)m_vMem.GetPtr(m_pElfRelocs[base].offset+ofsph)), inst);
					base++;
				}
			  	while (iLoop < m_iRelocCount) {
					inst = LW(*((u32*)m_vMem.GetPtr(m_pElfRelocs[iLoop].offset+ofsph)));
					if ((inst & 0xFFFF) != (loinst & 0xFFFF)) break;
					inst = (inst & ~0xFFFF) | lowaddr;
					SW(*((u32*)m_vMem.GetPtr(m_pElfRelocs[iLoop].offset+ofsph)), inst);
									
					imm = new ImmEntry;
					imm->addr = dwBase + ofsph + m_pElfRelocs[iLoop].offset;
					imm->target = addr;
					imm->text = ElfAddrIsText(addr - dwBase);
					imms[dwBase + ofsph + m_pElfRelocs[iLoop].offset] = imm;

			  		if (m_pElfRelocs[++iLoop].type != R_MIPS_LO16) break;
				}
				iLoop--;
				COutput::Printf(LEVEL_DEBUG, "Finished at %d\n", iLoop);
			}
			break;
			case R_MIPS_16:
			case R_MIPS_LO16: {
				u32 loinst;
				u32 addr;
				ImmEntry *imm;

				loinst = LW(*pData);
				addr = ((s16) (loinst & 0xFFFF)) + dwCurrBase;
				COutput::Printf(LEVEL_DEBUG, "Low at (%08X)\n", dwRealOfs);

				imm = new ImmEntry;
				imm->addr = dwRealOfs + dwBase;
				imm->target = addr;
				imm->text = ElfAddrIsText(addr - dwBase);
				imms[dwRealOfs + dwBase] = imm;

				loinst &= ~0xFFFF;
				loinst |= (addr & 0xFFFF);
				SW(*pData, loinst);
			}
			break;
			case R_MIPS_X_HI16: {
				u32 hiinst;
				u32 addr, hiaddr;
				ImmEntry *imm;

				hiinst = LW(*pData);
				addr = (hiinst & 0xFFFF) << 16;
				addr += rel->base + dwCurrBase;
				hiaddr = (((addr >> 15) + 1) >> 1) & 0xFFFF;
				COutput::Printf(LEVEL_DEBUG, "Extended hi at (%08X)\n", dwRealOfs);

				imm = new ImmEntry;
				imm->addr = dwRealOfs + dwBase;
				imm->target = addr;
				imm->text = ElfAddrIsText(addr - dwBase);
				imms[dwRealOfs + dwBase] = imm;

				hiinst &= ~0xFFFF;
				hiinst |= (hiaddr & 0xFFFF);
				SW(*pData, hiinst);			
			}
			break;
			case R_MIPS_X_J26:
			case R_MIPS_X_JAL26:
			case R_MIPS_26: {
				u32 dwAddr;
				u32 dwInst;

				dwInst = LW(*pData);
				dwAddr = (dwInst & 0x03FFFFFF) << 2;
				dwAddr += dwCurrBase;
				dwInst &= ~0x03FFFFFF;
				dwAddr = (dwAddr >> 2) & 0x03FFFFFF;
				dwInst |= dwAddr;
				SW(*pData, dwInst);
			}
			break;
			case R_MIPS_32:   {
				u32 dwData;
				ImmEntry *imm;

				dwData = LW(*pData);
				dwData += dwCurrBase;
				SW(*pData, dwData);

				imm = new ImmEntry;
				imm->addr = dwRealOfs + dwBase;
				imm->target = dwData;
				imm->text = ElfAddrIsText(dwData - dwBase);
				imms[dwRealOfs + dwBase] = imm;
			}
			break;
			default: /* Do nothing */
			break;
		};
	}

}

/* Print a row of a memory dump, up to row_size */
void CProcessPrx::PrintRow(FILE *fp, const u32* row, s32 row_size, u32 addr)
{
	char buffer[512];
	char *p = buffer;
	int i = 0;

	sprintf(p, "0x%08X - ", addr);
	p += strlen(p);

	for(i = 0; i < 16; i++)
	{
		if(i < row_size)
		{
			sprintf(p, "%02X ", row[i]);
		}
		else
		{
			sprintf(p, "-- ");
		}

		p += strlen(p);

		if((i < 15) && ((i & 3) == 3))
		{
			*p++ = '|';
			*p++ = ' ';
		}
	}

	sprintf(p, "- ");
	p += strlen(p);

	for(i = 0; i < 16; i++)
	{
		if(i < row_size)
		{
			if((row[i] >= 32) && (row[i] < 127))
			{
				if(m_blXmlDump && (row[i] == '<'))
				{
					strcpy(p, "&lt;");
					p += strlen(p);
				}
				else
				{
					*p++ = row[i];
				}
			}
			else
			{
				*p++ =  '.';
			}
		}
		else
		{
			*p++ = '.';
		}
	}
	*p = 0;

	fprintf(fp, "%s\n", buffer);
}

void CProcessPrx::DumpData(FILE *fp, u32 dwAddr, u32 iSize, unsigned char *pData)
{
	u32 i;
	u32 row[16];
	int row_size;

	fprintf(fp, "           - 00 01 02 03 | 04 05 06 07 | 08 09 0A 0B | 0C 0D 0E 0F - 0123456789ABCDEF\n");
	fprintf(fp, "-------------------------------------------------------------------------------------\n");
	memset(row, 0, sizeof(row));
	row_size = 0;
	for(i = 0; i < iSize; i++)
	{
		row[row_size] = pData[i];
		row_size++;
		if(row_size == 16)
		{
			if(m_blXmlDump)
			{
				fprintf(fp, "<a name=\"0x%08X\"></a>", dwAddr & ~15);
			}
			PrintRow(fp, row, row_size, dwAddr);
			dwAddr += 16;
			row_size = 0;
			memset(row, 0, sizeof(row));
		}
	}
	if(row_size > 0)
	{
		if(m_blXmlDump)
		{
			fprintf(fp, "<a name=\"0x%08X\"></a>", dwAddr & ~15);
		}
		PrintRow(fp, row, row_size, dwAddr);
	}
}

#define ISSPACE(x) ((x) == '\t' || (x) == '\r' || (x) == '\n' || (x) == '\v' || (x) == '\f')

bool CProcessPrx::ReadString(u32 dwAddr, std::string &str, bool unicode, u32 *dwRet)
{
	int i;
	std::string curr = "";
	int iSize = m_vMem.GetSize(dwAddr);
	unsigned int ch;
	bool blRet = false;
	int iRealLen = 0;

	if(unicode)
	{
		/* If a misaligned word address then exit, little chance it is a valid unicode string */
		if(dwAddr & 1)
		{
			return false;
		}

		iSize = iSize / 2;
	}

	for(i = 0; i < iSize; i++)
	{
		/* Dirty unicode, we dont _really_ care about it being unicode
		 * as opposed to being 16bits */
		if(!unicode)
		{
			ch = m_vMem.GetU8(dwAddr);
			dwAddr++;
		}
		else
		{
			ch = m_vMem.GetU16(dwAddr);
			dwAddr += 2;
		}

		if(ISSPACE(ch) || ((ch >= 32) && (ch < 127)))
		{
			if((ch >= 32) && (ch < 127))
			{
				if((m_blXmlDump) && (ch == '<'))
				{
					curr += "&lt;";
				}
				else
				{
					curr += (unsigned char) ch;
				}
				iRealLen++;
			}
			else
			{
				const char *temp = NULL;

				switch(ch)
				{
					case '\t': temp = "\\t";
							   break;
					case '\r': temp = "\\r";
							   break;
					case '\n': temp = "\\n";
							   break;
					case '\v': temp = "\\v";
							   break;
					case '\f': temp = "\\f";
							   break;
					default:   break;
				};

				if(temp)
				{
					curr += temp;
					iRealLen++;
				}
			}
		}
		else
		{
			if((ch == 0) && (iRealLen >= MINIMUM_STRING))
			{
				blRet = true;

				if(dwRet)
				{
					*dwRet = dwAddr;
				}

				if(unicode)
				{
					str = "L\"" + curr + "\"";
				}
				else
				{
					str = "\"" + curr + "\"";
				}
			}
			break;
		}
	}

	return blRet;
}

void CProcessPrx::DumpStrings(FILE *fp, u32 dwAddr, u32 iSize, unsigned char *pData)
{
	std::string curr = "";
	int iPrintHead = 0;
	u32 dwNext;
	u32 dwEnd;

	if(iSize > MINIMUM_STRING)
	{
		dwEnd = dwAddr + iSize - MINIMUM_STRING;
		while(dwAddr < dwEnd)
		{
			if(ReadString(dwAddr - m_dwBase, curr, false, &dwNext) || ReadString(dwAddr - m_dwBase, curr, true, &dwNext))
			{
				if(iPrintHead == 0)
				{
					fprintf(fp, "\n; Strings\n");
					iPrintHead = 1;
				}
				fprintf(fp, "0x%08X: %s\n", dwAddr, curr.c_str());
				dwAddr = dwNext + m_dwBase;
			}
			else
			{
				dwAddr++;
			}
		}
	}
}

void CProcessPrx::Disasm(FILE *fp, u32 dwAddr, u32 iSize, unsigned char *pData, ImmMap &imms, u32 dwBase)
{
	u32 iILoop;
	u32 *pInst;
	pInst  = (u32*) pData;
	u32 inst;
	SymbolEntry *lastFunc = NULL;
	unsigned int lastFuncAddr = 0;

	for(iILoop = 0; iILoop < (iSize / 4); iILoop++)
	{
		SymbolEntry *s;
		FunctionType *t;
		ImmEntry *imm;

		inst = LW(pInst[iILoop]);
		s = disasmFindSymbol(dwAddr);
		if(s)
		{
			switch(s->type)
			{
				case SYMBOL_FUNC: fprintf(fp, "\n; ======================================================\n");
						    	  fprintf(fp, "; Subroutine %s - Address 0x%08X ", s->name.c_str(), dwAddr);
								  if(s->alias.size() > 0)
								  {
									  fprintf(fp, "- Aliases: ");
									  u32 i;
									  for(i = 0; i < s->alias.size()-1; i++)
									  {
										  fprintf(fp, "%s, ", s->alias[i].c_str());
									  }
									 fprintf(fp, "%s", s->alias[i].c_str());
								  }
								  fprintf(fp, "\n");
								  t = m_pCurrNidMgr->FindFunctionType(s->name.c_str());
								  if(t)
								  {
									  fprintf(fp, "; Prototype: %s (*)(%s)\n", t->ret, t->args);
								  }
								  if(s->size > 0)
								  {
									  lastFunc = s;
									  lastFuncAddr = dwAddr + s->size;
								  }
								  if(s->exported.size() > 0)
								  {
									  unsigned int i;
									  for(i = 0; i < s->exported.size(); i++)
									  {
										if(m_blXmlDump)
										{
											fprintf(fp, "<a name=\"%s_%s\"></a>; Exported in %s\n", 
													s->exported[i]->name, s->name.c_str(), s->exported[i]->name);
										}
										else
										{
											fprintf(fp, "; Exported in %s\n", s->exported[i]->name);
										}
									  }
								  }
								  if(s->imported.size() > 0)
								  {
									  unsigned int i;
									  for(i = 0; i < s->imported.size(); i++)
									  {
										  if((m_blXmlDump) && (strlen(s->imported[i]->file) > 0))
										  {
											  fprintf(fp, "; Imported from <a href=\"%s.html#%s_%s\">%s</a>\n", 
													  s->imported[i]->file, s->imported[i]->name, 
													  s->name.c_str(), s->imported[i]->file);
										  }
										  else
										  {
											  fprintf(fp, "; Imported from %s\n", s->imported[i]->name);
										  }
									  }
								  }
								  if(m_blXmlDump)
								  {
								 	  fprintf(fp, "<a name=\"%s\">%s:</a>\n", s->name.c_str(), s->name.c_str());
								  }
								  else
								  {
									  fprintf(fp, "%s:", s->name.c_str());
								  }
								  break;
				case SYMBOL_LOCAL: fprintf(fp, "\n");
								   if(m_blXmlDump)
								   {
								 	  fprintf(fp, "<a name=\"%s\">%s:</a>\n", s->name.c_str(), s->name.c_str());
								   }
								   else
								   {
									   fprintf(fp, "%s:", s->name.c_str());
								   }
								   break;
				default: /* Do nothing atm */
								   break;
			};

			if(s->refs.size() > 0)
			{
				u32 i;
				fprintf(fp, "\t\t; Refs: ");
				for(i = 0; i < s->refs.size(); i++)
				{
					if(m_blXmlDump)
					{
						fprintf(fp, "<a href=\"#0x%08X\">0x%08X</a> ", s->refs[i], s->refs[i]);
					}
					else
					{
						fprintf(fp, "0x%08X ", s->refs[i]);
					}
				}
			}
			fprintf(fp, "\n");
		}

		imm = imms[dwAddr];
		if(imm)
		{
			SymbolEntry *sym = disasmFindSymbol(imm->target);
			if(imm->text)
			{
				if(sym)
				{
					if(m_blXmlDump)
					{
						fprintf(fp, "; Text ref <a href=\"#%s\">%s</a> (0x%08X)", sym->name.c_str(), sym->name.c_str(), imm->target);
					}
					else
					{
						fprintf(fp, "; Text ref %s (0x%08X)", sym->name.c_str(), imm->target);
					}
				}
				else
				{
					if(m_blXmlDump)
					{
						fprintf(fp, "; Text ref <a href=\"#0x%08X\">0x%08X</a>", imm->target, imm->target);
					}
					else
					{
						fprintf(fp, "; Text ref 0x%08X", imm->target);
					}
				}
			}
			else
			{
				std::string str;

				if(m_blXmlDump)
				{
					fprintf(fp, "; Data ref <a href=\"#0x%08X\">0x%08X</a>", imm->target & ~15, imm->target);
				}
				else
				{
					fprintf(fp, "; Data ref 0x%08X", imm->target);
				}
				if(ReadString(imm->target-dwBase, str, false, NULL) || ReadString(imm->target-dwBase, str, true, NULL))
				{
					fprintf(fp, " %s", str.c_str());
				}
				else
				{
					u8 *ptr = (u8*) m_vMem.GetPtr(imm->target - dwBase);
					if(ptr)
					{
						/* If a valid pointer try and print some data */
						int i;
						fprintf(fp, " ... ");
						if((imm->target & 3) == 0)
						{
							u32 *p32 = (u32*) ptr;
							/* Possibly words */
							for(i = 0; i < 4; i++)
							{
								fprintf(fp, "0x%08X ", LW(*p32));
								p32++;
							}
						}
						else
						{
							/* Just guess at printing bytes */
							for(i = 0; i < 16; i++)
							{
								fprintf(fp, "0x%02X ", *ptr++);
							}
						}
					}
				}
			}
			fprintf(fp, "\n");
		}

		/* Check if this is a jump */
		if((inst & 0xFC000000) == 0x0C000000)
		{
			u32 dwJump = (inst & 0x03FFFFFF) << 2;
			SymbolEntry *s;
			FunctionType *t;
			dwJump |= (dwBase & 0xF0000000);

			s = disasmFindSymbol(dwJump);
			if(s)
			{
				t = m_pCurrNidMgr->FindFunctionType(s->name.c_str());
				if(t)
				{
					fprintf(fp, "; Call - %s %s(%s)\n", t->ret, t->name, t->args);
				}
			}
		}

		if(m_blXmlDump)
		{
			fprintf(fp, "<a name=\"0x%08X\"></a>", dwAddr);
		}
		fprintf(fp, "\t%-40s\n", disasmInstruction(inst, dwAddr, NULL, NULL, 0));
		dwAddr += 4;
		if((lastFunc != NULL) && (dwAddr >= lastFuncAddr))
		{
			fprintf(fp, "\n; End Subroutine %s\n", lastFunc->name.c_str());
			fprintf(fp, "; ======================================================\n");
			lastFunc = NULL;
			lastFuncAddr = 0;
		}
	}
}

void CProcessPrx::DisasmXML(FILE *fp, u32 dwAddr, u32 iSize, unsigned char *pData, ImmMap &imms, u32 dwBase)
{
	u32 iILoop;
	u32 *pInst;
	pInst  = (u32*) pData;
	u32 inst;
	int infunc = 0;

	for(iILoop = 0; iILoop < (iSize / 4); iILoop++)
	{
		SymbolEntry *s;
		//FunctionType *t;
		//ImmEntry *imm;

		inst = LW(pInst[iILoop]);
		s = disasmFindSymbol(dwAddr);
		if(s)
		{
			switch(s->type)
			{
				case SYMBOL_FUNC: if(infunc)
								  {
									  fprintf(fp, "</func>\n");
								  }
								  else
								  {
									  infunc = 1;
								  }
								
						    	  fprintf(fp, "<func name=\"%s\" link=\"0x%08X\" ", s->name.c_str(), dwAddr);

								  if(s->refs.size() > 0)
								  {
									u32 i;
									fprintf(fp, "refs=\"");
									for(i = 0; i < s->refs.size(); i++)
									{
										if(i < (s->refs.size() - 1))
										{
											fprintf(fp, "0x%08X,", s->refs[i]);
										}
										else
										{
											fprintf(fp, "0x%08X", s->refs[i]);
										}
									}
									fprintf(fp, "\" ");
								  }
						    	  fprintf(fp, ">\n");

								  /*
								  if(s->exported.size() > 0)
								  {
									  unsigned int i;
									  for(i = 0; i < s->exported.size(); i++)
									  {
										  unsigned int nid = 0;
										  PspLibExport *pExp = s->imported[0];

										  for(int i = 0; i < pImp->f_count; i++)
										  {
										  	if(strcmp(s->name.c_str(), pImp->funcs[i].name) == 0)
										  	{
										  		nid = pImp->funcs[i].nid;
										  		break;
										  	}
										  }
									  }
								  }
								  */


								  /*
								  if(s->alias.size() > 0)
								  {
									  fprintf(fp, "- Aliases: ");
									  u32 i;
									  for(i = 0; i < s->alias.size()-1; i++)
									  {
										  fprintf(fp, "%s, ", s->alias[i].c_str());
									  }
									 fprintf(fp, "%s", s->alias[i].c_str());
								  }
								  fprintf(fp, "\n");
								  t = m_pCurrNidMgr->FindFunctionType(s->name.c_str());
								  if(t)
								  {
									  fprintf(fp, "; Prototype: %s (*)(%s)\n", t->ret, t->args);
								  }
								  if(s->size > 0)
								  {
									  lastFunc = s;
									  lastFuncAddr = dwAddr + s->size;
								  }
								  if(s->exported.size() > 0)
								  {
									  unsigned int i;
									  for(i = 0; i < s->exported.size(); i++)
									  {
										if(m_blXmlDump)
										{
											fprintf(fp, "<a name=\"%s_%s\"></a>; Exported in %s\n", 
													s->exported[i]->name, s->name.c_str(), s->exported[i]->name);
										}
										else
										{
											fprintf(fp, "; Exported in %s\n", s->exported[i]->name);
										}
									  }
								  }
								  if(s->imported.size() > 0)
								  {
									  unsigned int i;
									  for(i = 0; i < s->imported.size(); i++)
									  {
										  if((m_blXmlDump) && (strlen(s->imported[i]->file) > 0))
										  {
											  fprintf(fp, "; Imported from <a href=\"%s.html#%s_%s\">%s</a>\n", 
													  s->imported[i]->file, s->imported[i]->name, 
													  s->name.c_str(), s->imported[i]->file);
										  }
										  else
										  {
											  fprintf(fp, "; Imported from %s\n", s->imported[i]->name);
										  }
									  }
								  }
								  */
								  break;
				case SYMBOL_LOCAL: fprintf(fp, "<local name=\"%s\" link=\"0x%08X\" ", s->name.c_str(), dwAddr);
								  if(s->refs.size() > 0)
								  {
									u32 i;
									fprintf(fp, "refs=\"");
									for(i = 0; i < s->refs.size(); i++)
									{
										if(i < (s->refs.size() - 1))
										{
											fprintf(fp, "0x%08X,", s->refs[i]);
										}
										else
										{
											fprintf(fp, "0x%08X", s->refs[i]);
										}
									}
									fprintf(fp, "\"");
								  }
						    	  fprintf(fp, "/>\n");
								   break;
				default: /* Do nothing atm */
								   break;
			};

		}

#if 0
		imm = imms[dwAddr];
		if(imm)
		{
			SymbolEntry *sym = disasmFindSymbol(imm->target);
			if(imm->text)
			{
				if(sym)
				{
					if(m_blXmlDump)
					{
						fprintf(fp, "; Text ref <a href=\"#%s\">%s</a> (0x%08X)", sym->name.c_str(), sym->name.c_str(), imm->target);
					}
					else
					{
						fprintf(fp, "; Text ref %s (0x%08X)", sym->name.c_str(), imm->target);
					}
				}
				else
				{
					if(m_blXmlDump)
					{
						fprintf(fp, "; Text ref <a href=\"#0x%08X\">0x%08X</a>", imm->target, imm->target);
					}
					else
					{
						fprintf(fp, "; Text ref 0x%08X", imm->target);
					}
				}
			}
			else
			{
				std::string str;

				if(m_blXmlDump)
				{
					fprintf(fp, "; Data ref <a href=\"#0x%08X\">0x%08X</a>", imm->target & ~15, imm->target);
				}
				else
				{
					fprintf(fp, "; Data ref 0x%08X", imm->target);
				}
				if(ReadString(imm->target-dwBase, str, false, NULL) || ReadString(imm->target-dwBase, str, true, NULL))
				{
					fprintf(fp, " %s", str.c_str());
				}
				else
				{
					u8 *ptr = (u8*) m_vMem.GetPtr(imm->target - dwBase);
					if(ptr)
					{
						/* If a valid pointer try and print some data */
						int i;
						fprintf(fp, " ... ");
						if((imm->target & 3) == 0)
						{
							u32 *p32 = (u32*) ptr;
							/* Possibly words */
							for(i = 0; i < 4; i++)
							{
								fprintf(fp, "0x%08X ", LW(*p32));
								p32++;
							}
						}
						else
						{
							/* Just guess at printing bytes */
							for(i = 0; i < 16; i++)
							{
								fprintf(fp, "0x%02X ", *ptr++);
							}
						}
					}
				}
			}
			fprintf(fp, "\n");
		}
#endif

		fprintf(fp, "<inst link=\"0x%08X\">%s</inst>\n", dwAddr, disasmInstructionXML(inst, dwAddr));
		dwAddr += 4;
	}

	if(infunc)
	{
		fprintf(fp, "</func>\n");
	}
}

int CProcessPrx::FindFuncExtent(u32 dwStart, u8 *pTouchMap)
{
	return 0;
}

void CProcessPrx::MapFuncExtents(SymbolMap &syms)
{
	SymbolMap::iterator start = syms.begin();
	SymbolMap::iterator end = syms.end();
	u8 *pTouchMap;

	pTouchMap = new u8[m_iBinSize];
	memset(pTouchMap, 0, m_iBinSize);

	while(start != end)
	{
		SymbolEntry *s;
		s = syms[(*start).first];
		if((s->type == SYMBOL_FUNC) && (s->size == 0))
		{
			int size;

			size = FindFuncExtent(s->addr, pTouchMap);
			if(size > 0)
			{
				s->size = size;
			}
		}

		start++;
	}
}

bool CProcessPrx::BuildMaps()
{
	int iLoop;

	if(m_pElfRelocs)
	{
		FixupRelocs(m_dwBase, m_imms);
	}
	BuildSymbols(m_syms, m_dwBase);

	ImmMap::iterator start = m_imms.begin();
	ImmMap::iterator end = m_imms.end();

	while(start != end)
	{
		ImmEntry *imm;
		u32 inst;

		imm = m_imms[(*start).first];
		inst = m_vMem.GetU32(imm->target - m_dwBase);
		if(imm->text)
		{
			SymbolEntry *s;

			s = m_syms[imm->target];
			if(s == NULL)
			{
				s = new SymbolEntry;
				char name[128];
				/* Hopefully most functions will start with a SP assignment */
				if((inst >> 16) == 0x27BD)
				{
					snprintf(name, sizeof(name), "sub_%08X", imm->target);
					s->type = SYMBOL_FUNC;
				}
				else
				{
					snprintf(name, sizeof(name), "loc_%08X", imm->target);
					s->type = SYMBOL_LOCAL;
				}
				s->addr = imm->target;
				s->size = 0;
				s->refs.insert(s->refs.end(), imm->addr);
				s->name = name;
				m_syms[imm->target] = s;
			}
			else
			{
				s->refs.insert(s->refs.end(), imm->addr);
			}
		}

		start++;
	}

	/* Build symbols for branches in the code */
	for(iLoop = 0; iLoop < m_iSHCount; iLoop++)
	{
		if(m_pElfSections[iLoop].iFlags & SHF_EXECINSTR)
		{
			u32 iILoop;
			u32 dwAddr;
			u32 *pInst;
			dwAddr = m_pElfSections[iLoop].iAddr;
			pInst  = (u32*) m_vMem.GetPtr(dwAddr);

			for(iILoop = 0; iILoop < (m_pElfSections[iLoop].iSize / 4); iILoop++)
			{
				disasmAddBranchSymbols(LW(pInst[iILoop]), dwAddr + m_dwBase, m_syms);
				dwAddr += 4;
			}
		}
	}

	if(m_syms[m_elfHeader.iEntry + m_dwBase] == NULL)
	{
		SymbolEntry *s;
		s = new SymbolEntry;
		/* Hopefully most functions will start with a SP assignment */
		s->type = SYMBOL_FUNC;
		s->addr = m_elfHeader.iEntry + m_dwBase;
		s->size = 0;
		s->name = "_start";
		m_syms[m_elfHeader.iEntry + m_dwBase] = s;
	}

	MapFuncExtents(m_syms);

	return true;
}

void CProcessPrx::Dump(FILE *fp, const char *disopts)
{
	int iLoop;

	disasmSetSymbols(&m_syms);
	disasmSetOpts(disopts, 1);

	if(m_blXmlDump)
	{
		disasmSetXmlOutput();
		fprintf(fp, "<html><body><pre>\n");
	}
	for(iLoop = 0; iLoop < m_iSHCount; iLoop++)
	{
		if(m_pElfSections[iLoop].iFlags & (SHF_EXECINSTR | SHF_ALLOC))
		{
			if((m_pElfSections[iLoop].iSize > 0) && (m_pElfSections[iLoop].iType == SHT_PROGBITS))
			{
				fprintf(fp, "\n; ==== Section %s - Address 0x%08X Size 0x%08X Flags 0x%04X\n", 
						m_pElfSections[iLoop].szName, m_pElfSections[iLoop].iAddr + m_dwBase, 
						m_pElfSections[iLoop].iSize, m_pElfSections[iLoop].iFlags);
				if(m_pElfSections[iLoop].iFlags & SHF_EXECINSTR)
				{
					Disasm(fp, m_pElfSections[iLoop].iAddr + m_dwBase, 
							m_pElfSections[iLoop].iSize, 
							(u8*) m_vMem.GetPtr(m_pElfSections[iLoop].iAddr),
							m_imms, m_dwBase);
				}
				else
				{
					DumpData(fp, m_pElfSections[iLoop].iAddr + m_dwBase, 
							m_pElfSections[iLoop].iSize,
							(u8*) m_vMem.GetPtr(m_pElfSections[iLoop].iAddr));
					DumpStrings(fp, m_pElfSections[iLoop].iAddr + m_dwBase, 
							m_pElfSections[iLoop].iSize, 
							(u8*) m_vMem.GetPtr(m_pElfSections[iLoop].iAddr));
				}
			}
		}
	}
	if(m_blXmlDump)
	{
		fprintf(fp, "</pre></body></html>\n");
	}

	disasmSetSymbols(NULL);
}

void CProcessPrx::DumpXML(FILE *fp, const char *disopts)
{
	int iLoop;
	char *slash;
	PspLibExport *pExport;

	disasmSetSymbols(&m_syms);
	disasmSetOpts(disopts, 1);

	slash = strrchr(m_szFilename, '/');
	if(!slash)
	{
		slash = m_szFilename;
	}
	else
	{
		slash++;
	}

	fprintf(fp, "<prx file=\"%s\" name=\"%s\">\n", slash, m_modInfo.name);
	fprintf(fp, "<exports>\n");
	pExport = m_modInfo.exp_head;
	while(pExport)
	{
		fprintf(fp, "<lib name=\"%s\">\n", pExport->name);
		for(int i = 0; i < pExport->f_count; i++)
		{
			fprintf(fp, "<func nid=\"0x%08X\" name=\"%s\" ref=\"0x%08X\" />\n", pExport->funcs[i].nid, pExport->funcs[i].name,
					pExport->funcs[i].addr);
		}
		fprintf(fp, "</lib>\n");
		pExport = pExport->next;
	}
	fprintf(fp, "</exports>\n");

	for(iLoop = 0; iLoop < m_iSHCount; iLoop++)
	{
		if(m_pElfSections[iLoop].iFlags & (SHF_EXECINSTR | SHF_ALLOC))
		{
			if((m_pElfSections[iLoop].iSize > 0) && (m_pElfSections[iLoop].iType == SHT_PROGBITS))
			{
				if(m_pElfSections[iLoop].iFlags & SHF_EXECINSTR)
				{
					fprintf(fp, "<disasm>\n");
					DisasmXML(fp, m_pElfSections[iLoop].iAddr + m_dwBase, 
							m_pElfSections[iLoop].iSize, 
							(u8*) m_vMem.GetPtr(m_pElfSections[iLoop].iAddr),
							m_imms, m_dwBase);
					fprintf(fp, "</disasm>\n");
				}
			}
		}
	}
	fprintf(fp, "</prx>\n");

	disasmSetSymbols(NULL);
}

void CProcessPrx::SetXmlDump()
{
	m_blXmlDump = true;
}

SymbolEntry *CProcessPrx::GetSymbolEntryFromAddr(u32 dwAddr)
{
	return m_syms[dwAddr];
}
