/***************************************************************
 * PRXTool : Utility for PSP executables.
 * (c) TyRaNiD 2k5
 *
 * ProcessElf.C - Implementation of a class to manipulate a ELF
 ***************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cassert>
#include "ProcessElf.h"
#include "output.h"

CProcessElf::CProcessElf()
	: m_pElf(NULL)
	, m_iElfSize(0)
	, m_pElfBin(NULL)
	, m_iBinSize(0)
	, m_blElfLoaded(false)
	, m_pElfSections(NULL)
	, m_iSHCount(0)
	, m_pElfPrograms(NULL)
	, m_iPHCount(0)
	, m_pElfStrtab(NULL)
	, m_iBaseAddr(0)
{
	memset(&m_elfHeader, 0, sizeof(m_elfHeader));
}

CProcessElf::~CProcessElf()
{
	FreeMemory();
}

void CProcessElf::FreeMemory()
{
	if(m_pElfSections != NULL)
	{
		delete m_pElfSections;
		m_pElfSections = NULL;
	}

	if(m_pElfPrograms != NULL)
	{
		delete m_pElfPrograms;
		m_pElfPrograms = NULL;
	}

	/* Just an aliased pointer */
	m_pElfStrtab = NULL;

	if(m_pElf != NULL)
	{
		delete m_pElf;
		m_pElf = NULL;
	}
	m_iElfSize = 0;

	if(m_pElfBin != NULL)
	{
		delete m_pElfBin;
		m_pElfBin = NULL;
	}
	m_iBinSize = 0;

	m_blElfLoaded = false;
}

u8* CProcessElf::LoadFileToMem(const char *szFilename, u32 &lSize)
{
	FILE *fp;
	u8 *pData;

	pData = NULL;

	fp = fopen(szFilename, "rb");
	if(fp != NULL)
	{
		(void) fseek(fp, 0, SEEK_END);
		lSize = ftell(fp);
		rewind(fp);

		if(lSize >= sizeof(Elf32_Ehdr))
		{
			SAFE_ALLOC(pData, u8[lSize]);
			if(pData != NULL)
			{
				if(fread(pData, 1, lSize, fp) != lSize)
				{
					COutput::Puts(LEVEL_ERROR, "Could not read in file data");
					delete pData;
					pData = NULL;
				}
			}
			else
			{
				COutput::Puts(LEVEL_ERROR, "Could not allocate memory");
			}
		}
		else
		{
			COutput::Puts(LEVEL_ERROR, "File not large enough to contain an ELF");
		}

		fclose(fp);
		fp = NULL;
	}
	else
	{
		COutput::Printf(LEVEL_ERROR, "Could not open file %s\n", szFilename);
	}

	return pData;
}

void CProcessElf::ElfDumpHeader()
{
	COutput::Puts(LEVEL_DEBUG, "ELF Header:");
	COutput::Printf(LEVEL_DEBUG, "Magic %08X\n", m_elfHeader.iMagic);
	COutput::Printf(LEVEL_DEBUG, "Class %d\n", m_elfHeader.iClass);
	COutput::Printf(LEVEL_DEBUG, "Data %d\n", m_elfHeader.iData);
	COutput::Printf(LEVEL_DEBUG, "Idver %d\n", m_elfHeader.iIdver);
	COutput::Printf(LEVEL_DEBUG, "Type %04X\n", m_elfHeader.iType);
	COutput::Printf(LEVEL_DEBUG, "Start %08X\n", m_elfHeader.iEntry);
	COutput::Printf(LEVEL_DEBUG, "PH Offs %08X\n", m_elfHeader.iPhoff);
	COutput::Printf(LEVEL_DEBUG, "SH Offs %08X\n", m_elfHeader.iShoff);
	COutput::Printf(LEVEL_DEBUG, "Flags %08X\n", m_elfHeader.iFlags);
	COutput::Printf(LEVEL_DEBUG, "EH Size %d\n", m_elfHeader.iEhsize);
	COutput::Printf(LEVEL_DEBUG, "PHEntSize %d\n", m_elfHeader.iPhentsize);
	COutput::Printf(LEVEL_DEBUG, "PHNum %d\n", m_elfHeader.iPhnum);
	COutput::Printf(LEVEL_DEBUG, "SHEntSize %d\n", m_elfHeader.iShentsize);
	COutput::Printf(LEVEL_DEBUG, "SHNum %d\n", m_elfHeader.iShnum);
	COutput::Printf(LEVEL_DEBUG, "SHStrndx %d\n\n", m_elfHeader.iShstrndx);
}

void CProcessElf::ElfLoadHeader(const Elf32_Ehdr* pHeader)
{
	m_elfHeader.iMagic 		= LW(pHeader->e_magic);
	m_elfHeader.iClass 		= pHeader->e_class;
	m_elfHeader.iData 		= pHeader->e_data;
	m_elfHeader.iIdver 		= pHeader->e_idver;
	m_elfHeader.iType 		= LH(pHeader->e_type);
	m_elfHeader.iMachine 	= LH(pHeader->e_machine);
	m_elfHeader.iVersion 	= LW(pHeader->e_version);
	m_elfHeader.iEntry 		= LW(pHeader->e_entry);
	m_elfHeader.iPhoff 		= LW(pHeader->e_phoff);
	m_elfHeader.iShoff 		= LW(pHeader->e_shoff);
	m_elfHeader.iFlags 		= LW(pHeader->e_flags);
	m_elfHeader.iEhsize		= LH(pHeader->e_ehsize);
	m_elfHeader.iPhentsize 	= LH(pHeader->e_phentsize);
	m_elfHeader.iPhnum 		= LH(pHeader->e_phnum);
	m_elfHeader.iShentsize 	= LH(pHeader->e_shentsize);
	m_elfHeader.iShnum 		= LH(pHeader->e_shnum);
	m_elfHeader.iShstrndx 	= LH(pHeader->e_shstrndx);
}

bool CProcessElf::ElfValidateHeader()
{
	Elf32_Ehdr* pHeader;
	bool blRet = false;

	assert(m_pElf != NULL);
	assert(m_iElfSize > 0);

	pHeader = (Elf32_Ehdr*) m_pElf;

	ElfLoadHeader(pHeader);

	if(m_elfHeader.iMagic == ELF_MAGIC)
	{
		u32 iPhend = 0;
		u32 iShend = 0;

		/* Check that if we have program and section headers they are valid */
		if(m_elfHeader.iPhnum > 0)
		{
			iPhend = m_elfHeader.iPhoff + (m_elfHeader.iPhentsize * m_elfHeader.iPhnum);
		}

		if(m_elfHeader.iShnum > 0)
		{
			iShend = m_elfHeader.iShoff + (m_elfHeader.iShentsize * m_elfHeader.iShnum);
		}

		COutput::Printf(LEVEL_DEBUG, "%08X, %08X, %08X\n", iPhend, iShend, m_iElfSize);

		if((iPhend <= m_iElfSize) && (iShend <= m_iElfSize))
		{
			blRet = true;
		}
		else
		{
			COutput::Puts(LEVEL_ERROR, "Program or sections header information invalid");
		}
	}
	else
	{
		COutput::Puts(LEVEL_ERROR, "Magic value incorrect (not an ELF?)");
	}

	if(COutput::GetDebug())
	{
		ElfDumpHeader();
	}

	return blRet;
}

ElfSection* CProcessElf::ElfFindSection(const char *szName)
{
	ElfSection* pSection = NULL;

	if((m_pElfSections != NULL) && (m_iSHCount > 0) && (m_pElfStrtab != NULL))
	{
		int iLoop;

		if(szName == NULL)
		{
			/* Return the default entry, kinda pointless :P */
			pSection = &m_pElfSections[0];
		}
		else
		{
			for(iLoop = 0; iLoop < m_iSHCount; iLoop++)
			{
				if(strcmp(m_pElfSections[iLoop].szName, szName) == 0)
				{
					pSection = &m_pElfSections[iLoop];
				}
			}
		}
	}

	return pSection;
}

const char *CProcessElf::GetSymbolName(u32 name, u32 shndx)
{
	if((shndx > 0) && (shndx < (u32) m_iSHCount))
	{
		if((m_pElfSections[shndx].iType == SHT_STRTAB) && (name < m_pElfSections[shndx].iSize))
		{
			return (char *) (m_pElfSections[shndx].pData + name);
		}
	}

	return "";
}

bool CProcessElf::LoadPrograms()
{
	bool blRet = true;

	if((m_elfHeader.iPhoff > 0) && (m_elfHeader.iPhnum > 0) && (m_elfHeader.iPhentsize > 0))
	{
		Elf32_Phdr *pHeader;
		u8 *pData;
		u32 iLoop;

		pData = m_pElf + m_elfHeader.iPhoff;

		SAFE_ALLOC(m_pElfPrograms, ElfProgram[m_elfHeader.iPhnum]);

		if(m_pElfPrograms != NULL)
		{
			m_iPHCount = m_elfHeader.iPhnum;
			COutput::Puts(LEVEL_DEBUG, "Program Headers:");

			for(iLoop = 0; iLoop < (u32) m_iPHCount; iLoop++)
			{
				pHeader = (Elf32_Phdr *) pData;
				m_pElfPrograms[iLoop].iType = LW(pHeader->p_type);
				m_pElfPrograms[iLoop].iOffset = LW(pHeader->p_offset);
				m_pElfPrograms[iLoop].iVaddr = LW(pHeader->p_vaddr);
				m_pElfPrograms[iLoop].iPaddr = LW(pHeader->p_paddr);
				m_pElfPrograms[iLoop].iFilesz = LW(pHeader->p_filesz);
				m_pElfPrograms[iLoop].iMemsz = LW(pHeader->p_memsz);
				m_pElfPrograms[iLoop].iFlags = LW(pHeader->p_flags);
				m_pElfPrograms[iLoop].iAlign = LW(pHeader->p_align);
				// Setup pData ? 

				pData += m_elfHeader.iPhentsize;
			}

			if(COutput::GetDebug())
			{
				for(iLoop = 0; iLoop < (u32) m_iPHCount; iLoop++)
				{
					COutput::Printf(LEVEL_DEBUG, "Program Header %d:\n", iLoop);
					COutput::Printf(LEVEL_DEBUG, "Type: %08X\n", m_pElfPrograms[iLoop].iType);
					COutput::Printf(LEVEL_DEBUG, "Offset: %08X\n", m_pElfPrograms[iLoop].iOffset);
					COutput::Printf(LEVEL_DEBUG, "VAddr: %08X\n", m_pElfPrograms[iLoop].iVaddr);
					COutput::Printf(LEVEL_DEBUG, "PAddr: %08X\n", m_pElfPrograms[iLoop].iPaddr);
					COutput::Printf(LEVEL_DEBUG, "FileSz: %d\n", m_pElfPrograms[iLoop].iFilesz);
					COutput::Printf(LEVEL_DEBUG, "MemSz: %d\n", m_pElfPrograms[iLoop].iMemsz);
					COutput::Printf(LEVEL_DEBUG, "Flags: %08X\n", m_pElfPrograms[iLoop].iFlags);
					COutput::Printf(LEVEL_DEBUG, "Align: %08X\n\n", m_pElfPrograms[iLoop].iAlign);
				}
			}
		}
		else
		{
			blRet = false;
		}
	}

	return blRet;
}

bool CProcessElf::LoadSymbols()
{
	ElfSection *pSymtab;
	bool blRet = true;

	COutput::Printf(LEVEL_DEBUG, "Size %d\n", sizeof(Elf32_Sym));

	pSymtab = ElfFindSection(".symtab");
	if((pSymtab != NULL) && (pSymtab->iType == SHT_SYMTAB) && (pSymtab->pData != NULL))
	{
		Elf32_Sym *pSym;
		int iLoop, iSymcount;
		u32 symidx;
		u32 name;

		symidx = pSymtab->iLink;
		iSymcount = pSymtab->iSize / sizeof(Elf32_Sym);
		pSym = (Elf32_Sym*) pSymtab->pData;
		for(iLoop = 0; iLoop < iSymcount; iLoop++)
		{
			name = LW(pSym->st_name);

			COutput::Printf(LEVEL_DEBUG, "Symbol %d\n", iLoop);
			COutput::Printf(LEVEL_DEBUG, "Name %d, '%s'\n", name, GetSymbolName(name, symidx));
			COutput::Printf(LEVEL_DEBUG, "Value %08X\n", LW(pSym->st_value));
			COutput::Printf(LEVEL_DEBUG, "Size  %08X\n", LW(pSym->st_size));
			COutput::Printf(LEVEL_DEBUG, "Info  %02X\n", pSym->st_info);
			COutput::Printf(LEVEL_DEBUG, "Other %02X\n", pSym->st_other);
			COutput::Printf(LEVEL_DEBUG, "Shndx %04X\n\n", LH(pSym->st_shndx));
			pSym++;
		}
	}

	return blRet;
}

bool CProcessElf::FillSection(ElfSection& elfSect, const Elf32_Shdr *pSection)
{
	assert(pSection != NULL);

	elfSect.iName = LW(pSection->sh_name);
	elfSect.iType = LW(pSection->sh_type);
	elfSect.iFlags = LW(pSection->sh_flags);
	elfSect.iAddr = LW(pSection->sh_addr);
	elfSect.iOffset = LW(pSection->sh_offset);
	elfSect.iSize = LW(pSection->sh_size);
	elfSect.iLink = LW(pSection->sh_link);
	elfSect.iInfo = LW(pSection->sh_info);
	elfSect.iAddralign = LW(pSection->sh_addralign);
	elfSect.iEntsize = LW(pSection->sh_entsize);
	elfSect.pData = m_pElf + elfSect.iOffset;
	elfSect.pRelocs = NULL;
	elfSect.iRelocCount = 0;

	if(((elfSect.pData + elfSect.iSize) > (m_pElf + m_iElfSize)) && (elfSect.iType != SHT_NOBITS))
	{
		COutput::Puts(LEVEL_ERROR, "Section too big for file");
		elfSect.pData = NULL;
		return false;
	}

	return true;
}

void CProcessElf::ElfDumpSections()
{
	int iLoop;
	assert(m_pElfSections != NULL);

	for(iLoop = 0; iLoop < m_iSHCount; iLoop++)
	{
		ElfSection* pSection;

		pSection = &m_pElfSections[iLoop];
		COutput::Printf(LEVEL_DEBUG, "Section %d\n", iLoop);
		COutput::Printf(LEVEL_DEBUG, "Name: %d %s\n", pSection->iName, pSection->szName);
		COutput::Printf(LEVEL_DEBUG, "Type: %08X\n", pSection->iType);
		COutput::Printf(LEVEL_DEBUG, "Flags: %08X\n", pSection->iFlags);
		COutput::Printf(LEVEL_DEBUG, "Addr: %08X\n", pSection->iAddr);
		COutput::Printf(LEVEL_DEBUG, "Offset: %08X\n", pSection->iOffset);
		COutput::Printf(LEVEL_DEBUG, "Size: %08X\n", pSection->iSize);
		COutput::Printf(LEVEL_DEBUG, "Link: %08X\n", pSection->iLink);
		COutput::Printf(LEVEL_DEBUG, "Info: %08X\n", pSection->iInfo);
		COutput::Printf(LEVEL_DEBUG, "Addralign: %08X\n", pSection->iAddralign);
		COutput::Printf(LEVEL_DEBUG, "Entsize: %08X\n", pSection->iEntsize);
		COutput::Printf(LEVEL_DEBUG, "Data %p\n\n", pSection->pData);
	}
}

/* Build a binary image of the elf file in memory */
/* Really should build the binary image from program headers if no section headers */
bool CProcessElf::BuildBinaryImage()
{
	bool blRet = false; 
	int iLoop;
	u32 iMinAddr = 0xFFFFFFFF;
	u32 iMaxAddr = 0;
	long iMaxSize = 0;

	assert(m_pElf != NULL);
	assert(m_iElfSize > 0);
	assert(m_pElfBin == NULL);
	assert(m_iBinSize == 0);
	assert(m_pElfSections != NULL);
	assert(m_iSHCount != 0);

	/* Find the maximum and minimum addresses */
	for(iLoop = 0; iLoop < m_iSHCount; iLoop++)
	{
		ElfSection* pSection;

		pSection = &m_pElfSections[iLoop];

		if(pSection->iFlags & SHF_ALLOC)
		{
			if((pSection->iAddr + pSection->iSize) > (iMaxAddr + iMaxSize))
			{
				iMaxAddr = pSection->iAddr;
				iMaxSize = pSection->iSize;
			}

			if(pSection->iAddr < iMinAddr)
			{
				iMinAddr = pSection->iAddr;
			}
		}
	}

	COutput::Printf(LEVEL_DEBUG, "Min Address %08X, Max Address %08X, Max Sizs %d\n", 
								  iMinAddr, iMaxAddr, iMaxSize);

	if(iMinAddr != 0xFFFFFFFF)
	{
		m_iBinSize = iMaxAddr - iMinAddr + iMaxSize;
		SAFE_ALLOC(m_pElfBin, u8[m_iBinSize]);
		if(m_pElfBin != NULL)
		{
			memset(m_pElfBin, 0, m_iBinSize);
			for(iLoop = 0; iLoop < m_iSHCount; iLoop++)
			{
				ElfSection* pSection = &m_pElfSections[iLoop];

				if((pSection->iFlags & SHF_ALLOC) && (pSection->iType != SHT_NOBITS) && (pSection->pData != NULL))
				{
					memcpy(m_pElfBin + (pSection->iAddr - iMinAddr), pSection->pData, pSection->iSize);
				}
			}

			m_iBaseAddr = iMinAddr;
			blRet = true;
		}
	}

	return blRet;
}

bool CProcessElf::LoadSections()
{
	bool blRet = true;

	assert(m_pElf != NULL);

	if((m_elfHeader.iShoff != 0) && (m_elfHeader.iShnum > 0) && (m_elfHeader.iShentsize > 0))
	{
		SAFE_ALLOC(m_pElfSections, ElfSection[m_elfHeader.iShnum]);
		if(m_pElfSections != NULL)
		{
			int iLoop;
			u8 *pData;
			Elf32_Shdr *pSection;

			m_iSHCount = m_elfHeader.iShnum;
			memset(m_pElfSections, 0, sizeof(ElfSection) * m_iSHCount);
			pData = m_pElf + m_elfHeader.iShoff;

			for(iLoop = 0; iLoop < m_iSHCount; iLoop++)
			{
				pSection = (Elf32_Shdr*) pData;
				if(FillSection(m_pElfSections[iLoop], pSection) == false)
				{
					blRet = false;
					break;
				}

				pData += m_elfHeader.iShentsize;
			}

			if((m_elfHeader.iShstrndx > 0) && (m_elfHeader.iShstrndx < (u32) m_iSHCount))
			{
				if(m_pElfSections[m_elfHeader.iShstrndx].iType == SHT_STRTAB)
				{
					m_pElfStrtab = &m_pElfSections[m_elfHeader.iShstrndx];
				}
			}

			if(blRet)
			{
				/* If we found a string table let's run through the sections fixing up names */
				if(m_pElfStrtab != NULL)
				{
					for(iLoop = 0; iLoop < m_iSHCount; iLoop++)
					{
						strncpy(m_pElfSections[iLoop].szName, 
								(char *) (m_pElfStrtab->pData + m_pElfSections[iLoop].iName), ELF_SECT_MAX_NAME - 1);
						m_pElfSections[iLoop].szName[ELF_SECT_MAX_NAME-1] = 0;
					}
				}

				if(COutput::GetDebug())
				{
					ElfDumpSections();
				}
			}
		}
		else
		{
			COutput::Puts(LEVEL_ERROR, "Could not allocate memory for sections");
			blRet = false;
		}
	}
	else
	{
		COutput::Puts(LEVEL_DEBUG, "No section headers in ELF file");
	}

	return blRet;
}

u32 CProcessElf::ElfGetBaseAddr()
{
	if(m_blElfLoaded)
	{
		return m_iBaseAddr;
	}

	return 0;
}

u32 CProcessElf::ElfGetTopAddr()
{
	if(m_blElfLoaded)
	{
		return m_iBaseAddr + m_iBinSize;
	}

	return 0;
}

u32 CProcessElf::ElfGetLoadSize()
{
	if(m_blElfLoaded)
	{
		return m_iBinSize;
	}

	return 0;
}

bool CProcessElf::LoadFromFile(const char *szFilename)
{
	bool blRet = false;

	/* Return the object to a know state */
	FreeMemory();

	m_pElf = LoadFileToMem(szFilename, m_iElfSize);
	if((m_pElf != NULL) && (ElfValidateHeader() == true))
	{
		if((LoadPrograms() == true) && (LoadSections() == true) && (LoadSymbols() == true) && (BuildBinaryImage() == true))
		{
			strncpy(m_szFilename, szFilename, MAXPATH-1);
			m_szFilename[MAXPATH-1] = 0;
			blRet = true;
			m_blElfLoaded = true;
		}
	}

	if(blRet == false)
	{
		FreeMemory();
	}

	return blRet;
}

ElfSection* CProcessElf::ElfGetSections(u32 &iSHCount)
{
	if(m_blElfLoaded)
	{
		iSHCount = m_iSHCount;
		return m_pElfSections;
	}

	return NULL;
}

const char *CProcessElf::GetElfName()
{
	return m_szFilename;
}
