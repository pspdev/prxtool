/* 
   prxtool - Simple utility to build an idc file for use in IDA.
   (c) 2005 TyRaNiD - JF
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Should be different for different architectures */
/* Should return the data specified in native */
#define LW(x) (x)
#define LH(x) (x)

//#define DEBUG

/* Structure to hold the module export information */
typedef struct _PspModuleExport
{
	unsigned int name;
	unsigned int flags;
	unsigned int counts;
	unsigned int exports;
} PspModuleExport;

/* Structure to hold the module import information */
typedef struct _PspModuleImport
{
	unsigned int name;
	unsigned int flags;
	unsigned int counts;
	unsigned int nids;
	unsigned int funcs;
} PspModuleImport;

/* Structure to hold the module info */
typedef struct _PspModuleInfo
{
	unsigned int flags;
	char name[28];
	unsigned int gp;
	unsigned int exports;
	unsigned int exp_end;
	unsigned int imports;
	unsigned int imp_end;
} PspModuleInfo;

/* Define ELF types */
typedef unsigned int   Elf32_Addr; 
typedef unsigned short Elf32_Half;
typedef unsigned int   Elf32_Off;
typedef signed 	 int   Elf32_Sword;
typedef unsigned int   Elf32_Word;

#define SHT_NULL 0 
#define SHT_PROGBITS 1 
#define SHT_SYMTAB 2 
#define SHT_STRTAB 3 
#define SHT_RELA 4 
#define SHT_HASH 5 
#define SHT_DYNAMIC 6 
#define SHT_NOTE 7 
#define SHT_NOBITS 8 
#define SHT_REL 9 
#define SHT_SHLIB 10 
#define SHT_DYNSYM 11 
#define SHT_LOPROC 0x70000000 
#define SHT_HIPROC 0x7fffffff 
#define SHT_LOUSER 0x80000000 
#define SHT_HIUSER 0xffffffff

#define SHF_WRITE 		1
#define SHF_ALLOC 		2
#define SHF_EXECINSTR 	4

/* ELF file header */
typedef struct { 
	Elf32_Word e_magic;
	unsigned char e_class;
	unsigned char e_data;
	unsigned char e_idver;
	unsigned char e_pad[9];
	Elf32_Half e_type; 
	Elf32_Half e_machine; 
	Elf32_Word e_version; 
	Elf32_Addr e_entry; 
	Elf32_Off e_phoff; 
	Elf32_Off e_shoff; 
	Elf32_Word e_flags; 
	Elf32_Half e_ehsize; 
	Elf32_Half e_phentsize; 
	Elf32_Half e_phnum; 
	Elf32_Half e_shentsize; 
	Elf32_Half e_shnum; 
	Elf32_Half e_shstrndx; 
} __attribute__((packed)) Elf32_Ehdr;

/* ELF section header */
typedef struct { 
	Elf32_Word sh_name; 
	Elf32_Word sh_type; 
	Elf32_Word sh_flags; 
	Elf32_Addr sh_addr; 
	Elf32_Off sh_offset; 
	Elf32_Word sh_size; 
	Elf32_Word sh_link; 
	Elf32_Word sh_info; 
	Elf32_Word sh_addralign; 
	Elf32_Word sh_entsize; 
} __attribute__((packed)) Elf32_Shdr;

/* Dump elf header to the screen for debugging */
void ElfDumpHeader(const Elf32_Ehdr* pHeader)
{
#ifdef DEBUG
	fprintf(stderr, "// ELF Header:\n");
	fprintf(stderr, "// Magic %08X\n", LW(pHeader->e_magic));
	fprintf(stderr, "// Class %d\n", pHeader->e_class);
	fprintf(stderr, "// Data %d\n", pHeader->e_data);
	fprintf(stderr, "// Idver %d\n", pHeader->e_idver);
	fprintf(stderr, "// Type %04X\n", LH(pHeader->e_type));
	fprintf(stderr, "// Start %08X\n", LW(pHeader->e_entry));
	fprintf(stderr, "// PH Offs %08X\n", LW(pHeader->e_phoff));
	fprintf(stderr, "// SH Offs %08X\n", LW(pHeader->e_shoff));
	fprintf(stderr, "// Flags %08X\n", LW(pHeader->e_flags));
	fprintf(stderr, "// EH Size %d\n", LH(pHeader->e_ehsize));
	fprintf(stderr, "// PHEntSize %d\n", LH(pHeader->e_phentsize));
	fprintf(stderr, "// PHNum %d\n", LH(pHeader->e_phnum));
	fprintf(stderr, "// SHEntSize %d\n", LH(pHeader->e_shentsize));
	fprintf(stderr, "// SHNum %d\n", LH(pHeader->e_shnum));
	fprintf(stderr, "// SHStrndx %d\n", LH(pHeader->e_shstrndx));
#endif
}

/* Validate the ELF file header */
int ElfValidateHeader(const Elf32_Ehdr* pHeader)
{
	Elf32_Off  ofsSh;
	Elf32_Word wShnum;
	Elf32_Word wShentsize;
	Elf32_Word wMagic;
	int iRet = 0;

	wMagic = LW(pHeader->e_magic);
	ofsSh = LW(pHeader->e_shoff);
	wShnum = LH(pHeader->e_shnum);
	wShentsize = LH(pHeader->e_shentsize);

	if(wMagic == 0x464C457F)
	{
		if((ofsSh != 0) && (wShnum > 0) && (wShentsize > 0))
		{
			iRet = 1;
		}
		else
		{
			fprintf(stderr, "Error: Invalid section header information\n");
		}
	}
	else
	{
		fprintf(stderr, "Error: Magic value incorrect (not an ELF?)\n");
	}

	ElfDumpHeader(pHeader);

	return iRet;
}

/* Dump the section headers in IDA format */
void ElfDumpSectHeader(FILE *fp, int idx, const Elf32_Shdr* pHeader, const unsigned char *pStrtab)
{
	unsigned int shFlags;
	unsigned int shType;
	unsigned int shAddr;
	unsigned int shSize;

	shFlags = LW(pHeader->sh_flags);
	shType = LW(pHeader->sh_type);
	shAddr = LW(pHeader->sh_addr);
	shSize = LW(pHeader->sh_size);

	/* Check if the section is loadable */
	if((shFlags & SHF_ALLOC) && ((shType == SHT_PROGBITS) || (shType == SHT_NOBITS)))
	{
		fprintf(fp, "  SegCreate(0x%08X, 0x%08X, 0, 1, 1, 2);\n", 
				shAddr, shAddr + shSize);
		fprintf(fp, "  SegRename(0x%08X, \"%s\");\n", shAddr, &pStrtab[LW(pHeader->sh_name)]);
		fprintf(fp, "  SegClass(0x%08X, \"CODE\");\n", shAddr);
		if(shFlags & SHF_EXECINSTR)
		{
			fprintf(fp, "  SetSegmentType(0x%08X, SEG_CODE);\n", shAddr);
		}
		else
		{
			if(shType == SHT_NOBITS)
			{
				fprintf(fp, "  SetSegmentType(0x%08X, SEG_BSS);\n", shAddr);
			}
			else
			{
				fprintf(fp, "  SetSegmentType(0x%08X, SEG_DATA);\n", shAddr);
			}
		}
	}

#ifdef DEBUG

	fprintf(stderr, "\n// Section %d\n", idx);
	fprintf(stderr, "// Name %s\n", &pStrtab[LW(pHeader->sh_name)]);
	fprintf(stderr, "// Type %08X\n", LW(pHeader->sh_type));
	fprintf(stderr, "// Flags %08X\n", LW(pHeader->sh_flags));
	fprintf(stderr, "// Addr %08X\n", LW(pHeader->sh_addr));
	fprintf(stderr, "// Offset %08X\n", LW(pHeader->sh_offset));
	fprintf(stderr, "// Size %08X\n", LW(pHeader->sh_size));
	fprintf(stderr, "// Link %08X\n", LW(pHeader->sh_link));
	fprintf(stderr, "// Info %08X\n", LW(pHeader->sh_info));
	fprintf(stderr, "// AddrAlign %08X\n", LW(pHeader->sh_addralign));
	fprintf(stderr, "// EntSize %08X\n", LW(pHeader->sh_entsize)); 
#endif
}

/* Print usage */
void print_usage(void)
{
	printf("Usage: prxtool program.prx\n");
}

/* Load a file and allocate memory for it */
unsigned char *LoadFile(const char *szFilename, unsigned long *lSize)
{
	FILE *fp;
	unsigned char *pData;

	pData = NULL;

	fp = fopen(szFilename, "rb");
	if(fp != NULL)
	{
		(void) fseek(fp, 0, SEEK_END);
		*lSize = ftell(fp);
		rewind(fp);

		if(*lSize >= sizeof(Elf32_Ehdr))
		{
			pData = (unsigned char *) malloc(*lSize);
			if(pData != NULL)
			{
				if(fread(pData, 1, *lSize, fp) != *lSize)
				{
					fprintf(stderr, "Error: Could not read in file data\n");
					free(pData);
					pData = NULL;
				}
			}
			else
			{
				fprintf(stderr, "Error: Could not allocate memory\n");
			}
		}
		else
		{
			fprintf(stderr, "Error: File not large enough to contain an ELF\n");
		}

		fclose(fp);
		fp = NULL;
	}
	else
	{
		fprintf(stderr, "Error: Could not open file %s\n", szFilename);
	}

	return pData;
}

/* Scan the segments and find the string table */
const unsigned char *FindStringTable(const unsigned char *pElf, int iShoff, int iShnum, int iShentsize)
{
	const Elf32_Shdr *pHeader;
	const char* pPos;
	const char* pRet = NULL;

	pPos = pElf + iShoff;

	while(iShnum > 0)
	{
		pHeader = (const Elf32_Shdr*) pPos;
		if(pHeader->sh_type == SHT_STRTAB)
		{
			pRet = pElf + pHeader->sh_offset;
			break;
		}
		pPos += iShentsize;
		iShnum--;
	}

	return pRet;
}

/* Dump the sections to a IDC */
void DumpSections(FILE *fp, const unsigned char *pElf, 
				  unsigned long iSize, const unsigned char *pStrtab)
{
	Elf32_Ehdr* pHeader;
	Elf32_Off  ofsSh;
	Elf32_Word wShnum;
	Elf32_Word wShentsize;
	const unsigned char *pPos = pElf;
	int iLoop;

	pHeader = (Elf32_Ehdr *) pElf;
	ofsSh = LW(pHeader->e_shoff);
	wShnum = LH(pHeader->e_shnum);
	wShentsize = LH(pHeader->e_shentsize);

	fprintf(fp, "static createSegments() {\n\n");
	pPos += ofsSh;
	for(iLoop = 0; iLoop < wShnum; iLoop++)
	{
		ElfDumpSectHeader(fp, iLoop, (const Elf32_Shdr*) pPos, pStrtab);
		pPos += wShentsize;
	}

	fprintf(fp, "}\n\n");
}

/* Validate section headers */
int ElfValidateSections(const char *pElf, unsigned long iSize, const unsigned char **ppStrtab)
{
	Elf32_Ehdr* pHeader;
	Elf32_Off  ofsSh;
	Elf32_Word wShnum;
	Elf32_Word wShentsize;
	int iRet = 0;

	pHeader = (Elf32_Ehdr *) pElf;
	ofsSh = LW(pHeader->e_shoff);
	wShnum = LH(pHeader->e_shnum);
	wShentsize = LH(pHeader->e_shentsize);
	*ppStrtab = NULL;

	if((ofsSh + (wShnum * wShentsize)) < iSize)
	{
		*ppStrtab = FindStringTable(pElf, ofsSh, wShnum, wShentsize);
		if(*ppStrtab != NULL)
		{
			iRet = 1;
		}
		else
		{
			fprintf(stderr, "Error: Could not find the string table section\n");
		}
	}
	else
	{
		fprintf(stderr, "Error: ELF file was not big enough for specified sections\n");
	}
	
	return iRet;
}

/* Build a name from a base and extention */
const char *BuildName(const char* base, const char *ext)
{
	static char str_export[512];

	snprintf(str_export, sizeof(str_export), "%s_%s", base, ext);

	return str_export;
}

/* Make a name for the idc */
void MakeName(FILE *fp, const char *str, unsigned int addr)
{
	fprintf(fp, "  MakeName(0x%08X, \"%s\");\n", addr, str);
}

/* Max a string for the idc */
void MakeString(FILE *fp, const char *str, unsigned int addr)
{
	MakeName(fp, str, addr);
	fprintf(fp, "  MakeStr(0x%08X, BADADDR);\n", addr);
}

/* Make a dword for the idc */
void MakeDword(FILE *fp, const char*str, unsigned int addr)
{
	MakeName(fp, str, addr);
	fprintf(fp, "  MakeDword(0x%08X);\n", addr);
}

/* Make an offset for the idc */
void MakeOffset(FILE *fp, const char *str, unsigned int addr)
{
	MakeDword(fp, str, addr);
	fprintf(fp, "  OpOff(0x%08X, 0, 0);\n", addr);
}

/* Make a function for the idc */
void MakeFunction(FILE *fp, const char *str, unsigned int addr)
{
	MakeName(fp, str, addr);
	fprintf(fp, "  MakeFunction(0x%08X, BADADDR);\n", addr);
}

/* Find the name based on our list of names, not currently implemented */
const char *FindLibName(const char *lib, unsigned int nid)
{
	static char lib_name[512];

	if(lib == NULL)
	{
		snprintf(lib_name, sizeof(lib_name), "sys_%08X", nid);
	}
	else
	{
		snprintf(lib_name, sizeof(lib_name), "%s_%08X", lib, nid);
	}

	return lib_name;
}

/* Dump a single export stub */
void DumpSingleExport(FILE *fp, const char *name, unsigned int addr, const unsigned char *pElfBin, 
					  unsigned long iBinSize, unsigned int iBaseAddr)
{
	unsigned int bin_addr;
	const char *lib_name;
	PspModuleExport* export;

	bin_addr = addr - iBaseAddr;
	export = (PspModuleExport*) (pElfBin + bin_addr);
	
	if((LW(export->name) != 0) && (bin_addr <= iBinSize))
	{
		MakeOffset(fp, name, addr);
		MakeString(fp, BuildName(name, "name"), LW(export->name));
		lib_name = (const char *) (pElfBin + LW(export->name) - iBaseAddr);
	}
	else
	{
		MakeDword(fp, name, addr);
		lib_name = NULL;
	}

	MakeDword(fp, BuildName(name, "flags"), addr+4);
	MakeDword(fp, BuildName(name, "counts"), addr+8);

	bin_addr = LW(export->exports) - iBaseAddr;
	if(bin_addr < iBinSize)
	{
		/* Do the functions */
		int f_count;
		int v_count;
		unsigned int *ptr;
		int counts;
		int loop;

		counts = LW(export->counts);
		f_count = (counts >> 16) & 0xFF;
		v_count = (counts >> 8) & 0xFF;
		ptr = (unsigned int *) (pElfBin + bin_addr);

		MakeOffset(fp, BuildName(name, "exports"), addr+12);
		for(loop = 0; loop < f_count; loop++)
		{
			const char *f_name;

			f_name = FindLibName(lib_name, *ptr);

			/* Make the nid */
			MakeDword(fp, BuildName(name, f_name), bin_addr + iBaseAddr);

			if((ptr[v_count + f_count] - iBaseAddr) < iBinSize)
			{
				/* Make the function itself */
				MakeOffset(fp, "", bin_addr + iBaseAddr + ((v_count + f_count) * 4));
				MakeFunction(fp, f_name, ptr[v_count + f_count]);
			}
			else
			{
				MakeDword(fp, f_name, bin_addr + iBaseAddr + ((v_count + f_count) * 4));
			}

			ptr++;
			bin_addr+=4;
		}

		for(loop = 0; loop < v_count; loop++)
		{
			const char *v_name;

			v_name = FindLibName(lib_name, *ptr);

			MakeDword(fp, BuildName(name, v_name), bin_addr + iBaseAddr);

			if((ptr[v_count + f_count] - iBaseAddr) < iBinSize)
			{
				/* Make the variable name */
				MakeOffset(fp, "", bin_addr + iBaseAddr + ((v_count + f_count) * 4));
			}
			else
			{
				MakeDword(fp, v_name, bin_addr + iBaseAddr + ((v_count + f_count) * 4));
			}

			ptr++;
			bin_addr+=4;
		}
	}
	else
	{
		MakeDword(fp, BuildName(name, "exports"), addr+12);
	}
}

/* Dump the exports table */
void DumpExports(FILE *fp, const unsigned char *pElfBin, unsigned long iBinSize,
				 unsigned int iBaseAddr, PspModuleInfo* pModInfo)
{
	fprintf(fp, "static createExports() {\n");
	if(pModInfo != NULL)
	{
		unsigned int exp_base;
		unsigned int exp_end;
		int exp_loop;
		char str_export[128];

		exp_base = pModInfo->exports;
		exp_end  = pModInfo->exp_end;
		exp_loop = 0;
		while((exp_end - exp_base) >= sizeof(PspModuleExport))
		{
			snprintf(str_export, sizeof(str_export), "export_%d", exp_loop);
			DumpSingleExport(fp, str_export, exp_base, pElfBin, iBinSize, iBaseAddr);
			exp_loop++;
			exp_base += sizeof(PspModuleExport);
		}
	}
	fprintf(fp, "}\n\n");
}

/* Dump a single import stub */
void DumpSingleImport(FILE *fp, const char *name, unsigned int addr, const unsigned char *pElfBin, 
					  unsigned long iBinSize, unsigned int iBaseAddr)
{
	unsigned int name_addr;
	unsigned int nids_addr;
	unsigned int funcs_addr;
	const char *lib_name;
	PspModuleImport* import;

	name_addr = addr - iBaseAddr;
	import = (PspModuleImport*) (pElfBin + name_addr);
	
	if((LW(import->name) != 0) && (name_addr <= iBinSize))
	{
		MakeOffset(fp, name, addr);
		MakeString(fp, BuildName(name, "name"), LW(import->name));
		lib_name = (const char *) (pElfBin + LW(import->name) - iBaseAddr);
	}
	else
	{
		MakeDword(fp, name, addr);
		lib_name = NULL;
	}

	MakeDword(fp, BuildName(name, "flags"), addr+4);
	MakeDword(fp, BuildName(name, "counts"), addr+8);

	nids_addr = LW(import->nids) - iBaseAddr;
	funcs_addr = LW(import->funcs) - iBaseAddr;
	if((nids_addr < iBinSize) && (funcs_addr < iBinSize))
	{
		/* Do the functions */
		int f_count;
		int v_count;
		unsigned int *ptr_nids;
		int counts;
		int loop;

		counts = LW(import->counts);
		f_count = (counts >> 16) & 0xFF;
		v_count = (counts >> 8) & 0xFF;
		ptr_nids = (unsigned int *) (pElfBin + nids_addr);

		MakeOffset(fp, BuildName(name, "nids"), addr+12);
		MakeOffset(fp, BuildName(name, "funcs"), addr+16);

		for(loop = 0; loop < f_count; loop++)
		{
			const char *f_name;

			f_name = FindLibName(lib_name, *ptr_nids);

			/* Make the nid */
			MakeDword(fp, BuildName(name, f_name), nids_addr + iBaseAddr);

			MakeFunction(fp, f_name, funcs_addr + iBaseAddr);

			ptr_nids++;
			nids_addr+=4;
			funcs_addr+=8;
		}

		for(loop = 0; loop < v_count; loop++)
		{
			const char *v_name;

			v_name = FindLibName(lib_name, *ptr_nids);

			/* Make the nid */
			MakeDword(fp, BuildName(name, v_name), nids_addr + iBaseAddr);

			ptr_nids++;
			nids_addr+=4;
		}
	}
	else
	{
		MakeDword(fp, BuildName(name, "nids"), addr+12);
		MakeDword(fp, BuildName(name, "funcs"), addr+16);
	}

}

/* Dump the imports table */
void DumpImports(FILE *fp, const unsigned char *pElfBin, unsigned long iBinSize,
				 unsigned int iBaseAddr, PspModuleInfo* pModInfo)
{
	fprintf(fp, "static createImports() {\n");
	if(pModInfo != NULL)
	{
		unsigned int imp_base;
		unsigned int imp_end;
		int imp_loop;
		char str_import[128];

		imp_base = pModInfo->imports;
		imp_end =  pModInfo->imp_end;
		imp_loop = 0;
		while((imp_end - imp_base) >= sizeof(PspModuleImport))
		{
			snprintf(str_import, sizeof(str_import), "import_%d", imp_loop);
			DumpSingleImport(fp, str_import, imp_base, pElfBin, iBinSize, iBaseAddr);
			imp_loop++;
			imp_base += sizeof(PspModuleImport);
		}
	}
	fprintf(fp, "}\n\n");
}

/* Dump the start of the idc */
void DumpIDCStart(FILE *fp)
{
	fprintf(fp, "#include <idc.idc>\n\n");
	fprintf(fp, "static main() {\n");
	fprintf(fp, "   createSegments();\n");
	fprintf(fp, "   createModuleInfo();\n");
	fprintf(fp, "   createExports(); \n");
	fprintf(fp, "   createImports(); \n");
	fprintf(fp, "}\n\n");
}

/* Build a binary image of the elf */
unsigned char *ElfBuildBinary(const char *pElf, long iSize, 
							  long *iBinSize, unsigned int *iBaseAddr)
{
	Elf32_Ehdr* pHeader;
	Elf32_Word wShnum;
	Elf32_Word wShentsize;
	const unsigned char *pPos = pElf;
	int iLoop;
	unsigned int iMinAddr = 0xFFFFFFFF;
	unsigned int iMaxAddr = 0;
	long iMaxSize = 0;
	unsigned char* pRet = NULL;
	Elf32_Shdr* pSection;

	pHeader = (Elf32_Ehdr *) pElf;
	wShnum = LH(pHeader->e_shnum);
	wShentsize = LH(pHeader->e_shentsize);

	/* Find the maximum and minimum address */
	pPos += LW(pHeader->e_shoff);
	for(iLoop = 0; iLoop < wShnum; iLoop++)
	{
		pSection = (Elf32_Shdr*) pPos;
		if(LW(pSection->sh_flags) & SHF_ALLOC)
		{
			if((LW(pSection->sh_addr) + LW(pSection->sh_size)) > (iMaxAddr + iMaxSize))
			{
				iMaxAddr = LW(pSection->sh_addr);
				iMaxSize = LW(pSection->sh_size);
			}

			if(LW(pSection->sh_addr) < iMinAddr)
			{
				iMinAddr = LW(pSection->sh_addr);
			}
		}

		pPos += wShentsize;
	}

	if(iMinAddr != 0xFFFFFFFF)
	{
		pRet = malloc(iMaxAddr - iMinAddr + iMaxSize);
		if(pRet != NULL)
		{
			memset(pRet, 0, iMaxAddr - iMinAddr + iMaxSize);
			pPos = pElf + LW(pHeader->e_shoff);
			for(iLoop = 0; iLoop < wShnum; iLoop++)
			{
				pSection = (Elf32_Shdr*) pPos;
				if(LW(pSection->sh_flags) & SHF_ALLOC) 
				{
					if(LW(pSection->sh_type) != SHT_NOBITS)
					{
						memcpy(pRet + LW(pSection->sh_addr) - iMinAddr, 
							pElf + LW(pSection->sh_offset), LW(pSection->sh_size));
					}
				}

				pPos += wShentsize;
			}
			*iBaseAddr = iMinAddr;
			*iBinSize = iMaxAddr + iMaxSize;
		}
		else
		{
			fprintf(stderr, "Error: Couldn't allocate memory\n");
		}
	}
	else
	{
		fprintf(stderr, "Error: Couldn't find loadable sections\n");
	}

	return pRet;
}


/* Find the module info section */
PspModuleInfo* FindModuleInfo(FILE* fp, const unsigned char *pElf, long iElfSize, 
							  const unsigned char *pElfBin, long iBinSize, 
							  unsigned int iBaseAddr, const unsigned char *pStrtab)
{
	PspModuleInfo* pRet = NULL;
	Elf32_Ehdr* pHeader;
	Elf32_Off  ofsSh;
	Elf32_Word wShnum;
	Elf32_Word wShentsize;
	const unsigned char *pPos = pElf;
	Elf32_Shdr *pSection;
	int iLoop;

	pHeader = (Elf32_Ehdr *) pElf;
	ofsSh = LW(pHeader->e_shoff);
	wShnum = LH(pHeader->e_shnum);
	wShentsize = LH(pHeader->e_shentsize);

	fprintf(fp, "static createModuleInfo() {\n");
	pPos += ofsSh;
	for(iLoop = 0; iLoop < wShnum; iLoop++)
	{
		pSection = (Elf32_Shdr*) pPos;
		if(strcmp(&pStrtab[LW(pSection->sh_name)], ".rodata.sceModuleInfo") == 0)
		{
			unsigned int addr;

			addr = LW(pSection->sh_addr);
			pRet = (PspModuleInfo*) (pElfBin + (addr - iBaseAddr));

			/* Build the idc data */
			MakeDword(fp, "_module_flags", addr);
			MakeString(fp, "_module_name", addr+4);
			MakeDword(fp, "_module_gp", addr+32);
			MakeOffset(fp, "_module_exports", addr+36);
			MakeOffset(fp, "_module_exp_end", addr+40);
			MakeOffset(fp, "_module_imports", addr+44);
			MakeOffset(fp, "_module_imp_end", addr+48);

#ifdef DEBUG
			fprintf(stderr, "sh_addr %08X, base %08X\n", pSection->sh_addr, iBaseAddr);
			fprintf(stderr, "PSP Module Info: \n");
			fprintf(stderr, "Flags %08X, Name %s\n", pRet->flags, pRet->name);
			fprintf(stderr, "gp %08X, export %08X, exp_end %08X\n", pRet->gp, pRet->exports,
					pRet->exp_end);
			fprintf(stderr, "import %08X, imp_end %08X\n", pRet->imports, pRet->imp_end);
#endif
			break;
		}

		pPos += wShentsize;
	}
	fprintf(fp, "}\n\n");

	return pRet;
}

int main(int argc, char **argv)
{
	unsigned char *pElf;
	unsigned char *pElfBin;
	unsigned long iElfSize;
	const unsigned char *pStrtab;
	long iBinSize;
	unsigned int iBaseAddr;
	FILE *fpout = stdout;
	PspModuleInfo *pModInfo;

	if(argc < 2)
	{
		print_usage();
		return 1;
	}

	pElf = LoadFile(argv[1], &iElfSize);
	if(pElf != NULL)
	{
		if((ElfValidateHeader((Elf32_Ehdr*) pElf)) && 
				(ElfValidateSections(pElf, iElfSize, &pStrtab)))
		{
			pElfBin = ElfBuildBinary(pElf, iElfSize, &iBinSize, &iBaseAddr);
			if(pElfBin != NULL)
			{
				FILE *dump;

				dump = fopen("dump.bin", "wb");
				fwrite(pElfBin, 1, iBinSize, dump);
				fclose(dump);

				DumpIDCStart(fpout);
				DumpSections(fpout, pElf, iElfSize, pStrtab);
				pModInfo = FindModuleInfo(fpout, pElf, iElfSize, pElfBin, iBinSize, iBaseAddr, pStrtab);
				DumpExports(fpout, pElfBin, iBinSize, iBaseAddr, pModInfo);
				DumpImports(fpout, pElfBin, iBinSize, iBaseAddr, pModInfo);
				free(pElfBin);
			}
			else
			{
				fprintf(stderr, "Error: Failed to build binary image of elf\n");
			}
		}

		free(pElf);
		pElf = NULL;
	}
	else
	{
		return 1;
	}


	return 0;
}
