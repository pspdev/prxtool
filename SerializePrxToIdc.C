#include <stdio.h>
#include "SerializePrxToIdc.h"

/* Build a name from a base and extention */
static const char *BuildName(const char* base, const char *ext)
{
	static char str_export[512];

	snprintf(str_export, sizeof(str_export), "%s_%s", base, ext);

	return str_export;
}

/* Make a name for the idc */
static void MakeName(FILE *fp, const char *str, unsigned int addr)
{
	fprintf(fp, "  MakeName(0x%08X, \"%s\");\n", addr, str);
}

/* Max a string for the idc */
static void MakeString(FILE *fp, const char *str, unsigned int addr)
{
	MakeName(fp, str, addr);
	fprintf(fp, "  MakeStr(0x%08X, BADADDR);\n", addr);
}

/* Make a dword for the idc */
static void MakeDword(FILE *fp, const char*str, unsigned int addr)
{
	MakeName(fp, str, addr);
	fprintf(fp, "  MakeDword(0x%08X);\n", addr);
}

/* Make an offset for the idc */
static void MakeOffset(FILE *fp, const char *str, unsigned int addr)
{
	MakeDword(fp, str, addr);
	fprintf(fp, "  OpOff(0x%08X, 0, 0);\n", addr);
}

/* Make a function for the idc */
static void MakeFunction(FILE *fp, const char *str, unsigned int addr)
{
	MakeName(fp, str, addr);
	fprintf(fp, "  MakeFunction(0x%08X, BADADDR);\n", addr);
}

CSerializePrxToIdc::CSerializePrxToIdc(FILE *fpOut)
{
	m_fpOut = fpOut;
}

CSerializePrxToIdc::~CSerializePrxToIdc()
{
	fflush(m_fpOut);
}

bool CSerializePrxToIdc::StartFile()
{
	return true;
}

bool CSerializePrxToIdc::EndFile()
{
	/* Do nothing */
	return true;
}

bool CSerializePrxToIdc::StartPrx(const char* szFilename, const PspModule *mod, u32 iSMask)
{
	u32 addr;

	fprintf(m_fpOut, "#include <idc.idc>\n\n");
	fprintf(m_fpOut, "static main() {\n");
	if(iSMask & SERIALIZE_SECTIONS)
	{
		fprintf(m_fpOut, "   createSegments();\n");
	}
	fprintf(m_fpOut, "   createModuleInfo();\n");
	if(iSMask & SERIALIZE_EXPORTS)
	{
		fprintf(m_fpOut, "   createExports(); \n");
	}
	if(iSMask & SERIALIZE_IMPORTS)
	{
		fprintf(m_fpOut, "   createImports(); \n");
	}
	if(iSMask & SERIALIZE_RELOCS)
	{
		fprintf(m_fpOut, "   createRelocs();  \n");
	}
	fprintf(m_fpOut, "}\n\n");

	fprintf(m_fpOut, "static createModuleInfo() {\n");

	addr = mod->addr;

	MakeDword(m_fpOut, "_module_flags", addr);
	MakeString(m_fpOut, "_module_name", addr+4);
	MakeDword(m_fpOut, "_module_gp", addr+32);
	MakeOffset(m_fpOut, "_module_exports", addr+36);
	MakeOffset(m_fpOut, "_module_exp_end", addr+40);
	MakeOffset(m_fpOut, "_module_imports", addr+44);
	MakeOffset(m_fpOut, "_module_imp_end", addr+48);

	fprintf(m_fpOut, "}\n\n");

	return true;
}

bool CSerializePrxToIdc::EndPrx()
{
	/* Do nothing */
	return true;
}

bool CSerializePrxToIdc::StartSects()
{
	fprintf(m_fpOut, "static createSegments() {\n");
	return true;
}

bool CSerializePrxToIdc::SerializeSect(int num, ElfSection &sect)
{
	u32 shFlags;
	u32 shType;
	u32 shAddr;
	u32 shSize;
	const char *pName;

	shFlags = sect.iFlags;
	shType = sect.iType;
	shAddr = sect.iAddr;
	shSize = sect.iSize;
	pName = sect.szName;

	/* Check if the section is loadable */
	if((shFlags & SHF_ALLOC) && ((shType == SHT_PROGBITS) || (shType == SHT_NOBITS)))
	{
		fprintf(m_fpOut, "  SegCreate(0x%08X, 0x%08X, 0, 1, 1, 2);\n", 
				shAddr, shAddr + shSize);
		fprintf(m_fpOut, "  SegRename(0x%08X, \"%s\");\n", shAddr, pName);
		fprintf(m_fpOut, "  SegClass(0x%08X, \"CODE\");\n", shAddr);
		if(shFlags & SHF_EXECINSTR)
		{
			fprintf(m_fpOut, "  SetSegmentType(0x%08X, SEG_CODE);\n", shAddr);
		}
		else
		{
			if(shType == SHT_NOBITS)
			{
				fprintf(m_fpOut, "  SetSegmentType(0x%08X, SEG_BSS);\n", shAddr);
			}
			else
			{
				fprintf(m_fpOut, "  SetSegmentType(0x%08X, SEG_DATA);\n", shAddr);
			}
		}
	}

	return true;
}

bool CSerializePrxToIdc::EndSects()
{
	fprintf(m_fpOut, "}\n\n");
	return true;
}

bool CSerializePrxToIdc::StartImports()
{
	fprintf(m_fpOut, "static createImports() {\n");
	return true;
}

bool CSerializePrxToIdc::SerializeImport(int num, const PspLibImport *imp)
{
	char str_import[128];
	int iLoop;
	u32 addr;
	snprintf(str_import, sizeof(str_import), "import%d", num);

	addr = imp->addr;

	if(imp->stub.name != 0)
	{
		MakeOffset(m_fpOut, str_import, addr);
		MakeString(m_fpOut, BuildName(str_import, "name"), imp->stub.name);
	}
	else
	{
		MakeDword(m_fpOut, str_import, addr);
	}

	MakeDword(m_fpOut, BuildName(str_import, "flags"), addr+4);
	MakeDword(m_fpOut, BuildName(str_import, "counts"), addr+8);
	MakeOffset(m_fpOut, BuildName(str_import, "nids"), addr+12);
	MakeOffset(m_fpOut, BuildName(str_import, "funcs"), addr+16);

	for(iLoop = 0; iLoop < imp->f_count; iLoop++)
	{
		MakeDword(m_fpOut, BuildName(str_import, imp->funcs[iLoop].name), imp->funcs[iLoop].nid_addr);
		MakeFunction(m_fpOut, imp->funcs[iLoop].name, imp->funcs[iLoop].addr);
	}

	for(iLoop = 0; iLoop < imp->v_count; iLoop++)
	{
		MakeDword(m_fpOut, BuildName(str_import, imp->vars[iLoop].name), imp->vars[iLoop].nid_addr);
		MakeOffset(m_fpOut, "", imp->vars[iLoop].nid_addr + ((imp->v_count + imp->f_count) * 4));
	}

	return true;
}

bool CSerializePrxToIdc::EndImports()
{
	fprintf(m_fpOut, "}\n\n");
	return true;
}

bool CSerializePrxToIdc::StartExports()
{
	fprintf(m_fpOut, "static createExports() {\n");
	return true;
}

bool CSerializePrxToIdc::SerializeExport(int num, const PspLibExport *exp)
{
	char str_export[128];
	int iLoop;
	u32 addr;
	snprintf(str_export, sizeof(str_export), "export_%d", num);

	addr = exp->addr;

	if(exp->stub.name != 0)
	{
		MakeOffset(m_fpOut, str_export, addr);
		MakeString(m_fpOut, BuildName(str_export, "name"), exp->stub.name);
	}
	else
	{
		MakeDword(m_fpOut, str_export, addr);
	}

	MakeDword(m_fpOut, BuildName(str_export, "flags"), addr+4);
	MakeDword(m_fpOut, BuildName(str_export, "counts"), addr+8);
	MakeOffset(m_fpOut, BuildName(str_export, "exports"), addr+12);

	for(iLoop = 0; iLoop < exp->f_count; iLoop++)
	{
		MakeDword(m_fpOut, BuildName(str_export, exp->funcs[iLoop].name), exp->funcs[iLoop].nid_addr);
		MakeOffset(m_fpOut, "", exp->funcs[iLoop].nid_addr + ((exp->v_count + exp->f_count) * 4));
		MakeFunction(m_fpOut, exp->funcs[iLoop].name, exp->funcs[iLoop].addr);
	}

	for(iLoop = 0; iLoop < exp->v_count; iLoop++)
	{
		MakeDword(m_fpOut, BuildName(str_export, exp->vars[iLoop].name), exp->vars[iLoop].nid_addr);
		MakeOffset(m_fpOut, "", exp->vars[iLoop].nid_addr + ((exp->v_count + exp->f_count) * 4));
	}

	return true;
}

bool CSerializePrxToIdc::EndExports()
{
	fprintf(m_fpOut, "}\n\n");
	return true;
}

bool CSerializePrxToIdc::StartRelocs()
{
	fprintf(m_fpOut, "static createRelocs() {\n");
	return true;
}

bool CSerializePrxToIdc::SerializeReloc(int count, const ElfReloc *rel)
{
	ElfSection *pDataSect, *pTextSect;

	pDataSect = m_currPrx->ElfFindSection(".data");
	pTextSect = m_currPrx->ElfFindSection(".text");

	fprintf(stderr, "Reloc count %d, %s, data %p, text %p\n", count, rel->secname, pDataSect, pTextSect);
	return true;
}

bool CSerializePrxToIdc::EndRelocs()
{
	fprintf(m_fpOut, "}\n\n");
	return true;
}

