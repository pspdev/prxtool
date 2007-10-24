/***************************************************************
 * PRXTool : Utility for PSP executables.
 * (c) TyRaNiD 2k5
 *
 * main.C - Main function for PRXTool
 ***************************************************************/

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <cassert>
#include <sys/stat.h>
#include "SerializePrxToIdc.h"
#include "SerializePrxToXml.h"
#include "SerializePrxToMap.h"
#include "ProcessPrx.h"
#include "output.h"
#include "getargs.h"

#define PRXTOOL_VERSION "1.1"

enum OutputMode
{
	OUTPUT_NONE = 0,
	OUTPUT_IDC = 1,
	OUTPUT_MAP = 2,
	OUTPUT_XML = 3,
	OUTPUT_ELF = 4,
	OUTPUT_STUB = 6,
	OUTPUT_DEP = 7,
	OUTPUT_MOD = 8,
	OUTPUT_PSTUB = 9,
	OUTPUT_IMPEXP = 10,
	OUTPUT_SYMBOLS = 11,
	OUTPUT_DISASM  = 12,
	OUTPUT_XMLDB = 13,
};

static char **g_ppInfiles;
static int  g_iInFiles;
static char *g_pOutfile;
static char *g_pNamefile;
static char *g_pFuncfile;
static bool g_blDebug;
static OutputMode g_outputMode;
static u32 g_iSMask;
static int g_newstubs;
static u32 g_dwBase;
static const char *g_disopts = "";
static char g_namepath[PATH_MAX];
static char g_funcpath[PATH_MAX];
static bool g_loadbin = false;
static bool g_xmlOutput = false;
static bool g_aliasOutput = false;
static const char *g_pDbTitle;
static unsigned int g_database = 0;

int do_serialize(const char *arg)
{
	int i;

	i = 0;
	g_iSMask = 0;
	while(arg[i])
	{
		switch(tolower(arg[i]))
		{
			case 'i' : g_iSMask |= SERIALIZE_IMPORTS;
						break;
			case 'x' : g_iSMask |= SERIALIZE_EXPORTS;
						break;
			case 'r' : g_iSMask |= SERIALIZE_RELOCS;
						break;
			case 's' : g_iSMask |= SERIALIZE_SECTIONS;
						break;
			case 'l' : g_iSMask |= SERIALIZE_DOSYSLIB;
						break;
			default:   COutput::Printf(LEVEL_WARNING, 
							"Unknown serialize option '%c'\n", 
							tolower(arg[i]));
					   return 0;
		};
		i++;
	}

	return 1;
}

int do_xmldb(const char *arg)
{
	g_pDbTitle = arg;
	g_outputMode = OUTPUT_XMLDB;

	return 1;
}

static struct ArgEntry cmd_options[] = {
	{"output", 'o', ARG_TYPE_STR, ARG_OPT_REQUIRED, (void*) &g_pOutfile, 0, 
		"outfile : Outputfile. If not specified uses stdout"},
	{"idcout", 'c', ARG_TYPE_INT, ARG_OPT_NONE, (void*) &g_outputMode, OUTPUT_IDC, 
		"        : Output an IDC file (default)"},
	{"mapout", 'a', ARG_TYPE_INT, ARG_OPT_NONE, (void*) &g_outputMode, OUTPUT_MAP, 
		"        : Output a MAP file"},
	{"xmlout", 'x', ARG_TYPE_INT, ARG_OPT_NONE, (void*) &g_outputMode, OUTPUT_XML, 
		"        : Output an XML file"},
	{"elfout", 'e', ARG_TYPE_INT, ARG_OPT_NONE, (void*) &g_outputMode, OUTPUT_ELF, 
		"        : Output an ELF from a PRX"},
	{"debug", 'd', ARG_TYPE_BOOL, ARG_OPT_NONE, (void*) &g_blDebug, true,
		"        : Enable debug mode"},
	{"serial", 's', ARG_TYPE_FUNC, ARG_OPT_REQUIRED, (void*) &do_serialize, 0, 
		"ixrsl   : Specify what to serialize (Imports,Exports,Relocs,Sections,SyslibExp)"},
	{"xmlfile", 'n', ARG_TYPE_STR, ARG_OPT_REQUIRED, (void*) &g_pNamefile, 0, 
		"imp.xml : Specify a XML file containing the NID tables"},
	{"xmldis", 'g', ARG_TYPE_BOOL, ARG_OPT_NONE, (void*) &g_xmlOutput, true, 
		"        : Enable XML disassembly output mode"},
	{"xmldb",  'w', ARG_TYPE_FUNC, ARG_OPT_REQUIRED, (void*) &do_xmldb, 0,
		"title   : Output the PRX(es) as an XML database disassembly with a title" },
	{"stubs", 't', ARG_TYPE_INT, ARG_OPT_NONE, (void*) &g_outputMode, OUTPUT_STUB, 
		"        : Emit stub files for the XML file passed on the command line"},
	{"prxstubs", 'u', ARG_TYPE_INT, ARG_OPT_NONE, (void*) &g_outputMode, OUTPUT_PSTUB, 
		"        : Emit stub files based on the exports of the specified PRX files" },
	{"newstubs", 'k', ARG_TYPE_BOOL, ARG_OPT_NONE, (void*) &g_newstubs, true, 
		"        : Emit new style stubs for the SDK"},
	{"depends", 'q', ARG_TYPE_INT, ARG_OPT_NONE, (void*) &g_outputMode, OUTPUT_DEP, 
		"        : Print PRX dependencies. (Should have loaded an XML file to be useful"},
	{"modinfo", 'm', ARG_TYPE_INT, ARG_OPT_NONE, (void*) &g_outputMode, OUTPUT_MOD, 
		"        : Print the module and library information to screen"},
	{"impexp", 'f', ARG_TYPE_INT, ARG_OPT_NONE, (void*) &g_outputMode, OUTPUT_IMPEXP, 
		"        : Print the imports and exports of a prx"},
	{"disasm", 'w', ARG_TYPE_INT, ARG_OPT_NONE, (void*) &g_outputMode, OUTPUT_DISASM, 
		"        : Disasm the executable sections of the files (if more than one file output name is automatic)"},
	{"disopts", 'i', ARG_TYPE_STR, ARG_OPT_REQUIRED, (void*) &g_disopts, 0, 
		"opts    : Specify options for disassembler"},
	{"binary", 'b', ARG_TYPE_BOOL, ARG_OPT_NONE, (void*) &g_loadbin, true, 
		"        : Load the file as binary for disassembly"},
	{"database", 'l', ARG_TYPE_INT, ARG_OPT_REQUIRED, (void*) &g_database, 0, 
		"        : Specify the offset of the data section in the file for binary disassembly"},
	{"reloc", 'r', ARG_TYPE_INT, ARG_OPT_REQUIRED, (void*) &g_dwBase, 0, 
		"addr    : Relocate the PRX to a different address"},
	{"symbols", 'y', ARG_TYPE_INT, ARG_OPT_NONE, (void*) &g_outputMode, OUTPUT_SYMBOLS, 
		"Output a symbol file based on the input file"},
	{"funcs", 'z', ARG_TYPE_STR, ARG_OPT_REQUIRED, (void*) &g_pFuncfile, 0, 
		"        : Specify a functions file for disassembly"},
	{"alias", 'A', ARG_TYPE_BOOL, ARG_OPT_NONE, (void*) &g_aliasOutput, true, 
		"        : Print aliases when using -f mode" },
};

void DoOutput(OutputLevel level, const char *str)
{
	switch(level)
	{
		case LEVEL_INFO: fprintf(stderr, str);
						 break;
		case LEVEL_WARNING: fprintf(stderr, "Warning: %s", str);
							break;
		case LEVEL_ERROR: fprintf(stderr, "Error: %s", str);
						  break;
		case LEVEL_DEBUG: fprintf(stderr, "Debug: %s", str);
						  break;
		default: fprintf(stderr, "Unknown Level: %s", str);
				 break;
	};
}

void init_arguments()
{
	const char *home;

	g_ppInfiles = NULL;
	g_iInFiles = 0;
	g_pOutfile = NULL;
	g_blDebug = false;
	g_outputMode = OUTPUT_IDC;
	g_iSMask = SERIALIZE_ALL & ~SERIALIZE_SECTIONS;
	g_newstubs = 0;
	g_dwBase = 0;

	memset(g_namepath, 0, sizeof(g_namepath));
	memset(g_funcpath, 0, sizeof(g_funcpath));
	home = getenv("HOME");
	if(home)
	{
		struct stat s;

		snprintf(g_namepath, sizeof(g_namepath), "%s/.prxtool/psplibdoc.xml", home);
		if(stat(g_namepath, &s) == 0)
		{
			g_pNamefile = g_namepath;
		}
		snprintf(g_funcpath, sizeof(g_funcpath), "%s/.prxtool/functions.txt", home);
		if(stat(g_funcpath, &s) == 0)
		{
			g_pFuncfile = g_funcpath;
		}
	}
}

int process_args(int argc, char **argv)
{
	init_arguments();

	g_ppInfiles = GetArgs(&argc, argv, cmd_options, ARG_COUNT(cmd_options));
	if((g_ppInfiles) && (argc > 0))
	{
		g_iInFiles = argc;
	}
	else
	{
		return 0;
	}

	return 1;
}

void print_help()
{
	unsigned int i;
	COutput::Printf(LEVEL_INFO, "Usage: prxtool [options...] file\n");
	COutput::Printf(LEVEL_INFO, "Options:\n");

	for(i = 0; i < ARG_COUNT(cmd_options); i++)
	{
		if(cmd_options[i].help)
		{
			COutput::Printf(LEVEL_INFO, "--%-10s -%c %s\n", cmd_options[i].full, cmd_options[i].ch, cmd_options[i].help);
		}
	}
	COutput::Printf(LEVEL_INFO, "\n");
	COutput::Printf(LEVEL_INFO, "Disassembler Options:\n");
	COutput::Printf(LEVEL_INFO, "x - Print immediates all in hex (not just appropriate ones\n");
	COutput::Printf(LEVEL_INFO, "d - When combined with 'x' prints the hex as signed\n");
	COutput::Printf(LEVEL_INFO, "r - Print CPU registers using rN format rather than mnemonics (i.e. $a0)\n");
	COutput::Printf(LEVEL_INFO, "s - Print the PC as a symbol if possible\n");
	COutput::Printf(LEVEL_INFO, "m - Disable macro instructions (e.g. nop, beqz etc.\n");
	COutput::Printf(LEVEL_INFO, "w - Indicate PC, opcode information goes after the instruction disasm\n");
}

void output_elf(const char *file, FILE *out_fp)
{
	CProcessPrx prx(g_dwBase);

	COutput::Printf(LEVEL_INFO, "Loading %s\n", file);
	if(prx.LoadFromFile(file) == false)
	{
		COutput::Puts(LEVEL_ERROR, "Couldn't load prx file structures\n");
	}
	else
	{
		if(prx.PrxToElf(out_fp) == false)
		{
			COutput::Puts(LEVEL_ERROR, "Failed to create a fixed up ELF\n");
		}
	}
}

int compare_symbols(const void *left, const void *right)
{
	ElfSymbol *pLeft, *pRight;

	pLeft = (ElfSymbol *) left;
	pRight = (ElfSymbol *) right;

	return ((int) pLeft->value) - ((int) pRight->value);
}

void output_symbols(const char *file, FILE *out_fp)
{
	CProcessPrx prx(g_dwBase);

	COutput::Printf(LEVEL_INFO, "Loading %s\n", file);
	if(prx.LoadFromFile(file) == false)
	{
		COutput::Puts(LEVEL_ERROR, "Couldn't load elf file structures");
	}
	else
	{
		ElfSymbol *pSymbols;
		ElfSymbol *pSymCopy;
		SymfileHeader fileHead;
		int iSymCount;
		int iSymCopyCount;
		int iStrSize;
		int iStrPos;

		pSymbols = prx.GetSymbols(iSymCount);
		if(pSymbols != NULL)
		{
			SAFE_ALLOC(pSymCopy, ElfSymbol[iSymCount]);
			if(pSymCopy)
			{
				iSymCopyCount = 0;
				iStrSize = 0;
				iStrPos  = 0;
				/* Calculate the sizes */
				for(int i = 0; i < iSymCount; i++)
				{
					int type;

					type = ELF32_ST_TYPE(pSymbols[i].info);
					if(((type == STT_FUNC) || (type == STT_OBJECT)) && (strlen(pSymbols[i].symname) > 0))
					{
						memcpy(&pSymCopy[iSymCopyCount], &pSymbols[i], sizeof(ElfSymbol));
						iSymCopyCount++;
						iStrSize += strlen(pSymbols[i].symname) + 1;
					}
				}

				COutput::Printf(LEVEL_DEBUG, "Removed %d symbols, leaving %d\n", iSymCount - iSymCopyCount, iSymCopyCount);
				COutput::Printf(LEVEL_DEBUG, "String size %d\n", iSymCount - iSymCopyCount, iSymCopyCount);
				qsort(pSymCopy, iSymCopyCount, sizeof(ElfSymbol), compare_symbols);
				memcpy(fileHead.magic, SYMFILE_MAGIC, 4);
				memcpy(fileHead.modname, prx.GetModuleInfo()->name, PSP_MODULE_MAX_NAME);
				SW(fileHead.symcount, iSymCopyCount);
				SW(fileHead.strstart, sizeof(fileHead) + (sizeof(SymfileEntry)*iSymCopyCount));
				SW(fileHead.strsize, iStrSize);
				fwrite(&fileHead, 1, sizeof(fileHead), out_fp);
				for(int i = 0; i < iSymCopyCount; i++)
				{
					SymfileEntry sym;

					SW(sym.name, iStrPos);
					SW(sym.addr, pSymCopy[i].value);
					SW(sym.size, pSymCopy[i].size);
					iStrPos += strlen(pSymCopy[i].symname)+1;
					fwrite(&sym, 1, sizeof(sym), out_fp);
				}

				/* Write out string table */
				for(int i = 0; i < iSymCopyCount; i++)
				{
					fwrite(pSymCopy[i].symname, 1, strlen(pSymCopy[i].symname)+1, out_fp);
				}

				delete pSymCopy;
			}
			else
			{
				COutput::Puts(LEVEL_ERROR, "Could not allocate memory for symbol copy\n");
			}
		}
		else
		{
			COutput::Puts(LEVEL_ERROR, "No symbols available");
		}
	}
}

void output_disasm(const char *file, FILE *out_fp, CNidMgr *nids)
{
	CProcessPrx prx(g_dwBase);
	bool blRet;

	COutput::Printf(LEVEL_INFO, "Loading %s\n", file);
	prx.SetNidMgr(nids);
	if(g_loadbin)
	{
		blRet = prx.LoadFromBinFile(file, g_database);
	}
	else
	{
		blRet = prx.LoadFromFile(file);
	}

	if(g_xmlOutput)
	{
		prx.SetXmlDump();
	}

	if(blRet == false)
	{
		COutput::Puts(LEVEL_ERROR, "Couldn't load elf file structures");
	}
	else
	{
		prx.Dump(out_fp, g_disopts);
	}
}

void output_xmldb(const char *file, FILE *out_fp, CNidMgr *nids)
{
	CProcessPrx prx(g_dwBase);
	bool blRet;

	COutput::Printf(LEVEL_INFO, "Loading %s\n", file);
	prx.SetNidMgr(nids);
	if(g_loadbin)
	{
		blRet = prx.LoadFromBinFile(file, g_database);
	}
	else
	{
		blRet = prx.LoadFromFile(file);
	}

	if(blRet == false)
	{
		COutput::Puts(LEVEL_ERROR, "Couldn't load elf file structures");
	}
	else
	{
		prx.DumpXML(out_fp, g_disopts);
	}
}

void serialize_file(const char *file, CSerializePrx *pSer, CNidMgr *pNids)
{
	CProcessPrx prx(g_dwBase);

	assert(pSer != NULL);

	prx.SetNidMgr(pNids);
	COutput::Printf(LEVEL_INFO, "Loading %s\n", file);
	if(prx.LoadFromFile(file) == false)
	{
		COutput::Puts(LEVEL_ERROR, "Couldn't load prx file structures\n");
	}
	else
	{
		pSer->SerializePrx(prx, g_iSMask);
	}
}

void output_mods(const char *file, CNidMgr *pNids)
{
	CProcessPrx prx(g_dwBase);

	prx.SetNidMgr(pNids);
	if(prx.LoadFromFile(file) == false)
	{
		COutput::Puts(LEVEL_ERROR, "Couldn't load prx file structures\n");
	}
	else
	{
		PspModule *pMod;
		PspLibExport *pExport;
		PspLibImport *pImport;
		int count;

		pMod = prx.GetModuleInfo();
		COutput::Puts(LEVEL_INFO, "Module information\n");
		COutput::Printf(LEVEL_INFO, "Name:    %s\n", pMod->name);
		COutput::Printf(LEVEL_INFO, "Attrib:  %04X\n", pMod->info.flags & 0xFFFF);
		COutput::Printf(LEVEL_INFO, "Version: %d.%d\n", 
				(pMod->info.flags >> 24) & 0xFF, (pMod->info.flags >> 16) & 0xFF);
		COutput::Printf(LEVEL_INFO, "GP:      %08X\n", pMod->info.gp);

		COutput::Printf(LEVEL_INFO, "\nExports:\n");
		pExport = pMod->exp_head;
		count = 0;
		while(pExport != NULL)
		{
			COutput::Printf(LEVEL_INFO, "Export %d, Name %s, Functions %d, Variables %d, flags %08X\n", 
					count++, pExport->name, pExport->f_count, pExport->v_count, pExport->stub.flags);
			pExport = pExport->next;
		}

		COutput::Printf(LEVEL_INFO, "\nImports:\n");
		pImport = pMod->imp_head;
		count = 0;
		while(pImport != NULL)
		{
			COutput::Printf(LEVEL_INFO, "Import %d, Name %s, Functions %d, Variables %d, flags %08X\n", 
					count++, pImport->name, pImport->f_count, pImport->v_count, pImport->stub.flags);
			pImport = pImport->next;
		}

	}
}

void output_importexport(const char *file, CNidMgr *pNids)
{
	CProcessPrx prx(g_dwBase);
	int iLoop;

	prx.SetNidMgr(pNids);
	if(prx.LoadFromFile(file) == false)
	{
		COutput::Puts(LEVEL_ERROR, "Couldn't load prx file structures\n");
	}
	else
	{
		PspModule *pMod;
		PspLibExport *pExport;
		PspLibImport *pImport;
		int count;

		pMod = prx.GetModuleInfo();
		COutput::Puts(LEVEL_INFO, "Module information\n");
		COutput::Printf(LEVEL_INFO, "Name:    %s\n", pMod->name);
		COutput::Printf(LEVEL_INFO, "Attrib:  %04X\n", pMod->info.flags & 0xFFFF);
		COutput::Printf(LEVEL_INFO, "Version: %d.%d\n", 
				(pMod->info.flags >> 24) & 0xFF, (pMod->info.flags >> 16) & 0xFF);
		COutput::Printf(LEVEL_INFO, "GP:      %08X\n", pMod->info.gp);

		COutput::Printf(LEVEL_INFO, "\nExports:\n");
		pExport = pMod->exp_head;
		count = 0;
		while(pExport != NULL)
		{
			COutput::Printf(LEVEL_INFO, "Export %d, Name %s, Functions %d, Variables %d, flags %08X\n", 
					count++, pExport->name, pExport->f_count, pExport->v_count, pExport->stub.flags);

			if(pExport->f_count > 0)
			{
				COutput::Printf(LEVEL_INFO, "Functions:\n");
				for(iLoop = 0; iLoop < pExport->f_count; iLoop++)
				{

					COutput::Printf(LEVEL_INFO, "0x%08X [0x%08X] - %s", pExport->funcs[iLoop].nid, 
							pExport->funcs[iLoop].addr, pExport->funcs[iLoop].name);
					if(g_aliasOutput)
					{
						SymbolEntry *pSym;

						pSym = prx.GetSymbolEntryFromAddr(pExport->funcs[iLoop].addr);
						if((pSym) && (pSym->alias.size() > 0))
						{
							if(strcmp(pSym->name.c_str(), pExport->funcs[iLoop].name))
							{
								COutput::Printf(LEVEL_INFO, " => %s", pSym->name.c_str());
							}
							else
							{
								COutput::Printf(LEVEL_INFO, " => %s", pSym->alias[0].c_str());
							}
						}
					}
					COutput::Printf(LEVEL_INFO, "\n");
				}
			}

			if(pExport->v_count > 0)
			{
				COutput::Printf(LEVEL_INFO, "Variables:\n");
				for(iLoop = 0; iLoop < pExport->v_count; iLoop++)
				{
					COutput::Printf(LEVEL_INFO, "0x%08X [0x%08X] - %s\n", pExport->vars[iLoop].nid, 
							pExport->vars[iLoop].addr, pExport->vars[iLoop].name);
				}
			}

			pExport = pExport->next;
		}

		COutput::Printf(LEVEL_INFO, "\nImports:\n");
		pImport = pMod->imp_head;
		count = 0;
		while(pImport != NULL)
		{
			COutput::Printf(LEVEL_INFO, "Import %d, Name %s, Functions %d, Variables %d, flags %08X\n", 
					count++, pImport->name, pImport->f_count, pImport->v_count, pImport->stub.flags);

			if(pImport->f_count > 0)
			{
				COutput::Printf(LEVEL_INFO, "Functions:\n");
				for(iLoop = 0; iLoop < pImport->f_count; iLoop++)
				{
					COutput::Printf(LEVEL_INFO, "0x%08X [0x%08X] - %s\n", 
							pImport->funcs[iLoop].nid, pImport->funcs[iLoop].addr, 
							pImport->funcs[iLoop].name);
				}
			}

			if(pImport->v_count > 0)
			{
				COutput::Printf(LEVEL_INFO, "Variables:\n");
				for(iLoop = 0; iLoop < pImport->v_count; iLoop++)
				{
					COutput::Printf(LEVEL_INFO, "0x%08X [0x%08X] - %s\n", 
							pImport->vars[iLoop].nid, pImport->vars[iLoop].addr, 
							pImport->vars[iLoop].name);
				}
			}

			pImport = pImport->next;
		}

	}

}

void output_deps(const char *file, CNidMgr *pNids)
{
	CProcessPrx prx(g_dwBase);

	prx.SetNidMgr(pNids);
	if(prx.LoadFromFile(file) == false)
	{
		COutput::Puts(LEVEL_ERROR, "Couldn't load prx file structures\n");
	}
	else
	{
		PspLibImport *pHead;
		char path[PATH_MAX];
		int i;

		i = 0;
		COutput::Printf(LEVEL_INFO, "Dependancy list for %s\n", file);
		pHead = prx.GetImports();
		while(pHead != NULL)
		{
			if(strlen(pHead->file) > 0)
			{
				strcpy(path, pHead->file);
			}
			else
			{
				snprintf(path, PATH_MAX, "Unknown (%s)", pHead->name);
			}
			COutput::Printf(LEVEL_INFO, "Dependancy %d for %s: %s\n", i++, pHead->name, path);
			pHead = pHead->next;
		}
	}
}

void write_stub(const char *szDirectory, PspLibExport *pExp, CProcessPrx *pPrx)
{
	char szPath[MAXPATH];
	FILE *fp;
	COutput::Printf(LEVEL_DEBUG, "Library %s\n", pExp->name);
	if(pExp->v_count != 0)
	{
		COutput::Printf(LEVEL_WARNING, "%s: Stub output does not currently support variables\n", pExp->name);
	}

	strcpy(szPath, szDirectory);
	strcat(szPath, pExp->name);
	strcat(szPath, ".S");

	fp = fopen(szPath, "w");
	if(fp != NULL)
	{
		fprintf(fp, "\t.set noreorder\n\n");
		fprintf(fp, "#include \"pspstub.s\"\n\n");
		fprintf(fp, "\tSTUB_START\t\"%s\",0x%08X,0x%08X\n", pExp->name, pExp->stub.flags, (pExp->f_count << 16) | 5);

		for(int i = 0; i < pExp->f_count; i++)
		{
			SymbolEntry *pSym;

			if(pPrx)
			{
				pSym = pPrx->GetSymbolEntryFromAddr(pExp->funcs[i].addr);
			}
			else
			{
				pSym = NULL;
			}

			if((g_aliasOutput) && (pSym) && (pSym->alias.size() > 0))
			{
				if(strcmp(pSym->name.c_str(), pExp->funcs[i].name))
				{
					fprintf(fp, "\tSTUB_FUNC_WITH_ALIAS\t0x%08X,%s,%s\n", pExp->funcs[i].nid, pExp->funcs[i].name,
							pSym->name.c_str());
				}
				else
				{
					fprintf(fp, "\tSTUB_FUNC_WITH_ALIAS\t0x%08X,%s,%s\n", pExp->funcs[i].nid, pExp->funcs[i].name,
							pSym->alias[0].c_str());
				}
			}
			else
			{
				fprintf(fp, "\tSTUB_FUNC\t0x%08X,%s\n", pExp->funcs[i].nid, pExp->funcs[i].name);
			}
		}

		fprintf(fp, "\tSTUB_END\n");
		fclose(fp);
	}
}

void write_stub_new(const char *szDirectory, PspLibExport *pExp, CProcessPrx *pPrx)
{
	char szPath[MAXPATH];
	FILE *fp;
	COutput::Printf(LEVEL_DEBUG, "Library %s\n", pExp->name);
	if(pExp->v_count != 0)
	{
		COutput::Printf(LEVEL_WARNING, "%s: Stub output does not currently support variables\n", pExp->name);
	}

	strcpy(szPath, szDirectory);
	strcat(szPath, pExp->name);
	strcat(szPath, ".S");

	fp = fopen(szPath, "w");
	if(fp != NULL)
	{
		fprintf(fp, "\t.set noreorder\n\n");
		fprintf(fp, "#include \"pspimport.s\"\n\n");

		fprintf(fp, "// Build List\n");
		fprintf(fp, "// %s_0000.o ", pExp->name);
		for(int i = 0; i < pExp->f_count; i++)
		{
			fprintf(fp, "%s_%04d.o ", pExp->name, i + 1);
		}
		fprintf(fp, "\n\n");

		fprintf(fp, "#ifdef F_%s_0000\n", pExp->name);
		fprintf(fp, "\tIMPORT_START\t\"%s\",0x%08X\n", pExp->name, pExp->stub.flags);
		fprintf(fp, "#endif\n");

		for(int i = 0; i < pExp->f_count; i++)
		{
			SymbolEntry *pSym;

			fprintf(fp, "#ifdef F_%s_%04d\n", pExp->name, i + 1);
			if(pPrx)
			{
				pSym = pPrx->GetSymbolEntryFromAddr(pExp->funcs[i].addr);
			}
			else
			{
				pSym = NULL;
			}

			if((g_aliasOutput) && (pSym) && (pSym->alias.size() > 0))
			{
				if(strcmp(pSym->name.c_str(), pExp->funcs[i].name))
				{
					fprintf(fp, "\tIMPORT_FUNC_WITH_ALIAS\t\"%s\",0x%08X,%s,%s\n", pExp->name, 
							pExp->funcs[i].nid, pExp->funcs[i].name, pSym->name.c_str());
				}
				else
				{
					fprintf(fp, "\tIMPORT_FUNC_WITH_ALIAS\t\"%s\",0x%08X,%s,%s\n", pExp->name, 
							pExp->funcs[i].nid, pExp->funcs[i].name, pSym->alias[0].c_str());
				}
			}
			else
			{
				fprintf(fp, "\tIMPORT_FUNC\t\"%s\",0x%08X,%s\n", pExp->name, pExp->funcs[i].nid, pExp->funcs[i].name);
			}

			fprintf(fp, "#endif\n");
		}
			
		fclose(fp);
	}
}


void output_stubs_prx(const char *file, CNidMgr *pNids)
{
	CProcessPrx prx(g_dwBase);

	prx.SetNidMgr(pNids);
	if(prx.LoadFromFile(file) == false)
	{
		COutput::Puts(LEVEL_ERROR, "Couldn't load prx file structures\n");
	}
	else
	{
		PspLibExport *pHead;
		int i;

		i = 0;
		COutput::Printf(LEVEL_INFO, "Dependancy list for %s\n", file);
		pHead = prx.GetExports();
		while(pHead != NULL)
		{
			if(strcmp(pHead->name, PSP_SYSTEM_EXPORT) != 0)
			{
				if(g_newstubs)
				{
					write_stub_new("", pHead, &prx);
				}
				else
				{
					write_stub("", pHead, &prx);
				}
			}
			pHead = pHead->next;
		}
	}
}

void output_stubs_xml(CNidMgr *pNids)
{
	LibraryEntry *pLib = NULL;
	PspLibExport *pExp = NULL;

	pLib = pNids->GetLibraries();
	pExp = new PspLibExport;

	while(pLib != NULL)
	{
		/* Convery the LibraryEntry into a valid PspLibExport */
		int i;

		memset(pExp, 0, sizeof(PspLibExport));
		strcpy(pExp->name, pLib->lib_name);
		pExp->f_count = pLib->fcount;
		pExp->v_count = pLib->vcount;
		pExp->stub.flags = pLib->flags;

		for(i = 0; i < pExp->f_count; i++)
		{
			pExp->funcs[i].nid = pLib->pNids[i].nid;
			strcpy(pExp->funcs[i].name, pLib->pNids[i].name);
		}

		if(g_newstubs)
		{
			write_stub_new("", pExp, NULL);
		}
		else
		{
			write_stub("", pExp, NULL);
		}

		pLib = pLib->pNext;
	}

	if(pExp != NULL)
	{
		delete pExp;
		pExp = NULL;
	}
}

int main(int argc, char **argv)
{
	CSerializePrx *pSer;
	CNidMgr nids;
	FILE *out_fp;

	out_fp = stdout;
	COutput::SetOutputHandler(DoOutput);
	COutput::Printf(LEVEL_INFO, "PRXTool v%s : (c) TyRaNiD 2k6\n", PRXTOOL_VERSION);
	COutput::Printf(LEVEL_INFO, "Built: %s %s\n", __DATE__, __TIME__);

	if(process_args(argc, argv))
	{
		COutput::SetDebug(g_blDebug);
		if(g_pOutfile != NULL)
		{
			switch(g_outputMode)
			{
				case OUTPUT_ELF :
					out_fp = fopen(g_pOutfile, "wb");
					break;
				default:
					out_fp = fopen(g_pOutfile, "wt");
					break;
			}
			if(out_fp == NULL)
			{
				COutput::Printf(LEVEL_ERROR, "Couldn't open output file %s\n", g_pOutfile);
				return 1;
			}
		}

		switch(g_outputMode)
		{
			case OUTPUT_XML : pSer = new CSerializePrxToXml(out_fp);
							  break;
			case OUTPUT_MAP : pSer = new CSerializePrxToMap(out_fp);
							  break;
			case OUTPUT_IDC : pSer = new CSerializePrxToIdc(out_fp);
							  break;
			default: pSer = NULL;
					 break;
		};

		if(g_pNamefile != NULL)
		{
			(void) nids.AddXmlFile(g_pNamefile);
		}
		if(g_pFuncfile != NULL)
		{
			(void) nids.AddFunctionFile(g_pFuncfile);
		}

		if(g_outputMode == OUTPUT_ELF)
		{
			output_elf(g_ppInfiles[0], out_fp);
		}
		else if(g_outputMode == OUTPUT_STUB)
		{
			CNidMgr nidData;

			if(nidData.AddXmlFile(g_ppInfiles[0]))
			{
				output_stubs_xml(&nidData);
			}
		}
		else if(g_outputMode == OUTPUT_DEP)
		{
			int iLoop;

			for(iLoop = 0; iLoop < g_iInFiles; iLoop++)
			{
				output_deps(g_ppInfiles[iLoop], &nids);
			}
		}
		else if(g_outputMode == OUTPUT_MOD)
		{
			int iLoop;

			for(iLoop = 0; iLoop < g_iInFiles; iLoop++)
			{
				output_mods(g_ppInfiles[iLoop], &nids);
			}
		}
		else if(g_outputMode == OUTPUT_PSTUB)
		{
			int iLoop;

			for(iLoop = 0; iLoop < g_iInFiles; iLoop++)
			{
				output_stubs_prx(g_ppInfiles[iLoop], &nids);
			}
		}
		else if(g_outputMode == OUTPUT_IMPEXP)
		{
			int iLoop;

			for(iLoop = 0; iLoop < g_iInFiles; iLoop++)
			{
				output_importexport(g_ppInfiles[iLoop], &nids);
			}
		}
		else if(g_outputMode == OUTPUT_SYMBOLS)
		{
			output_symbols(g_ppInfiles[0], out_fp);
		}
		else if(g_outputMode == OUTPUT_XMLDB)
		{
			int iLoop;

			fprintf(out_fp, "<?xml version=\"1.0\" ?>\n");
			fprintf(out_fp, "<firmware title=\"%s\">\n", g_pDbTitle);
			for(iLoop = 0; iLoop < g_iInFiles; iLoop++)
			{
				output_xmldb(g_ppInfiles[iLoop], out_fp, &nids);
			}
			fprintf(out_fp, "</firmware>\n");
		}
		else if(g_outputMode == OUTPUT_DISASM)
		{
			int iLoop;

			if(g_iInFiles == 1)
			{
				output_disasm(g_ppInfiles[0], out_fp, &nids);
			}
			else
			{
				char path[PATH_MAX];
				int len;

				for(iLoop = 0; iLoop < g_iInFiles; iLoop++)
				{
					FILE *out;
					const char *file;

					file = strrchr(g_ppInfiles[iLoop], '/');
					if(file)
					{
						file++;
					}
					else
					{
						file = g_ppInfiles[iLoop];
					}

					if(g_xmlOutput)
					{
						len = snprintf(path, PATH_MAX, "%s.html", file);
					}
					else
					{
						len = snprintf(path, PATH_MAX, "%s.txt", file);
					}

					if((len < 0) || (len >= PATH_MAX))
					{
						continue;
					}

					out = fopen(path, "w");
					if(out == NULL)
					{
						COutput::Printf(LEVEL_INFO, "Could not open file %s for writing\n", path);
						continue;
					}

					output_disasm(g_ppInfiles[iLoop], out, &nids);
					fclose(out);
				}
			}
		}
		else
		{
			int iLoop;

			pSer->Begin();
			for(iLoop = 0; iLoop < g_iInFiles; iLoop++)
			{
				serialize_file(g_ppInfiles[iLoop], pSer, &nids);
			}
			pSer->End();

			delete pSer;
			pSer = NULL;
		}

		if((g_pOutfile != NULL) && (out_fp != NULL))
		{
			fclose(out_fp);
		}

		COutput::Puts(LEVEL_INFO, "Done");
	}
	else
	{
		print_help();
	}
}
