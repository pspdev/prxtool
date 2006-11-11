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
#include <getopt.h>
#include "SerializePrxToIdc.h"
#include "SerializePrxToXml.h"
#include "SerializePrxToMap.h"
#include "ProcessPrx.h"
#include "output.h"

#define PRXTOOL_VERSION "1.0"

enum OutputMode
{
	OUTPUT_NONE = 0,
	OUTPUT_IDC = 1,
	OUTPUT_MAP = 2,
	OUTPUT_XML = 3,
	OUTPUT_ELF = 4,
	OUTPUT_PRX = 5,
	OUTPUT_STUB = 6,
	OUTPUT_DEP = 7,
	OUTPUT_MOD = 8,
	OUTPUT_PSTUB = 9,
	OUTPUT_IMPEXP = 10,
	OUTPUT_SYMBOLS = 11,
	OUTPUT_DISASM  = 12,
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

static struct option cmd_options[] = {
	{"output", required_argument, 0, 'o'},
	{"idcout", no_argument, 0, 'c'},
	{"mapout", no_argument, 0, 'a'},
	{"xmlout", no_argument, 0, 'x'},
	{"prxout", no_argument, 0, 'p'},
	{"elfout", no_argument, 0, 'e'},
	{"debug", no_argument, 0, 'd'},
	{"serial", required_argument, 0, 's'},
	{"xmlfile", required_argument, 0, 'n'},
	{"stubs", no_argument, 0, 't'},
	{"prxstubs", no_argument, 0, 'u'},
	{"newstubs", no_argument, 0, 'k'},
	{"depends", no_argument, 0, 'q'},
	{"modinfo", no_argument, 0, 'm'},
	{"impexp", no_argument, 0, 'f'},
	{"disasm", no_argument, 0, 'w'},
	{"disopts", required_argument, 0, 'i'},
	{"reloc", required_argument, 0, 'r'},
	{"symbols", no_argument, 0, 'y'},
	{"funcs", required_argument, 0, 'z'},
	{NULL, 0, 0, 0},
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

void init_args()
{
	g_ppInfiles = NULL;
	g_iInFiles = 0;
	g_pOutfile = NULL;
	g_pNamefile = NULL;
	g_blDebug = false;
	g_outputMode = OUTPUT_IDC;
	g_iSMask = SERIALIZE_ALL & ~SERIALIZE_SECTIONS;
	g_newstubs = 0;
}

int process_args(int argc, char **argv)
{
	int ch;
	int opt_index = 0;
	init_args();

	while((ch = getopt_long(argc, argv, "o:caxpeds:n:tukqmfwi:r:z:y", 
					cmd_options, &opt_index)) != -1)
	{
		switch(ch)
		{
			case 'd': g_blDebug = true;
					  break;
			case 'x' : g_outputMode = OUTPUT_XML;
					   break;
			case 'p' : g_outputMode = OUTPUT_PRX;
					   break;
			case 'e' : g_outputMode = OUTPUT_ELF;
					   break;
			case 'c' : g_outputMode = OUTPUT_IDC;
					   break;
			case 'a' : g_outputMode = OUTPUT_MAP;
					   break;
			case 't' : g_outputMode = OUTPUT_STUB;
					   break;
			case 'q' : g_outputMode = OUTPUT_DEP;
					   break;
			case 'u' : g_outputMode = OUTPUT_PSTUB;
					   break;
			case 'w' : g_outputMode = OUTPUT_DISASM;
					   break;
			case 'i':  g_disopts = optarg;
					   break;
			case 'o' : g_pOutfile = optarg;
					   break;
			case 'n' : g_pNamefile = optarg;
					   break;
			case 'm' : g_outputMode = OUTPUT_MOD;
					   break;
			case 'k' : g_newstubs = 1;
					   break;
			case 'f' : g_outputMode = OUTPUT_IMPEXP;
					   break;
			case 'r':  g_dwBase = strtoul(optarg, NULL, 0);
					   break;
			case 's' : {
						   int i;

						   i = 0;
						   g_iSMask = 0;
						   while(optarg[i])
						   {
							   switch(tolower(optarg[i]))
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
													  tolower(optarg[i]));
											  break;
							   };
							   i++;
						   }
					   }
					   break;
			case 'y': g_outputMode = OUTPUT_SYMBOLS;
					  break;
			case 'z': g_pFuncfile = optarg;
					  break;
			case '?':
			default:
					   return 0;
		};
	}

	argc -= optind;
	argv += optind;

	if(argc < 1)
	{
		return 0;
	}

	g_ppInfiles = &argv[0];
	g_iInFiles = argc;

	return 1;
}

void print_help()
{
	COutput::Printf(LEVEL_INFO, "Usage: prxtool [options...] file\n");
	COutput::Printf(LEVEL_INFO, "Options:\n");
	COutput::Printf(LEVEL_INFO, "--output,   -o outfile : Output file. If not specified uses stdout\n");
	COutput::Printf(LEVEL_INFO, "--idcout,   -c         : Output an IDC file (default)\n");
	COutput::Printf(LEVEL_INFO, "--mapout,   -a         : Output a MAP file\n");
	COutput::Printf(LEVEL_INFO, "--xmlout,   -x         : Output an XML file\n");
	COutput::Printf(LEVEL_INFO, "--prxout,   -p         : Output a PRX/PFX (from an ELF)\n");
	COutput::Printf(LEVEL_INFO, "--elfout,   -e         : Output an ELF (from a PRX)\n");
	COutput::Printf(LEVEL_INFO, "--debug,    -d         : Enable debug mode\n");
	COutput::Printf(LEVEL_INFO, "--serial,   -s ixrsl   : Specify what to serialize (Imports,Exports,Relocs,Sections,SyslibExp)\n");
	COutput::Printf(LEVEL_INFO, "--xmlfile,  -n imp.xml : Specify a XML file containing the nid tables\n");
	COutput::Printf(LEVEL_INFO, "--funcs,    -z funcs   : Specify a function prototype file\n");
	COutput::Printf(LEVEL_INFO, "--stubs,    -t         : Emit stub files for the XML file passed on the command line\n");
	COutput::Printf(LEVEL_INFO, "--prxstubs, -u         : Emit stub files based on the exports of the specified prx files\n");
	COutput::Printf(LEVEL_INFO, "--newstubs, -k         : Emit new style stubs for the SDK\n");
	COutput::Printf(LEVEL_INFO, "--depends,  -q         : Print PRX dependencies. (Should have loaded an XML file to be useful\n");
	COutput::Printf(LEVEL_INFO, "--modinfo,  -m         : Print the module and library information to screen\n");
	COutput::Printf(LEVEL_INFO, "--impexp,   -f         : Print the imports and exports of a prx\n");
	COutput::Printf(LEVEL_INFO, "--symbols,  -y         : Output special symbols file\n");
	COutput::Printf(LEVEL_INFO, "--disasm,   -w         : Disasm the executable sections of the file\n");
	COutput::Printf(LEVEL_INFO, "--disopts,  -i [opts]  : A list dissasembler options\n");
	COutput::Printf(LEVEL_INFO, "--reloc     -r addr    : Relocation the PRX to a different address\n");
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
	CProcessPrx prx;

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

void output_prx(const char *file, FILE *out_fp)
{
	CProcessPrx prx;

	COutput::Printf(LEVEL_INFO, "Loading %s\n", file);
	if(prx.LoadFromFile(file) == false)
	{
		COutput::Puts(LEVEL_ERROR, "Couldn't load elf file structures\n");
	}
	else
	{
		if(prx.ElfToPrx(out_fp) == false)
		{
			COutput::Puts(LEVEL_ERROR, "Failed to create a fixed up PRX\n");
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
	CProcessPrx prx;

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
	CProcessPrx prx;

	COutput::Printf(LEVEL_INFO, "Loading %s\n", file);
	prx.SetNidMgr(nids);
	if(prx.LoadFromFile(file) == false)
	{
		COutput::Puts(LEVEL_ERROR, "Couldn't load elf file structures");
	}
	else
	{
		prx.Dump(false, out_fp, g_disopts, g_dwBase);
	}
}

void serialize_file(const char *file, CSerializePrx *pSer, CNidMgr *pNids)
{
	CProcessPrx prx;

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
	CProcessPrx prx;

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
	CProcessPrx prx;
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
					COutput::Printf(LEVEL_INFO, "0x%08X [0x%08X] - %s\n", pExport->funcs[iLoop].nid, 
							pExport->funcs[iLoop].addr, pExport->funcs[iLoop].name);
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
	CProcessPrx prx;

	prx.SetNidMgr(pNids);
	if(prx.LoadFromFile(file) == false)
	{
		COutput::Puts(LEVEL_ERROR, "Couldn't load prx file structures\n");
	}
	else
	{
		PspLibImport *pHead;
		int i;

		i = 0;
		COutput::Printf(LEVEL_INFO, "Dependancy list for %s\n", file);
		pHead = prx.GetImports();
		while(pHead != NULL)
		{
			COutput::Printf(LEVEL_INFO, "Dependacy %d for %s: %s\n", i++, pHead->name, pNids->FindDependancy(pHead->name));
			pHead = pHead->next;
		}
	}
}

void write_stub(const char *szDirectory, PspLibExport *pExp)
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
			fprintf(fp, "\tSTUB_FUNC\t0x%08X,%s\n", pExp->funcs[i].nid, pExp->funcs[i].name);
		}

		fprintf(fp, "\tSTUB_END\n");
		fclose(fp);
	}
}

void write_stub_new(const char *szDirectory, PspLibExport *pExp)
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
			fprintf(fp, "#ifdef F_%s_%04d\n", pExp->name, i + 1);
			fprintf(fp, "\tIMPORT_FUNC\t\"%s\",0x%08X,%s\n", pExp->name, pExp->funcs[i].nid, pExp->funcs[i].name);
			fprintf(fp, "#endif\n");
		}
			
		fclose(fp);
	}
}


void output_stubs_prx(const char *file, CNidMgr *pNids)
{
	CProcessPrx prx;

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
					write_stub_new("", pHead);
				}
				else
				{
					write_stub("", pHead);
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
			write_stub_new("", pExp);
		}
		else
		{
			write_stub("", pExp);
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

	if(process_args(argc, argv))
	{
		COutput::SetDebug(g_blDebug);
		if(g_pOutfile != NULL)
		{
			switch(g_outputMode)
			{
				case OUTPUT_ELF :
				case OUTPUT_PRX :
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
		else if(g_outputMode == OUTPUT_PRX)
		{
			output_prx(g_ppInfiles[0], out_fp);
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
		else if(g_outputMode == OUTPUT_DISASM)
		{
			output_disasm(g_ppInfiles[0], out_fp, &nids);
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
