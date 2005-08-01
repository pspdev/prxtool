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
#include "SerializePrxToIdc.h"
#include "SerializePrxToXml.h"
#include "ProcessPrx.h"
#include "output.h"

enum OutputMode
{
	OUTPUT_NONE = 0,
	OUTPUT_IDC = 1,
	OUTPUT_XML = 2,
	OUTPUT_ELF = 3,
	OUTPUT_PRX = 4,
	OUTPUT_STUB = 5,
	OUTPUT_DEP = 6,
	OUTPUT_MOD = 7,
	OUTPUT_PSTUB = 8,
};

static char **g_ppInfiles;
static int  g_iInFiles;
static char *g_pOutfile;
static char *g_pNamefile;
static bool g_blDebug;
static OutputMode g_outputMode;
static u32 g_iSMask;

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
	g_iSMask = SERIALIZE_ALL;
}

int process_args(int argc, char **argv)
{
	int ch;
	init_args();

	while((ch = getopt(argc, argv, "xcptuqemdo:s:n:")) != -1)
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
			case 't' : g_outputMode = OUTPUT_STUB;
					   break;
			case 'q' : g_outputMode = OUTPUT_DEP;
					   break;
			case 'u' : g_outputMode = OUTPUT_PSTUB;
					   break;
			case 'o' : g_pOutfile = optarg;
					   break;
			case 'n' : g_pNamefile = optarg;
					   break;
			case 'm' : g_outputMode = OUTPUT_MOD;
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
	COutput::Printf(LEVEL_INFO, "-o outfile : Output file. If not specified uses stdout\n");
	COutput::Printf(LEVEL_INFO, "-c         : Output an IDC file (default)\n");
	COutput::Printf(LEVEL_INFO, "-x         : Output an XML file\n");
	COutput::Printf(LEVEL_INFO, "-p         : Output a PRX/PFX (from an ELF)\n");
	COutput::Printf(LEVEL_INFO, "-e         : Output an ELF (from a PRX)\n");
	COutput::Printf(LEVEL_INFO, "-d         : Enable debug mode\n");
	COutput::Printf(LEVEL_INFO, "-s ixrsl   : Specify what to serialize (Imports,Exports,Relocs,Sections,SyslibExp)\n");
	COutput::Printf(LEVEL_INFO, "-n imp.xml : Specify a XML file containing the nid tables\n");
	COutput::Printf(LEVEL_INFO, "-t         : Emit stub files for the XML file passed on the command line\n");
	COutput::Printf(LEVEL_INFO, "-u         : Emit stub files based on the exports of the specified prx files\n");
	COutput::Printf(LEVEL_INFO, "-q         : Print PRX dependencies. (Should have loaded an XML file to be useful\n");
	COutput::Printf(LEVEL_INFO, "-m         : Print the module and library information to screen\n");
	COutput::Printf(LEVEL_INFO, "\n");
	COutput::Printf(LEVEL_INFO, "Example 1: prxtool -o output.idc -s xr myfile.prx\n");
	COutput::Printf(LEVEL_INFO, "Outputs an IDC to output.idc, only serializing Exports and Relocs\n");
	COutput::Printf(LEVEL_INFO, "Example 2: prxtool -c psplibdoc.xml\n");
	COutput::Printf(LEVEL_INFO, "Outputs one or more stub .S files to the current directory from the XML file\n");
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
				(pMod->info.flags >> 16) & 0xFF, (pMod->info.flags >> 24) & 0xFF);
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

void output_stubs(const char *file, CNidMgr *pNids)
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
				write_stub("", pHead);
			}
			pHead = pHead->next;
		}
	}
}

int main(int argc, char **argv)
{
	CSerializePrx *pSer;
	CNidMgr nids;
	FILE *out_fp;

	out_fp = stdout;
	COutput::SetOutputHandler(DoOutput);

	if(process_args(argc, argv))
	{
		COutput::SetDebug(g_blDebug);
		if(g_pOutfile != NULL)
		{
			switch(g_outputMode)
			{
				case OUTPUT_XML :
				case OUTPUT_IDC :
					out_fp = fopen(g_pOutfile, "wt");
					break;
				case OUTPUT_ELF :
				case OUTPUT_PRX :
				default:
					out_fp = fopen(g_pOutfile, "wb");
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
			case OUTPUT_IDC : pSer = new CSerializePrxToIdc(out_fp);
							  break;
			default: pSer = NULL;
					 break;
		};

		if(g_pNamefile != NULL)
		{
			(void) nids.AddXmlFile(g_pNamefile);
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
				if(nidData.EmitStubs("") == false)
				{
					COutput::Puts(LEVEL_ERROR, "Failed to emit stubs");
				}
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
				output_stubs(g_ppInfiles[iLoop], &nids);
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
