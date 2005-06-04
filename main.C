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
	OUTPUT_IDC = 0,
	OUTPUT_XML = 1,
	OUTPUT_ELF = 2,
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

	while((ch = getopt(argc, argv, "xcpdo:s:n:")) != -1)
	{
		switch(ch)
		{
			case 'd': g_blDebug = true;
					  break;
			case 'x' : g_outputMode = OUTPUT_XML;
					   break;
			case 'p' : g_outputMode = OUTPUT_ELF;
					   break;
			case 'c' : g_outputMode = OUTPUT_IDC;
					   break;
			case 'o' : g_pOutfile = optarg;
					   break;
			case 'n' : g_pNamefile = optarg;
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
	COutput::Printf(LEVEL_INFO, "Usage: prxtool [options...] prxfile\n");
	COutput::Printf(LEVEL_INFO, "Options:\n");
	COutput::Printf(LEVEL_INFO, "-o outfile : Output file. If not specified uses stdout\n");
	COutput::Printf(LEVEL_INFO, "-c         : Output an IDC file (default)\n");
	COutput::Printf(LEVEL_INFO, "-x         : Output an XML file\n");
	COutput::Printf(LEVEL_INFO, "-p         : Output a patched ELF file\n");
	COutput::Printf(LEVEL_INFO, "-t         : Output a text file containing a list of nids\n");
	COutput::Printf(LEVEL_INFO, "-d         : Enable debug mode\n");
	COutput::Printf(LEVEL_INFO, "-s ixrs    : Specify what to serialize (Imports,Exports,Relocs,Sections)\n");
	COutput::Printf(LEVEL_INFO, "-n imp.xml : Specify a XML file containing the nid tables\n");
	COutput::Printf(LEVEL_INFO, "\n");
	COutput::Printf(LEVEL_INFO, "Example: irxtool -o output.idc -s xr myfile.prx\n");
	COutput::Printf(LEVEL_INFO, "Outputs an IDC to output.idc, only serializing Exports and Relocs\n");
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
		if(prx.FixupPrx(out_fp) == false)
		{
			COutput::Puts(LEVEL_ERROR, "Failed to create a fixed up ELF\n");
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

int main(int argc, char **argv)
{
	CSerializePrx *pSer;
	CNidMgr nids;
	FILE *out_fp;

	out_fp = stdout;

	if(process_args(argc, argv))
	{
		COutput::SetDebug(g_blDebug);
		COutput::SetOutputHandler(DoOutput);
		if(g_pOutfile != NULL)
		{
			out_fp = fopen(g_pOutfile, "w");
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

		if((g_pNamefile != NULL) && (pSer != NULL))
		{
			(void) nids.AddXmlFile(g_pNamefile);
		}

		if(g_outputMode == OUTPUT_ELF)
		{
			output_elf(g_ppInfiles[0], out_fp);
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
	}
	else
	{
		print_help();
	}
}
