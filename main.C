#include <stdio.h>
#include <unistd.h>
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

static char *g_pInfile;
static char *g_pOutfile;
static bool g_blDebug;
static OutputMode g_outputMode;

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
	g_pInfile = NULL;
	g_pOutfile = NULL;
	g_blDebug = false;
	g_outputMode = OUTPUT_IDC;
}

int process_args(int argc, char **argv)
{
	int ch;
	init_args();

	while((ch = getopt(argc, argv, "xcpdo:")) != -1)
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

	g_pInfile = argv[0];

	return 1;
}

void print_help()
{
	fprintf(stderr, "Usage: prxtool [options...] prxfile\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "-o outfile : Output file. If not specified uses stdout\n");
	fprintf(stderr, "-c         : Output an IDC file (default)\n");
	fprintf(stderr, "-x         : Output an XML file\n");
	fprintf(stderr, "-p         : Output a patched ELF file\n");
	fprintf(stderr, "-d         : Enable debug mode\n");
}

int main(int argc, char **argv)
{
	CProcessPrx prx;
	CSerializePrx *pSer;
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
			default			: pSer = new CSerializePrxToIdc(out_fp);
							  break;
							  
		};

		if(prx.LoadFromFile(g_pInfile) == false)
		{
			COutput::Puts(LEVEL_ERROR, "Couldn't load prx file structures\n");
		}
		else
		{
			pSer->Serialize(prx);
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
