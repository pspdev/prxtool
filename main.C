#include <stdio.h>
#include "SerializePrxToIdc.h"
#include "SerializePrxToXml.h"
#include "ProcessPrx.h"
#include "output.h"

static char *pInfile;
static char *pOutfile;

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
	pInfile = NULL;
	pOutfile = NULL;
}

int process_args(int argc, char **argv)
{
	init_args();

	if(argc < 2)
	{
		return 0;
	}

	pInfile = argv[1];

	return 1;
}

void print_help()
{
	fprintf(stderr, "Usage: prxtool prxfile\n");
}

int main(int argc, char **argv)
{
	CProcessPrx elf;


	if(process_args(argc, argv))
	{
		COutput::SetDebug(false);
		COutput::SetOutputHandler(DoOutput);
		if(elf.LoadFromFile(pInfile) == false)
		{
			COutput::Puts(LEVEL_ERROR, "Couldn't load prx file structures\n");
		}
		else
		{
			CSerializePrxToIdc ser(stdout);
			ser.Serialize(elf);
		}
	}
	else
	{
		print_help();
	}
}
