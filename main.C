#include <stdio.h>
#include "SerializePrxToIdc.h"
#include "ProcessPrx.h"
#include "output.h"

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

int main(int argc, char **argv)
{
	CProcessPrx elf;

	COutput::SetDebug(true);
	COutput::SetOutputHandler(DoOutput);
	if(elf.LoadFromFile(argv[1]) == false)
	{
		COutput::Puts(LEVEL_ERROR, "Couldn't load prx file structures\n");
	}
	else
	{
		CSerializePrxToIdc ser(stdout);
		ser.Serialize(elf);
	}
}
