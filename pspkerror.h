/***************************************************************
 * PRXTool : Utility for PSP executables.
 * (c) TyRaNiD 2k5
 *
 * pspkerror.h - Definitions for error codes
 ***************************************************************/
#ifndef PSPKERROR_H
#define PSPKERROR_H

#include <stdlib.h>

struct PspErrorCode
{
	const char *name;
	unsigned int num;
};

extern struct PspErrorCode PspKernelErrorCodes[];

#endif /* PSPKERROR_H */
