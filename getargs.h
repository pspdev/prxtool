/***************************************************************
 * PRXTool : Utility for PSP executables.
 * (c) TyRaNiD 2k5
 *
 * getargs.h - Argument parser
 ***************************************************************/
#ifndef __GET_ARGS_H__
#define __GET_ARGS_H__
/* Replacement for getopt_long as I think it sucks ;P */

typedef int (*ArgFunc)(const char *opt);

enum ArgTypes
{
	ARG_TYPE_INT,
	ARG_TYPE_BOOL,
	ARG_TYPE_STR,
	ARG_TYPE_FUNC,
};

enum ArgOpts
{
	ARG_OPT_NONE,
	ARG_OPT_REQUIRED,
};

struct ArgEntry
{
	const char *full;
	char ch;
	enum ArgTypes type;
	enum ArgOpts opt;
	void *argvoid;
	int val;
	const char *help;
};

#define ARG_COUNT(x) (sizeof(x) / sizeof(struct ArgEntry))

char** GetArgs(int *argc, char **argv, struct ArgEntry *entry, int argcount);

#endif
