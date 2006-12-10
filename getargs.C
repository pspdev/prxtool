/***************************************************************
 * PRXTool : Utility for PSP executables.
 * (c) TyRaNiD 2k5
 *
 * getargs.C - Argument parser
 ***************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "getargs.h"

char **GetArgs(int *argc, char **argv, struct ArgEntry *entry, int argcount)
{
	int error = 0;

	if((argc == NULL) || (argv == NULL) || (entry == NULL))
	{
		return NULL;
	}

	(*argc)--;
	argv++;

	while(*argc > 0)
	{
		const char *arg;
		struct ArgEntry *ent;

		if(*argv == NULL)
		{
			error = 1;
			break;
		}
		arg = *argv;

		if(arg[0] != '-')
		{
			break;
		}

		if(arg[1] == '-')
		{
			/* Long arg */
			int i;

			ent = NULL;
			for(i = 0; i < argcount; i++)
			{
				if(entry[i].full)
				{
					if(strcmp(entry[i].full, &arg[2]) == 0)
					{
						ent = &entry[i];
					}
				}
			}
		}
		else if(arg[1] != 0)
		{
			int i;

			ent = NULL;

			/* Error check, short options should be 2 characters */
			if(strlen(arg) == 2)
			{
				for(i = 0; i < argcount; i++)
				{
					if(entry[i].ch == arg[1])
					{
						ent = &entry[i];
					}
				}
			}
		}
		else
		{
			/* Single - means stop processing */
			(*argc)--;
			argv++;
			break;
		}

		if(ent == NULL)
		{
			fprintf(stderr, "Invalid argument %s\n", arg);
			error = 1;
			break;
		}

		if(ent->argvoid == NULL)
		{
			fprintf(stderr, "Internal error processing %s\n", arg);
			error = 1;
			break;
		}

		if(ent->opt == ARG_OPT_NONE)
		{
			switch(ent->type)
			{
				case ARG_TYPE_BOOL: { 
										bool *argbool = (bool *) ent->argvoid;
										*argbool = ent->val;
									}
									break;
				case ARG_TYPE_INT: {
										int *argint = (int *) ent->argvoid;
										*argint = ent->val;
									 }
									 break;
				case ARG_TYPE_FUNC: { ArgFunc argfunc = (ArgFunc) ent->argvoid; 
								    if(argfunc(NULL) == 0)
									{
										fprintf(stderr, "Error processing argument for %s\n", arg);
										error = 1;
									}
									}
									break;
				default: fprintf(stderr, "Invalid type for option %s\n", arg);
						 error = 1;
						 break;
			};

			if(error)
			{
				break;
			}
		}
		else if(ent->opt == ARG_OPT_REQUIRED)
		{
			if(*argc <= 1)
			{
				fprintf(stderr, "No argument passed for %s\n", arg);
				error = 1;
				break;
			}
			(*argc)--;
			argv++;

			switch(ent->type)
			{
				case ARG_TYPE_INT: { int *argint = (int*) ent->argvoid;
								   *argint = strtoul(argv[0], NULL, 0);
								   }
								   break;
				case ARG_TYPE_STR: { const char **argstr = (const char **) ent->argvoid;
								   *argstr = argv[0];
								   }
								   break;
				case ARG_TYPE_FUNC: { ArgFunc argfunc = (ArgFunc) ent->argvoid; 
								    if(argfunc(argv[0]) == 0)
									{
										fprintf(stderr, "Error processing argument for %s\n", arg);
										error = 1;
									}
									}
									break;
				default: fprintf(stderr, "Invalid type for option %s\n", arg);
						 error = 1;
						 break;
			};

			if(error)
			{
				break;
			}
		}
		else
		{
			fprintf(stderr, "Internal options error processing %s\n", arg);
			error = 1;
			break;
		}

		(*argc)--;
		argv++;
	}

	if(error)
	{
		return NULL;
	}
	else
	{
		return argv;
	}
}
