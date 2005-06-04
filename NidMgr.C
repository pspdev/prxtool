#include <stdio.h>
#include <stdlib.h>
#include <tinyxml.h>
#include "NidMgr.h"

CNidMgr::CNidMgr()
	: m_pLibHead(NULL)
{
}

CNidMgr::~CNidMgr()
{
}

/* Find the name based on our list of names, not currently implemented */
const char *CNidMgr::FindLibName(const char *lib, unsigned int nid)
{
	static char lib_name[512];

	if(lib == NULL)
	{
		snprintf(lib_name, sizeof(lib_name), "sys_%08X", nid);
	}
	else
	{
		snprintf(lib_name, sizeof(lib_name), "%s_%08X", lib, nid);
	}

	return lib_name;
}
