#ifndef __NIDMGR_H__
#define __NIDMGR_H__

#include "types.h"

#define LIB_NAME_MAX 32
#define LIB_SYMBOL_NAME_MAX 128

struct LibraryNid
{
	struct LibraryNid* pNext;
	u32 nid;
	char name[LIB_SYMBOL_NAME_MAX];
};

struct LibraryEntry
{
	struct LibraryEntry* pNext;
	char lib_name[LIB_NAME_MAX];
	int  entry_count;
	LibraryNid *pHead;
};

class CNidMgr
{
public:
	CNidMgr();
	~CNidMgr();
	const char *FindLibName(const char *lib, u32 nid);
	bool AddXmlFile(const char *szFilename);
};

#endif
