#ifndef __NIDMGR_H__
#define __NIDMGR_H__

#include "types.h"
#include <tinyxml/tinyxml.h>

#define LIB_NAME_MAX 64
#define LIB_SYMBOL_NAME_MAX 128

struct LibraryNid
{
	u32 nid;
	char name[LIB_SYMBOL_NAME_MAX];
};

struct LibraryEntry
{
	struct LibraryEntry* pNext;
	char prx_name[LIB_NAME_MAX];
	char lib_name[LIB_NAME_MAX];
	int  flags;
	int  entry_count;
	int  vcount;
	int  fcount;
	LibraryNid *pNids;
};

class CNidMgr
{
	LibraryEntry *m_pLibHead;
	char m_szCurrName[LIB_SYMBOL_NAME_MAX];
	const char *GenName(const char *lib, u32 nid);
	const char *SearchLibs(const char *lib, u32 nid);
	void FreeMemory();
	const char* ReadNid(TiXmlElement *pElement, u32 &nid);
	int CountNids(TiXmlElement *pElement, const char *name);
	void ProcessLibrary(TiXmlElement *pLibrary, const char *prx_name);
	void ProcessPrxfile(TiXmlElement *pPrxfile);
	bool OutputStub(const char *szDirectory, LibraryEntry *pLib);
public:
	CNidMgr();
	~CNidMgr();
	const char *FindLibName(const char *lib, u32 nid);
	bool AddXmlFile(const char *szFilename);
	bool EmitStubs(const char *szDirectory);
};

#endif
