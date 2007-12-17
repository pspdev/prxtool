/***************************************************************
 * PRXTool : Utility for PSP executables.
 * (c) TyRaNiD 2k5
 *
 * NidMgr.h - Definition of a class to manipulate a list
 * of NID Libraries.
 ***************************************************************/

#ifndef __NIDMGR_H__
#define __NIDMGR_H__

#include "types.h"
#include <tinyxml/tinyxml.h>
#include <vector>

#define LIB_NAME_MAX 64
#define LIB_SYMBOL_NAME_MAX 128

#define FUNCTION_NAME_MAX   128
#define FUNCTION_ARGS_MAX   128
#define FUNCTION_RET_MAX    64

struct LibraryEntry;

/** Structure to hold a single library nid */
struct LibraryNid
{
	/** The NID value for this symbol */
	u32 nid;
	/** The name of the symbol */
	char name[LIB_SYMBOL_NAME_MAX];
	/** The parent library */
	struct LibraryEntry *pParentLib;
};

/** Structure to hold a single function entry */
struct FunctionType
{
	char name[FUNCTION_NAME_MAX];
	char args[FUNCTION_ARGS_MAX];
	char ret[FUNCTION_RET_MAX];
};

/** Structure to hold a single library entry */
struct LibraryEntry
{
	/** Pointer to the next library in the chain */
	struct LibraryEntry* pNext;
	/** The PRX name (i.e. module name) of the file containing this lib */
	char prx_name[LIB_NAME_MAX];
	/** The name of the library */
	char lib_name[LIB_NAME_MAX];
	/** The filename of the module containing this lib (for dependancies) */
	char prx[MAXPATH];
	/** The flags as defined in the export */
	int  flags;
	/** The number of entries in the NID list */
	int  entry_count;
	/** The number of variable NIDs in the list */
	int  vcount;
	/** The number of function NIDs in the list */
	int  fcount;
	/** A pointer to a list of NIDs */
	LibraryNid *pNids;
};

/** Class to load and manage a list of libraries */
class CNidMgr
{
	typedef std::vector<FunctionType *> FunctionVect;

	/** Head pointer to the list of libraries */
	LibraryEntry *m_pLibHead;
	/** Mapping of function names to prototypes */
	FunctionVect  m_funcMap;
	/** A buffer to store a pre-generated symbol name so it can be passed to the caller */
	char m_szCurrName[LIB_SYMBOL_NAME_MAX];
	/** Indicator that we have loaded a master NID file */
	LibraryEntry *m_pMasterNids;
	/** Generate a name */
	const char *GenName(const char *lib, u32 nid);
	/** Search the loaded libs for a symbol */
	const char *SearchLibs(const char *lib, u32 nid);
	void FreeMemory();
	const char* ReadNid(TiXmlElement *pElement, u32 &nid);
	int CountNids(TiXmlElement *pElement, const char *name);
	void ProcessLibrary(TiXmlElement *pLibrary, const char *prx_name, const char *prx);
	void ProcessPrxfile(TiXmlElement *pPrxfile);
public:
	CNidMgr();
	~CNidMgr();
	const char *FindLibName(const char *lib, u32 nid);
	const char *FindDependancy(const char *lib);
	bool AddXmlFile(const char *szFilename);
	LibraryEntry *GetLibraries(void);
	bool AddFunctionFile(const char *szFilename);
	FunctionType *FindFunctionType(const char *name);
};

#endif
