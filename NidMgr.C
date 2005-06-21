/***************************************************************
 * PRXTool : Utility for PSP executables.
 * (c) TyRaNiD 2k5
 *
 * NidMgr.C - Implementation of a class to manipulate a list
 * of NID Libraries.
 ***************************************************************/

#include <stdlib.h>
#include <tinyxml/tinyxml.h>
#include "output.h"
#include "NidMgr.h"

/* Default constructor */
CNidMgr::CNidMgr()
	: m_pLibHead(NULL)
{
}

/* Destructor */
CNidMgr::~CNidMgr()
{
	FreeMemory();
}

/* Free allocated memory */
void CNidMgr::FreeMemory()
{
	LibraryEntry* pLib;

	pLib = m_pLibHead;
	while(pLib != NULL)
	{
		LibraryEntry* pNext;

		pNext = pLib->pNext;

		if(pLib->pNids != NULL)
		{
			delete pLib->pNids;
			pLib->pNids = NULL;
		}

		delete pLib;
		pLib = pNext;
	}

	m_pLibHead = NULL;
}

/* Generate a simple name based on the library and the nid */
const char *CNidMgr::GenName(const char *lib, u32 nid)
{
	if(lib == NULL)
	{
		snprintf(m_szCurrName, LIB_SYMBOL_NAME_MAX, "sys_%08X", nid);
	}
	else
	{
		snprintf(m_szCurrName, LIB_SYMBOL_NAME_MAX, "%s_%08X", lib, nid);
	}

	return m_szCurrName;
}

/* Search the NID list for a function and return the name */
const char *CNidMgr::SearchLibs(const char *lib, u32 nid)
{
	const char *pName = NULL;
	LibraryEntry *pLib;

	pLib = m_pLibHead;

	/* Very lazy, could be sped up using a hash table */
	while(pLib != NULL)
	{
		if(strcmp(lib, pLib->lib_name) == 0)
		{
			int iNidLoop;

			for(iNidLoop = 0; iNidLoop < pLib->entry_count; iNidLoop++)
			{
				if(pLib->pNids[iNidLoop].nid == nid)
				{
					pName = pLib->pNids[iNidLoop].name;
					COutput::Printf(LEVEL_DEBUG, "Using %s, nid %08X\n", pName, nid);
					break;
				}
			}

			if(pName != NULL)
			{
				break;
			}
		}

		pLib = pLib->pNext;
	}

	if(pName == NULL)
	{
		COutput::Puts(LEVEL_DEBUG, "Using default name");
		pName = GenName(lib, nid);
	}

	return pName;
}

/* Read the NID data from the XML file */
const char* CNidMgr::ReadNid(TiXmlElement *pElement, u32 &nid)
{
	TiXmlHandle nidHandle(pElement);
	TiXmlText *pNid;
	TiXmlText *pName;
	const char* szName;

	szName = NULL;
	pNid = nidHandle.FirstChild("NID").FirstChild().Text();
	pName = nidHandle.FirstChild("NAME").FirstChild().Text();

	if((pNid != NULL) && (pName != NULL))
	{
		nid = strtoul(pNid->Value(), NULL, 16);
		szName = pName->Value();
	}

	return szName;
}

/* Count the number of nids in the current element */
int CNidMgr::CountNids(TiXmlElement *pElement, const char *name)
{
	TiXmlElement *pIterator;
	u32 nid;
	int iCount = 0;

	pIterator = pElement;
	while(pIterator != NULL)
	{
		if(ReadNid(pIterator, nid) != NULL)
		{
			iCount++;
		}
		pIterator = pIterator->NextSiblingElement(name);
	}

	return iCount;
}

/* Process a library XML element */
void CNidMgr::ProcessLibrary(TiXmlElement *pLibrary, const char *prx_name, const char *prx)
{
	TiXmlHandle libHandle(pLibrary);
	TiXmlText *elmName;
	TiXmlText *elmFlags;
	TiXmlElement *elmFunction;
	TiXmlElement *elmVariable;
	int fCount;
	int vCount;
	
	assert(prx_name != NULL);
	assert(prx != NULL);

	elmName = libHandle.FirstChild("NAME").FirstChild().Text();
	elmFlags = libHandle.FirstChild("FLAGS").FirstChild().Text();
	if(elmName)
	{
		LibraryEntry *pLib;

		COutput::Printf(LEVEL_DEBUG, "Library %s\n", elmName->Value());
		SAFE_ALLOC(pLib, LibraryEntry);
		if(pLib != NULL)
		{
			memset(pLib, 0, sizeof(LibraryEntry));
			strcpy(pLib->lib_name, elmName->Value());
			if(elmFlags)
			{
				pLib->flags = strtoul(elmFlags->Value(), NULL, 16);
			}

			strcpy(pLib->prx_name, prx_name);
			strcpy(pLib->prx, prx);
			elmFunction = libHandle.FirstChild("FUNCTIONS").FirstChild("FUNCTION").Element();
			elmVariable = libHandle.FirstChild("VARIABLES").FirstChild("VARIABLE").Element();
			fCount = CountNids(elmFunction, "FUNCTION");
			vCount = CountNids(elmVariable, "VARIABLE");
			pLib->vcount = vCount;
			pLib->fcount = fCount;
			if((fCount+vCount) > 0)
			{
				SAFE_ALLOC(pLib->pNids, LibraryNid[vCount+fCount]);
				if(pLib->pNids != NULL)
				{
					int iLoop;
					const char *pName;

					memset(pLib->pNids, 0, sizeof(LibraryNid) * (vCount+fCount));
					pLib->entry_count = vCount + fCount;
					iLoop = 0;
					while(elmFunction != NULL)
					{
						pName = ReadNid(elmFunction, pLib->pNids[iLoop].nid);
						if(pName)
						{
							strcpy(pLib->pNids[iLoop].name, pName);
							COutput::Printf(LEVEL_DEBUG, "Read func:%s nid:0x%08X\n", pLib->pNids[iLoop].name, pLib->pNids[iLoop].nid);
							iLoop++;
						}

						elmFunction = elmFunction->NextSiblingElement("FUNCTION");
					}

					while(elmVariable != NULL)
					{
						pName = ReadNid(elmVariable, pLib->pNids[iLoop].nid);
						if(pName)
						{
							strcpy(pLib->pNids[iLoop].name, pName);
							COutput::Printf(LEVEL_DEBUG, "Read var:%s nid:0x%08X\n", pLib->pNids[iLoop].name, pLib->pNids[iLoop].nid);
							iLoop++;
						}

						elmVariable = elmVariable->NextSiblingElement("VARIABLE");
					}
				}
			}

			/* Link into list */
			if(m_pLibHead == NULL)
			{
				m_pLibHead = pLib;
			}
			else
			{
				pLib->pNext = m_pLibHead;
				m_pLibHead = pLib;
			}
		}

		/* Allocate library memory */
	}
}

/* Process a PRXFILE XML element */
void CNidMgr::ProcessPrxfile(TiXmlElement *pPrxfile)
{
	TiXmlHandle prxHandle(pPrxfile);
	TiXmlElement *elmLibrary;
	TiXmlText *txtName;
	TiXmlText *txtPrx;
	const char *szPrx;

	txtPrx = prxHandle.FirstChild("PRX").FirstChild().Text();
	txtName = prxHandle.FirstChild("PRXNAME").FirstChild().Text();

	elmLibrary = prxHandle.FirstChild("LIBRARIES").FirstChild("LIBRARY").Element();
	while(elmLibrary)
	{
		COutput::Puts(LEVEL_DEBUG, "Found LIBRARY");

		if(txtPrx == NULL)
		{
			szPrx = "unknown.prx";
		}
		else
		{
			szPrx = txtPrx->Value();
		}

		if(txtName != NULL)
		{
			ProcessLibrary(elmLibrary, txtName->Value(), szPrx);
		}

		elmLibrary = elmLibrary->NextSiblingElement("LIBRARY");
	}
}

/* Add an XML file to the current library list */
bool CNidMgr::AddXmlFile(const char *szFilename)
{
	TiXmlDocument doc(szFilename);
	bool blRet = false;

	if(doc.LoadFile())
	{
		COutput::Printf(LEVEL_DEBUG, "Loaded XML file %s", szFilename);
		TiXmlHandle docHandle(&doc);
		TiXmlElement *elmPrxfile;

		elmPrxfile = docHandle.FirstChild("PSPLIBDOC").FirstChild("PRXFILES").FirstChild("PRXFILE").Element();
		while(elmPrxfile)
		{
			COutput::Puts(LEVEL_DEBUG, "Found PRXFILE");
			ProcessPrxfile(elmPrxfile);

			elmPrxfile = elmPrxfile->NextSiblingElement("PRXFILE");
		}
		blRet = true;
	}
	else
	{
		COutput::Printf(LEVEL_ERROR, "Couldn't load xml file %s\n", szFilename);
	}

	return blRet;
}

/* Find the name based on our list of names */
const char *CNidMgr::FindLibName(const char *lib, u32 nid)
{
	return SearchLibs(lib, nid);
}

/* Iterate through the list of libraries and generate assembly stubs for use in pspsdk */
bool CNidMgr::EmitStubs(const char *szDirectory)
{
	LibraryEntry *pLib;
	char szPath[MAXPATH];
	int pathLen;

	memset(szPath, 0, MAXPATH);
	if(szDirectory != NULL)
	{
		strcpy(szPath, szDirectory);
	}
	pathLen = strlen(szPath);
	if((pathLen > 0) && (szPath[pathLen-1] != '/') && (szPath[pathLen-1] != '\\'))
	{
		szPath[pathLen-1] = '/';
		szPath[pathLen] = 0;
		pathLen++;
	}

	pLib = m_pLibHead;


	while(pLib != NULL)
	{
		/* Ignore failure */
		if(OutputStub(szPath, pLib) == false)
		{
			COutput::Printf(LEVEL_ERROR, "Could not create stub file for library %s\n", pLib->lib_name);
		}

		pLib = pLib->pNext;
	}

	return true;
}

/* Output a single stub file */
bool CNidMgr::OutputStub(const char *szDirectory, LibraryEntry *pLib)
{
	char szPath[MAXPATH];
	FILE *fp;
	COutput::Printf(LEVEL_DEBUG, "Library %s\n", pLib->lib_name);
	if(pLib->vcount != 0)
	{
		COutput::Printf(LEVEL_WARNING, "%s: Stub output does not currently support variables\n", pLib->lib_name);
	}

	strcpy(szPath, szDirectory);
	strcat(szPath, pLib->lib_name);
	strcat(szPath, ".S");

	fp = fopen(szPath, "w");
	if(fp != NULL)
	{
		fprintf(fp, "\t.set noreorder\n\n");
		fprintf(fp, "#include \"common.s\"\n\n");
		fprintf(fp, "\tSTUB_START\t\"%s\",0x%08X,0x%08X\n", pLib->lib_name, pLib->flags, (pLib->fcount << 16) | 5);

		for(int i = 0; i < pLib->fcount; i++)
		{
			fprintf(fp, "\tSTUB_FUNC\t0x%08X,%s\n", pLib->pNids[i].nid, pLib->pNids[i].name);
		}

		fprintf(fp, "\tSTUB_END\n");
		fclose(fp);
	}

	return true;
}

/* Find the name of the dependany library for a specified lib */
const char *CNidMgr::FindDependancy(const char *lib)
{
	LibraryEntry *pLib;
	static char szUnknown[256];

	pLib = m_pLibHead;

	while(pLib != NULL)
	{
		if(strcmp(pLib->lib_name, lib) == 0)
		{
			return pLib->prx;
		}

		pLib = pLib->pNext;
	}

	sprintf(szUnknown, "Unknown (%s)", lib);
	return szUnknown;
}
