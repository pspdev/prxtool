#include <stdlib.h>
#include <tinyxml/tinyxml.h>
#include "output.h"
#include "NidMgr.h"

CNidMgr::CNidMgr()
	: m_pLibHead(NULL)
{
}

CNidMgr::~CNidMgr()
{
	FreeMemory();
}

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

const char *CNidMgr::SearchLibs(const char *lib, unsigned int nid)
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

void CNidMgr::ProcessLibrary(TiXmlElement *pLibrary, const char *prx_name)
{
	TiXmlHandle libHandle(pLibrary);
	TiXmlText *elmName;
	TiXmlElement *elmFunction;
	TiXmlElement *elmVariable;
	int fCount;
	int vCount;
	
	assert(prx_name != NULL);

	elmName = libHandle.FirstChild("NAME").FirstChild().Text();
	if(elmName)
	{
		LibraryEntry *pLib;

		COutput::Printf(LEVEL_DEBUG, "Library %s\n", elmName->Value());
		SAFE_ALLOC(pLib, LibraryEntry);
		if(pLib != NULL)
		{
			memset(pLib, 0, sizeof(LibraryEntry));
			strcpy(pLib->lib_name, elmName->Value());
			strcpy(pLib->prx_name, prx_name);
			elmFunction = libHandle.FirstChild("FUNCTIONS").FirstChild("FUNCTION").Element();
			elmVariable = libHandle.FirstChild("VARIABLES").FirstChild("VARIABLE").Element();
			fCount = CountNids(elmFunction, "FUNCTION");
			vCount = CountNids(elmVariable, "VARIABLE");
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

void CNidMgr::ProcessPrxfile(TiXmlElement *pPrxfile)
{
	TiXmlHandle prxHandle(pPrxfile);
	TiXmlElement *elmLibrary;
	TiXmlText *txtName;

	txtName = prxHandle.FirstChild("PRXNAME").FirstChild().Text();

	elmLibrary = prxHandle.FirstChild("LIBRARIES").FirstChild("LIBRARY").Element();
	while(elmLibrary)
	{
		COutput::Puts(LEVEL_DEBUG, "Found LIBRARY");

		if(txtName != NULL)
		{
			ProcessLibrary(elmLibrary, txtName->Value());
		}

		elmLibrary = elmLibrary->NextSiblingElement("LIBRARY");
	}
}

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
	}
	else
	{
		COutput::Printf(LEVEL_ERROR, "Couldn't load xml file %s\n", szFilename);
	}

	return blRet;
}

/* Find the name based on our list of names, not currently implemented */
const char *CNidMgr::FindLibName(const char *lib, unsigned int nid)
{
	return SearchLibs(lib, nid);
}
