#ifndef __SERIALIZEPRX_H__
#define __SERIALIZEPRX_H__

#include "types.h"
#include "types.h"
#include "ProcessPrx.h"

/* Base class for serializing a prx file */
class CSerializePrx 
{
protected:
	virtual bool StartFile(const char *szFilename)					= 0;
	virtual bool EndFile()											= 0;
	virtual bool StartSects()										= 0;
	virtual bool SerializeSect(int num, ElfSection &sect)			= 0;
	virtual bool EndSects()											= 0;
	virtual bool StartModule()										= 0;
	virtual bool SerializeModule(const PspModule *mod) 				= 0;
	virtual bool EndModule()										= 0;
	virtual bool StartImports()										= 0;
	virtual bool SerializeImport(int num, const PspLibImport *imp)	= 0;
	virtual bool EndImports()										= 0;
	virtual bool StartExports()										= 0;
	virtual bool SerializeExport(int num, const PspLibExport *exp)	= 0;
	virtual bool EndExports()										= 0;
	virtual bool StartRelocs()										= 0;
	virtual bool SerializeReloc()									= 0;
	virtual bool EndRelocs()										= 0;

	void DoSects(CProcessPrx &prx);
	void DoModule(CProcessPrx &prx);
	void DoImports(CProcessPrx &prx);
	void DoExports(CProcessPrx &prx);
	void DoRelocs(CProcessPrx &prx);
public:
	CSerializePrx();
	virtual ~CSerializePrx();
	bool Serialize(CProcessPrx &prx);
};

#endif
