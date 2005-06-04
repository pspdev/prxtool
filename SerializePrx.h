#ifndef __SERIALIZEPRX_H__
#define __SERIALIZEPRX_H__

#include "types.h"
#include "types.h"
#include "ProcessPrx.h"

enum {
	SERIALIZE_IMPORTS  = (1 << 0),
	SERIALIZE_EXPORTS  = (1 << 1),
	SERIALIZE_SECTIONS = (1 << 2),
	SERIALIZE_RELOCS   = (1 << 3),
	SERIALIZE_ALL	   = 0xFFFFFFFF
};

/** Base class for serializing a prx file */
class CSerializePrx 
{
protected:
	/** Called when the output file is started */
	virtual bool StartFile()											= 0;
	/** Called when the output file is ended */
	virtual bool EndFile()												= 0;
	/** Called when a new prx is about to be serialized */
	virtual bool StartPrx(const char *szFilename, const PspModule *mod, u32 iSMask)			= 0;
	virtual bool EndPrx()												= 0;
	/** Called when we are about to start serializing the sections */
	virtual bool StartSects()											= 0;
	/** Called when we want to serialize a section */
	virtual bool SerializeSect(int index, ElfSection &sect)				= 0;
	/** Called when have finished serializing the sections */
	virtual bool EndSects()												= 0;
	//virtual bool StartModule()											= 0;
	//virtual bool SerializeModule(const PspModule *mod) 					= 0;
	//virtual bool EndModule()											= 0;
	virtual bool StartImports()											= 0;
	virtual bool SerializeImport(int index, const PspLibImport *imp)	= 0;
	virtual bool EndImports()											= 0;
	virtual bool StartExports()											= 0;
	virtual bool SerializeExport(int index, const PspLibExport *exp)	= 0;
	virtual bool EndExports()											= 0;
	virtual bool StartRelocs()											= 0;
	/* Called with a list of relocs for a single segment */
	virtual bool SerializeReloc(int count, const ElfReloc *rel)		= 0;
	virtual bool EndRelocs()											= 0;

	/** Pointer to the current prx, if the functions need it for what ever reason */
	CProcessPrx* m_currPrx;
	bool m_blStarted;

	void DoSects(CProcessPrx &prx);
	//void DoModule(CProcessPrx &prx);
	void DoImports(CProcessPrx &prx);
	void DoExports(CProcessPrx &prx);
	void DoRelocs(CProcessPrx &prx);
public:
	CSerializePrx();
	virtual ~CSerializePrx();
	bool Begin();
	bool SerializePrx(CProcessPrx &prx, u32 iSMask);
	bool End();
};

#endif
