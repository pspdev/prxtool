/***************************************************************
 * PRXTool : Utility for PSP executables.
 * (c) TyRaNiD 2k5
 *
 * SerializePrxToXml.h - Definition of a class to serialize a
 * PRX to an XML file.
 ***************************************************************/

#ifndef __SERIALIZEPRXTOXML_H__
#define __SERIALIZEPRXTOXML_H__

#include <stdio.h>
#include "SerializePrx.h"

class CSerializePrxToXml : public CSerializePrx
{
	FILE *m_fpOut;

	virtual bool StartFile();
	virtual bool EndFile();
	virtual bool StartPrx(const char *szFilename, const PspModule *mod, u32 iSMask);
	virtual bool EndPrx();
	virtual bool StartSects();
	virtual bool SerializeSect(int num, ElfSection &sect);
	virtual bool EndSects();
	virtual bool StartImports();
	virtual bool SerializeImport(int num, const PspLibImport *imp);
	virtual bool EndImports();
	virtual bool StartExports();
	virtual bool SerializeExport(int num, const PspLibExport *exp);
	virtual bool EndExports();
	virtual bool StartRelocs();
	virtual bool SerializeReloc(int count, const ElfReloc *rel);
	virtual bool EndRelocs();

public:
	CSerializePrxToXml(FILE *fpOut);
	~CSerializePrxToXml();
};

#endif
