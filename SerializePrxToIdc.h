#ifndef __SERIALIZEPRXTOIDC_H__
#define __SERIALIZEPRXTOIDC_H__

#include <stdio.h>
#include "SerializePrx.h"

class CSerializePrxToIdc : public CSerializePrx
{
	FILE *m_fpOut;

	virtual bool StartFile(const char *szFilename);
	virtual bool EndFile();
	virtual bool StartSects();
	virtual bool SerializeSect(int num, ElfSection &sect);
	virtual bool EndSects();
	virtual bool StartModule();
	virtual bool SerializeModule(const PspModule *mod);
	virtual bool EndModule();
	virtual bool StartImports();
	virtual bool SerializeImport(int num, const PspLibImport *imp);
	virtual bool EndImports();
	virtual bool StartExports();
	virtual bool SerializeExport(int num, const PspLibExport *exp);
	virtual bool EndExports();
	virtual bool StartRelocs();
	virtual bool SerializeReloc();
	virtual bool EndRelocs();

public:
	CSerializePrxToIdc(FILE *fpOut);
	~CSerializePrxToIdc();
};

#endif
