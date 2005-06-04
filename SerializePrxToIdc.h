#ifndef __SERIALIZEPRXTOIDC_H__
#define __SERIALIZEPRXTOIDC_H__

#include <stdio.h>
#include "SerializePrx.h"

class CSerializePrxToIdc : public CSerializePrx
{
	FILE *m_fpOut;

	virtual bool StartFile();
	virtual bool EndFile();
	virtual bool StartPrx(const char *szFilename, const PspModule *pMod, u32 iSMask);
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
	CSerializePrxToIdc(FILE *fpOut);
	~CSerializePrxToIdc();
};

#endif
