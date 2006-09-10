/***************************************************************
 * PRXTool : Utility for PSP executables.
 * (c) TyRaNiD 2k5
 *
 * SerializePrxToMap.h - Implementation of a class to serialize
 * a loaded PRX file to a PS2DIS Map file.
 ***************************************************************/

#ifndef __SERIALIZEPRXTOMAP_H__
#define __SERIALIZEPRXTOMAP_H__

#include <stdio.h>
#include "SerializePrx.h"

class CSerializePrxToMap : public CSerializePrx
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
	CSerializePrxToMap(FILE *fpOut);
	~CSerializePrxToMap();
};

#endif
