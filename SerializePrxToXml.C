#include <stdio.h>
#include "SerializePrxToXml.h"

CSerializePrxToXml::CSerializePrxToXml(FILE *fpOut)
{
	m_fpOut = fpOut;
}

CSerializePrxToXml::~CSerializePrxToXml()
{
	fflush(m_fpOut);
}

bool CSerializePrxToXml::StartFile(const char *szFilename)
{
	fprintf(m_fpOut, "<?xml version=\"1.0\" ?>\n");
	fprintf(m_fpOut, "<PSPLIBDOC>\n");
	fprintf(m_fpOut, "\t<PRXFILES>\n");
	fprintf(m_fpOut, "\t\t<PRX>%s</PRX>\n", szFilename);

	return true;
}

bool CSerializePrxToXml::EndFile()
{
	fprintf(m_fpOut, "\t\t</LIBRARIES>\n");
	fprintf(m_fpOut, "\t</PRXFILES>\n");
	fprintf(m_fpOut, "</PSPLIBDOC>\n");
	return true;
}

bool CSerializePrxToXml::StartSects()
{
	/* Do nothing for this in XML */
	return true;
}

bool CSerializePrxToXml::SerializeSect(int num, ElfSection &sect)
{
	/* Do nothing for this in XML */

	return true;
}

bool CSerializePrxToXml::EndSects()
{
	/* Do nothing for this in XML */
	return true;
}

bool CSerializePrxToXml::StartModule()
{
	/* Do nothing for this in XML */
	return true;
}

bool CSerializePrxToXml::SerializeModule(const PspModule *mod)
{
	fprintf(m_fpOut, "\t\t<PRXNAME>%s</PRXNAME>\n", mod->name);

	return true;
}

bool CSerializePrxToXml::EndModule()
{
	fprintf(m_fpOut, "\t\t<LIBRARIES>\n");
	return true;
}

bool CSerializePrxToXml::StartImports()
{
	return true;
}

bool CSerializePrxToXml::SerializeImport(int num, const PspLibImport *imp)
{
	int iLoop;

	fprintf(m_fpOut, "\t\t\t<LIBRARY>\n");
	fprintf(m_fpOut, "\t\t\t\t<NAME>%s</NAME>\n", imp->name);

	if(imp->f_count > 0)
	{
		fprintf(m_fpOut, "\t\t\t\t<FUNCTIONS>\n");

		for(iLoop = 0; iLoop < imp->f_count; iLoop++)
		{
			fprintf(m_fpOut, "\t\t\t\t\t<FUNCTION>\n");
			fprintf(m_fpOut, "\t\t\t\t\t\t<NID>0x%08X</NID>\n", imp->funcs[iLoop].nid);
			fprintf(m_fpOut, "\t\t\t\t\t\t<NAME>%s</NAME>\n", imp->funcs[iLoop].name);
			fprintf(m_fpOut, "\t\t\t\t\t</FUNCTION>\n");
		}

		fprintf(m_fpOut, "\t\t\t\t</FUNCTIONS>\n");
	}


	if(imp->v_count > 0)
	{
		fprintf(m_fpOut, "\t\t\t\t<VARIABLES>\n");

		for(iLoop = 0; iLoop < imp->v_count; iLoop++)
		{
			fprintf(m_fpOut, "\t\t\t\t\t<FUNCTION>\n");
			fprintf(m_fpOut, "\t\t\t\t\t\t<NID>0x%08X</NID>\n", imp->vars[iLoop].nid);
			fprintf(m_fpOut, "\t\t\t\t\t\t<NAME>%s</NAME>\n", imp->vars[iLoop].name);
			fprintf(m_fpOut, "\t\t\t\t\t</FUNCTION>\n");
		}
		fprintf(m_fpOut, "\t\t\t\t</VARIABLES>\n");
	}

	fprintf(m_fpOut, "\t\t\t</LIBRARY>\n");

	return true;
}

bool CSerializePrxToXml::EndImports()
{
	return true;
}

bool CSerializePrxToXml::StartExports()
{
	return true;
}

bool CSerializePrxToXml::SerializeExport(int num, const PspLibExport *exp)
{
	int iLoop;

	fprintf(m_fpOut, "\t\t\t<LIBRARY>\n");
	fprintf(m_fpOut, "\t\t\t\t<NAME>%s</NAME>\n", exp->name);

	if(exp->f_count > 0)
	{
		fprintf(m_fpOut, "\t\t\t\t<FUNCTIONS>\n");

		for(iLoop = 0; iLoop < exp->f_count; iLoop++)
		{
			fprintf(m_fpOut, "\t\t\t\t\t<FUNCTION>\n");
			fprintf(m_fpOut, "\t\t\t\t\t\t<NID>0x%08X</NID>\n", exp->funcs[iLoop].nid);
			fprintf(m_fpOut, "\t\t\t\t\t\t<NAME>%s</NAME>\n", exp->funcs[iLoop].name);
			fprintf(m_fpOut, "\t\t\t\t\t</FUNCTION>\n");
		}

		fprintf(m_fpOut, "\t\t\t\t</FUNCTIONS>\n");
	}


	if(exp->v_count > 0)
	{
		fprintf(m_fpOut, "\t\t\t\t<VARIABLES>\n");
		for(iLoop = 0; iLoop < exp->v_count; iLoop++)
		{
			fprintf(m_fpOut, "\t\t\t\t\t<FUNCTION>\n");
			fprintf(m_fpOut, "\t\t\t\t\t\t<NID>0x%08X</NID>\n", exp->vars[iLoop].nid);
			fprintf(m_fpOut, "\t\t\t\t\t\t<NAME>%s</NAME>\n", exp->vars[iLoop].name);
			fprintf(m_fpOut, "\t\t\t\t\t</FUNCTION>\n");
		}
		fprintf(m_fpOut, "\t\t\t\t</VARIABLES>\n");
	}

	fprintf(m_fpOut, "\t\t\t</LIBRARY>\n");

	return true;
}

bool CSerializePrxToXml::EndExports()
{
	return true;
}

bool CSerializePrxToXml::StartRelocs()
{
	return true;
}

bool CSerializePrxToXml::SerializeReloc()
{
	return true;
}

bool CSerializePrxToXml::EndRelocs()
{
	return true;
}

