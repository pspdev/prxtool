/***************************************************************
 * PRXTool : Utility for PSP executables.
 * (c) TyRaNiD 2k5
 *
 * Output.C - Static class to handle information and debug 
 * textual output.
 ***************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include "output.h"

bool COutput::m_blDebug = false;
OutputHandler COutput::m_fnOutput = NULL;

void COutput::SetDebug(bool blDebug)
{
	m_blDebug = blDebug;
}

bool COutput::GetDebug()
{
	return m_blDebug;
}

void COutput::SetOutputHandler(OutputHandler fn)
{
	m_fnOutput = fn;
}

void COutput::Puts(OutputLevel level, const char *str)
{
	Printf(level, "%s\n", str);
}

void COutput::Printf(OutputLevel level, const char *str, ...)
{
	va_list opt;
	char buff[2048];

	va_start(opt, str);
	(void) vsnprintf(buff, (size_t) sizeof(buff), str, opt);

	if(m_fnOutput != NULL)
	{
		if((level != LEVEL_DEBUG) || (m_blDebug))
		{
			m_fnOutput(level, buff);
		}
	}
}
