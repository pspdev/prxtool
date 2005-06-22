/***************************************************************
 * PRXTool : Utility for PSP executables.
 * (c) TyRaNiD 2k5
 *
 * output.h - Definition of a class to handle textual output.
 ***************************************************************/

#ifndef __OUTPUT_H__
#define __OUTPUT_H__

enum OutputLevel
{
	LEVEL_INFO = 0,
	LEVEL_WARNING = 1,
	LEVEL_ERROR = 2,
	LEVEL_DEBUG = 3
};

typedef void (*OutputHandler)(OutputLevel level, const char *szDebug);

class COutput
{
	/* Enables debug output */
	static bool m_blDebug;
	static OutputHandler m_fnOutput;
	COutput() {};
	~COutput() {};
public:
	static void SetDebug(bool blDebug);
	static bool GetDebug();
	static void SetOutputHandler(OutputHandler fn);
	static void Puts(OutputLevel level, const char *str);
	static void Printf(OutputLevel level, const char *str, ...);
};

#endif
