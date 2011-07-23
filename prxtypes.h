/***************************************************************
 * PRXTool : Utility for PSP executables.
 * (c) TyRaNiD 2k5
 *
 * prxtypes.h - Definition of PRX specific types.
 ***************************************************************/

#ifndef __PRXTYPES_H__
#define __PRXTYPES_H__

#include <limits.h>
#include "types.h"

#define PSP_MODULE_MAX_NAME 28
#define PSP_LIB_MAX_NAME 128
#define PSP_ENTRY_MAX_NAME 128
/* Define the maximum number of permitted entries per lib */
#define PSP_MAX_V_ENTRIES 255
#define PSP_MAX_F_ENTRIES 2000

#define PSP_MODULE_INFO_NAME ".rodata.sceModuleInfo"

/* Define a name for the unnamed first export */
#define PSP_SYSTEM_EXPORT "syslib"

enum PspEntryType
{
	PSP_ENTRY_FUNC = 0,
	PSP_ENTRY_VAR = 1
};

/* Define the in-prx structure types */

/* Structure to hold the module export information */
struct PspModuleExport
{
	u32 name;
	u32 flags;
	u32 counts;
	u32 exports;
};

/* Base size of an import structure */
#define PSP_IMPORT_BASE_SIZE (5*4)

/* Structure to hold the module import information */
struct PspModuleImport
{
	u32 name;
	u32 flags;
	u32 counts;
	u32 nids;
	u32 funcs;
	u32 vars;
};

/* Structure to hold the module info */
struct PspModuleInfo
{
	u32 flags;
	char name[PSP_MODULE_MAX_NAME];
	u32 gp;
	u32 exports;
	u32 exp_end;
	u32 imports;
	u32 imp_end;
};

/* Define the loaded prx types */
struct PspEntry
{
	/* Name of the entry */
	char name[PSP_ENTRY_MAX_NAME];
	/* Nid of the entry */
	u32 nid;
	/* Type of the entry */
	PspEntryType type;
	/* Virtual address of the entry in the loaded elf */
	u32 addr;
	/* Virtual address of the nid dword */
	u32 nid_addr;
};

/* Holds a linking entry for an import library */
struct PspLibImport
{
	/** Previous import */
	PspLibImport *prev;
	/** Next import */
	PspLibImport *next;
	/** Name of the library */
	char name[PSP_LIB_MAX_NAME];
	/** Virtual address of the lib import stub */
	u32 addr;
	/** Copy of the import stub (in native byte order) */
	PspModuleImport stub;
	/** List of function entries */
	PspEntry funcs[PSP_MAX_F_ENTRIES];
	/** Number of function entries */
	int f_count;
	/** List of variable entried */
	PspEntry vars[PSP_MAX_V_ENTRIES];
	/** Number of variable entries */
	int v_count;
	/** File containing the export */
	char file[PATH_MAX];
};

/* Holds a linking entry for an export library */
struct PspLibExport
{
	/** Previous export in the chain */
	PspLibExport *prev;
	/** Next export in the chain */
	PspLibExport *next;
	/** Name of the library */
	char name[PSP_LIB_MAX_NAME];
	/** Virtual address of the lib import stub */
	u32 addr;
	/** Copy of the import stub (in native byte order) */
	PspModuleExport stub;
	/** List of function entries */
	PspEntry funcs[PSP_MAX_F_ENTRIES];
	/** Number of function entries */
	int f_count;
	/** List of variable entried */
	PspEntry vars[PSP_MAX_V_ENTRIES];
	/** Number of variable entires */
	int v_count;
};

/** Structure to hold the loaded module information */
struct PspModule
{
	/** Name of the module */
	char name[PSP_MODULE_MAX_NAME+1];
	/** Info structure, in native byte order */
	PspModuleInfo info;
	/** Virtual address of the module info section */
	u32 addr;
	/** Head of the export list */
	PspLibExport *exp_head;
	/** Head of the import list */
	PspLibImport *imp_head;
};

#define SYMFILE_MAGIC "SYMS"

struct SymfileHeader
{
	char magic[4];
	char modname[PSP_MODULE_MAX_NAME];
	u32  symcount;
	u32  strstart;
	u32  strsize;
} __attribute__((packed));

struct SymfileEntry
{
	u32 name;
	u32 addr;
	u32 size;
} __attribute__((packed));

#endif
