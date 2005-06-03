#ifndef __TYPES_H__
#define __TYPES_H__

#include <sys/types.h>

/* Re-define some system types */
typedef uint8_t 	u8;
typedef uint16_t 	u16;
typedef uint32_t	u32;
typedef int8_t		s8;
typedef int16_t		s16;
typedef int32_t		s32;

inline u32 lw_le(const u8 *ptr)
{
	u32 val;

	val = ptr[0] | (ptr[1] << 8) | (ptr[2] << 16) | (ptr[3] << 24);

	return val;
}

inline u16 lh_le(const u8 *ptr)
{
	u16 val;

	val = ptr[0] | (ptr[1] << 8);

	return val;
}

inline u32 lw_be(const u8 *ptr)
{
	u32 val;

	val = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];

	return val;
}

inline u16 lh_be(const u8 *ptr)
{
	u16 val;

	val = (ptr[0] << 16) | ptr[1];

	return val;
}

/* Should be different for different architectures */
/* Should read X as a little endian word and return the native word */
#define LW_LE(x) (lw_le((u8*) &(x)))
#define LW_BE(x) (lw_be((u8*) &(x)))
#define LH_LE(x) (lh_le((u8*) &(x)))
#define LH_BE(x) (lh_be((u8*) &(x)))
#define LW(x) (LW_LE(x))
#define LH(x) (LH_LE(x))

/* Do a safe alloc which should work on vc6 or latest gcc etc */
/* If alloc fails will always return NULL */
#define SAFE_ALLOC(p, t) try { (p) = new t; } catch(...) { (p) = NULL; }

#ifndef MAXPATH
#define MAXPATH 256
#endif

#endif
