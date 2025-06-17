/***************************************************************
 * Name:      pubdef.h
 * Purpose:   Public Definitions
 **************************************************************/
#ifndef __PUBDEF_H__
#define __PUBDEF_H__

#ifndef UINT8
typedef unsigned char UINT8;
#endif

#ifndef INT8
typedef signed char INT8;
#endif

#ifndef UINT16
typedef unsigned short UINT16;
#endif

#ifndef INT16
typedef signed short INT16;
#endif

#ifndef UINT32
typedef unsigned int UINT32;
#endif

#ifndef INT32
typedef signed int INT32;
#endif

#ifndef UINT64
typedef unsigned long long UINT64;
#endif

#ifndef INT64
typedef long long INT64;
#endif

#ifndef VOID
typedef void VOID;
#endif

#ifndef BOOL
typedef INT32 BOOL;
#endif

#define BYTE_BITS  8
#define UINT8_BITS  8
#define UINT16_BITS 16
#define UINT32_BITS 32
#define UINT64_BITS 64

#define MAX_UINT8 0xFF
#define MAX_UINT16 0xFFFF
#define MAX_UINT32 0xFFFFFFFF
#define MAX_UINT64 0xFFFFFFFFFFFFFFFF

#define PCL_OK 0
#define PCL_ERROR 1
#define PCL_FALSE 0
#define PCL_TRUE 1
#define PCL_BYTE_BITS (8)
#define PCL_MIN(a, b) (((a) < (b)) ? (a) : (b))
#define PCL_MAX(a, b) (((a) > (b)) ? (a) : (b))

#define SHIFT_LEFT_BITS(n) (1 << (n))
#define SHIFT_RIGHT_BITS(n) (1 >> (n))

#endif // __PUBDEF_H__
