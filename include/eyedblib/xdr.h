/* 
   EyeDB Object Database Management System
   Copyright (C) 1994-2008 SYSRA
   
   EyeDB is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.
   
   EyeDB is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   
   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA 
*/

/*
   Author: Eric Viara <viara@sysra.com>
*/


#ifndef _EYEDBLIB_XDR_H
#define _EYEDBLIB_XDR_H

#include <netinet/in.h>
#include <eyedblib/machtypes.h>
#include <eyedblib/endian.h>

#define XDR_MACROS

/*#define INTERNAL_XDR*/

#ifdef INTERNAL_XDR
#undef htonl
#undef htons
#undef ntohl
#undef ntohs
#endif

#ifdef XDR_MACROS

/* host to external macros (h2x) */
#define h2x_16(x) (eyedblib::int16)htons(x)
#define h2x_u16(x) (eyedblib::uint16)h2x_16((eyedblib::uint16)(x))
#define h2x_32(x) (eyedblib::int32)htonl(x)
#define h2x_u32(x) (eyedblib::uint32)h2x_32((eyedblib::uint32)(x))

#ifdef EYEDBLIB_BIG_ENDIAN
#define h2x_64(x) (x)
#else
#define h2x_64(x) (((unsigned long long)htonl(x)) << 32 | htonl((x >> 32) & 0xffffffff))
#endif

/* external to host macros (x2h) */

#define x2h_u64(x) ((eyedblib::uint64)x2h_64((eyedblib::uint64)(x)))
#define x2h_16(x) (eyedblib::int16)ntohs(x)
#define x2h_u16(x) (eyedblib::uint16)x2h_16((eyedblib::uint16)(x))
#define x2h_32(x) (eyedblib::int32)ntohl(x)
#define x2h_u32(x) (eyedblib::uint32)x2h_32((eyedblib::uint32)(x))

#ifdef EYEDBLIB_BIG_ENDIAN
#define x2h_64(x) (x)
#else
#define x2h_64(x) (((unsigned long long)ntohl(x)) << 32 | ntohl((x >> 32) & 0xffffffff))
#endif

#define h2x_u64(x) ((eyedblib::uint64)h2x_64((eyedblib::uint64)(x)))

/* host to external copy macros (h2x_cpy) */

#ifdef EYEDBLIB_BIG_ENDIAN

#define h2x_16_cpy(to, from) \
do { \
  if (from) eyedblib_mcp((to), (from), sizeof(eyedblib::int16)); \
} while(0)

#define h2x_32_cpy(to, from) \
do { \
  if (from) eyedblib_mcp((to), (from), sizeof(eyedblib::int32)); \
} while(0)

#define h2x_64_cpy(to, from) \
do { \
  if (from) eyedblib_mcp((to), (from), sizeof(eyedblib::int64)); \
} while(0)

#else

#define h2x_16_cpy(to, xfrom) \
do { \
  eyedblib::int16 sx; \
  const void *from = (xfrom); \
  if (!from) from = (to); \
  eyedblib_mcp(&sx, (from), sizeof(sx)); \
  sx = h2x_16(sx); \
  eyedblib_mcp(to, &sx, sizeof(sx)); \
} while(0)

#define h2x_32_cpy(to, xfrom) \
do { \
  eyedblib::int32 sx; \
  const void *from = (xfrom); \
  if (!from) from = (to); \
  eyedblib_mcp(&sx, (from), sizeof(sx)); \
  sx = h2x_32(sx); \
  eyedblib_mcp(to, &sx, sizeof(sx)); \
} while(0)

#define h2x_64_cpy(to, xfrom) \
do { \
  eyedblib::int64 sx; \
  const void *from = (xfrom); \
  if (!from) from = (to); \
  eyedblib_mcp(&sx, (from), sizeof(sx)); \
  sx = h2x_64(sx); \
  eyedblib_mcp(to, &sx, sizeof(sx)); \
} while(0)
#endif

/* external to host copy macros (x2h_cpy) */

#ifdef EYEDBLIB_BIG_ENDIAN

#define x2h_16_cpy(to, from) if (from) eyedblib_mcp((to), (from), sizeof(eyedblib::int16))
#define x2h_32_cpy(to, from) if (from) eyedblib_mcp((to), (from), sizeof(eyedblib::int32))
#define x2h_64_cpy(to, from) if (from) eyedblib_mcp((to), (from), sizeof(eyedblib::int64))

#else

#define x2h_16_cpy(to, xfrom) \
{ \
  eyedblib::int16 sx; \
  const void *from = (xfrom); \
  if (!from) from = (to); \
  eyedblib_mcp(&sx, (from), sizeof(sx)); \
  sx = x2h_16(sx); \
  eyedblib_mcp(to, &sx, sizeof(sx)); \
}

#define x2h_32_cpy(to, xfrom) \
{ \
  eyedblib::int32 sx; \
  const void *from = (xfrom); \
  if (!from) from = (to); \
  eyedblib_mcp(&sx, (from), sizeof(sx)); \
  sx = x2h_32(sx); \
  eyedblib_mcp(to, &sx, sizeof(sx)); \
}

#define x2h_64_cpy(to, xfrom) \
{ \
  eyedblib::int64 sx; \
  const void *from = (xfrom); \
  if (!from) from = (to); \
  eyedblib_mcp(&sx, (from), sizeof(sx)); \
  sx = x2h_64(sx); \
  eyedblib_mcp(to, &sx, sizeof(sx)); \
}
#endif

#else

/* host to external functions (h2x) */
extern eyedblib::int16 h2x_16(eyedblib::int16);
extern eyedblib::uint16 h2x_u16(eyedblib::uint16);
extern eyedblib::int32 h2x_32(eyedblib::int32);
extern eyedblib::uint16 h2x_u32(eyedblib::uint32);
extern eyedblib::int64 h2x_64(eyedblib::int64);
extern eyedblib::uint16 h2x_u64(eyedblib::uint64);

/* external to host functions (x2h) */
extern eyedblib::int16 x2h_16(eyedblib::int16);
extern eyedblib::uint16 x2h_u16(eyedblib::uint16);
extern eyedblib::int32 x2h_32(eyedblib::int32);
extern eyedblib::uint16 x2h_u32(eyedblib::uint32);
extern eyedblib::int64 x2h_64(eyedblib::int64);
extern eyedblib::uint16 x2h_u64(eyedblib::uint64);

extern void h2x_16_cpy(void *to, const void *from);
extern void h2x_32_cpy(void *to, const void *from);
extern void h2x_64_cpy(void *to, const void *from);

extern void x2h_16_cpy(void *to, const void *from);
extern void x2h_32_cpy(void *to, const void *from);
extern void x2h_64_cpy(void *to, const void *from);

#endif

extern eyedblib::float32 h2x_f32(eyedblib::float32);
extern eyedblib::float64 h2x_f64(eyedblib::float64);

#define h2x_f h2x_f32
#define h2x_d h2x_f64

#define h2x_f32_cpy h2x_32_cpy
#define h2x_f64_cpy h2x_64_cpy

extern eyedblib::float32 x2h_f32(eyedblib::float32);
extern eyedblib::float64 x2h_f64(eyedblib::float64);

#define x2h_f x2h_f32
#define x2h_d x2h_f64

#define x2h_f32_cpy x2h_32_cpy
#define x2h_f64_cpy x2h_64_cpy

#define h2x_16_icp(addr) h2x_16_cpy(addr, 0)
#define h2x_32_icp(addr) h2x_32_cpy(addr, 0)
#define h2x_64_icp(addr) h2x_64_cpy(addr, 0)

#define x2h_16_icp(addr) x2h_16_cpy(addr, 0)
#define x2h_32_icp(addr) x2h_32_cpy(addr, 0)
#define x2h_64_icp(addr) x2h_64_cpy(addr, 0)

#define x2h_nop(x) (x)
#define h2x_nop(x) (x)

#endif
