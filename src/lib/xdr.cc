/* 
   EyeDB Object Database Management System
   Copyright (C) 1994-2018 SYSRA
   
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

#include <eyedbsmconfig.h>

#include <eyedblib/xdr.h>
#include <eyedblib/rpc_lib.h>

#ifndef XDR_MACROS
eyedblib::int16
h2x_16(eyedblib::int16 x)
{
  return htons(x);
}

eyedblib::uint16
h2x_u16(eyedblib::uint16 x)
{
  return (eyedblib::uint16)h2x_16((eyedblib::uint16)x);
}

eyedblib::int32
h2x_32(eyedblib::int32 x)
{
  return htonl(x);
}

eyedblib::uint16
h2x_u32(eyedblib::uint32 x)
{
  return (eyedblib::uint32)h2x_32((eyedblib::uint32)x);
}

eyedblib::int64
h2x_64(eyedblib::int64 x)
{
#ifdef EYEDBLIB_BIG_ENDIAN
#error __FILE__ __LINE__ EYEDBLIB_BIG_ENDIAN is defined
  return x;
#else
  return ((unsigned long long)htonl(l)) << 32 | htonl((x >> 32) & 0xffffffff);
#endif
}

eyedblib::uint16
h2x_u64(eyedblib::uint64 x)
{
  return (eyedblib::uint64)h2x_64((eyedblib::uint64)x);
}

eyedblib::int16
x2h_16(eyedblib::int16 x)
{
  return ntohs(x);
}

eyedblib::uint16
x2h_u16(eyedblib::uint16 x)
{
  return (eyedblib::uint16)x2h_16((eyedblib::uint16)x);
}

eyedblib::int32
x2h_32(eyedblib::int32 x)
{
  return ntohl(x);
}

eyedblib::uint16
x2h_u32(eyedblib::uint32 x)
{
  return (eyedblib::uint32)x2h_32((eyedblib::uint32)x);
}

eyedblib::int64
x2h_64(eyedblib::int64 x)
{
#ifdef EYEDBLIB_BIG_ENDIAN
#error __FILE__ __LINE__ EYEDBLIB_BIG_ENDIAN is defined
  return x;
#else
  return ((unsigned long long)ntohl(l)) << 32 | ntohl((x >> 32) & 0xffffffff);
#endif
}

eyedblib::uint16
x2h_u64(eyedblib::uint64 x)
{
  return (eyedblib::uint64)x2h_64((eyedblib::uint64)x);
}


#endif

eyedblib::float32
h2x_f32(eyedblib::float32 x)
{
  eyedblib::int32 ix;
  eyedblib_mcp(&ix, &x, sizeof(ix));
  ix = h2x_32(ix);
  eyedblib_mcp(&x, &ix, sizeof(ix));
  return x;
}

eyedblib::float64
h2x_f64(eyedblib::float64 x)
{
  eyedblib::int64 ix;
  eyedblib_mcp(&ix, &x, sizeof(ix));
  ix = h2x_64(ix);
  eyedblib_mcp(&x, &ix, sizeof(ix));
  return x;
}

eyedblib::float32
x2h_f32(eyedblib::float32 x)
{
  eyedblib::int32 ix;
  eyedblib_mcp(&ix, &x, sizeof(ix));
  ix = x2h_32(ix);
  eyedblib_mcp(&x, &ix, sizeof(ix));
  return x;
}

eyedblib::float64
x2h_f64(eyedblib::float64 x)
{
  eyedblib::int64 ix;
  eyedblib_mcp(&ix, &x, sizeof(ix));
  ix = x2h_64(ix);
  eyedblib_mcp(&x, &ix, sizeof(ix));
  return x;
}

#ifndef XDR_MACROS
/* h2x_cpy functions */
void
h2x_16_cpy(void *to, const void *from)
{
#ifdef EYEDBLIB_BIG_ENDIAN
#error __FILE__ __LINE__ EYEDBLIB_BIG_ENDIAN is defined
  if (from)
    eyedblib_mcp(to, from, sizeof(eyedblib::int16));
#else
  eyedblib::int16 sx;
  if (!from) from = to;
  eyedblib_mcp(&sx, from, sizeof(sx));
  sx = h2x_16(sx);
  eyedblib_mcp(to, &sx, sizeof(sx));
#endif
}

void
h2x_32_cpy(void *to, const void *from)
{
#ifdef EYEDBLIB_BIG_ENDIAN
#error __FILE__ __LINE__ EYEDBLIB_BIG_ENDIAN is defined
  if (from)
    eyedblib_mcp(to, from, sizeof(eyedblib::int32));
#else
  eyedblib::int32 sx;
  if (!from) from = to;
  eyedblib_mcp(&sx, from, sizeof(sx));
  sx = h2x_32(sx);
  eyedblib_mcp(to, &sx, sizeof(sx));
#endif
}

void
h2x_64_cpy(void *to, const void *from)
{
#ifdef EYEDBLIB_BIG_ENDIAN
#error __FILE__ __LINE__ EYEDBLIB_BIG_ENDIAN is defined
  if (from)
    eyedblib_mcp(to, from, sizeof(eyedblib::int64));
#else
  eyedblib::int64 sx;
  if (!from) from = to;
  eyedblib_mcp(&sx, from, sizeof(sx));
  sx = h2x_64(sx);
  eyedblib_mcp(to, &sx, sizeof(sx));
#endif
}

/* x2h_cpy functions */
void
x2h_16_cpy(void *to, const void *from)
{
#ifdef EYEDBLIB_BIG_ENDIAN
#error __FILE__ __LINE__ EYEDBLIB_BIG_ENDIAN is defined
  if (from)
    eyedblib_mcp(to, from, sizeof(eyedblib::int16));
#else
  eyedblib::int16 sx;
  if (!from) from = to;
  eyedblib_mcp(&sx, from, sizeof(sx));
  sx = x2h_16(sx);
  eyedblib_mcp(to, &sx, sizeof(sx));
#endif
}

void
x2h_32_cpy(void *to, const void *from)
{
#ifdef EYEDBLIB_BIG_ENDIAN
#error __FILE__ __LINE__ EYEDBLIB_BIG_ENDIAN is defined
  if (from)
    eyedblib_mcp(to, from, sizeof(eyedblib::int32));
#else
  eyedblib::int32 sx;
  if (!from) from = to;
  eyedblib_mcp(&sx, from, sizeof(sx));
  sx = x2h_32(sx);
  eyedblib_mcp(to, &sx, sizeof(sx));
#endif
}

void
x2h_64_cpy(void *to, const void *from)
{
#ifdef EYEDBLIB_BIG_ENDIAN
#error __FILE__ __LINE__ EYEDBLIB_BIG_ENDIAN is defined
  if (from)
    eyedblib_mcp(to, from, sizeof(eyedblib::int64));
#else
  eyedblib::int64 sx;
  if (!from) from = to;
  eyedblib_mcp(&sx, from, sizeof(sx));
  sx = x2h_64(sx);
  eyedblib_mcp(to, &sx, sizeof(sx));
#endif
}
#endif

#ifdef INTERNAL_XDR

/*#define NEUTRAL_XDR*/

#ifndef NEUTRAL_XDR
typedef struct {
  char x[4];
} x32;
#endif

unsigned int htonl(unsigned int hostlong)
{
#ifndef NEUTRAL_XDR
  x32 *x = (x32 *)&hostlong;
  char c = x->x[0];
  x->x[0] = x->x[3];
  x->x[3] = c;
  c = x->x[1];
  x->x[1] = x->x[2];
  x->x[2] = c;
  memcpy(&hostlong, x, sizeof(hostlong));
#endif
  return hostlong;
}

unsigned short
int htons(unsigned short int hostshort)
{
  return hostshort;
}

unsigned 
int ntohl(unsigned int netlong)
{
  return htonl(netlong);
}

unsigned short
int ntohs(unsigned short int netshort)
{
  return netshort;
}
#endif
