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


#ifndef _EYEDBLIB_UTLOG_H
#define _EYEDBLIB_UTLOG_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" 
{
#endif

extern void utlogInit(const char *progName, const char *devname);
extern FILE *utlogFDGet();
extern FILE *utlogFDSet(FILE *);
extern void utlog(const char *fmt, ...);
extern void utlog_p(const char *s);
extern const char *utlogDevNameGet();
extern void
  utlogResetTimer(),
  utlogSetLogDate(int on),
  utlogSetLogTimer(int on),
  utlogSetLogPid(int on),
  utlogSetLogProgName(int on);

#ifdef __cplusplus
}
#endif

#endif
