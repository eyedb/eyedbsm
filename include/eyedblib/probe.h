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

#ifndef _EYEDBLIB_PROBE_H
#define _EYEDBLIB_PROBE_H

#include <stdio.h>

typedef struct p_ProbeHandle p_ProbeHandle;

typedef enum {
  p_ProbeCHAIN   = 0x1,
  p_ProbeAVERAGE = 0x2,
  p_ProbeINFO    = 0x4,
  p_ProbeLOCS    = 0x8,
  p_ProbeMARKS   = 0x10,
  p_ProbeWHOLE   = p_ProbeCHAIN | p_ProbeAVERAGE | p_ProbeINFO |
    p_ProbeLOCS | p_ProbeMARKS
} p_ProbeProfileType;
    
enum {
  P_PROBE_FILE  = 64,
  P_PROBE_INFO  = 80,
  P_PROBE_PNAME = 128
};

typedef struct {
  char _not;
  int sm, em;
} p_ProbeProfileMark;

typedef struct {
  char _not;
  int line;
  const char *file;
} p_ProbeProfileLoc;

typedef struct {
  p_ProbeProfileType type;
  int c_marks;
  p_ProbeProfileMark *marks;
  int c_locs;
  p_ProbeProfileLoc *locs;
} p_ProbeProfileDesc;

extern p_ProbeHandle
  *p_probeInit(const char *pname);

extern void
  p_probeBegin(const char *pname),
  p_probeEnd(const char *file);

extern void
  p_probeRecord(p_ProbeHandle *ph, const char *file, int line,
		int mark, const char *info),
  p_probeProfile(p_ProbeHandle *ph, FILE *fd, p_ProbeProfileDesc *desc),
  p_probeSave(p_ProbeHandle *ph, const char *file),
  p_probeRestore(p_ProbeHandle **ph, const char *file);

extern int
  p_probeActiveSet(p_ProbeHandle *ph, int act);

extern p_ProbeHandle
  *p_probeGlobalSet(p_ProbeHandle *ph),
  *p_probeGlobalGet(void);

#ifdef P_NO_PROBE

#define p_probe(ph)
#define p_probeI(ph, i)
#define p_probeM(ph, m)
#define p_probeMI(ph, m, i)

#define p_probeX
#define p_probeXI(i)
#define p_probeXM(m)
#define p_probeXMI(m, i)

#else

#define p_probe(ph)         p_probeRecord(ph, __FILE__, __LINE__, 0, 0)
#define p_probeI(ph, i)     p_probeRecord(ph, __FILE__, __LINE__, 0, i)
#define p_probeM(ph, m)     p_probeRecord(ph, __FILE__, __LINE__, m, 0)
#define p_probeMI(ph, m, i) p_probeRecord(ph, __FILE__, __LINE__, m, i)

#define p_probeX            p_probeRecord(p_probeGlobalGet(), __FILE__,\
					  __LINE__, 0, 0)
#define p_probeXI(i)	    p_probeRecord(p_probeGlobalGet(), __FILE__,\
					  __LINE__, 0, i)
#define p_probeXM(m)        p_probeRecord(p_probeGlobalGet(), __FILE__,\
					  __LINE__, m, 0)
#define p_probeXMI(m, i)    p_probeRecord(p_probeGlobalGet(), __FILE__,\
					  __LINE__, m, i)
#endif

#endif
