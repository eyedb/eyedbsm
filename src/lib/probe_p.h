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

#include <eyedblib/probe.h>
#include <time.h>
#include <sys/time.h>
#include <sys/times.h>

typedef struct p_Reg p_Reg;

struct p_Reg {
  const char *f1, *f2;
  int l1, l2;
  p_Reg *next;
};

typedef struct p_Probe p_Probe;

struct p_Probe {
  char file[P_PROBE_FILE];
  int line;
  char info[P_PROBE_INFO];
  int mark;
  struct tms cpu;
  struct timeval tp;
  int i;
  p_Probe *next, *pf_next;
};

struct p_ProbeHandle {
  char pname[P_PROBE_PNAME];
  p_Probe *p_head, *p_last, *pf_head;
  time_t it, st;
  int act, i;
  p_Reg *r_head;
};
