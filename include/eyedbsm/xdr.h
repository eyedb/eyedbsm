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


#ifndef _EYEDBSM_XDR_H
#define _EYEDBSM_XDR_H

#include <eyedblib/xdr.h>

#define SEXDR

namespace eyedbsm {

#ifdef SEXDR
extern void x2h_oid(Oid *hoid, const void *xoid);
extern void h2x_oid(void *xoid, const Oid *hoid);

extern void x2h_oids(Oid *hoid, const void *xoid, unsigned int cnt);
extern void h2x_oids(void *xoid, const Oid *hoid, unsigned int cnt);

extern int cmp_oid(const void *xoid, const Oid *hoid);

extern int cmp_oids(const void *xoid, const Oid *hoid,
		       unsigned int cnt);
#endif

}

#endif
