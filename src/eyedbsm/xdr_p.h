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


#ifndef _EYEDBSM_XDR_P_H
#define _EYEDBSM_XDR_P_H

#include <xdr_off.h>
#include <eyedbsm/xdr.h>

namespace eyedbsm {

  extern void x2h_oidloc(OidLoc *oidloc, const void *addr);
  extern void h2x_oidloc(void *addr, OidLoc *oidloc);

  extern unsigned int x2h_getSize_v2(unsigned int);
  extern unsigned int x2h_makeValid_v2(unsigned int size);

  extern size_t x2h_getSize_v3(size_t);
  extern size_t x2h_makeValid_v3(size_t size);

  extern void x2h_mapHeader(MapHeader *hmap, const MapHeader *xmap);
  extern void h2x_mapHeader(MapHeader *xmap, const MapHeader *hmap);

  extern void x2h_dbHeader(DbHeader *hdbh, const DbHeader *xdbh);
  extern void h2x_dbHeader(DbHeader *xdbh, const DbHeader *hdbh);

  extern void x2h_protoids(Oid *prot_lock_oid, Oid *prot_list_oid,
			   Oid *prot_uid_oid, DbHeader *dbh);

  extern void h2x_protoids(Oid *prot_lock_oid, Oid *prot_list_oid,
			   Oid *prot_uid_oid, DbHeader *dbh);

#define x2h_prologue(XMP, MP) \
  unsigned char buf[MapHeader_SIZE + 8]; \
  POINTER_INT_TYPE buf_off_8 = reinterpret_cast<POINTER_INT_TYPE>(&buf) & 0x7; \
  unsigned char *buf_align_8 = (buf_off_8) ? buf - buf_off_8 + 0x8 : buf; \
  MapHeader _tmp_(buf_align_8), *MP = &_tmp_; \
  x2h_mapHeader(MP, XMP)

#define h2x_epilogue(XMP, MP) \
  h2x_mapHeader(XMP, MP)
}

#endif
