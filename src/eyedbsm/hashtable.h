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


#include <eyedbsm/eyedbsm.h>
#include <transaction.h>

namespace eyedbsm {
struct HashTable {
#ifdef TRS_SECURE
  eyedblib::uint32 magic;
#endif
  unsigned int cnt;
  unsigned int mask;
#ifdef KEEP_ORDER
  XMOffset xfirst, xlast;
#endif
  XMOffset offs[1];
};

#define HashTableSize(COUNT) \
	(sizeof(HashTable) + ((COUNT)-1) * sizeof(XMOffset))

#ifdef TRS_SECURE
  static const unsigned int HT_MAGIC = 0xf78e8ef3;
#endif

HashTable *
HashTableMake(XMHandle *, int);

extern void
HashTableFree(XMHandle *, HashTable *);

extern HashTable *
  HashTableCreate(XMHandle *, int);

extern int
  HashTableTRObjectInsert(XMHandle *, HashTable *, TRObject *),
  HashTableTRObjectSuppress(XMHandle *, HashTable *, TRObject *),
  HashTablePObjectInsert(XMHandle *, HashTable *, PObject *),
  HashTablePObjectSuppress(XMHandle *, HashTable *, PObject *);

extern XMOffset
  HashTableTRObjectLookup(XMHandle *, HashTable *, const Oid *),
  HashTablePObjectLookup(XMHandle *, HashTable *, const Oid *);

}
