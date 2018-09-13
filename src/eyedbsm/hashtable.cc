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

#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

#include <eyedblib/iassert.h>
#include <eyedblib/machtypes.h>
#include <transaction.h>
#include <eyedbsm_p.h>
#include <hashtable.h>
#include <lock.h>

namespace eyedbsm {

HashTable *
HashTableCreate(XMHandle *xmh, int count)
{
  HashTable *ht;
  unsigned int size = HashTableSize(count);

  ht = (HashTable *)XMAlloc(xmh, size);

  if (!ht)
    return ht;

  memset(ht, 0, size);
#ifdef TRS_SECURE
  ht->magic = HT_MAGIC;
#endif
  ht->cnt = 0;
  ht->mask = count - 1;

#ifdef KEEP_ORDER
  ht->xfirst = ht->xlast = 0;
#endif
  return ht;
}

/* TRObject HashTable */
int
HashTableTRObjectInsert(XMHandle *xmh, HashTable *ht, TRObject *tro)
{
  XMOffset off;
  int key = tro->oid.getNX() & ht->mask;

#ifdef KEEP_ORDER
  XMOffset xlast = ht->xlast;
#endif
  XMOffset tro_off = XM_OFFSET(xmh, tro);

#ifdef TRS_SECURE
  ESM_ASSERT_ABORT(ht->magic == HT_MAGIC, 0, 0);
#endif
  off = ht->offs[key];

  if (off)
    {
      TRObject *tr = (TRObject *)XM_ADDR(xmh, off);
      tr->prev = tro_off;
    }

  tro->next = off;
  tro->prev = XM_NULLOFFSET;
  ht->offs[key] = XM_OFFSET(xmh, tro);

#ifdef KEEP_ORDER
  xlast = ht->xlast;
  ht->xlast = tro_off;
  tro->xprev = xlast;
  tro->xnext = 0;

  if (xlast)
    {
      TRObject *tr = (TRObject *)XM_ADDR(xmh, xlast);
      tr->xnext = tro_off;
    }

  if (!ht->xfirst)
    ht->xfirst = tro_off;
#endif

  return ++ht->cnt;
}

int
HashTableTRObjectSuppress(XMHandle *xmh, HashTable *ht, TRObject *tro)
{
  TRObject *next, *prev;
  XMOffset tro_off = XM_OFFSET(xmh, tro);

  next = (TRObject *)XM_ADDR(xmh, tro->next);
  prev = (TRObject *)XM_ADDR(xmh, tro->prev);

  if (next)
    next->prev = tro->prev;

  if (prev)
    prev->next = tro->next;
  else
    ht->offs[tro->oid.getNX() & ht->mask] = tro->next;

#ifdef KEEP_ORDER
  if (tro->xprev)
    {
      TRObject *tr = (TRObject *)XM_ADDR(xmh, tro->xprev);
      tr->xnext = tro->xnext;
    }

  if (tro->xnext)
    {
      TRObject *tr = (TRObject *)XM_ADDR(xmh, tro->xnext);
      tr->xprev = tro->xprev;
    }

  if (ht->xlast == tro_off)
    ht->xlast = tro->xprev;

  if (ht->xfirst == tro_off)
    ht->xfirst = tro->xnext;
#endif
  return --ht->cnt;
}

XMOffset
HashTableTRObjectLookup(XMHandle *xmh, HashTable *ht,
			   const Oid *oid)
{
  XMOffset tro_off;

  tro_off = ht->offs[oid->getNX() & ht->mask];

#ifdef TRS_SECURE
  ESM_ASSERT_ABORT(ht->magic == HT_MAGIC, 0, 0);
#endif
  while (tro_off)
    {
      TRObject *tro = (TRObject *)XM_ADDR(xmh, tro_off);

      if (!memcmp(&tro->oid, oid, sizeof(Oid)))
	return tro_off;

      tro_off = tro->next;
    }

  return XM_NULLOFFSET;
}

/* PObject HashTable */
int
HashTablePObjectInsert(XMHandle *xmh, HashTable *ht, PObject *po)
{
  XMOffset off;
  int key = po->oid.getNX() & ht->mask;

#ifdef TRS_SECURE
  ESM_ASSERT_ABORT(ht->magic == HT_MAGIC, 0, 0);
#endif
  off = ht->offs[key];

  if (off)
    {
      PObject *p = (PObject *)XM_ADDR(xmh, off);
      p->prev = XM_OFFSET(xmh, po);
    }

  po->next = off;
  po->prev = XM_NULLOFFSET;
  ht->offs[key] = XM_OFFSET(xmh, po);

  return ++ht->cnt;
}

int
HashTablePObjectSuppress(XMHandle *xmh, HashTable *ht, PObject *po)
{
  PObject *next, *prev;

  next = (PObject *)XM_ADDR(xmh, po->next);
  prev = (PObject *)XM_ADDR(xmh, po->prev);

  if (next)
    next->prev = po->prev;

  if (prev)
    prev->next = po->next;
  else
    ht->offs[po->oid.getNX() & ht->mask] = po->next;

  return --ht->cnt;
}

XMOffset
HashTablePObjectLookup(XMHandle *xmh, HashTable *ht,
			  const Oid *oid)
{
  XMOffset po_off;

#ifdef TRS_SECURE
  ESM_ASSERT_ABORT(ht->magic == HT_MAGIC, 0, 0);
#endif

  po_off = ht->offs[oid->getNX() & ht->mask];

  while (po_off)
    {
      PObject *po = (PObject *)XM_ADDR(xmh, po_off);

      if (!memcmp(&po->oid, oid, sizeof(Oid)))
	return po_off;

      po_off = po->next;
    }

  return XM_NULLOFFSET;
}
}
