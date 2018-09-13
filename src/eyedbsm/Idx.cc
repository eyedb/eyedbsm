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

#include <eyedblib/thread.h>
#include <eyedbsm/eyedbsm.h>
#include <eyedbsm/Idx.h>
#include <stdlib.h>
#include <eyedblib/xdr.h>
#include <eyedbsm/xdr.h>
#include <assert.h>

#include <iostream>
#include <eyedblib/log.h>
#include <eyedblib/machtypes.h>
#include <eyedblib/rpc_lib.h>
#include <eyedblib/m_mem.h>
#include "lib/m_mem_p.h"

#include <fstream>

namespace eyedbsm {

  Idx::Idx(Boolean _opened,
	   Boolean (*_precmp)(void const * p, void const * q,
			      KeyType const * type, int & r))
  {
    opened = _opened;
    precmp = _precmp;
  }

  Status
  Idx::make(DbHandle *dbh, const Oid &oid, Idx *&idx)
  {
    unsigned int idxtype;
    idx = 0;
    Status s = objectRead(dbh, 0, sizeof(unsigned int), &idxtype,
			  DefaultLock, 0, 0, &oid);
    if (s) return s;

    idxtype = x2h_u32(idxtype);

    if (idxtype == HashType) {
      idx = new HIdx(dbh, &oid);
      return Success;
    }

    if (idxtype == BTreeType) {
      idx = new BIdx(dbh, oid);
      return Success;
    }

    return statusMake(ERROR, "object %s is not a valid index [%x]",
		      getOidString(&oid), idxtype);
  }

  Status
  Idx::checkOpened() const
  {
    if (!opened)
      return statusMake(ERROR, "index %s is not opened",
			getOidString(&oid()));
    return Success;
  }

  Idx::Key::Key(int sz)
  {
    size = sz;
    key = (size ? m_malloc(size) : 0);
  }

  void Idx::Key::setKey(void *k, int sz, const KeyType &keyType)
  {
#if 1
    Boolean no_x2h;
    if (sz < 0) {no_x2h = True; sz = -sz;}
    else no_x2h = False;
#endif
    if (sz > size) {
      free(key);
      size = sz;
      key = m_malloc(sz);
      assert(key);
    }

#if 1
    if (no_x2h)
      memcpy(key, k, sz);
    else
#endif
      x2h(key, k, keyType, sz);
  }

  Idx::Key::~Key()
  {
    free(key);
  }

  unsigned int
  Idx::computeCount()
  {
    IdxCursor *curs;

    if (asHIdx())
      curs = new HIdxCursor(asHIdx(), 0, 0, False, False);
    else
      curs = new BIdxCursor(asBIdx(), 0, 0, False, False);

    unsigned int count = 0;

    for (;;)
      {
	Boolean found;
	Oid oid;
	curs->next(&found, &oid, 0);

	if (!found)
	  break;

	count++;
      }

    delete curs;
    return count;
  }

  using namespace std;

  static ofstream DEVNULL("/dev/null");

#define mkcmp(type, x2h) \
inline static int \
cmp(type const * p, type const * q, unsigned i, unsigned char bswap) \
{ \
	for (; i-- > 0; p++, q++) { \
		type _p, _q; \
		eyedblib_mcp(&_p, p, sizeof(_p)); \
		eyedblib_mcp(&_q, q, sizeof(_q)); \
		if (bswap & OP1_SWAP) _p = x2h(_p); \
		if (bswap & OP2_SWAP) _q = x2h(_q); \
		if (_p > _q) \
			return 1; \
		else if (_p < _q) \
			return -1; \
        } \
	return 0; \
}

  mkcmp(unsigned char, x2h_nop)
    mkcmp(signed char, x2h_nop)
    mkcmp(eyedblib::int16, x2h_16)
    mkcmp(eyedblib::uint16, x2h_u16)
    mkcmp(eyedblib::int32, x2h_32)
    mkcmp(eyedblib::uint32, x2h_u32)
    mkcmp(eyedblib::int64, x2h_64)
    mkcmp(eyedblib::uint64, x2h_u64)
    mkcmp(eyedblib::float32, x2h_f32)
    mkcmp(eyedblib::float64, x2h_f64)
    //mkcmp(Oid)
#undef mkcmp


    static inline void const *
  fpos_(void const * p, int offset)
  {
    return (char const *)p + offset;
  }

  static inline void *
  fpos_(void * p, int offset)
  {
    return (char *)p + offset;
  }

  //
  // Improvment?
  // is this switch really necessary !?
  // in fact, yes! Because comparison is not bit per bit comparison but a
  // typed comparison: 'x < y' has not the same implementation for float or int
  //

  static Boolean offset_cmp = getenv("EYEDBNOIDXOFF") ? True : False;

  int
  Idx::compare(void const * p, void const * q, KeyType const * type,
	       unsigned char bswap) const
  {
    // EV: added 13/12/01
    if (!offset_cmp && precmp) {
      int r;
      if (precmp(p, q, type, r))
	return r;
    }
    // end added

    p = fpos_(p, type->offset);
    q = fpos_(q, type->offset);

    switch (type->type)
      {
      case tChar:
	return memcmp(p, q, type->count);

      case tInt32:
	return cmp((eyedblib::int32 const *)p, (eyedblib::int32 const *)q, type->count, bswap);

      case tInt64:
	return cmp((eyedblib::int64 const *)p, (eyedblib::int64 const *)q, type->count, bswap);

      case tInt16:
	return cmp((eyedblib::int16 const *)p, (eyedblib::int16 const *)q, type->count, bswap);

      case tFloat32:
	return cmp((eyedblib::float32 const *)p, (eyedblib::float32 const *)q, type->count, bswap);

      case tFloat64:
	return cmp((eyedblib::float64 const *)p, (eyedblib::float64 const *)q, type->count, bswap);

      case tSignedChar:
	return cmp((signed char const *)p, (signed char const *)q, type->count, bswap);

      case tUnsignedChar:
	return cmp((unsigned char const *)p, (unsigned char const *)q, type->count, bswap);

      case tUnsignedInt16:
	return cmp((eyedblib::uint16 const *)p, (eyedblib::uint16 const *)q, type->count, bswap);

      case tUnsignedInt32:
	return cmp((eyedblib::uint32 const *)p, (eyedblib::uint32 const *)q, type->count, bswap);

      case tUnsignedInt64:
	return cmp((eyedblib::uint64 const *)p, (eyedblib::uint64 const *)q, type->count, bswap);

      case tOid:
	if (!bswap)
	  return memcmp(p, q, type->count * sizeof(Oid));
	else {
	  assert(type->count == 1);
	  Oid poid, qoid;
	  eyedblib_mcp(&poid, p, sizeof(poid));
	  eyedblib_mcp(&qoid, q, sizeof(qoid));
	  if (bswap & OP1_SWAP) x2h_oid(&poid, &poid);
	  if (bswap & OP2_SWAP) x2h_oid(&qoid, &qoid);
	  return memcmp(&poid, &qoid, sizeof(Oid));
	}

      case tString:
	return strncmp((char const *)p, (char const *)q, type->count);

      default:
	assert(0);
      }
    return 0;
  }

  void
  Idx::h2x(void *xkey, const void *hkey, const KeyType &type)
  {
    if (type.offset)
      memcpy((char *)xkey, (char *)hkey, type.offset);

    xkey = fpos_(xkey, type.offset);
    hkey = fpos_(hkey, type.offset);
    //printf("h2x(%s[%d])\n", typeString(type.type), type.count);

    switch (type.type)
      {
      case tInt32:
      case tFloat32:
      case tUnsignedInt32:
	h2x_32_cpy(xkey, hkey);
	break;

      case tInt64:
      case tFloat64:
      case tUnsignedInt64:
	h2x_64_cpy(xkey, hkey);
	break;

      case tInt16:
      case tUnsignedInt16:
	h2x_16_cpy(xkey, hkey);
	break;

      case tOid:
	{
	  Oid hoid;
	  memcpy(&hoid, hkey, sizeof(hoid));
	  h2x_oid((Oid *)xkey, &hoid); // 2nd arg need to be aligned !
	}
	break;

      default:
	printf("ERROR TYPE = %d\n", type.type);
	assert(0);
      }
  }

  void
  Idx::x2h(void *hkey, const void *xkey, const KeyType &type,
	   unsigned int size)
  {
    if (type.offset)
      memcpy((char *)hkey, (char *)xkey, type.offset);

    hkey = fpos_(hkey, type.offset);
    xkey = fpos_(xkey, type.offset);
    //printf("x2h(%s[%d])+%d\n", typeString(type.type), type.count, type.offset);

    Oid hoid;
    switch (type.type)
      {
      case tInt32:
      case tFloat32:
      case tUnsignedInt32:
	x2h_32_cpy(hkey, xkey);
	break;

      case tInt64:
      case tFloat64:
      case tUnsignedInt64:
	x2h_64_cpy(hkey, xkey);
	break;

      case tInt16:
      case tUnsignedInt16:
	x2h_16_cpy(hkey, xkey);
	break;

      case tOid:
	x2h_oid(&hoid, (const Oid *)xkey); // 1st arg need to be aligned !
	memcpy(hkey, &hoid, sizeof(hoid));
	break;

      default:
	memcpy(hkey, xkey, size - type.offset);
	break;
      }
  }

  const char *
  Idx::typeString(Type type)
  {
    switch (type) {
    case tChar:
      return "tChar";

    case tUnsignedChar:
      return "tUnsignedChar";

    case tSignedChar:
      return "tSignedChar";

    case tInt16:
      return "tInt16";

    case tUnsignedInt16:
      return "tUnsignedInt16";

    case tInt32:
      return "tInt32";

    case tUnsignedInt32:
      return "tUnsignedInt32";

    case tInt64:
      return "tInt64";

    case tUnsignedInt64:
      return "tUnsignedInt64";

    case tFloat32:
      return "tFloat32";

    case tFloat64:
      return "tFloat64";

    case tOid:
      return "tOid";

    case tString:
      return "tString";

    default:
      fprintf(stderr, "%s line %d: unknown index type %d\n", __FILE__, __LINE__, int(type));
      abort();
      return 0;
    }
  }

  size_t
  Idx::typeSize(Type type)
  {
    switch (type) {
    case tChar:
      return sizeof(char);

    case tUnsignedChar:
      return sizeof(unsigned char);

    case tSignedChar:
      return sizeof(signed char);

    case tInt16:
      return sizeof(eyedblib::int16);

    case tUnsignedInt16:
      return sizeof(eyedblib::uint16);

    case tInt32:
      return sizeof(eyedblib::int32);

    case tUnsignedInt32:
      return sizeof(eyedblib::uint32);

    case tInt64:
      return sizeof(eyedblib::int64);

    case tUnsignedInt64:
      return sizeof(eyedblib::uint64);

    case tFloat32:
      return sizeof(eyedblib::float32);

    case tFloat64:
      return sizeof(eyedblib::float64);

    case tOid:
      return sizeof(Oid);

    case tString:
      return sizeof(char);
      /*
	fprintf(stderr, "%s line %d: not yet supported string type in index\n", __FILE__, __LINE__);
	abort();
	return 0;
      */

    default:
      fprintf(stderr, "%s line %d: unknown index type %d\n", __FILE__, __LINE__, int(type));
      abort();
      return 0;
    }
  }

  void DataBuffer::setData(void *_data, unsigned int _datasz)
  {
    static const unsigned int INCRSZ = 512;
    datasz = _datasz;

    if (datasz > allocsz) {
      allocsz = datasz + INCRSZ;
      delete [] data;
      data = new unsigned char[allocsz];
    }

    memcpy(data, _data, datasz);
  }
}
