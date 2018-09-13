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

//#define CACHE_FOR_LOCK

//#define TRUSS1_GC
//#define TRUSS2_GC
#define OPT_FREELIST

#include <eyedbsm/eyedbsm.h>
#include <eyedbsm/HIdx.h>
#include "IdxP.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <eyedblib/rpc_lib.h>
#include <eyedblib/performer.h>
#include <eyedblib/strutils.h>
#include <eyedbsm/xdr.h>
#include <eyedblib/log.h>
#include <eyedblib/m_mem.h>
#include "lib/m_mem_p.h"

#include <map>
#include <vector>

namespace eyedbsm {
  class MapHeader;
  class DbHeader;
  class DatafileDesc;
  class DataspaceDesc;

#define OPTIM_LARGE_OBJECTS

#define DATASZ_SIZE 4

#define NEW_WAIT
//#define MULTI_LIST

//#define TRACK_MAP
//#define TRACK_MAP_2

#define HIDX_XDR
#define HIDX_XDR_OID
#define HIDX_XDR_OVERHEAD

#define NO_EXTEND

#define NullOffset (-1)

//#define TRACE_HIDX
//#define ESM_HIDX_REGISTER

#define VARSZ_DATACNT

#define NEW_HASH_KEY
#define NEW_HASH_KEY_VERSION 206004

#define STRTYPE(IDX) \
    ((IDX)->hidx.keytype == Idx::tString)

#define IDXSZ(V) (sizeof(HIdx::_Idx))

  extern Boolean backend_interrupt;

#define data_group_sz(I, THIS) \
 (THIS)->data_grouped_sizeof + (I) * (THIS)->hidx.datasz

static void
dump_keytype(const char *msg, const Idx::KeyType &keytype,
	     const HIdx::_Idx &hidx)
{
  printf("%s:\n"
	 "    type=%s count=%d offset=%d\n", msg,
	 Idx::typeString(keytype.type), keytype.count, keytype.offset);
  printf("    hidx.keytype=%s hidx.keysz=%d hidx.offset=%d\n",
	 Idx::typeString((Idx::Type)hidx.keytype), hidx.keysz, hidx.offset);
}

static void cmp_offset(unsigned long off, const char *str)
{
  printf("SAME OFFSET %s: %d\n", str, off);
}

#define mcp(D, S, N) \
do { \
  int __n__ = (N); \
  char *__d__ = (char *)(D), *__s__ = (char *)(S); \
  while(__n__--) \
    *__d__++ = *__s__++; \
} while(0)

#define mset(D, V, N) \
do { \
  int __n__ = (N); \
  char *__d__ = (char *)(D); \
  while(__n__--) \
    *__d__++ = V; \
} while(0)

static void x2h_idx(HIdx::_Idx *idx);
static void h2x_idx(HIdx::_Idx *idx, const HIdx::_Idx *);
static void x2h_chd(HIdx::CListHeader *);
static void h2x_chd(HIdx::CListHeader *, const HIdx::CListHeader *);
static void x2h_header(HIdx::CListObjHeader *);
static void h2x_header(HIdx::CListObjHeader *, const HIdx::CListObjHeader *);
static void x2h_overhead(HIdx::CellHeader *);
static void h2x_overhead(HIdx::CellHeader *, const HIdx::CellHeader *);

#define KEY_OFF (3)

#define OFFSET(T, X) (unsigned long)(&((T *)0)->X)

const char HIdxCursor::defaultSKey[] = "";

#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))

static const int IniSize_Default = 4096;
//static const int IniObjCnt_Default = 256;

static const unsigned int SmallThreshold_Default = 4;

static const unsigned int IniSizeSmall_Default = 256;
static const unsigned int IniObjCntSmall_Default = 8;

static const int XCoef_Default = 1;

static int
get_iniobjcnt_def(const HIdx::_Idx &hidx)
{
  if (hidx.keysz == HIdx::VarSize)
    return 0;

  return hidx.key_count <= SmallThreshold_Default ? IniObjCntSmall_Default :
    (hidx.mag_order+1) / hidx.key_count;
}

static int
get_inisize_small_def(const HIdx::_Idx &hidx)
{
  assert(hidx.key_count <= SmallThreshold_Default);

  if (hidx.keysz != HIdx::VarSize) {
    assert(hidx.impl_hints[HIdx::IniObjCnt_Hints]);
    return (sizeof(HIdx::CellHeader) + hidx.keysz + hidx.datasz) * 
      hidx.impl_hints[HIdx::IniObjCnt_Hints];
    // - sizeof(HIdx::CellHeader); necessary ?
  }

  return IniSizeSmall_Default;
}

static int
get_inisize_def(const HIdx::_Idx &hidx)
{
  if (hidx.key_count <= SmallThreshold_Default)
    return get_inisize_small_def(hidx);

  if (hidx.keysz != HIdx::VarSize) {
    assert(hidx.impl_hints[HIdx::IniObjCnt_Hints]);
    return (sizeof(HIdx::CellHeader) + hidx.keysz + hidx.datasz) * 
      hidx.impl_hints[HIdx::IniObjCnt_Hints];
    // - sizeof(HIdx::CellHeader); necessary ?
  }

  return IniSize_Default;
}

static int
get_xcoef_def(const HIdx::_Idx &)
{
  return XCoef_Default;
}

static int
get_sizemax_def(const HIdx::_Idx &hidx)
{
  assert(hidx.impl_hints[HIdx::XCoef_Hints] &&
	 hidx.impl_hints[HIdx::IniSize_Hints]);
	 
  int xcoef = hidx.impl_hints[HIdx::XCoef_Hints];
  return xcoef * xcoef * hidx.impl_hints[HIdx::IniSize_Hints];
}

static unsigned int
key_offset(int x)
{
  return x + KEY_OFF;
}

//#define IDX_DBG

Boolean trace_idx;
FILE *trace_idx_fd = stdout;
Boolean trace_idx_sync;

/*extern "C" */ unsigned int getDbVersion(void *);
/*extern "C" */ Boolean isWholeMapped(void *);

static Boolean
isPower2(int x)
{
  int n = 0;
  while(x) {
      if ((x & 1) && ++n > 1)
	return False;

      x >>= 1;
    }

  return True;
}

const unsigned int HIdx::MaxKeys = 0x800000;
const unsigned int HIdx::VarSize = 0xffffffff;
const unsigned int HIdx::MagorderKeycountCoef = 64;

#define get_gkey(V) key_offset

unsigned int
computeKeyCount(unsigned int key_count, int &mag_order,
		unsigned int maxkeys, Boolean &pow2)
{
  if (key_count) {
    key_count = (key_count > maxkeys ? maxkeys : key_count);
    pow2 = isPower2(key_count);
  }
  else {
    unsigned int ncells = (mag_order/HIdx::MagorderKeycountCoef)+1;
    if (ncells >= maxkeys-1)
      key_count = maxkeys;
    else {
      key_count = 1;
      
      for (;;) {
	if (key_count >= ncells)
	  break;
	key_count <<= 1;
      }

      pow2 = True;
    }
  }

  mag_order = key_count * HIdx::MagorderKeycountCoef-1;
  return key_count;
}

static unsigned int
get_keyTypeCount(const HIdx::_Idx &hidx)
{
  if (hidx.keysz == HIdx::VarSize)
    return HIdx::VarSize; // changed the 29/01/02: was return 0

  unsigned tsz = Idx::typeSize((Idx::Type)hidx.keytype);
  unsigned int count = (hidx.keysz - hidx.offset) / tsz;
  assert(count * tsz == (hidx.keysz - hidx.offset));

  return count;
}

//#define FORCE_COPY

static Boolean _isUExtend(const HIdx::_Idx &hidx)
{
  return (hidx.impl_hints[HIdx::XCoef_Hints] > 1) ? True : False;
}

static Boolean _isDataGroupedByKey(const HIdx::_Idx &hidx)
{
  return (hidx.impl_hints[HIdx::DataGroupedByKey_Hints] != 0) ? True : False;
}

static unsigned int _dataGroupedByKeySize(const HIdx::_Idx &hidx)
{
  return (unsigned int)hidx.impl_hints[HIdx::DataGroupedByKey_Hints];
}

void
HIdx::init(DbHandle *_dbh, unsigned int _keytype,
	      unsigned int keysz, unsigned int offset,
	      unsigned int datasz, short _dspid, int mag_order,
	      int key_count,
	      const int *impl_hints,
	      unsigned int impl_hints_cnt)
{
  dbh = _dbh;
  version = getDbVersion(dbh);
#ifdef FORCE_COPY
  nocopy = False;
#else
  nocopy = isWholeMapped(dbh);
#endif
  memset(&hidx, 0, sizeof(hidx));

  hidx.key_count = computeKeyCount(key_count, mag_order, MaxKeys, pow2);

  hidx.idxtype = HashType;
  hidx.mag_order = mag_order;
  hidx.object_count = 0;
  hidx.dspid = _dspid;
  hidx.keytype = _keytype;

  hidx.keysz = keysz;
  hidx.datasz = datasz;
  hidx.offset = offset;

  memset(&treeoid, 0, sizeof(treeoid));
#ifdef NEW_HASH_TRACE
  keytype.type = (Type)hidx.keytype;
  keytype.count = get_keyTypeCount(hidx);
  dump_keytype("creating hash index", keytype, hidx);;
#endif

  hash_data = 0;
  hash_key = 0;
#ifdef NEW_HASH_KEY
  set_hash_key();
#endif

  if (impl_hints)
    memcpy(hidx.impl_hints, impl_hints, impl_hints_cnt*sizeof(impl_hints[0]));

  if (hidx.keysz == HIdx::VarSize)
    hidx.impl_hints[IniObjCnt_Hints] = 0; // ignored
  else if (!hidx.impl_hints[IniObjCnt_Hints])
    hidx.impl_hints[IniObjCnt_Hints] = get_iniobjcnt_def(hidx);

  if (!hidx.impl_hints[IniSize_Hints])
    hidx.impl_hints[IniSize_Hints] = get_inisize_def(hidx);

  if (!hidx.impl_hints[XCoef_Hints])
    hidx.impl_hints[XCoef_Hints] = get_xcoef_def(hidx);

  if (!hidx.impl_hints[SzMax_Hints])
    hidx.impl_hints[SzMax_Hints] = get_sizemax_def(hidx);

  if (_isDataGroupedByKey(hidx) && isDataVarSize()) {
    stat = statusMake(NOT_YET_IMPLEMENTED, "data_grouped_by_key hash indexes does not yet support variable size data");
    return;
  }

  mask = hidx.key_count - 1;
  unsigned int (*gkey)(int) = get_gkey(version);

  int len = gkey(hidx.key_count);
  IDB_LOG(IDB_LOG_IDX_CREATE,
	  ("Creating Hash Index: magorder=%u, entries=%u "
	   "keysz=%u, datasz=%u, "
	   "size=%u [%d objects of size %u + 1 object of size %u]\n",
	   hidx.mag_order,
	   hidx.key_count,
	   hidx.keysz,
	   hidx.datasz,
	   sizeof(CListHeader)*hidx.key_count+len*sizeof(Oid),
	   hidx.key_count,
	   sizeof(CListHeader),
	   len*sizeof(Oid)));

  CListHeader *chds;
  chds = new CListHeader[len];

  memset(chds, 0, sizeof(CListHeader) * len);
  _Idx xidx;
  h2x_idx(&xidx, &hidx);
  mcp(chds, &xidx, sizeof(xidx));
  assert(sizeof(xidx) <= KEY_OFF * sizeof(CListHeader));

  bsize = hidx.impl_hints[IniSize_Hints];

  /*
    printf("creating index header size=%d, magorder=%d\n", sizeof(Oid) * len,
    hidx.mag_order);
  */
#ifdef TRACE_HIDX
  printf("creating index %d\n",  sizeof(Oid) * len);
#endif

  CListHeader *tchds = new CListHeader[len];
  memcpy(tchds, chds, sizeof(CListHeader) * KEY_OFF);
  for (int i = KEY_OFF; i < len; i++)
    h2x_chd(&tchds[i], &chds[i]);
  stat = objectCreate(dbh, tchds, sizeof(CListHeader) * len, hidx.dspid,
			 &treeoid);
  delete [] tchds;

  if (!stat)
    IDB_LOG(IDB_LOG_IDX_CREATE,
	    ("Have Created Hash Index: treeoid=%s\n",
	     getOidString(&treeoid)));
  delete [] chds;
  uextend = _isUExtend(hidx);
  data_grouped_by_key = _isDataGroupedByKey(hidx);
  data_grouped_sizeof = _dataGroupedByKeySize(hidx);
}

HIdx::HIdx(DbHandle *_dbh, KeyType _keytype,
	   unsigned int datasz, short _dspid,
	   int _mag_order, int key_count,
	   const int *impl_hints,
	   unsigned int impl_hints_cnt)
  : Idx(False)
{
  keytype = _keytype;
  init(_dbh, (unsigned int)keytype.type,
       ((unsigned int)keytype.count == VarSize ? VarSize :
	(typeSize(keytype.type) * keytype.count) + keytype.offset),
       keytype.offset,
       datasz, _dspid, _mag_order, key_count,
       impl_hints, impl_hints_cnt);
}

unsigned int
HIdx::getMagOrder(unsigned int keycount)
{
  return keycount * HIdx::MagorderKeycountCoef;
}

unsigned int
HIdx::getKeyCount(unsigned int magorder)
{
  unsigned int keycount = magorder / MagorderKeycountCoef;

  if (keycount >= MaxKeys)
    return MaxKeys;

  return keycount ? keycount : 1;
}

HIdx::HIdx(DbHandle *_dbh, const Oid *_oid,
		 hash_key_t _hash_key,
		 void *_hash_data,
		 Boolean (*precmp)(void const * p, void const * q,
				      KeyType const * type, int & r))
  : Idx(True, precmp), dbh(_dbh)
{
  version = getDbVersion(_dbh);
  stat = objectRead(dbh, 0, IDXSZ(version), &hidx, DefaultLock, 0, 0, _oid);

  /*
    printf("version = %d %d [%d vs. %d] status %d\n",
    version, IDXSZ(version), sizeof(HIdx::_Idx),
    sizeof(OIdx), stat);
  */
    
  if (stat)
    return;

#ifdef FORCE_COPY
  nocopy = False;
#else
  nocopy = isWholeMapped(dbh);
#endif
  x2h_idx(&hidx);

  keytype.type = (Type)hidx.keytype;
  keytype.count = get_keyTypeCount(hidx);

  hash_key = _hash_key;
  hash_data = _hash_data;
  treeoid = *_oid;

#ifdef NEW_HASH_KEY
  set_hash_key();
#endif

  keytype.offset = hidx.offset;

  //dump_keytype("Idx::HIdx", keytype, hidx);;

  //unsigned int (*gkey)(int) = get_gkey(version);
  //int len = gkey(hidx.key_count);
  mask = hidx.key_count - 1;
  pow2 = isPower2(hidx.key_count);
  bsize = hidx.impl_hints[IniSize_Hints];
  uextend = _isUExtend(hidx);
  data_grouped_by_key = _isDataGroupedByKey(hidx);
  data_grouped_sizeof = _dataGroupedByKeySize(hidx);
}

#ifdef NEW_HASH_KEY

//  mcp(&t, (unsigned char *)(key)+((HIdx::_Idx *)xhidx)->offset, sizeof(T));

#define MK_DEF_HASH_KEY(T, F) \
Status \
HIdx::F(const void *key, unsigned int len, void *xhidx, unsigned int &x) \
{ \
  T t; \
  mcp(&t, (unsigned char *)key, sizeof(T)); \
  x = (int)t; \
  return Success; \
}

Status
HIdx::get_def_oiddata_hash_key(const void *key, unsigned int len,
				  void *xhidx, unsigned int &x)
{
  Oid oid;
  mcp(&oid, (unsigned char *)(key), sizeof(oid));
  x = oid.getNX();
  return Success;
}

MK_DEF_HASH_KEY(eyedblib::int16, get_def_int16data_hash_key);
MK_DEF_HASH_KEY(eyedblib::int32, get_def_int32data_hash_key);
MK_DEF_HASH_KEY(eyedblib::int64, get_def_int64data_hash_key);
MK_DEF_HASH_KEY(eyedblib::float32, get_def_float32data_hash_key);
MK_DEF_HASH_KEY(eyedblib::float64, get_def_float64data_hash_key);

void
HIdx::set_hash_key()
{
#ifdef NEW_HASH_TRACE
  printf("hash_key for index %s [hash_key=%p]\n",
	 getOidString(&treeoid), hash_key);
  dump_keytype("hash_key : ", keytype, hidx);;
#endif
  if (hash_key) return;

  hash_data = 0;
  /*
  if (hidx.keytype == tString) {
    hash_key = get_def_string_hash_key;
    return;
  }
  */

  if (version >= NEW_HASH_KEY_VERSION) {
    hash_data = &hidx;

    switch(hidx.keytype) {
    case tString:
      hash_key = get_def_nstring_hash_key;
      return;

    case tInt16:
    case tUnsignedInt16:
      hash_key = get_def_int16data_hash_key;
      return;

    case tInt32:
    case tUnsignedInt32:
      hash_key = get_def_int32data_hash_key;
      return;

    case tInt64:
    case tUnsignedInt64:
      hash_key = get_def_int64data_hash_key;
      return;

    case tOid:
      hash_key = get_def_oiddata_hash_key;
      return;

    case tFloat32:
      hash_key = get_def_float32data_hash_key;
      return;

    case tFloat64:
      hash_key = get_def_float64data_hash_key;
      return;
    }

    hash_data = 0;
  }

  if (hidx.keytype == tString) {
    hash_key = get_def_string_hash_key;
    return;
  }

  hash_key = get_def_rawdata_hash_key;
}
#endif

void
HIdx::open(hash_key_t _hash_key,
	      void *_hash_data,
	      Boolean (*_precmp)(void const * p, void const * q,
				    KeyType const * type, int & r))
{
  keytype.type = (Type)hidx.keytype;
  keytype.count = get_keyTypeCount(hidx);
  keytype.offset = hidx.offset;

  hash_key = _hash_key;
  hash_data = _hash_data;
#ifdef NEW_HASH_KEY
  set_hash_key();
  assert(hash_key);
#endif
  precmp = _precmp;
  opened = True;
}

HIdx::~HIdx()
{
  flush_cache(false);
}

Boolean trace_it;

#define first_char ' '
#define last_char  '~'
#define asc(x) ((unsigned int)((x) - first_char))
#define asc_len ((unsigned int)(last_char - first_char + 1))

#define NEW_HASH_KEY2

Status
HIdx::get_def_string_hash_key(const void *key, unsigned int len, void *, unsigned int &x)
{
#ifdef NEW_HASH_KEY2
  unsigned char *k = (unsigned char *)key;
  x = 1;
  for (unsigned int i = 0; i < len; i++) {
    x *= *k++;
    x ^= x >> 8;
  }
#else
  x = 0;
  char *k = (char *)key;
  for (unsigned int i = 0; i < len; i++)
    x += *k++ * (i+1); //x += *k++;

#endif
  return Success;
}

Status
HIdx::get_def_nstring_hash_key(const void *key, unsigned int len, void *, unsigned int &x)
{
  unsigned char *k = (unsigned char *)key;
  if (len > 12)
    len = 12;
#ifdef NEW_HASH_KEY2
  x = 1;
  for (unsigned int i = 0; i < len; i++) {
    x *= *k++;
    x ^= x >> 8;
  }
#else
  int coef = 1;
  eyedblib::int64 r = 0;
  for (unsigned int n = 0; n < len; n++, k++) {
    r += coef * asc(*k);
    coef *= asc_len;
  }

  x = r;
#endif
  return Success;
}

Status
HIdx::get_string_hash_key(const void *key, unsigned int len, unsigned int &x) const
{
#ifdef NEW_HASH_KEY
  assert(hash_key);
#endif
  if (hash_key)
    return hash_key(key, len, hash_data, x);

  abort();
  return get_def_string_hash_key(key, len, 0, x);
}

Status
HIdx::get_def_rawdata_hash_key(const void *key, unsigned int len, void *, unsigned int &x)
{
  x = 0;
  unsigned char *k = (unsigned char *)key;
  for (unsigned int i = 0; i < len; i++)
    x += *k++;

  return Success;
}

Status
HIdx::get_rawdata_hash_key(const void *key, unsigned int len, unsigned int &x) const
{
#ifdef NEW_HASH_KEY
  assert(hash_key);
#endif
  if (hash_key)
    return hash_key(key, len, hash_data, x);

  return get_def_rawdata_hash_key(key, len, 0, x);
}

static inline void const *
fpos_(void const * p, int offset)
{
  return (char const *)p + offset;
}

inline Status HIdx::get_key(unsigned int &n, const void *key, unsigned int *size) const
{
  key = fpos_(key, keytype.offset);
  Status s;
  unsigned int x;

  unsigned int datasz = (isDataVarSize() ? 0 : hidx.datasz);

  if (STRTYPE(this)) {
    int len = strlen((char *)key);
    s = get_string_hash_key(key, len, x);
    if (s)
      return s;
    
    if (size) {
      if (hidx.keysz == VarSize) {
	*size = datasz + len + 1;
      }
      else {
	*size = datasz + hidx.keysz;
      }
    }
    
    n = (pow2 ? (x & mask) : (x % mask));
    return Success;
  }

  s = get_rawdata_hash_key(key, hidx.keysz - keytype.offset, x);
  if (s)
    return s;

  if (size) {
    *size = datasz + hidx.keysz;
  }
  
  n = (pow2 ? (x & mask) : (x % mask));
  return Success;
}

Status
HIdx::suppressObjectFromFreeList(CListHeader &chd, unsigned int chd_k, CListObjHeader &h,
				    const Oid &koid)
{
#ifdef TRACK_MAP
  printf("suppressObjectFromFreeList(%s)\n", getOidString(&koid));
#endif  
  Status s;

  if (h.clobj_free_prev.getNX()) {
    Oid xoid;
    h2x_oid(&xoid, &h.clobj_free_next);
    s = objectWrite(dbh, OFFSET(CListObjHeader, clobj_free_next), sizeof(Oid),
		       &xoid, &h.clobj_free_prev);
    if (s)
      return s;
  }
  
  if (h.clobj_free_next.getNX()) {
    Oid xoid;
    h2x_oid(&xoid, &h.clobj_free_prev);
    s = objectWrite(dbh, OFFSET(CListObjHeader, clobj_free_prev), sizeof(Oid),
		       &xoid, &h.clobj_free_next);
    if (s)
      return s;
  }
  
  if (chd.clobj_free_first.getNX() == koid.getNX()) {
    chd.clobj_free_first = h.clobj_free_next;
    s = writeCListHeader(chd_k, chd);
    if (s)
      return s;
  }

  mset(&h.clobj_free_prev, 0, sizeof(h.clobj_free_prev));
  mset(&h.clobj_free_next, 0, sizeof(h.clobj_free_next));

  return Success;
}

Status
HIdx::suppressObjectFromList(CListHeader &chd, unsigned int chd_k, CListObjHeader &h,
				const Oid &koid)
{
#ifdef TRACK_MAP
  printf("suppressObjectFromList(%s)\n", getOidString(&koid));
#endif  
  Status s;

  if (h.clobj_prev.getNX()) {
    Oid xoid;
    h2x_oid(&xoid, &h.clobj_next);
    s = objectWrite(dbh, OFFSET(CListObjHeader, clobj_next), sizeof(Oid),
		       &xoid, &h.clobj_prev);
    if (s)
      return s;
  }
  
  if (h.clobj_next.getNX()) {
    Oid xoid;
    h2x_oid(&xoid, &h.clobj_prev);
    s = objectWrite(dbh, OFFSET(CListObjHeader, clobj_prev), sizeof(Oid),
		       &xoid, &h.clobj_next);
    if (s)
      return s;
  }
  
  Boolean write_chd = False;
  if (chd.clobj_first.getNX() == koid.getNX()) {
    chd.clobj_first = h.clobj_next;
    write_chd = True;
  }

  if (chd.clobj_last.getNX() == koid.getNX()) {
    chd.clobj_last = h.clobj_prev;
    write_chd = True;
  }

  if (write_chd) {
    s = writeCListHeader(chd_k, chd);
    if (s)
      return s;
  }

  return objectDelete(dbh, &koid);
}

Status
HIdx::modifyObjectSize(int osize, int nsize, const Oid &koid, 
		       Oid &nkoid)
{
  // ATTENTION:
  // 1. il ne faut utiliser cette fonction qui si koid est un oid physique
  //    test: if (isPhysicalOid(dbh, &koid))
  // 2. il faut creer le nouvel objet sur le meme dataspace !!
  //    => objectRead() permet de recuperer le datid mais objectCreate()
  //       necessite le dspid. Comment fait-on ?
  //       créer une fonction: datGetDspid(dbh, short datid, short *dspid)
  //printf("Modify Object Size from %d to %d\n", osize, nsize);

  unsigned char *data = new unsigned char[osize];
  short datid;
  Status s = objectRead(dbh, 0, osize, data, DefaultLock, &datid,
			      0, &koid);
  if (s) {
    delete [] data;
    return s;
  }

  short dspid;
  s = datGetDspid(dbh, datid, &dspid);

#ifdef OPTIM_LARGE_OBJECTS
  if (!s)
    s = objectCreate(dbh, ObjectNone, nsize, dspid, &nkoid);
#else
  if (!s)
    s = objectCreate(dbh, 0, nsize, dspid, &nkoid);
#endif

  if (s) {
    delete[] data;
    return s;
  }

  s = objectWrite(dbh, 0, osize, data, &nkoid);
  delete [] data;
  if (s) {
    (void)objectDelete(dbh, &nkoid);
    return s;
  }

  s = objectDelete(dbh, &koid);
  if (s)
    (void)objectDelete(dbh, &nkoid);

  return s;
}

Status
HIdx::replaceObjectInList(CListHeader &chd, unsigned int chd_k, CListObjHeader &h,
			     const Oid &koid, const Oid &nkoid)
{
#ifdef TRACK_MAP
  printf("replaceObjectFromList(%s, %s)\n", getOidString(&koid),
	 getOidString(&nkoid));
  printf("CHD first=%s last=%s\n", getOidString(&chd.first), getOidString(&chd.last));
  printf("CHD2 free_first=%s\n",
	 getOidString(&chd.free_first));
  printf("HEADER prev=%s, next=%s, free_prev=%s, free_next=%s\n",
	 getOidString(&h.clobj_prev),
	 getOidString(&h.clobj_next),
	 getOidString(&h.clobj_free_prev),
	 getOidString(&h.clobj_free_next));
#endif  
  Status s;

  Oid xoid;
  h2x_oid(&xoid, &nkoid);

  if (h.clobj_prev.getNX()) {
    s = objectWrite(dbh, OFFSET(CListObjHeader, clobj_next), sizeof(Oid),
		       &xoid, &h.clobj_prev);
    if (s)
      return s;
  }
  
  if (h.clobj_next.getNX()) {
    s = objectWrite(dbh, OFFSET(CListObjHeader, clobj_prev), sizeof(Oid),
		       &xoid, &h.clobj_next);
    if (s)
      return s;
  }
  
  if (h.clobj_free_prev.getNX()) {
    s = objectWrite(dbh, OFFSET(CListObjHeader, clobj_free_next), sizeof(Oid),
		       &xoid, &h.clobj_free_prev);
    if (s)
      return s;
  }
  
  if (h.clobj_free_next.getNX()) {
    s = objectWrite(dbh, OFFSET(CListObjHeader, clobj_free_prev), sizeof(Oid),
		       &xoid, &h.clobj_free_next);
    if (s)
      return s;
  }
  
  Boolean write_chd = False;
  if (chd.clobj_first.getNX() == koid.getNX()) {
    chd.clobj_first = xoid;
    write_chd = True;
  }

  if (chd.clobj_last.getNX() == koid.getNX()) {
    chd.clobj_last = xoid;
    write_chd = True;
  }

  if (chd.clobj_free_first.getNX() == koid.getNX()) {
    chd.clobj_free_first = xoid;
    write_chd = True;
  }

  if (write_chd) {
    s = writeCListHeader(chd_k, chd);
    if (s)
      return s;
  }

  return Success;
}

//#define BUG_DATA_STORE
#define BUG_DATA_STORE2

Status
HIdx::insert_realize(CListHeader &chd, unsigned int chd_k, const void *key,
		     unsigned int size, const void *xdata,
		     const Oid &koid,
		     CListObjHeader &h, int offset, CellHeader &o, unsigned int datasz)
{
  int osize = o.size, onext = o.cell_free_next;
  int ovsize = size + sizeof(CellHeader);
  Status s;

  assert(o.free);

  /*
  printf("insert_realize offset %d o.free %d o.cell_free_next %d o.cell_free_prev %d\n",
	 offset, o.free, o.cell_free_next, o.cell_free_prev);
  */

#ifdef TRACK_MAP
  printf("insert_realize(%d vs. %d", osize, size);
  if (hidx.datasz >= sizeof(Oid)) {
    Oid xdata_oid;
    memcpy(&xdata_oid, xdata, sizeof(Oid));
    printf(". [%s]", getOidString(&xdata_oid));
  }
  printf("\n");
#endif

#ifdef BUG_DATA_STORE
  if (osize > size + sizeof(CellHeader))
    o.size = size;
  else
    ovsize += osize - size;
#endif

#ifdef HAS_ALLOC_BUFFER
  char *data = insert_buffer.alloc(ovsize);
#else
  char *data = (char *)m_malloc(ovsize);
#endif
  if (STRTYPE(this))
    memcpy(data + sizeof(CellHeader), key, strlen((char *)key)+1);
  else if (hidx.keytype == tUnsignedChar || hidx.keytype == tChar ||
	   hidx.keytype == tSignedChar)
    memcpy(data + sizeof(CellHeader), key, size - datasz);
  else {
    char xkey[Idx_max_type_size];
    assert(size - datasz <= Idx_max_type_size);
    h2x(xkey, key, keytype);
    memcpy(data + sizeof(CellHeader), xkey, size - datasz);
  }

  if (o.cell_free_next != NullOffset) {
    CellHeader no;
    s = readCellHeader(o.cell_free_next, koid, no);
    if (s)
      return s;
    assert(no.free);
    no.cell_free_prev = o.cell_free_prev;
    s = writeCellHeader(o.cell_free_next, koid, no);
    if (s)
      return s;
  }

  if (o.cell_free_prev != NullOffset) {
    CellHeader no;
    s = readCellHeader(o.cell_free_prev, koid, no);
    if (s)
      return s;
    assert(no.free);
    no.cell_free_next = o.cell_free_next;
    s = writeCellHeader(o.cell_free_prev, koid, no);
    if (s)
      return s;
  }
  else {
    assert(h.cell_free_first == offset);
    h.cell_free_first = o.cell_free_next;
  }

#if 0
  if (h.cell_free_first == offset) {
    printf("h.cell_free_first == offset %d\n", offset);
    if (o.cell_free_next != NullOffset) {
      CellHeader no;
      s = readCellHeader(o.cell_free_next, koid, no);
      if (s)
	return s;
      // EV : 3/05/07
      assert(no.free);
      no.cell_free_prev = NullOffset;
      s = writeCellHeader(o.cell_free_next, koid, no);
      if (s)
	return s;
    }
    h.cell_free_first = o.cell_free_next;
    printf("setting free_first to %d\n", h.cell_free_first);
  }
#endif


#ifndef BUG_DATA_STORE
  if (osize > size + sizeof(CellHeader))
    o.size = size;
#endif

  o.free = 0;
  o.cell_free_next = NullOffset;
  o.cell_free_prev = NullOffset;
  CellHeader to;
  h2x_overhead(&to, &o);
  mcp(data, &to, sizeof(to));
  //  memcpy(data + ovsize - hidx.datasz, xdata, hidx.datasz);
  if (isDataVarSize()) {
    unsigned int xdatasz = h2x_u32(datasz);
    memcpy(data + ovsize - datasz - DATASZ_SIZE, &xdatasz, DATASZ_SIZE);
    memcpy(data + ovsize - datasz, xdata, datasz);
  }
  else {
    memcpy(data + ovsize - datasz, xdata, datasz);
  }
  //printf("writing OBJECT %s of size %d offset = %d total = %d\n", getOidString(&koid), ovsize, offset, offset+ovsize);
  s = objectWrite(dbh, offset, ovsize, data, &koid);
#ifndef HAS_ALLOC_BUFFER
  free(data);
#endif
  if (s)
    return s;  

  h.free_whole -= osize;

#if 0
  assert(!writeCListObjHeader(koid, h));
#endif

  if (osize == size) {
#ifdef TRACK_MAP
    printf("exact size %d\n", size);
#endif
  }
  else if (osize > size + sizeof(CellHeader)) {
    /* generation d'une nouvelle cellule */
#ifdef TRACK_MAP
    printf("split cell %d %d %d %d\n", size+sizeof(CellHeader), osize, offset, h.cell_free_first);
#endif
    int noffset = offset + size + sizeof(CellHeader);
    s = insertCell(noffset, osize - size - sizeof(CellHeader), h, koid);
    if (s)
      return s;
  }
#ifdef TRACK_MAP
  else {
    printf("special case: we are loosing some place %s ?\n", getOidString(&koid));
  }
#endif

  h.free_cnt--;
  h.alloc_cnt++;

  /*
  printf("insert: ovsize=%d, free_whole=%d, free_cnt=%d, alloc_cnt=%d\n",
	 ovsize, h.free_whole, h.free_cnt, h.alloc_cnt);
  */

  // changed this test the 29/06/02 to allow to get rid of unuseful objects
#ifdef OPT_FREELIST
  if (!h.free_cnt || (STRTYPE(this) && h.free_whole <= sizeof(CellHeader)+8))
#else
  if (!h.free_cnt)
#endif
    {
#ifdef TRACK_MAP
    printf("making chain for new object\n");
#endif
    Status s;
    // ASTUCE : si la taille n'est pas au maximum, alors ne pas supprimer
    // cet objet de la free list mais, au contraire, l'étendre en utilisant
    // hints[XCoef_Hints].
    if (!uextend || !candidateForExtension(h)) {
#ifdef TRUSS2_GC
      if (h.free_cnt) {
	printf("get rid of this fucking object %d %s\n", h.free_whole, getOidString(&koid));
      }
#endif
      s = suppressObjectFromFreeList(chd, chd_k, h, koid);
      if (s)
	return s;
    }
  }

  s = writeCListObjHeader(koid, h);

  if (!s)
    s = count_manage(dbh, 1);

  return s;
}

Status
HIdx::count_manage(DbHandle *_dbh, int inc)
{
  unsigned int count;
  Status s = objectRead(_dbh, sizeof(unsigned int),
			sizeof(unsigned int), &count,
			DefaultLock, 0, 0, &treeoid);
  if (s)
    return s;
  count = x2h_u32(count);
  unsigned int o_count = hidx.object_count;

  hidx.object_count = count + inc;
  count = h2x_u32(hidx.object_count);

  s = objectWrite(_dbh, sizeof(unsigned int),
		  sizeof(unsigned int), &count, &treeoid);
  
  if (s) hidx.object_count = o_count;
  return s;
}

Status
HIdx::readCListHeader(unsigned int k, CListHeader &chd) const
{
  Status s;
  unsigned int (*gkey)(int) = get_gkey(version);

  s = objectRead(dbh, gkey(k) * sizeof(CListHeader), sizeof(CListHeader), &chd,
		    DefaultLock, 0, 0, &treeoid);
  if (s)
    return s;
  x2h_chd(&chd);
  return Success;
}

Status
HIdx::readCListObjHeader(const Oid &koid, CListObjHeader &h) const
{
  Status s;
  s = objectRead(dbh, 0, sizeof(CListObjHeader), &h, DefaultLock,
		    0, 0, &koid);
  if (s)
    return s;
  x2h_header(&h);
  return Success;
}

Status
HIdx::writeCListObjHeader(const Oid &koid, const CListObjHeader &h) const
{
#if 0
  if (h.cell_free_first != NullOffset) {
    CellHeader o = {0};
    Status s = readCellHeader(h.cell_free_first, koid, o);
    if (s)
      statusPrint(s, "...");
    assert(o.free);
  }
#endif
  CListObjHeader th;
  h2x_header(&th, &h);
  return objectWrite(dbh, 0, sizeof(CListObjHeader), &th, &koid);
}

Status
HIdx::readCellHeader(int offset, const Oid &koid, CellHeader &o) const
{
  Status s;
  s = objectRead(dbh, offset, sizeof(CellHeader), &o, DefaultLock,
		    0, 0, &koid);
  if (s)
    return s;
  x2h_overhead(&o);
  return Success;
}

void HIdx::printCellHeader(const HIdx::CellHeader *o, int offset) const
{
  printf("CellHeader at %d\n", offset);
  printf("  o.free %d\n", o->free);
  printf("  o.size %d\n", o->size);
  printf("  o.cell_free_prev %d\n", o->cell_free_prev);
  printf("  o.cell_free_next %d\n", o->cell_free_next);
}

void HIdx::checkCellHeader(int offset, const Oid *koid) const
{
  HIdx::CellHeader o;
  readCellHeader(offset, *koid, o);
  printCellHeader(&o, offset);
}

void HIdx::printCListObjHeader(const HIdx::CListObjHeader *h) const
{
  printf("CListObjHeader\n");
  printf("  h.size %u\n", h->size);
  printf("  h.free_cnt %d\n", h->free_cnt);
  printf("  h.alloc_cnt %d\n", h->alloc_cnt);
  printf("  h.free_whole %d\n", h->free_whole);
  printf("  h.cell_free_first %d\n", h->cell_free_first);
  printf("  h.clobj_free_prev %s\n", getOidString(&h->clobj_free_prev));
  printf("  h.clobj_free_next %s\n", getOidString(&h->clobj_free_next));
  printf("  h.clobj_prev %s\n", getOidString(&h->clobj_prev));
  printf("  h.clobj_next %s\n", getOidString(&h->clobj_next));
}

void HIdx::checkCListObjHeader(const Oid *koid) const
{
  HIdx::CListObjHeader h;
  readCListObjHeader(*koid, h);
  printCListObjHeader(&h);
}

void HIdx::checkChain(const Oid *koid) const
{
  CListObjHeader h;
  readCListObjHeader(*koid, h);
  int offset = h.cell_free_first;
  int prev = NullOffset;
  //printCListObjHeader(&h);

  for (unsigned int n = 0; offset != NullOffset && n < 100; n++) {
    CellHeader o;
    assert(!readCellHeader(offset, *koid, o));
    assert(o.free);
    assert(o.cell_free_prev == prev);
    prev = offset;
    //printCellHeader(&o, offset);
    offset = o.cell_free_next;
    if (n > 90)
      printf("chain loop\n");
  }
}

void HIdx::checkChain(const CListHeader *chd, const std::string &msg) const
{
 Oid koid = chd->clobj_free_first;

 //printf("\nChecking chain %s {\n", msg.c_str());

  int cnt = 0;
  while (koid.getNX()) {
    CListObjHeader h;
    assert(!readCListObjHeader(koid, h));
    //printf("h.cell_free_first %d\n", h.cell_free_first);
    checkChain(&koid);
    koid = h.clobj_free_next;
    cnt++;
  }
  //printf("} %d found\n", cnt);
}

static bool dont_check = false;
//static bool dont_check = true;

Status
HIdx::writeCellHeader(int offset, const Oid &koid,
		       const CellHeader &o) const
{
  CellHeader to;
  h2x_overhead(&to, &o);

#if 0
  if (!dont_check) {
    std::map<unsigned int, bool> map;
    map[offset] = true;

    unsigned off = o.cell_free_prev;
    bool loop = false;
    for (int n = 0; !loop && n < 10; n++) {
      if (off == NullOffset)
	break;

      if (loop) {
	printf("offset %u at #%d\n", off, n);
      }

      if (map.find(off) != map.end()) {
	printf("loop in writeCellHeader prev %u at #%d [prev %d]\n", off, n, o.cell_free_prev);
	loop = true;
      }
      map[off] = true;
      CellHeader no;
      readCellHeader(off, koid, no);
      off = no.cell_free_prev;
    }
    if (loop)
      printf("*** prev EOL\n");

    off = o.cell_free_next;
    loop = false;
    for (int n = 0; !loop && n < 10; n++) {
      if (off == NullOffset)
	break;

      if (loop) {
	printf("offset %u at #%d\n", off, n);
      }

      if (map.find(off) != map.end()) {
	printf("loop in writeCellHeader next %u at #%d [next %d]\n", off, n, o.cell_free_next);
	loop = true;
      }
      map[off] = true;
      CellHeader no;
      readCellHeader(off, koid, no);
      off = no.cell_free_next;
    }
    if (loop)
      printf("*** next EOL\n");
  }
#endif
  return objectWrite(dbh, offset, sizeof(CellHeader), &to, &koid);
}

Status
HIdx::readCListHeaders(CListHeader *&chds) const
{
  Status s;
  int len = get_gkey(version)(hidx.key_count);
  chds = new CListHeader[len];

  s = objectRead(dbh, 0, len * sizeof(CListHeader), chds,
		    DefaultLock, 0, 0, &treeoid);
  if (s)
    return s;
  for (int i = KEY_OFF; i < len; i++)
    x2h_chd(&chds[i]);
  return Success;
}

Status
HIdx::writeCListHeaders(const CListHeader *chds) const
{
  int len = get_gkey(version)(hidx.key_count);
  CListHeader *nchds = new CListHeader[len];
  memcpy(nchds, chds, sizeof(CListHeader) * KEY_OFF);
  for (int i = KEY_OFF; i < len; i++)
    h2x_chd(&nchds[i], &chds[i]);

  Status s = objectWrite(dbh, 0, len * sizeof(CListHeader), nchds,
			       &treeoid);
  delete [] nchds;
  return s;
}

Status
HIdx::writeCListHeader(unsigned int k, const CListHeader &chd) const
{
  Status s;
  unsigned int (*gkey)(int) = get_gkey(version);

  CListHeader tchd;
  h2x_chd(&tchd, &chd);
  s = objectWrite(dbh, gkey(k) * sizeof(CListHeader), sizeof(CListHeader), &tchd,
		     &treeoid);
  if (s)
    return s;
  return Success;
}

Status
HIdx::dumpMemoryMap(const CListHeader &chd, const char *msg, FILE *fd)
{
  fprintf(fd, "%sFREE MEMORY MAP {\n", msg);
  Oid prev;
  Oid koid = chd.clobj_free_first;
  memset(&prev, 0, sizeof(prev));

  int cnt = 0;
  while (koid.getNX()) {
    Status s;
    CListObjHeader h;
    s = readCListObjHeader(koid, h);
    if (s)
      return s;
    fprintf(fd, "\tObject %s -> Free Whole: %d, Free Count: %d\n",
	    getOidString(&koid), h.free_whole, h.free_cnt);
    assert(!memcmp(&h.clobj_free_prev, &prev, sizeof(prev)));
    prev = koid;
    koid = h.clobj_free_next;
    cnt++;
  }
  fprintf(fd, "} -> %d cells in FREE MAP\n\n", cnt);

  cnt = 0;
  memset(&prev, 0, sizeof(prev));
  koid = chd.clobj_first;

  fprintf(fd, "%sMEMORY MAP {\n", msg);
  fprintf(fd, "\tFirst Free %s\n", getOidString(&chd.clobj_free_first));
  while (koid.getNX()) {
    Status s;
    CListObjHeader h;
    s = readCListObjHeader(koid, h);
    if (s)
      return s;
    size_t sz = 0; // V3_API_size_t
    s = objectSizeGet(dbh, &sz, DefaultLock, &koid);
    if (s)
      return s;
    int cur = sizeof(CListObjHeader);
    fprintf(fd, "\tObject %s {\n\t  First Free: %d\n\t  Free Whole: %d\n\t  "
	    "Free Count: %d\n\t  Alloc Count: %d\n\t  Size: %d\n\t  "
	    "Free Prev: %s\n\t  Free Next: %s\n",
	    getOidString(&koid), h.cell_free_first,
	    h.free_whole, h.free_cnt, h.alloc_cnt, sz,
	    getOidString(&h.clobj_free_prev), getOidString(&h.clobj_free_next));
    assert(!memcmp(&h.clobj_prev, &prev, sizeof(prev)));

    int busy_cnt = 0;
    int free_cnt = 0;
    while (cur + sizeof(CellHeader) <= sz) {
      CellHeader to;
      s = readCellHeader(cur, koid, to);
      if (s)
	return s;
      fprintf(fd, "\t  #%d size %d %s", cur,
	      to.size, (to.free ? "free" : "busy"));

      if (to.cell_free_prev != NullOffset)
	fprintf(fd, " free_prev %d", to.cell_free_prev);

      if (to.cell_free_next != NullOffset)
	fprintf(fd, " free_next %d", to.cell_free_next);

      fprintf(fd, "\n");
      if (to.free) free_cnt++;
      else busy_cnt++;
      cur += to.size + sizeof(CellHeader);
    }

    fprintf(fd, "\t}\n");
    // now checking
    assert(free_cnt == h.free_cnt);
    assert(busy_cnt == h.alloc_cnt);
    int free_cur = h.cell_free_first;
    int free_prev = NullOffset;
    int free_size = 0;
    while (free_cur != NullOffset) {
      CellHeader to;
      s = readCellHeader(free_cur, koid, to);
      if (s)
	return s;
      if (!to.free || to.cell_free_prev != free_prev) {
	fprintf(fd, "#%d free, free_prev %d %d\n", free_cur, to.cell_free_prev,
		free_prev);
	assert(0);
      }
      assert(to.free);
      assert(to.cell_free_prev == free_prev);
      free_size += to.size;
      free_prev = free_cur;
      free_cur = to.cell_free_next;
    }

    assert(free_size == h.free_whole);
    prev = koid;
    koid = h.clobj_next;
    cnt++;
  }
  fprintf(fd, "} -> %d cells in MAP\n", cnt);

  return Success;
}

Status
HIdx::makeObject(CListHeader &chd, unsigned int chd_k, Oid &koid, int &offset,
		    CListObjHeader &h, CellHeader &o, unsigned int objsize)
{
#ifdef TRACK_MAP
  printf("making object\n");
#endif
  unsigned int bsz = bsize; // changed the 30/01/02
  objsize += sizeof(CellHeader); // added the 30/01/02
  int utsize = (bsz > objsize ? bsz : objsize);
  //int size = sizeof(CListObjHeader) + sizeof(CellHeader) + utsize;
  unsigned int size = sizeof(CListObjHeader) + utsize;

#ifdef OPTIM_LARGE_OBJECTS

  int alloc_size = sizeof(CListObjHeader) + sizeof(CellHeader);
#ifdef HAS_ALLOC_BUFFER
  char *d = makeobj_buffer.alloc(alloc_size);
#else
  char *d = (char *)m_malloc(alloc_size);
#endif

#else

#ifdef HAS_ALLOC_BUFFER
  char *d = makeobj_buffer.alloc(size);
#else
  char *d = (char *)m_malloc(size);
#endif

#endif

  offset = sizeof(CListObjHeader);
  h.size = size;
  h.free_cnt = 1;
  h.alloc_cnt = 0;
  h.free_whole = utsize - sizeof(CellHeader);
  h.cell_free_first = sizeof(CListObjHeader);
  h.clobj_prev = chd.clobj_last;
  mset(&h.clobj_next, 0, sizeof(h.clobj_next));
  mset(&h.clobj_free_prev, 0, sizeof(h.clobj_free_prev));

  // changed the 20/05/02
  //mset(&h.clobj_free_next, 0, sizeof(h.clobj_free_next));
  h.clobj_free_next = chd.clobj_free_first;

  o.free = 1;
  o.size = utsize - sizeof(CellHeader); //  + sizeof(CellHeader); // 26/12/01: added '+ sizeof(CellHeader)'
  o.cell_free_next = NullOffset;
  o.cell_free_prev = NullOffset;
  CListObjHeader xh;
  h2x_header(&xh, &h);
  mcp(d, &xh, sizeof(CListObjHeader));
  CellHeader xo;
  h2x_overhead(&xo, &o);
  mcp(d + sizeof(CListObjHeader), &xo, sizeof(CellHeader));
  
#ifdef OPTIM_LARGE_OBJECTS
  Status s = objectCreate(dbh, ObjectNone, size, hidx.dspid, &koid);
  if (s) {free (d); return s;}
  s = objectWrite(dbh, 0, alloc_size, d, &koid);
#else
  Status s = objectCreate(dbh, d, size, hidx.dspid, &koid);
#endif

#ifndef HAS_ALLOC_BUFFER
  free(d);
#endif

  if (s)
    return s;

  if (!chd.clobj_first.getNX())
    chd.clobj_first = koid;
  else {
    Oid xoid;
    h2x_oid(&xoid, &koid);
    s = objectWrite(dbh, OFFSET(CListObjHeader, clobj_next), sizeof(Oid), &xoid,
		       &chd.clobj_last);
    if (s)
      return s;
  }

  chd.clobj_last = koid;
  // changed the 20/05/02
  return insertObjectInFreeList(chd, chd_k, h, koid);
}

inline bool
HIdx::inFreeList(const CListObjHeader &h, const CListHeader &chd, const Oid &koid)
{
  return h.clobj_free_prev.getNX() || h.clobj_free_next.getNX() || chd.clobj_free_first.getNX() == koid.getNX();
}

Status
HIdx::insertObjectInFreeList(CListHeader &chd, unsigned int chd_k, CListObjHeader &h,
				const Oid &koid)
{
#ifdef TRACK_MAP
  printf("hidx: insertion of a new cell!\n");
#endif
  Status s;
  if (chd.clobj_free_first.getNX()) {
    Oid xoid;
    h2x_oid(&xoid, &koid);
    s = objectWrite(dbh, OFFSET(CListObjHeader, clobj_free_prev),
		       sizeof(Oid), &xoid, &chd.clobj_free_first);
    if (s)
      return s;
  }

  h.clobj_free_next = chd.clobj_free_first;
  chd.clobj_free_first = koid;

  return writeCListHeader(chd_k, chd);
}

Boolean
HIdx::candidateForExtension(const CListObjHeader &h)
{
  unsigned int size_n = hidx.impl_hints[XCoef_Hints] * h.size;
  return (size_n <= (unsigned int)hidx.impl_hints[SzMax_Hints] ? True : False);
}

Status
HIdx::extendObject(unsigned int size, CListHeader &chd, unsigned int chd_k, Oid &koid,
		      CListObjHeader &h, int &offset, CellHeader &o,
		      Boolean &extended)
{
  unsigned int size_n = hidx.impl_hints[XCoef_Hints] * h.size;
  unsigned int size_inc = size_n - h.size;

  printf("extendObject %s [%d > %d && %d > %d] ?\n", getOidString(&koid),
	 size_n, hidx.impl_hints[SzMax_Hints],
	 size_inc + h.free_whole, size);

  if (size_n > (unsigned int)hidx.impl_hints[SzMax_Hints] &&
      (!size || size_inc + h.free_whole >= size)) {
    extended = False;
    return Success;
  }
    
  Status s;
  memset(&o, 0, sizeof(CellHeader));
  offset = h.cell_free_first;
  int lastoffset = NullOffset;
  while (offset != NullOffset) {
    s = readCellHeader(offset, koid, o);
    if (s)
      return s;
    lastoffset = offset;
    offset = o.cell_free_next;
  }

  Oid nkoid;
  if (o.free) {
#ifdef TRACK_MAP	
    printf("object %s can be extended from %d to %d -> extend overhead\n",
	   getOidString(&koid), h.size, size_n);
#endif
    o.size += size_inc;
    offset = lastoffset;
    s = writeCellHeader(offset, koid, o);
    if (s)
      return s;
    extended = True;
    h.free_whole += size_inc;
    int osize = h.size;
    h.size = size_n;
    s = writeCListObjHeader(koid, h);
    if (s)
      return s;
    if (isPhysicalOid(dbh, &koid)) {
      s = modifyObjectSize(osize, size_n, koid, nkoid);
      if (s)
	return s;
      s = replaceObjectInList(chd, chd_k, h, koid, nkoid);
      if (s)
	return s;
      koid = nkoid;
      return Success;
    }
    return objectSizeModify(dbh, size_n, True, &koid);
  }

  if (!size || size_inc >= size) {
    // must done a new overhead AND must chain with last overhead !
#ifdef TRACK_MAP	
    printf("object %s can be extended from %d to %d (diff=%d) -> new overhead\n",
	   getOidString(&koid), h.size, size_n, size_inc - size);
#endif
    if (isPhysicalOid(dbh, &koid)) {
      s = modifyObjectSize(h.size, size_n, koid, nkoid);
      if (s)
	return s;
      s = replaceObjectInList(chd, chd_k, h, koid, nkoid);
      koid = nkoid;
    }
    else
      s = objectSizeModify(dbh, size_n, True, &koid);
    if (s)
      return s;
    offset = h.size;
    if (lastoffset != NullOffset) {
      o.cell_free_next = offset;
      s = writeCellHeader(lastoffset, koid, o);
      if (s)
	return s;
    }
    else
      h.cell_free_first = offset;

    o.size = size_inc - sizeof(CellHeader);
    o.free = 1;
    o.cell_free_prev = lastoffset;
    o.cell_free_next = NullOffset;
    extended = True;
    h.free_cnt++;
    h.free_whole += size_inc - sizeof(CellHeader);
    h.size = size_n;
    if (!inFreeList(h, chd, koid)) {
      //      printf("not in free list ?\n");
      s = insertObjectInFreeList(chd, chd_k, h, koid);
      if (s)
	return s;
    }
    s = writeCListObjHeader(koid, h);
    if (s)
      return s;
    return writeCellHeader(offset, koid, o);
  }
  //printf("not extended\n");
  return Success;
}

#ifndef NO_EXTEND
Status
HIdx::getObjectToExtend(unsigned int size, CListHeader &chd, unsigned int chd_k,
			   Oid &koid, CListObjHeader &h, int &offset, CellHeader &o,
			   Boolean &found)
{
  ------ CODE NOT USED ----
  found = False;
  Status s;
  koid = chd.first;

  while (koid.getNX()) {
    s = readCListObjHeader(koid, h);
    if (s)
      return s;
    /*
    printf("KOID %s h.clobj_prev %s h.clobj_next %s\n", getOidString(&koid),
	   getOidString(&h.clobj_prev),
	   getOidString(&h.clobj_next));
    */
    unsigned int size_n = hidx.impl_hints[XCoef_Hints] * h.size;
    unsigned int size_inc = size_n - h.size;
    if (size_n <= hidx.impl_hints[SzMax_Hints] &&
	size_inc + h.free_whole >= size) {
      memset(&o, 0, sizeof(CellHeader));
      offset = h.cell_free_first;
      int lastoffset = NullOffset;
      while (offset != NullOffset) {
	s = readCellHeader(offset, koid, o);
	if (s)
	  return s;
	lastoffset = offset;
	offset = o.cell_free_next;
      }

      Oid nkoid;
      if (o.free) {
#ifdef TRACK_MAP	
	printf("object %s can be extended from %d to %d -> extend overhead\n",
	       getOidString(&koid), h.size, size_n);
#endif
	o.size += size_inc;
	offset = lastoffset;
	s = writeCellHeader(offset, koid, o);
	if (s)
	  return s;
	found = True;
	h.free_whole += size_inc;
	int osize = h.size;
	h.size = size_n;
	s = writeCListObjHeader(koid, h);
	if (s)
	  return s;
	if (isPhysicalOid(dbh, &koid)) {
	  s = modifyObjectSize(osize, size_n, koid, nkoid);
	  if (s)
	    return s;
	  s = replaceObjectInList(chd, chd_k, h, koid, nkoid);
	  if (s)
	    return s;
	  koid = nkoid;
	  return Success;
	}
	return objectSizeModify(dbh, size_n, True, &koid);
      }
      else if (size_inc >= size) {
	// must done a new overhead AND must chain with last overhead !
#ifdef TRACK_MAP	
	printf("object %s can be extended from %d to %d -> new overhead\n",
	       getOidString(&koid), h.size, size_n);
#endif
	if (isPhysicalOid(dbh, &koid)) {
	  s = modifyObjectSize(h.size, size_n, koid, nkoid);
	  if (s)
	    return s;
	  s = replaceObjectInList(chd, chd_k, h, koid, nkoid);
	  koid = nkoid;
	}
	else
	  s = objectSizeModify(dbh, size_n, True, &koid);
	if (s)
	  return s;
	offset = h.size;
	if (lastoffset != NullOffset) {
  ------ CODE NOT USED ----
	  o.cell_free_next = offset;
	  s = writeCellHeader(lastoffset, koid, o);
	  if (s)
	    return s;
	}
	else
	  h.cell_free_first = offset;

	o.size = size_inc - sizeof(CellHeader);
	o.free = 1;
	o.cell_free_prev = lastoffset;
	o.cell_free_next = NullOffset;
	found = True;
	h.free_cnt++;
	h.free_whole += size_inc - sizeof(CellHeader);
	h.size = size_n;
	if (!inFreeList(h, chd, koid)) {
	  s = insertObjectInFreeList(chd, chd_k, h, koid);
	  if (s)
	    return s;
	}
	s = writeCListObjHeader(koid, h);
	if (s)
	  return s;
	return writeCellHeader(offset, koid, o);
      }
    }
    koid = h.clobj_next;
  }

#ifdef TRACK_MAP
  printf("no candidates for extension\n");
#endif
  return Success;
}
#endif

int hidx_gccnt;

Status
HIdx::getCell(unsigned int size, CListHeader &chd, unsigned int chd_k,
		 Oid &koid, CListObjHeader &h, int &offset, CellHeader &o)
{
  Status s;
  koid = chd.clobj_free_first;
  hidx_gccnt = 0;
#ifdef TRUSS1_GC
  unsigned int total_whole = 0, min_whole = ~0, max_whole = 0;
#endif
#ifdef TRUSS2_GC
  printf("getcell size %d\n", size);
#endif

  while (koid.getNX()) {
    s = readCListObjHeader(koid, h);
    if (s)
      return s;

    Boolean extended;
    if (uextend) {
      if (h.free_whole < size) {
	s = extendObject(size, chd, chd_k, koid, h, offset, o, extended);
	if (s)
	  return s;
      }
    }

#ifdef TRUSS1_GC
    total_whole += h.free_whole;
    if (h.free_whole > max_whole)
      max_whole = h.free_whole;
    if (h.free_whole < min_whole)
      min_whole = h.free_whole;
#endif
#ifdef TRUSS2_GC
    printf("getcell free_whole %d #%d\n", h.free_whole, hidx_gccnt);
#endif
    if (h.free_whole >= size) { // optimisation added 29/01/02
      offset = h.cell_free_first;
      for (unsigned int n = 0; offset != NullOffset; n++) {
	if (n && offset == h.cell_free_first || n > 100) {
	  //printf("free_whole %u %d looping #%d\n", h.free_whole, size, n);
	  break;
	}
	s = readCellHeader(offset, koid, o);
	if (s)
	  return s;
	if (o.free && o.size >= size) {
	  //printf("object found free_next %d size %d\n", o.cell_free_next, o.size);
	  return Success;
	}

	if (uextend) {
	  s = extendObject(size, chd, chd_k, koid, h, offset, o, extended);
	  if (s)
	    return s;
	  if (extended && o.free && o.size >= size) {
	    //printf("object extended and found\n");
	    return Success;
	  }
	}

	//COMPARE_OFFSET(offset, o.cell_free_next, "looping");
	offset = o.cell_free_next;
      }
    }
    koid = h.clobj_free_next;
#ifdef TRUSS1_GC
    if (hidx_gccnt == 10000) {
      printf("hidx getcell size=%d, avg_whole=%f, min_whole=%d, "
	     "max_whole=%d\n",
	     size, (float)total_whole/hidx_gccnt, min_whole, max_whole);
      fflush(stdout);
    }
#endif
#ifdef OPT_FREELIST
    if (hidx.keysz != VarSize)
      break;
    // WARNING : 29/06/02 this test is to avoid too many search in free list
    // but this can make holes in the free list !
    if (hidx_gccnt > 4) {
      break;
    }
#endif
    hidx_gccnt++;
  }

#ifndef NO_EXTEND
  Boolean found;
  s = getObjectToExtend(size, chd, chd_k, koid, h, offset, o, found);
  if (s || found) return s;
#endif

  // not found
  return makeObject(chd, chd_k, koid, offset, h, o, size);
}

#ifdef CI_STORE
static char *
lowstring(const char *key)
{
  char *q = new char[strlen(key)+1];
  char c, *p;

  for (p = q; c = *key++; p++) {
    if (c >= 'A' && c <= 'Z')
      *p = c + 'a' - 'A';
    else
      *p = c;
  }

  *p = 0;
  return q;
}
#endif

void stop_imm1() { }

static int WRITE_HEADER;

HIdx::HKey::HKey(HIdx *hidx, const void *_key, bool copy) : hidx(hidx)
{
  if (copy) {
    Boolean isstr = hidx->hidx.keytype == Idx::tString ? True : False;
    key = copy_key(_key, hidx->hidx.keysz, isstr);
    _garbage = true;
  }
  else {
    key = _key;
    _garbage = false;
  }
}

HIdx::HKey::HKey(const HIdx::HKey &hkey)
{
  _garbage = false;
  key = 0;
  hidx = 0;
  *this = hkey;
}

HIdx::HKey& HIdx::HKey::operator=(const HIdx::HKey &hkey)
{
  if (this == &hkey)
    return *this;

  garbage();

  _garbage = hkey._garbage;
  hidx = hkey.hidx;

  if (_garbage) {
    Boolean isstr = hkey.hidx->hidx.keytype == Idx::tString ? True : False;
    key = copy_key(hkey.key, hkey.hidx->hidx.keysz, isstr);
  }
  else {
    key = hkey.key;
  }

  return *this;
}

Status HIdx::insert_cache(const void *key, const void *xdata)
{
  std::vector<const void *> xdata_v;
  xdata_v.push_back(xdata);
  return insert_cache(key, xdata_v);
}

Status HIdx::insert_cache(const void *key, std::vector<const void *> &xdata_v)
{
  if (isDataVarSize()) {
    return statusMake(ERROR, "Variable data size hash index: cannot use cache");
  }

  unsigned int xdata_v_cnt = xdata_v.size();
  HKey hkey(this, key, true);
  std::vector<const void *> &v = cache_map[hkey];
  for (unsigned int n = 0; n < xdata_v_cnt; n++) {
    unsigned char *data = new unsigned char[hidx.datasz];
    memcpy(data, xdata_v[n], hidx.datasz);
    v.push_back((const void *)data);
  }
  return Success;
}

Status HIdx::flush_cache(bool insert_data)
{
  std::map<HKey, std::vector<const void *> >::iterator begin = cache_map.begin();
  std::map<HKey, std::vector<const void *> >::iterator end = cache_map.end();

  while (begin != end) {
    std::vector<const void *> &v = (*begin).second;
    if (insert_data) {
      Status s = insert((*begin).first.getKey(), v);
      if (s)
	return s;
    }

    std::vector<const void *>::iterator b = v.begin();
    std::vector<const void *>::iterator e = v.end();
    while (b != e) {
      delete [] (unsigned char *)(*b);
      ++b;
    }
    v.clear();
    ++begin;
  }

  cache_map.clear();
  return Success;
}

Status HIdx::insert(const void *key, const void *xdata)
{ 
  if (isDataVarSize()) {
    return statusMake(ERROR, "Variable data size hash index: the data size must be given at insertion, use HIdx::insert(const void *key, const void *data, unsigned int datasz)");
  }

  return insert_perform(key, xdata, 0);
}

Status HIdx::insert(const void *key, const void *data, unsigned int datasz)
{
  if (!isDataVarSize() && hidx.datasz != datasz) {
    return statusMake(ERROR, "Fixed size hash index: the data size must be equals to %u", hidx.datasz);
  }

  return insert_perform(key, data, datasz);
}

Status HIdx::insert(const void *key, std::vector<const void *> &xdata_v)
{ 
  if (isDataVarSize()) {
    return statusMake(ERROR, "Variable data size hash index: the method HIdx::insert(const void *key, std::vector<const void *> &data_v) is not supported");
  }

  return insert_perform(key, xdata_v, 0);
}

Status HIdx::insert_perform(const void *key, const void *xdata, unsigned int datasz)
{
  std::vector<const void *> xdata_v;
  xdata_v.push_back(xdata);
  return insert_perform(key, xdata_v, datasz);
}

Status HIdx::insert_perform(const void *key, std::vector<const void *> &xdata_v, unsigned int xdatasz)
{ 
  Status s;

  if (stat)
    return stat;

  if (s = checkOpened())
    return s;

#ifdef CACHE_FOR_LOCK
  // oplist.insertObjectLast(new INSLink(this, key));
  // return Success;
#endif

  unsigned int datasz = xdatasz;

  unsigned int x;
  unsigned int size;
  unsigned int (*gkey)(int) = get_gkey(version);
  s = get_key(x, key, &size);
  if (s)
    return s;

  IdxLock lockx(dbh, treeoid);
  s = lockx.lock();
  if (s)
    return s;

  int xdata_v_cnt = xdata_v.size();

  /*
  CListHeader chd;
  s = readCListHeader(x, chd);
  if (s)
    return s;
  */

#ifdef TRACK_MAP
  printf("\nINSERT at #%d\n", x);
#endif
  unsigned char *rdata = 0;
  const void *xdata = 0;
  bool direct;
  if (datasz) {
    assert(xdata_v_cnt == 1);
    direct = true;
    if (isDataVarSize()) {
      size += datasz + DATASZ_SIZE;
    }
    else {
      size += datasz - hidx.datasz;
    }
  }
  else {
    direct = false;
    datasz = hidx.datasz;
  }

  if (data_grouped_by_key && !direct) {
#ifdef CHECK_CHAIN
    CListHeader chd2;
    s = readCListHeader(x, chd2);
    if (s)
      return s;
    
    checkChain(&chd2, "before remove");
#endif
    Boolean found = False;
    unsigned int datacnt = 0;
    s = remove_perform(key, 0, 0, &found, &rdata, &datacnt, 0, xdata_v_cnt);
    if (s)
      return s;

#ifdef TRACE_DGK
    printf("remove_perform(found=%d)\n", found);
#endif
    if (!found) {
      rdata = new unsigned char[data_group_sz(xdata_v_cnt, this)];
    }

    //  size += data_group_sz(datacnt, this);
    //  size += data_group_sz(datacnt, this) + (xdata_v_cnt - 1) * hidx.datasz;
    size += data_group_sz(datacnt + xdata_v_cnt - 1, this);
#ifdef TRACE_DGK
    printf("insert(datacnt = %d)\n", datacnt);
#endif
    for (unsigned int nn = 0; nn < xdata_v_cnt; nn++) {
      memcpy(rdata + data_group_sz(datacnt + nn, this), xdata_v[nn], hidx.datasz);
    }
    datacnt += xdata_v_cnt;
#ifdef VARSZ_DATACNT
    s = h2x_datacnt_cpy(rdata, &datacnt);
    if (s)
      return s;
#else
    h2x_32_cpy(rdata, &datacnt);
#endif
    xdata = (const void *)rdata;
    datasz = data_group_sz(datacnt, this);
    
    /*
      1. one must search for key
      2. if (found) {
      get the entry (ddata and dsize) : datacnt data(s)
      copy the entry : new unsigned char[dsize + datasz], memcpy(ndata, ddata, dsize)
      recompute the size : size += datasz
      remove the full entry by calling removeDataGroup
      [add W: ++datacnt data(s)+datai by calling insertDataGroup()]:
      memcpy(ndata + dsize, data, datasz)
      ++ndata.datacnt
      xdata = ndata
      => all in only one index scan
      }
      else {
      create the entry : ndata = new unsigned char[size + sizeof(datacnt)]
      recompute the size : size += sizeof(datacnt)
      ndata.datacnt = 1;
      memcpy(ndata + sizeof(datacnt), data, datasz)
      xdata = ndata
      }
      // at the end of the method: delete [] ndata
    */
  }
  else {
    if (xdata_v_cnt == 1) {
      xdata = xdata_v[0];
    }
    else {
      assert(!xdatasz);
      // 18/09/07: this is wrong !!
      rdata = new unsigned char[hidx.datasz * xdata_v_cnt];
      for (unsigned int nn = 0; nn < xdata_v_cnt; nn++) {
	memcpy(rdata + nn * hidx.datasz, xdata_v[nn], hidx.datasz);
      }
      xdata = (const void *)rdata;
    }
  }

  CListHeader chd;
  s = readCListHeader(x, chd);
  if (s)
    return s;

#ifdef CHECK_CHAIN
  checkChain(&chd, "before getcell");
#endif

  CellHeader o;
  CListObjHeader h;
  Oid koid;
  int offset = 0;
  s = getCell(size, chd, x, koid, h, offset, o);
  if (s) {
    delete [] rdata;
    return s;
  }

#ifdef CHECK_CHAIN
  CListHeader chd2;
  s = readCListHeader(x, chd2);
  if (s)
    return s;

  checkChain(&chd2, "after getcell");
#endif

#ifdef TRACK_MAP
  printf("GETTING CELL offset=%d, koid=%s\n", offset,
	 getOidString(&koid));
#endif

#ifdef TRACK_MAP_2
  (void)dumpMemoryMap(chd, "before inserting ");
#endif
  s = insert_realize(chd, x, key, size, xdata, koid, h, offset, o, datasz);
#ifdef TRACK_MAP_2
  (void)dumpMemoryMap(chd, "after inserting ");
#endif
  delete [] rdata;

#ifdef CHECK_CHAIN
  s = readCListHeader(x, chd2);
  if (s)
    return s;
    
  checkChain(&chd2, "after insert_realize");
#endif
  return s;
}

Status
HIdx::suppressCell(int offset, CListObjHeader &h, const Oid &koid) const
{
  Status s;
  CellHeader o;
  s = readCellHeader(offset, koid, o);
  if (s)
    return s;
#ifdef TRACK_MAP
  printf("suppressing cell at #%d size %d free_first is %d free_prev %d "
	 "free_next %d\n", offset, o.size, h.cell_free_first, o.cell_free_prev,
	 o.cell_free_next);
#endif
  CellHeader po, no;
  if (o.cell_free_prev != NullOffset) {
    s = readCellHeader(o.cell_free_prev, koid, po);
    if (s)
      return s;
    po.cell_free_next = o.cell_free_next;
    s = writeCellHeader(o.cell_free_prev, koid, po);
    if (s)
      return s;
  }
  else
    h.cell_free_first = o.cell_free_next;

  if (o.cell_free_next != NullOffset) {
    s = readCellHeader(o.cell_free_next, koid, no);
    if (s)
      return s;
    no.cell_free_prev = o.cell_free_prev;
    s = writeCellHeader(o.cell_free_next, koid, no);
    if (s)
      return s;
  }

#ifdef TRACK_MAP
  printf("now free_first %d\n", h.cell_free_first);
#endif
  h.free_cnt--;
  h.free_whole -= o.size;
  o.cell_free_next = NullOffset;
  o.cell_free_prev = NullOffset;
  o.free = 0;
  return writeCellHeader(offset, koid, o);
}

Status
HIdx::insertCell(int offset, unsigned int size, CListObjHeader &h,
		    const Oid &koid) const
{
#ifdef TRACK_MAP
  printf("inserting cell at #%d size %d [free_first %d]\n", offset, size,
	 h.cell_free_first);
#endif
  CellHeader o;
  o.size = size;
  o.free = 1;
  o.cell_free_next = h.cell_free_first;
  o.cell_free_prev = NullOffset;

  if (h.cell_free_first != NullOffset) {
    CellHeader po;
    Status s = readCellHeader(h.cell_free_first, koid, po);
    if (s)
      return s;
#ifdef TRACK_MAP
    printf("making prev link for #%d -> #%d next #%d\n", h.cell_free_first, offset, po.cell_free_next);
#endif
    assert(po.free);
    po.cell_free_prev = offset;
    bool old_dont_check = dont_check;
    dont_check = true;
    s = writeCellHeader(h.cell_free_first, koid, po);
    dont_check = old_dont_check;
    if (s)
      return s;
#ifdef TRACK_MAP
    s = readCellHeader(h.cell_free_first, koid, po);
    if (s)
      return s;
    printf("PO.offset = %d\n", po.cell_free_prev);
#endif
  }

  h.cell_free_first = offset;
  h.free_cnt++;
  h.free_whole += o.size;
  return writeCellHeader(offset, koid, o);
}

//#define SIMPLE_REMOVE
#ifdef SIMPLE_REMOVE
  h.free_whole += o->size;
  CellHeader co;
  co.free = 1;
  co.size = o->size;
  co.next = h.cell_free_first;
  int offset = (eyedblib::int32)(curcell - start);
  h.cell_free_first = offset;
  h.free_cnt++;
  h.alloc_cnt--;
#endif

Status
HIdx::remove_realize(CListHeader *chd, unsigned int chd_k,
			const char *curcell, const char *prevcell,
			const char *start, const CellHeader *o,
			const Oid *koid)
{
  Status s;
  CListObjHeader h;

  mcp(&h, start, sizeof(CListObjHeader));
  x2h_header(&h);

  CellHeader no, po;
  const char *nextcell = curcell + sizeof(CellHeader) + o->size;
  if ((eyedblib::int32)(nextcell - start) < h.size) {
    mcp(&no, nextcell, sizeof(CellHeader));
    x2h_overhead(&no);
  }
  else
    no.free = 0;

  if (prevcell) {
    mcp(&po, prevcell, sizeof(CellHeader));
    x2h_overhead(&po);
  }
  else
    po.free = 0;

#ifdef TRACK_MAP
  printf("co = #%d, no = #%d, po = #%d\n", curcell-start,
	 (curcell-start) + sizeof(CellHeader) + o->size,
	 (prevcell ? prevcell-start : 0));
  printf("fo = #%d", h.cell_free_first);
#endif
  CellHeader fo;
  if (h.cell_free_first >= 0) {
    mcp(&fo, h.cell_free_first + start, sizeof(CellHeader));
    x2h_overhead(&fo);
#ifdef TRACK_MAP
    printf(", fo.free = %d, fo.size = %d, fo.next = %d",
	   fo.free, fo.size, fo.cell_free_next);
#endif
  }

#ifdef TRACK_MAP
  printf("\n");
#endif

  if (no.free && po.free) {
    s = suppressCell(prevcell-start, h, *koid);
    if (s)
      return s;
    s = suppressCell(nextcell-start, h, *koid);
    if (s)
      return s;
    s = insertCell(prevcell-start,
		   o->size + po.size + no.size + 2 * sizeof(CellHeader),
		   h, *koid);
    if (s)
      return s;

      //h.free_whole += o->size + 2 * sizeof(CellHeader);
#ifdef TRACK_MAP
      printf("case no.free && po.free\n");
#endif
    }
  else if (no.free) {
    s = suppressCell(nextcell-start, h, *koid);
    if (s)
      return s;
      // 24/04/07: BUG ?
    s = insertCell(curcell-start,
		   o->size + no.size + sizeof(CellHeader),
		   h, *koid);
    //h.free_whole += o->size + sizeof(CellHeader);
#ifdef TRACK_MAP
    printf("case no.free\n");
#endif
    }
  else if (po.free) {
    // WARNING: 24/04/07 these 2 lines have been swapped !
    s = suppressCell(prevcell-start, h, *koid);
    if (s)
      return s;
    s = insertCell(prevcell-start,
		   o->size + po.size + sizeof(CellHeader),
		   h, *koid);
      //h.free_whole += o->size + sizeof(CellHeader);
#ifdef TRACK_MAP
      printf("case po.free\n");
#endif
    }
  else {
    s = insertCell(curcell-start, o->size, h, *koid);
    if (s)
      return s;
      //h.free_whole += o->size;
#ifdef TRACK_MAP
      printf("case *no* free\n");
#endif
    }
  
  // EV: 3/05/07: WHY ??
  h.alloc_cnt--;

  Boolean rmobj = False;
  if (!h.alloc_cnt) {
    s = suppressObjectFromFreeList(*chd, chd_k, h, *koid);
    if (s)
      return s;
    s = suppressObjectFromList(*chd, chd_k, h, *koid);
    if (s)
      return s;
    rmobj = True;
  }
  else if (!inFreeList(h, *chd, *koid)) {
    s = insertObjectInFreeList(*chd, chd_k, h, *koid);
    if (s)
      return s;
  }

  //printf("writing header %d: po.free %d, no.free %d %d %d %d\n", !rmobj, po.free, no.free, h.alloc_cnt, h.cell_free_first, h.free_cnt);
  if (!rmobj) {
    s = writeCListObjHeader(*koid, h);
    if (s)
      return s;
  }

#ifdef TRACK_MAP
  CListObjHeader xh;
  h2x_header(&xh, &h);
  memcpy((void *)start, &xh, sizeof(xh));
#endif

  return count_manage(dbh, -1);
}

#define get_off(X, THIS) \
 ((THIS)->hidx.keysz != HIdx::VarSize ? (THIS)->hidx.keysz : strlen(X) + 1)

Status HIdx::remove(const void *key, const void *data, unsigned int datasz, Boolean *found)
{
  if (!isDataVarSize() && hidx.datasz != datasz) {
    return statusMake(ERROR, "Fixed size hash index: the data size must be equals to %u", hidx.datasz);
  }

  return remove_perform(key, data, datasz, found, 0, 0, 0, 0);
}

Status HIdx::remove(const void *key, const void *xdata, Boolean *found)
{
  if (isDataVarSize()) {
    return statusMake(ERROR, "Variable data size hash index: the data size must be given at removing, use HIdx::remove(const void *key, const void *data, unsigned int datasz, Boolean *found)");
  }

  unsigned char *rdata = 0;

  if (data_grouped_by_key) {
    Boolean xfound = False;
    unsigned int datacnt = 0;
    int found_idx = -1;
    Status s = remove_perform(key, xdata, 0, &xfound, &rdata, &datacnt, &found_idx, 0);
    if (s)
      return s;

    if (found)
      *found = xfound;

    if (!xfound)
      return Success;

#ifdef TRACE_DGK
    printf("found_idx %d\n", found_idx);
#endif
    assert(found_idx >= 0);
    if (--datacnt) {
      memmove(rdata + data_group_sz(found_idx, this),
	      rdata + data_group_sz(found_idx + 1, this),
	      (datacnt - found_idx) * hidx.datasz);
#ifdef VARSZ_DATACNT
      s = h2x_datacnt_cpy(rdata, &datacnt);
      if (s)
	return s;
#else
      h2x_32_cpy(rdata, &datacnt);
#endif
#ifdef TRACE_DGK
      printf("insert_perforn(%d)\n", data_group_sz(datacnt, this));
#endif
      s = insert_perform(key, rdata, data_group_sz(datacnt, this));
    }
    delete [] rdata;
    return s;
  }
  else {
    return remove_perform(key, xdata, 0, found, 0, 0, 0, 0);
  }
}

Status
HIdx::remove_perform(const void *key, const void *xdata, unsigned int datasz, Boolean *found, unsigned char **prdata, unsigned int *pdatacnt, int *found_idx, unsigned int incr_alloc)
{
  Status s;
  
  if (stat)
    return stat;

  if (s = checkOpened())
    return s;

  if (!datasz) {
    datasz = hidx.datasz;
  }

#ifdef CACHE_FOR_LOCK
  // remove(const void *key, const void *xdata, found?)
  // oplist.insertObjectLast(new RMVLink(this, key, xdata, ?found));
  // return Success;

  // TRES IMPORTANT : il faut changer la stratégie relative au found, par
  // exemple :
  // remove(const void *key, const void *xdata,
  //        Status (*if_not_found)(void *arg) = 0, void *arg = 0)
  // oplist.insertObjectLast(new RMVLink(this, key, xdata, if_not_found, arg));
  // return Success;
  // Mais ce système risque (1) d'être contraignant pour l'utilisateur
  // de cette méthode, (2) de poser un pb de memory leak si arg est un
  // pointeur d'une spécialement allouée pour if_not_found : il faudrait alors
  // une autre fonction releaarg(void *) ou bien :
  // struct IfNotFound {
  //   private : void *arg;
  //   public: Status ifnot();
  //   public: Status release();
  // }; et remove(...., IfNotFound *if_not_found) en dernier argument !
  // autre solution : on supprime l'argument pour found et le client
  // devra faire Idx::search avant s'il veut savoir si la key/data existe
  // ou non
  // à noter que cela est utilisé uniquement dans : attr.cc et idbkern.cc
#endif
  if (found)
    *found = False;

  unsigned int x;
  unsigned int (*gkey)(int) = get_gkey(version);
  s = get_key(x, key);
  if (s)
    return s;

#ifdef TRACK_MAP
  printf("\nREMOVE at #%d\n", x);
#endif
  IdxLock lockx(dbh, treeoid);
  s = lockx.lock();
  if (s)
    return s;

  CListHeader chd;
  s = readCListHeader(x, chd);
  if (s)
    return s;

#ifdef IDX_DBG
  if (STRTYPE(this)) {
      printf("hidx: removing '%s' '%s'\n", key, getOidString((const Oid *)xdata));
    }
#endif
  Oid koid = chd.clobj_first;
  while (koid.getNX() > 0) {
    size_t size; // V3_API_size_t
      s = objectSizeGet(dbh, &size, DefaultLock, &koid);
      if (s)
	statusPrint(s, "HIdx::remove() treeoid %s", getOidString(&treeoid));

      if (s)
	return s;

      char *start = (char *)m_malloc(size);
      s = objectRead(dbh, 0, size, start, DefaultLock, 0, 0, &koid);
      
      if (s) {
	  free(start);
	  return s;
	}
      
      char *curcell, *end = start + size, *prevcell = 0;
      for (curcell = start + sizeof(CListObjHeader); curcell < end; ) {
	  CellHeader o;
	  mcp(&o, curcell, sizeof(CellHeader));
	  x2h_overhead(&o);
	  curcell += sizeof(CellHeader);
	  
	  if (!o.free && !cmp(key, curcell, OP2_SWAP)) {
	    int r = 1;
	    if (prdata) {
	      assert(data_grouped_by_key);
	      assert(pdatacnt);
#ifdef VARSZ_DATACNT
	      s = x2h_datacnt_cpy(pdatacnt, (unsigned char *)(curcell + get_off(curcell, this)));
	      if (s)
		return s;
#else
	      x2h_32_cpy(pdatacnt, curcell + get_off(curcell, this));
#endif
#ifdef TRACE_DGK
	      printf("DATACNT %d\n", *pdatacnt);
#endif
	      unsigned int size;
	      if (xdata) {
		assert(found_idx);
		*found_idx = -1;
		for (unsigned int n = 0; n < *pdatacnt; n++) {
		  r = memcmp(xdata, curcell + get_off(curcell, this) + data_group_sz(n, this), datasz);
		  if (!r) {
		    *found_idx = n;
		    break;
		  }
		}
		assert(!incr_alloc);
		size = data_group_sz(*pdatacnt, this);
	      }
	      else {
		size = data_group_sz((*pdatacnt)+incr_alloc, this);
		r = 0;
	      }

	      unsigned int cpsize = data_group_sz(*pdatacnt, this);
	      *prdata = new unsigned char[size];
	      memcpy(*prdata, curcell + get_off(curcell, this), cpsize);
	    }
	    else {
#ifdef BUG_DATA_STORE2
	      if (isDataVarSize()) {
		unsigned int xdatasz;
		memcpy(&xdatasz, curcell + get_off(curcell, this), DATASZ_SIZE);
		unsigned ndatasz = x2h_u32(xdatasz);
		if (ndatasz != datasz) {
		  r = -1;
		}
		else {
		  r = memcmp(xdata, curcell + get_off(curcell, this) + DATASZ_SIZE, datasz);
		}
	      }
	      else {
		r = memcmp(xdata, curcell + get_off(curcell, this), datasz);
	      }
#else
	      assert(0);
	      r = memcmp(xdata, curcell + o.size - datasz, datasz);
#endif
	    }
	    if (!r) {
#ifdef TRACK_MAP
	      CListObjHeader h;
	      memcpy(&h, start, sizeof(h));
	      x2h_header(&h);
	      dumpMemoryMap(chd, "before remove_realize ");
#endif
	      s = remove_realize(&chd, x, curcell - sizeof(CellHeader),
				 prevcell, start, &o, &koid);
#ifdef TRACK_MAP
	      memcpy(&h, start, sizeof(h));
	      x2h_header(&h);
	      dumpMemoryMap(chd, "after remove_realize ");
#endif

	      if (!s && found) {
		*found = True;
	      }
	      free(start);
	      return s;
	    }
	  }
	  
	  prevcell = curcell - sizeof(CellHeader);
	  curcell += o.size;
	}

      CListObjHeader h;
      mcp(&h, start, sizeof(CListObjHeader));
      x2h_header(&h);
      //koid = h.clobj_free_next;
      koid = h.clobj_next;
      free(start);
    }

  return Success;
}

unsigned int
HIdx::getCount() const
{
  return hidx.object_count;
}

short
HIdx::getDefaultDspid() const
{
  return hidx.dspid;

}

void
HIdx::setDefaultDspid(short dspid)
{
  hidx.dspid = dspid;
  dspid = h2x_16(dspid);
  objectWrite(dbh, 4*sizeof(unsigned int), sizeof(short),
		 &dspid, &treeoid);
}

static void
add(Oid *&oids, unsigned int &cnt, unsigned int &alloc_cnt,
    const Oid &oid)
{
  if (cnt >= alloc_cnt) {
    alloc_cnt = cnt + 32;
    oids = (Oid *)m_realloc(oids, alloc_cnt * sizeof(Oid));
  }

  oids[cnt++] = oid;
}

static const char *
implHintsStr(int hints)
{
  if (hints == HIdx::IniSize_Hints)
    return "Initial Size";

  if (hints == HIdx::IniObjCnt_Hints)
    return "Initial Object Count";

  if (hints == HIdx::XCoef_Hints)
    return "Extends Coeficient";

  if (hints == HIdx::SzMax_Hints)
    return "Maximal Hash Object Size";

  if (hints == HIdx::DataGroupedByKey_Hints)
    return "Data Grouped by Key";

  return "<unimplemented>";
}

std::string
HIdx::_Idx::toString() const
{
  std::string s;
  s = std::string("Key Count: ") + str_convert((unsigned long)key_count);
  s += std::string("Magnitude Order: ") + str_convert((unsigned long)mag_order);
  s += std::string("Object Count: ") + str_convert((unsigned long)object_count);
  s += std::string("Dataspace ID: ") + str_convert((long)(dspid == DefaultDspid ? -1 : dspid));
  s += std::string("Key Type: ") + typeString((Idx::Type)keytype);
  s += std::string("Key Size: ") + str_convert((long)keysz);
  s += std::string("Data Size: ") + str_convert((long)datasz);
  s += std::string("Data Offset: ") + str_convert((long)offset);
  s += "Implementation Hint:\n";
  for (int i = 0; i < HIdxImplHintsCount; i++)
    s += std::string("  ") + implHintsStr(i) + ": " + str_convert((long)impl_hints[i]);
  return s;
}

void
HIdx::_Idx::trace(FILE *fd) const
{
  fprintf(fd, "Key Count: %d\n", key_count);
  fprintf(fd, "Magnitude Order: %u\n", mag_order);
  fprintf(fd, "Object Count: %u\n", object_count);
  fprintf(fd, "Dataspace ID: %d\n", (dspid == DefaultDspid ? -1 : dspid));
  fprintf(fd, "Key Type: %s\n", typeString((Idx::Type)keytype));
  fprintf(fd, "Key Size: %d\n", keysz);
  fprintf(fd, "Data Size: %d\n", datasz);
  fprintf(fd, "Data Offset: %d\n", offset);
  fprintf(fd, "Implementation Hint:\n");
  for (int i = 0; i < HIdxImplHintsCount; i++)
    fprintf(fd, "  %s: %d\n", implHintsStr(i), impl_hints[i]);
}

Status
HIdx::getObjects(Oid *&oids, unsigned int &cnt) const
{
  unsigned int alloc_cnt = 0;
  cnt = 0;
  oids = 0;
  unsigned int (*gkey)(int) = get_gkey(version);

  for (int i = 0; i < hidx.key_count; i++) {
    HIdx::CListHeader chd;
    Status s = readCListHeader(i, chd);
    if (s)
      return s;

    Oid koid = chd.clobj_first;
    while (koid.getNX()) {
      add(oids, cnt, alloc_cnt, koid);
      HIdx::CListObjHeader h;
      s = objectRead(dbh, 0, sizeof(HIdx::CListObjHeader), &h,
			DefaultLock, 0, 0, &koid);
      if (s)
	return s;
      x2h_header(&h);
      koid = h.clobj_next;
    }
  }

  return Success;
}

static const char* SIMULATE_SKIP_COLLAPSE = getenv("SIMULATE_SKIP_COLLAPSE");
static const int SIMULATE_SKIP_COLLAPSE_IND = SIMULATE_SKIP_COLLAPSE ? atoi(SIMULATE_SKIP_COLLAPSE) : -1;

static void adapt(unsigned char *&clist_data,
		  size_t &clist_data_size, // EV: 2015-03-04: changed unsigned int to size_t
		  size_t &clist_data_alloc_size, // EV: 2015-03-04: changed unsigned int to size_t
		  unsigned int size)
{
  if (clist_data_size + size > clist_data_alloc_size) {
    size_t wanted_size = clist_data_size + size;
    double coef = wanted_size > 0x7FFFFFFFULL ? 1.20 : 2.;
    clist_data_alloc_size = (size_t)(wanted_size * 2);
    unsigned char *n_clist_data = new unsigned char[clist_data_alloc_size];
    memcpy(n_clist_data, clist_data, clist_data_size);
    delete [] clist_data;
    clist_data = n_clist_data;
  }
}

Status
HIdx::collapse(HIdx::PostCollapseTransformer *post_collapse_transformer)
{
  return collapse_realize(hidx.dspid, 0, post_collapse_transformer);
}

//#define COLLAPSE_TRACE

Status
HIdx::collapse_realize(short dspid, HIdx *idx_n, HIdx::PostCollapseTransformer *post_collapse_transformer)
{
  IdxLock lockx(dbh, treeoid);
  Status s = lockx.lock();
  if (s)
    return s;

  size_t clist_data_alloc_size = 0; // EV: 2015-03-04: changed unsigned int to size_t
  unsigned char *clist_data = 0;
  unsigned int clistobj_data_alloc_size = 0;
  unsigned char *clistobj_data = 0;

  for (unsigned int chd_k = 0; chd_k < hidx.key_count; chd_k++) {
    HIdx::CListHeader chd;
    s = readCListHeader(chd_k, chd);
    if (s)
      return s;

    unsigned int clistobj_cnt = 0;
    Oid koid = chd.clobj_first;
    std::vector<Oid> oid_v;
    if (koid.getNX()) {
#ifdef COLLAPSE_TRACE
      printf("Key #%d {\n", chd_k);
#endif
      unsigned int total_busy_cell_cnt = 0;
      size_t total_busy_size = 0;
      size_t total_free_size = 0;
      size_t clist_data_size = 0; // EV: 2015-03-04: changed unsigned int to size_t
      adapt(clist_data, clist_data_size, clist_data_alloc_size, sizeof(CListObjHeader));
      clist_data_size = sizeof(CListObjHeader);

      while (koid.getNX()) {
	oid_v.push_back(koid);
	unsigned int busy_size = 0;
	unsigned int free_size = 0;
	unsigned int busy_cell_cnt = 0;
	size_t sz = 0; // V3_API_size_t
	s = objectSizeGet(dbh, &sz, DefaultLock, &koid);
	if (s)
	  return s;

	if (sz > clistobj_data_alloc_size) {
	  delete [] clistobj_data; // EV: 2015-03-04
	  clistobj_data_alloc_size = sz + 1024; // + ONE_K: EV: 2015-03-04
	  clistobj_data = new unsigned char[clistobj_data_alloc_size];
	}

	CListObjHeader h;
	s = objectRead(dbh, 0, 0, clistobj_data, DefaultLock, 0, 0, &koid);
	if (s) {
	  return s;
	}
	unsigned char *d, *edata = clistobj_data + sz;
	for (d = clistobj_data + sizeof(CListObjHeader); d < edata; ) {
	  CellHeader o;
	  mcp(&o, d, sizeof(CellHeader));
	  x2h_overhead(&o);
	  if (!o.free) {
	    total_busy_size += o.size;
	    busy_size += o.size;
	    unsigned int cpsize = o.size + sizeof(CellHeader);
	    adapt(clist_data, clist_data_size, clist_data_alloc_size, cpsize);
	    memcpy(clist_data + clist_data_size, d, cpsize);
	    clist_data_size += cpsize;
	    busy_cell_cnt++;
	    total_busy_cell_cnt++;
	  } else {
	    total_free_size += o.size;
	    free_size += o.size;
	  }

	  d += sizeof(CellHeader);
	  d += o.size;
	}
#ifdef COLLAPSE_TRACE
	printf("  KOID %s [%d B] {\n", getOidString(&koid), sz);
	printf("    busy_cell_cnt: %d\n", busy_cell_cnt);
	printf("    busy_size: %u B\n", busy_size);
	printf("    free_size: %u B\n", free_size);
	printf("  }\n");
#endif
	memcpy(&h, clistobj_data, sizeof(h));
	x2h_header(&h);
	koid = h.clobj_next;
	clistobj_cnt++;
      }

      //if (SIMULATE_SKIP_COLLAPSE_IND >= 0 && chd_k == (unsigned int)SIMULATE_SKIP_COLLAPSE_IND) {
      if (clist_data_size >= MAXOBJSIZE) {
	delete [] clistobj_data;
	delete [] clist_data;
#ifdef COLLAPSE_TRACE
	printf("collapsing phase: error cannot collapse index entry #%u size too large %llu", chd_k, clist_data_size);
#endif
	return statusMake(COLLAPSING_LIMIT, "collapsing phase: warning cannot collapse index entry #%u size too large %llu", chd_k, clist_data_size);
      }

      if (idx_n || (clistobj_cnt > 1 && total_free_size != 0)) {
	CListObjHeader h;
	memset(&h, 0, sizeof(h));
	h.free_cnt = 0;
	// JE PENSE QUE CELA EST FAUX: alloc_cnt indique le nombre de cells
	// et pas le nombre de hashobject
	// h.alloc_cnt = busy_cell_cnt; ???
	//h.alloc_cnt = 1;
	h.alloc_cnt = total_busy_cell_cnt;
	h.free_whole = 0;
	h.cell_free_first = NullOffset;
	CListObjHeader xh;
	h2x_header(&xh, &h);
	memcpy(clist_data, &xh, sizeof(xh));
	
	memset(&chd, 0, sizeof(chd));
	//assert(!skip_entry);
#ifdef COLLAPSE_TRACE
	printf("  created collapsed object %lld\n", clist_data_size);
#endif
	if (NULL != post_collapse_transformer) {
	  post_collapse_transformer->reset();
#ifdef COLLAPSE_TRACE
	  printf("total_busy_cell_cnt %lld\n", total_busy_cell_cnt);
#endif
	  unsigned char *edata = clist_data + clist_data_size;
	  unsigned char *d;
	  int cell_num = 0;
	  for (d = clist_data + sizeof(CListObjHeader); d < edata; ) {
	    CellHeader o;
	    mcp(&o, d, sizeof(CellHeader));
	    x2h_overhead(&o);
	    assert(!o.free);
	    //printf("cell #%d [%s] %u\n", cell_num, d + sizeof(CellHeader), o.size);
	    const char* d_str = (const char*)d + sizeof(CellHeader);
	    size_t d_len = strlen(d_str) + 1;
	    unsigned int xdatasz;
	    memcpy(&xdatasz, d_str + d_len, DATASZ_SIZE);
	    unsigned int datasz = x2h_u32(xdatasz);
	    post_collapse_transformer->add(d_str, datasz, (const unsigned char*)d_str + d_len + DATASZ_SIZE);
	    d += sizeof(CellHeader);
	    d += o.size;
	    cell_num++;
	  }

	  size_t rdata_size;
	  unsigned char* rkey;
	  unsigned char* rdata;
	  clist_data_size = sizeof(CListObjHeader);
	  size_t total_cnt = 0;
	  while((rdata_size = post_collapse_transformer->next(rkey, rdata)) != 0) {
	    size_t d_len = strlen((const char*)rkey) + 1;

	    CellHeader o;
	    o.free = 0;
	    o.cell_free_prev = 0;
	    o.cell_free_next = 0;
	    o.size = d_len + DATASZ_SIZE + rdata_size;

	    adapt(clist_data, clist_data_size, clist_data_alloc_size, sizeof(CellHeader) + o.size);

	    CellHeader to;
	    h2x_overhead(&to, &o);
	    d = clist_data + clist_data_size;
	    mcp(d, &to, sizeof(to));

	    d += sizeof(CellHeader);
	    memcpy(d, rkey, d_len);

	    d += d_len;
	    unsigned int xrdata_size = h2x_u32(rdata_size);
	    mcp(d, &xrdata_size, sizeof(xrdata_size));
	    d += DATASZ_SIZE;

	    memcpy(d, rdata, rdata_size);

	    clist_data_size += sizeof(CellHeader) + o.size;
	    total_cnt++;
	  }
	  CListObjHeader h;
	  memset(&h, 0, sizeof(h));
	  h.free_cnt = 0;
	  h.alloc_cnt = total_cnt;
	  h.free_whole = 0;
	  h.cell_free_first = NullOffset;
	  CListObjHeader xh;
	  h2x_header(&xh, &h);
	  memcpy(clist_data, &xh, sizeof(xh));
#ifdef COLLAPSE_TRACE
	  printf("  created collapsed after transform %lld %d\n", clist_data_size, total_cnt);
#endif
	}
	s = objectCreate(dbh, clist_data, clist_data_size, dspid, &chd.clobj_first);
	if (s)
	  return s;
	
	// Corrected: 4/03/08
	//chd.clobj_last = chd.clobj_last;
	chd.clobj_last = chd.clobj_first;
	
	if (idx_n) {
	  s = idx_n->writeCListHeader(chd_k, chd);
	}
	else {
	  s = writeCListHeader(chd_k, chd);
	}

	if (s)
	  return s;

#ifdef COLLAPSE_TRACE
	printf("  collapse oids: %s\n", getOidString(&chd.clobj_first));
#endif
	if (!idx_n) {
	  std::vector<Oid>::iterator begin = oid_v.begin();
	  std::vector<Oid>::iterator end = oid_v.end();
	  unsigned int del_obj_cnt = 0;
	  while (begin != end) {
	    s = objectDelete(dbh, &(*begin));
	    if (s)
	      return s;
	    ++begin;
	    del_obj_cnt++;
	  }
#ifdef COLLAPSE_TRACE
	  printf("  deleted obj: %d\n", del_obj_cnt);
#endif
	}
      }
#ifdef COLLAPSE_TRACE
      else
	printf("  NO COLLAPSE\n");
#endif

      // must delete all koid
#ifdef COLLAPSE_TRACE
      printf("  clistobj_cnt: %u\n", clistobj_cnt);
      printf("  total_busy_cell_cnt: %u\n", total_busy_cell_cnt);
      printf("  total_busy_size: %llu B\n", total_busy_size);
      printf("  total_free_size: %llu B\n", total_free_size);
      printf("  clist_data_size: %llu\n", clist_data_size);
      printf("  clist_data_alloc_size: %llu\n", clist_data_alloc_size);
      printf("}\n");
#endif
    }
  }

  if (idx_n) {
    idx_n->hidx.object_count = hidx.object_count;
    unsigned int count = h2x_u32(idx_n->hidx.object_count);
    s = objectWrite(dbh, sizeof(unsigned int),
		    sizeof(unsigned int), &count, &idx_n->treeoid);
    if (s)
      return s;
  }

  delete [] clistobj_data;
  delete [] clist_data;
  return Success;
}

int
HIdx::cmp(const void *key, const void *d, unsigned char bswap) const
{
  return compare(key, d, &keytype, bswap);
}

Status HIdx::searchAny(const void *key, Boolean *found, void *xdata)
{
  if (isDataVarSize() && xdata) {
    return statusMake(ERROR, "Variable data size hash index: cannot use the HIdx::searchAny(const void *key, Boolean *found, void *data) method when data is not null");
  }

  unsigned int found_cnt;
  Status s = search_realize(key, &found_cnt, True, xdata);
  if (s) {
    return s;
  }
  *found = (found_cnt != 0) ? eyedbsm::True : eyedbsm::False;
  return Success;
}

Status HIdx::search(const void *key, unsigned int *found_cnt)
{
  return search_realize(key, found_cnt, False, 0);
}

Status HIdx::search_realize(const void *key, unsigned int *found_cnt, Boolean found_any, void *xdata)
{
  Status s;
  
  if (stat)
    return stat;

  if (s = checkOpened())
    return s;

  unsigned int x;

  *found_cnt = 0;

  unsigned int (*gkey)(int) = get_gkey(version);
  s = get_key(x, key);
  if (s)
    return s;

  CListHeader chd;
  s = readCListHeader(x, chd);
  if (s)
    return s;

  // EV: 23/04/07 it seems tchd this method search key, and can find it several time:
  // but the returned xdata will contained the last data and the count
  // will not be returned (only found == true)
  // => we changed this method by (at least) changing Boolean found to unsigned int found_cnt
  // or we add a break in case of *found == true as shown below:
  // idea:
  // 1. add the break, and rename the methode searchAny
  // 2. add a methode ::search(const void *key, unsigned int *found_cnt)
  Oid koid = chd.clobj_first;
  while (koid.getNX() > 0) {
    if (backend_interrupt)
      return statusMake(BACKEND_INTERRUPTED, "");
    size_t size; // V3_API_size_t
    Status s = objectSizeGet(dbh, &size, DefaultLock, &koid);
    if (s)
      return s;
    char *data = (char *)m_malloc(size);
    s = objectRead(dbh, 0, size, data, DefaultLock, 0, 0, &koid);
      
    if (s) {
      free(data);
      return s;
    }
      
    char *d, *edata = data + size;
    for (d = data + sizeof(CListObjHeader); d < edata; ) {
      CellHeader o;
      mcp(&o, d, sizeof(CellHeader));
      x2h_overhead(&o);
      d += sizeof(CellHeader);

      if (!o.free && !cmp(key, d, OP2_SWAP)) {
	unsigned int offset;
	if (data_grouped_by_key) {
	  unsigned int datacnt;
#ifdef VARSZ_DATACNT
	  s = x2h_datacnt_cpy(&datacnt, (unsigned char *)(d + get_off(d, this)));
	  if (s)
	    return s;
#else
	  x2h_32_cpy(&datacnt, d + get_off(d, this));
#endif
	  *found_cnt += datacnt;
	  offset = data_grouped_sizeof;
#if 0
	  for (unsigned int n = 0; n < datacnt; n++) {
	    if (hidx.datasz == sizeof(Oid)) { // perharps an Oid
	      Oid oo;
	      memcpy(&oo, d + get_off(d, this) + data_group_sz(n, this), hidx.datasz);
	      printf("Data oid[%d]: %s\n", n, getOidString(&oo));
	    }
	  }
#endif
	}
	else {
	  offset = 0;
	  (*found_cnt)++;
	}

	if (xdata) {
	  // NOTE: in case of data_grouped_by_key, only one data is copied
#ifdef BUG_DATA_STORE2
	  memcpy(xdata, d + get_off(d, this) + offset, hidx.datasz);
#else
	  memcpy(xdata, d + o.size - hidx.datasz, hidx.datasz);
#endif
	}

	if (found_any)
	  break;
      }
	  
      d += o.size;
    }
      
    CListObjHeader h;
    mcp(&h, data, sizeof(CListObjHeader));
    x2h_header(&h);
    //koid = h.clobj_free_next;
    koid = h.clobj_next;
    free(data);

    // break added in case of *found == true
    if (*found_cnt && found_any) {
      break;
    }
  }

  return Success;
}

Status HIdx::destroy()
{
  Status s = destroy_r();
  if (s)
    return s;
  return objectDelete(dbh, &treeoid);
}

Status HIdx::destroy_r()
{
  for (int n = 0; n < hidx.key_count; n++) {
    CListHeader chd;
    Status s = readCListHeader(n, chd);
    if (s)
      return s;

    Oid koid = chd.clobj_first;

    while (koid.getNX()) {
      CListObjHeader h;
      Status s = readCListObjHeader(koid, h);
      if (s)
	return s;

      s = objectDelete(dbh, &koid);
      if (s)
	return s;

      koid = h.clobj_next;
    }
  }

  return Success;
}

Status
HIdx::headPrint(FILE *fd, int n, Oid *koid, int &count) const
{
  CListObjHeader h;
  Status s = objectRead(dbh, 0, sizeof(CListObjHeader), &h, DefaultLock, 0,
			      0, koid);

  if (s)
    return s;
  x2h_header(&h);

  count = h.alloc_cnt;
  fprintf(fd, "\tsubcell[%d] %s {\n", n, getOidString(koid));
  fprintf(fd, "\t\tsize       = %d;\n", h.size);
  fprintf(fd, "\t\tnfree      = %d;\n", h.free_cnt);
  fprintf(fd, "\t\tnalloc     = %d;\n", h.alloc_cnt);
  fprintf(fd, "\t\tfree_whole = %d;\n", h.free_whole);
  fprintf(fd, "\t\tfirstfree  = %d;\n", h.cell_free_first);
  fprintf(fd, "\t\tprev       = %s;\n", getOidString(&h.clobj_prev));
  fprintf(fd, "\t\tnext       = %s;\n", getOidString(&h.clobj_next));
  fprintf(fd, "\t\tfree_prev  = %s;\n", getOidString(&h.clobj_free_prev));
  fprintf(fd, "\t\tfree_next  = %s;\n", getOidString(&h.clobj_free_next));
  fprintf(fd, "\t};\n");
  *koid = h.clobj_next;

  return Success;
}

Status
HIdx::getHashObjectBusySize(const Oid *koid, unsigned int &osize, unsigned int &count, unsigned int _size) const
{
  if (!STRTYPE(this) && !data_grouped_by_key) {
    CListObjHeader h;
    Status s = objectRead(dbh, 0, sizeof(CListObjHeader), &h, DefaultLock, 0,
				0, koid);
    
    if (s)
      return s;
    x2h_header(&h);
  
    osize = h.alloc_cnt * (sizeof(CellHeader) + hidx.keysz + hidx.datasz) + sizeof(CListObjHeader);
    count = h.alloc_cnt;
    return Success;
  }

  size_t size = _size; // V3_API_size_t
  Status s;
  if (!size) {
    s = objectSizeGet(dbh, &size, DefaultLock, koid);
    if (s)
      return s;
  }

  osize = sizeof(CListObjHeader);

  char *data;
  if (nocopy) {
    s = objectReadNoCopy(dbh, 0, size, &data, DefaultLock, 0, 0, koid);
  }
  else {
    data = (char *)m_malloc(size);
    s = objectRead(dbh, 0, size, data, DefaultLock, 0, 0, koid);
  }

  if (s) {if (!nocopy) free(data); return s;}

  count = 0;
  int cur = sizeof(CListObjHeader);
  while (cur + sizeof(CellHeader) <= size) {
    CellHeader to;
    s = readCellHeader(cur, *koid, to);
    if (s) {if (!nocopy) free(data); return s;}
    cur += sizeof(CellHeader);
    if (!to.free) {
      //      osize += sizeof(CellHeader) + strlen(data+cur)+1 + hidx.datasz;
      osize += sizeof(CellHeader) + to.size;
      if (data_grouped_by_key) {
	unsigned int datacnt;
#ifdef VARSZ_DATACNT
	s = x2h_datacnt_cpy(&datacnt, (unsigned char *)(data + cur + get_off(data + cur, this)));
	if (s)
	  return s;
#else
	x2h_32_cpy(&datacnt, data + cur + get_off(data + cur, this));
#endif
	count += datacnt;
      }
      else
	count++;
    }
    //    printf("SIZES '%s' %d %d %d free=%d\n", data+cur, to.size + sizeof(CellHeader), sizeof(CellHeader) + strlen(data+cur)+1, hidx.datasz, to.free);
    cur += to.size;
  }

  if (!nocopy)
    free(data);
  return Success;
}

Status
HIdx::getEntryCount(Oid *koid, unsigned int &count) const
{
  if (koid->getNX() == 0) {
    count = 0;
    return Success;
  }

  CListObjHeader h;
  Status s = objectRead(dbh, 0, sizeof(CListObjHeader), &h, DefaultLock, 0,
			      0, koid);

  if (s)
    return s;
  x2h_header(&h);

  count = h.alloc_cnt;
  *koid = h.clobj_next;

  return Success;
}

//#define ALL_STATS

Status
HIdx::dumpMemoryMap(FILE *fd)
{
  for (int n = 0; n < hidx.key_count; n++) {
    CListHeader chd;
    Status s = readCListHeader(n, chd);
    if (s)
      return s;
    Oid koid = chd.clobj_first;
    if (!koid.getNX()) continue;
    if (s)
      return s;
    s = dumpMemoryMap(chd, (std::string("Entry #") + str_convert((long)n) + " ").c_str(),
		      fd);
    if (s)
      return s;
  }

  return Success;
}

Status HIdx::printStat(FILE *fd) const
{
  //const Oid *koid;
  int n, total;

  if (!fd)
    fd = stdout;

#ifdef ALL_STATS
  fprintf(fd, "index bsize = 0x%x\n", hidx.impl_hints[IniSize_Hints]);
#endif
  fprintf(fd, "\tkey_count = %d\n", hidx.key_count);
  fflush(fd);

  total = 0;

  for (int n = 0; n < hidx.key_count; n++) {
    CListHeader chd;
    Status s = readCListHeader(n, chd);
    if (s)
      return s;

#ifdef ALL_STATS
    fprintf(fd, "cell[%d] = {\n", n);
    fprintf(fd, "\tfirst      = %s;\n", getOidString(&chd.clobj_first));
    fprintf(fd, "\tlast       = %s;\n", getOidString(&chd.clobj_last));
    fprintf(fd, "\tfree_first = %s;\n", getOidString(&chd.clobj_free_first));
#endif

    Oid toid;
    toid = chd.clobj_first;
    int cell_count = 0;

    while (toid.getNX() > 0) {
      unsigned int count;
      if (backend_interrupt) {
	/*
	fprintf(fd, "Interrupted!\n");
	fprintf(fd, "\tpartial total count = %d\n", total);
	fflush(fd);
	*/
	return statusMake(BACKEND_INTERRUPTED, "");
      }

      s = getEntryCount(&toid, count);
      if (s) {
	statusPrint(s, "");
	fflush(fd);
	return s;
      }
      cell_count += count;
    }
#ifdef ALL_STATS
#ifndef PRINT_DETAILS
    fprintf(fd, "\tcount      = %d;\n", cell_count);
#endif
#else
    if (cell_count) {
      fprintf(fd, "\tcell[%d] -> %d\n", n, cell_count);
      fflush(fd);
    }
#endif
    total += cell_count;
#ifdef ALL_STATS
    fprintf(fd, "};\n\n");
#endif
  }

  fprintf(fd, "\ttotal count = %d [%d]\n", total, getCount());
  fflush(fd);
  return Success;
}

#define ONE_LIST

struct Link {

  Link(unsigned int sz) {
    data = new unsigned char[sz];
    next = 0;
  }

  ~Link() {
    delete [] data;
  }

  Idx::Key key;
  unsigned char *data;
  Link *next;

private:
  // forbidden
  Link(const Link &);
  Link &operator=(const Link &);
};

class HIdxCursor::LinkList {

public:
  LinkList() {first = last = 0; cnt = 0;}

  void insert(Link *l) {
    eyedblib::MutexLocker _(mt);
    if (last)
      last->next = l;
    if (!first)
      first = l;
    last = l;
    cnt++;
  }

  Link *peek() {
    eyedblib::MutexLocker _(mt);
    if (first) {
      Link *l = first;
      first = first->next;
      if (!first) last = 0;
      cnt--;
      return l;
    }
    return 0;
  }

  int getCount() const {
    eyedblib::MutexLocker _(mt);
    return cnt;
  }

  ~LinkList() {
    eyedblib::MutexLocker _(mt);
    Link *l = first;
    while (l) {
      Link *next = l->next;
      delete l;
      l = next;
    }
  }

private:
  mutable eyedblib::Mutex mt;
  Link *first, *last;
  int cnt;
};

extern eyedblib::ThreadPool *getThreadPool();

#define MIN_OBJCNT_FOR_PARALLEL 10
//#define MIN_KEYCNT_FOR_PARALLEL 10

static eyedblib::ThreadPerformerArg
cursor_perform_wrapper(eyedblib::ThreadPerformerArg xarg)
{
  HIdxCursor *cur = (HIdxCursor *)xarg.data;
  for (;;) {
    Boolean found;
    Status s = cur->next(&found);
    if (s)
      return eyedblib::ThreadPerformerArg((void *)s);
    if (!found)
      return 0;
  }
  return 0;
}

static int user_cmp_mod;

static Boolean 
user_cmp(const void *, void *)
{
  static eyedblib::Mutex mt;
  //  eyedblib::MutexLocker _(mt);
  static int cnt;
  for (int n = 0; n < 50; n++) ;
  if (!(cnt++ % user_cmp_mod)) return True;
  return False;
}

Boolean
HIdxCursor::parallelInit(int thread_cnt)
{
  /*
  if ((skey && ekey) || !user_cmp ||
      idx->hidx.object_count <= MIN_OBJCNT_FOR_PARALLEL)
    return False;
  */

  if (thread_cnt < 2 || idx->hidx.object_count <= MIN_OBJCNT_FOR_PARALLEL ||
      (skey && ekey && !idx->cmp(skey, ekey, OPS_NOSWAP))) /*(skey && ekey) || */ // WARNING : 24/02/03 !!
    return False;

  thrpool = getThreadPool();
  if (!thrpool)
    return False;

  perf_cnt = thrpool->getThreadCount();

  if (perf_cnt > thread_cnt)
    perf_cnt = thread_cnt;

  if (perf_cnt < 1)
    return False;

  unsigned int itv = idx->hidx.key_count / perf_cnt;

  if (itv < 1)
    return False;

  /*
  printf("Hash Cursor %s candidate for parallelization: perf_cnt=%d, itv=%d, "
	 "max_threads=%d\n",
	 getOidString(&idx->treeoid),
	 perf_cnt, itv,  thrpool->getThreadCount());
  */

  master = True;
#ifdef MULTI_LIST
  lists = new LinkList*[perf_cnt];
  list = 0;
#else
  list = new LinkList();
  lists = 0;
#endif
  perf_curs = new HIdxCursor*[perf_cnt];

  /*
  const char *s = getenv("ESM_STD_USER_CMP");
  if (s) {
    user_cmp = user_cmp;
    user_cmp_mod = atoi(s);
  }
  */

  for (int n = 0; n < perf_cnt; n++) {
#ifdef MULTI_LIST
    lists[n] = new LinkList();
    perf_curs[n] = new HIdxCursor
      (idx,
       n*itv,
       (n == perf_cnt-1 ? idx->hidx.key_count : (n+1)*itv),
       skey, ekey,
       sexcl, eexcl,
       user_cmp, cmp_arg,
       lists[n]);
#else
    perf_curs[n] = new HIdxCursor
      (idx,
       n*itv,
       (n == perf_cnt-1 ? idx->hidx.key_count : (n+1)*itv),
       skey, ekey,
       sexcl, eexcl,
       user_cmp, cmp_arg,
       list);
#endif
  }

  /*
  s = getenv("ESM_MAX_PERF_CNT");
  if (s) {
    unsigned int cnt = atoi(getenv("ESM_MAX_PERF_CNT"));
    if (perf_cnt > cnt) {
      perf_cnt = cnt;
      printf("limited perf_cnt to %d\n", perf_cnt);
    }
  }
  */

  thrpool->reset();
  perfs = new eyedblib::ThreadPerformer*[perf_cnt];

  for (int n = 0; n < perf_cnt; n++) {
    perfs[n] = thrpool->start(cursor_perform_wrapper, perf_curs[n]);
  }

#ifdef NEW_WAIT
  perf_end_cnt = 0;
#endif
  return True;
}

void HIdxCursor::init(DbHandle *dbh)
{
  state = True;
  master = False;
  slave = False;

  sdata = 0;
  memset(&koid, 0, sizeof(koid));
  skey = ekey = 0;
  sdata = 0;

  perf_cnt = 0;
  perf_curs = 0;
  perfs = 0;
#ifdef FORCE_COPY
  nocopy = False;
#else
  nocopy = isWholeMapped(dbh);
#endif
  data_tofree = False;

  datacnt = 0;
  idata = 0;
  jumpsize = 0;
}

HIdxCursor::HIdxCursor(const HIdx *_idx,
			     unsigned int _k_cur,
			     unsigned int _k_end,
			     const void *_skey, const void *_ekey,
			     Boolean _sexcl, Boolean _eexcl,
			     Boolean (*_user_cmp)(const void *, void *),
			     void *_cmp_arg,
			     LinkList *_list) :
  idx(_idx),
  user_cmp(_user_cmp), cmp_arg(_cmp_arg),
  k_cur(_k_cur), k_end(_k_end), list(_list),
  sexcl(_sexcl), eexcl(_eexcl)
{
  init(idx->dbh);
  if (idx->isDataVarSize()) {
    // cannot have data variable size and parallel mode
    state = False;
    return;
  }
  slave = True;
  equal = False;
  Boolean isstr = (STRTYPE(idx) ? True : False);
  skey = HIdx::copy_key(_skey, idx->hidx.keysz, isstr, &state);
  ekey = HIdx::copy_key((_ekey == defaultSKey) ? _skey : _ekey, idx->hidx.keysz, isstr, &state);
  //printf("k_cur %d -> %d : %d\n", k_cur, k_end, idx->hidx.key_count);
}

HIdxCursor::HIdxCursor(const HIdx *_idx,
			     const void *_skey, const void *_ekey,
			     Boolean _sexcl, Boolean _eexcl,
			     Boolean (*_user_cmp)(const void *, void *),
			     void *_cmp_arg,
			     int thread_cnt) :
  idx(_idx), sexcl(_sexcl),
  eexcl(_eexcl),
  user_cmp(_user_cmp),
  cmp_arg(_cmp_arg)
{
  assert(!idx->status());
  assert(idx->isOpened());

  init(idx->dbh);
  list = 0;
  lists = 0;

  Status s;
  Boolean isstr = (STRTYPE(idx) ? True : False);
  skey = HIdx::copy_key(_skey, idx->hidx.keysz, isstr, &state);
  ekey = HIdx::copy_key((_ekey == defaultSKey) ? _skey : _ekey, idx->hidx.keysz, isstr, &state);

  if (!state)
    return;

  if (parallelInit(thread_cnt))
    return;

  if (skey && ekey && !idx->cmp(skey, ekey, OPS_NOSWAP)) {
    equal = True;
    s = idx->get_key(k_cur, skey);
    if (s) state = False;
  }
  else {
    k_cur = 0;
    equal = False;
  }
    
  k_end = idx->hidx.key_count;
}

#define NO_COPY

Status
HIdxCursor::read(Boolean &eox)
{
  size_t size = 0; // V3_API_size_t
  Status s;
  int n;

  HIdx::CListObjHeader h;

  unsigned int (*gkey)(int) = get_gkey(idx->version);
  //  printf("enter HIdxCursor::read()\n");
  for (n = 0; ; n++) {
    /*
    printf("@%d koid = %s k_cur=%d, k_end=%d\n", pthread_self(),
	   getOidString(&koid), k_cur, k_end);
    */
    if (backend_interrupt)
      return statusMake(BACKEND_INTERRUPTED, "");

    if (koid.getNX() == 0) {
      if (k_cur >= k_end) {
	eox = True;
	return Success;
      }

      HIdx::CListHeader chd;
      s = idx->readCListHeader(k_cur, chd);
      if (s)
	return s;
      koid = chd.clobj_first;

      if (equal) {
	if (koid.getNX() == 0) {
	  eox = True;
	  return Success;
	}
      }
      else
	k_cur++;
      
      if (koid.getNX() == 0)
	continue;
    }	  

    s = objectRead(idx->dbh, 0, sizeof(HIdx::CListObjHeader), &h,
		   DefaultLock, 0, &size, &koid);
    if (s)
      return s;
    x2h_header(&h);
    
    if (h.alloc_cnt)
      break;

    koid = h.clobj_next;
    
    if (equal && koid.getNX() == 0) {
      eox = True;
      return Success;
    }
  }      

  eox = False;

  Boolean nocopy_failed = False;

  if (data_tofree)
    free(sdata);

  if (nocopy) {
    s =  objectReadNoCopy(idx->dbh, 0, size, &sdata, DefaultLock, 0, 0,
			     &koid);
    if (!s) {
      edata = sdata + size;
      cur = sdata + sizeof(HIdx::CListObjHeader);
      data_tofree = False;
    }
    else {
      //printf("nocopy failed for %s\n", getOidString(&koid));
      nocopy_failed = True;
    }
  }

  if (!nocopy || nocopy_failed) {
    sdata = (char *)m_malloc(size);
    data_tofree = True;
    edata = sdata + size;
    cur = sdata + sizeof(HIdx::CListObjHeader);
    
    s =  objectRead(idx->dbh, 0, size, sdata, DefaultLock, 0, 0, &koid);
  }

  koid = h.clobj_next;

  return s;
}

void *HIdx::copy_key(const void *key, unsigned int keysz, Boolean isstr, Boolean *state)
{
  if (state)
    *state = True;

  if (!key)
    return 0;

  if (keysz == HIdx::VarSize)
    return strdup((char *)key);

  char *k = (char *)m_malloc(keysz);
  assert(k);

  if (isstr) {
    int len = strlen((char *)key)+1;

    if (len > keysz) { // was if (len >= keysz)
      if (state)
	*state = False;
    }
    else {
      memcpy(k, key, len);
      memset(k+len, 0, keysz-len);
    }
  }
  else
    memcpy(k, key, keysz);

  return k;
}

inline int
HIdxCursor::cmp_realize(const void *xkey, const void *ykey,
			   Boolean excl, unsigned char bswap) const
{
  int c = idx->cmp(xkey, ykey, bswap);

  if (c == 0) {
    if (excl)
      return 1;
    return 0;
  }
  
  return (c > 0);
}

inline int
HIdxCursor::cmp(const void *key) const
{
  if (equal)
    return idx->cmp(skey, key, OP2_SWAP);

  if (!skey && !ekey)
    return 0;

  if (skey && ekey)
    return cmp_realize(skey, key, sexcl, OP2_SWAP) ||
      cmp_realize(key, ekey, eexcl, OP1_SWAP);

  if (skey)
    return cmp_realize(skey, key, sexcl, OP2_SWAP);

  if (ekey)
    return cmp_realize(key, ekey, eexcl, OP1_SWAP);

  abort();
  return 1;
}

void HIdxCursor::append_next(void *data, Idx::Key *key, unsigned int n, DataBuffer *dataBuffer)
{
  int off = get_off(cur, idx);

  Link *l;
  if (slave) {
    l = new Link(idx->hidx.datasz);
    data = l->data;
    key = &l->key;
  }
  else {
    l = 0;
  }

  if (data || dataBuffer) {
    if (idx->isDataGroupedByKey()) {
      if (dataBuffer) {
	dataBuffer->setData(cur + off + data_group_sz(n, idx), idx->hidx.datasz);
      }
      else if (data) {
	memcpy(data, cur + off + data_group_sz(n, idx), idx->hidx.datasz);
      }
    }
    else {
      if (idx->isDataVarSize()) {
	unsigned int xdatasz, datasz;

	memcpy(&xdatasz, cur + off, DATASZ_SIZE);
	datasz = x2h_u32(xdatasz);

	if (dataBuffer) {
	  dataBuffer->setData(cur + off + DATASZ_SIZE, datasz);
	}
	else if (data) {
	  memcpy(data, cur + off + DATASZ_SIZE, datasz);
	}
      }
      else {
	if (dataBuffer) {
	  dataBuffer->setData(cur + off, idx->hidx.datasz);
	}
	else if (data) {
	  memcpy(data, cur + off, idx->hidx.datasz);
	}
      }
    }
  }
	
  if (key) {
    key->setKey(cur, (idx->hidx.keysz != HIdx::VarSize ?
		      idx->hidx.keysz : strlen(cur) + 1),
		idx->keytype);
  }
  
  if (slave) {
    list->insert(l);
  }
}

Status HIdxCursor::next(unsigned int *found_cnt, Idx::Key *key)
{
  if (!idx->isDataGroupedByKey()) {
    *found_cnt = 0;
    // for now
    return statusMake(ERROR, "cannot use this type of cursor on non data_grouped_by_key hash index");
  }

  Boolean found;
  return next(&found, found_cnt, 0, key, 0);
}

Status HIdxCursor::next(Boolean *found, void *data, Idx::Key *key)
{
  return next(found, 0, data, key, 0);
}

Status HIdxCursor::next(Boolean *found, DataBuffer &dataBuffer, Idx::Key *key)
{
  return next(found, 0, 0, key, &dataBuffer);
}

Status
HIdxCursor::next(Boolean *found, unsigned int *found_cnt, void *data, Idx::Key *key, DataBuffer *dataBuffer)
{
  if (!state) {
    if (found_cnt)
      *found_cnt = 0;
    *found = False;
    return Success;
  }

  if (master) {
    for (;;) {
      LinkList *tlist;
#ifdef MULTI_LIST
      for (int n = 0; n < perf_cnt; n++) {
	tlist = lists[n];
#else
	tlist = list;
#endif
	Link *l = tlist->peek();
	if (l) {
	  if (dataBuffer) {
	    dataBuffer->setData(l->data, idx->hidx.datasz);
	  }
	  else if (data) {
	    memcpy(data, l->data, idx->hidx.datasz);
	  }

	  if (key) {
	    key->setKey(l->key.getKey(), l->key.getSize(), idx->keytype);
	  }

	  delete l;
	  *found = True;
	  return Success;
	}
#ifdef MULTI_LIST
      }
#endif

#ifdef NEW_WAIT
      if (perf_end_cnt == perf_cnt) {
	thrpool->waitAll();
	if (found_cnt)
	  *found_cnt = 0;
	*found = False;
	return Success;
      }

      eyedblib::ThreadPerformer *perf;
      eyedblib::ThreadPerformerArg arg = thrpool->wait(perf);
      if (arg.data) {
	thrpool->waitAll(); // should advert thread to stop immediately !
	return (Status)arg.data;
      }

      perf_end_cnt++;
#else
      int n;
      for (n = 0; n < perf_cnt; n++) {
	if (!perfs[n]->isIdle())
	  break;
      }

      bool cond = (n == perf_cnt);
      if (!cond) { // at least one is still running
	eyedblib::ThreadPerformer *perf;
	eyedblib::ThreadPerformerArg arg = thrpool->wait(perf);
	if (arg.data) {
	  thrpool->waitAll(); // should advert thread to stop immediately !
	  return (Status)arg.data;
	}
      }
      else if (cond) { // all performers have finished
	thrpool->waitAll();
	if (found_cnt)
	  *found_cnt = 0;
	*found = False;
	return Success;
      }
#endif
    }
  }

  if (!sdata) {
    Boolean eox;
    Status s = read(eox);
    if (s)
      return s;
    
    if (eox) {
      if (found_cnt)
	*found_cnt = 0;
      *found = False;
      return Success;
    }
  }

  if (found_cnt) {
    cur += jumpsize;
    datacnt = 0;
    jumpsize = 0;
  }
  else if (++idata < datacnt) {
#ifdef TRACE_DGK
    printf("...CURSOR DATACNT %d idata=%d\n", datacnt, idata);
#endif
    *found = True;
    append_next(data, key, idata, dataBuffer);
    return Success;
  }
  else if (datacnt) {
#ifdef TRACE_DGK
    printf("...CURSOR jumping\n");
#endif
    cur += jumpsize;
    datacnt = 0;
    jumpsize = 0;
  }

  for (;;) {
    // changed the 8/12/99
    // for (; cur < edata; )
    for (; cur+sizeof(HIdx::CellHeader) <= edata; ) {
      if (backend_interrupt)
	return statusMake(BACKEND_INTERRUPTED, "");
      HIdx::CellHeader o;
      mcp(&o, cur, sizeof(HIdx::CellHeader));
      x2h_overhead(&o);
      cur += sizeof(HIdx::CellHeader);
	  
      if (!o.free && !cmp(cur)) {
	if (idx->precmp) {
	  int r;
	  void const * sk = skey ? skey : ekey;
	  if (sk && idx->precmp(sk, cur, &idx->keytype, r)) {
	    //printf("skipping entry\n");
	    if (!skey) {
	      cur += o.size; // 23/12/01: was not test with this statement
	      continue;
	    }

	    if (found_cnt)
	      *found_cnt = 0;
	    *found = False;
	    return Success;
	  }
	}
	
	if (user_cmp && !user_cmp(cur, cmp_arg)) {
	  cur += o.size;
	  continue;
	}

	if (idx->isDataGroupedByKey()) {
#ifdef VARSZ_DATACNT
	  Status s = idx->x2h_datacnt_cpy(&datacnt, (unsigned char *)(cur + get_off(cur, idx)));
	  if (s)
	    return s;
#else
	  x2h_32_cpy(&datacnt, cur + get_off(cur, idx));
#endif
	  idata = 0;
#ifdef TRACE_DGK
	  printf("CURSOR DATACNT %d idata=%d\n", datacnt, idata);
#endif
	  jumpsize = o.size;
	}
	else
	  datacnt = 1;

	if (found_cnt)
	  *found_cnt = datacnt;

	*found = True;
	append_next(data, key, 0, dataBuffer);

	if (!idx->isDataGroupedByKey())
	  cur += o.size;
	return Success;
      }
	  
      cur += o.size;
    }
      
    if (equal && !koid.getNX()) {
      if (found_cnt)
	*found_cnt = 0;
      *found = False;
      state = False;
      return Success;
    }

    Boolean eox;
    Status s = read(eox);
	  
    if (s)
      return s;

    if (eox) {
      if (found_cnt)
	*found_cnt = 0;
      *found = False;
      state = False;
      return Success;
    }
  }
}

HIdxCursor::~HIdxCursor()
{
  free(skey);
  free(ekey);
  if (data_tofree)
    free(sdata);
  delete [] perf_curs;
  delete [] perfs;
#ifdef MULTI_LIST
  if (lists) {
    for (int n = 0; n < perf_cnt; n++)
      delete lists[n];
    delete lists;
  }
#else
  delete list;
#endif
}

Status
HIdx::getStats(std::string &stats) const
{
  unsigned int total;
  int n;

  stats  = std::string("  Index type: 'hash'\n");

  stats += std::string("  Key count: ") + str_convert((long)hidx.key_count) + "\n";
  stats += std::string("  Magnitude Order: ") + str_convert((int)hidx.mag_order) + "\n";
  stats += std::string("  Key Type: ") + typeString((Type)hidx.keytype) + "\n";
  stats += std::string("  Implementation Hints:\n");
  for (int i = 0; i < HIdxImplHintsCount; i++)
    stats += std::string("    ") + implHintsStr(i) + ": " +
      str_convert((int)hidx.impl_hints[i]) + "\n";
  stats += std::string("  Dataspace ID: ") + str_convert((int)(hidx.dspid == DefaultDspid ? -1 : hidx.dspid)) + "\n";
  stats += std::string("  Data Size: ") + str_convert((long)hidx.datasz) + "\n";
  stats += std::string("  Key Size: ") + str_convert((int)hidx.keysz) + "\n";
  stats += std::string("  Magnitude Order: ") + str_convert((long)hidx.mag_order) + "\n";

  total = 0;
  unsigned int total_objs = 0;
  unsigned int max = 0;
  unsigned int min = ~0;
  unsigned int free = 0, busy = 0;

  for (n = 0; n < hidx.key_count; n++) {
    CListHeader chd;
    Status s = readCListHeader(n, chd);
    if (s)
      return s;

    Oid toid;
    toid = chd.clobj_first;
    unsigned int cell_count = 0;
    unsigned int nobjs = 0;
    while (toid.getNX() > 0) {
      unsigned int count;
      if (backend_interrupt)
	return statusMake(BACKEND_INTERRUPTED, "");

      s = getEntryCount(&toid, count);
      if (s)
	return s;

      cell_count += count;
      nobjs++;
    }

    total_objs += nobjs;

    if (cell_count > max)
      max = cell_count;
    if (cell_count < min)
      min = cell_count;

    if (cell_count) {
      busy++;
      stats += std::string("  Cell #") + str_convert(n) + ": " + str_convert((long)cell_count) + " object" + (cell_count != 1 ? "s" : "") + ", " + str_convert((long)nobjs) + " hash object" + (nobjs != 1 ? "s" : "") + "\n";
      total += cell_count;
    }
    else
      free++;
  }

  stats += std::string("  Total object count: ") + str_convert((long)total) +
    " {computed: " + str_convert((long)getCount()) + "}\n";
  stats += std::string("  Min object per entry: ") + str_convert((long)min) + "\n";
  stats += std::string("  Max entries per entry: ") + str_convert((long)max) + "\n";
  stats += std::string("  Free entry count: ") + str_convert((long)free) + "\n";
  stats += std::string("  Busy entry count: ") + str_convert((long)busy) + "\n";
  stats += std::string("  Total hash object count: 1+") +
    str_convert((long)total_objs) + "\n";
  return Success;
}

Status
HIdx::getStats(HIdx::Stats &stats) const
{
  memset(&stats, 0, sizeof(stats));
  memcpy(&stats.idx, &hidx, sizeof(hidx));

  unsigned int (*gkey)(int) = get_gkey(version);
  // the tree object:
  stats.total_hash_object_count = 1;
  stats.total_hash_object_size = sizeof(CListHeader) * gkey(hidx.key_count);

  stats.entries = new Stats::Entry[hidx.key_count];
  memset(stats.entries, 0, sizeof(Stats::Entry) * hidx.key_count);
  stats.min_objects_per_entry = ~0;

  Stats::Entry *entry = stats.entries;
  for (int n = 0; n < hidx.key_count; n++, entry++) {
    CListHeader chd;
    Status s = readCListHeader(n, chd);
    if (s)
      return s;
#if 1
    checkChain(&chd, "getStats");
#endif
    Oid koid;
    koid = chd.clobj_first;
    while (koid.getNX() > 0) {
      unsigned int count;
      if (backend_interrupt)
	return statusMake(BACKEND_INTERRUPTED, "");
      
      size_t size; // V3_API_size_t
      unsigned int busysize;
      s = objectSizeGet(dbh, &size, DefaultLock, &koid);
      if (s)
	return s;

      s = getHashObjectBusySize(&koid, busysize, count, size);
      if (s)
	return s;

      unsigned int ncount;
      s = getEntryCount(&koid, ncount);
      if (s)
	return s;
      
      /*
      if (ncount != count) {
	printf("HIdx: count differ %d %d\n", count, ncount);
      }
      else {
	printf("HIdx: count equal %d %d\n", count, ncount);
      }
      */

      entry->object_count += count;
      entry->hash_object_busy_size += busysize;
      entry->hash_object_count++;
      entry->hash_object_size += size;
    }

    if (entry->object_count > stats.max_objects_per_entry)
      stats.max_objects_per_entry = entry->object_count;
    if (entry->object_count < stats.min_objects_per_entry)
      stats.min_objects_per_entry = entry->object_count;

    stats.total_hash_object_count += entry->hash_object_count;
    stats.total_hash_object_busy_size += entry->hash_object_busy_size;
    stats.total_object_count += entry->object_count;
    stats.total_hash_object_size += entry->hash_object_size;

    if (entry->object_count)
      stats.busy_key_count++;
    else
      stats.free_key_count++;
  }

  return Success;
}

HIdx::Stats::Stats()
{
  entries = 0;
}

std::string
HIdx::Stats::toString(Boolean full) const
{
  std::string s = idx.toString();
  Entry *entry = entries;

  if (full) {
    for (int i = 0; i < idx.key_count; i++, entry++)
      if (entry->object_count) {
	s += std::string("Entry #") + str_convert((long)i) + " {\n";
	s += std::string("\tObject count: ") + str_convert(entry->object_count) +
	  "\n";
	s += std::string("\tObject size: ")  + 
	  str_convert(entry->hash_object_busy_size) + "\n";
	s += std::string("\tHash object count: ") +
	  str_convert(entry->hash_object_count) + "\n";
	s += std::string("\tHash object size: ")  + 
	  str_convert(entry->hash_object_size) + "B\n}\n";
      }

    s += "\n";
  }

  s += std::string("Min objects per entry: ") +
    str_convert(min_objects_per_entry) + "\n";
  s += std::string("Max objects per entry: ") +
    str_convert(max_objects_per_entry) + "\n";
  s += std::string("Total object count: ") +
    str_convert(total_object_count) + "\n";
  s += std::string("Total object size: ") +
    str_convert(total_hash_object_busy_size) + "B\n";
  s += std::string("Total hash object count: ") + 
    str_convert(total_hash_object_count) + "\n";
  s += std::string("Total hash object size: ") +
    str_convert(total_hash_object_size) + "B\n";
  s += std::string("Busy entry count: ") +
    str_convert(busy_key_count) + "\n";
  s += std::string("Free entry count: ") +
    str_convert(free_key_count) + "\n";
  return s;
}

void
HIdx::Stats::trace(Boolean full, FILE *fd) const
{
  idx.trace(fd);
  Entry *entry = entries;

  if (full) {
    for (int i = 0; i < idx.key_count; i++, entry++)
      if (entry->object_count) {
	fprintf(fd, "Entry #%d {\n", i);
	fprintf(fd, "\tObject count: %llu\n", entry->object_count);
	fprintf(fd, "\tHash object count: %llu\n", entry->hash_object_count);
	fprintf(fd, "\tHash object size: %lluB\n", entry->hash_object_size);
	fprintf(fd, "\tHash object busy size: %lluB\n", entry->hash_object_busy_size);
	fprintf(fd, "}\n");
      }
    fprintf(fd, "\n");
  }

  fprintf(fd, "Min objects per entry: %llu\n", min_objects_per_entry);
  fprintf(fd, "Max objects per entry: %llu\n", max_objects_per_entry);
  fprintf(fd, "Total object count: %llu\n", total_object_count);
  fprintf(fd, "Total hash object count: %llu\n", total_hash_object_count);
  fprintf(fd, "Total hash object size: %lluB\n", total_hash_object_size);
  fprintf(fd, "Total hash object busy size: %lluB\n", total_hash_object_busy_size);
  fprintf(fd, "Busy entry count: %llu\n", busy_key_count);
  fprintf(fd, "Free entry count: %llu\n", free_key_count);
}

HIdx::Stats::~Stats()
{
  delete [] entries;
}

Status
HIdx::copy(HIdx *&idx_n, int key_count, int mag_order, short dspid,
	      const int *impl_hints, unsigned int impl_hints_cnt,
	      hash_key_t _hash_key,
	      void *_hash_data, KeyType *ktype) const
{
  key_count = (key_count > MaxKeys ? MaxKeys : key_count);

  idx_n = new HIdx(dbh, (ktype ? *ktype : getKeyType()), hidx.datasz,
		      (dspid == DefaultDspid ? hidx.dspid : dspid),
		      (mag_order == 0 ? hidx.mag_order : mag_order),
		      key_count,
		      (impl_hints == 0 ? hidx.impl_hints : impl_hints),
		      (impl_hints == 0 ? HIdxImplHintsCount : impl_hints_cnt));

  if (idx_n->status())
    return idx_n->status();

  idx_n->open(_hash_key, _hash_data);
  
  return copy_realize(idx_n);
}

Status
HIdx::copy_realize(Idx *idx) const
{
  Status s = Success;
  HIdxCursor curs(this);
  unsigned char *data = new unsigned char[hidx.datasz];

  for (;;) {
    Boolean found;
    Idx::Key key;

    s = curs.next(&found, data, &key);
    if (s) goto error;

    if (!found) break;

    s = idx->insert(key.getKey(), data);
    if (s) goto error;
  }

 error:
  delete [] data;
  return s;
}

Status
HIdx::reimplementToBTree(Oid &newoid, int degree, short dspid)
{
  BIdx bidx(dbh, hidx.datasz, &keytype,
	       (dspid == DefaultDspid ? hidx.dspid : dspid),
	       degree, 1);

  if (bidx.status())
    return bidx.status();

  bidx.open();

  Status s = copy_realize(&bidx);
  if (s)
    return s;
  s = destroy();
  if (s)
    return s;

  newoid = bidx.oid();
  return Success;
}

Status HIdx::move(short dspid, eyedbsm::Oid &newoid,
		  hash_key_t hash_key, void *hash_data, PostCollapseTransformer *post_collapse_transformer)
{
  // for now
  /*
  return reimplementToHash(newoid, hidx.key_count, hidx.mag_order, dspid, hidx.impl_hints, HIdxImplHintsCount, hash_key, hash_data);
  */
  // construction d'un index comme dans copy
  // parcours de tous les objets comme dans collapse, puis writeCListHeader sur le nouvel index, sans destruction (le destroy se fait ensuite) => en fait, il faut dupliquer collapse, c'est trop different
  // note: le collapse est-il obligatoire ? ou bien c'est une option a ajouter dans le mvidx et a passer a Index::move puis a Index::realize (via les UserData) ?
  // dans un 1er temps, on peut le faire obligatoire
#if 1
  if (getenv("MOVE_IS_COLLAPSE")) {
    printf("move is collapse only\n");
    newoid = oid();
    return collapse();
  }
#endif

  HIdx *idx_n = new HIdx(dbh,
			 getKeyType(),
			 hidx.datasz,
			 dspid,
			 hidx.mag_order,
			 hidx.key_count,
			 hidx.impl_hints,
			 HIdxImplHintsCount);

  if (idx_n->status())
    return idx_n->status();

  idx_n->open(hash_key, hash_data);

  IdxLock lockx_n(dbh, idx_n->treeoid);
  Status s = lockx_n.lock();
  if (s)
    return s;

  time_t t0 = time(NULL);
  //fprintf(stderr, "BEGIN collapse %s", ctime(&t0));
  //fflush(stderr);
  s = collapse_realize(dspid, idx_n, post_collapse_transformer);
  if (s)
    return s;

  time_t t1 = time(NULL);
  //fprintf(stderr, "END collapse %d seconds\n", t1-t0);
  //fflush(stderr);

#if 0
  // EV: 2015-01-26: trying to avoid deleting all index objects
  // EV: 2015-03-04: disconnected because raises bugs when defragmentating a dataspace (objects are badly chained)
  s = objectDelete(dbh, &treeoid);
#else
  s = destroy();
#endif
  if (s)
    return s;

  t0 = t1;
  t1 = time(NULL);
  //fprintf(stderr, "END destroy %d seconds\n", t1-t0);
  //fflush(stderr);

  newoid = idx_n->oid();

  delete idx_n;

  t0 = t1;
  t1 = time(NULL);
  //fprintf(stderr, "END delete %d seconds\n", t1-t0);
  //fflush(stderr);

  return Success;
}

Status
HIdx::reimplementToHash(Oid &newoid, int key_count, int mag_order,
			   short dspid, const int *impl_hints,
			   unsigned int impl_hints_cnt,
			   hash_key_t _hash_key, void *_hash_data,
			   KeyType *ktype)
{
  IdxLock lockx(dbh, treeoid);
  Status s = lockx.lock();
  if (s)
    return s;

  printf("reimplementToHash:\n");
  printf("OLD: kc: %d dspid: %d hints: %d %d %d %d %d %d\n", hidx.key_count, hidx.dspid, hidx.impl_hints[0],hidx.impl_hints[1],hidx.impl_hints[2],hidx.impl_hints[3],hidx.impl_hints[4],hidx.impl_hints[5],hidx.impl_hints[6]);
  printf("NEW: kc: %d dspid: %d hints: %d %d %d %d %d %d\n", key_count, dspid, impl_hints[0],impl_hints[1],impl_hints[2],impl_hints[3],impl_hints[4],impl_hints[5],impl_hints[6]);

  // si tous les parametres sont identiques sauf le dspid, alors il suffit de
  // reorganiser l'index, et il ne faut pas le reimplementer !

  HIdx *idx_n = 0;
  s = copy(idx_n, key_count, mag_order, dspid, impl_hints,
	   impl_hints_cnt, _hash_key, _hash_data, ktype);
  if (s)
    return s;

  s = destroy();
  if (s)
    return s;
  newoid = idx_n->oid();
  delete idx_n;
  return Success;
}

Status
HIdx::simulate(Stats &stats, int key_count, int mag_order,
		  const int *impl_hints, unsigned int impl_hints_cnt,
		  hash_key_t _hash_key,
		  void *_hash_data) const
{
  HIdx *idx_n;
  Status s = copy(idx_n, key_count, mag_order, hidx.dspid, impl_hints,
		     impl_hints_cnt, _hash_key, _hash_data, 0);
  if (s)
    return s;

  s = idx_n->getStats(stats);
  idx_n->destroy();
  delete idx_n;
  return s;
}

static void x2h_idx(HIdx::_Idx *idx)
{
#ifdef HIDX_XDR
  idx->idxtype = x2h_u32(idx->idxtype);
  idx->object_count = x2h_u32(idx->object_count);
  idx->mag_order = x2h_u32(idx->mag_order);
  idx->key_count = x2h_u32(idx->key_count);
  idx->dspid = x2h_16(idx->dspid);
  idx->keytype = x2h_u32(idx->keytype);
  idx->keysz = x2h_u32(idx->keysz);
  idx->datasz = x2h_u32(idx->datasz);
  idx->offset = x2h_u32(idx->offset);
  for (int i = 0; i < HIdxImplHintsCount; i++)
    idx->impl_hints[i] = x2h_u32(idx->impl_hints[i]);
#endif
}

static void h2x_idx(HIdx::_Idx *xidx, const HIdx::_Idx *hidx)
{
#ifdef HIDX_XDR
  xidx->idxtype = h2x_u32(hidx->idxtype);
  xidx->object_count = h2x_u32(hidx->object_count);
  xidx->mag_order = h2x_u32(hidx->mag_order);
  xidx->key_count = h2x_u32(hidx->key_count);
  xidx->dspid = h2x_16(hidx->dspid);
  xidx->keytype = h2x_u32(hidx->keytype);
  xidx->keysz = h2x_u32(hidx->keysz);
  xidx->datasz = h2x_u32(hidx->datasz);
  xidx->offset = h2x_u32(hidx->offset);
  for (int i = 0; i < HIdxImplHintsCount; i++)
    xidx->impl_hints[i] = h2x_u32(hidx->impl_hints[i]);
#else
  if (xidx != hidx)
    memcpy(xidx, hidx, sizeof(*xidx));
#endif
}

static void x2h_chd(HIdx::CListHeader *chd)
{
#ifdef HIDX_XDR
  x2h_oid(&chd->clobj_first, &chd->clobj_first);
  x2h_oid(&chd->clobj_last, &chd->clobj_last);
  x2h_oid(&chd->clobj_free_first, &chd->clobj_free_first);
#endif
}

static void h2x_chd(HIdx::CListHeader *xchd, const HIdx::CListHeader *hchd)
{
#ifdef HIDX_XDR
  h2x_oid(&xchd->clobj_first, &hchd->clobj_first);
  h2x_oid(&xchd->clobj_last, &hchd->clobj_last);
  h2x_oid(&xchd->clobj_free_first, &hchd->clobj_free_first);
#else
  if (xchd != hchd)
    memcpy(xchd, hchd, sizeof(*xchd));
#endif
}

static void x2h_header(HIdx::CListObjHeader *h)
{
#ifdef HIDX_XDR
  h->size = x2h_32(h->size);
  h->free_cnt = x2h_u16(h->free_cnt);
  h->alloc_cnt = x2h_u16(h->alloc_cnt);
  h->free_whole = x2h_u32(h->free_whole);
  h->cell_free_first = x2h_u32(h->cell_free_first);
  x2h_oid(&h->clobj_free_prev, &h->clobj_free_prev);
  x2h_oid(&h->clobj_free_next, &h->clobj_free_next);
  x2h_oid(&h->clobj_prev, &h->clobj_prev);
  x2h_oid(&h->clobj_next, &h->clobj_next);
#endif
}

static void h2x_header(HIdx::CListObjHeader *xh, const HIdx::CListObjHeader *hh)
{
#ifdef HIDX_XDR
  xh->size = h2x_32(hh->size);
  xh->free_cnt = h2x_u16(hh->free_cnt);
  xh->alloc_cnt = h2x_u16(hh->alloc_cnt);
  xh->free_whole = h2x_u32(hh->free_whole);
  xh->cell_free_first = h2x_32(hh->cell_free_first);
  h2x_oid(&xh->clobj_free_prev, &hh->clobj_free_prev);
  h2x_oid(&xh->clobj_free_next, &hh->clobj_free_next);
  h2x_oid(&xh->clobj_prev, &hh->clobj_prev);
  h2x_oid(&xh->clobj_next, &hh->clobj_next);
#else
  if (xh != hh)
    memcpy(xh, hh, sizeof(*xh));
#endif
}

static void x2h_overhead(HIdx::CellHeader *o)
{
#ifdef HIDX_XDR_OVERHEAD
  unsigned int x;
  mcp(&x, o, sizeof(x));
  x = x2h_u32(x);
  o->free = x >> 31;
  o->size = x & 0xefffffff;
  o->cell_free_next = x2h_32(o->cell_free_next);
  o->cell_free_prev = x2h_32(o->cell_free_prev);
#endif
}

static void h2x_overhead(HIdx::CellHeader *xo, const HIdx::CellHeader *ho)
{
#ifdef HIDX_XDR_OVERHEAD
  unsigned int x = h2x_u32((ho->free << 31) | ho->size);
  mcp(xo, &x, sizeof(x));
  xo->cell_free_next = h2x_32(ho->cell_free_next);
  xo->cell_free_prev = h2x_32(ho->cell_free_prev);
#else
  if (xo != ho)
    memcpy(xo, ho, sizeof(*xo));
#endif
}

static const char out_of_bounds_fmt[] =
"out of bounds data grouped sizeof: maximum data count per key is %u";

static const char unsupported_sizeof_fmt[] =
"unsupported data grouped sizeof in hash index %u";

static Status out_of_bounds(unsigned int data_grouped_sizeof)
{
  return statusMake(ERROR, out_of_bounds_fmt,
		    (1 << (8 * data_grouped_sizeof)) - 1);
}

Status HIdx::h2x_datacnt_cpy(unsigned char *rdata, const unsigned int *pdatacnt) const
{
  if (data_grouped_sizeof == 4) {
    h2x_32_cpy(rdata, pdatacnt);
    return Success;
  }

  if (data_grouped_sizeof == 2) {
    unsigned short sdatacnt = *pdatacnt;
    if ((unsigned int)sdatacnt != *pdatacnt) {
      return out_of_bounds(data_grouped_sizeof);
    }
    h2x_16_cpy(rdata, &sdatacnt);
    return Success;
  }

  if (data_grouped_sizeof == 1) {
    *rdata = *pdatacnt;
    if ((unsigned int)*rdata != *pdatacnt) {
      return out_of_bounds(data_grouped_sizeof);
    }

    return Success;
  }

  return statusMake(ERROR, unsupported_sizeof_fmt, data_grouped_sizeof);
}

Status HIdx::x2h_datacnt_cpy(unsigned int *pdatacnt, const unsigned char *pdata) const
{
  if (data_grouped_sizeof == 4) {
    x2h_32_cpy(pdatacnt, pdata);
    return Success;
  }

  if (data_grouped_sizeof == 2) {
    unsigned short sdatacnt;
    x2h_16_cpy(&sdatacnt, pdata);
    *pdatacnt = sdatacnt;
    if ((unsigned int)sdatacnt != *pdatacnt) {
      return out_of_bounds(data_grouped_sizeof);
    }
    return Success;
  }

  if (data_grouped_sizeof == 1) {
    *pdatacnt = *pdata;

    if ((unsigned int)*pdata != *pdatacnt) {
      return out_of_bounds(data_grouped_sizeof);
    }

    return Success;
  }

  return statusMake(ERROR, unsupported_sizeof_fmt, data_grouped_sizeof);
}
}

