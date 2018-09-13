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


#ifndef	_eyedbsm_HIdx_
#define	_eyedbsm_HIdx_

#include <stdio.h>
#include <stdlib.h>
#include <eyedblib/machtypes.h>
#include <eyedbsm/Idx.h>
#include <vector>
#include <map>

namespace eyedblib {
  class ThreadPool;
  class ThreadPerformer;
}

#define HAS_ALLOC_BUFFER

namespace eyedbsm {

  /**
     @addtogroup eyedbsm
     @{
  */

  class HIdxCursor;

  static const int HIdxImplHintsCount = 8;
  static const unsigned int HIdxDataVarSize = ~0U;

  /**
     Not yet documented.
  */

  class HIdx : public Idx {

    friend class HIdxCursor;

#ifdef HAS_ALLOC_BUFFER
    AllocBuffer insert_buffer;
    AllocBuffer makeobj_buffer;
#endif

  public: /* conceptually private */
    class CellHeader;
    class CListObjHeader;
    class CListHeader;

    class PostCollapseTransformer {

    public:
      //virtual size_t transform(const unsigned char* data, size_t data_size, unsigned char*& rdata, bool& must_desallocate) = 0;
      virtual void reset() {}
      virtual void add(const char* key, size_t datasz, const unsigned char* data) = 0;
      virtual size_t next(unsigned char*& key, unsigned char*& data) = 0;
    };

  public:
    enum HIdxKeyType {
      stringType = 1,
      dataType
    };


    struct _Idx {
      unsigned int idxtype;
      unsigned int object_count;
      unsigned int mag_order;
      unsigned int key_count;
      short dspid;
      unsigned int keytype;
      unsigned int keysz;
      unsigned int datasz;
      unsigned int offset;
      int impl_hints[HIdxImplHintsCount];
      void trace(FILE *fd = stdout) const;
      std::string toString() const;
    };

  public: //@@@@ A.W just try to cure
    struct _Idx hidx;
  private:
    unsigned int mask;
    Boolean pow2;
    Boolean uextend;
    Boolean data_grouped_by_key;
    unsigned int data_grouped_sizeof;
    Oid treeoid;
    Status stat;
    DbHandle *dbh;
    int bsize;
    hash_key_t hash_key;
    void *hash_data;
    int version;
    Boolean nocopy;

    class HKey {
      const void *key;
      HIdx *hidx;
      bool _garbage;

    public:

      HKey(HIdx *hidx, const void *key, bool copy = false);
      HKey(const HKey &);
      HKey& operator=(const HKey &);

      int operator<(const HKey &okey) const {
	return hidx->cmp(key, okey.key, 0) < 0 ? 1 : 0;
      }

      const void *getKey() const {return key;}

      void garbage() {
	if (_garbage) {
	  free((char *)key);
	  key = 0;
	}
      }

      ~HKey() {
	garbage();
      }
    };

    friend class HKey;
   
    std::map<HKey, std::vector<const void *> > cache_map;

    static void *copy_key(const void *, unsigned int, Boolean, Boolean *state = 0);
    Status dumpMemoryMap(const CListHeader &, const char *msg = "", FILE *fd = stdout);

    Status readCellHeader(int off, const Oid &, CellHeader &) const;
    Status writeCellHeader(int off, const Oid &, const CellHeader &) const;
    Status readCListObjHeader(const Oid &, CListObjHeader &) const;
    Status writeCListObjHeader(const Oid &, const CListObjHeader &) const;
    Status readCListHeader(unsigned int k, CListHeader &chd) const;
    Status writeCListHeader(unsigned int k, const CListHeader &chd) const;
    Status readCListHeaders(CListHeader *&chds) const;
    Status writeCListHeaders(const CListHeader *chds) const;

    Status insertCell(int offset, unsigned int size, CListObjHeader &h,
		      const Oid &koid) const;
    Status suppressCell(int offset, CListObjHeader &h, const Oid &koid) const;
    Status get_key(unsigned int &, const void *, unsigned int * = 0) const;
    int cmp(const void *, const void *, unsigned char) const;
    Status count_manage(DbHandle *dbh, int inc);
    Status getCell(unsigned int size, CListHeader &chd, unsigned int chd_k,
		   Oid &koid, CListObjHeader &h, int &offset, CellHeader &o);
    Status insert_realize(CListHeader &chd, unsigned int chd_k, const void *key,
			  unsigned int size, const void *xdata,
			  const Oid &koid, CListObjHeader &h, int offset,
			  CellHeader &o, unsigned int datasz);
    Status insert_perform(const void *key, std::vector<const void *> &xdata_v, unsigned int datasz);
    Status insert_perform(const void *key, const void *xdata, unsigned int datasz);
    Status remove_perform(const void *key, const void *xdata, unsigned int datasz, Boolean *found, unsigned char **prdata, unsigned int *pdatacnt, int *found_idx, unsigned int incr_alloc);
    Status remove_realize(CListHeader *chd, unsigned int chd_key,
			  const char *, const char *, const char *,
			  const CellHeader *, const Oid *);
    Status search_realize(const void *key, unsigned int *found_cnt, Boolean found_any, void * data);
    Status getObjectToExtend(unsigned int size, CListHeader &chd, unsigned int chd_k,
			     Oid &koid, CListObjHeader &h, int &offset,
			     CellHeader &o, Boolean &found);
    Status extendObject(CListHeader &chd, unsigned int chd_k, const Oid &koid,
			CListObjHeader &h, Boolean &extended);
    Status extendObject(unsigned int size, CListHeader &chd, unsigned int chd_k, Oid &koid,
			CListObjHeader &h, int &offset, CellHeader &o,
			Boolean &extended);
    Boolean candidateForExtension(const CListObjHeader &);
    Status makeObject(CListHeader &chd, unsigned int chd_k, Oid &koid, int &offset,
		      CListObjHeader &h, CellHeader &o, unsigned int objsize);
    static bool inFreeList(const CListObjHeader &h, const CListHeader &chd, const Oid &koid);
    Status insertObjectInFreeList(CListHeader &chd, unsigned int chd_k, CListObjHeader &h,
				  const Oid &koid);
    Status suppressObjectFromFreeList(CListHeader &chd, unsigned int chd_k, CListObjHeader &h,
				      const Oid &koid);
    Status suppressObjectFromList(CListHeader &chd, unsigned int chd_k, CListObjHeader &h,
				  const Oid &koid);
    Status replaceObjectInList(CListHeader &chd, unsigned int chd_k, CListObjHeader &h,
			       const Oid &koid, const Oid &nkoid);
    Status modifyObjectSize(int osize, int nsize, const Oid &koid, 
			    Oid &nkoid);
    Status headPrint(FILE *, int, Oid *, int&) const;
    Status getEntryCount(Oid *, unsigned int& ) const;
    Status getHashObjectBusySize(const Oid *koid, unsigned int &busysize,
				 unsigned int &count, unsigned int size = 0) const;
    static Status get_def_string_hash_key(const void *key, unsigned int len,
					  void *, unsigned int &);
    static Status get_def_nstring_hash_key(const void *key, unsigned int len,
					   void *, unsigned int &);
    static Status get_def_rawdata_hash_key(const void *key, unsigned int len,
					   void *, unsigned int &);
    static Status get_def_int16data_hash_key(const void *key,
					     unsigned int len, void *, unsigned int &);
    static Status get_def_int32data_hash_key(const void *key,
					     unsigned int len, void *, unsigned int &);
    static Status get_def_int64data_hash_key(const void *key,
					     unsigned int len, void *, unsigned int &);
    static Status get_def_oiddata_hash_key(const void *key, unsigned int len,
					   void *, unsigned int &);
    static Status get_def_float32data_hash_key(const void *key,
					       unsigned int len,
					       void *, unsigned int &);
    static Status get_def_float64data_hash_key(const void *key,
					       unsigned int len,
					       void *, unsigned int &);

    Status get_string_hash_key(const void *key, unsigned int len, unsigned int &) const;
    Status get_rawdata_hash_key(const void *key, unsigned int len, unsigned int &) const;
    void printCellHeader(const HIdx::CellHeader *o, int offset) const;
    void checkCellHeader(int offset, const Oid *koid) const;
    void printCListObjHeader(const HIdx::CListObjHeader *h) const;
    void checkCListObjHeader(const Oid *koid) const;
    void checkChain(const Oid *koid) const;
    void checkChain(const CListHeader *chd, const std::string &msg) const;

    void set_hash_key();
    Status destroy_r();
    Status copy_realize(Idx *) const;
    void init(DbHandle *, unsigned int keytype, unsigned int keysz,
	      unsigned int offset,
	      unsigned int datasz, short dspid,
	      int mag_order, int key_count,
	      const int *impl_hints,
	      unsigned int impl_hints_cnt);
    KeyType keytype;
    Status collapse_realize(short dspid, HIdx *idx_n, PostCollapseTransformer *post_collapse_transformer);
    Status h2x_datacnt_cpy(unsigned char *rdata, const unsigned int *pdatacnt) const;
    Status x2h_datacnt_cpy(unsigned int *pdatacnt, const unsigned char *pdata) const;

  public:

    enum Hints {
      IniSize_Hints,
      IniObjCnt_Hints,
      XCoef_Hints,
      SzMax_Hints,
      DataGroupedByKey_Hints
    };

    static const unsigned int MaxKeys;
    static const unsigned int VarSize;
    static const unsigned int MagorderKeycountCoef;

    /**
       Not yet documented
       @param vh
       @param type
       @param datasz
       @param dspid
       @param magorder
       @param key_count
       @param impl_hints
       @param impl_hints_cnt
    */
    HIdx(DbHandle *vh, KeyType type,
	 unsigned int datasz, short dspid,
	 int magorder, int key_count = 0,
	 const int *impl_hints = 0,
	 unsigned int impl_hints_cnt = 0);

    /**
       Not yet documented
       @param vh
       @param poid
       @param hash_key
       @param hash_data
       @param precmp
    */
    HIdx(DbHandle *vh, const Oid *poid,
	 hash_key_t hash_key = 0,
	 void *hash_data = 0,
	 Boolean (*precmp)(void const * p, void const * q,
			   KeyType const * type, int & r) = 0);

    /**
       Not yet documented
       @param hash_key
       @param hash_data
       @param precmp
    */
    void open(hash_key_t hash_key = 0,
	      void *hash_data = 0,
	      Boolean (*precmp)(void const * p, void const * q,
				KeyType const * type, int & r) = 0);

    /**
       Not yet documented
       @return
    */
    unsigned int getCount() const;

    /**
       Not yet documented
       @return
    */
    short getDefaultDspid() const;

    /**
       Not yet documented
       @param dspid
    */
    void setDefaultDspid(short dspid);

    /**
       Not yet documented
       @param oids
       @param cnt
       @return
    */
    Status getObjects(Oid *&oids, unsigned int &cnt) const;

    /**
       Not yet documented
       @return
    */
    virtual HIdx *asHIdx() {return this;}

    /**
       Not yet documented
       @return
    */
    const KeyType & getKeyType() const {return keytype;}

    /**
       Not yet documented
       @return
    */
    const HIdx::_Idx & getIdx() const {return hidx;}

    ~HIdx();
  
    /**
       Not yet documented
       @param key
       @param data
       @return
    */
    Status insert(const void *key, const void *data);

    /**
       Not yet documented
       @param key
       @param data
       @param datasz
       @return
    */
    Status insert(const void *key, const void *data, unsigned int datasz);

    /**
       Not yet documented
       @param key
       @param data_v
       @return
    */
    Status insert(const void *key, std::vector<const void *> &data_v);

    /**
       Not yet documented
       @param key
       @param data
       @return
    */
    Status insert_cache(const void *key, const void *data);

    /**
       Not yet documented
       @param key
       @param data_v
       @return
    */
    Status insert_cache(const void *key, std::vector<const void *> &data_v);

    /**
       Not yet documented
       @return
    */
    Status flush_cache(bool insert_data = true);

    /**
       Not yet documented
       @param key
       @param data
       @param found
       @return
    */
    Status remove(const void *key, const void *data, Boolean *found = 0);

    /**
       Not yet documented
       @param key
       @param data
       @param datasz
       @param found
       @return
    */
    Status remove(const void *key, const void *data, unsigned int datasz, Boolean *found = 0);

    /**
       Not yet documented
       @param key
       @param found_cnt
       @param data
       @return
    */
    Status search(const void *key, unsigned int *found_cnt);

    /**
       Not yet documented
       @param key
       @param found
       @param data
       @return
    */
    Status searchAny(const void *key, Boolean *found, void *data = 0);

    /**
       Not yet documented
       @return
    */
    Status destroy();

    /**
       Not yet documented
       @param fd
       @return
    */
    Status printStat(FILE *fd = stdout) const;

    /**
       Not yet documented
       @param fd
       @return
    */
    Status dumpMemoryMap(FILE *fd = stdout);

    /**
       Not yet documented
       @return
    */
    Oid const& oid() const {return treeoid;}

    /**
       Not yet documented
       @return
    */
    Boolean isDataGroupedByKey() const {return data_grouped_by_key;}

    /**
       Not yet documented
       @return
    */
    bool isDataVarSize() const {return hidx.datasz == HIdxDataVarSize;}

    /**
       Not yet documented
       @return
    */
    unsigned int getDataGroupedSizeof() const {return data_grouped_sizeof;}

    /**
       Not yet documented
       @return
    */
    Status status() const {return stat;}

    /**
       Not yet documented
       @return
    */
    unsigned int getKeyCount() const {return hidx.key_count;}

    /**
       Not yet documented
       @return
    */
    Status collapse(PostCollapseTransformer *post_collapse_transformer = NULL);

    /**
       Not yet documented
       @param idx_n
       @param key_count
       @param mag_order
       @param dspid
       @param impl_hints
       @param impl_hints_cnt
       @param _hash_key
       @param _hash_data
       @param ktype
       @return
    */
    Status copy(HIdx *&idx_n, int key_count, int mag_order = 0,
		short dspid = DefaultDspid,
		const int *impl_hints = 0, unsigned int impl_hints_cnt = 0,
		hash_key_t _hash_key = 0,
		void *_hash_data = 0,
		KeyType *ktype = 0) const;

    /**
       Not yet documented
       @param keycount
       @return
    */
    static unsigned int getMagOrder(unsigned int keycount);

    /**
       Not yet documented
       @param magorder
       @return
    */
    static unsigned int getKeyCount(unsigned int magorder);

    /**
       Not yet documented
       @param stats
       @return
    */
    Status getStats(std::string& stats) const;

    struct Stats {
      _Idx idx;
      struct Entry {
	size_t object_count;
	size_t hash_object_count;
	size_t hash_object_size;
	size_t hash_object_busy_size;
      } *entries;
      size_t min_objects_per_entry;
      size_t max_objects_per_entry;
      size_t total_object_count;
      size_t total_hash_object_count;
      size_t total_hash_object_size;
      size_t total_hash_object_busy_size;
      size_t busy_key_count;
      size_t free_key_count;

      Stats();
      ~Stats();
      void trace(Boolean full = True, FILE *fd = stdout) const;
      std::string toString(Boolean full = True) const;
    };

    /**
       Not yet documented
       @param stats
       @return
    */
    Status getStats(HIdx::Stats &stats) const;

    /**
       Not yet documented
       @param dspid
       @return
    */
    Status move(short dspid, eyedbsm::Oid &newoid,
		hash_key_t hash_key = NULL,
		void *hash_data = NULL,
		PostCollapseTransformer *post_collapse_transformer = NULL);

    /**
       Not yet documented
       @param newoid
       @param key_count
       @param mag_order
       @param dspid
       @param impl_hints
       @param impl_hints_cnt
       @param hash_key
       @param hash_data
       @param ktype
       @return
    */
    Status reimplementToHash(Oid &newoid, int key_count, int mag_order = 0,
			     short dspid = DefaultDspid,
			     const int *impl_hints = 0,
			     unsigned int impl_hints_cnt = 0,
			     hash_key_t hash_key = 0,
			     void *hash_data = 0,
			     KeyType *ktype = 0);

    /**
       Not yet documented
       @param newoid
       @param degree
       @param dspid
       @return
    */
    Status reimplementToBTree(Oid &newoid, int degree = 0,
			      short dspid = DefaultDspid);

    /**
       Not yet documented
       @param stats
       @param key_count
       @param mag_order
       @param impl_hints
       @param impl_hints_cnt
       @param hash_key
       @param hash_data
       @return
    */
    Status simulate(HIdx::Stats &stats, int key_count,
		    int mag_order = 0,
		    const int *impl_hints = 0,
		    unsigned int impl_hints_cnt = 0,
		    hash_key_t hash_key = 0,
		    void *hash_data = 0) const;

  public: /* conceptually private */
    struct CellHeader {
    public:
      eyedblib::uint32 free:1, size:31;
      eyedblib::int32 cell_free_prev, cell_free_next;
    };

    struct CListObjHeader {
    public:
      unsigned int size;
      eyedblib::uint16 free_cnt, alloc_cnt;
      eyedblib::uint32 free_whole;
      eyedblib::int32 cell_free_first;
      Oid clobj_free_prev, clobj_free_next;
      Oid clobj_prev, clobj_next;
    };
  
    struct CListHeader {
    public:
      Oid clobj_first, clobj_last;
      Oid clobj_free_first;
    };
  };

  /**
     Not yet documented.
  */
  class HIdxCursor : public IdxCursor {

    const HIdx *idx;
    void *skey, *ekey;
    Boolean sexcl, eexcl;
    static const char defaultSKey[];
    char *sdata, *edata, *cur;
    unsigned int datacnt, idata;
    unsigned int jumpsize;
    Boolean nocopy;
    Boolean data_tofree;
    Status read(Boolean& end);
    Boolean equal;
    unsigned int k_cur, k_end;
    int cmp_realize(const void *, const void *, Boolean, unsigned char) const;
    int cmp(const void *) const;
    Oid koid;
    Boolean state;
    Boolean (*user_cmp)(const void *key, void *cmp_arg);
    void *cmp_arg;
    void append_next(void *data, Idx::Key *key, unsigned int n, DataBuffer *dataBuffer);

    void init(DbHandle *);

    // parallel management
    unsigned int perf_cnt, perf_end_cnt;
    Boolean master, slave;
    class LinkList;
    Boolean parallelInit(int thread_cnt);
    eyedblib::ThreadPerformer **perfs;
    HIdxCursor **perf_curs;
    LinkList *list;
    LinkList **lists;
    eyedblib::ThreadPool *thrpool;
    HIdxCursor(const HIdx *,
	       unsigned int k_start,
	       unsigned int k_end,
	       const void *,
	       const void *,
	       Boolean,
	       Boolean,
	       Boolean (*user_cmp)(const void *, void *),
	       void *cmp_arg,
	       LinkList *);

    Status next(Boolean *found, unsigned int *found_cnt, void *data, Idx::Key *key, DataBuffer *dataBuffer);

  public:
    /**
       Not yet documented
       @param idx
       @param skey
       @param ekey
       @param sexcl
       @param eexcl
       @param user_cmp
       @param cmp_arg
       @param thread_cnt
    */
    HIdxCursor(const HIdx *idx,
	       const void *skey = 0,
	       const void *ekey = defaultSKey,
	       Boolean sexcl = False,
	       Boolean eexcl = False,
	       Boolean (*user_cmp)(const void *key, void *cmp_arg) = 0,
	       void *cmp_arg = 0,
	       int thread_cnt = 0);

    /**
       Not yet documented
       @param found
       @param data
       @param key
       @return
    */
    Status next(Boolean *found, void *data = 0, Idx::Key *key = 0);

    /**
       Not yet documented
       @param found
       @param data
       @param key
       @return
    */
    Status next(Boolean *found, DataBuffer &data, Idx::Key *key = 0);

    /**
       Not yet documented
       @param found_cnt
       @param key
       @return
    */
    // note: can be only used on data_grouped_by_key index
    Status next(unsigned int *found_cnt, Idx::Key *key = 0);

    ~HIdxCursor();
  };

  /**
     @}
  */

};

#endif
