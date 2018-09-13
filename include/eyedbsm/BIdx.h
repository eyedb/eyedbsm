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
   Authors: Stuart Pook
            Eric Viara <viara@sysra.com>
*/


#ifndef	_eyedbsm_BIdx_
#define	_eyedbsm_BIdx_

#include <string.h>

#include <eyedbsm/Idx.h>

namespace eyedbsm {

  /**
     @addtogroup eyedbsm
     @{
  */

  enum {
    BIDX_DEF_DEGREE = 128
  };

  /**
     Not yet documented.
  */
  class BIdx : public Idx {
  public:
    class BTree;
    class Node;
    class Space;
    class InCore;

  private:

    friend class InCore;
    friend class Node;
    friend class Space;
    friend class BIdxCursor;
    Space * free;
    Space * occupied;

    eyedbsm::DbHandle * const dbh;
    eyedbsm::Oid treeOid;
    KeyType * _keyType;
    unsigned _nkeys;
    unsigned keySize;
    unsigned dataSize;
    short dspid;
    unsigned int degree;
    unsigned int maxchildren;
    unsigned int count;
    eyedbsm::Status stat;
    BIdx(BIdx const &);			// prevent copying
    BIdx & operator=(BIdx const &);	// prevent copying
    eyedbsm::Status fatal();
    eyedbsm::Status fatal(eyedbsm::Status);
    void kdCopy(void * kO, void * dO, void const * k, void const * d,
		unsigned int cnt = 1) const;
    eyedbsm::Status create(unsigned int degree, unsigned dataSize, KeyType const types[], unsigned ntypes, short dspid);
    eyedbsm::Status count_manage(int inc);
    eyedbsm::Status copy_realize(Idx *idx) const;
    eyedbsm::Status readBTree(BTree &) const;
    eyedbsm::Status writeBTree(const BTree &) const;
    eyedbsm::Status readKeyType(KeyType *&, unsigned int nkeys, const eyedbsm::Oid &) const;
    eyedbsm::Status createKeyType(const KeyType *, unsigned int nkeys, eyedbsm::Oid *) const;
    eyedbsm::Status readNode(Node *, const eyedbsm::Oid &) const;
    eyedbsm::Status writeNode(const Node *, const eyedbsm::Oid &) const;
    eyedbsm::Status createNode(const Node *, eyedbsm::Oid *) const;
    eyedbsm::Status searchPerform(const void *key, unsigned int *found_cnt, Boolean found_any, void * data);
    Node *tmpnode;

  public:
    /**
       Not yet documented.
       @param key
       @param d
       @param bswap
       @return
    */
    int cmp(void const *key, void const *d, unsigned char bswap);

    /**
       Not yet documented
       @param vh
       @param dataSize
       @param types
       @param dspid
       @param degree
       @param ntypes
    */
    BIdx(eyedbsm::DbHandle * vh, unsigned dataSize, KeyType const types[],
	 short dspid,
	 unsigned int degree = BIDX_DEF_DEGREE,
	 unsigned ntypes = 1);

    /**
       Not yet documented
       @param vh
       @param type
       @param dataSize
       @param dspid
       @param degree
    */
    BIdx(eyedbsm::DbHandle * vh, Type type, unsigned dataSize,
	 short dspid,
	 unsigned int degree = BIDX_DEF_DEGREE);

    /**
       Not yet documented
       @param vh
       @param idx
       @param precmp
    */
    BIdx(eyedbsm::DbHandle * vh, 
	 eyedbsm::Oid const &idx,
	 eyedbsm::Boolean (*precmp)(void const * p, void const * q, KeyType const * type, int & r) = 0);

    /**
       Not yet documented
       @param precmp
    */
    void open(eyedbsm::Boolean (*precmp)(void const * p, void const * q,
					 KeyType const * type, int & r) = 0);

    /**
       Not yet documented
       @return
    */
    virtual BIdx *asBIdx() {return this;}

    /**
       Not yet documented
       @param dspid
       @return
    */
    Status move(short dspid, eyedbsm::Oid &newoid);

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
    eyedbsm::Status reimplementToHash(eyedbsm::Oid &newoid, int key_count, int mag_order = 0,
				      short dspid = eyedbsm::DefaultDspid,
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
    eyedbsm::Status reimplementToBTree(eyedbsm::Oid &newoid, int degree = 0,
				       short dspid = eyedbsm::DefaultDspid);

    // stats methods not implemented
    struct Stats {
      const BIdx *idx;
      /*
	unsigned int degree;
	unsigned int dataSize;
	unsigned int keySize;
      */
      size_t keyOffset;
      size_t keyType;

      size_t total_object_count;
      size_t total_btree_object_count;
      size_t btree_node_size;
      size_t total_btree_node_count;
      size_t btree_key_object_size;
      size_t btree_data_object_size;
      size_t total_btree_object_size;

      void trace(FILE * = stdout) const;
      std::string toString() const;
    };

    eyedbsm::Status getStats(std::string& stats) const;
    eyedbsm::Status getStats(BIdx::Stats &stats) const;

    /**
       Not yet documented
       @return
    */
    unsigned getKeySize() const {return keySize;}

    /**
       Not yet documented
       @return
    */
    unsigned getDataSize() const {return dataSize;}

    /**
       Not yet documented
       @param nkeys
       @return
    */
    const Idx::KeyType *getKeyTypes(unsigned int &nkeys) const {
      nkeys = _nkeys;
      return _keyType;
    }

    /**
       Not yet documented
       @return
    */
    short getDspid() const {return dspid;}

    /**
       Not yet documented
       @return
    */
    unsigned int getDegree() const {return degree;}

    /**
       Not yet documented
       @return
    */
    unsigned int getMaxChildren() const {return maxchildren;}

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
       @return
    */
    void setDefaultDspid(short dspid);

    /**
       Not yet documented
       @param oids
       @param cnt
       @return
    */
    eyedbsm::Status getObjects(eyedbsm::Oid *&oids, unsigned int &cnt) const;

    /**
       Not yet documented
       @param degree
       @return
    */
    static unsigned int getMagOrder(unsigned int degree);

    /**
       Not yet documented
       @param magorder
       @return
    */
    static unsigned int getDegree(unsigned int magorder);

    ~BIdx();

    /**
       Not yet documented
       @param key
       @param data
       @return
    */
    eyedbsm::Status insert(void const * key, void const * data);

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
       @param data
       @param found
       @return
    */
    eyedbsm::Status remove(void const * key, void const * data, eyedbsm::Boolean * found = 0);

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
       @param xdata
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
    eyedbsm::Status searchAny(void const * key, eyedbsm::Boolean * found, void * data = 0);

    /**
       Not yet documented
       @return
    */
    eyedbsm::Status destroy();

    //  eyedbsm::Status check(unsigned long * = 0);

    /**
       Not yet documented
       @return
    */
    eyedbsm::Oid const & oid() const { return treeOid; }

    /**
       Not yet documented
       @return
    */
    eyedbsm::Status status() const { return stat; }
  };

  class BIdxChain;

  /**
     Not yet documented.
  */
  class BIdxCursor : public IdxCursor {
    BIdx * idx;
    void * sKey;
    eyedbsm::Boolean sExclusive;
    void * eKey;
    eyedbsm::Boolean eExclusive;
    BIdxChain * chain;
    BIdxChain * chainFirst;
    static char const defaultSKey[];
    BIdxCursor(BIdxCursor const &);
    BIdxCursor & operator=(BIdxCursor const &);
    eyedbsm::Boolean (*user_cmp)(const void *key, void *cmp_arg);
    void *cmp_arg;

  public:
    /**
       Not yet documented
       @param idx
       @param sKey
       @param eKey
       @param sExclusive
       @param eExclusive
       @param user_cmp
       @param cmp_arg
    */
    BIdxCursor(BIdx *idx,
	       void const * sKey = 0,
	       void const * eKey = defaultSKey,
	       eyedbsm::Boolean sExclusive = eyedbsm::False,
	       eyedbsm::Boolean eExclusive = eyedbsm::False,
	       eyedbsm::Boolean (*user_cmp)(const void *key, void *cmp_arg) = 0,
	       void *cmp_arg = 0);

    /**
       Not yet documented
       @param found
       @param data
       @param key
       @return
    */
    Status next(eyedbsm::Boolean * found, void * data = 0, Idx::Key * key = 0);

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
    Status next(unsigned int *found_cnt, Idx::Key *key = 0);

    ~BIdxCursor();
  };

  /**
     @}
  */
}

#endif
