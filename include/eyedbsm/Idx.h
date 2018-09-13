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


#ifndef _EYEDBSM_IDX_H
#define _EYEDBSM_IDX_H

#include <string>

namespace eyedbsm {

  class BIdx;
  class HIdx;

  class Idx {

  public:

    enum Type
      {
	tChar,
	tUnsignedChar,
	tSignedChar,
	tInt16,
	tUnsignedInt16,
	tInt32,
	tUnsignedInt32,
	tInt64,
	tUnsignedInt64,
	tFloat32,
	tFloat64,
	tString,
	tOid
      };

    enum IdxType {
      HashType  = 0x2311,
      BTreeType = 0xa765
    };

    struct KeyType
    {
      Type type;
      unsigned int count;
      unsigned int offset;
    };

    typedef eyedbsm::Status (*hash_key_t)(const void *, unsigned int, void *, unsigned int &);
  
    class Key {

    public:
      Key(int sz = 0);
      void *getKey() {return key;}
      void setKey(void *key, int sz, const KeyType &);
      unsigned int getSize() const {return size;}
      ~Key();

    private:
      void *key;
      unsigned int size;
    };

    /**
       Not yet documented
       @param opened
       @param precmp
    */
    Idx(eyedbsm::Boolean opened,
	eyedbsm::Boolean (*precmp)(void const * p, void const * q,
				   KeyType const * type, int & r) = 0);


    // "virtual" constructor
    /**
       Not yet documented
       @param dbh
       @param oid
       @param idx
       @return
    */
    static eyedbsm::Status make(eyedbsm::DbHandle *dbh, const eyedbsm::Oid &oid,
				Idx *&idx);

    /**
       Not yet documented
       @return
    */
    eyedbsm::Boolean isOpened() const {return opened;}

    virtual eyedbsm::Status insert(const void *key, const void *data) = 0;

    virtual eyedbsm::Status insert(const void *key, const void *data, unsigned int datasz) = 0;

    virtual eyedbsm::Status remove(const void *key, const void *data, eyedbsm::Boolean *found = 0) = 0;

    virtual eyedbsm::Status remove(const void *key, const void *data, unsigned int datasz, eyedbsm::Boolean *found = 0) = 0;

    virtual eyedbsm::Status search(const void *key, unsigned int *found_cnt) = 0;

    virtual eyedbsm::Status searchAny(const void *key, eyedbsm::Boolean *found, void * xdata = 0) = 0;

    /**
       Not yet documented
       @return
    */
    virtual eyedbsm::Status destroy() = 0;

    /**
       Not yet documented
       @return
    */
    virtual eyedbsm::Oid const &oid() const = 0;

    /**
       Not yet documented
       @return
    */
    virtual eyedbsm::Status status() const = 0;

    /**
       Not yet documented
       @return
    */
    virtual BIdx *asBIdx() {return NULL;}

    /**
       Not yet documented
       @return
    */
    virtual HIdx *asHIdx() {return NULL;}

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
    virtual eyedbsm::Status reimplementToHash(eyedbsm::Oid &newoid, int key_count,
					      int mag_order = 0,
					      short dspid = eyedbsm::DefaultDspid,
					      const int *impl_hints = 0,
					      unsigned int impl_hints_cnt = 0,
					      hash_key_t hash_key = 0,
					      void *hash_data = 0,
					      KeyType *ktype = 0) = 0;

    /**
       Not yet documented
       @param newoid
       @param degree
       @param dspid
       @return
    */
    virtual eyedbsm::Status reimplementToBTree(eyedbsm::Oid &newoid, int degree = 0,
					       short dspid = eyedbsm::DefaultDspid) = 0;

    /**
       Not yet documented
       @return
    */
    virtual unsigned int computeCount();

    /**
       Not yet documented
       @return
    */
    virtual unsigned int getCount() const = 0;

    /**
       Not yet documented
       @return
    */
    virtual short getDefaultDspid() const = 0;

    /**
       Not yet documented
       @param dspid
    */
    virtual void setDefaultDspid(short dspid) = 0;

    /**
       Not yet documented
       @param oids
       @param cnt
       @return
    */
    virtual eyedbsm::Status getObjects(eyedbsm::Oid *&oids, unsigned int &cnt) const = 0;

    virtual ~Idx() {}

  public: // implementation access
    int compare(void const * p, void const * q, KeyType const * type,
		unsigned char bswap) const;
    static size_t typeSize(Type type);
    static const char *typeString(Type type);
    eyedbsm::Boolean (*precmp)(void const * p, void const * q,
			       KeyType const * type, int & r);

  protected:
    eyedbsm::Boolean opened;
    eyedbsm::Status checkOpened() const;

  public:
    static void h2x(void *xkey, const void *hkey, const KeyType &keyType);
    static void x2h(void *hkey, const void *xkey, const KeyType &keyType,
		    unsigned int size);
  };

  class DataBuffer {

  public:
    DataBuffer() : data(0), datasz(0), allocsz(0) { }

    DataBuffer(const DataBuffer &buffer) : data(0), datasz(0), allocsz(0) {
      *this = buffer;
    }

    DataBuffer &operator=(const DataBuffer &buffer) {
      garbage();
      setData(buffer.data, buffer.datasz);
      return *this;
    }

    void *getData(unsigned int &_datasz) const {
      _datasz = datasz;
      return (void *)data;
    }

    void setData(void *data, unsigned int datasz);

    ~DataBuffer() {
      garbage();
    }

  private:
    unsigned char *data;
    unsigned int datasz;
    unsigned int allocsz;

    void garbage() {
      delete [] data;
      data = 0;
    }
  };

  class AllocBuffer {

  public:
    AllocBuffer() : allocsz(0), data(0) { }

    char *alloc(unsigned int size) {
      if (size > allocsz) {
	allocsz = 2 * size;
	delete [] data;
	data = new char[allocsz];
      }
      return data;
    }
    
    ~AllocBuffer() {
      delete [] data;
      data = 0;
    }

  private:
    unsigned int allocsz;
    char *data;
  };

  class IdxCursor {

  public:
    /**
       Not yet documented
    */
    IdxCursor() {}

    /**
       Not yet documented
       @param found
       @param data
       @param key
       @return
    */
    virtual Status next(eyedbsm::Boolean *found, void *data = 0, Idx::Key *key = 0) = 0;

    /**
       Not yet documented
       @param found
       @param data
       @param key
       @return
    */
    virtual Status next(eyedbsm::Boolean *found, DataBuffer &data, Idx::Key *key = 0) = 0;

    /**
       Not yet documented
       @param found_cnt
       @param key
       @return
    */
    virtual Status next(unsigned int *found_cnt, Idx::Key *key = 0) = 0;

    virtual ~IdxCursor() {}
  };

  enum {
    OPS_NOSWAP = 0,
    OP1_SWAP = 0x1,
    OP2_SWAP = 0x2,
    OPS_SWAP = (OP1_SWAP|OP2_SWAP)
  };

  const size_t Idx_max_type_size = 256; // must be greater or equal than
  // any type size (i.e. sizeof(eyedbsm::Oid), sizeof(eyedblib::float64) ...) +
  // [+ sizeof(index overhead)]

};

#endif
