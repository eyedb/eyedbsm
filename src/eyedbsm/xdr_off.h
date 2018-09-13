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


#ifndef _EYEDBSM_XDR_OFF_H
#define _EYEDBSM_XDR_OFF_H

#define MapHeader_SIZE 68
#define DatafileDesc_SIZE 376
#define DataspaceDesc_SIZE 104
#define DbHeader_SIZE 250696
#define DbRootEntry_SIZE 80
#define DbRootEntries_SIZE 2560

#define MapHeader_mtype_OFF 0
#define MapHeader_sizeslot_OFF 4
#define MapHeader_pow2_OFF 8
#define MapHeader_nslots_OFF 12
#define MapHeader_nbobjs_OFF 16
#define MapHeader_mstat_OFF 24
#define MapHeader_mstat_mtype_OFF 24
#define MapHeader_u_bmh_OFF 56
#define MapHeader_u_bmh_slot_cur_OFF 56
#define MapHeader_u_bmh_slot_lastbusy_OFF 60
#define MapHeader_u_bmh_retry_OFF 64
#define MapHeader_mstat_u_bmstat_OFF 32
#define MapHeader_mstat_u_bmstat_obj_count_OFF 32
#define MapHeader_mstat_u_bmstat_busy_slots_OFF 36
#define MapHeader_mstat_u_bmstat_busy_size_OFF 40
#define MapHeader_mstat_u_bmstat_hole_size_OFF 48
#define MapHeader_mstat_u_lmstat_OFF 32
#define MapHeader_mstat_u_lmstat_nfreecells_OFF 32
#define MapHeader_u_lmh_OFF 56
#define MapHeader_u_lmh_firstcell_OFF 56

#define DatafileDesc_file_OFF 0
#define DatafileDesc_name_OFF 256
#define DatafileDesc___maxsize_OFF 288
#define DatafileDesc_mp_OFF 296
#define DatafileDesc___lastslot_OFF 368
#define DatafileDesc___dspid_OFF 372

#define DataspaceDesc_name_OFF 0
#define DataspaceDesc___cur_OFF 32
#define DataspaceDesc___ndat_OFF 36
#define DataspaceDesc___datid_OFF(datid) (40 + (datid) * sizeof(eyedblib::int16))

#define DbRootEntry_key_OFF 0
#define DbRootEntry_data_OFF 16

#define DbHeader___magic_OFF 0
#define DbHeader___dbid_OFF 4
#define DbHeader_state_OFF 8
#define DbHeader___guest_uid_OFF 12
#define DbHeader___prot_uid_oid_OFF 16
#define DbHeader___prot_list_oid_OFF 24
#define DbHeader___prot_lock_oid_OFF 32
#define DbHeader_shmfile_OFF 40
#define DbHeader___nbobjs_OFF 296
#define DbHeader___ndat_OFF 300
#define DbHeader_dat_OFF(datid) (304 + (datid) * DatafileDesc_SIZE)
#define DbHeader___ndsp_OFF 192816
#define DbHeader_dsp_OFF(dspid) (192820 + (dspid) * DataspaceDesc_SIZE)
#define DbHeader___def_dspid_OFF 246068
#define DbHeader_vre_OFF(idx) (246070 + (idx) * DbRootEntry_SIZE)
#define DbHeader___lastidxbusy_OFF 248632
#define DbHeader___curidxbusy_OFF 248636
#define DbHeader___lastidxblkalloc_OFF 248640
#define DbHeader___lastnsblkalloc_OFF(datid) (248644 + (datid) * sizeof(eyedbsm::Oid::NX))

// access field macros

// Generic macros
#define Struct_Ref_X(Struct, addr, Attr, X) ((addr) + Struct##_##Attr##_OFF X)

#define Struct_X(Struct, Type, addr, Attr, X) (*(Type *)((addr) + Struct##_##Attr##_OFF X))
//#define Struct_(Struct, Type, addr, Attr) (*(Type *)((addr) + Struct##_##Attr##_OFF))
#define Struct_(Struct, Type, addr, Attr) Struct_X(Struct, Type, addr, Attr, )

#define Struct_ptr(Struct, Type, addr, Attr) (Type)((addr) + Struct##_##Attr##_OFF)

// Type oriented macros
#define MapHeader_(Type, addr, Attr) Struct_(MapHeader, Type, addr,  Attr)
#define DatafileDesc_(Type, addr, Attr) Struct_(DatafileDesc, Type, addr,  Attr)
#define DataspaceDesc_(Type, addr, Attr) Struct_(DataspaceDesc, Type, addr,  Attr)
#define DbRootEntry_(Type, addr, Attr) Struct_(DbRootEntry, Type, addr, Attr)
#define DbHeader_(Type, addr, Attr) Struct_(DbHeader, Type, addr, Attr)

#define DatafileDesc_ptr(Type, addr, Attr) Struct_ptr(DatafileDesc, Type, addr,  Attr)
#define DataspaceDesc_ptr(Type, addr, Attr) Struct_ptr(DataspaceDesc, Type, addr,  Attr)
#define DbRootEntry_ptr(Type, addr, Attr) Struct_ptr(DbRootEntry, Type, addr, Attr)
#define DbHeader_ptr(Type, addr, Attr) Struct_ptr(DbHeader, Type, addr, Attr)

// Field oriented macros
#define MapHeader_mtype(addr) MapHeader_(short, addr, mtype)
#define MapHeader_sizeslot(addr) MapHeader_(unsigned int, addr, sizeslot)
#define MapHeader_pow2(addr) MapHeader_(unsigned int, addr, pow2)
#define MapHeader_nslots(addr) MapHeader_(NS, addr, nslots)
#define MapHeader_nbobjs(addr) MapHeader_(Oid::NX, addr, nbobjs)
#define MapHeader_mstat_mtype(addr) MapHeader_(short, addr, mstat_mtype)
#define MapHeader_u_bmh_slot_cur(addr) MapHeader_(Oid::NX, addr, u_bmh_slot_cur)
#define MapHeader_u_bmh_slot_lastbusy(addr) MapHeader_(Oid::NX, addr, u_bmh_slot_lastbusy)
					       
#define MapHeader_u_bmh_retry(addr) MapHeader_(short, addr, u_bmh_retry)
					       
#define MapHeader_mstat_u_bmstat_obj_count(addr) MapHeader_(Oid::NX, addr, mstat_u_bmstat_obj_count)
#define MapHeader_mstat_u_bmstat_busy_slots(addr) MapHeader_(NS, addr, mstat_u_bmstat_busy_slots)
#define MapHeader_mstat_u_bmstat_busy_size(addr) MapHeader_(unsigned long long, addr, mstat_u_bmstat_busy_size)
#define MapHeader_mstat_u_bmstat_hole_size(addr) MapHeader_(unsigned long long, addr, mstat_u_bmstat_hole_size)

#define MapHeader_mstat_u_lmstat_nfreecells(addr) MapHeader_(unsigned int, addr, mstat_u_lmstat_nfreecells)

#define MapHeader_u_lmh_firstcell(addr) MapHeader_(int, addr, u_lmh_firstcell)

#define DatafileDesc_file(addr) DatafileDesc_ptr(char *, addr, file)
#define DatafileDesc_name(addr) DatafileDesc_ptr(char *, addr, name)
#define DatafileDesc___maxsize(addr) DatafileDesc_(unsigned int, addr, __maxsize)
#define DatafileDesc___lastslot(addr) DatafileDesc_(unsigned int, addr, __lastslot)
#define DatafileDesc___dspid(addr) DatafileDesc_(unsigned short, addr, __dspid)

#define DataspaceDesc_name(addr) DataspaceDesc_ptr(char *, addr, name)
#define DataspaceDesc___cur(addr) DataspaceDesc_(int, addr, __cur)
#define DataspaceDesc___ndat(addr) DataspaceDesc_(int, addr, __ndat)
					       
// !!!!!
#define DataspaceDesc___datid(addr, datid) Struct_X(DataspaceDesc, short, addr, __datid, (datid))

#define DbRootEntry_key(addr) DbRootEntry_ptr(char *, addr, key)
#define DbRootEntry_data(addr) DbRootEntry_ptr(char *, addr, data)

#define DbHeader___magic(addr) DbHeader_(unsigned int, addr, __magic)
#define DbHeader___dbid(addr) DbHeader_(int, addr, __dbid)
#define DbHeader_state(addr) DbHeader_(char, addr, state)
#define DbHeader___guest_uid(addr) DbHeader_(int, addr, __guest_uid)
#define DbHeader___prot_uid_oid(addr) DbHeader_(Oid, addr, __prot_uid_oid)
#define DbHeader___prot_list_oid(addr) DbHeader_(Oid, addr, __prot_list_oid)
#define DbHeader___prot_lock_oid(addr) DbHeader_(Oid, addr, __prot_lock_oid)

#define DbHeader_shmfile(addr) DbHeader_ptr(char *, addr, shmfile)

#define DbHeader___nbobjs(addr) DbHeader_(Oid::NX, addr, __nbobjs)
#define DbHeader___ndat(addr) DbHeader_(unsigned int, addr, __ndat)

// !!!
#define DbHeader_dat_ref(addr, datid) Struct_Ref_X(DbHeader, addr, dat, (datid))

#define DbHeader___ndsp(addr) DbHeader_(unsigned int, addr, __ndsp)

// !!!!
#define DbHeader_dsp_ref(addr, datid) Struct_Ref_X(DbHeader, addr, dsp, (datid))

#define DbHeader___def_dspid(addr) DbHeader_(short, addr, __def_dspid)
#define DbHeader_vre(addr, idx) Struct_Ref_X(DbHeader, addr, vre, (idx))
#define DbHeader___lastidxbusy(addr) DbHeader_(Oid::NX, addr, __lastidxbusy)
#define DbHeader___curidxbusy(addr) DbHeader_(Oid::NX, addr, __curidxbusy)

#define DbHeader___lastidxblkalloc(addr) DbHeader_(Oid::NX, addr, __lastidxblkalloc)

// !!!
#define DbHeader___lastnsblkalloc(addr, datid) Struct_X(DbHeader, Oid::NX, addr, __lastnsblkalloc, (datid))

namespace eyedbsm {

  class DbRootEntry {
    unsigned char *addr;

  public:
    DbRootEntry(unsigned char *addr) : addr(addr) { }

    char *key() {
      return DbRootEntry_key(addr);
    }

    char *data() {
      return DbRootEntry_data(addr);
    }
  };


  //typedef DbRootEntry DbRootEntries[MAX_ROOT_ENTRIES];

  class MapHeader {

    unsigned char *addr;
    bool toFree;

  public:
    MapHeader() {addr = (unsigned char *)(new long long[MapHeader_SIZE / sizeof(unsigned long long)]); toFree = true;}

    MapHeader(unsigned char *addr) : addr(addr) { toFree = false;}

    ~MapHeader() { if (toFree) delete [] addr;}

    void memzero() {
      memset(addr, 0, MapHeader_SIZE);
    }

    unsigned char *_addr() {return addr;}

    short &mtype() {
      return MapHeader_mtype(addr);
    }

    short mtype() const {
      return MapHeader_mtype(addr);
    }

    unsigned int &sizeslot() {
      return MapHeader_sizeslot(addr);
    }

    unsigned int sizeslot() const {
      return MapHeader_sizeslot(addr);
    }

    unsigned int &pow2() {
      return MapHeader_pow2(addr);
    }

    unsigned int pow2() const {
      return MapHeader_pow2(addr);
    }

    NS &nslots() {
      return MapHeader_nslots(addr);
    }

    Oid::NX &nbobjs() {
      return MapHeader_nbobjs(addr);
    }

    short &mstat_mtype() {
      return MapHeader_mstat_mtype(addr);
    }

    Oid::NX &mstat_u_bmstat_obj_count() {
      return MapHeader_mstat_u_bmstat_obj_count(addr);
    }

    NS &mstat_u_bmstat_busy_slots() {
      return MapHeader_mstat_u_bmstat_busy_slots(addr);
    }

    unsigned long long &mstat_u_bmstat_busy_size() {
      return MapHeader_mstat_u_bmstat_busy_size(addr);
    }

    unsigned long long &mstat_u_bmstat_hole_size() {
      return MapHeader_mstat_u_bmstat_hole_size(addr);
    }

    Oid::NX &u_bmh_slot_cur() {
      return MapHeader_u_bmh_slot_cur(addr);
    }

    Oid::NX &u_bmh_slot_lastbusy() {
      return MapHeader_u_bmh_slot_lastbusy(addr);
    }

    short &u_bmh_retry() {
      return MapHeader_u_bmh_retry(addr);
    }
  };

  class DatafileDesc {

    unsigned char *addr;

  public:
    MapHeader _mp;
    DatafileDesc(unsigned char *addr) :
      addr(addr), _mp(addr + DatafileDesc_mp_OFF) { }

    char *file() {
      return DatafileDesc_file(addr);
    }

    char *name() {
      return DatafileDesc_name(addr);
    }

    unsigned int &__maxsize() {
      return DatafileDesc___maxsize(addr);
    }

    MapHeader *mp() {
      return &_mp;
    }

    unsigned int &__lastslot() {
      return DatafileDesc___lastslot(addr);
    }

    unsigned short &__dspid() {
      return DatafileDesc___dspid(addr);
    }
  };

  class DataspaceDesc {

    unsigned char *addr;

  public:
    DataspaceDesc(unsigned char *addr) : addr(addr) { }

    char *name() {
      return DataspaceDesc_name(addr);
    }

    int &__cur() {
      return DataspaceDesc___cur(addr);
    }

    int &__ndat() {
      return DataspaceDesc___ndat(addr);
    }

    short *__datid_ref() {
      return (short *)(addr + DataspaceDesc___datid_OFF(0));
    }

    short &__datid(int datid) {
      return DataspaceDesc___datid(addr, datid);
    }
  };

  class DbHeader {

    unsigned char *addr;
    bool toFree;

  public:
    DbHeader() {addr = (unsigned char *)(new long long[DbHeader_SIZE / sizeof(unsigned long long)]); toFree = true;}
    
    DbHeader(unsigned char *addr) : addr(addr) { toFree = false;}

    ~DbHeader() { if (toFree) delete [] addr;}

    void memzero() {
      memset(addr, 0, DbHeader_SIZE);
    }

    unsigned char *_addr() {return addr;}

    unsigned int &__magic() {
      return DbHeader___magic(addr);
    }

    unsigned int __magic() const {
      return DbHeader___magic(addr);
    }

    int &__dbid() {
      return DbHeader___dbid(addr);
    }

    char &state() {
      return DbHeader_state(addr);
    }

    int &__guest_uid() {
      return DbHeader___guest_uid(addr);
    }

    Oid &__prot_uid_oid() {
      return DbHeader___prot_uid_oid(addr);
    }

    Oid &__prot_list_oid() {
      return DbHeader___prot_list_oid(addr);
    }

    Oid &__prot_lock_oid() {
      return DbHeader___prot_lock_oid(addr);
    }

    char *shmfile() {
      return DbHeader_shmfile(addr);
    }

    Oid::NX &__nbobjs() {
      return DbHeader___nbobjs(addr);
    }

    unsigned int &__ndat() {
      return DbHeader___ndat(addr);
    }

    DatafileDesc dat(short datid) const {
      return DatafileDesc(dat_addr(datid));
    }

    unsigned char *dat_addr(short datid) const {
      return DbHeader_dat_ref(addr, datid);
    }

    unsigned int &__ndsp() {
      return DbHeader___ndsp(addr);
    }

    DataspaceDesc dsp(short datid) const {
      return DataspaceDesc(dsp_addr(datid));
    }

    unsigned char *dsp_addr(short dspid) const {
      return DbHeader_dsp_ref(addr, dspid);
    }

    short &__def_dspid() {
      return DbHeader___def_dspid(addr);
    }

    DbRootEntry vre(int idx) {
      return DbRootEntry(vre_addr(idx));
    }

    unsigned char *vre_addr(int idx) {
      return DbHeader_vre(addr, idx);
    }

    Oid::NX &__lastidxbusy() {
      return DbHeader___lastidxbusy(addr);
    }

    Oid::NX &__curidxbusy() {
      return DbHeader___curidxbusy(addr);
    }

    Oid::NX &__lastidxblkalloc() {
      return DbHeader___lastidxblkalloc(addr);
    }

    Oid::NX &__lastnsblkalloc(short datid) {
      return DbHeader___lastnsblkalloc(addr, datid);
    }
  };
}

#endif
