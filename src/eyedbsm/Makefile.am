lib_LTLIBRARIES= libeyedbsm.la

libeyedbsm_la_SOURCES=				\
BIdxBTree.cc					\
BIdxDelete.cc					\
BIdxDestroy.cc					\
BIdxIncore.cc					\
BIdxInsert.cc					\
BIdxRedefine.cc					\
BIdxSearch.cc					\
BIdxXDR.cc					\
HIdx.cc						\
Idx.cc						\
api.cc					\
hashtable.cc					\
lock.cc						\
mutex.cc					\
transaction.cc					\
kern_alloc.cc					\
kern_dat.cc					\
kern_db.cc					\
kern_dsp.cc					\
kern_map.cc					\
kern_obj.cc					\
kern_omp.cc					\
kern_prot.cc					\
kern_reg.cc					\
kern_root.cc					\
kern_utils.cc					\
api_lib.cc					\
oapi.cc						\
status.cc					\
xdr.cc						\
smdcli.cc					\
xm_alloc.cc

libeyedbsm_la_LDFLAGS= -release $(EYEDBSM_VERSION)

SMLIBS=libeyedbsm.la $(top_builddir)/src/lib/libeyedbutils.la $(top_builddir)/src/lib/libeyedbrpcfe.la 

if COND_EYEDBSMD

sbin_PROGRAMS= eyedbsmd	eyedbsmtool

eyedbsmd_SOURCES=eyedbsmd.cc
eyedbsmd_LDADD=$(SMLIBS)

eyedbsmtool_SOURCES=eyedbsmtool.cc
eyedbsmtool_LDADD=$(SMLIBS)

else

sbin_PROGRAMS= eyedbsmtool

eyedbsmtool_SOURCES=eyedbsmtool.cc
eyedbsmtool_LDADD=$(SMLIBS)

endif

# The last directory is needed for endian.h, which is generated by configure.in
AM_CPPFLAGS=-I$(top_srcdir)/src -I$(top_srcdir)/include -I$(top_builddir)/include

noinst_HEADERS= \
BIdxBTree.h \
eyedbsm_p.h \
hashtable.h \
IdxP.h \
kern.h \
kern_p.h \
lock.h \
transaction.h \
xdr_off.h \
xdr_p.h 

