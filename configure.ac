# 
# configure.in for eyedbsm
# 

m4_include(version.m4)
AC_INIT([PRODUCT_NAME], [PRODUCT_VERSION], [PRODUCT_BUGREPORT], [PRODUCT_TARNAME])

AC_SUBST([EYEDBSM_VERSION_MAJOR], [PRODUCT_VERSION_MAJOR], [Eyedbsm major version])
AC_SUBST([EYEDBSM_VERSION_MINOR], [PRODUCT_VERSION_MINOR], [Eyedbsm minor version])
AC_SUBST([EYEDBSM_VERSION_PATCH], [PRODUCT_VERSION_PATCH], [Eyedbsm patch level])
AC_SUBST([EYEDBSM_VERSION], [PRODUCT_VERSION], [Eyedbsm version])
AC_DEFINE([EYEDBSM_VERSION_MAJOR], [PRODUCT_VERSION_MAJOR], [Eyedbsm major version - integer])
AC_DEFINE([EYEDBSM_VERSION_MINOR], [PRODUCT_VERSION_MINOR], [Eyedbsm minor version - integer])
AC_DEFINE([EYEDBSM_VERSION_PATCH], [PRODUCT_VERSION_PATCH], [Eyedbsm patch level])
AC_DEFINE([EYEDBSM_VERSION], [PRODUCT_VERSION], [Eyedbsm version])

AC_CONFIG_AUX_DIR([.])
AM_CONFIG_HEADER(eyedbsmconfig.h)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([include/eyedbsm/eyedbsm.h])

AM_INIT_AUTOMAKE(foreign)

# FD TO CHECK
# which one to use???

#
# Checks for command line flags
#

# if CXXFLAGS are not already set, set them to an empty value
if test x"$CXXFLAGS" = "x"
then
	CXXFLAGS=''
fi

#
# Collect arguments
#
# debug
AC_ARG_ENABLE(debug,
		AS_HELP_STRING([--enable-debug],
				[compile with debug [default=no]]),,
		enable_debug="no")
# optimize
AC_ARG_ENABLE(optimize,
		AS_HELP_STRING([--enable-optimize=flag],
				[compile with given optimization flag [default=no]]),,
		enable_optimize="")
# profile
AC_ARG_ENABLE(profile,
		AS_HELP_STRING([--enable-profile],
				[compile with profile [default=no]]),,
		enable_profile="no")
# FD TO CHECK
# Semaphore policy
AC_ARG_WITH( semaphore-policy, 
	     AS_HELP_STRING([--with-semaphore-policy=(posix|sysv_ipc)],[force semaphore implementation (if none given, is found by configure.in)]),
	     ac_semaphore_policy="$withval",
	     ac_semaphore_policy="guess")
# FD TO CHECK
# Installation directory: data bases directory
AC_ARG_WITH( databasedir, 
	     AS_HELP_STRING([--with-databasedir=DIRECTORY],[give databases directory (default is LOCALSTATEDIR/lib/eyedb/db)]),
	     ac_eyedb_databasedir="$withval",
	     ac_eyedb_databasedir='${localstatedir}/lib/eyedb/db')
# FD TO CHECK
# Installation directory: pipes directory
AC_ARG_WITH( pipedir, 
	     AS_HELP_STRING([--with-pipedir=DIRECTORY],[give pipes directory (default is LOCALSTATEDIR/lib/eyedb/pipes)]),
	     ac_eyedb_pipedir="$withval",
	     ac_eyedb_pipedir='${localstatedir}/lib/eyedb/pipes')
# FD TO CHECK
# Installation directory: temporary directory
AC_ARG_WITH( tmpdir, 
	     AS_HELP_STRING([--with-tmpdir=DIRECTORY],[give temporary directory (default is LOCALSTATEDIR/lib/eyedb/tmp)]),
	     ac_eyedb_tmpdir="$withval",
	     ac_eyedb_tmpdir='${localstatedir}/lib/eyedb/tmp')
# FD TO CHECK
# User under which EyeDB server should run
AC_ARG_WITH(eyedbd-user,
	AS_HELP_STRING([--with-eyedbd-user=USERNAME],[give user the EyeDB server shall be run as (default is eyedb)]),
	EYEDBD_USER="$withval",
	EYEDBD_USER=eyedb)
AC_SUBST(EYEDBD_USER)
# FD TO CHECK
# readline
AC_ARG_WITH(readline, 
	     AS_HELP_STRING([--with-readline=(readline|editline)],[use GNU readline or BSD editline for line editing (default is readline if available)]),
	     ac_eyedb_readline="$withval",
	     ac_eyedb_readline='none')
#
# End of arguments collect


# by default we install in /usr/local/eyedb
AC_PREFIX_DEFAULT(/usr/local/eyedb)

# check for GNU make
CHECK_GNU_MAKE
if test x"$_cv_gnu_make_command" = x ; then
    AC_MSG_ERROR(you must use GNU make to compile EyeDB)
fi

# check for compilers
AC_PROG_CXX

AC_LANG(C++)

# debug, optimize, profile flags
if test "$enable_debug" = "yes"; then
  CXXFLAGS="$CXXFLAGS -g"
fi
if test "x$enable_optimize" != "x"; then
  CXXFLAGS="$CXXFLAGS $enable_optimize"
fi
if test "$enable_profile" = "yes"; then
   if test x"$ac_cv_cxx_compiler_gnu" = x"yes"; then
      CXXFLAGS="$CXXFLAGS -pg"
      LDFLAGS="$LDFLAGS -pg"
   fi
fi

# check for architecture
AC_CANONICAL_HOST
AC_SUBST(host)
AC_SUBST(host_cpu)
AC_SUBST(host_os)

# special settings on Solaris 64 bits
case "$host" in
sparc-sun-solaris2.9)
	if test "$ac_cv_cxx_compiler_gnu" != "yes"
	then
		CFLAGS="-xtarget=ultra -xarch=v9"
		CXXFLAGS="$CXXFLAGS -xtarget=ultra -xarch=v9"
		LDFLAGS="-XCClinker -xtarget=ultra -XCClinker -xarch=v9"
	fi
	;;
esac
# special settings on Mac OS X
case "$host" in
powerpc-apple-darwin*)
	LDFLAGS="-Wl,-m -Wl,-multiply_defined -Wl,suppress"
	;;
esac

# check for endianism
AC_C_BIGENDIAN
if test $ac_cv_c_bigendian = yes; then
EYEDBSM_CONFIG_BYTE_ORDER=EYEDBLIB_BIG_ENDIAN
else
EYEDBSM_CONFIG_BYTE_ORDER=EYEDBLIB_LITTLE_ENDIAN
fi
AC_SUBST(EYEDBSM_CONFIG_BYTE_ORDER)

# check for unsigned long long type
AC_CHECK_TYPES( unsigned long long)
if test x"$ac_cv_type_unsigned_long_long" != xyes ; then
   AC_MSG_ERROR( "this platform does not support type unsigned long long")
fi

# check for type sizes
AC_CHECK_SIZEOF(void *)
AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned long)
AC_CHECK_SIZEOF(unsigned long long)
if test "$ac_cv_sizeof_unsigned_long_long" -lt 8 ; then
   AC_MSG_ERROR( "this platform has an unsigned long long type with sizeof(unsigned long long) < 8")
fi

AC_MSG_CHECKING(for integer type of same size as void *)
case $ac_cv_sizeof_void_p in
$ac_cv_sizeof_unsigned_int)
		ac_pointer_int_type='unsigned int'
	;;
$ac_cv_sizeof_unsigned_long)
		ac_pointer_int_type='unsigned long'
	;;
$ac_cv_sizeof_unsigned_long_long)
		ac_pointer_int_type='unsigned long long'
	;;
*)
		AC_MSG_ERROR('cannot find an integer type of same size as void *')
	;;
esac
AC_MSG_RESULT($ac_pointer_int_type)
AC_DEFINE_UNQUOTED([POINTER_INT_TYPE], $ac_pointer_int_type, [Define to the integer type of same size as void *])

# check for libtool
AC_PROG_LIBTOOL

# FD TO CHECK
# check for libraries
# this library is necessary on Solaris
AC_CHECK_LIB( nsl, gethostbyname)
AC_CHECK_LIB( dl, dlopen)
AC_CHECK_LIB( crypt, crypt)
AC_SEARCH_LIBS( socket, socket)

# check for pthread
ACX_PTHREAD
LIBS="$LIBS $PTHREAD_LIBS"
CXXFLAGS="$CXXFLAGS $PTHREAD_CFLAGS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
AC_CHECK_FUNC(pthread_mutexattr_setpshared,AC_DEFINE([HAVE_PTHREAD_MUTEXATTR_SETPSHARED],1,[Defined if function pthread_mutexattr_setpshared exists]),,[#include <pthread.h>])

# echo CFLAGS=$CFLAGS
# echo CXXFLAGS=$CXXFLAGS

# FD TO CHECK
# check for headers
AC_CHECK_HEADERS( time.h sys/time.h unistd.h sys/types.h regex.h libgen.h sys/stat.h pwd.h stropts.h crypt.h)
AC_HEADER_TIME

# FD TO CHECK
# check for flock structure
AC_CHECK_TYPES(flock_t,,,[#include <fcntl.h>])

# FD TO CHECK
# check for union semun
AC_CHECK_MEMBERS(union semun.val,,,[#include <sys/sem.h>])

# FD TO CHECK
# check for struct in_addr
AC_CHECK_MEMBERS(struct in_addr.s_addr,,,[#include <netinet/in.h>])
AC_CHECK_MEMBERS(struct in_addr._S_un,,,[#include <netinet/in.h>])

# FD TO CHECK
# check for functions
AC_CHECK_FUNCS(strsignal)
AC_CHECK_FUNCS(fattach)
# check if function ctime_r exists and has 2 or 3 arguments
AC_CHECK_FUNCS(ctime_r)
AC_FUNC_CTIME_R_3_ARGS
# check for regular expressions functions
AC_CHECK_FUNC(regcomp,AC_DEFINE([HAVE_REGCOMP],1,[Defined if function regcomp exists]),,[#include <regex.h>])
AC_CHECK_FUNC(regexec,AC_DEFINE([HAVE_REGEXEC],1,[Defined if function regexec exists]),,[#include <regex.h>])
AC_CHECK_FUNC(regcmp,AC_DEFINE([HAVE_REGCMP],1,[Defined if function regcmp exists]),,[#include <libgen.h>])
AC_CHECK_FUNC(regex,AC_DEFINE([HAVE_REGEX],1,[Defined if function regex exists]),,[#include <libgen.h>])

# FD TO CHECK
# check for tzset and long timezone
AC_CHECK_FUNC(tzset,AC_DEFINE([HAVE_TZSET],1,[Defined if function tzset exists]),,[#include <time.h>])
AC_VAR_LONG_TIMEZONE

# check for large file
AC_SYS_LARGEFILE
AC_FUNC_FSEEKO

# determine the semaphore implementation for this platform
AC_PTHREAD_PROCESS_SHARED

AC_MSG_CHECKING(for semaphore policy)
case "$ac_semaphore_policy" in
posix)
	if test "$ac_pthread_process_shared" = "no"; then
	   AC_MSG_ERROR( this platform does not support PTHREAD_PROCESS_SHARED and cannot use Posix semaphore policy)
	fi
	AC_MSG_RESULT(Posix)
	AC_DEFINE(HAVE_SEMAPHORE_POLICY_POSIX, 1, [Define if semaphore policy is Posix (must support PTHREAD_PROCESS_SHARED)])
	;;
sysv_ipc)
	AC_MSG_RESULT(Sys V IPC)
	AC_DEFINE(HAVE_SEMAPHORE_POLICY_SYSV_IPC, 1, [Define if semaphore policy is Sys V IPC])
	;;
guess)
	if test "$ac_pthread_process_shared" = "yes"; then
	   AC_MSG_RESULT(Posix)
	   ac_semaphore_policy="posix"
	   AC_DEFINE(HAVE_SEMAPHORE_POLICY_POSIX, 1, [Define if semaphore policy is Posix (must support PTHREAD_PROCESS_SHARED)])
	else
	   ac_semaphore_policy="sysv_ipc"
	   AC_MSG_RESULT(Sys V IPC)
	   AC_DEFINE(HAVE_SEMAPHORE_POLICY_SYSV_IPC, 1, [Define if semaphore policy is Sys V IPC])
	fi
	;;
*)
	AC_MSG_ERROR( "semaphore policy must be one of posix or sysv_ipc")
	;;
esac

# FD TO CHECK
# determine if we must use eyedbsmd, depending on the semaphore policy
if test "$ac_semaphore_policy" = "sysv_ipc" ; then
   AC_DEFINE(HAVE_EYEDBSMD, 1, [Define to 1 if we must use eyedbsmd])
fi
AM_CONDITIONAL(COND_EYEDBSMD, test "$ac_semaphore_policy" = "sysv_ipc")

# installation directories
eyedb_databasedir="$ac_eyedb_databasedir"
AC_SUBST(eyedb_databasedir)
eyedb_pipedir="$ac_eyedb_pipedir"
AC_SUBST(eyedb_pipedir)
eyedb_tmpdir="$ac_eyedb_tmpdir"
AC_SUBST(eyedb_tmpdir)

# must disappear
case "$host" in
sparc-sun-solaris2.9)
	ARCH_DEFINES="-DSOLARIS -DSPARCV9"
esac

# -D are taken verbatim for now. Later, may use autodetection and/or command line flags
DEFINES=""
CXXFLAGS="$CXXFLAGS $DEFINES $ARCH_DEFINES"

# FD TO CHECK (tests?)
# ========================================
# Python/pexpect tests
# ========================================
#AM_PATH_PYTHON(,ac_python_found="yes",ac_python_found="no")
#if test "$ac_python_found" = "yes" ; then
#   AC_PYTHON_MODULE(pexpect,ac_python_pexpect="yes",ac_python_pexpect="no")
#fi
#if test "$ac_python_found" = "yes" -a "$ac_python_pexpect" = "yes" ; then
#   COND_PYTHON_PEXPECT="yes"
#fi
#AM_CONDITIONAL(COND_PYTHON_PEXPECT, test x"$COND_PYTHON_PEXPECT" = xyes)

# ========================================
# API Documentation building
# ========================================
# Doxygen for C++ API documentation
AC_PATH_PROG(DOXYGEN, doxygen)
if test x"$DOXYGEN" != x ; then
   AC_MSG_CHECKING(for doxygen version)
   DOXYGEN_VERSION=`$DOXYGEN --version`
   AC_MSG_RESULT($DOXYGEN_VERSION)
   DOXYGEN_MAJOR_VERSION=[`echo "$DOXYGEN_VERSION" | sed -e 's/.[1-9]*.[1-9]*$//'`]
   DOXYGEN_MINOR_VERSION=[`echo "$DOXYGEN_VERSION" | sed -e 's/^[1-9]*.//' -e 's/.[1-9]*$//'`]
   DOXYGEN_REQUIRED_MAJOR_VERSION=1
   DOXYGEN_REQUIRED_MINOR_VERSION=4
   if test "$DOXYGEN_MAJOR_VERSION" -le "$DOXYGEN_REQUIRED_MAJOR_VERSION" -a "$DOXYGEN_MINOR_VERSION" -lt "$DOXYGEN_REQUIRED_MINOR_VERSION" ; then
      AC_MSG_WARN(doxygen version should be at least $DOXYGEN_REQUIRED_MAJOR_VERSION.$DOXYGEN_REQUIRED_MINOR_VERSION.x)
   else
      COND_DOXYGEN="yes"
   fi
fi
AM_CONDITIONAL(COND_DOXYGEN, test x"$COND_DOXYGEN" = xyes)

# Docbook manpages
# Look for XSL stylesheet
AC_MSG_CHECKING(for Docbook manpages XSL stylesheet)
MANPAGES_XSL_STYLESHEET_LOCATIONS="/usr/share/sgml/docbook/xsl-stylesheets/manpages /usr/share/xml/docbook/stylesheet/nwalsh/manpages"
for d in $MANPAGES_XSL_STYLESHEET_LOCATIONS ; do
    if test -f $d/docbook.xsl ; then
       MANPAGES_XSL_STYLESHEET_DIR=$d
       break
    fi
done
AC_MSG_RESULT($MANPAGES_XSL_STYLESHEET_DIR/docbook.xsl)
AC_SUBST(MANPAGES_XSL_STYLESHEET_DIR)

if test x"$XSLTPROC" != x -a x"$MANPAGES_XSL_STYLESHEET_DIR" != x ; then
COND_DOCBOOK_MANPAGES="yes"
fi
AM_CONDITIONAL(COND_DOCBOOK_MANPAGES, test x"$COND_DOCBOOK_MANPAGES" = xyes)

EYEDB_ARCH_LIBS=$LIBS
AC_CHECK_LIB( pthread, pthread_join, EYEDB_ARCH_LIBS="-lpthread $EYEDB_ARCH_LIBS")

AC_SUBST(EYEDB_ARCH_LIBS)

# ========================================
# End of Examples building
# ========================================



AC_CONFIG_FILES( dnl
Makefile dnl
include/Makefile dnl
include/eyedblib/Makefile dnl
include/eyedblib/endian.h dnl
include/eyedbsm/Makefile dnl
pkg-config/Makefile dnl
src/Makefile dnl
src/eyedbsm/Makefile dnl
src/lib/Makefile dnl
tests/Makefile dnl
tests/eyedbsm/Makefile dnl
tests/eyedbsm/basic/Makefile dnl
)
AC_OUTPUT


echo
echo
echo "  EyeDBSM ${PACKAGE_VERSION} configured for '${host}'."
echo
echo "  EyeDBSM will be compiled with the following options:"
echo 
echo "  *** EyeDBSM Core ***" 
echo "  EyeDBSM will be installed in: ${prefix:-none}"
# FD TO CHECK
V=${eyedb_databasedir}; while echo $V | grep '\$' > /dev/null 2>&1; do V=$(eval echo $V) ; done
echo "  EyeDB databases will be in: $V"
# FD TO CHECK
V=${eyedb_pipedir}; while echo $V | grep '\$' > /dev/null 2>&1; do V=$(eval echo $V) ; done
echo "  EyeDB pipes will be in: $V"
# FD TO CHECK
V=${eyedb_tmpdir}; while echo $V | grep '\$' > /dev/null 2>&1; do V=$(eval echo $V) ; done
echo "  EyeDB temporary files will be in: $V"

echo "  C++ compiler: ${CXX:-none}"
echo "  C++ compiler flags: ${CXXFLAGS:-none}"
echo "  Compile with debug: ${enable_debug:-no}"
echo "  Compile with profile: ${enable_profile:-no}"
echo "  Compile with optimization: ${enable_optimize:-no}"
echo "  Semaphore policy: ${ac_semaphore_policy}"
echo "  Libraries: ${LIBS}"
echo 

#FD TO CHECK
echo "  *** EyeDBSM Python pexpect tests ***" 
echo "  Run Python pexpect tests: ${COND_PYTHON_PEXPECT:-no}"
echo 
echo "  *** EyeDBSM documentation ***" 
echo "  Generate doxygen C++ api documentation: ${COND_DOXYGEN:-no}"
echo "  Generate Docbook man pages: ${COND_DOCBOOK_MANPAGES:-no}"
echo

