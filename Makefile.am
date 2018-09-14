AUTOMAKE_OPTIONS=dist-bzip2
ACLOCAL_AMFLAGS=-I m4

SUBDIRS=src include pkg-config

EXTRA_DIST= AUTHORS COPYING.LESSER VERSION autogen.sh

TAGS:
	find $(top_srcdir) \! -name '*~' \( -name '*.c' -o -name '*.h' -o -name '*.cc' -o -name '*.l' -o -name '*.y' -o -name '*.java' -o -name 'Makefile.am' -o \( -name '*.in' -a \! -name Makefile.in \) \) -print | etags -
.PHONY: TAGS
