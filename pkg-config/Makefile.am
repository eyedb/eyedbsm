pkgconfigdir=$(libdir)/pkgconfig
pkgconfig_DATA= eyedbsm.pc

EDIT = sed \
        -e 's,@bindir\@,$(bindir),g' \
        -e 's,@sbindir\@,$(sbindir),g' \
        -e 's,@includedir\@,$(includedir),g' \
        -e 's,@libdir\@,$(libdir),g' \
        -e 's,@EYEDBSM_ARCH_LIBS\@,$(EYEDBSM_ARCH_LIBS),g' \
        -e 's,@EYEDBSM_VERSION\@,$(EYEDBSM_VERSION),g' 

%.pc: Makefile $(srcdir)/%.pc.in
	rm -f $*.pc $*.pc.tmp
	$(EDIT) $(srcdir)/$*.pc.in >$*.pc.tmp
	mv $*.pc.tmp $*.pc

EXTRA_DIST=eyedbsm.pc.in

