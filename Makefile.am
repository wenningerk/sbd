SUBDIRS = src agent man tests

# .gz because github doesn't support .xz yet :-(
# this is modified
#
TAG		?= $(shell git log --pretty="format:%H" -n 1 || sed -n -e "s/%global commit //p" sbd.spec)$(shell test -n "$$(git status -s)" && echo -n "-mod")
distdir		 = $(PACKAGE)-$(TAG)
TARFILE		 = $(distdir).tar.gz
DIST_ARCHIVES	 = $(TARFILE)
KEEP_EXISTING_TAR = no
INJECT_GIT_COMMIT = yes
DISTCLEANFILES   = sbd-* sbd-*/
CLEANFILES       = *.rpm *.tar.* sbd-*

RPM_ROOT	= $(shell pwd)
RPM_OPTS	= --define "_sourcedir $(RPM_ROOT)" 	\
		  --define "_specdir   $(RPM_ROOT)" 	\
		  --define "_srcrpmdir $(RPM_ROOT)"     \
		  --define "_builddir  $(RPM_ROOT)"     \
		  --define "_rpmdir    $(RPM_ROOT)"

MOCK_TARGET     ?= rhel-7.1-candidate-x86_64
MOCK_OPTIONS	?= --resultdir=$(RPM_ROOT)/mock --no-cleanup-after

BUILD_COUNTER	?= build.counter
LAST_COUNT      = $(shell test ! -e $(BUILD_COUNTER) && echo 0; test -e $(BUILD_COUNTER) && cat $(BUILD_COUNTER))
COUNT           = $(shell expr 1 + $(LAST_COUNT))

TESTS           = tests/regressions.sh
export SBD_BINARY := src/sbd
export SBD_PRELOAD := tests/.libs/libsbdtestbed.so
export SBD_USE_DM := no

EXTRA_DIST      = sbd.spec tests/regressions.sh

export:
	rm -f $(PACKAGE)-HEAD.tar.*
	if test "$(KEEP_EXISTING_TAR)" != "yes"; then \
	    rm -f $(TARFILE); \
	fi;
	! (git status -s | grep "??" && echo "untracked files present in git-repo" )
	if [ -f $(TARFILE) ]; then						\
	    echo `date`: Using existing tarball: $(TARFILE);			\
	else									\
	    rm -f $(PACKAGE).tar.*;                                             \
	    (git archive --prefix=$(distdir)/ $(shell echo $(TAG)|cut -f1 -d-) || tar -c --transform="s,^,$(distdir)/," --exclude="*.tar.*" --exclude="$(distdir)" --exclude="*.o" --exclude="*.8" --exclude="config.*" --exclude="libtool" --exclusive="ltmain.sh*" --exclude="Makefile" --exclude="Makefile.in" --exclude="stamp-*" --exclude="*.service" --exclude="sbd" --exclude="*.m4" --exclude="*.cache" --exclude="configure" --exclude="*.list" --exclude="depcomp" --exclude="install-sh" --exclude="missing" --exclude="compile" --exclude="sbd.sh" --exclude="~" --exclude="*.swp" --exclude="*.patch" --exclude="*.diff" --exclude="*.orig" --exclude="*.rej" --exclude="*.rpm" --exclude=".deps" --exclude="test-driver" *) | gzip > $(TARFILE);	\
	    if test -n "$$(git status -s)" || test "$(INJECT_GIT_COMMIT)" = "yes"; then \
		if test -n "$$(git status -s)"; then git diff HEAD --name-only|grep -v "^\."|xargs -n1 git diff HEAD > uncommitted.diff; fi; \
		rm -rf $(distdir); tar -xzf $(TARFILE); rm $(TARFILE); \
		cd $(distdir); \
		if test -n "$$(git status -s)"; then patch -p1 -i ../uncommitted.diff; fi; \
		cd ..; \
		sed -i 's/global\ commit.*/global\ commit\ $(TAG)/' $(distdir)/$(PACKAGE).spec; \
		tar -czf $(TARFILE) $(distdir); rm -rf $(distdir); \
		rm -f uncommitted.diff; \
	    fi; \
	    echo `date`: Rebuilt $(TARFILE);					\
	fi

#replace commit id in sbd.spec
spec:
	rm -f *.src.rpm
	rm -rf $(distdir)
	mkdir $(distdir)
	cp $(PACKAGE).spec $(distdir)
	sed -i 's/global\ commit.*/global\ commit\ $(TAG)/' $(distdir)/$(PACKAGE).spec

srpm:	export spec
	if [ -e $(BUILD_COUNTER) ]; then							\
		sed -i 's/global\ buildnum.*/global\ buildnum\ $(COUNT)/' $(distdir)/$(PACKAGE).spec;	\
		echo $(COUNT) > $(BUILD_COUNTER);					\
	fi
	rpmbuild $(RPM_OPTS) -bs $(distdir)/$(PACKAGE).spec

rpm:	export spec
	rpmbuild $(RPM_OPTS) -ba $(distdir)/$(PACKAGE).spec

mock:   srpm
	-rm -rf $(RPM_ROOT)/mock
	@echo "mock --root=$* --rebuild $(MOCK_OPTIONS) $(RPM_ROOT)/*.src.rpm"
	mock --root=$(MOCK_TARGET) --rebuild $(MOCK_OPTIONS) $(RPM_ROOT)/*.src.rpm

beekhof: mock
	cluster-helper -- 'rm -f sbd-*.x86_64.rpm'
	cluster-helper --copy $(RPM_ROOT)/mock/sbd-*.x86_64.rpm {}: 
	cluster-helper -- yum install -y sbd-*.x86_64.rpm

