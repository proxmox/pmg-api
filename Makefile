include /usr/share/dpkg/pkg-info.mk

PACKAGE=pmg-api

BUILDDIR ?= $(PACKAGE)-$(DEB_VERSION)

DEB=$(PACKAGE)_$(DEB_VERSION_UPSTREAM_REVISION)_all.deb

REPOID = $(shell git rev-parse --short=8 HEAD)

export PACKAGE
export REPOID
export PMGVERSION = $(DEB_VERSION_UPSTREAM_REVISION)
export PMGRELEASE = $(DEB_VERSION_UPSTREAM)

$(BUILDDIR): src debian
	rm -rf $@ $@.tmp
	cp -a src $@.tmp
	cp -a debian $@.tmp/
	mv $@.tmp $@

.PHONY: deb
deb: $(DEB)
$(DEB): $(BUILDDIR)
	cd $(BUILDDIR); dpkg-buildpackage -b -us -uc
	lintian $(DEB)

.PHONY: upload
upload: $(DEB)
	tar cf - $(DEB) | ssh -X repoman@repo.proxmox.com -- upload --product pmg --dist bullseye

.PHONY: check
check:
	make -C src/tests check

.PHONY: clean distclean
distclean: clean
clean:
	rm -rf *.deb *.changes *.buildinfo $(BUILDDIR) $(PACKAGE)*.tar.gz *.dsc

.PHONY: dinstall
dinstall: $(DEB)
	dpkg -i $(DEB)
