include /usr/share/dpkg/pkg-info.mk

PACKAGE=pmg-api

BUILDDIR ?= $(PACKAGE)-$(DEB_VERSION)

DSC=$(PACKAGE)_$(DEB_VERSION).dsc
DEB=$(PACKAGE)_$(DEB_VERSION_UPSTREAM_REVISION)_all.deb

$(BUILDDIR): src debian
	rm -rf $@ $@.tmp
	cp -a src $@.tmp
	cp -a debian $@.tmp/
	echo "REPOID_GENERATED=$(shell git rev-parse --short=12 HEAD)" > $@.tmp/debian/rules.env
	mv $@.tmp $@

.PHONY: deb
deb: $(DEB)
$(DEB): $(BUILDDIR)
	cd $(BUILDDIR); dpkg-buildpackage -b -us -uc
	lintian $(DEB)

dsc:
	rm -rf $(BUILDDIR) $(DSC)
	$(MAKE) $(DSC)
	lintian $(DSC)
$(DSC): $(BUILDDIR)
	cd $(BUILDDIR); dpkg-buildpackage -S -us -uc -d

sbuild: $(DSC)
	sbuild $<

.PHONY: upload
upload: UPLOAD_DIST ?= $(DEB_DISTRIBUTION)
upload: $(DEB)
	tar cf - $(DEB) | ssh -X repoman@repo.proxmox.com -- upload --product pmg --dist $(UPLOAD_DIST)

.PHONY: check
check:
	$(MAKE) -C src/tests check

.PHONY: clean distclean
distclean: clean
clean:
	rm -rf $(PACKAGE)-[0-9]*/
	rm -rf *.deb *.changes *.build *.buildinfo $(PACKAGE)*tar* *.dsc

.PHONY: dinstall
dinstall: $(DEB)
	dpkg -i $(DEB)
