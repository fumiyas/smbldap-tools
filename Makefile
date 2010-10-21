PACKAGE=smbldap-tools
VERSION=0.9.5
RELEASE=1
DESTARCH=smbldap-tools-$(VERSION)
#RELEASE=$(shell date +%s)

# where to build the rpm
TOPDIR=/home/$(USER)/redhat
GPG_PATH=/home/$(USER)/.gnupg
#BUILD_CMD=rpmbuild -ba
BUILD_CMD=rpmbuild -ba --sign

prefix=/usr
sbindir=$(prefix)/sbin
sysconfdir=/etc/
make=/usr/bin/make
install=/usr/bin/install
rm=/bin/rm
sed=/bin/sed

prep:
	$(sed) -e 's|@SBINDIR@|$(sbindir)|g' smb.conf.in > smb.conf

all:	prep distclean rpm

install:
	@mkdir -p $(sbindir)
	@mkdir -p $(sysconfdir)/smbldap-tools/
	$(install) -m0755 smbldap-* smbldap_tools.pm $(sbindir)
	$(install) -m0644 smbldap.conf $(sysconfdir)/smbldap-tools/
	$(install) -m0600 smbldap_bind.conf $(sysconfdir)/smbldap-tools/

clean:
	$(rm) -f *~

distclean:
	$(rm) -f *~

dist: .diststamp
	@if [ -d $(DESTARCH) ];then echo "About to remove ./$(DESTARCH)/ in 5 seconds ..."; sleep 5; fi
	@rm -rf ./$(DESTARCH)/
	@mkdir -p $(DESTARCH)/doc
	@cp smbldap-tools.spec $(DESTARCH)
	@perl -i -pe's@^\%define version(.*)@\%define version $(VERSION)@' $(DESTARCH)/smbldap-tools.spec
	@perl -i -pe's@^\%define release(.*)@\%define release $(RELEASE)@' $(DESTARCH)/smbldap-tools.spec
	@cp Makefile $(DESTARCH)
	@cp CONTRIBUTORS $(DESTARCH)
	@cp COPYING $(DESTARCH)
	@cp ChangeLog $(DESTARCH)
	@cp FILES $(DESTARCH)
	@cp INSTALL $(DESTARCH)
	@cp README $(DESTARCH)
	@cp TODO $(DESTARCH)
	@cp INFRA $(DESTARCH)
	@cp smbldap-populate $(DESTARCH)
	@cp smbldap-groupadd $(DESTARCH)
	@cp smbldap-groupshow $(DESTARCH)
	@cp smbldap-groupmod $(DESTARCH)
	@cp smbldap-groupdel $(DESTARCH)
	@cp smbldap-useradd $(DESTARCH)
	@cp smbldap-usershow $(DESTARCH)
	@cp smbldap-usermod $(DESTARCH)
	@cp smbldap-userinfo $(DESTARCH)
	@cp smbldap-userlist $(DESTARCH)
	@cp smbldap-userdel $(DESTARCH)
	@cp smbldap-passwd $(DESTARCH)
	@cp smbldap_bind.conf $(DESTARCH)
	@cp smbldap_tools.pm $(DESTARCH)
	@cp smbldap.conf $(DESTARCH)
	@cp configure.pl $(DESTARCH)
	@cp -r migration_scripts $(DESTARCH)/doc/
	@cp doc/smbldap-tools/*.pdf doc/smbldap-tools/*.html $(DESTARCH)/doc/
	@cp slapd.conf $(DESTARCH)/doc/
	@cp smb.conf $(DESTARCH)/doc/
	@rm -rf $(DESTARCH)/doc/{html,migration_scripts}/.svn
	@echo "Creating tarball $(DESTARCH).tgz ...";
	@tar czf $(DESTARCH).tgz $(DESTARCH)
	@rm -r $(DESTARCH)
	@touch .diststamp

build_dir:
	@echo '%_topdir $(TOPDIR)' > $(HOME)/.rpmmacros
	@echo '%_signature gpg' >> $(HOME)/.rpmmacros
	@echo '%_gpg_name Jerome Tournier <jtournier@gmail.com>' >> $(HOME)/.rpmmacros
	@echo '%_gpg_path $(GPG_PATH)' >> $(HOME)/.rpmmacros
	@mkdir -p $(TOPDIR)/BUILD
	@mkdir -p $(TOPDIR)/RPMS/i386
	@mkdir -p $(TOPDIR)/SOURCES
	@mkdir -p $(TOPDIR)/SPECS
	@mkdir -p $(TOPDIR)/SRPMS

rpm: dist build_dir
	@cp -f $(DESTARCH).tgz $(TOPDIR)/SOURCES/
	@cp -f smbldap-tools.spec $(TOPDIR)/SPECS/
	@perl -i -pe's@^\%define version(.*)@\%define version $(VERSION)@' $(TOPDIR)/SPECS/smbldap-tools.spec
	@perl -i -pe's@^\%define release(.*)@\%define release $(RELEASE)@' $(TOPDIR)/SPECS/smbldap-tools.spec
	@perl -i -pe's@^Source0(.*)@Source0: smbldap-tools-$(VERSION).tgz@' $(TOPDIR)/SPECS/smbldap-tools.spec
	@cd $(TOPDIR)/SPECS/ && $(BUILD_CMD) smbldap-tools.spec
	@echo "Signing packages smbldap-tools-$(VERSION)-$(RELEASE).noarch.rpm"
	@cd $(TOPDIR)/RPMS/noarch &&  gpg --detach smbldap-tools-$(VERSION)-$(RELEASE).noarch.rpm
	@echo "Signing packages smbldap-tools-$(VERSION)-$(RELEASE).src.rpm"
	@cd $(TOPDIR)/SRPMS/ && gpg --detach smbldap-tools-$(VERSION)-$(RELEASE).src.rpm
	@echo "Signing packages smbldap-tools-$(VERSION).tgz"
	@cd $(TOPDIR)/SOURCES/ && gpg --detach smbldap-tools-$(VERSION).tgz
	@echo "Arch: $(DESTARCH).tgz"


home_devel: rpm
	@mkdir -p iallanis/{docs/{smbldap-tools,samba-ldap-howto},old,development_release}
	@cp -f iallanis/development_release/ChangeLog "/tmp/ChangeLog-homedevel-`date`"
	@cp -f ChangeLog iallanis/development_release/
	@cp $(TOPDIR)/SOURCES/smbldap-tools-$(VERSION){.tgz,.tgz.sig} iallanis/development_release/
	@cp $(TOPDIR)/RPMS/noarch/smbldap-tools-$(VERSION)-$(RELEASE).noarch{.rpm,.rpm.sig} iallanis/development_release/
	@cp $(TOPDIR)/SRPMS/smbldap-tools-$(VERSION)-$(RELEASE).src{.rpm,.rpm.sig} iallanis/development_release/
	@rsync -avz --delete --delete-excluded --exclude .svn -e "ssh -p 443" iallanis/ 192.168.10.1:/home/www/html/smbldap-tools

home: rpm
	@cp -f iallanis/ChangeLog "/tmp/ChangeLog-home-`date`"
	@cp -f ChangeLog iallanis/
	@cp doc/smbldap-tools/smbldap-tools.html iallanis/docs/smbldap-tools/index.html
	@cp doc/samba-ldap-howto/smbldap-howto.html iallanis/docs/samba-ldap-howto/index.html
	@cp $(TOPDIR)/SOURCES/smbldap-tools-$(VERSION){.tgz,.tgz.sig} iallanis/
	@cp $(TOPDIR)/RPMS/noarch/smbldap-tools-$(VERSION)-$(RELEASE).noarch{.rpm,.rpm.sig} iallanis/
	@cp $(TOPDIR)/SRPMS/smbldap-tools-$(VERSION)-$(RELEASE).src{.rpm,.rpm.sig} iallanis/
	rsync -avz --delete --delete-excluded --exclude .svn -e "ssh -p 443" iallanis/ 192.168.10.1:/home/www/html/smbldap-tools

gna:
	@cp -f ChangeLog GNA/packages/
	@cp $(TOPDIR)/SOURCES/smbldap-tools-$(VERSION){.tgz,.tgz.sig} GNA/packages/
	@cp $(TOPDIR)/RPMS/noarch/smbldap-tools-$(VERSION)-$(RELEASE).noarch{.rpm,.rpm.sig} GNA/packages/
	@cp $(TOPDIR)/SRPMS/smbldap-tools-$(VERSION)-$(RELEASE).src{.rpm,.rpm.sig} GNA/packages/
	rsync -avz -e ssh --delete --delete-excluded --exclude .svn GNA/ download.gna.org:/upload/smbldap-tools/
