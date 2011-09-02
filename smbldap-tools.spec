%define version 0.9.6.svn
%define release 3
%define name	smbldap-tools

Summary:	User and Group administration tools for Samba/LDAP
Name: 		%{name}
version: 	%{version}
Release: 	%{release}
Group: 		System Environment/Base
License: 	GPLv2+
URL:		https://gna.org/projects/smbldap-tools/
Packager:	Jerome Tournier <jtournier@gmail.com>
Source0: 	smbldap-tools-%{version}.tgz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:	perl
BuildArch:	noarch
Requires:	perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
Requires:	perl >= 5.8.1

%description
smbldap-tools is a set of perl scripts designed to manage user and group
accounts stored in an LDAP directory. They can be used both by users and
administrators of Linux systems:

  * administrators can perform users and groups management operations,
    in a way similar to the standard useradd or groupmod commands
  * users can change their LDAP password from the command line and
    get/change personnal informations

This was first contributed by IDEALX (http://www.opentrust.com/)

%prep
%setup -q

%build
%configure

make

for f in smbldap-config smbldap-upgrade-0.9.6; do
    cp -p $f.cmd doc/$f.pl
    chmod -x doc/$f.pl
done

%install
%{__rm} -rf %{buildroot}

make install DESTDIR=%{buildroot}

mkdir -p -m 0755 %{buildroot}%{_sysconfdir}/smbldap-tools
cp -a smbldap.conf smbldap_bind.conf %{buildroot}%{_sysconfdir}/smbldap-tools/

mkdir -p -m 0755 %{buildroot}%{_mandir}/man8/
cp -p *.8 %{buildroot}%{_mandir}/man8/

%clean
%{__rm} -rf %{buildroot}

%triggerpostun -- %{name} < 0.9.6.svn
if [ "$1" -eq "2" ]; then ## Upgrade
    %{__perl} %{_docdir}/%{name}-%{version}/smbldap-upgrade-0.9.6.pl
fi

%files
%defattr(-,root,root,-)
%doc ChangeLog CONTRIBUTORS COPYING FILES INFRA INSTALL README TODO
%doc configure.pl *.conf doc/*.conf doc/migration_scripts/ doc/*.pdf doc/*.pl
%dir %{_sysconfdir}/smbldap-tools/
%config(noreplace) %{_sysconfdir}/smbldap-tools/smbldap.conf
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/smbldap-tools/smbldap_bind.conf
%{_sbindir}/smbldap-groupadd
%{_sbindir}/smbldap-groupdel
%{_sbindir}/smbldap-grouplist
%{_sbindir}/smbldap-groupmod
%{_sbindir}/smbldap-groupshow
%{_sbindir}/smbldap-passwd
%{_sbindir}/smbldap-populate
%{_sbindir}/smbldap-useradd
%{_sbindir}/smbldap-userdel
%{_sbindir}/smbldap-userlist
%{_sbindir}/smbldap-usermod
%{_sbindir}/smbldap-userinfo
%{_sbindir}/smbldap-usershow
%{perl_vendorlib}/smbldap_tools.pm
%{_mandir}/man8/smbldap-groupadd.8*
%{_mandir}/man8/smbldap-groupdel.8*
%{_mandir}/man8/smbldap-grouplist.8*
%{_mandir}/man8/smbldap-groupmod.8*
%{_mandir}/man8/smbldap-groupshow.8*
%{_mandir}/man8/smbldap-passwd.8*
%{_mandir}/man8/smbldap-populate.8*
%{_mandir}/man8/smbldap-useradd.8*
%{_mandir}/man8/smbldap-userdel.8*
%{_mandir}/man8/smbldap-userinfo.8*
%{_mandir}/man8/smbldap-userlist.8*
%{_mandir}/man8/smbldap-usermod.8*
%{_mandir}/man8/smbldap-usershow.8*

%changelog
* Thu Jul  7 2011 SATOH Fumiyasu <fumiyas at OSS Technology, Inc.> - 0.9.6.svn-3
- Run smbldap-upgrade-0.9.6.pl in %%triggerun %%{name} < 0.9.6.svn

* Wed Jun 22 2011 SATOH Fumiyasu <fumiyas at OSS Technology, Inc.> - 0.9.6.svn-2
- New upstream version

* Fri Aug 10 2007 Jerome Tournier <jtournier@gmail.com> 0.9.4-1
- see Changelog file for updates in scripts

