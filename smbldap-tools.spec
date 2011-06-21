# $Source: $
%define version 0.9.5
%define release 1
%define name	smbldap-tools
%define _prefix	/usr

Summary:	User & Group administration tools for Samba/LDAP
Name: 		%{name}
version: 	%{version}
Release: 	%{release}
Group: 		System Environment/Base
License: 	GPL
URL:		https://gna.org/projects/smbldap-tools/
Packager:	Jerome Tournier <jtournier@gmail.com>
Source0: 	smbldap-tools-%{version}.tgz
BuildRoot: 	/%{_tmppath}/%{name}
BuildRequires:	perl >= 5.6
Requires:	perl >= 5.6
Prefix:		%{_prefix}
BuildArch:	noarch

%description
Smbldap-tools is a set of perl scripts designed to manage user and group 
accounts stored in an LDAP directory. They can be used both by users and 
administrators of Linux systems: 
* administrators can perform users and groups management operations, in a 
  way similar to the standard useradd or groupmod commands
* users can change their LDAP password from the command line and get/change
  personnal informations

This was first contributed by IDEALX (http://www.opentrust.com/)

%prep
%setup -q

%build
sed -i "s,/etc/opt/IDEALX/smbldap-tools/,%{_sysconfdir}/smbldap-tools/,g" smbldap_tools.pm
sed -i "s,/etc/opt/IDEALX/smbldap-tools/,%{_sysconfdir}/smbldap-tools/,g" configure.pl
sed -i "s,/etc/opt/IDEALX/,%{_sysconfdir}/,g" smbldap.conf


%install
%{__rm} -rf %{buildroot}
mkdir -p $RPM_BUILD_ROOT/%_sysconfdir/smbldap-tools
mkdir -p $RPM_BUILD_ROOT/%_prefix/{bin,sbin}
mkdir -p $RPM_BUILD_ROOT/usr/share/man/man8/

for i in smbldap-[pgut]*
do
	install $i $RPM_BUILD_ROOT/%prefix/sbin/$i
done
cp -a smbldap.conf smbldap_bind.conf $RPM_BUILD_ROOT/%{_sysconfdir}/smbldap-tools/
cp -a smbldap_tools.pm $RPM_BUILD_ROOT/%{prefix}/sbin/
for i in smbldap-[gpu]*;
do
	pod2man --section=8 $i > $RPM_BUILD_ROOT/usr/share/man/man8/$i.8
done

%clean
if [ -n "$RPM_BUILD_ROOT" ] ; then
   [ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
fi

%pre
files=`ls %{_prefix}/sbin/smbldap*.pl 2>/dev/null`
if [ "$files" != "" ];
then
	echo "WARNING: new scripts do not have any .pl extension"
	echo "         You need to update the smb.conf file"
fi

%post
# from smbldap-tools-0.8-2, libraries are loaded with the FindBin perl package
if [ -f /usr/lib/perl5/site_perl/smbldap_tools.pm ];
then
	rm -f /usr/lib/perl5/site_perl/smbldap_tools.pm
fi

if [ ! -n `grep with_slappasswd %{_sysconfdir}/smbldap-tools/smbldap.conf | grep -v "^#"` ];
then
        echo "Check if you have the with_slappasswd parameter defined"
	echo "in smbldap.conf file (see the INSTALL file)"
fi

%files
%defattr(-,root,root)
%{prefix}/sbin/smbldap-groupadd
%{prefix}/sbin/smbldap-groupdel
%{prefix}/sbin/smbldap-grouplist
%{prefix}/sbin/smbldap-groupmod
%{prefix}/sbin/smbldap-groupshow
%{prefix}/sbin/smbldap-populate
%{prefix}/sbin/smbldap-passwd
%{prefix}/sbin/smbldap-useradd
%{prefix}/sbin/smbldap-userdel
%{prefix}/sbin/smbldap-usermod
%{prefix}/sbin/smbldap-userinfo
%{prefix}/sbin/smbldap-userlist
%{prefix}/sbin/smbldap-usershow
%{prefix}/sbin/smbldap_tools.pm
%doc CONTRIBUTORS COPYING ChangeLog FILES INFRA README INSTALL TODO
%doc doc/smb.conf doc/slapd.conf smbldap.conf smbldap_bind.conf
%doc doc/smbldap-*
%doc doc/*.html
%doc doc/*.pdf
%doc doc/migration_scripts
%doc /usr/share/man/man8/*
%doc configure.pl
%defattr(644,root,root)
%config(noreplace) %{_sysconfdir}/smbldap-tools/smbldap.conf
%defattr(600,root,root)
%config(noreplace) %{_sysconfdir}/smbldap-tools/smbldap_bind.conf
%exclude %{prefix}/sbin/smbldap-tools.spec

%changelog
* Fri Aug 10 2007 Jerome Tournier <jtournier@gmail.com> 0.9.4-1
- see Changelog file for updates in scripts

