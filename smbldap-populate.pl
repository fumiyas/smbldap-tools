#!@PERL_CMD@

# $Id$

#  This code was developped by Jerome Tournier (jtournier@gmail.com) and
#  contributors (their names can be found in the CONTRIBUTORS file).

#  This was first contributed by IDEALX (http://www.opentrust.com/)

#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

#  Purpose :
#       . Create an initial LDAP database suitable for Samba 3
#       . For lazy people, replace ldapadd (with only an ldif parameter)

use strict;
use warnings;
use FindBin qw($RealBin);
use smbldap_tools;
use Getopt::Std;
use Net::LDAP::LDIF;
use Net::LDAP::Entry;

my %oc_by_attr = (
      "ou" =>	"organizationalUnit",
      "o" =>	"organization",
      "dc" =>	"dcObject",
);

my %Options;

my $ok = getopts('a:b:e:g:i:k:l:m:r:R:u:?', \%Options);
if ( (!$ok) || ($Options{'?'}) ) {
    print_banner;
    print "Usage: $0 [-abegiklmru?] [ldif]\n";
    print "  -a user	administrator login name (default: root)\n";
    print "  -b user	guest login name (default: nobody)\n";
    print "  -e file	export ldif file\n";
    print "  -g gidNumber	first uidNumber to allocate (default: 1000)\n";
    print "  -i file	import ldif file\n";
    print "  -k uidNumber	administrator's uidNumber (default: 0)\n";
    print "  -l uidNumber	guest's uidNumber (default: 999)\n";
    print "  -m gidNumber	administrator's gidNumber (default: 0)\n";
    print "  -r ridNumber	first sambaNextRid to allocate (default: 1000)\n";
    print "  -R ridBase		sambaAlgorithmicRidBase (none)\n";
    print "  -u uidNumber	first uidNumber to allocate (default: 1000)\n";
    print "  -?		show this help message\n";

    exit (1);
}

# sanity checks
my $domain = $config{sambaDomain};
if (! defined $domain) {
    print STDERR "error: domain name not found !\n";
    print STDERR "possible reasons are:\n";
    print STDERR ". incorrect 'sambaDomain' parameter in smbldap.conf\n";
    print STDERR ". incorrect 'samba_conf' definition in smbldap_tools.pm\n";
    die;
}

my $firstuidNumber=$Options{'u'};
if (!defined($firstuidNumber)) {
    $firstuidNumber=1000;
}

my $firstgidNumber=$Options{'g'};
if (!defined($firstgidNumber)) {
    $firstgidNumber=1000;
}

my $firstridNumber=$Options{'r'};
if (!defined($firstridNumber)) {
    $firstridNumber=1000;
}

my $algorithmicRidBase = $Options{'R'};

my $adminName = $Options{'a'};
if (!defined($adminName)) {
    $adminName = "root";
}

my $guestName = $Options{'b'};
if (!defined($guestName)) {
    $guestName = "nobody";
}

my $adminUidNumber=$Options{'k'};
my $adminRid = 500;
if (!defined($adminUidNumber)) {
    $adminUidNumber = 0;
} else {
    if (defined($algorithmicRidBase)) {
	## For backward compatibility with smbldap-tools 0.9.6 and older
	$adminRid = 2 * $adminUidNumber + $algorithmicRidBase;
    }
}

my $guestUidNumber=$Options{'l'};
my $guestRid = 501;
if (!defined($guestUidNumber)) {
    $guestUidNumber = "999";
} else {
    if (defined($algorithmicRidBase)) {
	## For backward compatibility with smbldap-tools 0.9.6 and older
	$guestRid = 2 * $guestUidNumber + $algorithmicRidBase;
    }
}

my $adminGidNumber=$Options{'m'};
if (!defined($adminGidNumber)) {
    $adminGidNumber = "0";
}

print "Populating LDAP directory for domain $domain ($config{SID})\n";

my $entries_iter;

if (my $file = $Options{'i'}) {
    my $ldif = Net::LDAP::LDIF->new($file, "r", onerror => 'undef') or
	die "Cannot open file: $file: $!";
    $entries_iter = sub {
	return $ldif->read_entry;
    };
} else {
    my @entries;
    my $entry;

    print "(using builtin directory structure)\n\n";

    unless ($config{suffix} =~ /^([^=]+)=([^,]+)/) {
	die "Cannot extract first attr and value from suffix: $config{suffix}";
    }
    my $suffix_attr = $1;
    my $suffix_val = $2;
    my $suffix_oc = $oc_by_attr{$suffix_attr};
    if (!defined($suffix_oc)) {
	die "Cannot determine object class for suffix entry: $config{suffix}";
    }

    $entry = Net::LDAP::Entry->new($config{suffix},
	objectClass => $suffix_oc,
	$suffix_attr => $suffix_val,
    );
    if ($config{suffix} =~ m/(?:^|,)dc=([^,]+)/) {
	$entry->add(
	    objectClass => "organization",
	    o => $1,
	);
    }
    push(@entries, $entry);

    my %node_created = ();
    for my $config_dn (qw(usersdn groupsdn computersdn idmapdn)) {
	my $prefix = $config{$config_dn} || next;
	$prefix =~ s/,\Q$config{suffix}\E$//i;

	my $dn = $config{suffix};
	for my $node (reverse(split(/,/, $prefix))) {
	    $dn = "$node,$dn";
	    next if ($node_created{$dn});

	    unless ($node =~ /^([^=]+)=([^,]*)$/) {
		die "Cannot extract first attr and value for entry: $dn";
	    }
	    my $attr = $1;
	    my $val = $2;
	    my $oc = $oc_by_attr{$attr};
	    if (!defined($oc)) {
		die "Cannot determine object class for entry: $dn";
	    }
	    $entry = Net::LDAP::Entry->new($dn,
		objectClass => $oc,
		$attr => $val,
	    );
	    push(@entries, $entry);
	    $node_created{$dn} = 1;
	}
    }

    $entry = Net::LDAP::Entry->new("uid=$adminName,$config{usersdn}",
	objectClass =>	[qw(top person organizationalPerson inetOrgPerson sambaSAMAccount posixAccount)],
	uid =>		$adminName,
	cn =>		$adminName,
	sn =>		$adminName,
	gidNumber =>	$adminGidNumber,
	uidNumber =>	$adminUidNumber,
    );
    if ($config{shadowAccount}) {
	$entry->add(objectClass => "shadowAccount");
    }
    if (defined $config{userHome} and $config{userHome} ne "") {
	my $userHome=$config{userHome};
	$userHome=~s/\%U/$adminName/;
	$entry->add(homeDirectory => $userHome);
    } else {
	$entry->add(homeDirectory => "/nonexistent");
    }
    $entry->add(
	sambaPwdLastSet =>	0,
	sambaLogonTime =>	0,
	sambaLogoffTime =>	2147483647,
	sambaKickoffTime =>	2147483647,
	sambaPwdCanChange =>	0,
	sambaPwdMustChange =>	2147483647,
    );
    if (defined $config{userSmbHome} and $config{userSmbHome} ne "") {
	my $userSmbHome = $config{userSmbHome};
	$userSmbHome =~ s/\%U/$adminName/;
	$entry->add(sambaHomePath => $userSmbHome);
    }
    if (defined $config{userHomeDrive} and $config{userHomeDrive} ne "") {
	$entry->add(sambaHomeDrive => $config{userHomeDrive});
    }
    if (defined $config{userProfile} and $config{userProfile} ne "") {
	my $userProfile = $config{userProfile};
	$userProfile =~ s/\%U/$adminName/;
	$entry->add(sambaProfilePath => $userProfile);
    }
    $entry->add(
	sambaPrimaryGroupSID =>	"$config{SID}-512",
	sambaLMPassword =>	"XXX",
	sambaNTPassword =>	"XXX",
	sambaAcctFlags =>	"[U          ]",
	sambaSID =>		"$config{SID}-$adminRid",
	loginShell =>		"/bin/false",
	gecos =>		"Netbios Domain Administrator",
    );
    push(@entries, $entry);

    $entry = Net::LDAP::Entry->new("uid=$guestName,$config{usersdn}",
	objectClass => [qw(top person organizationalPerson inetOrgPerson sambaSAMAccount posixAccount)],
	cn =>			$guestName,
	sn =>			$guestName,
	gidNumber =>		514,
	uid =>			$guestName,
	uidNumber =>		$guestUidNumber,
	homeDirectory =>	"/nonexistent",
	sambaPwdLastSet =>	0,
	sambaLogonTime =>	0,
	sambaLogoffTime =>	2147483647,
	sambaKickoffTime =>	2147483647,
	sambaPwdCanChange =>	0,
	sambaPwdMustChange =>	2147483647,
    );
    if ($config{shadowAccount}) {
	$entry->add(objectClass => "shadowAccount");
    }
    if (defined $config{userSmbHome} and $config{userSmbHome} ne "") {
	my $userSmbHome = $config{userSmbHome};
	$userSmbHome =~ s/\%U/$guestName/;
	$entry->add(sambaHomePath => $userSmbHome);
    }
    if (defined $config{userHomeDrive} and $config{userHomeDrive} ne "") {
	$entry->add(sambaHomeDrive => $config{userHomeDrive});
    }
    if (defined $config{userProfile} and $config{userProfile} ne "") {
	my $userProfile=$config{userProfile};
	$userProfile=~s/\%U/$guestName/;
	$entry->add(sambaProfilePath => $userProfile);
    }
    $entry->add(
	sambaPrimaryGroupSID => "$config{SID}-514",
	sambaLMPassword =>	"NO PASSWORDXXXXXXXXXXXXXXXXXXXXX",
	sambaNTPassword =>	"NO PASSWORDXXXXXXXXXXXXXXXXXXXXX",
	# account disabled by default
	sambaAcctFlags =>	"[NUD        ]",
	sambaSID =>		"$config{SID}-$guestRid",
	loginShell =>		"/bin/false",
    );
    push(@entries, $entry);

    $entry = Net::LDAP::Entry->new("cn=Domain Admins,$config{groupsdn}",
	objectClass => [qw(top posixGroup sambaGroupMapping)],
	cn =>		"Domain Admins",
	gidNumber =>	512,
	memberUid =>	$adminName,
	description =>	"Netbios Domain Administrators",
	sambaSID =>	"$config{SID}-512",
	sambaGroupType =>2,
	displayName =>	"Domain Admins",
    );
    push(@entries, $entry);

    $entry = Net::LDAP::Entry->new("cn=Domain Users,$config{groupsdn}",
	objectClass => [qw(top posixGroup sambaGroupMapping)],
	cn =>		"Domain Users",
	gidNumber =>	513,
	description =>	"Netbios Domain Users",
	sambaSID =>	"$config{SID}-513",
	sambaGroupType =>2,
	displayName =>	"Domain Users",
    );
    push(@entries, $entry);

    $entry = Net::LDAP::Entry->new("cn=Domain Guests,$config{groupsdn}",
	objectClass => [qw(top posixGroup sambaGroupMapping)],
	cn =>		"Domain Guests",
	gidNumber =>	514,
	description =>	"Netbios Domain Guests Users",
	sambaSID =>	"$config{SID}-514",
	sambaGroupType =>2,
	displayName =>	"Domain Guests",
    );
    push(@entries, $entry);

    $entry = Net::LDAP::Entry->new("cn=Domain Computers,$config{groupsdn}",
	objectClass => [qw(top posixGroup sambaGroupMapping)],
	cn =>		"Domain Computers",
	gidNumber =>	515,
	description =>	"Netbios Domain Computers accounts",
	sambaSID =>	"$config{SID}-515",
	sambaGroupType =>2,
	displayName =>	"Domain Computers",
    );
    push(@entries, $entry);

    $entry = Net::LDAP::Entry->new("cn=Administrators,$config{groupsdn}",
	objectClass => [qw(top posixGroup sambaGroupMapping)],
	cn =>		"Administrators",
	gidNumber =>	544,
	description =>	"Netbios Domain Members can fully administer the computer/sambaDomainName",
	sambaSID =>	"S-1-5-32-544",
	sambaGroupType => 4,
	displayName =>	"Administrators",
    );
    push(@entries, $entry);

#    $entry = Net::LDAP::Entry->new("cn=Users,$config{groupsdn}",
#	objectClass => [qw(top posixGroup sambaGroupMapping)],
#	gidNumber =>	545,
#	cn =>		"Users",
#	description =>	"Netbios Domain Ordinary users",
#	sambaSID =>	"S-1-5-32-545",
#	sambaGroupType =>	4,
#	displayName =>	"users",
#    );
#    push(@entries, $entry);

#    $entry = Net::LDAP::Entry->new("cn=Guests,$config{groupsdn}",
#	objectClass => [qw(top posixGroup sambaGroupMapping)],
#	gidNumber =>	546,
#	cn =>		"Guests",
#	memberUid =>	$guestName,
#	description =>	"Netbios Domain Users granted guest access to the computer/sambaDomainName",
#	sambaSID =>	"S-1-5-32-546",
#	sambaGroupType =>	4,
#	displayName =>	"Guests",
#    );
#    push(@entries, $entry);

#    $entry = Net::LDAP::Entry->new("cn=Power Users,$config{groupsdn}",
#	objectClass => [qw(top posixGroup sambaGroupMapping)],
#	gidNumber =>	547,
#	cn =>		"Power Users",
#	description =>	"Netbios Domain Members can share directories and printers",
#	sambaSID =>	"S-1-5-32-547",
#	sambaGroupType =>	4,
#	displayName =>	"Power Users",
#    );
#    push(@entries, $entry);

    $entry = Net::LDAP::Entry->new("cn=Account Operators,$config{groupsdn}",
	objectClass => [qw(top posixGroup sambaGroupMapping)],
	cn =>		"Account Operators",
	gidNumber =>	548,
	description =>	"Netbios Domain Users to manipulate users accounts",
	sambaSID =>	"S-1-5-32-548",
	sambaGroupType =>	4,
	displayName =>	"Account Operators",
    );
    push(@entries, $entry);

#    $entry = Net::LDAP::Entry->new("cn=System Operators,$config{groupsdn}",
#	objectClass => [qw(top posixGroup sambaGroupMapping)],
#	gidNumber =>	549,
#	cn =>		"System Operators",
#	description =>	"Netbios Domain System Operators",
#	sambaSID =>	"S-1-5-32-549",
#	sambaGroupType =>	4,
#	displayName =>	"System Operators",
#    );
#    push(@entries, $entry);

    $entry = Net::LDAP::Entry->new("cn=Print Operators,$config{groupsdn}",
	objectClass =>	[qw(top posixGroup sambaGroupMapping)],
	cn =>		"Print Operators",
	gidNumber =>	550,
	description =>	"Netbios Domain Print Operators",
	sambaSID =>	"S-1-5-32-550",
	sambaGroupType =>	4,
	displayName =>	"Print Operators",
    );
    push(@entries, $entry);

    $entry = Net::LDAP::Entry->new("cn=Backup Operators,$config{groupsdn}",
	objectClass =>	[qw(top posixGroup sambaGroupMapping)],
	cn =>		"Backup Operators",
	gidNumber =>	551,
	description =>	"Netbios Domain Members can bypass file security to back up files",
	sambaSID =>	"S-1-5-32-551",
	sambaGroupType =>	4,
	displayName =>	"Backup Operators",
    );
    push(@entries, $entry);

    $entry = Net::LDAP::Entry->new("cn=Replicators,$config{groupsdn}",
	objectClass => [qw(top posixGroup sambaGroupMapping)],
	cn =>		"Replicators",
	gidNumber =>	552,
	description =>	"Netbios Domain Supports file replication in a sambaDomainName",
	sambaSID =>	"S-1-5-32-552",
	sambaGroupType =>	4,
	displayName =>	"Replicators",
    );
    push(@entries, $entry);

    $entry = Net::LDAP::Entry->new("sambaDomainName=$domain,$config{suffix}",
	objectClass =>	[qw(top sambaDomain)],
	sambaDomainName =>	$domain,
	sambaSID =>		$config{SID},
    );
    if (defined($algorithmicRidBase)) {
	$entry->add(sambaAlgorithmicRidBase => $algorithmicRidBase);
    } else {
	$entry->add(sambaNextRid => $firstridNumber);
    }
    if ("sambaDomainName=$domain,$config{suffix}" eq $config{sambaUnixIdPooldn}) {
	$entry->add(
	    objectClass =>	"sambaUnixIdPool",
	    uidNumber =>	$firstuidNumber,
	    gidNumber =>	$firstgidNumber,
	);
	push(@entries, $entry);
    } else {
	push(@entries, $entry);

	my ($pool_attr, $pool_val)=($config{sambaUnixIdPooldn}=~/([^=]+)=([^,]+),\Q$config{suffix}\E/);
	my $pool_oc = $oc_by_attr{$pool_attr} || 'inetOrgPerson';

	$entry = Net::LDAP::Entry->new($config{sambaUnixIdPooldn},
	    objectClass => [$pool_oc, qw(sambaUnixIdPool)],
	    $pool_attr => $pool_val,
	    uidNumber => $firstuidNumber,
	    gidNumber => $firstgidNumber,
	);
	$entry->add(sn => $pool_val) if ($pool_oc eq 'inetOrgPerson');
	push(@entries, $entry);
    }

    $entries_iter = sub {
	return shift(@entries);
    };
}

if (my $file = $Options{'e'}) {
    open my $file_fh, ">$file" or die "Cannot open file: $file: $!";
    while (my $entry = $entries_iter->()) {
	$file_fh->print($entry->ldif);
    }
    print "exported ldif file: $file\n";
    exit(0);
}

my $ldap_master=connect_ldap_master();
while (my $entry = $entries_iter->()) {
    my $dn = $entry->dn;
    # we first check if the entry exist
    my $mesg = $ldap_master->search(
	base => $dn,
	scope => "base",
	filter => "objectclass=*"
    );
    $mesg->code && die "failed to search entry: ", $mesg->error;
    if ($mesg->count == 1) {
	print "entry $dn already exist. ";
	if ($dn eq $config{sambaUnixIdPooldn}) {
	    print "Updating it...\n";
	    my @mods;
	    foreach my $attr_tmp ($entry->attributes) {
		push(@mods,$attr_tmp=>[$entry->get_value("$attr_tmp")]);
	    }
	    my $modify = $ldap_master->modify($dn,
		'replace' => { @mods },
	    );
	    $modify->code && warn "failed to modify entry: ", $modify->error ;
	} else {
	    print "\n";
	}
    } else {
	print "adding new entry: $dn\n";
	my $result=$ldap_master->add($entry);
	$result->code && warn "failed to add entry: ", $result->error ;
    }
}
$ldap_master->unbind;

# secure the admin account
print "\nPlease provide a password for the domain $adminName: \n";
system("$RealBin/smbldap-passwd", $adminName);

exit(0);


########################################

=head1 NAME

smbldap-populate - Populate your LDAP database

=head1 SYNOPSIS

smbldap-populate [ldif-file]

=head1 DESCRIPTION

The smbldap-populate command helps to populate an LDAP server by adding the necessary entries : base suffix (doesn't abort if already there), organizational units for users, groups and computers, builtin users : Administrator and guest, builtin groups (though posixAccount only, no SambaTNG support).

-a name
Your local administrator login name (default: root)

-b name
Your local guest login name (default: nobody)

-e file
export an ldif file

-i file
import an ldif file (Options -a and -b will be ignored)

=head1 FILES

@SYSCONFDIR@/smbldap.conf : main configuration
@SYSCONFDIR@/smbldap_bind.conf : credentials for binding to the directory

=head1 SEE ALSO

smb.conf(5)

=cut

#'



# - The End
