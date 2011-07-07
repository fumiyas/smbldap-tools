#!@PERL_CMD@

# $Id$

#  This code was developped by Jerome Tournier (jtournier@gmail.com) and
#  contributors (their names can be found in the CONTRIBUTORS file).

#  This was first created by tarjei Huse <tarjei@nu.no>

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

# Purpose of smbldap-usermod : user (posix,shadow,samba) modification

use strict;
use warnings;
use Getopt::Std;
use smbldap_tools;

# function declaration
sub exist_in_tab;

my %Options;

my $ok = getopts('adeghlmu?', \%Options);
if ( (!$ok) || ($Options{'?'}) || $Options{'h'} ) {
    print "Usage: $0 [adeghlmu?] [user template]\n\n";
    print "Available UNIX options are:\n";
    print "-a     Show gecos, password last change, expiration date and account status\n";
    print "-d     Show last modification password date.\n";
    print "-e     Show the expiration date\n";
    print "-g     Show gecos entry\n";
    print "-l     Show account status (locl/unlock)\n";
    print "-m     Only list machines.\n";
    print "-u     Only list users\n";
    print "-?|-h  show the help message\n";
    exit (1);
}

die "Error: can't use both options -u and -m\n" if ($Options{u} && $Options{m});

my $binduser;
my $pass;

if (!defined($binduser)) {
    $binduser = getpwuid($<);
}

my $search;
if ( $ARGV[0] ) {
    if ( $< != 0 ) {
        die "Only root can show other users inormations\n";
    } else {
        $search=$ARGV[0];
    }
} elsif ( $< != 0 ) {
    $search=$binduser;
}


my ($dn,$ldap_master);
# First, connecting to the directory
if ($< != 0) {
    # non-root user
    if (!defined($pass)) {
	$pass = password_read("UNIX password: ");

# JTO: search real basedn: may be different in case ou=bla1,ou=bla2 !
# JTO: faire afficher egalement lock, expire et lastChange
$config{masterDN}="uid=$binduser,$config{usersdn}";
$config{masterPw}="$pass";
$ldap_master=connect_ldap_master();
$dn=$config{masterDN};
if (!is_user_valid($binduser, $dn, $pass)) {
    print "Authentication failure\n";
    exit (10);
}
}
} else {
    # root user
    $ldap_master=connect_ldap_master();
# test existence of user in LDAP
my $dn_line;
}

sub print_user {
    my ($entry, %Options) = @_;
    printf "%4s ", $entry->get_value('uidNumber') ;
    printf "|%-20s ", $entry->get_value('uid');
    if ($Options{'d'} || $Options{'a'}) {
    	my $sambaPwdLastSet=$entry->get_value('sambaPwdLastSet');
	if (defined $sambaPwdLastSet) {
	    #printf "%-16s ", time2str("%D %H:%m", $sambaPwdLastSet);
	    $sambaPwdLastSet=localtime($sambaPwdLastSet);
	    #print "sambaPwdLastSet\n";
	    $sambaPwdLastSet=~/(\w*)\s(\w*)\s*(\d*)\s*(\d*):(\d*):(\d*)\s*(\d*)/;
	    $sambaPwdLastSet="$1 $2 $3 $7 $4:$5";
	    printf "|%-23s", $sambaPwdLastSet;
	} else {
	    printf "|%-23s","- ";
	}
    	my $shadowLastChange=$entry->get_value('shadowLastChange');
	if (defined $shadowLastChange) {
	    $shadowLastChange=localtime($shadowLastChange*86400);
	    $shadowLastChange=~/(\w*)\s(\w*)\s*(\d*)\s*(\d*):(\d*):(\d*)\s*(\d*)/;
	    $shadowLastChange="$1 $2 $3 $7";
	    printf "|%-18s", $shadowLastChange;
	} else {
	    printf "|%-18s","- ";
	}
	#print "\n";
    }
    if ($Options{'e'} || $Options{'a'}) {
    	my $sambaPwdMustChange=$entry->get_value('sambaPwdMustChange');
	if (defined $sambaPwdMustChange) {
	    $sambaPwdMustChange=localtime($sambaPwdMustChange);
            $sambaPwdMustChange=~/(\w*)\s(\w*)\s*(\d*)\s*(\d*):(\d*):(\d*)\s*(\d*)/;
            $sambaPwdMustChange="$1 $2 $3 $7 $4:$5";
	    printf "|%-22s", $sambaPwdMustChange;
	} else {
	    printf "|%-22s","- ";
	}
    	my $sambaKickoffTime=$entry->get_value('sambaKickoffTime');
	if (defined $sambaKickoffTime) {
	    $sambaKickoffTime=localtime($sambaKickoffTime);
            $sambaKickoffTime=~/(\w*)\s(\w*)\s*(\d*)\s*(\d*):(\d*):(\d*)\s*(\d*)/;
            $sambaKickoffTime="$1 $2 $3 $7 $4:$5";
	    printf "|%-22s", $sambaKickoffTime;
	} else {
	    printf "|%-22s","- ";
	}
    	my $shadowExpire=$entry->get_value('shadowExpire');
	if (defined $shadowExpire) {
	    $shadowExpire=localtime($shadowExpire*86400);
	    $shadowExpire=~/(\w*)\s(\w*)\s*(\d*)\s*(\d*):(\d*):(\d*)\s*(\d*)/;
	    $shadowExpire="$1 $2 $3 $7";
	    printf "|%-16s", $shadowExpire;
	} else {
	    printf "|%-16s","- ";
	}
    	my $shadowMin=$entry->get_value('shadowMin');
	if (defined $shadowMin) {
	    printf "|%-10s", $shadowMin;
	} else {
	    printf "|%-10s","- ";
	}
    	my $shadowMax=$entry->get_value('shadowMax');
	if (defined $shadowMax) {
	    printf "|%-10s", $shadowMax;
	} else {
	    printf "|%-10s","- ";
	}
    }
    if ($Options{'l'} || $Options{'a'}) {
    	my $userPassword=$entry->get_value('userPassword');
	if (defined $userPassword) {
            my $status;
            if ( $userPassword =~ /!/ ) {
                $status="locked";
            } else {
                $status="unlocked";
            }
	    printf "|%-10s", $status;
	} else {
	    printf "|%-10s","- ";
	}
    	my $sambaAcctFlags=$entry->get_value('sambaAcctFlags');
	if (defined $sambaAcctFlags) {
	    $sambaAcctFlags=~s/\s*//g;
	    printf "|%-10s", $sambaAcctFlags;
	} else {
	    printf "|%-10s","- ";
	}
    }
    if ((($Options{'g'} || $Options{'a'})))
    {
	if (defined $entry->get_value('gecos') and ($Options{'g'} || $Options{'a'}))
	{
	    printf "|%-10s", $entry->get_value('gecos');

	} else {
	    print "|-";
	}
    }
    print "|\n";
}

my $attrs="['username','uidNumber','uid'";
my $banner="uid  |username             ";
if ($Options{'d'} || $Options{'a'})
{
    $banner .= "|sambaPwdLastSet        ";
    $banner .= "|shadowLastChange  ";
    $attrs  .=  ",'sambaPwdLastSet','shadowLastChange'";
}
if ($Options{'e'} || $Options{'a'})
{
    $banner .= "|sambaPwdMustChange    ";
    $banner .= "|sambaKickoffTime      ";
    $banner .= "|shadowExpire    ";
    $banner .= "|shadowMax ";
    $attrs  .= ",'sambaPwdMustChange','sambaKickoffTime','shadowExpire','shadowMax'";
    $banner .= "|shadowMin ";
    $attrs  .= ",'sambaPwdMustChange','sambaKickoffTime','shadowExpire','shadowMin'";
}
if ($Options{'l'} || $Options{'a'})
{
    $banner .= "|status UNX";
    $banner .= "|status SMB";
    $attrs  .= ",'userPassword','sambaAcctFlags'";
}
if ($Options{'g'} || $Options{'a'})
{
    $banner .= "|gecos      |";
    $attrs  .= ",'gecos'";
}
$attrs.="]";
print "$banner\n\n";
my $filter;
$filter = "(&(objectclass=posixAccount)";
my $base;
if ($Options{'m'}) {
    # $filter .= "(sambaAcctFlags=[W          ])";
    $base=$config{computersdn}
} elsif ($Options{'u'}) {
    # $filter .= "(sambaAcctFlags=[U          ])";
    $base=$config{usersdn}
} else {
    $base=$config{suffix}
}
if ($search) {
    $filter.="(uid=$search)";
}

$filter.=")";

my  $mesg = $ldap_master->search ( base   => $base,
                                   scope => $config{scope},
                                   filter => $filter,
				   attrs => "$attrs"
				   );
$mesg->code && warn $mesg->error;

foreach my $entry ($mesg->all_entries) {
    print_user($entry,%Options);
}
########################################

=head1 NAME

smbldap-userlist list users or machines with some info

=head1 SYNOPSIS

smbldap-userlist [-a] [-g] [-d] [-e] [-l] [-m] [user template]


=head1 DESCRIPTION

-a     Show gecos, password last change, expiration date and account status

-g     Show gecos entry

-d     Show last modification password date

-e     Show the expiration date

-l     Show account status (locl/unlock)

-m     Only list machines

-u     Only list users

-?     show the help message

=head1 EXAMPLE

smbldap-userlist -a

smbldap-userlist -a jtournier

smbldap-userlist -a "*ourn*"

=cut

#'

# The End
