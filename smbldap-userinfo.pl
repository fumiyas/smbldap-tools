#!@PERL_CMD@ -w

# $Id$

#  This code was developped by Jerome Tournier (<jtournier@gmail.com>)
#  This was first contributed by IDEALX (http://www.opentrust.com/)
#  Originally developped by P.Wieleba@iem.pw.edu.pl
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
#  USA.

use strict;
use Getopt::Std;
use FindBin;
use FindBin qw($RealBin);
use lib "$RealBin/";
use smbldap_tools;

# function declaration
sub exist_in_tab;

my %Options;

my $ok = getopts('f:h:lo:r:s:vw:?', \%Options);
if ( (!$ok) || ($Options{'?'}) ) {
    print "Usage: $0 [-fhlorsvw?] username\n";
    print "  -f full_name\n";
    print "  -h home_ph\n";
    print "  -l only list user information\n";
    print "  -o other\n";
    print "  -r room_no\n";
    print "  -s shell\n";
    print "  -v show modified user record\n";
    print "  -w work_ph\n";
    print "  -? show this help message\n";
    exit (1);
}


my $user;
my $pass;
if ( $< != 0 ) {
    my $current_user = getpwuid($<);
    if ($current_user and $ARGV[0] and $current_user ne $ARGV[0] ) {
        die "Only root can change other users inormation\n";
    }
} else {
    if ( $ARGV[0] ) {
    $user = $ARGV[0];
}
    $pass = 1;
}

if (!defined($user)) {
    $user = getpwuid($<);
}

my ($dn,$ldap_master);

# make a anonymous connection to get the corect user's dn (not necessarily in $config{usersdn}
$ldap_master=connect_ldap_master();
my $user_entry = read_user_entry($user);
if (!defined($user_entry)) {
    print "$0: user $user doesn't exist\n";
    exit (1);
}
# get the dn of the user
$dn= $user_entry->dn();
my $entry = read_user_entry($user);
# unbind from LDAP
$ldap_master->unbind();

if ($Options{'l'}) {
    if (! $entry->get_value('userPassword')) {
        print "ACL on userPassword requires authentication... \n";
	$pass = read_password("Please enter your UNIX password: ");
        # now bind again with user's parameters
        $config{masterDN}="$dn";
        $config{masterPw}="$pass";
        $ldap_master=connect_ldap_master();
        $entry = read_user_entry($user);
        if (!is_user_valid($user, $dn, $pass)) {
            print "\nWarning: Authentication failure. Will not display account status (lock/unlock).\n\n";
	} else {
	    print "\n";
	}
        # unbind from LDAP
        $ldap_master->unbind();
    }

    my %attrs = (
		 'cn' => 'Full Name',
		 'sn' => 'Family Name',
		 'givenName'   => 'First Name',
		 'LoginShell'  => 'User Shell',
		 'roomNumber' => 'Room Number',
		 'telephoneNumber' => 'Work Phone',
		 'homePhone' => 'Home Phone',
		 'other' => 'Other',
		 'shadowMax' => 'Maximum number of days between Shadow password change',
		 'shadowMin' => 'Minimum number of days between Shadow password change',
		 'shadowInactive' => 'Shadow  Inactive',
		 'shadowWarning' => 'Shadow Warning',
		 'shadowExpire' => 'Shadow Expires',
		 'shadowLastChange' => 'Shadow Last Change',
                 'userPassword' => 'Shadow Account Satus',
                 'sambaPwdLastSet' => 'Samba Password Last Set',
                 'sambaPwdMustChange' => 'Samba Password Must Change',
                 'sambaAcctFlags' => 'Samba Flags'
		 );
    foreach my $key ('cn','sn','givenName','LoginShell','roomNumber','telephoneNumber','homePhone','other','shadowMax','shadowMin','shadowWarning','shadowInactive','shadowExpire','shadowLastChange','userPassword','sambaPwdLastSet','sambaPwdMustChange','sambaAcctFlags') {
        my $value=$entry->get_value("$key");
        if (defined $value and ($key eq "shadowExpire" || $key eq "shadowLastChange")) {
	    $value=localtime($value*86400);
	    $value=~/(\w*)\s(\w*)\s*(\d*)\s*(\d*):(\d*):(\d*)\s*(\d*)/;
	    $value="$1 $2 $3 $7";
	}
        if ($key eq "userPassword") {
            my $status;
        if ($value) {
            if ( $value =~ /!/ ) {
                $status="lock";
            } else {
                $status="unlock";
            }
        } else {
                $status="unknown";
        }
            $value=$status;
        }
        if ($value and ($key eq "sambaPwdLastSet" || $key eq "sambaPwdMustChange") ) {
	    $value=localtime($value);
            $value=~/(\w*)\s(\w*)\s*(\d*)\s*(\d*):(\d*):(\d*)\s*(\d*)/;
            $value="$1 $2 $3 $7 $4:$5";
        }
	if (! defined $value) {
	    print "$attrs{$key}: -\n";
	} else {
	    print "$attrs{$key}: $value\n";
	}
        if ($value and $key eq "sambaAcctFlags") {
            $value=~s/\s*//g;
        }
    }
    exit;
}

# First, connecting to the directory
if ($< != 0) {
    # non-root user
    if (!defined($pass)) {
	$pass = read_password("UNIX password: ");

# now make a connection with the user's dn and password
$config{masterDN}="$dn";
$config{masterPw}="$pass";
$ldap_master=connect_ldap_master();
$dn=$config{masterDN};
if (!is_user_valid($user, $dn, $pass)) {
    print "Authentication failure\n";
    exit (10);
}
}
} else {
    # root user
    $ldap_master=connect_ldap_master();
# test existence of user in LDAP
my $dn_line;
if (!defined($dn_line = get_user_dn($user))) {
    print "$0: user $user doesn't exist\n";
exit (10);
}
$dn = get_dn_from_line($dn_line);
}

# obtain old values
$entry = read_user_entry($user);


my %eng = (
	   'name'   => 'Full Name',
	   'shell'  => 'User Shell',
	   'office' => 'Room Number',
	   'wphone' => 'Work Phone',
	   'hphone' => 'Home Phone',
	   'other' => 'Other',
	   'shadowMax' => 'Password Max',
	   'shadowMin' => 'Password Min',
	   'shadowInactive' => 'Password Inactive',
	   'shadowExpire' => 'Account Expires',
	   'shadowLastChange' => 'Last Change'
	   );

my $gecos = $entry->get_value('gecos');
my %old;
( $old{'name'},
  $old{'office'},
  $old{'wphone'},
  $old{'hphone'},
  $old{'other'}
  ) = split(/,/,$gecos);
$old{'shell'} = $entry->get_value('LoginShell');
# unbind from LDAP
$ldap_master->unbind();


foreach my $key (keys %old) {
    !defined($old{$key}) and $old{$key}="";
}


# read new values
my %new;
if ($Options{'f'}) {
    $new{'name'} = $Options{'f'};
}
if ($Options{'r'}) {
    $new{'office'} = $Options{'r'};
}
if ($Options{'w'}) {
    $new{'wphone'} = $Options{'w'};
}
if ($Options{'h'}) {
    $new{'hphone'} = $Options{'h'};
}
if ($Options{'o'}) {
    $new{'other'} = $Options{'o'};
}
if ($Options{'s'}) {
    $new{'shell'} = $Options{'s'};
}
if ( keys(%Options) < 1 or keys(%Options) == 1 and $Options{'v'} ) {
    print "Changing the user information for $user\n";
    print "Enter the new value, or press ENTER for the default\n";

    print " $eng{'shell'} [$old{'shell'}]: ";
    $new{'shell'} = readline(*STDIN);
    print " $eng{'name'} [$old{'name'}]: ";
    $new{'name'} = readline(*STDIN);
    print " $eng{'office'} [$old{'office'}]: ";
    $new{'office'} = readline(*STDIN);
    print " $eng{'wphone'} [$old{'wphone'}]: ";
    $new{'wphone'} = readline(*STDIN);
    print " $eng{'hphone'} [$old{'hphone'}]: ";
    $new{'hphone'} = readline(*STDIN);
    print " $eng{'other'} [$old{'other'}]: ";
    $new{'other'} = readline(*STDIN);
}


foreach my $key (keys %old) {
    if (!$new{$key}) {
	$new{$key} = $old{$key};
    }
}

# simple check of new values
foreach my $key (keys %new) {
    chop($new{$key}) if ( $new{$key}=~/\n$/ );
    if ($new{$key} =~ /^\s+$/ and $key ne 'shell') {
	$new{$key} = "";
    } elsif ($new{$key} =~ /^$/) {
	$new{$key} = $old{$key};
    } elsif ($key ne 'other' and $new{$key} =~ /.*,.*/) {
	print "Comma cannot be used with $key.\n";
	exit(6);
    }
    # $new{$key} eq "" 
}

# [TODO] check if shell really exists
if ( $new{'shell'} and !($new{'shell'}=~/^\/.+\/.+/)
     and ($old{'shell'}=~/^\/.+\/.+/)
     ) {
    $new{'shell'} = $old{'shell'};
} elsif ( $new{'shell'} and !($new{'shell'}=~/^\/.+\/.+/)
          or !$new{'shell'} and !$old{'shell'}
	  ) {
    $new{'shell'} = '/bin/sh';
}

if ( !$new{'name'} ) {
    $new{'name'} = $user;
}

# prepare gecos field
$gecos = join(',',
	      ( $new{'name'},
		$new{'office'},
		$new{'wphone'},
		$new{'hphone'},
		$new{'other'}
		)
	      );

my @tmp = split(/\s+/,$new{'name'});
my $sn = $tmp[$#tmp];
pop(@tmp);
my $givenName = join(' ',@tmp);

$entry->replace( 'gecos' => $gecos );
$entry->replace( 'cn'    => $new{'name'} );

if ( exist_in_tab( [$entry->get_value('objectClass')],'inetOrgPerson') ) {
    if ( $sn ) {
	$entry->replace('sn' => $sn);
    } else {
	$entry->replace('sn' => $user);
    }
    if ( $givenName ) {
	$entry->replace('givenName' => $givenName);
    } else {
	$entry->get_value('givenName') and $entry->delete('givenName');
    }
    if ( $new{'office'} ) {
	$entry->replace('roomNumber' => $new{'office'});
    } else {
	$entry->get_value('roomNumber') and $entry->delete('roomNumber');
    }
    if ( $new{'wphone'} ) {
	$entry->replace('telephoneNumber' => $new{'wphone'});
    } else {
	$entry->get_value('telephoneNumber') and $entry->delete('telephoneNumber');
    }
    if ( $new{'hphone'} ) {
	$entry->replace('homePhone' => $new{'hphone'});
    } else {
	$entry->get_value('homePhone') and $entry->delete('homePhone');
    }
}				#end of inetOrgPerson
if ( $new{'shell'} ) {
    $entry->replace('loginShell' => $new{'shell'});
} else {
    $entry->get_value('loginShell') and $entry->delete('loginShell');
}

if ($Options{'v'}) {
    $entry->dump();
}
# bind to LDAP and update entry
$ldap_master = connect_ldap_master();
my $mesg = $entry->update($ldap_master);
if ($mesg->is_error()) {
    print "Error: " . $mesg->error() . "\n";
} else {
    print "LDAP updated\n";
}
$ldap_master and $ldap_master->unbind;

# Check if a $text element exists in @table
# eg. exist_in_tab(\@table,$text);
sub exist_in_tab
{
    my($ref_tab,$text) = @_;
    my @tab = @$ref_tab;

    foreach my $elem (@tab) {
	if ( lc($elem) eq lc($text) ) {
	    return 1;
	}
    }
    return 0;
}

########################################

=head1 NAME

smbldap-userinfo - change user real name, information and shell

=head1 SYNOPSIS

smbldap-userinfo [-f full_name] [-r room_no] [-w work_ph] [-h home_ph]
[-o other] [-s login_shell] [-l] [-?] [-v]

=head1 DESCRIPTION

This command changes user gecos fields and login shell.
The normal user can change only the fields for his own account,
the super user may change the fiels for any account.

If none of the options are selected, the command is run
in an interactive mode for the current user account. User is
asked for all fields. To accept a default value you should 
just press <ENTER>, otherwise write text and press <ENTER>.

posixAccount objectClasses has to be present in the modified
entry. If inetOrgPerson objectClass is also present additional
attributes will be changed (givenName,sn,roomNumber,telephoneNumber,
homePhone)

-l
       Display users informations and password status.

-f full_name
       affected attributes: 'gecos', 'cn' (and 'givenName', 'sn'
       if inetOrgPerson is present) 

-r room_number
       affected attributes: 'gecos' (and 'roomNumber'
       if inetOrgPerson is present)

-w work_phone
       affected attributes: 'gecos' (and 'telephoneNumber'
       if inetOrgPerson is present)

-h home_phone
       affected attributes: 'gecos' (and 'homePhone'
       if inetOrgPerson is present)

-o other
       affected attributes: 'gecos'

-s login_shell
       affected attributes: 'loginShell'

-?     show the help message

-v     verbose - show modified user entry

=cut

#'

# The End

