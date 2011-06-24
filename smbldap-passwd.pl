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
#       . ldap-unix passwd sync for SAMBA>2.2.2 + LDAP
#       . may also replace /bin/passwd

use strict;
use warnings;
use smbldap_tools;

use Crypt::SmbHash;

my $user= undef;
my $pass_old = undef;

my $arg;
my $update_samba_passwd= 1;
my $update_unix_passwd= 1;
my $force_update_samba_passwd=0;
my $use_dialog=1;

foreach $arg (@ARGV) {
    if ( substr( $arg, 0, 1 ) eq '-' ) {
	if ( $arg eq '-h' || $arg eq '-?' || $arg eq '--help' ) {
	    print_banner;
	    print "Usage: $0 [hpsuB?] [username]\n";
	    print "  -h, -?, --help show this help message\n";
	    print "  -p             read password from STDIN without verification (root only)\n";
	    print "  -s             update only samba password\n";
	    print "  -u             update only UNIX password\n";
	    print "  -B             must change Samba password at logon\n";
	    exit (6);
	} elsif ($arg eq '-s') {
	    $update_samba_passwd= 1; $update_unix_passwd= 0;
	} elsif ($arg eq '-u') {
	    $update_samba_passwd= 0; $update_unix_passwd= 1;
	} elsif ($arg eq '-B') {
            $force_update_samba_passwd= 1;
	} elsif ($arg eq '-p') {
            $use_dialog= 0;
        }
    } else {
	if ( $< != 0 ) {
	    die "Only root can specify username\n";
	}
	$user= $arg; last;
    }
}

if (!defined($user)) {
    $user = getpwuid($<);		# $user=$ENV{"USER"};
}

# check if $user variable is not tainted
# [TODO] create proper user mask
$user =~ /^([-\@\ \w.]+\$?)$/ and $user = $1 or
    die "$0: username '$user' is tainted\n";


my ($dn,$ldap_master);
# First, connecting to the directory
if ($< != 0) {
    # non-root user
    if (!defined($pass_old)) {
	# prompt for password
	print "Identity validation...\n";
	$pass_old = password_read("Enter your UNIX password: ");

	$config{masterDN}="uid=$user,$config{usersdn}";
	$config{masterPw} = $pass_old;
	$ldap_master=connect_ldap_master();
	$dn=$config{masterDN};
	if (!is_user_valid($user, $dn, $pass_old)) {
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

my $samba = is_samba_user($user);

# Printing verbose message
if ( $samba and $update_samba_passwd ) {
    if ( $update_unix_passwd ) {
	print "Changing UNIX and samba passwords for $user\n";
    } else {
	print "Changing samba password for $user\n";
    }
} else {
    if ( $update_unix_passwd ) {
	print "Changing UNIX password for $user\n";
    } else {
	die "Internal error";
    }
}

# prompt for new password

my $pass;

if (($< != 0) || $use_dialog) {
	$pass = password_read("New password: ");
	my $pass2 = password_read("Retype new password: ");

	if ($pass ne $pass2) {
	    print "New passwords don't match!\n";
	    exit (10);
	}
} else {
	$pass = password_read();
}

# First, connecting to the directory
if ($< != 0) {
    # if we are not root, we close the connection to re-open it as a normal user
    $ldap_master->unbind;
    $config{masterDN}="uid=$user,$config{usersdn}";
    $config{masterPw} = $pass_old;
    $ldap_master=connect_ldap_master();
}

# only modify smb passwords if smb user
if ( $samba and $update_samba_passwd ) {
    if (!$config{with_smbpasswd}) {
	# generate LanManager and NT clear text passwords
	my ($sambaLMPassword,$sambaNTPassword) = ntlmgen $pass;
	# the sambaPwdLastSet must be updating
	my $date=time;
	my @mods;
	push(@mods, 'sambaLMPassword' => $sambaLMPassword);
	push(@mods, 'sambaNTPassword' => $sambaNTPassword);
	push(@mods, 'sambaPwdLastSet' => $date);
	if (defined $config{defaultMaxPasswordAge}) {
	    my $new_sambaPwdMustChange=$date+$config{defaultMaxPasswordAge}*24*60*60;
	    push(@mods, 'sambaPwdMustChange' => $new_sambaPwdMustChange);
	    if ($< ==0) {
		push(@mods, 'sambaAcctFlags' => '[U]');
	    }
	}
	if ($force_update_samba_passwd == 1) {
		    # To force a user to change his password:
		    # . the attribut sambaPwdLastSet must be != 0
		    # . the attribut sambaAcctFlags must not match the 'X' flag
		    my $winmagic = 2147483647;
		    my $valacctflags = "[U]";
		    push(@mods, 'sambaPwdMustChange' => 0);
		    push(@mods, 'sambaPwdLastSet' => 0);
		    push(@mods, 'sambaAcctFlags' => $valacctflags);
		}
	# Let's change nt/lm passwords
	my $modify = $ldap_master->modify ( "$dn",
					    'replace' => { @mods }
					    );
	$modify->code && warn "Failed to modify SMB password: ", $modify->error ;

    } else {
	if ($< != 0) {
	    my $FILE="|$config{smbpasswd} -s >/dev/null";
	    open (FILE, $FILE) || die "$!\n";
	    print FILE <<EOF;
$pass_old
$pass
$pass
EOF
		;
	    close FILE;
	} else {
	    open FILE,"|-" or
		exec "$config{smbpasswd}","-s","$user";
	    local $SIG{PIPE} = sub {die "buffer pipe terminated" };
	    print FILE <<EOF;
$pass
$pass
EOF
		;
	    close FILE;
	}
    }
}

if ( $update_unix_passwd ) {
    password_set($dn, $pass, $pass_old);
}

# take down session
$ldap_master->unbind;

exit 0;

# - The End

=head1 NAME

smbldap-passwd - change user password

=head1 SYNOPSIS

smbldap-passwd [-?|--help|-s|-u] [name]

=head1 DESCRIPTION

smbldap-passwd changes passwords for user accounts. A normal user may only change the password for their own account, the super user may change the password for any account.

If option -s specified then changed only samba password.
If options -u specified then changed only UNIX password.
With no options then changed both - UNIX and samba passwords.

Password Changes
The user is first prompted for their old password, if one is present. This password is then tested against the stored password by binding to the server. The user has only one chance to enter the correct passwword. The super user is permitted to bypass this step so that forgotten passwords may be changed.
The user is then prompted for a replacement password. As a general guideline, passwords should consist of 6 to 8 characters including one or more from each of following sets:

Lower case alphabetics

Upper case alphabetics

Digits 0 thru 9

Punctuation marks

Password will prompt again and compare the second entry against the first. Both entries are require to match in order for the password to be changed.

=head1 SEE ALSO

passwd(1)

=cut

#'
