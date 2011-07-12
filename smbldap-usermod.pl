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

# Purpose of smbldap-usermod : user (posix,shadow,samba) modification

use strict;
use warnings;
use FindBin qw($RealBin);
use smbldap_tools;
use Time::Local;
#####################

use Getopt::Long;
my %Options;

Getopt::Long::Configure('bundling');
my $ok = GetOptions(
    "A|sambaPwdCanChange=s"  => \$Options{A},
    "B|sambaPwdMustChange=s" => \$Options{B},
    "C|sambaHomePath=s"      => \$Options{C},
    "D|sambaHomeDrive=s"     => \$Options{D},
    "E|sambaLogonScript=s"   => \$Options{E},
    "F|sambaProfilePath=s"   => \$Options{F},
    "G|group=s"              => \$Options{G},
    "H|sambaAcctFlags=s"     => \$Options{H},
    "I|sambaDisable"         => \$Options{I},
    "J|sambaEnable"          => \$Options{J},
    "L|shadowLock"           => \$Options{L},
    "M|mail=s"               => \$Options{M},
    "N|givenName=s"          => \$Options{N},
    "O|mailLocalAddress=s"   => \$Options{O},
    "P"                      => \$Options{P},
    "U|shadowUnlock"         => \$Options{U},
    "S|surname=s"            => \$Options{S},
    "T|mailToAddress=s"      => \$Options{T},
    "X|inputEncoding=s"      => \$Options{X},
    "Z|attr=s@"              => \$Options{Z},
    "a|addsambaSAMAccount"   => \$Options{a},
    "c|gecos=s"              => \$Options{c},
    "d|homedir=s"            => \$Options{d},
    "e|expire=s"             => \$Options{e},
    "sambaExpire=s"          => \$Options{sambaExpire},
    "g|gid=s"                => \$Options{g},
    "h|?|help"               => \$Options{h},
    "o|canBeNotUnique"       => \$Options{o},
    "ou=s"                   => \$Options{ou},
    "r|rename=s"             => \$Options{r},
    "s|shell=s"              => \$Options{s},
    "shadowExpire=s"         => \$Options{shadowExpire},
    "shadowMax=s"            => \$Options{shadowMax},
    "shadowMin=s"            => \$Options{shadowMin},
    "shadowInactive=s"       => \$Options{shadowInactive},
    "shadowWarning=s"        => \$Options{shadowWarning},
    "u|uid=s"                => \$Options{u}
);

if ( ( !$ok ) || ( @ARGV < 1 ) || ( $Options{'h'} ) ) {
    print_banner;
    print "Usage: $0 [options] username\n\n";

    print "Available UNIX options are:\n";
    print "  -c|--gecos <gecos>           gecos\n";
    print "  -d|--homedir <dir>           home directory\n";
    print "  -r|--rename <username>       username\n";
    print "  -u|--uid <uidNumber>         uid\n";
    print "  -o|--canBeNotUnique          uid can be non unique\n";
    print "  -g|--gid <gidNumber          gid\n";
    print
      "  -G|--group [+-]<grp1,...>    supplementary groups (comma separated)\n";
    print "  -s|--shell <shell>           shell\n";
    print "  -N|--givenName <name>        given name (first name)\n";
    print "  -S|--surname <suname>        surname (family name)\n";
    print "  -P                           ends by invoking smbldap-passwd\n";
    print "  -M|--mail <mail,>            e-mail addresses (comma seperated)\n";
    print
"  -O|--mailLocalAddress <mail,> mailLocalAddress (comma separated)\n";
    print
"  -T|--mailToAddress <mail,>   mailToAddress (forward address) (comma separated)\n";
    print
"  -e|--expire <date>           Sets both shadow and samba expiration date: like \"YYYY-MM-DD(HH:MM:SS)\", or \"yYmMdD\" to extend y year,m months and d days\n";
    print
"  --shadowExpire <date/n>      Shadow expiration date (like \"YYYY-MM-DD\") or 'n' days from today\n";
    print
"  --shadowMax <n>              User must change the password, at least, every 'n' days\n";
    print
"  --shadowMin <n>              user must wait 'n' days once the password has changed before changing it again\n";
    print
"  --shadowInactive <n>         number of days of inactivity allowed for the specified user\n";
    print
"  --shadowWarning <n>          User is warned that the password must be changed four days before the password expires\n";
    print "  -L|--shadowLock              lock unix user's password\n";
    print "  -U|--shadowUnlock            unlock unix user's password\n";
    print
"  -Z                           add custom attributes, as name=value pairs comma separated\n";
    print "\n";
    print "Available SAMBA options are:\n";
    print "  -a|--addsambaSAMAccount        add sambaSAMAccount objectclass\n";
    print
"  --sambaExpire <date>           expire date (\"YYYY-MM-DD HH:MM:SS\")\n";
    print
"  -A|--sambaPwdCanChange         can change password ? 0 if no, 1 if yes\n";
    print
"  -B|--sambaPwdMustChange        must change password ? 0 if no, 1 if yes\n";
    print
"  -C|--sambaHomePath <dir>       sambaHomePath (SMB home share, like '\\\\PDC-SRV\\homes')\n";
    print
"  -D|--sambaHomeDrive <drive>    sambaHomeDrive (letter associated with home share, like 'H:')\n";
    print
"  -E|--sambaLogonScript <script> sambaLogonScript (DOS script to execute on login)\n";
    print
"  -F|--sambaProfilePath <path>   sambaProfilePath (profile directory, like '\\\\PDC-SRV\\profiles\\foo')\n";
    print
"  -H|--sambaAcctFlags <flags>    sambaAcctFlags (samba account control bits like '[NDHTUMWSLKI]')\n";
    print
"  -I|--sambaDisable              disable an user. Can't be used with -H or -J\n";
    print
"  -J|--sambaEnable               enable an user. Can't be used with -H or -I\n";
    print
"  -X|--inputEncoding             input encoding for givenname and surname (defaults to UTF-8)\n";
    print "  -h|--help                      show this help message\n";
    exit(1);
}

if ( $< != 0 ) {
    print "You must be root to modify an user\n";
    exit(1);
}

# Read only first @ARGV
my $user = $ARGV[0];

# Get the input encoding
my $characterSet;
if ( defined( $Options{'X'} ) ) {
	$characterSet = $Options{'X'};
} else {
	$characterSet = "UTF-8";
}

# Let's connect to the directory first
my $ldap_master = connect_ldap_master();

# Read user data
my $user_entry = read_user_entry($user);
if ( !defined($user_entry) ) {
    print "$0: user $user doesn't exist\n";
    exit(1);
}

my $samba = is_samba_user($user);

# get the dn of the user
my $dn = $user_entry->dn();

my $tmp;
my @mods;
my @dels;
if ( defined( $tmp = $Options{'a'} ) ) {
    if ($samba) {
        print "Error: Account for user $user already _is_ a Samba account!\n",
          "Omit option -a!\n";
        exit(1);
    }

    # Let's connect to the directory first
    my $winmagic         = 2147483647;
    my $valpwdcanchange  = 0;
    my $valpwdmustchange = $winmagic;
    my $valpwdlastset    = 0;
    my $valacctflags     = "[UX]";
    my $user_entry       = read_user_entry($user);
    my $uidNumber        = $user_entry->get_value('uidNumber');
    my $userRid          = user_next_rid($uidNumber);

    # apply changes
    my $modify = $ldap_master->modify(
        "$dn",
        changes => [
            add => [ objectClass        => 'sambaSAMAccount' ],
            add => [ sambaPwdLastSet    => "$valpwdlastset" ],
            add => [ sambaLogonTime     => '0' ],
            add => [ sambaLogoffTime    => '2147483647' ],
            add => [ sambaKickoffTime   => '2147483647' ],
            add => [ sambaPwdCanChange  => "$valpwdcanchange" ],
            add => [ sambaPwdMustChange => "$valpwdmustchange" ],
            add => [ sambaSID           => "$config{SID}-$userRid" ],
            add => [ sambaAcctFlags     => "$valacctflags" ],
        ]
    );
    if ( $modify->code ) {
        warn "failed to modify entry: ", $modify->error;
        exit 1;
    }

    # when adding samba attributes, try to set samba primary group as well.
    my $group_entry =
      read_group_entry_gid( $user_entry->get_value('gidNumber') );

    # override group if new group id sould be set with this call as well
    $group_entry = read_group_entry_gid( $Options{'g'} ) if $Options{'g'};
    my $userGroupSID = $group_entry->get_value('sambaSID');
    if ($userGroupSID) {
        my $modify_grpSID = $ldap_master->modify( "$dn",
            changes => [ add => [ sambaPrimaryGroupSID => "$userGroupSID" ], ]
        );

        if ( $modify_grpSID->code ) {
            warn "failed to modify entry: ", $modify_grpSID->error;
            exit 1;
        }
    }
    else {    # no reason to abort imho
        print
"Warning: sambaPrimaryGroupSID could not be set beacuse group of user $user is not a mapped Domain group!\n",
"To get a list of groups mapped to Domain groups, use \"net groupmap list\" on a Domain member machine.\n";
    }

# now it is a samba account. this flag is needed here if someone uses i. e. "-a -g newgroupid".
# if not set here, the sambaPrimaryGroupSID value would not be updated
    $samba = 1;

}

# Process options
my $_userUidNumber;
my $_userRid;

if ( defined( $tmp = $Options{'u'} ) ) {
    if ( !defined( $Options{'o'} ) ) {
	nsc_invalidate("passwd");
        if ( getpwuid($tmp) ) {
            print "$0: uid number $tmp exists\n";
            exit(6);
        }
    }

    push( @mods, 'uidNumber', $tmp );
    $_userUidNumber = $tmp;
    if ($samba and my $rid_base = account_base_rid()) {
	## For backward compatibility with smbldap-tools 0.9.6 and older
	my $_userRid = 2 * $_userUidNumber + $rid_base;
        push( @mods, 'sambaSID', $config{SID} . '-' . $_userRid );
    }
}

my $_userGidNumber;
my $_userGroupSID;
if ( defined( $tmp = $Options{'g'} ) ) {
    $_userGidNumber = parse_group($tmp);
    if ( $_userGidNumber < 0 ) {
        print "$0: group $tmp doesn't exist\n";
        exit(6);
    }
    push( @mods, 'gidNumber', $_userGidNumber );
    if ($samba) {

        # as grouprid we use the sambaSID attribute's value of the group
        my $group_entry   = read_group_entry_gid($_userGidNumber);
        my $_userGroupSID = $group_entry->get_value('sambaSID');
        unless ($_userGroupSID) {
            print
"Error: sambaPrimaryGroupSid could not be set (sambaSID for group $_userGidNumber does not exist)\n";
            exit(7);
        }
        push( @mods, 'sambaPrimaryGroupSid', $_userGroupSID );
    }
}

if ( defined( $tmp = $Options{'s'} ) ) {
    push( @mods, 'loginShell' => $tmp );
}

if ( defined( $tmp = $Options{'c'} ) ) {
    push(
        @mods,
        'gecos'       => $tmp,
        'description' => $tmp
    );
}

if ( defined( $tmp = $Options{'d'} ) ) {
    push( @mods, 'homeDirectory' => $tmp );
}

# RFC 2256 & RFC 2798
# sn: family name (option S)             # RFC 2256: family name of a person.
# givenName: prenom (option N)           # RFC 2256: part of a person's name which is not their surname nor middle name.
# cn: person's full name                 # RFC 2256: person's full name.
# displayName: perferably displayed name # RFC 2798: preferred name of a person to be used when displaying entries.

#givenname is the forename of a person (not famiy name) => http://en.wikipedia.org/wiki/Given_name
#surname (or sn) is the familiy name => http://en.wikipedia.org/wiki/Surname
# my surname (or sn): Tournier
# my givenname: Jerome

if ( defined( $tmp = $Options{'N'} ) ) {
    push( @mods, 'givenName' => utf8Encode($characterSet,$tmp) );
}

if ( defined( $tmp = $Options{'S'} ) ) {
    push( @mods, 'sn' => utf8Encode($characterSet,$tmp) );
}

my $cn;
if ( $Options{'N'} or $Options{'S'} or $Options{'a'} ) {
    $Options{'N'} = $user_entry->get_value('givenName') unless $Options{'N'};
    $Options{'S'} = $user_entry->get_value('sn')        unless $Options{'S'};

# if givenName eq sn eq username (default of smbldap-useradd), cn and displayName would
# be "username username". So we just append surname if its not default
# (there may be the very very special case of an user where those three values _are_ equal)
    $cn = "$Options{'N'}";
    $cn .= " " . $Options{'S'}
      unless ( $Options{'S'} eq $Options{'N'} and $Options{'N'} eq $user );
    my $push_val = utf8Encode($characterSet,$cn);
    push( @mods, 'cn' => $push_val );

    # set displayName for Samba account
    if ($samba) {
        push( @mods, 'displayName' => $push_val );
    }
}

if ( defined $Options{'e'} ) {
    if ( !defined $Options{'shadowExpire'} ) {
        $Options{'shadowExpire'} = $Options{'e'};
    }
    if ( !defined $Options{'sambaExpire'} ) {
        $Options{'sambaExpire'} = $Options{'e'};
    }
}

sub parse_date_to_unix {
    my ($date) = @_;

    if ( $date =~ /(\d\d\d\d)-(\d?\d)-(\d?\d)(\s+(\d?\d):(\d\d):(\d\d))?/ ) {
        my $localtime;
        if ( defined $5 and defined $6 and defined $7 ) {
            $localtime = timelocal( $7, $6, $5, $3, $2 - 1, $1 );
        }
        else {
            $localtime = timelocal( 0, 0, 2, $3, $2 - 1, $1 );
        }
        my $shadowExpire = int($localtime);
        $shadowExpire = sprintf( "%d", $shadowExpire );
        return $shadowExpire;
    }
    else {
        my $daysAdd = 0;

        if ( $date =~ /(\d+)y/ ) {
            $daysAdd += 365.3 * $1;
        }

        if ( $date =~ /(\d+)m/ ) {
            $daysAdd += 30.4 * $1;
        }

        if ( $date =~ /(\d+)([^ym]{1}|$)/ ) {
            $daysAdd += $1;
        }

        if ( $daysAdd > 0 ) {
            return int( time + ( $daysAdd * 24 * 3600 ) );
        }
        else {
            return -1;
        }
    }

    return -1;
}

sub parse_date_to_unix_days {
    my ($arg) = @_;
    return int( parse_date_to_unix($arg) / 86400 );
}

# Shadow password parameters
my $localtime = time() / 86400;
if ( defined $Options{'shadowExpire'} ) {

    # Unix expiration password
    my $tmp = $Options{'shadowExpire'};
    chomp($tmp);

    #    my $expire=`date --date='$tmp' +%s`;
    #    chomp($expire);
    #    my $shadowExpire=int($expire/86400)+1;
    # date syntax asked: YYYY-MM-DD

    $tmp = parse_date_to_unix_days($tmp);
    if ( $tmp != -1 ) {
        push( @mods, 'shadowExpire', $tmp );
    }
    else {
        print "Invalid format for '--shadowExpire' option.\n";
    }
}

if ( defined $Options{'shadowWarning'} ) {
    push( @mods, 'shadowWarning', $Options{shadowWarning} );
}

if ( defined $Options{'shadowMax'} ) {
    push( @mods, 'shadowMax', $Options{shadowMax} );
}

if ( defined $Options{'shadowMin'} ) {
    push( @mods, 'shadowMin', $Options{shadowMin} );
}

if ( defined $Options{'shadowInactive'} ) {
    push( @mods, 'shadowInactive', $Options{shadowInactive} );
}

if ( defined $Options{'L'} ) {

    # lock shadow account
    $tmp = $user_entry->get_value('userPassword');
    if ( !( $tmp =~ /!/ ) ) {
        $tmp =~ s/}/}!/;
    }
    push( @mods, 'userPassword' => $tmp );
}

if ( defined $Options{'U'} ) {

    # unlock shadow account
    $tmp = $user_entry->get_value('userPassword');
    if ( $tmp =~ /!/ ) {
        $tmp =~ s/}!/}/;
    }
    push( @mods, 'userPassword' => $tmp );
}

if ( $tmp = $Options{'M'} ) {    

    # action si + or - for adding or deleting an entry
    my $action = '';
    if ( $tmp =~ s/^([+-])+\s*// ) {
        $action = $1;
    }
    my @mail = &split_arg_comma($tmp);
    foreach my $m (@mail) {
        my $domain = $config{mailDomain};
        if ( $m !~ /^(.+)@/ ) {
            $m = $m . ( $domain ? '@' . $domain : '' );
        }
    }
    if ($action) {
        my @old_mail;
        @old_mail      = $user_entry->get_value('mail');
        if ( $action eq '+' ) {
            @mail          = &list_union( \@old_mail,      \@mail );
        }
        elsif ( $action eq '-' ) {
            @mail          = &list_minus( \@old_mail,      \@mail );
        }
    }
    push( @mods, 'mail' => [@mail] );
}

my $mailobj = 0;
if ( $tmp = $Options{'O'} ) {    

    # action si + or - for adding or deleting an entry
    my $action = '';
    if ( $tmp =~ s/^([+-])+\s*// ) {
        $action = $1;
    }
    my @userMailLocal = &split_arg_comma($tmp);
    if ($action) {
        my @old_MailLocal;
        @old_MailLocal = $user_entry->get_value('mailLocalAddress');
        if ( $action eq '+' ) {
            @userMailLocal = &list_union( \@old_MailLocal, \@userMailLocal );
        }
        elsif ( $action eq '-' ) {
            @userMailLocal = &list_minus( \@old_MailLocal, \@userMailLocal );
        }
    }
    push( @mods, 'mailLocalAddress', [@userMailLocal] );
    $mailobj = 1;
}

if ( $tmp = $Options{'T'} ) {
    my $action = '';
    my @old;

    # action si + or - for adding or deleting an entry
    if ( $tmp =~ s/^([+-])+\s*// ) {
        $action = $1;
    }
    my @userMailTo = &split_arg_comma($tmp);
    if ($action) {
        @old = $user_entry->get_value('mailRoutingAddress');
    }
    if ( $action eq '+' ) {
        @userMailTo = &list_union( \@old, \@userMailTo );
    }
    elsif ( $action eq '-' ) {
        @userMailTo = &list_minus( \@old, \@userMailTo );
    }
    push( @mods, 'mailRoutingAddress', [@userMailTo] );
    $mailobj = 1;
}
if ($mailobj) {
    my @objectclass = $user_entry->get_value('objectClass');
    if ( !grep ( $_ =~ /^inetLocalMailRecipient$/i, @objectclass ) ) {
        push( @mods,
            'objectClass' => [ @objectclass, 'inetLocalMailRecipient' ] );
    }
}

if ( defined( $tmp = $Options{'G'} ) ) {
    my $action = '';
    if ( $tmp =~ s/^([+-])+\s*// ) {
        $action = $1;
    }
    if ( $action eq '-' ) {

        # remove user from specified groups
        foreach my $gname ( &split_arg_comma($tmp) ) {
            group_remove_member( $gname, $user );
        }
    }
    else {
        if ( $action ne '+' ) {
            my @old = &find_groups_of($user);

            # remove user from old groups
            foreach my $gname (@old) {
                if ( $gname ne "" ) {
                    group_remove_member( $gname, $user );
                }
            }
        }

        # add user to new groups
        add_grouplist_user( $tmp, $user );
    }
}

#
# A : sambaPwdCanChange
# B : sambaPwdMustChange
# C : sambaHomePath
# D : sambaHomeDrive
# E : sambaLogonScript
# F : sambaProfilePath
# H : sambaAcctFlags

my $attr;
my $winmagic = 2147483647;

$samba = is_samba_user($user);

if ( defined( $tmp = $Options{'sambaExpire'} ) ) {
    if ( $samba == 1 ) {
        my $kickoffTime = parse_date_to_unix($tmp);
        if ( $kickoffTime != -1 ) {
            push( @mods, 'sambakickoffTime' => $kickoffTime );
        }
        else {
            print "Invalid format for '--sambaExpire' option (" . $tmp . ").\n";
        }
    }
    else {
        print "User $user is not a samba user\n";
    }
}

my $_sambaPwdCanChange;
if ( defined( $tmp = $Options{'A'} ) ) {
    if ( $samba == 1 ) {
        $attr = "sambaPwdCanChange";
        if ( $tmp != 0 ) {
            $_sambaPwdCanChange = 0;
        }
        else {
            $_sambaPwdCanChange = $winmagic;
        }
        push( @mods, 'sambaPwdCanChange' => $_sambaPwdCanChange );
    }
    else {
        print "User $user is not a samba user\n";
    }
}

if ( defined( $tmp = $Options{'B'} ) ) {
    if ( $samba == 1 ) {
        if ( $tmp != 0 ) {
            # To force a user to change his password:
            # . the attribut sambaAcctFlags must not match the 'X' flag
            my $_sambaAcctFlags;
            my $flags = $user_entry->get_value('sambaAcctFlags');
            if ( defined $flags and $flags =~ /X/ ) {
                my $letters;
                if ( $flags =~ /(\w+)/ ) {
                    $letters = $1;
                }
                $letters =~ s/X//;
                $_sambaAcctFlags = "\[$letters\]";
                push( @mods, 'sambaAcctFlags' => $_sambaAcctFlags );
            }
	    push(@mods, 'sambaPwdLastSet' => 0);
	    push(@mods, 'sambaPwdMustChange' => 0);
        }
        else {
	    push(@mods, 'sambaPwdLastSet' => time);
	    push(@mods, 'sambaPwdMustChange' => $winmagic);
        }
    }
    else {
        print "User $user is not a samba user\n";
    }
}

if ( defined( $tmp = $Options{'C'} ) ) {
    if ( $samba == 1 ) {
        if ( $tmp eq "" and defined $user_entry->get_value('sambaHomePath') ) {
            push( @dels, 'sambaHomePath' => [] );
        }
        elsif ( $tmp ne "" ) {
            push( @mods, 'sambaHomePath' => $tmp );
        }
    }
    else {
        print "User $user is not a samba user\n";
    }
}

if ( defined( $tmp = $Options{'D'} ) ) {
    if ( $samba == 1 ) {
        if ( $tmp eq "" and defined $user_entry->get_value('sambaHomeDrive') ) {
            push( @dels, 'sambaHomeDrive' => [] );
        }
        elsif ( $tmp ne "" ) {
            $tmp = $tmp . ":" unless ( $tmp =~ /:/ );
            push( @mods, 'sambaHomeDrive' => $tmp );
        }
    }
    else {
        print "User $user is not a samba user\n";
    }
}

if ( defined( $tmp = $Options{'E'} ) ) {
    if ( $samba == 1 ) {
        if ( $tmp eq "" and defined $user_entry->get_value('sambaLogonScript') )
        {
            push( @dels, 'sambaLogonScript' => [] );
        }
        elsif ( $tmp ne "" ) {
            push( @mods, 'sambaLogonScript' => $tmp );
        }
    }
    else {
        print "User $user is not a samba user\n";
    }
}

if ( defined( $tmp = $Options{'F'} ) ) {
    if ( $samba == 1 ) {
        if ( $tmp eq "" and defined $user_entry->get_value('sambaProfilePath') )
        {
            push( @dels, 'sambaProfilePath' => [] );
        }
        elsif ( $tmp ne "" ) {
            push( @mods, 'sambaProfilePath' => $tmp );
        }
    }
    else {
        print "User $user is not a samba user\n";
    }
}

if ( $samba == 1
    and
    ( defined $Options{'H'} or defined $Options{'I'} or defined $Options{'J'} )
  )
{
    my $_sambaAcctFlags;
    if ( defined( $tmp = $Options{'H'} ) ) {

        #$tmp =~ s/\\/\\\\/g;
        $_sambaAcctFlags = $tmp;
    }
    else {

        # I or J
        my $flags;
        $flags = $user_entry->get_value('sambaAcctFlags');

        if ( defined( $tmp = $Options{'I'} ) ) {
            if ( !( $flags =~ /D/ ) ) {
                my $letters;
                if ( $flags =~ /(\w+)/ ) {
                    $letters = $1;
                }
                $_sambaAcctFlags = "\[D$letters\]";
            }
        }
        elsif ( defined( $tmp = $Options{'J'} ) ) {
            if ( $flags =~ /D/ ) {
                my $letters;
                if ( $flags =~ /(\w+)/ ) {
                    $letters = $1;
                }
                $letters =~ s/D//;
                $_sambaAcctFlags = "\[$letters\]";
            }
        }
    }

    if ( $_sambaAcctFlags and "$_sambaAcctFlags" ne '' ) {
        push( @mods, 'sambaAcctFlags' => $_sambaAcctFlags );
        my $date = time;
        push( @mods, 'sambaPwdLastSet' => $date );
    }

}
elsif ( !$samba == 1
    and
    ( defined $Options{'H'} or defined $Options{'I'} or defined $Options{'J'} )
  )
{
    print "User $user is not a samba user\n";
}

if ( defined( $tmp = $Options{'Z'} ) ) {
    my %mods;
    for my $pair ( map { split /,/ } @{$Options{'Z'}} ) {
	my ( $name, $value ) = split( /[=:]/, $pair, 2 );
	$name = lc( $name );
	if ( defined($value) ) {
	    if ( $name =~ s/^([\+\-])// ) {
		my $action = $1;
		my @value_old = $mods{$name}
		    ? @{$mods{$name}}
		    : $user_entry->get_value($name);
		my @value = ($action eq '+')
		    ? list_union( \@value_old, [$value] )
		    : list_minus( \@value_old, [$value] );
		$mods{$name} = \@value;
	    } else {
		push( @{$mods{$name}}, $value );
	    }
	} elsif ( $name =~ s/^-// ) {
	    $mods{$name} = [];
	}
    }

    while ( my ($name, $value) = each( %mods ) ) {
	push( @mods, $name => $value );
    }
}

# apply changes
my $modify = $ldap_master->modify( "$dn", 'replace' => {@mods} );
$modify->code && warn "failed to modify entry: ", $modify->error;

# we can delete only if @dels is not empty: we check the number of elements
my $nb_to_del = scalar(@dels);
if ( $nb_to_del != 0 ) {
    $modify = $ldap_master->modify( "$dn", 'delete' => {@dels} );

    # don't proceed on error
    $modify->code && die "failed to modify entry: ", $modify->error;
}

if (defined(my $ou_rdn_hier = $Options{'ou'})) {
    my @ou_rdn_hier = split(/,/, $ou_rdn_hier);
    ## "foo,bar" -> "ou=foo,ou=bar"
    for my $ou_rdn (@ou_rdn_hier) {
	$ou_rdn = "ou=$ou_rdn" if ($ou_rdn !~ /^\w+=/);
    }

    my $dn = utf8Decode($characterSet,$user_entry->dn);
    my ($rdn, $superior) = split(",", $dn, 2);
    my $suffix = ($rdn =~ /\$$/) ?  $config{computersdn} : $config{usersdn};

    my $rdn_new = $rdn; ## FIXME: Merge --rename=newname option
    my $dn_new = join(",", $rdn_new, @ou_rdn_hier, $suffix);

    if (lc($dn_new) ne lc($dn)) { ## FIXME: Use Unicode::Normalize::NFC() instaed of lc()
	my $superior_new= $suffix;
	for my $ou_rdn (reverse(@ou_rdn_hier)) {
	    my $superior_new_superior = $superior_new;
	    $superior_new = "$ou_rdn,$superior_new";
	    my $mesg = $ldap_master->search(
		base   => utf8Encode($characterSet,$superior_new_superior),
		scope  => "one",
		filter => "(&(objectClass=organizationalUnit)(".utf8Encode($characterSet,$ou_rdn)."))",
	    );
	    $mesg->code && die "Faild to search: $ou_rdn: ", $mesg->error;
	    next if ($mesg->count ne 0);

	    print "$superior_new does not exist. Creating it (Y/[N]) ? ";
	    chomp(my $answ = <STDIN>);
	    unless ($answ eq "y" || $answ eq "Y") {
		print "exiting.\n";
		exit(1);
	    }

	    # add organizational unit
	    my $ou = $ou_rdn;
	    $ou =~ s/^.*=//;
	    my $add = $ldap_master->add(
		utf8Encode($characterSet,$superior_new),
		attr => [
		    'objectclass' => 'organizationalUnit',
		    'ou'          => utf8Encode($characterSet,$ou),
		]
	    );
	    $add->code && die "Failed to add entry: $superior_new: ", $add->error;
	    print "$superior_new created\n";
	}

	my $modify = $ldap_master->moddn(
	    utf8Encode($characterSet,$dn),
	    newrdn       => $rdn_new,
	    newsuperior  => utf8Encode($characterSet,$superior_new),
	    deleteoldrdn => 1,
	);
	$modify->code && die "Failed to modify DN: $dn -> $dn_new: ", $modify->error;

	# Re-read user entry
	$user_entry = read_user_entry($user);
    }
}

# asked to rename the account. only do that if new rdn doesn't equal old one
if ( defined( my $new_user = $Options{'r'} ) and $Options{'r'} ne $user ) {
    my $ldap_master = connect_ldap_master();
    chomp($new_user);

    # read eventual new user entry
    my $new_user_entry = read_user_entry($new_user);
    if ( defined($new_user_entry) ) {
        print "$0: user $new_user already exists, cannot rename\n";
        exit(8);
    }

    # we check the real dn as it could be a user or computer account
    $dn = $user_entry->dn;
    my $computer;
    my ( $account, $rdn ) = ( $dn =~ m/([^,])*,(.*)$/ );
    if ( $account =~ m/(.*)\$/ ) {

        # it's a computer account
        $computer = 1;
        my $modify = $ldap_master->moddn(
            "uid=$user,$rdn",
            newrdn       => "uid=$new_user",
            deleteoldrdn => "1",
            newsuperior  => "$rdn"
        );

    }
    else {
        my $modify = $ldap_master->moddn(
            "uid=$user,$rdn",
            newrdn       => "uid=$new_user",
            deleteoldrdn => "1",
            newsuperior  => "$rdn"
        );
    }
    $modify->code && die "failed to change dn: ", $modify->error;

    # change cn, sn, displayName, givenName attributes
    my $user_entry = read_user_entry($new_user);
    my $dn         = $user_entry->dn();
    my @mods;

# If old sn is not old username (which would be the default) we assume that there is a surename that is correctly set
# so no change is required here. If they equal, we use the new username for new sn unless
# -S option is used (the sn value would have been set/updated before in that case).
    push( @mods, 'sn' => $new_user )
      unless ( $user_entry->get_value('sn')
        and $user_entry->get_value('sn') ne $user or $Options{'S'} );

# If old givenName is not old username (which would be the default) we assume that there is a
# givenName correctly set so no change is required here. If they equal, we set givenName to the new username unless
# the -N option is used (the givenName would have been set/updated before in that case).
    push( @mods, 'givenName' => $new_user )
      unless ( $user_entry->get_value('givenName')
        and $user_entry->get_value('givenName') ne $new_user or $Options{'N'} );

# common name, should be "fistname lastname". Same for displayName but only if $samba.
# Uses utf8Encode like processing of options -S and -N above. If old cn is old username
# (which would be the default) this field should be updated, unless -N _and_ -S is given.
# Then assume it has been set correctly with -N and -S before.
    push( @mods, "cn" => $new_user )
      unless ( $user_entry->get_value("cn")
        and $user_entry->get_value("cn") ne utf8Encode($characterSet,$user)
        or $Options{'N'} and $Options{'S'} );
    push( @mods, "displayName" => $new_user )
      unless ( not $samba
        or $user_entry->get_value("displayName")
        and $user_entry->get_value("displayName") ne utf8Encode($characterSet,$user)
        or $Options{'N'} and $Options{'S'} );

    if ( @mods > 0 ) {    # only change if there is something to change
        $modify =
          $ldap_master->modify( "$dn", changes => [ 'replace' => [@mods] ] );
        $modify->code && warn "failed to rename the user: ", $modify->error;
    }

    # changing username in groups
    my @groups = &find_groups_of($user);
    foreach my $gname (@groups) {
        if ( $gname ne "" ) {
            my $dn_line = get_group_dn($gname);
            my $dn      = get_dn_from_line("$dn_line");
            print "updating group $gname\n";
            $modify = $ldap_master->modify(
                "$dn",
                changes => [
                    'delete' => [ memberUid => $user ],
                    'add'    => [ memberUid => $new_user ]
                ]
            );
            $modify->code
              && warn "failed to update user's supplementary group $gname: ",
              $modify->error;
        }
    }
}

$ldap_master->unbind;
nsc_invalidate("passwd");

if ( defined( $Options{'P'} ) ) {
    exec "$RealBin/smbldap-passwd $user";
}

############################################################

=head1 NAME

smbldap-usermod - Modify a user account

=head1 SYNOPSIS

smbldap-usermod [-c gecos] [-d home_dir] [-r login_name] [-u uid] [-g gid] [-o] [-G group[,...]] [-s shell] [-N first_name] [-S surname] [-P] [-M mail[,...]] [-T mail,[..]] [--shadowExpire date/n] [--shadowMax n] [--shadowMin n] [--shadowInactive n] [--shadowWarning n] [-L] [-U] [-a] [-e expiration_date/n] [--sambaExpire date/n] [-A canchange] [-B mustchange] [-C smbhome] [-D homedrive] [-E scriptpath] [-F profilepath] [-H acctflags] [-I] [-J] [-h] login

=head1 DESCRIPTION

The smbldap-usermod  command  modifies the system account files to reflect the changes that are specified
on the  command  line.

=head2 UNIX options

-c, --gecos gecos
    The new value of the user's comment field (gecos). (Don't use this to modify displayName or cn. Use -N and -S options combined instead).

-d, --homedir home_dir
    The user's new login directory.

-r, --rename new_user
    Allow to rename a user. This option will update the dn attribute for the user. You can also update others attributes using the corresponding script options.

-u, --uid uid
    The numerical  value  of  the  user's  ID.   This value must be unique, unless the -o option is used.  The value must  be  non negative.  Any files which the user owns  and  which  are located  in  the directory tree rooted at the user's home directory will have the file user ID  changed  automatically.   Files outside of the user's home directory must be altered manually.

-o, --canBeNotUnique
    uidNumber can be non unique

-g, --gid initial_group
    The group name or number of the user's new initial login  group. The  group  name  must  exist. A group number must refer to an already existing group.  The default group number is 1.

-G, --group [+-]group,[...]
    A list of supplementary groups which the user is also  a  member of.   Each  group is separated from the next by a comma, with no intervening whitespace.  The groups  are  subject  to  the  same restrictions as the group given with the -g option.  If the user is currently a member of a group which is not listed, the user will be removed from the group, unless the '+' or '-' caracter is used to add or remove groups to inital ones.

-s, --shel shell
    The name of the user's new login shell.  Setting this  field  to blank causes the system to select the default
    login shell.

-N, --givenName
    set the user's given name (attribute givenName). Additionally used to set the first name in displayName and cn.

-S, --surname
    Set the user's surname (attribute sn). Additionally used to set the last name in displayName and cn.

-P
    End by invoking smbldap-passwd to change the user password (both unix and samba passwords)

-M, --mailAddresses  mail,[...]
    mailAddresses (comma seperated)

-T, --mailToAddress  mail,[...]
    mailToAddress (forward address) (comma seperated)

--shadowExpire <YYYY-MM-DD/n>
    Set the expiration date for the user password. This only affect unix account. The date may be specified as either YYYY-MM-DD or 'n' days from day. The 'n' syntax also supports the extended format (#y)(#m)(#d) for years, months, and days from today. One need not specify all three, so all of the following are examples of valid input: '5y4m2d' (5 years, 4 months, and 2 days), '5y' (5 years), '5y2d' (5 years and 2 days), and '3' (3 days). This option calls the internal 'timelocal' command to set calculate the number of seconds from Junary 1 1970 to the specified date.
 
--shadowMax <n>
    User must change the password, at least, every 'n' days

--shadowMin <n>
    User must wait 'n' days once the password has changed before changing it again

--shadowInactive <n>
    Number of days of inactivity allowed for the specified user

--shadowWarning <n>
    User is warned that the password must be changed four days before the password expires

-L, --shadowLock
    Lock unix user's password. This puts a '!' in front of the encrypted password, effectively disabling the password.

-U, --shadowUnlock
    Unlock unix user's password. This removes the '!' in front of the encrypted password.

=head2 SAMBA options

-a, --addsambaSAMAccount
    Add the sambaSAMAccount objectclass to the specified user account. This allow the user to become a samba user.

-e, --expire <YYYY-MM-DD(HH:MM:SS)/n>
    Sets the expiration for both samba (--sambaExpire) and shadow (--shadowExpire).

--ou node
    The user's account will be moved to the specified organazional unit. It is relative to the user suffix dn ($usersdn) defined in the configuration file.
    Ex: 'ou=admin,ou=all'

--sambaExpire <YYYY-MM-DD HH:MM:SS/n>
    Set the expiration date for the user account. This only affects the samba account. The date must be in the following format: YYYY-MM-DD HH:MM:SS. The n-days format of shadowExpire is also supported. This option uses the internal 'timelocal' command to set calculate the number of seconds from Junary 1 1970 to the specified date.

-A, --sambaPwdCanChange
    can change password ? 0 if no, 1 if yes

-B, --sambaPwdMustChange
    must change password ? 0 if no, 1 if yes

-C, --sambaHomePath path
    sambaHomePath (SMB home share, like '\\\\PDC-SRV\\homes')

-D, --sambaHomeDrive drive
    sambaHomeDrive (letter associated with home share, like 'H:')

-E, --sambaLogonScript script
    sambaLogonScript, relative to the [netlogon] share (DOS script to execute on login, like 'foo.bat')

-F, --sambaProfilePath path
    sambaProfilePath (profile directory, like '\\\\PDC-SRV\\profiles\\foo')

-H, --sambaAcctFlags flags
    sambaAcctFlags, spaces and trailing bracket are ignored (samba account control bits like '[NDHTUMWSLKI]')

-I, --sambaDisable
    disable user. Can't be used with -H or -J

-J, --sambaEnable
    enable user. Can't be used with -H or -I

-h, --help
    print this help

=head1 SEE ALSO

usermod(1)

=cut

#'
