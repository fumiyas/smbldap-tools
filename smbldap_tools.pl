#!@PERL_CMD@

# $Id$

#  This code was developped by Jerome Tournier (jtournier@gmail.com) and
#  contributors (their names can be found in the CONTRIBUTORS file).

#  This was first contributed by IDEALX (http://www.opentrust.com/)
#
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

use strict;
use warnings;

package smbldap_tools;
use Encode;
use POSIX qw(:termios_h);
use IO::File;
use Net::LDAP;
use Net::LDAP::Extension::SetPassword;
use Crypt::SmbHash;
use Digest::MD5 qw(md5);
use Digest::SHA1 qw(sha1);
use MIME::Base64 qw(encode_base64);

use constant true => 1;
use constant false => 0;

my %conf_renamed_by = (
    password_hash =>			'hash_encrypt',
    password_crypt_salt_format =>	'crypt_salt_format',
);

my $smbldap_conf =
    $ENV{'SMBLDAP_CONF'} ||
    '@sysconfdir@/smbldap.conf';
my $smbldap_bind_conf =
    $ENV{'SMBLDAP_BIND_CONF'} ||
    '@sysconfdir@/smbldap_bind.conf';
my $samba_conf =
    $ENV{'SMBLDAP_SMB_CONF'} ||
    $ENV{'SMB_CONF_PATH'} ||
    '@SAMBA_SYSCONFDIR@/smb.conf';

use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
use Exporter;
$VERSION = 1.00;

@ISA = qw(Exporter);
use vars qw(%config $ldap);

@EXPORT = qw(
  get_user_dn
  get_group_dn
  is_group_member
  is_samba_user
  is_unix_user
  is_nonldap_unix_user
  is_user_valid
  does_sid_exist
  get_dn_from_line
  add_posix_machine
  add_samba_machine
  add_samba_machine_smbpasswd
  group_add_user
  add_grouplist_user
  disable_user
  delete_user
  group_add
  group_del
  get_homedir
  read_user
  read_user_human_readable
  read_user_entry
  read_group
  read_group_entry
  read_group_entry_gid
  find_groups_of
  parse_group
  group_remove_member
  group_get_members
  get_user_dn2
  connect_ldap_master
  connect_ldap_slave
  group_name_by_type
  group_type_by_name
  subst_configvar
  read_conf
  read_parameter
  subst_user
  split_arg_comma
  list_union
  list_minus
  account_by_sid
  user_next_uid
  user_next_rid
  group_next_uid
  group_next_rid
  print_banner
  getDomainName
  getLocalSID
  utf8Encode
  utf8Decode
  password_read
  password_set
  shadow_update
  nsc_invalidate
  %config
);

sub print_banner {
    print STDERR
      "(c) Jerome Tournier - (jtournier\@gmail.com)- Licensed under the GPL\n"
      unless $config{no_banner};
}

sub read_parameter {
    my $line = shift;
    ## check for a param = value
    if ( $line =~ /=/ ) {
        my ( $param, $val );
        if ( $line =~ /\s*(.*?)\s*=\s*"(.*)"/ ) {
            ( $param, $val ) = ($1, $2);
        }
        elsif ( $line =~ /\s*(.*?)\s*=\s*'(.*)'/ ) {
            ( $param, $val ) = ($1, $2);
        }
        else {
            ( $param, $val ) = $line =~ /\s*(.*?)\s*=\s*(.*)/;
        }
        return ( $param, $val );
    }
}

sub subst_configvar {
    my $value = shift;
    my $vars  = shift;

    $value =~ s/\$\{([^}]+)\}/$vars->{$1} ? $vars->{$1} : $1/eg;
    return $value;
}

sub read_conf {
    my %conf;
    open( CONFIGFILE, "$smbldap_conf" )
      || die "Unable to open $smbldap_conf for reading !\n";
    while (<CONFIGFILE>) {
        chomp($_);
        ## throw away comments
        next if ( /^\s*#/ || /^\s*$/ || /^\s*\;/ );
        ## check for a param = value
        my ( $parameter, $value ) = read_parameter($_);
        $value = &subst_configvar( $value, \%conf );
        $conf{$parameter} = $value;
    }
    close(CONFIGFILE);

    if ( $< == 0 ) {
        open( CONFIGFILE, "$smbldap_bind_conf" )
          || die "Unable to open $smbldap_bind_conf for reading !\n";
        while (<CONFIGFILE>) {
            chomp($_);
            ## throw away comments
            next if ( /^\s*#/ || /^\s*$/ || /^\s*\;/ );
            ## check for a param = value
            my ( $parameter, $value ) = read_parameter($_);
            $value = &subst_configvar( $value, \%conf );
            $conf{$parameter} = $value;
        }
        close(CONFIGFILE);
    }
    else {
        $conf{slaveDN} = $conf{slavePw} = $conf{masterDN} = $conf{masterPw} =
          "";
    }

    while (my ($new, $old) = each(%conf_renamed_by)) {
	if (exists($conf{$old})) {
	    $conf{$new} = delete($conf{$old});
	}
    }

    # automatically find SID
    if ( not $conf{SID} ) {
        $conf{SID} = getLocalSID()
          || die
"Unable to determine domain SID: please edit your smbldap.conf, or start your samba server for a few minutes to allow for SID generation to proceed\n";
    }
    return (%conf);
}

sub read_smbconf {
    my %conf;
    my $smbconf = "$samba_conf";
    open( CONFIGFILE, "$smbconf" )
      || die "Unable to open $smbconf for reading !\n";
    my $global   = 0;
    my $prevline = "";
    while (<CONFIGFILE>) {
        chomp;
        if (/^(.*)\\$/) {
            $prevline .= $1;
            next;
        }
        $_        = $prevline . $_;
        $prevline = "";
        if (/^\[global\]/) {
            $global = 1;
        }
        if ( $global == 1 ) {
            if ( /^\[/ and !/\[global\]/ ) {
                $global = 0;
            }
            else {
                ## throw away comments
                #next if ( ! /workgroup/i );
                next if ( /^\s*#/ || /^\s*$/ || /^\s*\;/ || /\[/ );
                ## check for a param = value
                my ( $parameter, $value ) = read_parameter($_);
                $value = &subst_configvar( $value, \%conf );
                $conf{$parameter} = $value;
            }
        }
    }
    close(CONFIGFILE);
    return (%conf);
}
my %smbconf = read_smbconf();

sub getLocalSID {
    my $string =
`LANG= PATH=/opt/IDEALX/bin:/usr/local/bin:/usr/bin:/bin net getlocalsid 2>/dev/null`;
    my ( $domain, $sid ) = ( $string =~ m/^SID for domain (\S+) is: (\S+)$/ );

    return $sid;
}

# let's read the configurations file...
%config = (
    masterLDAP =>		'127.0.0.1',
    masterPort =>		389,
    slaveLDAP =>		'127.0.0.1',
    slavePort =>		389,
    ldapTLS =>			false,
    ldapSSL =>			false,
    password_hash =>		'SSHA',
    password_crypt_salt_format=>'%s',
    shadowAccount =>		true,
    nscd =>			"/usr/sbin/nscd",
    read_conf(),
);

sub get_parameter {

# this function return the value for a parameter. The name of the parameter can be either this
# defined in smb.conf or smbldap.conf
    my $parameter_smb     = shift;
    my $parameter_smbldap = shift;
    if ( defined $config{$parameter_smbldap}
        and $config{$parameter_smbldap} ne "" )
    {
        return $config{$parameter_smbldap};
    }
    elsif ( defined $smbconf{$parameter_smb}
        and $smbconf{$parameter_smb} ne "" )
    {
        return $smbconf{$parameter_smb};
    }
    else {

#print "could not find parameter's value (parameter given: $parameter_smbldap or $parameter_smb) !!\n";
        undef $smbconf{$parameter_smb};
    }

}

$config{sambaDomain} = get_parameter( "workgroup",        "sambaDomain" );
$config{suffix}      = get_parameter( "ldap suffix",      "suffix" );
$config{usersdn}     = get_parameter( "ldap user suffix", "usersdn" );
if ( $config{usersdn} !~ m/,/ ) {
    $config{usersdn} = $config{usersdn} . "," . $config{suffix};
}
$config{groupsdn} = get_parameter( "ldap group suffix", "groupsdn" );
if ( $config{groupsdn} !~ m/,/ ) {
    $config{groupsdn} = $config{groupsdn} . "," . $config{suffix};
}
$config{computersdn} = get_parameter( "ldap machine suffix", "computersdn" );
if ( $config{computersdn} !~ m/,/ ) {
    $config{computersdn} = $config{computersdn} . "," . $config{suffix};
}
$config{idmapdn} = get_parameter( "ldap idmap suffix", "idmapdn" );
if ( defined $config{idmapdn} ) {
    if ( $config{idmapdn} !~ m/,/ ) {
        $config{idmapdn} = $config{idmapdn} . "," . $config{suffix};
    }
}

# next uidNumber and gidNumber available are stored in sambaDomainName object
if ( !defined $config{sambaUnixIdPooldn} ) {
    $config{sambaUnixIdPooldn} =
      "sambaDomainName=$config{sambaDomain},$config{suffix}";
}
if ( $config{ldapSSL} == 1 and $config{ldapTLS} == 1 ) {
    die "Both options ldapSSL and ldapTLS could not be activated\n";
}

sub connect_ldap_master {
    my $mesg;

    # bind to a directory with dn and password
    my $ldap_master;
    if ( $config{ldapSSL} ) {
        $ldap_master = Net::LDAP->new(
            "ldaps://$config{masterLDAP}:$config{masterPort}",
            verify => "$config{verify}",
            cafile => "$config{cafile}"
        ) or die "LDAP error: Can't contact master ldap server with SSL ($@)";
    }
    else {
        $ldap_master = Net::LDAP->new(
            "$config{masterLDAP}",
            port    => "$config{masterPort}",
            version => 3,
            timeout => 60,

            # debug => 0xffff,
          )
          or die
          "erreur LDAP: Can't contact master ldap server for writing ($@)";
    }
    if ( $config{ldapTLS} == 1 ) {
        $mesg = $ldap_master->start_tls(
            verify     => "$config{verify}",
            clientcert => "$config{clientcert}",
            clientkey  => "$config{clientkey}",
            cafile     => "$config{cafile}"
        );
        if ( $mesg->code ) {
            die( "Could not start_tls: " . $mesg->error );
        }
    }
    $mesg = $ldap_master->bind( "$config{masterDN}",
        password => "$config{masterPw}" );
    $ldap = $ldap_master;
    return ($ldap_master);
}

sub connect_ldap_slave {
    my $mesg;
    my $conf_cert;
    my $ldap_slave;
    if ( $config{ldapSSL} == 1 ) {
        $ldap_slave = Net::LDAP->new(
            "ldaps://$config{slaveLDAP}:$config{slavePort}",
            verify => "$config{verify}",
            cafile => "$config{cafile}"
          )
          or warn
"LDAP error: Can't contact slave ldap server with SSL ($@)\n=>trying to contact the master server\n";
    }
    else {
        $ldap_slave = Net::LDAP->new(
            "$config{slaveLDAP}",
            port    => "$config{slavePort}",
            version => 3,
            timeout => 60,

            # debug => 0xffff,
          )
          or warn
"erreur LDAP: Can't contact slave ldap server ($@)\n=>trying to contact the master server\n";
    }
    if ( !$ldap_slave ) {

        # connection to the slave failed: trying to contact the master ...
        $ldap_slave      = connect_ldap_master();
        $config{slaveDN} = $config{masterDN};
        $config{slavePw} = $config{masterPw};
    }
    elsif ( $config{ldapTLS} == 1 ) {
        $mesg = $ldap_slave->start_tls(
            verify     => "$config{verify}",
            clientcert => "$config{clientcert}",
            clientkey  => "$config{clientkey}",
            cafile     => "$config{cafile}"
        );
        if ( $mesg->code ) {
            die( "Could not start_tls: " . $mesg->error );
        }
    }
    $ldap_slave->bind( "$config{slaveDN}", password => "$config{slavePw}" );
    $ldap = $ldap_slave;
    return ($ldap_slave);
}

sub get_user_dn {
    my $user = shift;
    my $dn   = '';
    my $mesg = $ldap->search(
        base   => $config{suffix},
        scope  => $config{scope},
        filter => "(&(objectclass=posixAccount)(uid=$user))"
    );
    $mesg->code && die $mesg->error;
    foreach my $entry ( $mesg->all_entries ) {
        $dn = $entry->dn;
    }
    chomp($dn);
    if ( $dn eq '' ) {
        return undef;
    }
    $dn = "dn: " . $dn;
    return $dn;
}

sub get_user_dn2 {
    my $user = shift;
    my $dn   = '';
    my $mesg = $ldap->search(
        base   => $config{suffix},
        scope  => $config{scope},
        filter => "(&(objectclass=posixAccount)(uid=$user))"
    );
    $mesg->code && warn "failed to perform search; ", $mesg->error;

    foreach my $entry ( $mesg->all_entries ) {
        $dn = $entry->dn;
    }
    chomp($dn);
    if ( $dn eq '' ) {
        return ( 1, undef );
    }
    $dn = "dn: " . $dn;
    return ( 1, $dn );
}

sub get_group_dn {
    my $group = shift;
    my $dn    = '';
    my $filter;
    if ( $group =~ /^\d+$/ ) {
        $filter = "(&(objectclass=posixGroup)(|(cn=$group)(gidNumber=$group)))";
    }
    else {
        $filter = "(&(objectclass=posixGroup)(cn=$group))";
    }
    my $mesg = $ldap->search(
        base   => $config{groupsdn},
        scope  => $config{scope},
        filter => $filter
    );
    $mesg->code && die $mesg->error;
    foreach my $entry ( $mesg->all_entries ) {
        $dn = $entry->dn;
    }
    chomp($dn);
    if ( $dn eq '' ) {
        return undef;
    }
    $dn = "dn: " . $dn;
    return $dn;
}

# return (success, dn)
# bool = is_samba_user($username)
sub is_samba_user {
    my $user = shift;
    my $mesg = $ldap->search(
        base   => $config{suffix},
        scope  => $config{scope},
        filter => "(&(objectClass=sambaSamAccount)(uid=$user))"
    );
    $mesg->code && die $mesg->error;
    return ( $mesg->count ne 0 );
}

sub is_unix_user {
    my $user = shift;
    my $mesg = $ldap->search(
        base   => $config{suffix},
        scope  => $config{scope},
        filter => "(&(objectClass=posixAccount)(uid=$user))"
    );
    $mesg->code && die $mesg->error;
    return ( $mesg->count ne 0 );
}

sub is_nonldap_unix_user {
    my $user = shift;
    my $uid  = getpwnam($user);

    if ($uid) {
        return 1;
    }
    else {
        return 0;
    }
}

sub is_group_member {
    my $dn_group = shift;
    my $user     = shift;
    my $mesg     = $ldap->search(
        base   => $dn_group,
        scope  => 'base',
        filter => "(&(memberUid=$user))"
    );
    $mesg->code && die $mesg->error;
    return ( $mesg->count ne 0 );
}

# all entries = does_sid_exist($sid,$config{scope})
sub does_sid_exist {
    my $sid      = shift;
    my $dn_group = shift;
    my $mesg     = $ldap->search(
        base   => $dn_group,
        scope  => $config{scope},
        filter => "(sambaSID=$sid)"
    );
    $mesg->code && die $mesg->error;
    return ($mesg);
}

# try to bind with user dn and password to validate current password
sub is_user_valid {
    my ( $user, $dn, $pass ) = @_;
    my $userLdap = Net::LDAP->new(
        "$config{slaveLDAP}",
        port    => "$config{slavePort}",
        version => 3,
        timeout => 60
      )
      or warn
"erreur LDAP: Can't contact slave ldap server ($@)\n=>trying to contact the master server\n";
    if ( !$userLdap ) {

        # connection to the slave failed: trying to contact the master ...
        $userLdap = Net::LDAP->new(
            "$config{masterLDAP}",
            port    => "$config{masterPort}",
            version => 3,
            timeout => 60
        ) or die "erreur LDAP: Can't contact master ldap server ($@)\n";
    }
    if ($userLdap) {
        if ( $config{ldapTLS} == 1 ) {
            $userLdap->start_tls(
                verify     => "$config{verify}",
                clientcert => "$config{clientcert}",
                clientkey  => "$config{clientkey}",
                cafile     => "$config{cafile}"
            );
        }
        my $mesg = $userLdap->bind( dn => $dn, password => $pass );
        if ( $mesg->code eq 0 ) {
            $userLdap->unbind;
            return 1;
        }
        else {
            if ( $userLdap->bind() ) {
                $userLdap->unbind;
                return 0;
            }
            else {
                print(
"The LDAP directory is not available.\n Check the server, cables ..."
                );
                $userLdap->unbind;
                return 0;
            }
            die "Problem : contact your administrator";
        }
    }
}

# dn = get_dn_from_line ($dn_line)
# helper to get "a=b,c=d" from "dn: a=b,c=d"
sub get_dn_from_line {
    my $dn = shift;
    $dn =~ s/^dn: //;
    return $dn;
}

# success = add_posix_machine($user, $uid, $gid)
sub add_posix_machine {
    my ( $user, $uid, $gid, $wait ) = @_;
    if ( !defined $wait ) {
        $wait = 0;
    }

    # bind to a directory with dn and password
    my $add = $ldap->add(
        "uid=$user,$config{computersdn}",
        attr => [

#'objectclass' => ['top', 'person', 'organizationalPerson', 'inetOrgPerson', 'posixAccount'],
            'objectclass' => [ 'top', 'account', 'posixAccount' ],
            'cn'          => "$user",

            #'sn'   => "$user",
            'uid'           => "$user",
            'uidNumber'     => "$uid",
            'gidNumber'     => "$gid",
            'homeDirectory' => '/nonexistent',
            'loginShell'    => '/bin/false',
            'description'   => 'Computer',
            'gecos'         => 'Computer',
        ]
    );

    $add->code && warn "failed to add entry: ", $add->error;
    sleep($wait);
    return 1;
}

# success = add_samba_machine_smbpasswd($computername)
sub add_samba_machine_smbpasswd {
    my $user = shift;
    system($config{smbpasswd}, "-a", "-m", $user);
    return 1;
}

sub add_samba_machine {
    my ( $user, $uid ) = @_;
    my $sambaSID = 2 * $uid + 1000;
    my $name     = $user;
    $name =~ s/.$//s;

    my ( $lmpassword, $ntpassword ) = ntlmgen $name;
    my $modify = $ldap->modify(
        "uid=$user,$config{computersdn}",
        changes => [

#replace => [objectClass => ['inetOrgPerson', 'posixAccount', 'sambaSAMAccount']],
            replace => [ objectClass => [ 'posixAccount', 'sambaSAMAccount' ] ],
            add => [ sambaPwdLastSet      => '0' ],
            add => [ sambaLogonTime       => '0' ],
            add => [ sambaLogoffTime      => '2147483647' ],
            add => [ sambaKickoffTime     => '2147483647' ],
            add => [ sambaPwdCanChange    => '0' ],
            add => [ sambaPwdMustChange   => '0' ],
            add => [ sambaAcctFlags       => '[W          ]' ],
            add => [ sambaLMPassword      => "$lmpassword" ],
            add => [ sambaNTPassword      => "$ntpassword" ],
            add => [ sambaSID             => "$config{SID}-$sambaSID" ],
            add => [ sambaPrimaryGroupSID => "$config{SID}-0" ]
        ]
    );

    $modify->code && die "failed to add entry: ", $modify->error;

    return 1;
}

sub group_add_user {
    my ( $group, $userid ) = @_;
    my $members = '';
    my $dn_line = get_group_dn($group);
    if ( !defined( get_group_dn($group) ) ) {
        print "$0: group \"$group\" doesn't exist\n";
        exit(6);
    }
    if ( !defined($dn_line) ) {
        return 1;
    }
    my $dn = get_dn_from_line("$dn_line");

    # on look if the user is already present in the group
    my $is_member = is_group_member( $dn, $userid );
    if ( $is_member == 1 ) {
        print "User \"$userid\" already member of the group \"$group\".\n";
    }
    else {

     # bind to a directory with dn and password
     # It does not matter if the user already exist, Net::LDAP will add the user
     # if he does not exist, and ignore him if his already in the directory.
        my $modify =
          $ldap->modify( "$dn",
            changes => [ add => [ memberUid => $userid ] ] );
        $modify->code && die "failed to modify entry: ", $modify->error;
    }
}

sub group_del {
    my $group_dn = shift;

    # bind to a directory with dn and password
    my $modify = $ldap->delete($group_dn);
    $modify->code && die "failed to delete group : ", $modify->error;
}

sub add_grouplist_user {
    my ( $grouplist, $user ) = @_;
    my @array = split( /,/, $grouplist );
    foreach my $group (@array) {
        group_add_user( $group, $user );
    }
}

sub disable_user {
    my $user = shift;
    my $dn_line;
    my $dn = get_dn_from_line($dn_line);

    if ( !defined( $dn_line = get_user_dn($user) ) ) {
        print "$0: user $user doesn't exist\n";
        exit(10);
    }
    my $modify =
      $ldap->modify( "$dn",
        changes => [ replace => [ userPassword => '{crypt}!x' ] ] );
    $modify->code && die "failed to modify entry: ", $modify->error;

    if ( is_samba_user($user) ) {
        my $modify =
          $ldap->modify( "$dn",
            changes => [ replace => [ sambaAcctFlags => '[D       ]' ] ] );
        $modify->code && die "failed to modify entry: ", $modify->error;
    }
}

# delete_user($user)
sub delete_user {
    my $user = shift;
    my $dn_line;

    if ( !defined( $dn_line = get_user_dn($user) ) ) {
        print "$0: user $user doesn't exist\n";
        exit(10);
    }
    my $dn     = get_dn_from_line($dn_line);
    my $modify = $ldap->delete($dn);
    $modify->code && die "failed to delete entry: ", $modify->error;
}

# $gid = group_add($groupname, $group_gid, $force_using_existing_gid)
sub group_add {
    my ( $gname, $gid, $force ) = @_;

    nsc_invalidate("group");

    if ( !defined($gid) ) {
        $gid = group_next_gid();
    }
    else {
        if ( !defined($force) ) {
            if ( defined( getgrgid($gid) ) ) {
                return undef;
            }
        }
    }
    my $modify = $ldap->add(
        "cn=$gname,$config{groupsdn}",
        attrs => [
            objectClass => [ 'top', 'posixGroup' ],
            cn          => "$gname",
            gidNumber   => "$gid"
        ]
    );

    $modify->code && die "failed to add entry: ", $modify->error;
    return $gid;
}

# $homedir = get_homedir ($user)
sub get_homedir {
    my $user    = shift;
    my $homeDir = '';
    my $entry;
    my $mesg = $ldap->search(
        base   => $config{usersdn},
        scope  => $config{scope},
        filter => "(&(objectclass=posixAccount)(uid=$user))"
    );
    $mesg->code && die $mesg->error;

    my $nb = $mesg->count;
    if ( $nb > 1 ) {
        print "Aborting: there are $nb existing user named $user\n";
        foreach $entry ( $mesg->all_entries ) {
            my $dn = $entry->dn;
            print "  $dn\n";
        }
        exit(4);
    }
    else {
        $entry   = $mesg->shift_entry();
        $homeDir = $entry->get_value("homeDirectory");
    }

    chomp $homeDir;
    if ( $homeDir eq '' ) {
        return undef;
    }
    return $homeDir;
}

# search for an user
sub read_user {
    my $user  = shift;
    my $lines = '';
    my $mesg  = $ldap->search(    # perform a search
        base   => $config{suffix},
        scope  => $config{scope},
        filter => "(&(objectclass=posixAccount)(uid=$user))"
    );

    $mesg->code && die $mesg->error;
    foreach my $entry ( $mesg->all_entries ) {
        $lines .= "dn: " . $entry->dn . "\n";
        foreach my $attr ( $entry->attributes ) {
            my @vals = $entry->get_value($attr);
#	    my $val_utf8 = eval {
#		Encode::decode_utf8($val, Encode::FB_CROAK);
#	    };
#	    $val = "**UNPRINTABLE**" if ($@ || $val_utf8 =~ /\P{IsPrint}/);
            $lines .= $attr . ": " . join( ',', @vals ) . "\n";
        }
    }
    chomp $lines;
    if ( $lines eq '' ) {
        return undef;
    }
    return $lines;
}

# search for an user and print in a human readable format
sub read_user_human_readable {
    my $user  = shift;
    my $lines = '';
    my $mesg  = $ldap->search(    # perform a search
        base   => $config{suffix},
        scope  => $config{scope},
        filter => "(&(objectclass=posixAccount)(uid=$user))"
    );

    $mesg->code && die $mesg->error;
    foreach my $entry ( $mesg->all_entries ) {
        $lines .= "dn: " . $entry->dn . "\n";
        foreach my $attr ( $entry->attributes ) {
            my @vals = $entry->get_value($attr);
            foreach my $val (@vals) {
		my $val_utf8 = eval {
		    Encode::decode_utf8($val, Encode::FB_CROAK);
		};
		$val = "**UNPRINTABLE**" if ($@ || $val_utf8 =~ /\P{IsPrint}/);
            }
            if (   $attr eq "sambaPwdLastSet"
                or $attr eq "sambaPwdCanChange"
                or $attr eq "sambaPwdMustChange"
                or $attr eq "sambaLogoffTime"
                or $attr eq "sambaKickoffTime" )
            {
                my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday ) =
                  gmtime( $entry->get_value($attr) );
                $year += 1900;
                $mon  += 1;
                $lines .= $attr . ": $year/$mon/$mday\n";
            }
            elsif ( $attr eq "shadowLastChange" or $attr eq "shadowExpire" ) {
                my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday ) =
                  gmtime( $entry->get_value($attr) * 24 * 60 * 60 );
                $year += 1900;
                $mon  += 1;
                $lines .= $attr . ": $year/$mon/$mday\n";
            }
            else {
                $lines .= $attr . ": " . join( ',', @vals ) . "\n";
            }
        }
    }
    chomp $lines;
    if ( $lines eq '' ) {
        return undef;
    }
    return $lines;
}

# search for a user
# return the attributes in an array
sub read_user_entry {
    my $user = shift;
    my $mesg = $ldap->search(    # perform a search
        base   => $config{suffix},
        scope  => $config{scope},
        filter => "(&(objectclass=posixAccount)(uid=$user))"
    );

    $mesg->code && die $mesg->error;
    my $entry = $mesg->entry();
    return $entry;
}

# search for a group
sub read_group {
    my $user  = shift;
    my $lines = '';
    my $mesg  = $ldap->search(    # perform a search
        base   => $config{groupsdn},
        scope  => $config{scope},
        filter => "(&(objectclass=posixGroup)(cn=$user))"
    );

    $mesg->code && die $mesg->error;
    foreach my $entry ( $mesg->all_entries ) {
        $lines .= "dn: " . $entry->dn . "\n";
        foreach my $attr ( $entry->attributes ) {
            {
                $lines .=
                  $attr . ": " . join( ',', $entry->get_value($attr) ) . "\n";
            }
        }
    }
    chomp $lines;
    if ( $lines eq '' ) {
        return undef;
    }
    return $lines;
}

# find groups of a given user
##### MODIFIE ########
sub find_groups_of {
    my $user   = shift;
    my @groups = ();
    my $mesg   = $ldap->search(    # perform a search
        base   => $config{groupsdn},
        scope  => $config{scope},
        filter => "(&(objectclass=posixGroup)(memberuid=$user))"
    );
    $mesg->code && die $mesg->error;

    my $entry;
    while ( $entry = $mesg->shift_entry() ) {
        push( @groups, scalar( $entry->get_value('cn') ) );
    }
    return (@groups);
}

sub read_group_entry {
    my $group = shift;
    my $entry;
    my %res;
    my $mesg = $ldap->search(    # perform a search
        base   => $config{groupsdn},
        scope  => $config{scope},
        filter => "(&(objectclass=posixGroup)(cn=$group))"
    );

    $mesg->code && die $mesg->error;
    my $nb = $mesg->count;
    if ( $nb > 1 ) {
        print "Error: $nb groups exist \"cn=$group\"\n";
        foreach $entry ( $mesg->all_entries ) {
            my $dn = $entry->dn;
            print "  $dn\n";
        }
        exit 11;
    }
    else {
        $entry = $mesg->shift_entry();
    }
    return $entry;
}

sub read_group_entry_gid {
    my $group = shift;
    my %res;
    my $mesg = $ldap->search(    # perform a search
        base   => $config{groupsdn},
        scope  => $config{scope},
        filter => "(&(objectclass=posixGroup)(gidNumber=$group))"
    );

    $mesg->code && die $mesg->error;
    my $entry = $mesg->shift_entry();
    return $entry;
}

# return the gidnumber for a group given as name or gid
# -1 : bad group name
# -2 : bad gidnumber
sub parse_group {
    my $userGidNumber = shift;
    if ( $userGidNumber =~ /[^\d]/ ) {

        # make a search based on the group name
        my $gname = $userGidNumber;
        my $mesg  = $ldap->search(    # perform a search
            base   => $config{groupsdn},
            scope  => $config{scope},
            filter => "(&(objectclass=posixGroup)(cn=$gname))"
        );
        $mesg->code && die $mesg->error;
        my $entry = $mesg->shift_entry();
        my $gidnum;
        if ($entry) {
            $gidnum = $entry->get_value('gidNumber');

            #my $gidnum = getgrnam($gname);
        }
        else {
            $gidnum = "";
        }
        if ( $gidnum !~ /\d+/ ) {
            return -1;
        }
        else {
            $userGidNumber = $gidnum;
        }
    }
    else {

        # make a search based on the group gidNumber
        # we check that the gidNumber is attributed to a real group
        my $mesg = $ldap->search(    # perform a search
            base   => $config{groupsdn},
            scope  => $config{scope},
            filter => "(&(objectclass=posixGroup)(gidNumber=$userGidNumber))"
        );
        $mesg->code && die $mesg->error;
        my $entry = $mesg->shift_entry();
        if ( !$entry ) {
            return -2;
        }
    }
    return $userGidNumber;
}

# remove $user from $group
sub group_remove_member {
    my ( $group, $user ) = @_;
    my $members  = '';
    my $grp_line = get_group_dn($group);
    if ( !defined($grp_line) ) {
        return 0;
    }
    my $dn = get_dn_from_line($grp_line);

    # we test if the user exist in the group
    my $is_member = is_group_member( $dn, $user );
    if ( $is_member == 1 ) {

        # delete only the user from the group
        my $modify =
          $ldap->modify( "$dn",
            changes => [ delete => [ memberUid => ["$user"] ] ] );
        $modify->code && die "failed to delete entry: ", $modify->error;
    }
    return 1;
}

sub group_get_members {
    my ($group) = @_;
    my $members;
    my @resultat;
    my $grp_line = get_group_dn($group);
    if ( !defined($grp_line) ) {
        return 0;
    }
    my $mesg = $ldap->search(
        base   => $config{groupsdn},
        scope  => $config{scope},
        filter => "(&(objectclass=posixgroup)(cn=$group))"
    );
    $mesg->code && die $mesg->error;
    foreach my $entry ( $mesg->all_entries ) {
        foreach my $attr ( $entry->attributes ) {
            if ( $attr =~ /\bmemberUid\b/ ) {
                foreach my $ent ( $entry->get_value($attr) ) {
                    push( @resultat, $ent );
                }
            }
        }
    }
    return @resultat;
}

sub group_name_by_type {
    my $groupmap = shift;
    my %type_name  = (
	2 => 'domain',
	4 => 'local',
	5 => 'builtin'
    );
    return $type_name{$groupmap};
}

sub group_type_by_name {
    my $type_name = shift;
    my %groupmap  = (
        'domain'  => 2,
        'local'   => 4,
        'builtin' => 5
    );
    return $groupmap{$type_name};
}

sub subst_user {
    my ( $str, $username ) = @_;
    $str =~ s/%U/$username/ if ($str);
    return ($str);
}

# all given mails are stored in a table (remove the comma separated)
sub split_arg_comma {
    my $arg = shift;
    my @args;
    if ( defined($arg) ) {
        if ( $arg eq '-' ) {
            @args = ();
        }
        else {
            @args = split( /\s*,\s*/, $arg );
        }
    }
    return (@args);
}

sub list_union {
    my ( $list1, $list2 ) = @_;
    my @res = @$list1;
    foreach my $e (@$list2) {
        if ( !grep( $_ eq $e, @$list1 ) ) {
            push( @res, $e );
        }
    }
    return @res;
}

sub list_minus {
    my ( $list1, $list2 ) = @_;
    my @res = ();
    foreach my $e (@$list1) {
        if ( !grep( $_ eq $e, @$list2 ) ) {
            push( @res, $e );
        }
    }
    return @res;
}

sub account_next_id
{
    my $attr = shift;
    my $domain = shift || $config{sambaDomain};
    my $checker = shift;

    my $base =  $config{sambaUnixIdPooldn};
    my $oc = "sambaUnixIdPool";
    my $filter = "(objectClass=sambaUnixIdPool)";
    my $scope = "base";
    my $id_bias = 0;
    if ($attr =~ /rid$/i) {
	$base = $config{suffix};
	$oc = "sambaDomain";
	$filter = "(&(objectClass=sambaDomain)(sambaDomainName=$domain))",
	$scope = "sub";
	## NOTE: sambaNextRid has "latest RID", not "next RID!
	$id_bias = 1;
    } else {
    }

    for (;;) {
	my $search = $ldap->search(
	    base   => $base,
	    filter => $filter,
	    scope  => $scope,
	    attrs => [$attr],
	);
	if ($search->code) {
	    die "Failed to search $oc to get next $attr: " .
		$search->error;
	}
	if ($search->count != 1) {
	    die "Failed to find $oc to get next $attr";
	}

	my $entry = $search->entry(0);
	my $id = $entry->get_value($attr);

	my $modify = $ldap->modify($entry->dn,
	    changes => [ replace => [ $attr=> $id + 1 ] ]
	);
	if ($modify->code) {
	    die "Failed to update $attr in $oc: " .
		$modify->error;
	}

	$id += $id_bias;
	unless ($checker && !$checker->($id)) {
	    return $id;
	}
    }
}

sub account_next_rid
{
    my $domain = shift || $config{sambaDomain};
    my $checker = shift || \&rid_is_free;

    return account_next_id("sambaNextRid", $domain, $checker);
}

sub account_base_rid
{
    my $domain = shift || $config{sambaDomain};

    my $search = $ldap->search(
	base   => $config{suffix},
	filter => "(&(objectClass=sambaDomain)(sambaDomainName=$domain))",
	scope  => "sub",
	attrs => ["sambaAlgorithmicRidBase", "sambaNextRid"],
    );
    if ($search->code) {
	die "Failed to search sambaDomain object to get sambaAlgorithmicRidBase: " .
	    $search->error;
    }
    if ($search->count != 1) {
	die "Failed to find sambaDomain object to get sambaAlgorithmicRidBase";
    }

    my $entry = $search->entry(0);
    my $rid_base = $entry->get_value("sambaAlgorithmicRidBase");
    if (!defined($rid_base) && !defined($entry->get_value("sambaNextRid"))) {
	return 1000;
    }

    return $rid_base;
}

sub account_by_sid
{
    my $sid = shift;

    my $search = $ldap->search(
	base => $config{suffix},
	filter => "(sambaSID=$sid)",
	scope => "sub",
    );
    if ($search->code) {
	die "Failed to search entries by SID: $sid: " .
	    $search->error;
    }

    return ($search->entries)[0];
}

sub account_by_rid
{
    my $rid = shift;
    my $domain_sid = shift || $config{SID};

    return account_by_sid("$domain_sid-$rid");
}

sub rid_is_free
{
    my $rid = shift;
    my $domain_sid = shift || $config{SID};

    return !defined(account_by_rid($rid, $domain_sid));
}

sub user_by_uid
{
    my $uid = shift;

    my $search = $ldap->search(
	base => $config{suffix},
	filter => "(&(objectClass=posixAccount)(uidNumber=$uid))",
	scope => "sub",
    );
    if ($search->code) {
	die "Failed to search entries by UID: $uid: " .
	    $search->error;
    }

    return ($search->entries)[0];
}

sub uid_is_free
{
    my ($uid) = @_;

    return !defined(user_by_uid($uid));
}

sub user_next_uid
{
    my $domain = shift || $config{sambaDomain};
    my $checker = shift || \&uid_is_free;

    return account_next_id("uidNumber", $domain, $checker);
}

sub user_next_rid
{
    my $uid = shift;
    my $domain = shift || $config{sambaDomain};
    my $checker = shift || \&rid_is_free;

    if (defined(my $rid_base = account_base_rid($domain))) {
	## Use legacy algorithmic RID generator
	return $uid * 2 + $rid_base;
    }

    return account_next_rid($domain, $checker);
}

sub group_by_gid
{
    my $gid = shift;

    my $search = $ldap->search(
	base => $config{suffix},
	filter => "(&(objectClass=posixGroup)(gidNumber=$gid))",
	scope => "sub",
    );
    if ($search->code) {
	die "Failed to search entries by GID: $gid: " .
	    $search->error;
    }

    return ($search->entries)[0];
}

sub gid_is_free
{
    my ($gid) = @_;

    return !defined(group_by_gid($gid));
}

sub group_next_gid
{
    my $domain = shift || $config{sambaDomain};
    my $checker = shift || \&gid_is_free;

    return account_next_id("gidNumber", $domain, $checker);
}

sub group_next_rid
{
    my $gid = shift;
    my $domain = shift || $config{sambaDomain};
    my $checker = shift || \&rid_is_free;

    if (defined(my $rid_base = account_base_rid($domain))) {
	## Use legacy algorithmic RID generator
	return $gid * 2 + $rid_base + 1;
    }

    return account_next_rid($domain, $checker);
}

sub utf8Encode {
    my $encoding = shift;
    my $string = shift;

    if ($encoding eq "UTF-8") {
	return $string;
    }

    Encode::from_to($string, $encoding, "UTF-8");

    return $string;
}

sub utf8Decode {
    my $encoding = shift;
    my $string = shift;

    if ($encoding eq "UTF-8") {
	return $string;
    }

    Encode::from_to($string, "UTF-8", $encoding);

    return $string;
}

sub password_read
{
    my ($prompt, $timeout) = @_;

    my $termios = POSIX::Termios->new;
    my $term_flag = defined($termios->getattr(STDIN->fileno)) ?
	$termios->getlflag : undef;

    my $pass;
    for (;;) {
	my $sig_handlers_orig = {};
	my $sig_sent = {};
	my $sig_hander = sub { $sig_sent->{shift(@_)} = 1; die; };

	for my $sig_name qw(ALRM INT HUP QUIT TERM TSTP TTIN TTOU) {
	    $sig_handlers_orig->{$sig_name} = $SIG{$sig_name};
	    $SIG{$sig_name} = $sig_hander;
	}
	$sig_handlers_orig->{'PIPE'} = $SIG{'PIPE'};
	$SIG{'PIPE'} = 'IGNORE';

	print $prompt if (defined($prompt));
	$pass = eval {
	    if ($term_flag && $term_flag & ECHO) {
		$termios->setlflag($term_flag & ~ECHO);
		$termios->setattr(STDIN->fileno, TCSANOW);
	    }
	    alarm($timeout) if ($timeout);
	    STDIN->getline;
	};
	alarm(0) if ($timeout);

	if ($term_flag && $term_flag & ECHO) {
	    print "\n";
	    $termios->setlflag($term_flag);
	    $termios->setattr(STDIN->fileno, TCSANOW);
	}

	while (my ($sig_name, $sig_handler_orig) = each(%$sig_handlers_orig)) {
	    $SIG{$sig_name} = $sig_handler_orig || 'DEFAULT';
	}

	my $restart = false;
	for my $sig_name (keys %$sig_sent) {
	    kill($sig_name, $$) unless ($sig_name eq 'ALRM' && $timeout);
	    $restart = true if ($sig_name =~ /^T(STP|TIN|TOU)$/);
	}
	last unless ($restart);
    }

    chomp($pass) if (defined($pass));

    return $pass;
}

sub password_set
{
    my ($dn, $pass, $pass_old, $hash, $salt_format) = @_;
    $hash ||= $config{password_hash};

    if ($hash eq "exop") {
	password_exop($dn, $pass, $pass_old);
    } else {
	password_modify($dn, $pass, $pass_old, $hash, $salt_format);
    }

    shadow_update($dn);
}

sub password_exop
{
    my ($dn, $pass, $pass_old) = @_;

    my %values = (
      user =>		$dn,
      newpasswd =>	$pass,
    );
    $values{oldpasswd} = $pass_old if (defined($pass_old));

    my $set = $ldap->set_password(%values);

    $set->code && die "Failed to modify UNIX password: ", $set->error;
}

sub password_modify
{
    my ($dn, $pass, $pass_old, $hash, $salt_format) = @_;

    my $pass_hashed = password_hash($pass, $hash, $salt_format);

    my $modify = $ldap->modify ($dn,
	changes => [
	    replace => [userPassword => $pass_hashed],
	]
    );

    $modify->code && die "Failed to modify UNIX password: ", $modify->error;
}

sub password_hash
{
    my ($pass, $hash, $salt_format) = @_;

    return ($config{with_slappasswd}) ?
	password_hash_by_slappasswd($pass, $hash, $salt_format) :
	password_hash_internal($pass, $hash, $salt_format);
}

# Generates hash to be one of the following RFC 2307 schemes:
# CRYPT, MD5, SMD5, SHA, SSHA and CLEARTEXT
sub password_hash_internal
{
    my $pass = shift;
    my $hash = shift || $config{password_hash};
    my $crypt_salt_format = shift || $config{password_crypt_salt_format};

    my $pass_hashed;
    if ($hash eq "CLEARTEXT") {
	return $pass;
    } elsif ($hash eq "CRYPT") {
	my $salt = sprintf($crypt_salt_format, password_salt());
	$pass_hashed = crypt($pass, $salt);
    } elsif ($hash eq "MD5") {
	$pass_hashed = encode_base64( md5($pass),'' );
    } elsif ($hash eq "SMD5") {
	my $salt = password_salt(4);
	$pass_hashed = encode_base64(md5($pass . $salt) . $salt, '');
    } elsif ($hash eq "SHA") {
	$pass_hashed = encode_base64(sha1($pass), '');
    } elsif ($hash eq "SSHA") {
	my $salt = password_salt(4);
	$pass_hashed = encode_base64(sha1($pass . $salt) . $salt, '');
    } else {
	die "Unknown password hash scheme: $hash\n";
    }

    return "{$hash}$pass_hashed";
}

sub password_hash_by_slappasswd
{
    my $pass = shift;
    my $hash = shift || $config{password_hash};
    my $crypt_salt_format = shift || $config{password_crypt_salt_format};

    # checking if password is tainted: nothing is changed!!!!
    # essential for perl 5.8
    ($pass =~ /^(.*)$/ and $pass=$1) or
	die "$0: user password is tainted\n";

    my $pass_hashed;

    if ($hash eq "CLEARTEXT") {
	return $pass;
    } elsif ($hash eq "CRYPT") {
	open BUF, "-|" or
	    exec "$config{slappasswd}",
	    "-h","{$hash}",
	    "-c",$crypt_salt_format,
	    "-s","$pass";
	$pass_hashed = <BUF>;
	close BUF;
    } else {
	open(BUF, "-|") or
	    exec "$config{slappasswd}",
	    "-h","{$hash}",
	    "-s","$pass";
	$pass_hashed = <BUF>;
	close BUF;
    }

    defined($pass_hashed) or die "Failed to generate password hash!\n";
    chomp($pass_hashed);
    length($pass_hashed) or die "Failed to generate password hash!";

    return $pass_hashed;
}

# Generates salt
# Similar to Crypt::Salt module from CPAN
sub password_salt
{
    my $length= shift || 32;

    my @seeds = ('.', '/', 0..9, 'A'..'Z', 'a'..'z');
    return join "", @seeds[map {rand scalar(@seeds)} (1..$length)];
}

sub shadow_update
{
    if (!$config{shadowAccount}) {
	return;
    }

    shadow_update_internal(@_);
}

sub shadow_update_internal
{
    my $dn = shift;
    my $time = shift || time;
    my $pass_maxage = shift || $config{defaultMaxPasswordAge};

    my $shadowLastChange = int($time / 86400);
    my $modify = $ldap->modify ($dn,
	changes => [
	    replace => [shadowLastChange => $shadowLastChange],
	]
    );
    $modify->code && die "Failed to modify shadowLastChange: ", $modify->error;

    if (($< == 0) && ($pass_maxage)) {
	my $modify = $ldap->modify ($dn,
	    changes => [
		replace => [shadowMax => $pass_maxage]
	    ]
	);
	$modify->code && die "Failed to modify shadowMax: ", $modify->error;
    }
}

sub nsc_invalidate
{
    my ($dbname) = @_;

    return unless (defined($config{nscd}) && length($config{nscd}));

    system("\Q$config{nscd}\E -i \Q$dbname\E 2>/dev/null");
}

1;
