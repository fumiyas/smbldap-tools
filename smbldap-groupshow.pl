#!@PERL_COMMAND@

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

# Purpose of smbldap-groupshow : user (posix,shadow,samba) display
#

use strict;
use warnings;
use smbldap_tools;
use Getopt::Std;
my %Options;

my $ok = getopts('?', \%Options);

if ( (!$ok) || (@ARGV < 1) || ($Options{'?'}) ) {
    print_banner;
    print "Usage: $0 [-?] group\n";
    print "  -?	show this help message\n";
    exit (1);
}

# Read only first @ARGV
my $group = $ARGV[0];

my $ldap_slave=connect_ldap_slave();

my $lines = read_group($group);
if (!defined($lines)) {
    print "group $group doesn't exist\n";
    exit (1);
}

print "$lines\n";

# take down session
$ldap_slave->unbind;

exit(0);

############################################################

=head1 NAME

smbldap-groupshow - Display group informations

=head1 SYNOPSIS

smbldap-groupshow groupname

=head1 DESCRIPTION

The smbldap-groupshow command displays informations associated with the given group.

=cut

#'
