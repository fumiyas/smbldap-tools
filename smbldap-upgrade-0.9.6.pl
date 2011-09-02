#!@PERL_CMD@
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
use smbldap_tools;

my $base_attr = "sambaAlgorithmicRidBase";
my $base_value = 1000;

my $ldap = eval { connect_ldap_master(); };
if ($@) {
    ## Not configured?
    die "$0: ERROR: Connecting to LDAP master failed: $@\n";
}

my $search = $ldap->search(
    base => $config{suffix},
    filter => "(objectClass=sambaDomain)",
    scope => "sub",
    attrs => [$base_attr],
);
if ($search->code) {
    ## Not configured?
    die "$0: ERROR: Searching for sambaDomain object failed: " . $search->error . "\n";
}

for my $entry ($search->entries) {
    next if (defined($entry->get_value($base_attr)));
    print "$0: Adding $base_attr to " . $entry->dn . " ...\n";
    my $modify = $ldap->modify($entry->dn, add => [$base_attr => $base_value]);
    if ($modify->code) {
	die "$0: ERROR: Cannot add $base_attr to " . $entry->dn . ": " . $modify->error . "\n";
    }
}

exit(0);

