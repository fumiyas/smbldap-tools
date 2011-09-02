#!@PERL_CMD@

use strict;
use warnings;
use smbldap_tools;

my $attr = "sambaAlgorithmicRidBase";

my $ldap = eval { connect_ldap_master(); };
## Not configured?
$@ && exit(0);

my $search = $ldap->search(
    base => $config{suffix},
    filter => "(objectClass=sambaDomain)",
    scope => "sub",
    attrs => [$attr],
);
## Not configured?
$search->code && exit(0);

for my $entry ($search->entries) {
    next if (defined($entry->get_value($attr)));
    my $modify = $ldap->modify($entry->dn, replace => [$attr => 1000]);
    $modify->code && die "$0: ERROR: Cannot add $attr to " . $entry->dn;
}

exit(0);

