package PMG::RuleDB::ReceiverDomain;

use strict;
use warnings;

use PMG::RuleDB::Domain;

use base qw(PMG::RuleDB::Domain);

sub otype {
    return 1008;
}

sub receivertest {
    return 1;
}

1;
