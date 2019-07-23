package PMG::RuleDB::Receiver;

use strict;
use warnings;

use PMG::RuleDB::EMail;

use base qw(PMG::RuleDB::EMail);

sub otype {
    return 1007;
}

sub receivertest {
    return 1;
}

1;
