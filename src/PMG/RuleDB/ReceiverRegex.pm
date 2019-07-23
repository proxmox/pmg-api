package PMG::RuleDB::ReceiverRegex;

use strict;
use warnings;

use PMG::RuleDB::WhoRegex;

use base qw(PMG::RuleDB::WhoRegex);

sub otype {
    return 1009;
}

sub receivertest {
    return 1;
}

1;
