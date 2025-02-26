package PMG::Auth::PAM;

use strict;
use warnings;

use PMG::Auth::Plugin;

use base qw(PMG::Auth::Plugin);

sub type {
    return 'pam';
}

sub options {
    return {
	default => { optional => 1 },
	comment => { optional => 1 },
    };
}

1;
