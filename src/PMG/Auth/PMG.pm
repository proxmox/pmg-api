package PMG::Auth::PMG;

use strict;
use warnings;

use PMG::Auth::Plugin;

use base qw(PMG::Auth::Plugin);

sub type {
    return 'pmg';
}

sub properties {
    return {
	default => {
	    description => "Use this as default realm",
	    type => 'boolean',
	    optional => 1,
	},
	comment => {
	    description => "Description.",
	    type => 'string',
	    optional => 1,
	    maxLength => 4096,
	},
    };
}

sub options {
    return {
	default => { optional => 1 },
	comment => { optional => 1 },
    };
}

1;
