package PMG::API2;

use strict;
use warnings;

use PVE::RESTHandler;
use PVE::JSONSchema;

use PMG::API2::AccessControl;
use PMG::API2::Nodes;
use PMG::API2::Config;
use PMG::API2::Quarantine;
use PMG::API2::Statistics;
use PMG::pmgcfg;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Config",
    path => 'config',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Nodes",
    path => 'nodes',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::AccessControl",
    path => 'access',
			      });

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Quarantine",
    path => 'quarantine',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Statistics",
    path => 'statistics',
});

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    permissions => { user => 'all' },
    description => "Directory index.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		subdir => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($resp, $param) = @_;

	my $res = [
	    { subdir => 'access' },
	    { subdir => 'config' },
	    { subdir => 'nodes' },
	    { subdir => 'version' },
	    { subdir => 'quarantine' },
	    { subdir => 'statistics' },
	    ];

	return $res;
    }});


__PACKAGE__->register_method ({
    name => 'version',
    path => 'version',
    method => 'GET',
    permissions => { user => 'all' },
    description => "API version details.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => "object",
	properties => {
	    version => {
		type => 'string',
		description => 'The current installed pmg-api package version',
	    },
	    release => {
		type => 'string',
		description => 'The current installed Proxmox Mailgateway Release',
	    },
	    repoid => {
		type => 'string',
		description => 'The short git commit hash ID from which this version was build',
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	return PMG::pmgcfg::version_info();
    }});

1;
