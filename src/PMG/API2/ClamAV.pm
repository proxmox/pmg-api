package PMG::API2::ClamAV;

use strict;
use warnings;

use PVE::Tools;
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::Exception qw(raise_param_exc);
use PVE::RESTHandler;
use PMG::RESTEnvironment;
use PVE::JSONSchema qw(get_standard_option);

use PMG::Utils;

use base qw(PVE::RESTHandler);


__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $res = [];

	push @$res, { subdir => "database" };

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'database_status',
    path => 'database',
    method => 'GET',
    description => "ClamAV virus database status.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    permissions => { check => [ 'admin', 'audit' ] },
    proxyto => 'node',
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		type => { type => 'string' },
		build_time => { type => 'string' },
		version => { type => 'string', optional => 1 },
		nsigs => { type => 'integer' },
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	return PMG::Utils::clamav_dbstat();
    }});

__PACKAGE__->register_method({
    name => 'update_database',
    path => 'database',
    method => 'POST',
    description => "Update ClamAV virus databases.",
    permissions => { check => [ 'admin' ] },
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => { type => 'string' },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();

	my $realcmd = sub {
	    my $upid = shift;

	    # remove mirrors.dat so freshclam checks all servers again
	    # fixes bug #303
	    unlink "/var/lib/clamav/mirrors.dat";

	    my $cmd = ['/usr/bin/freshclam', '--stdout'];

	    PVE::Tools::run_command($cmd);
	};

	return $rpcenv->fork_worker('avupdate', undef, $authuser, $realcmd);
    }});

1;
