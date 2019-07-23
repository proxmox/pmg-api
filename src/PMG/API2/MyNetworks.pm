package PMG::API2::MyNetworks;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use HTTP::Status qw(:constants);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;

use PMG::Config;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "List of trusted networks from where SMTP clients are allowed to relay mail through Proxmox Mail Gateway.",
    proxyto => 'master',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		cidr => { type => 'string'},
	    },
	},
	links => [ { rel => 'child', href => "{cidr}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $mynetworks = PVE::INotify::read_file('mynetworks');

	my $res = [];

	foreach my $cidr (sort keys %$mynetworks) {
	    push @$res, $mynetworks->{$cidr};
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'create',
    path => '',
    method => 'POST',
    proxyto => 'master',
    protected => 1,
    permissions => { check => [ 'admin' ] },
    description => "Add a trusted network.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    cidr => {
		description => "IPv4 or IPv6 network in CIDR notation.",
		type => 'string', format => 'CIDR',
	    },
	    comment => {
		description => "Comment.",
		type => 'string',
		optional => 1,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $mynetworks = PVE::INotify::read_file('mynetworks');

	    die "trusted network '$param->{cidr}' already exists\n"
		if $mynetworks->{$param->{cidr}};

	    $mynetworks->{$param->{cidr}} = {
		comment => $param->{comment} // '',
	    };

	    PVE::INotify::write_file('mynetworks', $mynetworks);

	    my $cfg = PMG::Config->new();

	    if ($cfg->rewrite_config_postfix()) {
		PMG::Utils::service_cmd('postfix', 'reload');
	    }
	};

	PMG::Config::lock_config($code, "add trusted network failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'read',
    path => '{cidr}',
    method => 'GET',
    description => "Read trusted network data (comment).",
    proxyto => 'master',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    cidr => {
		description => "IPv4 or IPv6 network in CIDR notation.",
		type => 'string', format => 'CIDR',
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
	    cidr => { type => 'string'},
	    comment => { type => 'string'},
	},
    },
    code => sub {
	my ($param) = @_;

	my $mynetworks = PVE::INotify::read_file('mynetworks');

	die "trusted network '$param->{cidr}' does not exist\n"
	    if !$mynetworks->{$param->{cidr}};

	return $mynetworks->{$param->{cidr}}
    }});

__PACKAGE__->register_method ({
    name => 'write',
    path => '{cidr}',
    method => 'PUT',
    description => "Update trusted data (comment).",
    protected => 1,
    permissions => { check => [ 'admin' ] },
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    cidr => {
		description => "IPv4 or IPv6 network in CIDR notation.",
		type => 'string', #format => 'CIDR',
	    },
	    comment => {
		description => "Comment.",
		type => 'string',
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $mynetworks = PVE::INotify::read_file('mynetworks');

	    die "trusted network '$param->{cidr}' does not exist\n"
		if !$mynetworks->{$param->{cidr}};

	    $mynetworks->{$param->{cidr}}->{comment} = $param->{comment};

	    PVE::INotify::write_file('mynetworks', $mynetworks);
	};

	PMG::Config::lock_config($code, "update trusted network failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'delete',
    path => '{cidr}',
    method => 'DELETE',
    description => "Delete a truster network",
    protected => 1,
    permissions => { check => [ 'admin' ] },
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    cidr => {
		description => "IPv4 or IPv6 network in CIDR notation.",
		type => 'string', format => 'CIDR',
	    },
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $mynetworks = PVE::INotify::read_file('mynetworks');

	    die "trusted network '$param->{cidr}' does not exist\n"
		if !$mynetworks->{$param->{cidr}};

	    delete $mynetworks->{$param->{cidr}};

	    PVE::INotify::write_file('mynetworks', $mynetworks);

	    my $cfg = PMG::Config->new();

	    if ($cfg->rewrite_config_postfix()) {
		PMG::Utils::service_cmd('postfix', 'reload');
	    }
	};

	PMG::Config::lock_config($code, "delete trusted network failed");

	return undef;
    }});

1;
