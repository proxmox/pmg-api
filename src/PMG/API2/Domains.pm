package PMG::API2::Domains;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;

use PMG::Config;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "List relay domains.",
    permissions => { check => [ 'admin', 'audit' ] },
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		domain => { type => 'string'},
		comment => { type => 'string'},
	    },
	},
	links => [ { rel => 'child', href => "{domain}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $domains = PVE::INotify::read_file('domains');

	my $res = [];

	foreach my $domain (sort keys %$domains) {
	    push @$res, $domains->{$domain};
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
    description => "Add relay domain.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    domain => {
		description => "Domain name.",
		type => 'string', format => 'transport-domain',
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

	    my $domains = PVE::INotify::read_file('domains');

	    die "Domain '$param->{domain}' already exists\n"
		if $domains->{$param->{domain}};

	    $domains->{$param->{domain}} = {
		comment => $param->{comment} // '',
	    };

	    PVE::INotify::write_file('domains', $domains);

	    PMG::Config::postmap_pmg_domains();
	};

	PMG::Config::lock_config($code, "add relay domain failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'read',
    path => '{domain}',
    method => 'GET',
    description => "Read Domain data (comment).",
    proxyto => 'master',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    domain => {
		description => "Domain name.",
		type => 'string', format => 'transport-domain',
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
	    domain => { type => 'string'},
	    comment => { type => 'string'},
	},
    },
    code => sub {
	my ($param) = @_;

	my $domains = PVE::INotify::read_file('domains');

	die "Domain '$param->{domain}' does not exist\n"
	    if !$domains->{$param->{domain}};

	return $domains->{$param->{domain}};
    }});

__PACKAGE__->register_method ({
    name => 'write',
    path => '{domain}',
    method => 'PUT',
    description => "Update relay domain data (comment).",
    protected => 1,
    permissions => { check => [ 'admin' ] },
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    domain => {
		description => "Domain name.",
		type => 'string', format => 'transport-domain',
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

	    my $domains = PVE::INotify::read_file('domains');

	    die "Domain '$param->{domain}' does not exist\n"
		if !$domains->{$param->{domain}};

	    $domains->{$param->{domain}}->{comment} = $param->{comment};

	    PVE::INotify::write_file('domains', $domains);

	    PMG::Config::postmap_pmg_domains();
	};

	PMG::Config::lock_config($code, "update relay domain failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'delete',
    path => '{domain}',
    method => 'DELETE',
    description => "Delete a relay domain",
    protected => 1,
    permissions => { check => [ 'admin' ] },
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    domain => {
		description => "Domain name.",
		type => 'string', format => 'transport-domain',
	    },
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $domains = PVE::INotify::read_file('domains');

	    die "Domain '$param->{domain}' does not exist\n"
		if !$domains->{$param->{domain}};

	    delete $domains->{$param->{domain}};

	    PVE::INotify::write_file('domains', $domains);

	    PMG::Config::postmap_pmg_domains();
	};

	PMG::Config::lock_config($code, "delete relay domain failed");

	return undef;
    }});

1;
