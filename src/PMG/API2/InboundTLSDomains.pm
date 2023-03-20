package PMG::API2::InboundTLSDomains;

use strict;
use warnings;

use PVE::RESTHandler;
use PVE::INotify;
use PVE::Exception qw(raise_param_exc);

use PMG::Config;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => 'List tls_inbound_domains entries.',
    proxyto => 'master',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => 'string',
	    format => 'transport-domain',
	},
	description => 'List of domains for which TLS will be enforced on incoming connections',
	links => [ { rel => 'child', href => '{domain}' } ],
    },
    code => sub {
	my ($param) = @_;

	my $res = [];

	my $domains = PVE::INotify::read_file('tls_inbound_domains');

	foreach my $domain (sort keys %$domains) {
	    push @$res, { domain => $domain };
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
    description => 'Add new tls_inbound_domains entry.',
    parameters => {
	additionalProperties => 0,
	properties => {
	    domain => {
		type => 'string',
		format => 'transport-domain',
		description => 'Domain for which TLS should be enforced on incoming connections',
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;
	my $domain = $param->{domain};

	my $code = sub {
	    my $domains = PVE::INotify::read_file('tls_inbound_domains');
	    raise_param_exc({ domain => "InboundTLSDomains entry for '$domain' already exists" })
		if $domains->{$domain};

	    $domains->{$domain} = 1;

	    PVE::INotify::write_file('tls_inbound_domains', $domains);
	    PMG::Config::postmap_tls_inbound_domains();
	};

	PMG::Config::lock_config($code, 'adding tls_inbound_domains entry failed');

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'delete',
    path => '{domain}',
    method => 'DELETE',
    description => 'Delete a tls_inbound_domains entry',
    protected => 1,
    permissions => { check => [ 'admin' ] },
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    domain => {
		type => 'string',
		format => 'transport-domain',
		description => 'Domain which should be removed from tls_inbound_domains',
	    },
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;
	my $domain = $param->{domain};

	my $code = sub {
	    my $domains = PVE::INotify::read_file('tls_inbound_domains');

	    raise_param_exc({ domain => "tls_inbound_domains entry for '$domain' does not exist" })
		if !$domains->{$domain};

	    delete $domains->{$domain};

	    PVE::INotify::write_file('tls_inbound_domains', $domains);
	    PMG::Config::postmap_tls_inbound_domains();
	};

	PMG::Config::lock_config($code, 'deleting tls_inbound_domains entry failed');

	return undef;
    }});

1;
