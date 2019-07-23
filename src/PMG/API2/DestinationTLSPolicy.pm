package PMG::API2::DestinationTLSPolicy;

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
    description => "List tls_policy entries.",
    proxyto => 'master',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => 'object',
	    properties => {
		domain => { type => 'string', format => 'transport-domain'},
		policy => { type => 'string', format => 'tls-policy'},
	    },
	},
	links => [ { rel => 'child', href => "{domain}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $res = [];

	my $policies = PVE::INotify::read_file('tls_policy');
	foreach my $policy (sort keys %$policies) {
	    push @$res, $policies->{$policy};
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
    description => "Add tls_policy entry.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    domain => {
		description => "Domain name.",
		type => 'string', format => 'transport-domain',
	    },
	    policy => {
		description => "TLS policy",
		type => 'string', format => 'tls-policy-strict',
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;
	my $domain = $param->{domain};
	my $policy = $param->{policy};

	my $code = sub {
	    my $tls_policy = PVE::INotify::read_file('tls_policy');
	    raise_param_exc({ domain => "DestinationTLSPolicy entry for '$domain' already exists" })
		if $tls_policy->{$domain};

	    $tls_policy->{$domain} = {
		domain => $domain,
		policy => $param->{policy},
	    };

	    PVE::INotify::write_file('tls_policy', $tls_policy);
	    PMG::Config::postmap_tls_policy();
	};

	PMG::Config::lock_config($code, "add tls_policy entry failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'read',
    path => '{domain}',
    method => 'GET',
    description => "Read tls_policy entry.",
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
	    domain => { type => 'string', format => 'transport-domain'},
	    policy => { type => 'string', format => 'tls-policy'},
	},
    },
    code => sub {
	my ($param) = @_;
	my $domain = $param->{domain};

	my $tls_policy = PVE::INotify::read_file('tls_policy');

	if (my $entry = $tls_policy->{$domain}) {
	    return $entry;
	}

	raise_param_exc({ domain => "DestinationTLSPolicy entry for '$domain' does not exist" });
    }});

__PACKAGE__->register_method ({
    name => 'write',
    path => '{domain}',
    method => 'PUT',
    description => "Update tls_policy entry.",
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
	    policy => {
		description => "TLS policy",
		type => 'string', format => 'tls-policy-strict',
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;
	my $domain = $param->{domain};
	my $policy = $param->{policy};

	my $code = sub {

	    my $tls_policy = PVE::INotify::read_file('tls_policy');

	    raise_param_exc({ domain => "DestinationTLSPolicy entry for '$domain' does not exist" })
		if !$tls_policy->{$domain};

	    $tls_policy->{$domain}->{policy} = $policy;

	    PVE::INotify::write_file('tls_policy', $tls_policy);
	    PMG::Config::postmap_tls_policy();
	};

	PMG::Config::lock_config($code, "update tls_policy entry failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'delete',
    path => '{domain}',
    method => 'DELETE',
    description => "Delete a tls_policy entry",
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
	my $domain = $param->{domain};

	my $code = sub {
	    my $tls_policy = PVE::INotify::read_file('tls_policy');

	    raise_param_exc({ domain => "DestinationTLSPolicy entry for '$domain' does not exist" })
		if !$tls_policy->{$domain};

	    delete $tls_policy->{$domain};

	    PVE::INotify::write_file('tls_policy', $tls_policy);
	    PMG::Config::postmap_tls_policy();
	};

	PMG::Config::lock_config($code, "delete tls_policy entry failed");

	return undef;
    }});

1;
