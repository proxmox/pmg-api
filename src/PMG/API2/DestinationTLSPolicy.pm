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
		destination => { type => 'string', format => 'transport-domain-or-nexthop'},
		policy => { type => 'string', format => 'tls-policy'},
	    },
	},
	links => [ { rel => 'child', href => "{destination}" } ],
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
	    destination => {
		description => "Destination (Domain or next-hop).",
		type => 'string', format => 'transport-domain-or-nexthop',
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
	my $destination = $param->{destination};
	my $policy = $param->{policy};

	my $code = sub {
	    my $tls_policy = PVE::INotify::read_file('tls_policy');
	    raise_param_exc({ destination => "DestinationTLSPolicy entry for '$destination' already exists" })
		if $tls_policy->{$destination};

	    $tls_policy->{$destination} = {
		destination => $destination,
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
    path => '{destination}',
    method => 'GET',
    description => "Read tls_policy entry.",
    proxyto => 'master',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    destination => {
		description => "Destination (Domain or next-hop).",
		type => 'string', format => 'transport-domain-or-nexthop',
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
	    destination => { type => 'string', format => 'transport-domain-or-nexthop'},
	    policy => { type => 'string', format => 'tls-policy'},
	},
    },
    code => sub {
	my ($param) = @_;
	my $destination = $param->{destination};

	my $tls_policy = PVE::INotify::read_file('tls_policy');

	if (my $entry = $tls_policy->{$destination}) {
	    return $entry;
	}

	raise_param_exc({ destination => "DestinationTLSPolicy entry for '$destination' does not exist" });
    }});

__PACKAGE__->register_method ({
    name => 'write',
    path => '{destination}',
    method => 'PUT',
    description => "Update tls_policy entry.",
    protected => 1,
    permissions => { check => [ 'admin' ] },
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    destination => {
		description => "Destination (Domain or next-hop).",
		type => 'string', format => 'transport-domain-or-nexthop',
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
	my $destination = $param->{destination};
	my $policy = $param->{policy};

	my $code = sub {

	    my $tls_policy = PVE::INotify::read_file('tls_policy');

	    raise_param_exc({ destination => "DestinationTLSPolicy entry for '$destination' does not exist" })
		if !$tls_policy->{$destination};

	    $tls_policy->{$destination}->{policy} = $policy;

	    PVE::INotify::write_file('tls_policy', $tls_policy);
	    PMG::Config::postmap_tls_policy();
	};

	PMG::Config::lock_config($code, "update tls_policy entry failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'delete',
    path => '{destination}',
    method => 'DELETE',
    description => "Delete a tls_policy entry",
    protected => 1,
    permissions => { check => [ 'admin' ] },
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    destination => {
		description => "Destination (Domain or next-hop).",
		type => 'string', format => 'transport-domain-or-nexthop',
	    },
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;
	my $destination = $param->{destination};

	my $code = sub {
	    my $tls_policy = PVE::INotify::read_file('tls_policy');

	    raise_param_exc({ destination => "DestinationTLSPolicy entry for '$destination' does not exist" })
		if !$tls_policy->{$destination};

	    delete $tls_policy->{$destination};

	    PVE::INotify::write_file('tls_policy', $tls_policy);
	    PMG::Config::postmap_tls_policy();
	};

	PMG::Config::lock_config($code, "delete tls_policy entry failed");

	return undef;
    }});

1;
