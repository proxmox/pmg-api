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

my @domain_args = ('domains', 'relay', 1);

sub index_method {
    my ($filename, $type, $run_postmap) = @_;
    return {
	name => 'index',
	path => '',
	method => 'GET',
	description => "List $type domains.",
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

	    my $domains = PVE::INotify::read_file($filename);

	    my $res = [];

	    foreach my $domain (sort keys %$domains) {
		push @$res, $domains->{$domain};
	    }

	    return $res;
	}};
}

sub create_method {
    my ($filename, $type, $run_postmap) = @_;
    return {
	name => 'create',
	path => '',
	method => 'POST',
	proxyto => 'master',
	protected => 1,
	permissions => { check => [ 'admin' ] },
	description => "Add $type domain.",
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

		my $domains = PVE::INotify::read_file($filename);

		die "Domain '$param->{domain}' already exists\n"
		    if $domains->{$param->{domain}};

		$domains->{$param->{domain}} = {
		    comment => $param->{comment} // '',
		};

		PVE::INotify::write_file($filename, $domains);

		PMG::Config::postmap_pmg_domains() if $run_postmap;
	    };

	    PMG::Config::lock_config($code, "add $type domain failed");

	    return undef;
	}};
}

sub read_method {
    my ($filename, $type, $run_postmap) = @_;
    return {
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

	    my $domains = PVE::INotify::read_file($filename);

	    die "Domain '$param->{domain}' does not exist\n"
		if !$domains->{$param->{domain}};

	    return $domains->{$param->{domain}};
	}};
}

sub write_method {
    my ($filename, $type, $run_postmap) = @_;
    return {
	name => 'write',
	path => '{domain}',
	method => 'PUT',
	description => "Update $type domain data (comment).",
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

		my $domains = PVE::INotify::read_file($filename);

		die "Domain '$param->{domain}' does not exist\n"
		    if !$domains->{$param->{domain}};

		$domains->{$param->{domain}}->{comment} = $param->{comment};

		PVE::INotify::write_file($filename, $domains);

		PMG::Config::postmap_pmg_domains() if $run_postmap;
	    };

	    PMG::Config::lock_config($code, "update $type domain failed");

	    return undef;
	}};
}

sub delete_method {
    my ($filename, $type, $run_postmap) = @_;
    return {
	name => 'delete',
	path => '{domain}',
	method => 'DELETE',
	description => "Delete a $type domain",
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

		my $domains = PVE::INotify::read_file($filename);

		die "Domain '$param->{domain}' does not exist\n"
		    if !$domains->{$param->{domain}};

		delete $domains->{$param->{domain}};

		PVE::INotify::write_file($filename, $domains);

		PMG::Config::postmap_pmg_domains() if $run_postmap;
	    };

	    PMG::Config::lock_config($code, "delete $type domain failed");

	    return undef;
	}};
}

__PACKAGE__->register_method(index_method(@domain_args));
__PACKAGE__->register_method(create_method(@domain_args));
__PACKAGE__->register_method(read_method(@domain_args));
__PACKAGE__->register_method(write_method(@domain_args));
__PACKAGE__->register_method(delete_method(@domain_args));

1;
