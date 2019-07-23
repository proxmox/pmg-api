package PMG::CLI::pmgconfig;

use strict;
use warnings;
use IO::File;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::INotify;
use PVE::CLIHandler;

use PMG::RESTEnvironment;
use PMG::RuleDB;
use PMG::RuleCache;
use PMG::Cluster;
use PMG::LDAPConfig;
use PMG::LDAPSet;
use PMG::Config;
use PMG::Ticket;

use base qw(PVE::CLIHandler);

sub setup_environment {
    PMG::RESTEnvironment->setup_default_cli_env();
}

__PACKAGE__->register_method ({
    name => 'dump',
    path => 'dump',
    method => 'POST',
    description => "Print configuration setting which can be used in templates.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::Config->new();
	my $vars = $cfg->get_template_vars();

	foreach my $realm (sort keys %$vars) {
	    foreach my $section (sort keys %{$vars->{$realm}}) {
		my $secvalue = $vars->{$realm}->{$section} // '';
		if (ref($secvalue)) {
		    foreach my $key (sort keys %{$vars->{$realm}->{$section}}) {
			my $value = $vars->{$realm}->{$section}->{$key} // '';
			print "$realm.$section.$key = $value\n";
		    }
		} else {
		    print "$realm.$section = $secvalue\n";
		}
	    }
	}

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'sync',
    path => 'sync',
    method => 'POST',
    description => "Syncronize Proxmox Mail Gateway configurations with system configuration.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    restart => {
		description => "Restart services if necessary.",
		type => 'boolean',
		default => 0,
		optional => 1,
	    },
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::Config->new();

	my $ruledb = PMG::RuleDB->new();
	my $rulecache = PMG::RuleCache->new($ruledb);

	$cfg->rewrite_config($rulecache, $param->{restart});

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'ldapsync',
    path => 'ldapsync',
    method => 'POST',
    description => "Syncronize the LDAP database.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $ldap_cfg = PVE::INotify::read_file("pmg-ldap.conf");
	PMG::LDAPSet::ldap_resync($ldap_cfg, 1);

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'apicert',
    path => 'apicert',
    method => 'POST',
    description => "Generate /etc/pmg/pmg-api.pem (self signed certificate for GUI and REST API).",
    parameters => {
	additionalProperties => 0,
	properties => {
	    force => {
		description => "Overwrite existing certificate.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    },
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	PMG::Ticket::generate_api_cert($param->{force});

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'tlscert',
    path => 'tlscert',
    method => 'POST',
    description => "Generate /etc/pmg/pmg-tls.pem (self signed certificate for encrypted SMTP traffic).",
    parameters => {
	additionalProperties => 0,
	properties => {
	    force => {
		description => "Overwrite existing certificate.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    },
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	PMG::Utils::gen_proxmox_tls_cert($param->{force});

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'init',
    path => 'init',
    method => 'POST',
    description => "Generate required files in /etc/pmg/",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::Config->new();

	PMG::Ticket::generate_api_cert();
	PMG::Ticket::generate_csrf_key();
	PMG::Ticket::generate_auth_key();

	if ($cfg->get('mail', 'tls')) {
	    PMG::Utils::gen_proxmox_tls_cert();
	}

	return undef;
    }});

our $cmddef = {
    'dump' => [ __PACKAGE__, 'dump', []],
    sync => [ __PACKAGE__, 'sync', []],
    ldapsync => [ __PACKAGE__, 'ldapsync', []],
    apicert => [ __PACKAGE__, 'apicert', []],
    tlscert => [ __PACKAGE__, 'tlscert', []],
    init => [ __PACKAGE__, 'init', []],
};


1;
