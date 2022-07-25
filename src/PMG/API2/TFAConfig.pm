package PMG::API2::TFAConfig;

use strict;
use warnings;

use PVE::Exception qw(raise raise_perm_exc raise_param_exc);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::Tools qw(extract_param);

use PMG::AccessControl;
use PMG::RESTEnvironment;
use PMG::TFAConfig;
use PMG::UserConfig;
use PMG::Utils;

use base qw(PVE::RESTHandler);

my $wa_config_schema = {
    type => 'object',
    properties => {
	rp => {
	    type => 'string',
	    description =>
		"Relying party name. Any text identifier.\n"
		."Changing this *may* break existing credentials.",
	},
	origin => {
	    type => 'string',
	    optional => 1,
	    description =>
		'Site origin. Must be a `https://` URL (or `http://localhost`).'
		.' Should contain the address users type in their browsers to access the web'
		." interface.\n"
		.'Changing this *may* break existing credentials.',
	},
	id => {
	    type => 'string',
	    description =>
		"Relying part ID. Must be the domain name without protocol, port or location.\n"
		.'Changing this *will* break existing credentials.',
	},
	'allow-subdomains' => {
	    type => 'boolean',
	    description =>
		'Whether to allow the origin to be a subdomain, rather than the exact URL.',
	    optional => 1,
	    default => 1,
	},
    },
};

my %return_properties = $wa_config_schema->{properties}->%*;
$return_properties{$_}->{optional} = 1 for keys %return_properties;

my $wa_config_return_schema = {
    type => 'object',
    properties => \%return_properties,
};

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
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
		section => { type => 'string'},
	    },
	},
	links => [ { rel => 'child', href => "{section}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $res = [
	    { section => 'webauthn' },
	];

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'get_webauthn_config',
    path => 'webauthn',
    method => 'GET',
    protected => 1,
    permissions => { user => 'all' },
    description => "Read the webauthn configuration.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	optional => 1,
	$wa_config_schema->%*,
    },
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::TFAConfig->new();
	return $cfg->get_webauthn_config();
    }});

__PACKAGE__->register_method({
    name => 'update_webauthn_config',
    path => 'webauthn',
    method => 'PUT',
    protected => 1,
    proxyto => 'master',
    permissions => { check => [ 'admin' ] },
    description => "Read the webauthn configuration.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    $wa_config_schema->{properties}->%*,
	    delete => {
		type => 'string', enum => [keys $wa_config_schema->{properties}->%*],
		description => "A list of settings you want to delete.",
		optional => 1,
	    },
	    digest => {
		type => 'string',
		description => 'Prevent changes if current configuration file has different SHA1 digest.'
		    .' This can be used to prevent concurrent modifications.',
		maxLength => 40,
		optional => 1,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $digest = extract_param($param, 'digest');
	my $delete = extract_param($param, 'delete');

	PMG::TFAConfig::lock_config(sub {
	    my $cfg = PMG::TFAConfig->new();

	    my ($config_digest, $wa) = $cfg->get_webauthn_config();
	    if (defined($digest)) {
		PVE::Tools::assert_if_modified($digest, $config_digest);
	    }

	    foreach my $opt (PVE::Tools::split_list($delete)) {
		delete $wa->{$opt};
	    }
	    foreach my $opt (keys %$param) {
		my $value = $param->{$opt};
		if (length($value)) {
		    $wa->{$opt} = $value;
		} else {
		    delete $wa->{$opt};
		}
	    }

	    # to remove completely, pass `undef`:
	    if (!%$wa) {
		$wa = undef;
	    }

	    $cfg->set_webauthn_config($wa);

	    $cfg->write();
	});

	return;
    }});

1;
