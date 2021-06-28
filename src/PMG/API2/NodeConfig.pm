package PMG::API2::NodeConfig;

use strict;
use warnings;

use PVE::JSONSchema qw(get_standard_option);
use PVE::Tools qw(extract_param);

use PMG::NodeConfig;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'get_config',
    path => '',
    method => 'GET',
    description => "Get node configuration options.",
    protected => 1,
    proxyto => 'node',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns =>  PMG::NodeConfig::acme_config_schema({
	digest => {
	    type => 'string',
	    description => 'Prevent changes if current configuration file has different SHA1 digest.'
		.' This can be used to prevent concurrent modifications.',
	    maxLength => 40,
	    optional => 1,
	},
    }),
    code => sub {
	my ($param) = @_;

	return PMG::NodeConfig::load_config();
    }});

__PACKAGE__->register_method ({
    name => 'set_config',
    path => '',
    method => 'PUT',
    description => "Set node configuration options.",
    protected => 1,
    proxyto => 'node',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => PMG::NodeConfig::acme_config_schema({
	delete => {
	    type => 'string', format => 'pve-configid-list',
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
	node => get_standard_option('pve-node'),
    }),
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	my $node = extract_param($param, 'node');
	my $delete = extract_param($param, 'delete');
	my $digest = extract_param($param, 'digest');

	PMG::NodeConfig::lock_config(sub {
	    my $conf = PMG::NodeConfig::load_config();

	    PVE::Tools::assert_if_modified($digest, delete $conf->{digest});

	    foreach my $opt (PVE::Tools::split_list($delete)) {
		delete $conf->{$opt};
	    }
	    foreach my $opt (keys %$param) {
		$conf->{$opt} = $param->{$opt};
	    }

	    # validate the acme config (check for duplicates)
	    PMG::NodeConfig::get_acme_conf($conf);

	    PMG::NodeConfig::write_config($conf);
	});

	return undef;
    }});

1;
