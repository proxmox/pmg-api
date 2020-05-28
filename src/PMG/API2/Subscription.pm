package PMG::API2::Subscription;

use strict;
use warnings;

use PVE::Tools;
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::Exception qw(raise_param_exc);
use PVE::RESTHandler;
use PMG::RESTEnvironment;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Subscription;

use PMG::Utils;
use PMG::Config;

use base qw(PVE::RESTHandler);

PVE::INotify::register_file('subscription', "/etc/pmg/subscription",
			    \&read_etc_pmg_subscription,
			    \&write_etc_pmg_subscription);

my $subscription_pattern = 'pmg([cbsp])-[0-9a-f]{10}';

sub parse_key {
    my ($key, $noerr) = @_;

    if ($key =~ m/^${subscription_pattern}$/) {
	return $1 # subscription level
    }
    return undef if $noerr;

    die "Wrong subscription key format\n";
}

sub read_etc_pmg_subscription {
    my ($filename, $fh) = @_;

    my $server_id = PMG::Utils::get_hwaddress();

    my $info = PVE::Subscription::read_subscription($server_id, $filename, $fh);
    my $level = parse_key($info->{key});

    if ($info->{status} eq 'Active') {
	$info->{level} = $level;
    }

    return $info;
};

sub write_etc_pmg_subscription {
    my ($filename, $fh, $info) = @_;

    my $server_id = PMG::Utils::get_hwaddress();

    PVE::Subscription::write_subscription($server_id, $filename, $fh, $info);
}

__PACKAGE__->register_method ({
    name => 'get',
    path => '',
    method => 'GET',
    description => "Read subscription info.",
    proxyto => 'node',
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => { type => 'object'},
    code => sub {
	my ($param) = @_;

	my $server_id = PMG::Utils::get_hwaddress();
	my $url = "https://www.proxmox.com/proxmox-mail-gateway/pricing";
	my $info = PVE::INotify::read_file('subscription');
	if (!$info) {
	    return {
		status => "NotFound",
		message => "There is no subscription key",
		serverid => $server_id,
		url => $url,
	    }
	}

	$info->{serverid} = $server_id;
	$info->{url} = $url;

	return $info
    }});

__PACKAGE__->register_method ({
    name => 'update',
    path => '',
    method => 'POST',
    description => "Update subscription info.",
    proxyto => 'node',
    protected => 1,
    permissions => { check => [ 'admin' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    force => {
		description => "Always connect to server, even if we have up to date info inside local cache.",
		type => 'boolean',
		optional => 1,
		default => 0
	    }
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $info = PVE::INotify::read_file('subscription');
	return undef if !$info;

	my $server_id = PMG::Utils::get_hwaddress();
	my $key = $info->{key};

	if ($key) {
	    PVE::Subscription::update_apt_auth($key, $server_id);
	}

	if (!$param->{force} && $info->{status} eq 'Active') {
	    my $age = time() -  $info->{checktime};
	    return undef if $age < $PVE::Subscription::localkeydays*60*60*24;
	}

	my $pmg_cfg = PMG::Config->new();
	my $proxy = $pmg_cfg->get('admin', 'http_proxy');

	$info = PVE::Subscription::check_subscription($key, $server_id, $proxy);

	PVE::INotify::write_file('subscription', $info);

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'set',
    path => '',
    method => 'PUT',
    description => "Set subscription key.",
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    key => {
		description => "Proxmox Mail Gateway subscription key",
		type => 'string',
		pattern => $subscription_pattern,
		maxLength => 32,
	    },
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $key = PVE::Tools::trim($param->{key});

	my $level = parse_key($key);

	my $info = {
	    status => 'New',
	    key => $key,
	    checktime => time(),
	};

	my $server_id = PMG::Utils::get_hwaddress();

	PVE::INotify::write_file('subscription', $info);

	my $pmg_cfg = PMG::Config->new();
	my $proxy = $pmg_cfg->get('admin', 'http_proxy');

	$info = PVE::Subscription::check_subscription($key, $server_id, $proxy);

	PVE::INotify::write_file('subscription', $info);

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'delete',
    path => '',
    method => 'DELETE',
    description => "Delete subscription key.",
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => { type => 'null'},
    code => sub {
	my $subscription_file = '/etc/pmg/subscription';
	return if ! -e $subscription_file;
	unlink($subscription_file) or die "cannot delete subscription key: $1";
	return undef;
    }});

1;
