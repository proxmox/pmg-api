package PMG::API2::Subscription;

use strict;
use warnings;

use Proxmox::RS::Subscription;

use PVE::Tools;
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::Exception qw(raise_param_exc);
use PVE::RESTHandler;
use PMG::RESTEnvironment;
use PVE::JSONSchema qw(get_standard_option);

use PMG::Utils;
use PMG::Config;

use base qw(PVE::RESTHandler);

my $subscription_pattern = 'pmg([cbsp])-[0-9a-f]{10}';
my $filename = "/etc/pmg/subscription";

sub parse_key {
    my ($key, $noerr) = @_;

    if ($key =~ m/^${subscription_pattern}$/) {
	return $1 # subscription level
    }
    return undef if $noerr;

    die "Wrong subscription key format\n";
}

sub read_etc_subscription {
    my $server_id = PMG::Utils::get_hwaddress();

    my $info = Proxmox::RS::Subscription::read_subscription($filename);
    return $info if !$info;

    my $level = parse_key($info->{key});

    if ($info->{status} eq 'active') {
	$info->{level} = $level;
    }

    return $info;
};

sub write_etc_subscription {
    my ($info) = @_;

    my $server_id = PMG::Utils::get_hwaddress();

    Proxmox::RS::Subscription::write_subscription($filename, "/etc/apt/auth.conf.d/pmg.conf", "enterprise.proxmox.com/debian/pmg", $info);
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
	my $info = read_etc_subscription();
	if (!$info) {
	    return {
		status => "notfound",
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

	my $info = read_etc_subscription();
	return undef if !$info;

	my $server_id = PMG::Utils::get_hwaddress();
	my $key = $info->{key};

	# key has been recently checked
	return undef
	    if !$param->{force}
		&& $info->{status} eq 'active'
		&& Proxmox::RS::Subscription::check_age($info, 1)->{status} eq 'active';

	my $pmg_cfg = PMG::Config->new();
	my $proxy = $pmg_cfg->get('admin', 'http_proxy');

	$info = Proxmox::RS::Subscription::check_subscription($key, $server_id, "", "Proxmox Mail Gateway", $proxy);

	write_etc_subscription($info);

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
	    status => 'new',
	    key => $key,
	    checktime => time(),
	};

	my $server_id = PMG::Utils::get_hwaddress();

	write_etc_subscription($info);

	my $pmg_cfg = PMG::Config->new();
	my $proxy = $pmg_cfg->get('admin', 'http_proxy');

	$info = Proxmox::RS::Subscription::check_subscription($key, $server_id, "", "Proxmox Mail Gateway", $proxy);

	write_etc_subscription($info);

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
	return if ! -e $filename;
	unlink($filename) or die "cannot delete subscription key: $!";
	return undef;
    }});

1;
