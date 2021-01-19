package PMG::API2::SpamAssassin;

use strict;
use warnings;

use PVE::Tools;
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::Exception qw(raise_param_exc);
use PVE::RESTHandler;
use PMG::RESTEnvironment;
use PVE::JSONSchema qw(get_standard_option);

use PMG::Utils;
use PMG::Config;

use Mail::SpamAssassin;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $res = [];

	push @$res, { subdir => "rules" };

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'rules_status',
    path => 'rules',
    method => 'GET',
    description => "SpamAssassin rules status.",
    permissions => { check => [ 'admin', 'audit' ] },
    proxyto => 'node',
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		channel => { type => 'string' },
		update_avail => { type => 'boolean' },
		version => { type => 'string', optional => 1 },
		last_updated => { type => 'integer', optional => 1},
		update_version => { type => 'string', optional => 1},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $saversion = $Mail::SpamAssassin::VERSION;
	my $sa_update_dir = "/var/lib/spamassassin/$saversion/";

	my $check_channel = sub {
	    my ($channel) = @_;

	    # see sa-update source:
	    my $channel_file_base = $channel;
	    $channel_file_base =~ s/[^A-Za-z0-9-]+/_/g;
	    my $channelfile = "${sa_update_dir}${channel_file_base}.cf";

	    my $mtime = -1;
	    my $version = -1;
	    my $newversion = -1;

	    if (-f $channelfile) {
		# stat metadata cf file
		$mtime = (stat($channelfile))[9]; # 9 is mtime

		# parse version from metadata cf file
		my $metadata = PVE::Tools::file_read_firstline($channelfile);
		if ($metadata =~ m/\s([0-9]+)$/) {
		    $version = $1;
		} else {
		    warn "invalid metadata in '$channelfile'\n";
		}
	    }
	    # call sa-update to see if updates are available

	    my $cmd = "sa-update -v --checkonly --channel $channel";
	    PVE::Tools::run_command($cmd, noerr => 1, logfunc => sub {
		my ($line) = @_;

		if ($line =~ m/Update available for channel \S+: -?[0-9]+ -> ([0-9]+)/) {
		    $newversion = $1;
		}
	    });

	    my $result = {
		channel => $channel,
	    };

	    $result->{version} = $version if $version > -1;
	    $result->{update_version} = $newversion if $newversion > -1;
	    $result->{last_updated} = $mtime if $mtime > -1;

	    if ($newversion > $version) {
		$result->{update_avail} = 1;
	    } else {
		$result->{update_avail} = 0;
	    }
	    return $result;
	};

	my @channels = ('updates.spamassassin.org');

	my $localchannels = PMG::Utils::local_spamassassin_channels();
	push(@channels, map { $_->{channelurl} } @$localchannels);

	return [ map { $check_channel->($_) } @channels];
    }});

__PACKAGE__->register_method({
    name => 'update_rules',
    path => 'rules',
    method => 'POST',
    description => "Update SpamAssassin rules.",
    protected => 1,
    permissions => { check => [ 'admin' ] },
    proxyto => 'node',
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => { type => 'string' },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();

	my $realcmd = sub {
	    my $upid = shift;

	    # setup proxy env (assume sa-update use http)
	    my $pmg_cfg = PMG::Config->new();
	    if (my $http_proxy = $pmg_cfg->get('admin', 'http_proxy')) {
		$ENV{http_proxy} = $http_proxy;
	    }

	    my $cmd = "sa-update -v";

	    PVE::Tools::run_command($cmd, noerr => 1);

	    PMG::Utils::update_local_spamassassin_channels(1);
	};

	return $rpcenv->fork_worker('saupdate', undef, $authuser, $realcmd);
    }});

1;
