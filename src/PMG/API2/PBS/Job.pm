package PMG::API2::PBS::Job;

use strict;
use warnings;

use POSIX qw(strftime);
use File::Path qw(rmtree);

use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::PBSClient;

use PMG::RESTEnvironment;
use PMG::Backup;
use PMG::PBSConfig;
use PMG::PBSSchedule;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'list',
    path => '',
    method => 'GET',
    description => "List all configured Proxmox Backup Server jobs.",
    permissions => { check => [ 'admin', 'audit' ] },
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => "array",
	items => PMG::PBSConfig->createSchema(1),
	links => [ { rel => 'child', href => "{remote}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $res = [];

	my $conf = PMG::PBSConfig->new();
	return $res if !defined($conf);

	foreach my $remote (keys %{$conf->{ids}}) {
	    my $d = $conf->{ids}->{$remote};
	    push @$res, {
		remote => $remote,
		server => $d->{server},
		datastore => $d->{datastore},
	    };
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'remote_index',
    path => '{remote}',
    method => 'GET',
    description => "Backup Job index.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    remote => {
		description => "Proxmox Backup Server ID.",
		type => 'string', format => 'pve-configid',
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => { section => { type => 'string'} },
	},
	links => [ { rel => 'child', href => "{section}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $result = [
	    { section => 'snapshot' },
	    { section => 'timer' },
	];
	return $result;
}});


my sub get_snapshots {
    my ($remote, $group) = @_;

    my $conf = PMG::PBSConfig->new();

    my $remote_config = $conf->{ids}->{$remote};
    die "PBS remote '$remote' does not exist\n" if !$remote_config;

    my $res = [];
    return $res if $remote_config->{disable};

    my $pbs = PVE::PBSClient->new($remote_config, $remote, $conf->{secret_dir});

    my $snapshots = $pbs->get_snapshots($group);
    foreach my $item (@$snapshots) {
	my ($type, $id, $time) = $item->@{qw(backup-type backup-id backup-time)};
	next if $type ne 'host';

	my @pxar = grep { $_->{filename} eq 'pmgbackup.pxar.didx' } @{$item->{files}};
	next if (scalar(@pxar) != 1);

	my $time_rfc3339 = strftime("%FT%TZ", gmtime($time));

	push @$res, {
	    'backup-id' => $id,
	    'backup-time' => $time_rfc3339,
	    ctime => $time,
	    size => $item->{size} // 1,
	};
    }
    return $res;
}

__PACKAGE__->register_method ({
    name => 'get_snapshots',
    path => '{remote}/snapshot',
    method => 'GET',
    description => "Get snapshots stored on remote.",
    proxyto => 'node',
    protected => 1,
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    remote => {
		description => "Proxmox Backup Server ID.",
		type => 'string', format => 'pve-configid',
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		'backup-time' => { type => 'string'},
		'backup-id' => { type => 'string'},
		ctime => { type => 'string'},
		size => { type => 'integer'},
	    },
	},
	links => [ { rel => 'child', href => "{backup-id}" } ],
    },
    code => sub {
	my ($param) = @_;

	return get_snapshots($param->{remote});
    }});

__PACKAGE__->register_method ({
    name => 'get_group_snapshots',
    path => '{remote}/snapshot/{backup-id}',
    method => 'GET',
    description => "Get snapshots from a specific ID stored on remote.",
    proxyto => 'node',
    protected => 1,
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    remote => {
		description => "Proxmox Backup Server ID.",
		type => 'string', format => 'pve-configid',
	    },
	    'backup-id' => {
		description => "ID (hostname) of backup snapshot",
		type => 'string',
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		'backup-time' => { type => 'string'},
		'backup-id' => { type => 'string'},
		ctime => { type => 'string'},
		size => { type => 'integer'},
	    },
	},
	links => [ { rel => 'child', href => "{backup-time}" } ],
    },
    code => sub {
	my ($param) = @_;

	return get_snapshots($param->{remote}, "host/$param->{'backup-id'}");
    }});

__PACKAGE__->register_method ({
    name => 'forget_snapshot',
    path => '{remote}/snapshot/{backup-id}/{backup-time}',
    method => 'DELETE',
    description => "Forget a snapshot",
    proxyto => 'node',
    protected => 1,
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    remote => {
		description => "Proxmox Backup Server ID.",
		type => 'string', format => 'pve-configid',
	    },
	    'backup-id' => {
		description => "ID (hostname) of backup snapshot",
		type => 'string',
	    },
	    'backup-time' => {
		description => "Backup time in RFC 3339 format",
		type => 'string',
	    },
	},
    },
    returns => {type => 'null' },
    code => sub {
	my ($param) = @_;

	my $remote = $param->{remote};
	my $id = $param->{'backup-id'};
	my $time = $param->{'backup-time'};

	my $conf = PMG::PBSConfig->new();
	my $remote_config = $conf->{ids}->{$remote};
	die "PBS remote '$remote' does not exist\n" if !$remote_config;
	die "PBS remote '$remote' is disabled\n" if $remote_config->{disable};

	my $pbs = PVE::PBSClient->new($remote_config, $remote, $conf->{secret_dir});

	eval { $pbs->forget_snapshot("host/$id/$time") };
	die "Forgetting backup failed: $@" if $@;

	return;

    }});

__PACKAGE__->register_method ({
    name => 'run_backup',
    path => '{remote}/snapshot',
    method => 'POST',
    description => "Create a new backup and prune the backup group afterwards, if configured.",
    proxyto => 'node',
    protected => 1,
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    remote => {
		description => "Proxmox Backup Server ID.",
		type => 'string', format => 'pve-configid',
	    },
	    statistic => {
		description => "Backup statistic databases.",
		type => 'boolean',
		optional => 1,
		default => 1,
	    },
	    notify => {
		description => "Specify when to notify via e-mail",
		type => 'string',
		enum => [ 'always', 'error', 'never' ],
		optional => 1,
		default => 'never',
	    },
	},
    },
    returns => { type => "string" },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();

	my $remote = $param->{remote};
	my $node = $param->{node};

	my $conf = PMG::PBSConfig->new();

	my $remote_config = $conf->{ids}->{$remote};
	die "PBS remote '$remote' does not exist\n" if !$remote_config;
	die "PBS remote '$remote' is disabled\n" if $remote_config->{disable};

	$param->{statistic} //= $remote_config->{'include-statistics'} // 1;
	my $notify = $param->{notify} // $remote_config->{notify} // 'never';

	my $pbs = PVE::PBSClient->new($remote_config, $remote, $conf->{secret_dir});

	my $time = time;
	my $backup_dir = "/tmp/pbsbackup_${remote}_$$.$time";

	my $worker = sub {
	    my $upid = shift;

	    my $full_log = "";
	    my $log = sub { print "$_[0]\n"; $full_log .= "$_[0]\n"; };

	    $log->("starting update of current backup state");

	    eval {
		-d $backup_dir || mkdir $backup_dir;
		PMG::Backup::pmg_backup($backup_dir, $param->{statistic});

		$pbs->backup_fs_tree($backup_dir, $node, 'pmgbackup');

		rmtree $backup_dir;
	    };
	    if (my $err = $@) {
		$log->($err);
		PMG::Backup::send_backup_notification($notify, $remote, $full_log, $err);
		rmtree $backup_dir;
		die "backup failed: $err\n";
	    }
	    $log->("backup finished");

	    my $group = "host/$node";
	    if (defined(my $prune_opts = $conf->prune_options($remote))) {
		$log->("starting prune of $group");
		my $res = eval { $pbs->prune_group(undef, $prune_opts, $group) };
		if (my $err = $@) {
		    $log->($err);
		    PMG::Backup::send_backup_notification($notify, $remote, $full_log, $err);
		    die "pruning failed: $err\n";
		}
		foreach my $pruned (@$res){
		    my $time = strftime("%FT%TZ", gmtime($pruned->{'backup-time'}));
		    my $snap = $pruned->{'backup-type'} . '/' . $pruned->{'backup-id'} . '/' .  $time;
		    $log->("pruned snapshot: $snap");
		}
		$log->("prune finished");
	    }

	    PMG::Backup::send_backup_notification($notify, $remote, $full_log, undef);

	    return;
	};

	return $rpcenv->fork_worker('pbs_backup', undef, $authuser, $worker);

    }});

__PACKAGE__->register_method ({
    name => 'restore',
    path => '{remote}/snapshot/{backup-id}/{backup-time}',
    method => 'POST',
    description => "Restore the system configuration.",
    permissions => { check => [ 'admin' ] },
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    PMG::Backup::get_restore_options(),
	    remote => {
		description => "Proxmox Backup Server ID.",
		type => 'string', format => 'pve-configid',
	    },
	    'backup-time' => {
		description=> "backup-time to restore",
		type => 'string'
	    },
	    'backup-id' => {
		description => "backup-id (hostname) of backup snapshot",
		type => 'string'
	    },
	},
    },
    returns => { type => "string" },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();

	my $remote = $param->{remote};
	my $id = $param->{'backup-id'};
	my $time = $param->{'backup-time'};
	my $snapshot = "host/$id/$time";

	my $conf = PMG::PBSConfig->new();

	my $remote_config = $conf->{ids}->{$remote};
	die "PBS remote '$remote' does not exist\n" if !$remote_config;
	die "PBS remote '$remote' is disabled\n" if $remote_config->{disable};

	my $pbs = PVE::PBSClient->new($remote_config, $remote, $conf->{secret_dir});

	my $now = time;
	my $dirname = "/tmp/proxrestore_$$.$now";

	$param->{database} //= 1;

	die "nothing selected - please select what you want to restore (config or database?)\n"
	    if !($param->{database} || $param->{config});

	my $worker = sub {
	    print "starting restore of $snapshot from $remote\n";

	    $pbs->restore_pxar($snapshot, 'pmgbackup', $dirname);
	    print "starting restore of PMG config\n";
	    PMG::Backup::pmg_restore(
		$dirname,
		$param->{database},
		$param->{config},
		$param->{statistic}
	    );
	    print "restore finished\n";
	};

	return $rpcenv->fork_worker('pbs_restore', undef, $authuser, $worker);
    }});

__PACKAGE__->register_method ({
    name => 'create_timer',
    path => '{remote}/timer',
    method => 'POST',
    description => "Create backup schedule",
    proxyto => 'node',
    protected => 1,
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    remote => {
		description => "Proxmox Backup Server ID.",
		type => 'string', format => 'pve-configid',
	    },
	    schedule => {
		description => "Schedule for the backup (OnCalendar setting of the systemd.timer)",
		type => 'string', pattern => '[0-9a-zA-Z*.:,\-/ ]+',
		default => 'daily', optional => 1,
	    },
	    delay => {
		description => "Randomized delay to add to the starttime (RandomizedDelaySec setting of the systemd.timer)",
		type => 'string', pattern => '[0-9a-zA-Z. ]+',
		default => '5min', optional => 1,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $remote = $param->{remote};
	my $schedule = $param->{schedule} // 'daily';
	my $delay = $param->{delay} // '5min';

	my $conf = PMG::PBSConfig->new();

	my $remote_config = $conf->{ids}->{$remote};
	die "PBS remote '$remote' does not exist\n" if !$remote_config;
	die "PBS remote '$remote' is disabled\n" if $remote_config->{disable};

	PMG::PBSSchedule::create_schedule($remote, $schedule, $delay);

    }});

__PACKAGE__->register_method ({
    name => 'delete_timer',
    path => '{remote}/timer',
    method => 'DELETE',
    description => "Delete backup schedule",
    proxyto => 'node',
    protected => 1,
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    remote => {
		description => "Proxmox Backup Server ID.",
		type => 'string', format => 'pve-configid',
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $remote = $param->{remote};

	PMG::PBSSchedule::delete_schedule($remote);

    }});

__PACKAGE__->register_method ({
    name => 'list_timer',
    path => '{remote}/timer',
    method => 'GET',
    description => "Get timer specification",
    proxyto => 'node',
    protected => 1,
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    remote => {
		description => "Proxmox Backup Server ID.",
		type => 'string', format => 'pve-configid',
	    },
	},
    },
    returns => {
	type => 'object',
	properties => {
	    remote => {
		description => "Proxmox Backup Server remote ID.",
		type => 'string', format => 'pve-configid',
		optional => 1,
	    },
	    schedule => {
		description => "Schedule for the backup (OnCalendar setting of the systemd.timer)",
		type => 'string', pattern => '[0-9a-zA-Z*.:,\-/ ]+',
		default => 'daily', optional => 1,
	    },
	    delay => {
		description => "Randomized delay to add to the starttime (RandomizedDelaySec setting of the systemd.timer)",
		type => 'string', pattern => '[0-9a-zA-Z. ]+',
		default => '5min', optional => 1,
	    },
	    'next-run' => {
		description => "The date time of the next run, in server locale.",
		type => 'string',
		optional => 1,
	    },
	    unitfile => {
		description => "unit file for the systemd.timer unit",
		type => 'string', optional => 1,
	    },
	}
    },
    code => sub {
	my ($param) = @_;

	my $remote = $param->{remote};

	my $schedules = PMG::PBSSchedule::get_schedules($remote);

	my $res = {};
	if (scalar(@$schedules) >= 1) {
	    $res = $schedules->[0];
	}

	return $res
    }});

1;
