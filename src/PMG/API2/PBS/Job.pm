package PMG::API2::PBS::Job;

use strict;
use warnings;

use POSIX qw(strftime);

use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::PBSClient;

use PMG::RESTEnvironment;
use PMG::Backup;
use PMG::PBSConfig;

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
	if (defined($conf)) {
	    foreach my $remote (keys %{$conf->{ids}}) {
		my $d = $conf->{ids}->{$remote};
		my $entry = {
		    remote => $remote,
		    server => $d->{server},
		    datastore => $d->{datastore},
		};
		push @$res, $entry;
	    }
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
	    { section => 'snapshots' },
	    { section => 'backup' },
	    { section => 'restore' },
	    { section => 'timer' },
	];
	return $result;
}});

__PACKAGE__->register_method ({
    name => 'get_snapshots',
    path => '{remote}/snapshots',
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
		time => { type => 'string'},
		ctime => { type => 'string'},
		size => { type => 'integer'},
	    },
	},
	links => [ { rel => 'child', href => "{time}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $remote = $param->{remote};
	my $node = $param->{node};

	my $conf = PMG::PBSConfig->new();

	my $remote_config = $conf->{ids}->{$remote};
	die "PBS remote '$remote' does not exist\n" if !$remote_config;

	return [] if $remote_config->{disable};

	my $snap_param = {
	    group => "host/$node",
	};

	my $pbs = PVE::PBSClient->new($remote_config, $remote, $conf->{secret_dir});
	my $snapshots = $pbs->get_snapshots($snap_param);
	my $res = [];
	foreach my $item (@$snapshots) {
	    my $btype = $item->{"backup-type"};
	    my $bid = $item->{"backup-id"};
	    my $epoch = $item->{"backup-time"};
	    my $size = $item->{size} // 1;

	    my @pxar = grep { $_->{filename} eq 'pmgbackup.pxar.didx' } @{$item->{files}};
	    die "unexpected number of pmgbackup archives in snapshot\n" if (scalar(@pxar) != 1);


	    next if !($btype eq 'host');
	    next if !($bid eq $node);

	    my $time = strftime("%FT%TZ", gmtime($epoch));

	    my $info = {
		time => $time,
		ctime => $epoch,
		size => $size,
	    };

	    push @$res, $info;
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'forget_snapshot',
    path => '{remote}/snapshots/{time}',
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
	    time => {
		description => "Backup time in RFC 3399 format",
		type => 'string',
	    },
	},
    },
    returns => {type => 'null' },
    code => sub {
	my ($param) = @_;

	my $remote = $param->{remote};
	my $node = $param->{node};
	my $time = $param->{time};

	my $snapshot = "host/$node/$time";

	my $conf = PMG::PBSConfig->new();

	my $remote_config = $conf->{ids}->{$remote};
	die "PBS remote '$remote' does not exist\n" if !$remote_config;
	die "PBS remote '$remote' is disabled\n" if $remote_config->{disable};

	my $pbs = PVE::PBSClient->new($remote_config, $remote, $conf->{secret_dir});

	eval {
	    $pbs->forget_snapshot($snapshot);
	};
	die "Forgetting backup failed: $@" if $@;

	return;

    }});

__PACKAGE__->register_method ({
    name => 'run_backup',
    path => '{remote}/backup',
    method => 'POST',
    description => "run backup and prune the backupgroup afterwards.",
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

	my $pbs = PVE::PBSClient->new($remote_config, $remote, $conf->{secret_dir});
	my $backup_dir = "/var/lib/pmg/backup/current";

	my $worker = sub {
	    my $upid = shift;

	    print "starting update of current backup state\n";

	    -d $backup_dir || mkdir $backup_dir;
	    PMG::Backup::pmg_backup($backup_dir, $param->{statistic});
	    my $pbs_opts = {
		type => 'host',
		id => $node,
		pxarname => 'pmgbackup',
		root => $backup_dir,
	    };

	    $pbs->backup_tree($pbs_opts);

	    print "backup finished\n";

	    my $group = "host/$node";
	    print "starting prune of $group\n";
	    my $prune_opts = $conf->prune_options($remote);
	    my $res = $pbs->prune_group(undef, $prune_opts, $group);

	    foreach my $pruned (@$res){
		my $time = strftime("%FT%TZ", gmtime($pruned->{'backup-time'}));
		my $snap = $pruned->{'backup-type'} . '/' . $pruned->{'backup-id'} . '/' .  $time;
		print "pruned snapshot: $snap\n";
	    }

	    print "prune finished\n";

	    return;
	};

	return $rpcenv->fork_worker('pbs_backup', undef, $authuser, $worker);

    }});

__PACKAGE__->register_method ({
    name => 'restore',
    path => '{remote}/restore',
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
	    'backup-time' => {description=> "backup-time to restore",
		optional => 1, type => 'string'
	    },
	    'backup-id' => {description => "backup-id (hostname) of backup snapshot",
		optional => 1, type => 'string'
	    },
	},
    },
    returns => { type => "string" },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();

	my $remote = $param->{remote};
	my $backup_id = $param->{'backup-id'} // $param->{node};
	my $snapshot = "host/$backup_id";
	$snapshot .= "/$param->{'backup-time'}" if defined($param->{'backup-time'});

	my $conf = PMG::PBSConfig->new();

	my $remote_config = $conf->{ids}->{$remote};
	die "PBS remote '$remote' does not exist\n" if !$remote_config;
	die "PBS remote '$remote' is disabled\n" if $remote_config->{disable};

	my $pbs = PVE::PBSClient->new($remote_config, $remote, $conf->{secret_dir});

	my $time = time;
	my $dirname = "/tmp/proxrestore_$$.$time";

	$param->{database} //= 1;

	die "nothing selected - please select what you want to restore (config or database?)\n"
	    if !($param->{database} || $param->{config});

	my $pbs_opts = {
	    pxarname => 'pmgbackup',
	    target => $dirname,
	    snapshot => $snapshot,
	};

	my $worker = sub {
	    my $upid = shift;

	    print "starting restore of $snapshot from $remote\n";

	    $pbs->restore_pxar($pbs_opts);
	    print "starting restore of PMG config\n";
	    PMG::Backup::pmg_restore($dirname, $param->{database},
		 $param->{config}, $param->{statistic});
	    print "restore finished\n";

	    return;
	};

	return $rpcenv->fork_worker('pbs_restore', undef, $authuser, $worker);
    }});

1;
