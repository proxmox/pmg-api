package PMG::CLI::pmgcm;

use strict;
use warnings;
use Data::Dumper;
use Term::ReadLine;
use POSIX qw(strftime);
use JSON;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::INotify;
use PVE::CLIHandler;

use PMG::Utils;
use PMG::Ticket;
use PMG::RESTEnvironment;
use PMG::DBTools;
use PMG::RuleDB;
use PMG::RuleCache;
use PMG::Cluster;
use PMG::ClusterConfig;
use PMG::API2::Cluster;

use base qw(PVE::CLIHandler);

sub setup_environment {
    PMG::RESTEnvironment->setup_default_cli_env();

    my $rpcenv = PMG::RESTEnvironment->get();
    # API /config/cluster/nodes need a ticket to connect to other nodes
    my $ticket = PMG::Ticket::assemble_ticket('root@pam');
    $rpcenv->set_ticket($ticket);
}

my $upid_exit = sub {
    my $upid = shift;
    my $status = PVE::Tools::upid_read_status($upid);
    exit($status eq 'OK' ? 0 : -1);
};

my $format_nodelist = sub {
    my $res = shift;

    if (!scalar(@$res)) {
	print "no cluster defined\n";
	return;
    }

    print "NAME(CID)--------------IPADDRESS----ROLE-STATE---------UPTIME---LOAD----MEM---DISK\n";
    foreach my $ni (@$res) {
	my $state = 'A';
	$state = 'S' if !$ni->{insync};

	if (my $err = $ni->{conn_error}) {
	    $err =~ s/\n/ /g;
	    $state = "ERROR: $err";
	}

	my $uptime = $ni->{uptime} ? PMG::Utils::format_uptime($ni->{uptime}) : '-';

	my $loadavg1 = '-';
	if (my $d = $ni->{loadavg}) {
	    $loadavg1 = $d->[0];
	}

	my $mem = '-';
	if (my $d = $ni->{memory}) {
	    $mem = int(0.5 + ($d->{used}*100/$d->{total}));
	}
	my $disk = '-';
	if (my $d = $ni->{rootfs}) {
	    $disk = int(0.5 + ($d->{used}*100/$d->{total}));
	}

	printf "%-20s %-15s %-6s %1s %15s %6s %5s%% %5s%%\n",
	"$ni->{name}($ni->{cid})", $ni->{ip}, $ni->{type},
	$state, $uptime, $loadavg1, $mem, $disk;
    }
};

__PACKAGE__->register_method({
    name => 'join_cmd',
    path => 'join_cmd',
    method => 'GET',
    description => "Prints the command for joining an new node to the cluster. You need to execute the command on the new node.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $cinfo = PMG::ClusterConfig->new();

	if (scalar(keys %{$cinfo->{ids}})) {

	    my $master = $cinfo->{master} ||
		die "no master found\n";

	    print "pmgcm join $master->{ip} --fingerprint $master->{fingerprint}\n";

	} else {
	    die "no cluster defined\n";
	}

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'delete',
    path => 'delete',
    method => 'GET',
    description => "Remove a node from the cluster.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    cid => {
		description => "Cluster Node ID.",
		type => 'integer',
		minimum => 1,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {
	    my $cinfo = PMG::ClusterConfig->new();

	    die "no cluster defined\n" if !scalar(keys %{$cinfo->{ids}});

	    my $master = $cinfo->{master} || die "unable to lookup master node\n";

	    die "operation not permitted (not master)\n"
		if $cinfo->{local}->{cid} != $master->{cid};

	    my $cid = $param->{cid};

	    die "unable to delete master node\n"
		if $cinfo->{local}->{cid} == $cid;

	    die "no such node (cid == $cid does not exists)\n" if !$cinfo->{ids}->{$cid};

	    delete $cinfo->{ids}->{$cid};

	    $cinfo->write();
	};

	PMG::ClusterConfig::lock_config($code, "delete cluster node failed");

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'join',
    path => 'join',
    method => 'GET',
    description => "Join a new node to an existing cluster.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    master_ip => {
		description => "IP address.",
		type => 'string', format => 'ip',
	    },
	    fingerprint => {
		description => "SSL certificate fingerprint.",
		type => 'string',
		pattern => '^(:?[A-Z0-9][A-Z0-9]:){31}[A-Z0-9][A-Z0-9]$',
		optional => 1,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {
	    my $cinfo = PMG::ClusterConfig->new();

	    die "cluster already defined\n" if scalar(keys %{$cinfo->{ids}});

	    my $term = new Term::ReadLine ('pmgcm');
	    my $attribs = $term->Attribs;
	    $attribs->{redisplay_function} = $attribs->{shadow_redisplay};
	    my $password = $term->readline('Enter password: ');

	    my $setup = {
		username => 'root@pam',
		password => $password,
		cookie_name => 'PMGAuthCookie',
		host => $param->{master_ip},
	    };
	    if ($param->{fingerprint}) {
		$setup->{cached_fingerprints} = {
		    $param->{fingerprint} => 1,
		};
	    } else {
		# allow manual fingerprint verification
		$setup->{manual_verification} = 1;
	    }

	    PMG::API2::Cluster::cluster_join($cinfo, $setup);
	};

	PMG::ClusterConfig::lock_config($code, "cluster join failed");

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'sync',
    path => 'sync',
    method => 'GET',
    description => "Synchronize cluster configuration.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    master_ip => {
		description => 'Optional IP address for master node.',
		type => 'string', format => 'ip',
		optional => 1,
	    }
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $cinfo = PMG::ClusterConfig->new();

        my $master_name = undef;
	my $master_ip = $param->{master_ip};

	if (!$master_ip && $cinfo->{master}) {
	    $master_ip = $cinfo->{master}->{ip};
	    $master_name = $cinfo->{master}->{name};
	}

	die "no master IP specified (use option --master_ip)\n" if !$master_ip;

	if ($cinfo->{local}->{ip} eq $master_ip) {
	    print STDERR "local node is master - nothing to do\n";
	    return undef;
	}

	print STDERR "syncing master configuration from '${master_ip}'\n";

	my $restart = PMG::Cluster::sync_config_from_master($master_name, $master_ip);

	my $cfg = PMG::Config->new();

	$cfg->rewrite_config(undef, 1);

	if (scalar(keys %$restart)) {
	    print "please restart the following daemons:\n";
	    for my $service (sort keys %$restart) {
		print "$service\n"
	    }
	}

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'promote',
    path => 'promote',
    method => 'POST',
    description => "Promote current node to become the new master.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {
	    my $cinfo = PMG::ClusterConfig->new();

	    die "no cluster defined\n" if !scalar(keys %{$cinfo->{ids}});

	    my $master = $cinfo->{master} || die "unable to lookup master node\n";

	    die "this node is already master\n"
		if $cinfo->{local}->{cid} == $master->{cid};

	    my $maxcid = $master->{maxcid};
	    $master->{type} = 'node';

	    my $newmaster = $cinfo->{local};

	    $newmaster->{maxcid} = $maxcid;
	    $newmaster->{type} = 'master';

	    $cinfo->{master} = $newmaster;

	    $cinfo->write();
	};

	PMG::ClusterConfig::lock_config($code, "promote new master failed");

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'update_fingerprints',
    path => 'update-fingerprints',
    method => 'POST',
    description => "Notify master to refresh all certificate fingerprints",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $cinfo = PMG::ClusterConfig->new();
	if (!scalar(keys %{$cinfo->{ids}})) {
	    warn "no cluster defined, nothing to do...\n";
	    return undef;
	}

	PMG::Cluster::trigger_update_fingerprints($cinfo);
    }});

our $cmddef = {
    status => [ 'PMG::API2::Cluster', 'status', [], {}, $format_nodelist],
    create => [ 'PMG::API2::Cluster', 'create', [], {}, $upid_exit],
    delete => [ __PACKAGE__, 'delete', ['cid']],
    join => [ __PACKAGE__, 'join', ['master_ip']],
    'join-cmd' => [ __PACKAGE__, 'join_cmd', []],
    join_cmd => { alias => 'join-cmd' },
    sync => [ __PACKAGE__, 'sync', []],
    promote => [ __PACKAGE__, 'promote', []],
    'update-fingerprints' => [ __PACKAGE__, 'update_fingerprints'],
};

1;
