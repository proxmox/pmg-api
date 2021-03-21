package PMG::Service::pmgmirror;

use strict;
use warnings;
use Data::Dumper;
use Time::HiRes qw (gettimeofday tv_interval);

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::INotify;
use PVE::Daemon;
use PVE::ProcFSTools;

use PMG::Ticket;
use PMG::RESTEnvironment;
use PMG::DBTools;
use PMG::RuleDB;
use PMG::Cluster;
use PMG::ClusterConfig;
use PMG::Statistic;
use PMG::Utils;

use base qw(PVE::Daemon);

my $cmdline = [$0, @ARGV];

my %daemon_options = (restart_on_error => 5, stop_wait_time => 5);

my $daemon = __PACKAGE__->new('pmgmirror', $cmdline, %daemon_options);

my $restart_request = 0;
my $next_update = 0;

my $cycle = 0;
my $updatetime = 60*2;
my $maxtimediff = 5;

my $initial_memory_usage;

sub init {
    # syslog('INIT');
}

sub hup {
    my ($self) = @_;

    $restart_request = 1;
}

sub sync_data_from_node {
    my ($dbh, $rdb, $cinfo, $ni, $ticket, $rsynctime_ref) = @_;

    my $ctime = PMG::DBTools::get_remote_time($rdb);
    my $ltime = time();

    my $timediff = abs($ltime - $ctime);
    if ($timediff > $maxtimediff) {
	die "large time difference (> $timediff seconds) - not syncing\n";
    }

    if ($ni->{type} eq 'master') {
	PMG::Cluster::sync_ruledb_from_master($dbh, $rdb, $ni, $ticket);
	PMG::Cluster::sync_deleted_nodes_from_master($dbh, $rdb, $cinfo, $ni, $rsynctime_ref);
    }

    PMG::Cluster::sync_quarantine_db($dbh, $rdb, $ni, $rsynctime_ref);

    PMG::Cluster::sync_greylist_db($dbh, $rdb, $ni);

    PMG::Cluster::sync_userprefs_db($dbh, $rdb, $ni);

    PMG::Cluster::sync_statistic_db($dbh, $rdb, $ni);

    if ($ni->{type} eq 'master') {
	PMG::Cluster::sync_domainstat_db($dbh, $rdb, $ni);

	PMG::Cluster::sync_dailystat_db($dbh, $rdb, $ni);

	PMG::Cluster::sync_virusinfo_db($dbh, $rdb, $ni);
    }

    PMG::Cluster::sync_localstat_db($dbh, $rdb, $ni);
}

sub cluster_sync {

    my $cinfo = PMG::ClusterConfig->new(); # reload
    my $role = $cinfo->{local}->{type} // '-';

    return if $role eq '-';
    return if !$cinfo->{master}; # just to be sure

    my $start_time = [ gettimeofday() ];

    syslog ('info', "starting cluster synchronization");

    my $master_ip = $cinfo->{master}->{ip};
    my $master_name = $cinfo->{master}->{name};

    my $force_restart = {};
    if ($role ne 'master') {
	$force_restart = PMG::Cluster::sync_config_from_master($master_name, $master_ip);
    }

    my $csynctime = tv_interval($start_time);

    $cinfo = PMG::ClusterConfig->new(); # reload
    $role = $cinfo->{local}->{type} // '-';

    return if $role eq '-';
    return if !$cinfo->{master}; # just to be sure

    my $ticket = PMG::Ticket::assemble_ticket('root@pam');

    my $dbh = PMG::DBTools::open_ruledb();

    my $errcount = 0;

    my $rsynctime = 0;

    my $sync_node = sub {
	my ($ni) = @_;

	my $rdb;
	eval {
	    $rdb = PMG::DBTools::open_ruledb(undef, '/run/pmgtunnel', $ni->{cid});
	    sync_data_from_node($dbh, $rdb, $cinfo, $ni, $ticket, \$rsynctime);
	};
	my $err = $@;

	$rdb->disconnect() if $rdb;

	if ($err) {
	    $errcount++;
	    syslog ('err', "database sync '$ni->{name}' failed - $err");
	} else {
	    PMG::DBTools::create_clusterinfo_default($dbh, $ni->{cid}, 'lastsync', 0, undef);
	    PMG::DBTools::write_maxint_clusterinfo($dbh, $ni->{cid}, 'lastsync', time());
	}
    };

    # sync data from master first
    if ($cinfo->{master}->{cid} ne $cinfo->{local}->{cid}) {
	$sync_node->($cinfo->{master});

	# rewrite config after sync from master
	my $cfg = PMG::Config->new();
	my $ruledb = PMG::RuleDB->new($dbh);
	my $rulecache = PMG::RuleCache->new($ruledb);
	$cfg->rewrite_config($rulecache, 1);
    }

    foreach my $ni (values %{$cinfo->{ids}}) {
	next if $ni->{cid} eq $cinfo->{local}->{cid};
	next if $ni->{cid} eq $cinfo->{master}->{cid};
	$sync_node->($ni);
    }

    $dbh->disconnect();

    my $cptime = tv_interval($start_time);

    my $dbtime = $cptime - $rsynctime - $csynctime;

    syslog('info', sprintf("cluster synchronization finished  (%d errors, %.2f seconds " .
			   "(files %.2f, database %.2f, config %.2f))",
			   $errcount, $cptime, $rsynctime, $dbtime, $csynctime));

    foreach my $service (keys %$force_restart) {
	PMG::Utils::service_cmd($service, 'restart');
    }
}

sub run {
    my ($self) = @_;

    for (;;) { # forever

	$next_update = time() + $updatetime;

	eval {
	    # Note: do nothing in first cycle (give pmgtunnel some time to startup)
	    cluster_sync() if $cycle > 0;
	};
	if (my $err = $@) {
	    syslog('err', "sync error: $err");
	}

	$cycle++;

	last if $self->{terminate};

	my $mem = PVE::ProcFSTools::read_memory_usage();

	if (!defined($initial_memory_usage) || ($cycle < 10)) {
	    $initial_memory_usage = $mem->{resident};
	} else {
	    my $diff = $mem->{resident} - $initial_memory_usage;
	    if ($diff > 5*1024*1024) {
		syslog ('info', "restarting server after $cycle cycles to " .
			"reduce memory usage (free $mem->{resident} ($diff) bytes)");
		$self->restart_daemon();
	    }
	}

	my $wcount = 0;
	while ((time() < $next_update) &&
	       ($wcount < $updatetime) && # protect against time wrap
	       !$restart_request && !$self->{terminate}) {

	    $wcount++; sleep (1);
	};

	last if $self->{terminate};

	$self->restart_daemon() if $restart_request;
    }
}

$daemon->register_start_command("Start the Database Mirror Daemon");
$daemon->register_stop_command("Stop the Database Mirror Daemon");
$daemon->register_restart_command(1, "Restart the Database Mirror Daemon");

our $cmddef = {
    start => [ __PACKAGE__, 'start', []],
    restart => [ __PACKAGE__, 'restart', []],
    stop => [ __PACKAGE__, 'stop', []],
};

1;
