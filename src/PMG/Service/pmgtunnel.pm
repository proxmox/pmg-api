package PMG::Service::pmgtunnel;

use strict;
use warnings;
use Data::Dumper;
use Time::HiRes qw (gettimeofday);

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::INotify;
use PVE::Daemon;

use PMG::RESTEnvironment;
use PMG::DBTools;
use PMG::RuleDB;
use PMG::Cluster;
use PMG::ClusterConfig;
use PMG::Statistic;

use base qw(PVE::Daemon);

my $cmdline = [$0, @ARGV];

my %daemon_options = (restart_on_error => 5, stop_wait_time => 5);

my $daemon = __PACKAGE__->new('pmgtunnel', $cmdline, %daemon_options);

my $restart_request = 0;
my $next_update = 0;

my $cycle = 0;
my $updatetime = 10;

my $workers = {};
my $delayed_exec = {};
my $startcount = {};

my $socketdir = "/run/pmgtunnel";

my $socketfile = sub {
    my ($cid) = @_;
    return "$socketdir/.s.PGSQL.$cid";
};

sub finish_children {
    while ((my $cpid = waitpid(-1, POSIX::WNOHANG())) > 0) {
	if (defined($workers->{$cpid})) {
	    my $ip = $workers->{$cpid}->{ip};
	    my $cid = $workers->{$cpid}->{cid};
	    syslog('err', "tunnel finished $cpid $ip");
	    unlink $socketfile->($cid);
	    $delayed_exec->{$cid} = time + ($startcount->{$cid} > 5 ? 60 : 10);
	    delete $workers->{$cpid};
	}
    }
}

sub start_tunnels {
    my ($self, $cinfo) = @_;

    my $role = $cinfo->{local}->{type} // '-';
    return if $role eq '-';

    foreach my $cid (keys %{$cinfo->{ids}}) {
	my $ni = $cinfo->{ids}->{$cid};
	next if $ni->{ip} eq $cinfo->{local}->{ip}; # just to be sure

	my $running;
	foreach my $cpid (keys %$workers) {
	    $running = 1 if $workers->{$cpid}->{ip} eq  $ni->{ip};
	}
	next if $running;

	if ($delayed_exec->{$cid} && (time < $delayed_exec->{$cid})) {
	    next;
	}
	$delayed_exec->{$cid} = 0;
	$startcount->{$cid}++;

	my $pid = fork;

	if (!defined ($pid)) {

	    syslog('err', "can't fork tunnel");

	} elsif($pid) { # parent

	    $workers->{$pid}->{ip} = $ni->{ip};
	    $workers->{$pid}->{cid} = $cid;

	    if ($startcount->{$cid} > 1) {
		syslog('info', "restarting crashed tunnel $pid $ni->{ip}");
	    } else {
		syslog('info', "starting tunnel $pid $ni->{ip}");
	    }

	} else { # child

	    $self->after_fork_cleanup();

	    mkdir $socketdir;
	    my $sock = $socketfile->($cid);
	    unlink $sock;
	    exec('/usr/bin/ssh', '-N', '-o', 'BatchMode=yes',
		 '-o', "HostKeyAlias=$ni->{name}",
		 '-L', "$sock:/var/run/postgresql/.s.PGSQL.5432",
		 $ni->{ip});
	    exit (0);
	}
    }
}

sub purge_tunnels {
    my ($self, $cinfo) = @_;

    foreach my $cpid (keys %$workers) {
	my $ip = $workers->{$cpid}->{ip};
	my $cid = $workers->{$cpid}->{cid};

	my $found;
	foreach my $ni (values %{$cinfo->{ids}}) {
	    $found = 1 if ($ni->{ip} eq $ip) && ($ni->{cid} eq $cid);
	}

	my $role = $cinfo->{local}->{type} // '-';
	$found = 0 if $role eq '-';

	if (!$found) {
	    syslog ('info', "trying to finish tunnel $cpid $ip");
	    kill(15, $cpid);
	    $delayed_exec->{$cid} = time + ($startcount->{$cid} > 5 ? 60 : 10);
	    delete $workers->{$cpid};
	}
    }
}

sub init {
    # syslog('INIT');
}

sub shutdown {
    my ($self) = @_;

    syslog('info' , "server closing");

    foreach my $cpid (keys %$workers) {
	if (kill (15, $cpid) || ! kill(0, $cpid)) {
	    my $ip = $workers->{$cpid}->{ip};
	    delete $workers->{$cpid};
	    syslog ('info', "successfully deleted tunnel $cpid $ip");
	}
    }

    # wait for children
    1 while (waitpid(-1, POSIX::WNOHANG()) > 0);

 #   $self->exit_daemon(0);
}

sub hup {
    my ($self) = @_;

    $restart_request = 1;
}



sub run {
    my ($self) = @_;

    local $SIG{CHLD} = \&finish_children;

    for (;;) { # forever

	$next_update = time() + $updatetime;

	eval {
	    my $cinfo = PMG::ClusterConfig->new(); # reload
	    $self->purge_tunnels($cinfo);
	    $self->start_tunnels($cinfo);
	};

	if (my $err = $@) {

	    syslog('err', "status update error: $err");
	}

	my $wcount = 0;
	while ((time() < $next_update) &&
	       ($wcount < $updatetime) && # protect against time wrap
	       !$restart_request && !$self->{terminate}) {

	    finish_children();

	    $wcount++; sleep (1);
	};

	last if $self->{terminate};

	$self->restart_daemon() if $restart_request;
    }
}

__PACKAGE__->register_method ({
    name => 'status',
    path => 'status',
    method => 'GET',
    description => "Print cluster tunnel status.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $status = $daemon->running() ? 'running' : 'stopped';
	print "$status\n";

	return undef;
    }});


$daemon->register_start_command("Start the Cluster Tunnel Daemon");
$daemon->register_stop_command("Stop the Cluster Tunnel Daemon");
$daemon->register_restart_command(1, "Restart the Cluster Tunnel Daemon");

our $cmddef = {
    start => [ __PACKAGE__, 'start', []],
    restart => [ __PACKAGE__, 'restart', []],
    stop => [ __PACKAGE__, 'stop', []],
    status => [ __PACKAGE__, 'status', []]
};

1;
