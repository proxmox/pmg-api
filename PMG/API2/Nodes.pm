package PMG::API2::NodeInfo;

use strict;
use warnings;
use Time::Local qw(timegm_nocheck);
use Filesys::Df;
use Data::Dumper;

use PVE::INotify;
use PVE::RESTHandler;
use PVE::JSONSchema qw(get_standard_option);
use PMG::RESTEnvironment;
use PVE::SafeSyslog;
use PVE::ProcFSTools;

use PMG::pmgcfg;
use PMG::Ticket;
use PMG::Report;
use PMG::API2::Subscription;
use PMG::API2::APT;
use PMG::API2::Tasks;
use PMG::API2::Services;
use PMG::API2::Network;
use PMG::API2::ClamAV;
use PMG::API2::SpamAssassin;
use PMG::API2::Postfix;
use PMG::API2::MailTracker;
use PMG::API2::Backup;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Postfix",
    path => 'postfix',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::ClamAV",
    path => 'clamav',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::SpamAssassin",
    path => 'spamassassin',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Network",
    path => 'network',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Tasks",
    path => 'tasks',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Services",
    path => 'services',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Subscription",
    path => 'subscription',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::APT",
    path => 'apt',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::MailTracker",
    path => 'tracker',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Backup",
    path => 'backup',
});

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    permissions => { user => 'all' },
    description => "Node index.",
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
	links => [ { rel => 'child', href => "{name}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $result = [
	    { name => 'apt' },
	    { name => 'backup' },
	    { name => 'clamav' },
	    { name => 'spamassassin' },
	    { name => 'postfix' },
	    { name => 'services' },
	    { name => 'syslog' },
	    { name => 'journal' },
	    { name => 'tasks' },
	    { name => 'tracker' },
	    { name => 'time' },
	    { name => 'report' },
	    { name => 'status' },
	    { name => 'subscription' },
	    { name => 'termproxy' },
	    { name => 'rrddata' },
	];

	return $result;
    }});

__PACKAGE__->register_method({
    name => 'report',
    path => 'report',
    method => 'GET',
    protected => 1,
    proxyto => 'node',
    permissions => { check => [ 'admin', 'audit' ] },
    description => "Gather various system information about a node",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	return PMG::Report::generate();
    }});

__PACKAGE__->register_method({
    name => 'rrddata',
    path => 'rrddata',
    method => 'GET',
    protected => 1, # fixme: can we avoid that?
    proxyto => 'node',
    permissions => { check => [ 'admin', 'audit' ] },
    description => "Read node RRD statistics",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    timeframe => {
		description => "Specify the time frame you are interested in.",
		type => 'string',
		enum => [ 'hour', 'day', 'week', 'month', 'year' ],
	    },
	    cf => {
		description => "The RRD consolidation function",
		type => 'string',
		enum => [ 'AVERAGE', 'MAX' ],
		optional => 1,
	    },
	},
    },
    returns => {
	type => "array",
	items => {
	    type => "object",
	    properties => {},
	},
    },
    code => sub {
	my ($param) = @_;

	return PMG::Utils::create_rrd_data(
	    "pmg-node-v1.rrd", $param->{timeframe}, $param->{cf});
    }});


__PACKAGE__->register_method({
    name => 'syslog',
    path => 'syslog',
    method => 'GET',
    description => "Read system log",
    proxyto => 'node',
    protected => 1,
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    start => {
		type => 'integer',
		minimum => 0,
		optional => 1,
	    },
	    limit => {
		type => 'integer',
		minimum => 0,
		optional => 1,
	    },
	    since => {
		type => 'string',
		pattern => '^\d{4}-\d{2}-\d{2}( \d{2}:\d{2}(:\d{2})?)?$',
		description => "Display all log since this date-time string.",
		optional => 1,
	    },
	    'until' => {
		type => 'string',
		pattern => '^\d{4}-\d{2}-\d{2}( \d{2}:\d{2}(:\d{2})?)?$',
		description => "Display all log until this date-time string.",
		optional => 1,
	    },
	    service => {
		description => "Service ID",
		type => 'string',
		maxLength => 128,
		optional => 1,
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		n => {
		  description=>  "Line number",
		  type=> 'integer',
		},
		t => {
		  description=>  "Line text",
		  type => 'string',
		}
	    }
	}
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();

	my $service = $param->{service};
	$service = PMG::Utils::lookup_real_service_name($service)
	    if $service;

	my ($count, $lines) = PVE::Tools::dump_journal(
	    $param->{start}, $param->{limit},
	    $param->{since}, $param->{'until'}, $service);

	$restenv->set_result_attrib('total', $count);

	return $lines;
    }});

__PACKAGE__->register_method({
    name => 'journal',
    path => 'journal',
    method => 'GET',
    description => "Read Journal",
    proxyto => 'node',
    permissions => { check => [ 'admin', 'audit' ] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    since => {
		type=> 'number',
		description => "Display all log since this UNIX epoch.",
		optional => 1,
	    },
	    until => {
		type=> 'number',
		description => "Display all log until this UNIX epoch.",
		optional => 1,
	    },
	    lastentries => {
		description => "Limit to the last X lines.",
		type => 'integer',
		optional => 1,
	    },
	    startcursor => {
		description => "Start after the given Cursor.",
		type => 'string',
		optional => 1,
	    },
	    endcursor => {
		description => "End before the given Cursor.",
		type => 'string',
		optional => 1,
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "string",
	}
    },
    code => sub {
	my ($param) = @_;

	my $lines = [];

	my $parser = sub {
	    push @$lines, shift;
	};

	my $cmd = ["/usr/bin/mini-journalreader"];
	push @$cmd, '-n', $param->{lastentries} if $param->{lastentries};
	push @$cmd, '-b', $param->{since} if $param->{since};
	push @$cmd, '-e', $param->{until} if $param->{until};
	push @$cmd, '-f', $param->{startcursor} if $param->{startcursor};
	push @$cmd, '-t', $param->{endcursor} if $param->{endcursor};

	PVE::Tools::run_command($cmd, outfunc => $parser);

	return $lines;
    }});


__PACKAGE__->register_method ({
    name => 'termproxy',
    path => 'termproxy',
    method => 'POST',
    permissions => { check => [ 'admin' ] },
    protected => 1,
    description => "Creates a Terminal proxy.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    upgrade => {
		type => 'boolean',
		description => "Run 'apt-get dist-upgrade' instead of normal shell.",
		optional => 1,
		default => 0,
	    },
	},
    },
    returns => {
    	additionalProperties => 0,
	properties => {
	    user => { type => 'string' },
	    ticket => { type => 'string' },
	    port => { type => 'integer' },
	    upid => { type => 'string' },
	},
    },
    code => sub {
	my ($param) = @_;

	my $node = $param->{node};

	if ($node ne PVE::INotify::nodename()) {
	    die "termproxy to remote node not implemented";
	}

	my $authpath = "/nodes/$node";

	my $restenv = PMG::RESTEnvironment->get();
	my $user = $restenv->get_user();

	raise_perm_exc('user != root@pam') if $param->{upgrade} && $user ne 'root@pam';

	my $ticket = PMG::Ticket::assemble_vnc_ticket($user, $authpath);

	my $family = PVE::Tools::get_host_address_family($node);
	my $port = PVE::Tools::next_vnc_port($family);

	my $shcmd;

	if ($user eq 'root@pam') {
	    if ($param->{upgrade}) {
		my $upgradecmd = "pmgupgrade --shell";
		# $upgradecmd = PVE::Tools::shellquote($upgradecmd) if $remip;
		$shcmd = [ '/bin/bash', '-c', $upgradecmd ];
	    } else {
		$shcmd = [ '/bin/login', '-f', 'root' ];
	    }
	} else {
	    $shcmd = [ '/bin/login' ];
	}

	my $cmd = ['/usr/bin/termproxy', $port, '--path', $authpath,
		   '--', @$shcmd];

	my $realcmd = sub {
	    my $upid = shift;

	    syslog ('info', "starting termproxy $upid\n");

	    my $cmdstr = join (' ', @$cmd);
	    syslog ('info', "launch command: $cmdstr");

	    PVE::Tools::run_command($cmd);

	    return;
	};

	my $upid = $restenv->fork_worker('termproxy', "", $user, $realcmd);

	PVE::Tools::wait_for_vnc_port($port);

	return {
	    user => $user,
	    ticket => $ticket,
	    port => $port,
	    upid => $upid,
	};
    }});

__PACKAGE__->register_method({
    name => 'vncwebsocket',
    path => 'vncwebsocket',
    method => 'GET',
    permissions => { check => [ 'admin' ] },
    description => "Opens a weksocket for VNC traffic.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    vncticket => {
		description => "Ticket from previous call to vncproxy.",
		type => 'string',
		maxLength => 512,
	    },
	    port => {
		description => "Port number returned by previous vncproxy call.",
		type => 'integer',
		minimum => 5900,
		maximum => 5999,
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
	    port => { type => 'string' },
	},
    },
    code => sub {
	my ($param) = @_;

	my $authpath = "/nodes/$param->{node}";

	my $restenv = PMG::RESTEnvironment->get();
	my $user = $restenv->get_user();

	PMG::Ticket::verify_vnc_ticket($param->{vncticket}, $user, $authpath);

	my $port = $param->{port};

	return { port => $port };
    }});

__PACKAGE__->register_method({
    name => 'dns',
    path => 'dns',
    method => 'GET',
    description => "Read DNS settings.",
    proxyto => 'node',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => "object",
	additionalProperties => 0,
	properties => {
	    search => {
		description => "Search domain for host-name lookup.",
		type => 'string',
		optional => 1,
	    },
	    dns1 => {
		description => 'First name server IP address.',
		type => 'string',
		optional => 1,
	    },
	    dns2 => {
		description => 'Second name server IP address.',
		type => 'string',
		optional => 1,
	    },
	    dns3 => {
		description => 'Third name server IP address.',
		type => 'string',
		optional => 1,
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $res = PVE::INotify::read_file('resolvconf');

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'update_dns',
    path => 'dns',
    method => 'PUT',
    description => "Write DNS settings.",
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    search => {
		description => "Search domain for host-name lookup.",
		type => 'string',
	    },
	    dns1 => {
		description => 'First name server IP address.',
		type => 'string', format => 'ip',
		optional => 1,
	    },
	    dns2 => {
		description => 'Second name server IP address.',
		type => 'string', format => 'ip',
		optional => 1,
	    },
	    dns3 => {
		description => 'Third name server IP address.',
		type => 'string', format => 'ip',
		optional => 1,
	    },
	},
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	PVE::INotify::update_file('resolvconf', $param);

	return undef;
    }});


__PACKAGE__->register_method({
    name => 'time',
    path => 'time',
    method => 'GET',
    description => "Read server time and time zone settings.",
    proxyto => 'node',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => "object",
	additionalProperties => 0,
	properties => {
	    timezone => {
		description => "Time zone",
		type => 'string',
	    },
	    time => {
		description => "Seconds since 1970-01-01 00:00:00 UTC.",
		type => 'integer',
		minimum => 1297163644,
	    },
	    localtime => {
		description => "Seconds since 1970-01-01 00:00:00 (local time)",
		type => 'integer',
		minimum => 1297163644,
	    },
        },
    },
    code => sub {
	my ($param) = @_;

	my $ctime = time();
	my $ltime = timegm_nocheck(localtime($ctime));
	my $res = {
	    timezone => PVE::INotify::read_file('timezone'),
	    time => time(),
	    localtime => $ltime,
	};

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'set_timezone',
    path => 'time',
    method => 'PUT',
    description => "Set time zone.",
    proxyto => 'node',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    timezone => {
		description => "Time zone. The file '/usr/share/zoneinfo/zone.tab' contains the list of valid names.",
		type => 'string',
	    },
	},
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	PVE::INotify::write_file('timezone', $param->{timezone});

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'status',
    path => 'status',
    method => 'GET',
    description => "Read server status. This is used by the cluster manager to test the node health.",
    proxyto => 'node',
    permissions => { check => [ 'admin', 'qmanager', 'audit' ] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => "object",
	additionalProperties => 1,
	properties => {
	    time => {
		description => "Seconds since 1970-01-01 00:00:00 UTC.",
		type => 'integer',
		minimum => 1297163644,
	    },
	    uptime => {
		description => "The uptime of the system in seconds.",
		type => 'integer',
		minimum => 0,
	    },
	    insync => {
		description => "Database is synced with other nodes.",
		type => 'boolean',
	    },
        },
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();
	my $cinfo = $restenv->{cinfo};

	my $ctime = time();

	my $res = { time => $ctime, insync => 1 };

	my $si = PMG::DBTools::cluster_sync_status($cinfo);
	foreach my $cid (keys %$si) {
	    my $lastsync = $si->{$cid};
	    my $sdiff = $ctime - $lastsync;
	    $sdiff = 0 if $sdiff < 0;
	    $res->{insync} = 0 if $sdiff > (60*3);
	}

	my ($uptime, $idle) = PVE::ProcFSTools::read_proc_uptime();
	$res->{uptime} = $uptime;

	my ($avg1, $avg5, $avg15) = PVE::ProcFSTools::read_loadavg();
	$res->{loadavg} = [ $avg1, $avg5, $avg15];

	my ($sysname, $nodename, $release, $version, $machine) = POSIX::uname();

	$res->{kversion} = "$sysname $release $version";

	$res->{cpuinfo} = PVE::ProcFSTools::read_cpuinfo();

	my $stat = PVE::ProcFSTools::read_proc_stat();
	$res->{cpu} = $stat->{cpu};
	$res->{wait} = $stat->{wait};

	my $meminfo = PVE::ProcFSTools::read_meminfo();
	$res->{memory} = {
	    free => $meminfo->{memfree},
	    total => $meminfo->{memtotal},
	    used => $meminfo->{memused},
	};

	$res->{swap} = {
	    free => $meminfo->{swapfree},
	    total => $meminfo->{swaptotal},
	    used => $meminfo->{swapused},
	};

	$res->{pmgversion} = PMG::pmgcfg::package() . "/" .
	    PMG::pmgcfg::version_text();

	my $dinfo = df('/', 1); # output is bytes

	$res->{rootfs} = {
	    total => $dinfo->{blocks},
	    avail => $dinfo->{bavail},
	    used => $dinfo->{used},
	    free => $dinfo->{blocks} - $dinfo->{used},
	};

	if (my $subinfo = PVE::INotify::read_file('subscription')) {
	    if (my $level = $subinfo->{level}) {
		$res->{level} = $level;
	    }
	}

	return $res;
   }});

__PACKAGE__->register_method({
    name => 'node_cmd',
    path => 'status',
    method => 'POST',
    permissions => { check => [ 'admin' ] },
    protected => 1,
    description => "Reboot or shutdown a node.",
    proxyto => 'node',
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    command => {
		description => "Specify the command.",
		type => 'string',
		enum => [qw(reboot shutdown)],
	    },
	},
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	if ($param->{command} eq 'reboot') {
	    system ("(sleep 2;/sbin/reboot)&");
	} elsif ($param->{command} eq 'shutdown') {
	    system ("(sleep 2;/sbin/poweroff)&");
	}

	return undef;
    }});

package PMG::API2::Nodes;

use strict;
use warnings;

use PVE::RESTHandler;
use PVE::JSONSchema qw(get_standard_option);

use PMG::RESTEnvironment;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    subclass => "PMG::API2::NodeInfo",
    path => '{node}',
});

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    permissions => { user => 'all' },
    description => "Cluster node index.",
    parameters => {
    	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{node}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $nodename =  PVE::INotify::nodename();

	my $res = [ { node => $nodename } ];

	my $done = {};

	$done->{$nodename} = 1;

	my $restenv = PMG::RESTEnvironment->get();
	my $cinfo = $restenv->{cinfo};

	foreach my $ni (values %{$cinfo->{ids}}) {
	    push @$res, { node => $ni->{name} } if !$done->{$ni->{name}};
	    $done->{$ni->{name}} = 1;
	}

	return $res;
    }});


1;
