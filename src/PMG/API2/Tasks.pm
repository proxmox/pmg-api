package PMG::API2::Tasks;

use strict;
use warnings;
use POSIX;
use IO::File;
use File::ReadBackwards;
use PVE::Tools;
use PVE::SafeSyslog;
use PVE::RESTHandler;
use PVE::ProcFSTools;
use PMG::RESTEnvironment;
use PVE::JSONSchema qw(get_standard_option);

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method({
    name => 'node_tasks',
    path => '',
    method => 'GET',
    description => "Read task list for one node (finished tasks).",
    proxyto => 'node',
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
	    userfilter => {
		type => 'string',
		optional => 1,
	    },
	    errors => {
		type => 'boolean',
		optional => 1,
	    },
	    typefilter => {
		type => 'string',
		optional => 1,
		description => 'Only list tasks of this type (e.g., aptupdate, saupdate).',
	    },
	    since => {
		type => 'integer',
		description => "Only list tasks since this UNIX epoch.",
		optional => 1,
	    },
	    until => {
		type => 'integer',
		description => "Only list tasks until this UNIX epoch.",
		optional => 1,
	    },
	    statusfilter => {
		type => 'string',
		format => 'pve-task-status-type-list',
		optional => 1,
		description => 'List of Task States that should be returned.',
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		upid => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{upid}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();

	my $res = [];

	my $filename = "/var/log/pve/tasks/index";

	my $node = $param->{node};
	my $start = $param->{start} || 0;
	my $limit = $param->{limit} || 50;
	my $userfilter = $param->{userfilter};
	my $typefilter = $param->{typefilter};
	my $since = $param->{since};
	my $until = $param->{until};
	my $errors = $param->{errors};

	my $statusfilter = {
	    ok => 1,
	    warning => 1,
	    error => 1,
	    unknown => 1,
	};

	if (defined($param->{statusfilter}) && !$errors) {
	    $statusfilter = {
		ok => 0,
		warning => 0,
		error => 0,
		unknown => 0,
	    };
	    for my $filter (PVE::Tools::split_list($param->{statusfilter})) {
		$statusfilter->{lc($filter)} = 1 ;
	    }
	} elsif ($errors) {
	    $statusfilter->{ok} = 0;
	}

	my $count = 0;
	my $line;

	my $parse_line = sub {
	    if ($line =~ m/^(\S+)(\s([0-9A-Za-z]{8})(\s(\S.*))?)?$/) {
		my $upid = $1;
		my $endtime = $3;
		my $status = $5;
		if ((my $task = PVE::Tools::upid_decode($upid, 1))) {
		    return if $userfilter && $task->{user} !~ m/\Q$userfilter\E/i;
		    return if defined($since) && $task->{starttime} < $since;
		    return if defined($until) && $task->{starttime} > $until;
		    return if $typefilter && $task->{type} ne $typefilter;

		    my $statustype = PVE::Tools::upid_normalize_status_type($status);
		    return if !$statusfilter->{$statustype};

		    return if $count++ < $start;
		    return if $limit <= 0;

		    $task->{upid} = $upid;
		    $task->{endtime} = hex($endtime) if $endtime;
		    $task->{status} = $status if $status;
		    push @$res, $task;
		    $limit--;
		}
	    }
	};

	if (my $bw = File::ReadBackwards->new($filename)) {
	    while (defined ($line = $bw->readline)) {
		&$parse_line();
	    }
	    $bw->close();
	}
	if (my $bw = File::ReadBackwards->new("$filename.1")) {
	    while (defined ($line = $bw->readline)) {
		&$parse_line();
	    }
	    $bw->close();
	}

	$restenv->set_result_attrib('total', $count);

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'upid_index',
    path => '{upid}',
    method => 'GET',
    description => '', # index helper
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    upid => { type => 'string' },
	}
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

	return [
	    { name => 'log' },
	    { name => 'status' }
	    ];
    }});

__PACKAGE__->register_method({
    name => 'stop_task',
    path => '{upid}',
    method => 'DELETE',
    description => 'Stop a task.',
    protected => 1,
    proxyto => 'node',
    permissions => { check => [ 'admin' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    upid => { type => 'string' },
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my ($task, $filename) = PVE::Tools::upid_decode($param->{upid}, 1);
	raise_param_exc({ upid => "unable to parse worker upid" }) if !$task;
	raise_param_exc({ upid => "no such task" }) if ! -f $filename;

	my $restenv = PMG::RESTEnvironment->get();
	PMG::RESTEnvironment->check_worker($param->{upid}, 1);

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'read_task_log',
    path => '{upid}/log',
    method => 'GET',
    protected => 1,
    description => "Read task log.",
    proxyto => 'node',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    upid => { type => 'string' },
	    start => {
		type => 'integer',
		minimum => 0,
		optional => 1,
		description => "Start at this line when reading the tasklog",
	    },
	    limit => {
		type => 'integer',
		minimum => 0,
		optional => 1,
		description => "The amount of lines to read from the tasklog.",
	    },
	    download => {
		type => 'boolean',
		optional => 1,
		description => "Whether the tasklog file should be downloaded. This parameter can't be used in conjunction with other parameters",
	    }
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

	my ($task, $filename) = PVE::Tools::upid_decode($param->{upid}, 1);
	raise_param_exc({ upid => "unable to parse worker upid" }) if !$task;

	my $restenv = PMG::RESTEnvironment->get();

	if ($param->{download}) {
	    die "Parameter 'download' can't be used with other parameters\n"
		if (defined($param->{start}) || defined($param->{limit}));

	    my $fh;
	    my $use_compression = ( -s $filename ) > 1024;

	    # 1024 is a practical cutoff for the size distribution of our log files.
	    if ($use_compression) {
		open($fh, "-|", "/usr/bin/gzip", "-c", "$filename")
		    or die "Could not create compressed file stream for file '$filename' - $!\n";
	    } else {
		open($fh, '<', $filename) or die "Could not open file '$filename' - $!\n";
	    }

	    my $task_time = strftime('%FT%TZ', gmtime($task->{starttime}));
	    my $download_name = 'task-'.$task->{node}.'-'.$task->{type}.'-'.$task_time.'.log';

	    return {
		download => {
		    fh => $fh,
		    stream => 1,
		    'content-encoding' => $use_compression ? 'gzip' : undef,
		    'content-type' => "text/plain",
		    'content-disposition' => "attachment; filename=\"".$download_name."\"",
		},
	    },
	} else {
	    my $start = $param->{start} // 0;
	    my $limit = $param->{limit} // 50;

	    my ($count, $lines) = PVE::Tools::dump_logfile($filename, $start, $limit);

	    $restenv->set_result_attrib('total', $count);

	    return $lines;
	}
    }});


my $exit_status_cache = {};

__PACKAGE__->register_method({
    name => 'read_task_status',
    path => '{upid}/status',
    method => 'GET',
    protected => 1,
    description => "Read task status.",
    proxyto => 'node',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    upid => { type => 'string' },
	},
    },
    returns => {
	type => "object",
	properties => {
	    pid => {
		type => 'integer'
	    },
	    status => {
		type => 'string', enum => ['running', 'stopped'],
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my ($task, $filename) = PVE::Tools::upid_decode($param->{upid}, 1);
	raise_param_exc({ upid => "unable to parse worker upid" }) if !$task;
	raise_param_exc({ upid => "no such task" }) if ! -f $filename;

	my $lines = [];

	my $pstart = PVE::ProcFSTools::read_proc_starttime($task->{pid});
	$task->{status} = ($pstart && ($pstart == $task->{pstart})) ?
	    'running' : 'stopped';

	$task->{upid} = $param->{upid}; # include upid

	if ($task->{status} eq 'stopped') {
	    if (!defined($exit_status_cache->{$task->{upid}})) {
		$exit_status_cache->{$task->{upid}} =
		    PVE::Tools::upid_read_status($task->{upid});
	    }
	    $task->{exitstatus} = $exit_status_cache->{$task->{upid}};
	}

	return $task;
    }});

1;
