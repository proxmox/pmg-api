package PMG::API2::MailTracker;

use strict;
use warnings;

use Data::Dumper;
use Digest::MD5;
use Encode;
use POSIX;
use Time::Zone;

use PVE::Exception qw(raise_param_exc);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::SafeSyslog;
use PVE::Tools;

use PMG::RESTEnvironment;

use base qw(PVE::RESTHandler);

my $get_start_end_time = sub {
    my ($param) = @_;
    my $start = $param->{starttime} // (time - 86400);
    my $end = $param->{endtime} // ($start + 86400);
    raise_param_exc({'endtime' => "must be newer than 'starttime'"}) if $start > $end;
    return ($start, $end);
};

my $statmap = {
    2 => 'delivered',
    4 => 'deferred',
    5 => 'bounced',
    N => 'rejected',
    G => 'greylisted',
    A => 'accepted',
    B => 'blocked',
    Q => 'quarantine',
};

my $run_pmg_log_tracker = sub {
    my ($args, $includelog) = @_;

    my $logids = {};

    if (defined(my $id = $includelog)) {
	if ($id =~ m/^Q([a-f0-9]+)R([a-f0-9]+)$/i) {
	    $logids->{$1} = 1;
	    $logids->{$2} = 1;
	    push @$args, '-q', $1, '-q', $2;
	} else {
	    $logids->{$id} = 1;
	    push @$args, '-q', $id;
	}
    }

    my $lookup_hash = {};
    my $list = [];
    my $state = 'start';
    my $status;
    my $entry;
    my $logs = [];

    my $parser = sub {
	my ($line) = @_;

	# assume syslog is UTF-8 encoded
	$line = decode('UTF-8', $line);

	if ($state eq 'start') {

	    return if $line =~ m/^\#/;
	    return if $line =~ m/^\s*$/;

	    if ($line =~ m/^STATUS: (.*)$/) {
		$state = 'end';
		$status = $1;
		return;
	    }

	    if ($line =~ m/^SMTPD:\s+(T[0-9A-F]+L[0-9A-F]+)$/) {
		$state = 'smtp';
		$entry = { id => $1 };
		return;
	    }

	    if ($line =~ m/^QENTRY:\s+([0-9A-F]+)$/) {
		$state = 'qentry';
		$entry = { qid => $1 };
		return;
	    }

	    die "got unexpected data: $line";
	} elsif ($state eq 'end') {
	    die "got unexpected data after status: $line";
	} elsif ($state eq 'skiplogs') {
	    if ($line =~  m/^\s*$/) {
		$entry = undef;
		$state = 'start';
	    } else {
		# skip
	    }
	} elsif ($state eq 'logs') {
	    if ($line =~  m/^\s*$/) {
		$entry = undef;
		$state = 'start';
	    } elsif ($line =~ m/^(SMTP|FILTER|QMGR):/) {
		# skip
	    } elsif ($line =~ m/^(L[A-F0-9]+)\s(.*)$/) {
		push @$logs, { linenr => $1, text => $2 };
	    } else {
		die "got unexpected data: $line";
	    }
	} elsif ($state eq 'qentry') {
	    if ($line =~  m/^\s*$/) {
		$entry = undef;
		$state = 'start';
	    } elsif ($line =~ m/^SIZE:\s+(\d+)$/) {
		$entry->{size} = $1;
	    } elsif ($line =~ m/^CLIENT:\s+(\S+)$/) {
		$entry->{client} = $1;
	    } elsif ($line =~ m/^MSGID:\s+(\S+)$/) {
		$entry->{msgid} = $1;
	    } elsif ($line =~ m/^CTIME:\s+([0-9A-F]+)$/) {
		# ignore ?
	    } elsif ($line =~ m/^TO:([0-9A-F]+):([0-9A-F]+):([0-9A-Z]):\s+from <([^>]*)>\s+to\s+<([^>]+)>\s+\((\S+)\)$/) {
		my $new = {
		    size => $entry->{size} // 0,
		    time => hex($1),
		    qid => $2,
		    dstatus => $3,
		    from => $4,
		    to => $5,
		    relay => $6,
		};
		$new->{client} = $entry->{client} if defined($entry->{client});
		$new->{msgid} = $entry->{msgid} if defined($entry->{msgid});

		my $dstatus = $new->{dstatus};
		if ($dstatus =~ /P|D|R/) {
		    my $before_queue_status = {
			P => '2',
			D => '4',
			R => '5',
		    };
		    $new->{dstatus} = 'A';
		    $new->{rstatus} = $before_queue_status->{$dstatus};
		}

		push @$list, $new;

		my ($qid, $to) = $new->@{'qid', 'to'};
		$lookup_hash->{$qid}->{$to} = $new;
	    } elsif ($line =~ m/^(SMTP|FILTER|QMGR):/) {
		if ($logids->{$entry->{qid}}) {
		    $state = 'logs';
		} else {
		    $state = 'skiplogs';
		}
	    } else {
		die "got unexpected data: $line";
	    }
	} elsif ($state eq 'smtp') {

	    if ($line =~  m/^\s*$/) {
		$entry = undef;
		$state = 'start';
	    } elsif  ($line =~ m/^CLIENT:\s+(\S+)$/) {
		$entry->{client} = $1;
	    } elsif ($line =~ m/^CTIME:\s+([0-9A-F]+)$/) {
		# ignore ?
	    } elsif ($line =~ m/^TO:([0-9A-F]+):(T[0-9A-F]+L[0-9A-F]+):([0-9A-Z]):\s+from <([^>]*)>\s+to\s+<([^>]*)>$/) {
		my $e = {};
		$e->{client} = $entry->{client} if defined($entry->{client});
		$e->{time} = hex($1);
		$e->{id} = $2;
		$e->{dstatus} = $3;
		$e->{from} = $4;
		die "empty to address only allowed in NOQUEUE case\n" if !$5 && $e->{dstatus} ne 'N';
		$e->{to} = $5;
		push @$list, $e;
	    } elsif ($line =~ m/^LOGS:$/) {
		if ($logids->{$entry->{id}}) {
		    $state = 'logs';
		} else {
		    $state = 'skiplogs';
		}
	    } else {
		die "got unexpected data: $line";
	    }
	} else {
	    die "unknown state '$state'\n";
	}
    };

    my $cmd = ['/usr/bin/pmg-log-tracker', '-v', '-l', 2000];

    PVE::Tools::run_command([@$cmd, @$args], timeout => 25, outfunc => $parser);

    my $sorted_logs = [];
    foreach my $le (sort {$a->{linenr} cmp $b->{linenr}} @$logs) {
	push @$sorted_logs, $le->{text};
    }

    foreach my $e (@$list) {
	if (my $id = $e->{qid}) {
	    if (my $relay = $e->{relay}) {
		if (my $ref = $lookup_hash->{$relay}->{$e->{to}}) {
		    $ref->{is_relay} = 1;
		    $id = 'Q' . $e->{qid} . 'R' . $e->{relay};
		    if ($e->{dstatus} eq 'A') {
			$e->{rstatus} = $ref->{dstatus};
		    }
		}
	    }
	    $e->{id} = $id;
	}
	if ($includelog && ($e->{id} eq $includelog)) {
	    $e->{logs} = $sorted_logs;
	}
    }

    return wantarray ? ($list, $status) : $list;
};

my $email_log_property_desc = {
    id => {
	description => "Unique ID.",
	type => 'string',
    },
    from => {
	description => "Sender email address.",
	type => 'string',
    },
    to => {
	description => "Receiver email address.",
	type => 'string',
    },
    qid => {
	description => "Postfix qmgr ID.",
	type => 'string',
	optional => 1,
    },
    time => {
	description => "Delivery timestamp.",
	type => 'integer',
    },
    dstatus => {
	description => "Delivery status.",
	type => 'string',
	minLength => 1,
	maxLength => 1,
    },
    rstatus => {
	description => "Delivery status of relayed mail.",
	type => 'string',
	minLength => 1,
	maxLength => 1,
	optional => 1,
    },
    relay => {
	description => "ID of relayed mail.",
	type => 'string',
	optional => 1,
    },
    size => {
	description => "The size of the raw email.",
	type => 'number',
	optional => 1,
    },
    client => {
	description => "Client address",
	type => 'string',
	optional => 1,
    },
    msgid => {
	description => "SMTP message ID.",
	type => 'string',
	optional => 1,
    },
};

__PACKAGE__->register_method({
    name => 'list_mails',
    path => '',
    method => 'GET',
    description => "Read mail list.",
    proxyto => 'node',
    protected => 1,
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    starttime => get_standard_option('pmg-starttime'),
	    endtime => get_standard_option('pmg-endtime'),
	    xfilter => {
		description => "Only include mails containing this filter string.",
		type => 'string',
		minLength => 1,
		maxLength => 256,
		optional => 1,
	    },
	    from => {
		description => "Sender email address filter.",
		type => 'string',
		optional => 1,
		minLength => 1,
		maxLength => 256,
	    },
	    target => {
		description => "Receiver email address filter.",
		type => 'string',
		optional => 1,
		minLength => 1,
		maxLength => 256,
	    },
	    ndr => {
		description => "Include NDRs (non delivery reports).",
		type => 'boolean',
		optional => 1,
		default => 0,
	    },
	    greylist => {
		description => "Include Greylisted entries.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => $email_log_property_desc,
	},
	links => [ { rel => 'child', href => "{id}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();

	my $args = [];

	my ($start, $end) = $get_start_end_time->($param);

	push @$args, '-s', $start;
	push @$args, '-e', $end;

	push @$args, '-n' if !$param->{ndr};

	push @$args, '-g' if !$param->{greylist};

	push @$args, '-x', $param->{xfilter} if defined($param->{xfilter});

	if (defined($param->{from})) {
	    push @$args, '-f', $param->{from};
	}
	if (defined($param->{target})) {
	    push @$args, '-t', $param->{target};
	}

	my ($list, $status) = $run_pmg_log_tracker->($args);

	my $res = [];
	foreach my $e (@$list) {
	    push @$res, $e if !$e->{is_relay};
	}

	# hack: return status message in 'changes' attribute
	$restenv->set_result_attrib('changes', $status) if defined($status);

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'maillog',
    path => '{id}',
    method => 'GET',
    description => "Get the detailed syslog entries for a specific mail ID.",
    proxyto => 'node',
    protected => 1,
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    starttime => get_standard_option('pmg-starttime'),
	    endtime => get_standard_option('pmg-endtime'),
	    id => {
		description => "Mail ID (as returned by the list API).",
		type => 'string',
		minLength => 3,
		maxLength => 64,
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
	    %$email_log_property_desc,
	    logs => {
		type => 'array',
		items => { type => "string" },
	    }
	},
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();

	my $args = ['-v'];

	my ($start, $end) = $get_start_end_time->($param);

	push @$args, '-s', $start;
	push @$args, '-e', $end;

	my $list = $run_pmg_log_tracker->($args, $param->{id});

	my $res;
	foreach my $e (@$list) {
	    $res = $e if $e->{id} eq $param->{id};
	}

	die "entry '$param->{id}' not found\n" if !defined($res);

	return $res;
    }});

1;
