package PMG::API2::Statistics;

use strict;
use warnings;
use Data::Dumper;
use JSON;
use Time::Local;

use PVE::Tools;
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::Exception qw(raise_param_exc);
use PVE::RESTHandler;
use PMG::RESTEnvironment;
use PVE::JSONSchema qw(get_standard_option);

use PMG::Utils;
use PMG::Config;
use PMG::RuleDB;
use PMG::Statistic;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
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
	links => [ { rel => 'child', href => "{name}" } ],
    },
    code => sub {
	my ($param) = @_;

	return [
	    { name => "contact" },
	    { name => "detail" },
	    { name => "domains" },
	    { name => "mail" },
	    { name => "mailcount" },
	    { name => "recent" },
	    { name => "recentreceivers" },
	    { name => "maildistribution" },
	    { name => "spamscores" },
	    { name => "sender" },
	    { name => "rblcount" },
	    { name => "receiver" },
	    { name => "virus" },
	];
    }});

my $decode_orderby = sub {
    my ($orderby, $allowed_props) = @_;

    my $sorters;

    eval { $sorters = decode_json($orderby); };
    if (my $err = $@) {
	raise_param_exc({ orderby => 'invalid JSON'});
    }

    my $schema = {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		property => {
		    type => 'string',
		    enum => $allowed_props,
		},
		direction => {
		    type => 'string',
		    enum => ['ASC', 'DESC'],
		},
	    },
	},
    };

    PVE::JSONSchema::validate($sorters, $schema, "Parameter 'orderby' verification failed\n");

    return $sorters;
};

my $api_properties = {
    orderby => {
	description => "Remote sorting configuration(JSON, ExtJS compatible).",
	type => 'string',
	optional => 1,
	maxLength => 4096,
    },
};

my $default_properties = sub {
    my ($prop) = @_;

    $prop //= {};

    $prop->{starttime} = get_standard_option('pmg-starttime');
    $prop->{endtime} = get_standard_option('pmg-endtime');

    $prop->{year} = {
	description => "Year. Defaults to current year. You will get statistics for the whole year if you do not specify a month or day.",
	type => 'integer',
	minimum => 1900,
	maximum => 3000,
	optional => 1,
    };

    $prop->{month} = {
	description => "Month. You will get statistics for the whole month if you do not specify a day.",
	type => 'integer',
	minimum => 1,
	maximum => 12,
	optional => 1,
    };

    $prop->{day} = {
	description => "Day of month. Get statistics for a single day.",
	type => 'integer',
	minimum => 1,
	maximum => 31,
	optional => 1,
    };

    return $prop;
};

my $extract_start_end = sub {
    my ($param) = @_;

    my $has_ymd;
    foreach my $k (qw(year month day)) {
	if (defined($param->{$k})) {
	    $has_ymd = $k;
	    last;
	}
    }
    my $has_se;
    foreach my $k (qw(starttime endtime)) {
	if (defined($param->{$k})) {
	    $has_se = $k;
	    last;
	}
    }

    raise_param_exc({ $has_se => "parameter conflicts with parameter '$has_ymd'"})
	if $has_se && $has_ymd;

    my $start;
    my $end;

    if ($has_ymd) {
	my (undef, undef, undef, undef, $month, $year) = localtime(time());
	$month += 1;
	$year = $param->{year} if defined($param->{year});
	if (defined($param->{day})) {
	    my $day = $param->{day};
	    $month = $param->{month} if defined($param->{month});
	    $start = timelocal(0, 0, 0, $day, $month - 1, $year);
	    $end = timelocal(59, 59, 23, $day, $month - 1, $year);
	} elsif (defined($param->{month})) {
	    my $month = $param->{month};
	    if ($month < 12) {
		$start = timelocal(0, 0, 0, 1, $month - 1, $year);
		$end = timelocal(0, 0, 0, 1, $month, $year);
	    } else {
		$start = timelocal(0, 0, 0, 1, 11, $year);
		$end = timelocal(0, 0, 0, 1, 0, $year + 1);
	    }
	} else {
	    $start = timelocal(0, 0, 0, 1, 0, $year);
	    $end = timelocal(0, 0, 0, 1, 0, $year + 1);
	}
    } else {
	$start = $param->{starttime} // (time - 86400);
	$end = $param->{endtime} // ($start + 86400);
    }

    return ($start, $end);
};

my $userstat_limit = 2000; # hardcoded limit

__PACKAGE__->register_method ({
    name => 'contact',
    path => 'contact',
    method => 'GET',
    description => "Contact Address Statistics.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => $default_properties->({
	    filter => {
		description => "Contact address filter.",
		type => 'string',
		maxLength => 512,
		optional => 1,
	    },
	    orderby => $api_properties->{orderby},
	}),
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		contact => {
		    description => "Contact email.",
		    type => 'string',
		},
		count => {
		    description => "Mail count.",
		    type => 'number',
		    optional => 1,
		},
		bytes => {
		    description => "Mail traffic (Bytes).",
		    type => 'number',
		},
		viruscount => {
		    description => "Number of sent virus mails.",
		    type => 'number',
		    optional => 1,
		},
	    },
	},
	links => [ { rel => 'child', href => "{contact}" } ],
    },
    code => sub {
	my ($param) = @_;

	my ($start, $end) = $extract_start_end->($param);

	my $cfg = PMG::Config->new();
	my $advfilter = $cfg->get('admin', 'advfilter');

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	my $sorters = [];
	if ($param->{orderby}) {
	    my $props = ['contact', 'count', 'bytes', 'viruscount'];
	    $sorters = $decode_orderby->($param->{orderby}, $props);
	}

	my $res = $stat->user_stat_contact($rdb, $userstat_limit, $sorters, $param->{filter}, $advfilter);

	return $res;
    }});

my $detail_return_properties = sub {
    my ($prop) = @_;

    $prop //= {};

    $prop->{time} = {
	description => "Receive time stamp",
	type => 'integer',
    };

    $prop->{bytes} = {
	description => "Mail traffic (Bytes).",
	type => 'number',
    };

    $prop->{blocked} = {
	description => "Mail was blocked.",
	type => 'boolean',
    };

    $prop->{spamlevel} = {
	description => "Spam score.",
	type => 'number',
    };

    $prop->{virusinfo} = {
	description => "Virus name.",
	type => 'string',
	optional => 1,
    };

    return $prop;
};

sub get_detail_statistics {
    my ($type, $param) = @_;

    my ($start, $end) = $extract_start_end->($param);
    my $sorters = [];
    if ($param->{orderby}) {
	my $props = ['time', 'sender', 'bytes', 'blocked', 'spamlevel', 'virusinfo'];
	$props->[1] = 'receiver' if $type eq 'sender';
	$sorters = $decode_orderby->($param->{orderby}, $props);
    }
    my $address = $param->{address} // $param->{$type};
    my $rdb = PMG::RuleDB->new();

    my @args = ($rdb, $address, $userstat_limit, $sorters, $param->{filter});

    my $stat = PMG::Statistic->new($start, $end);
    if ($type eq 'contact') {
	return $stat->user_stat_contact_details(@args);
    } elsif ($type eq 'sender') {
	return $stat->user_stat_sender_details(@args);
    } elsif ($type eq 'receiver') {
	return $stat->user_stat_receiver_details(@args);
    } else {
	die "invalid type provided (not 'contact', 'sender', 'receiver')\n";
    }
}

__PACKAGE__->register_method ({
    name => 'detailstats',
    path => 'detail',
    method => 'GET',
    description => "Detailed Statistics.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => $default_properties->({
	    type => {
		description => "Type of statistics",
		type => 'string',
		enum => [ 'contact', 'sender', 'receiver' ],
	    },
	    address => get_standard_option('pmg-email-address', {
		description => "Email address.",
	    }),
	    filter => {
		description => "Address filter.",
		type => 'string',
		maxLength => 512,
		optional => 1,
	    },
	    orderby => $api_properties->{orderby},
	}),
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => $detail_return_properties->({
		sender => {
		    description => "Sender email. (for contact and receiver statistics)",
		    type => 'string',
		    optional => 1,
		},
		receiver => {
		    description => "Receiver email. (for sender statistics)",
		    type => 'string',
		    optional => 1,
		},
	    }),
	},
    },
    code => sub {
	my ($param) = @_;

	return get_detail_statistics($param->{type}, $param);
    }});

__PACKAGE__->register_method ({
    name => 'sender',
    path => 'sender',
    method => 'GET',
    description => "Sender Address Statistics.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => $default_properties->({
	    filter => {
		description => "Sender address filter.",
		type => 'string',
		maxLength => 512,
		optional => 1,
	    },
	    orderby => $api_properties->{orderby},
	}),
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		sender => {
		    description => "Sender email.",
		    type => 'string',
		},
		count => {
		    description => "Mail count.",
		    type => 'number',
		    optional => 1,
		},
		bytes => {
		    description => "Mail traffic (Bytes).",
		    type => 'number',
		},
		viruscount => {
		    description => "Number of sent virus mails.",
		    type => 'number',
		    optional => 1,
		},
	    },
	},
	links => [ { rel => 'child', href => "{sender}" } ],
    },
    code => sub {
	my ($param) = @_;

	my ($start, $end) = $extract_start_end->($param);

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	my $sorters = [];
	if ($param->{orderby}) {
	    my $props = ['sender', 'count', 'bytes', 'viruscount'];
	    $sorters = $decode_orderby->($param->{orderby}, $props);
	}

	my $res = $stat->user_stat_sender($rdb, $userstat_limit, $sorters, $param->{filter});

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'receiver',
    path => 'receiver',
    method => 'GET',
    description => "Receiver Address Statistics.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => $default_properties->({
	    filter => {
		description => "Receiver address filter.",
		type => 'string',
		maxLength => 512,
		optional => 1,
	    },
	    orderby => $api_properties->{orderby},
	}),
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		receiver => {
		    description => "Sender email.",
		    type => 'string',
		},
		count => {
		    description => "Mail count.",
		    type => 'number',
		    optional => 1,
		},
		bytes => {
		    description => "Mail traffic (Bytes).",
		    type => 'number',
		},
		spamcount => {
		    description => "Number of sent spam mails.",
		    type => 'number',
		    optional => 1,
		},
		viruscount => {
		    description => "Number of sent virus mails.",
		    type => 'number',
		    optional => 1,
		},
	    },
	},
	links => [ { rel => 'child', href => "{receiver}" } ],
    },
    code => sub {
	my ($param) = @_;

	my ($start, $end) = $extract_start_end->($param);

	my $cfg = PMG::Config->new();
	my $advfilter = $cfg->get('admin', 'advfilter');

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	my $sorters = [];
	if ($param->{orderby}) {
	    my $props = ['receiver', 'count', 'bytes', 'spamcount', 'viruscount'];
	    $sorters = $decode_orderby->($param->{orderby}, $props);
	}

	my $res = $stat->user_stat_receiver($rdb, $userstat_limit, $sorters, $param->{filter}, $advfilter);

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'domains',
    path => 'domains',
    method => 'GET',
    description => "Mail Domains Statistics.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => $default_properties->(),
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		domain => {
		    description => "Domain name.",
		    type => 'string',
		},
		count_in => {
		    description => "Incoming mail count.",
		    type => 'number',
		},
		count_out => {
		    description => "Outgoing mail count.",
		    type => 'number',
		},
		spamcount_in => {
		    description => "Incoming spam mails.",
		    type => 'number',
		},
		spamcount_out => {
		    description => "Outgoing spam mails.",
		    type => 'number',
		},
		bytes_in => {
		    description => "Incoming mail traffic (Bytes).",
		    type => 'number',
		},
		bytes_out => {
		    description => "Outgoing mail traffic (Bytes).",
		    type => 'number',
		},
		viruscount_in => {
		    description => "Number of incoming virus mails.",
		    type => 'number',
		},
		viruscount_out => {
		    description => "Number of outgoing virus mails.",
		    type => 'number',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my ($start, $end) = $extract_start_end->($param);

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	#PMG::Statistic::update_stats_domainstat_in($rdb->{dbh}, $cinfo);
	#PMG::Statistic::update_stats_domainstat_out($rdb->{dbh}, $cinfo);

	my $res = $stat->total_domain_stat($rdb);


	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'mail',
    path => 'mail',
    method => 'GET',
    description => "General Mail Statistics.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => $default_properties->(),
    },
    returns => {
	type => "object",
	properties => {
	    avptime => {
		description => "Average mail processing time in seconds.",
		type => 'number',
	    },
	    bounces_in => {
		description => "Incoming bounce mail count (sender = <>).",
		type => 'number',
	    },
	    bounces_out => {
		description => "Outgoing bounce mail count (sender = <>).",
		type => 'number',
	    },
	    count => {
		description => "Overall mail count (in and out).",
		type => 'number',
	    },
	    count_in => {
		description => "Incoming mail count.",
		type => 'number',
	    },
	    count_out => {
		description => "Outgoing mail count.",
		type => 'number',
	    },
	    glcount => {
		description => "Number of greylisted mails.",
		type => 'number',
	    },
	    rbl_rejects => {
		description => "Number of RBL rejects.",
		type => 'integer',
	    },
	    pregreet_rejects => {
		description => "PREGREET recject count.",
		type => 'integer',
	    },
	    junk_in => {
		description => "Incoming junk mail count (viruscount_in + spamcount_in + glcount + spfcount + rbl_rejects + pregreet_rejects).",
		type => 'number',
	    },
	    junk_out => {
		description => "Outgoing junk mail count (viruscount_out + spamcount_out).",
		type => 'number',
	    },
	    spamcount_in => {
		description => "Incoming spam mails.",
		type => 'number',
	    },
	    spamcount_out => {
		description => "Outgoing spam mails.",
		type => 'number',
	    },
	    spfcount => {
		description => "Mails rejected by SPF.",
		type => 'number',
	    },
	    bytes_in => {
		description => "Incoming mail traffic (bytes).",
		type => 'number',
	    },
	    bytes_out => {
		description => "Outgoing mail traffic (bytes).",
		type => 'number',
	    },
	    viruscount_in => {
		description => "Number of incoming virus mails.",
		type => 'number',
	    },
	    viruscount_out => {
		description => "Number of outgoing virus mails.",
		type => 'number',
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my ($start, $end) = $extract_start_end->($param);

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	my $res = $stat->total_mail_stat($rdb);

	my $rejects = $stat->postscreen_stat($rdb);

	$res->{rbl_rejects} //= 0;
	if (defined(my $rbl_rejects = $rejects->{rbl_rejects})) {
	    foreach my $k (qw(rbl_rejects junk_in count_in count)) {
		$res->{$k} += $rbl_rejects;
	    }
	}

	$res->{pregreet_rejects} //= 0;
	if (defined(my $pregreet_rejects = $rejects->{pregreet_rejects})) {
	    foreach my $k (qw(pregreet_rejects junk_in count_in count)) {
		$res->{$k} += $pregreet_rejects;
	    }
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'recent',
    path => 'recent',
    method => 'GET',
    description => "Mail Count Statistics.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    hours => {
		description => "How many hours you want to get",
		type => 'integer',
		minimum => 1,
		maximum => 24,
		optional => 1,
		default => 12,
	    },
	    timespan => {
		description => "The Timespan for one datapoint (in seconds)",
		type => 'integer',
		minimum => 1,
		maximum => 1800,
		optional => 1,
		default => 1800,
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		index => {
		    description => "Time index.",
		    type => 'integer',
		},
		time => {
		    description => "Time (Unix epoch).",
		    type => 'integer',
		},
		count => {
		    description => "Overall mail count (in and out).",
		    type => 'number',
		},
		count_in => {
		    description => "Incoming mail count.",
		    type => 'number',
		},
		count_out => {
		    description => "Outgoing mail count.",
		    type => 'number',
		},
		spam => {
		    description => "Overall spam mail count (in and out).",
		    type => 'number',
		},
		spam_in => {
		    description => "Incoming spam mails (spamcount_in + glcount + spfcount).",
		    type => 'number',
		},
		spam_out => {
		    description => "Outgoing spam mails.",
		    type => 'number',
		},
		bytes_in => {
		    description => "Number of incoming bytes mails.",
		    type => 'number',
		},
		bytes_out => {
		    description => "Number of outgoing bytes mails.",
		    type => 'number',
		},
		virus_in => {
		    description => "Number of incoming virus mails.",
		    type => 'number',
		},
		virus_out => {
		    description => "Number of outgoing virus mails.",
		    type => 'number',
		},
		timespan => {
		    description => "Timespan in seconds for one data point",
		    type => 'number',
		}
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $hours = $param->{hours} // 12;
	my $span = $param->{timespan} // 1800;

	my $end = time();
	my $start = $end - 3600*$hours;

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	my $res = $stat->recent_mailcount($rdb, $span);

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'recentreceivers',
    path => 'recentreceivers',
    method => 'GET',
    description => "Top recent Mail Receivers (including spam)",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    hours => {
		description => "How many hours you want to get",
		type => 'integer',
		minimum => 1,
		maximum => 24,
		optional => 1,
		default => 12,
	    },
	    limit => {
		description => "The maximum number of receivers to return.",
		type => 'integer',
		minimum => 1,
		maximum => 50,
		optional => 1,
		default => 5,
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		count => {
		    description => "The count of incoming not blocked E-Mails",
		    type => 'integer',
		},
		receiver => {
		    description => "The receiver",
		    type => 'string',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $hours = $param->{hours} // 12;

	my $limit = $param->{limit} // 5;

	my $end = time();
	my $start = $end - 3600*$hours;

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	my $res = $stat->recent_receivers($rdb, $limit);

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'mailcount',
    path => 'mailcount',
    method => 'GET',
    description => "Mail Count Statistics.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => $default_properties->({
	    timespan => {
		description => "Return Mails/<timespan>, where <timespan> is specified in seconds.",
		type => 'integer',
		minimum => 3600,
		maximum => 366*86400,
		optional => 1,
		default => 3600,
	    },
	}),
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		index => {
		    description => "Time index.",
		    type => 'integer',
		},
		time => {
		    description => "Time (Unix epoch).",
		    type => 'integer',
		},
		count => {
		    description => "Overall mail count (in and out).",
		    type => 'number',
		},
		count_in => {
		    description => "Incoming mail count.",
		    type => 'number',
		},
		count_out => {
		    description => "Outgoing mail count.",
		    type => 'number',
		},
		spamcount_in => {
		    description => "Incoming spam mails (spamcount_in + glcount + spfcount + rbl_rejects + pregreet_rejects).",
		    type => 'number',
		},
		spamcount_out => {
		    description => "Outgoing spam mails.",
		    type => 'number',
		},
		viruscount_in => {
		    description => "Number of incoming virus mails.",
		    type => 'number',
		},
		viruscount_out => {
		    description => "Number of outgoing virus mails.",
		    type => 'number',
		},
		rbl_rejects => {
		    description => "Number of RBL rejects.",
		    type => 'integer',
		},
		pregreet_rejects => {
		    description => "PREGREET recject count.",
		    type => 'integer',
		},
		bounces_in => {
		    description => "Incoming bounce mail count (sender = <>).",
		    type => 'number',
		},
		bounces_out => {
		    description => "Outgoing bounce mail count (sender = <>).",
		    type => 'number',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my ($start, $end) = $extract_start_end->($param);

	my $span = $param->{timespan} // 3600;

	my $count = ($end - $start)/$span;

	die "too many entries - try to increase parameter 'span'\n" if $count > 5000;

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	#PMG::Statistic::update_stats_dailystat($rdb->{dbh}, $cinfo);

	my $rejects = $stat->postscreen_stat_graph($rdb, $span);

	my $res = $stat->traffic_stat_graph ($rdb, $span);

	my $element_count = scalar(@$res);

	for (my $i = 0; $i < $element_count; $i++) {
	    my $el = $rejects->[$i];
	    next if !$el;
	    my $d = $res->[$i];
	    foreach my $k ('rbl_rejects', 'pregreet_rejects') {
		my $count = $el->{$k} // 0;
		$d->{$k} = $count;
		foreach my $k (qw(count count_in spamcount_in)) {
		    $d->{$k} += $count;
		}
	    }
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'virus',
    path => 'virus',
    method => 'GET',
    description => "Get Statistics about detected Viruses.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => $default_properties->(),
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		name => {
		    description => 'Virus name.',
		    type => 'string',
		},
		count => {
		    description => 'Detection count.',
		    type => 'integer',
		},
	    },
	}
    },
    code => sub {
	my ($param) = @_;

	my ($start, $end) = $extract_start_end->($param);

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	my $res = $stat->total_virus_stat($rdb);

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'spamscores',
    path => 'spamscores',
    method => 'GET',
    description => "Get the count of spam mails grouped by spam score. " .
	"Count for score 10 includes mails with spam score > 10.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => $default_properties->(),
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		level => {
		    description => 'Spam level.',
		    type => 'string',
		},
		count => {
		    description => 'Detection count.',
		    type => 'integer',
		},
		ratio => {
		    description => 'Portion of overall mail count.',
		    type => 'number',
		},
	    },
	}
    },
    code => sub {
	my ($param) = @_;

	my ($start, $end) = $extract_start_end->($param);

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	my $totalstat = $stat->total_mail_stat ($rdb);
	my $spamstat = $stat->total_spam_stat($rdb);

	my $res = [];

	my $count_in = $totalstat->{count_in};

	my $levelcount = {};
	my $spamcount = 0;
	foreach my $ref (@$spamstat) {
	    if (my $level = $ref->{spamlevel}) {
		next if $level < 1; # just to be sure
		$spamcount += $ref->{count};
		$level = 10 if $level > 10;
		$levelcount->{$level} += $ref->{count};
	    }
	}

	$levelcount->{0} = $count_in - $spamcount;

	for (my $i = 0; $i <= 10; $i++) {
	    my $count = $levelcount->{$i} // 0;
	    my $ratio = $count_in ? $count/$count_in : 0;
	    push @$res, { level => $i, count => $count, ratio => $ratio };
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'maildistribution',
    path => 'maildistribution',
    method => 'GET',
    description => "Get the count of spam mails grouped by spam score. " .
	"Count for score 10 includes mails with spam score > 10.",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => $default_properties->(),
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		index => {
		    description => "Hour (0-23).",
		    type => 'integer',
		},
		count => {
		    description => "Overall mail count (in and out).",
		    type => 'number',
		},
		count_in => {
		    description => "Incoming mail count.",
		    type => 'number',
		},
		count_out => {
		    description => "Outgoing mail count.",
		    type => 'number',
		},
		spamcount_in => {
		    description => "Incoming spam mails (spamcount_in + glcount + spfcount).",
		    type => 'number',
		},
		spamcount_out => {
		    description => "Outgoing spam mails.",
		    type => 'number',
		},
		viruscount_in => {
		    description => "Number of incoming virus mails.",
		    type => 'number',
		},
		viruscount_out => {
		    description => "Number of outgoing virus mails.",
		    type => 'number',
		},
		bounces_in => {
		    description => "Incoming bounce mail count (sender = <>).",
		    type => 'number',
		},
		bounces_out => {
		    description => "Outgoing bounce mail count (sender = <>).",
		    type => 'number',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my ($start, $end) = $extract_start_end->($param);

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	#PMG::Statistic::update_stats_dailystat($rdb->{dbh}, $cinfo);

	my $res = $stat->traffic_stat_day_dist ($rdb);

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'rejectcount',
    path => 'rejectcount',
    method => 'GET',
    description => "Early SMTP reject count statistic (RBL, PREGREET rejects with postscreen)",
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    parameters => {
	additionalProperties => 0,
	properties => $default_properties->({
	    timespan => {
		description => "Return RBL/PREGREET rejects/<timespan>, where <timespan> is specified in seconds.",
		type => 'integer',
		minimum => 3600,
		maximum => 366*86400,
		optional => 1,
		default => 3600,
	    },
	}),
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		index => {
		    description => "Time index.",
		    type => 'integer',
		},
		time => {
		    description => "Time (Unix epoch).",
		    type => 'integer',
		},
		rbl_rejects => {
		    description => "RBL recject count.",
		    type => 'integer',
		},
		pregreet_rejects => {
		    description => "PREGREET recject count.",
		    type => 'integer',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my ($start, $end) = $extract_start_end->($param);

	my $span = $param->{timespan} // 3600;

	my $count = ($end - $start)/$span;

	die "too many entries - try to increase parameter 'span'\n" if $count > 5000;

	my $stat = PMG::Statistic->new($start, $end);
	my $rdb = PMG::RuleDB->new();

	my $res = $stat->postscreen_stat_graph($rdb, $span);

	return $res;
    }});

1;
