package PMG::CLI::pmgqm;

use strict;
use Data::Dumper;
use Encode qw(encode);
use Template;
use MIME::Entity;
use HTML::Entities;
use Time::Local;
use Clone 'clone';
use Mail::Header;
use POSIX qw(strftime);
use File::Find;
use File::stat;
use URI::Escape;

use PVE::SafeSyslog;
use PVE::Tools;
use PVE::INotify;
use PVE::CLIHandler;
use PVE::JSONSchema qw(get_standard_option);

use PMG::RESTEnvironment;
use PMG::Utils;
use PMG::Ticket;
use PMG::DBTools;
use PMG::RuleDB;
use PMG::Config;
use PMG::ClusterConfig;
use PMG::API2::Quarantine;

use base qw(PVE::CLIHandler);

sub setup_environment {
    PMG::RESTEnvironment->setup_default_cli_env();
}

sub get_item_data {
    my ($data, $ref) = @_;

    my @lines = split ('\n', $ref->{header});
    my $head = new Mail::Header(\@lines);

    my $item = {};

    $item->{id} = sprintf("C%dR%dT%d", $ref->{cid}, $ref->{rid}, $ref->{ticketid});

    $item->{subject} = PMG::Utils::rfc1522_to_html(
	PVE::Tools::trim($head->get('subject')) || 'No Subject');

    my $from = PMG::Utils::rfc1522_to_html(PVE::Tools::trim($head->get('from') // $ref->{sender}));
    my $sender = PMG::Utils::rfc1522_to_html(PVE::Tools::trim($head->get('sender')));

    if ($sender) {
	$item->{sender} = $sender;
	$item->{from} = sprintf ("%s on behalf of %s", $sender, $from);
    } else {
	$item->{from} = $from;
    }

    $item->{envelope_sender} = $ref->{sender};
    $item->{pmail} = encode_entities(PMG::Utils::try_decode_utf8($ref->{pmail}));
    $item->{receiver} = $ref->{receiver} || $ref->{pmail};

    $item->{date} = strftime("%F", localtime($ref->{time}));
    $item->{time} = strftime("%H:%M:%S", localtime($ref->{time}));

    $item->{bytes} = $ref->{bytes};
    $item->{spamlevel} = $ref->{spamlevel};
    $item->{spaminfo} = $ref->{info};
    $item->{file} = $ref->{file};

    my $basehref = "$data->{protocol_fqdn_port}/quarantine";
    if ($data->{authmode} ne 'ldap') {
	my $ticket = uri_escape($data->{ticket});
	$item->{href} = "$basehref?ticket=$ticket&cselect=$item->{id}&date=$item->{date}";
    } else {
	$item->{href} = "$basehref?cselect=$item->{id}&date=$item->{date}";
    }

    return $item;
}

__PACKAGE__->register_method ({
    name => 'status',
    path => 'status',
    method => 'POST',
    description => "Print quarantine status (mails per user) for specified time span.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    timespan => {
		description => "Select time span.",
		type => 'string',
		enum => ['today', 'yesterday', 'week'],
		default => 'today',
		optional => 1,
	    },
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $cinfo = PMG::ClusterConfig->new();
	my $role = $cinfo->{local}->{type} // '-';

	if (!(($role eq '-') || ($role eq 'master'))) {
	   warn "local node is not master\n";
	   return;
	}

	my $cfg = PMG::Config->new();

	my $timespan = $param->{timespan} // 'today';

	my ($start, $end) = PMG::Utils::lookup_timespan($timespan);

	my $hostname = PVE::INotify::nodename();

	my $fqdn = $cfg->get('spamquar', 'hostname') //
	    PVE::Tools::get_fqdn($hostname);


	my $dbh = PMG::DBTools::open_ruledb();

	my $domains = PVE::INotify::read_file('domains');
	my $domainregex = PMG::Utils::domain_regex([keys %$domains]);

	my $sth = $dbh->prepare(
	    "SELECT pmail, AVG(spamlevel) as spamlevel, count(*)  FROM CMailStore, CMSReceivers " .
	    "WHERE time >= $start AND time < $end AND " .
	    "QType = 'S' AND CID = CMailStore_CID AND RID = CMailStore_RID " .
	    "AND Status = 'N' " .
	    "GROUP BY pmail " .
	    "ORDER BY pmail");

	$sth->execute();

	print "Count  Spamlevel Mail\n";
	my $res = [];
	while (my $ref = $sth->fetchrow_hashref()) {
	    push @$res, $ref;
	    my $extern = ($domainregex && $ref->{pmail} !~ $domainregex);
	    my $hint = $extern ? " (external address)" : "";
	    printf ("%-5d %10.2f %s$hint\n", $ref->{count}, $ref->{spamlevel}, $ref->{pmail});
	}

	$sth->finish();

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'send',
    path => 'send',
    method => 'POST',
    description => "Generate and send spam report emails.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    receiver => get_standard_option('pmg-email-address', {
		description => "Generate report for a single email address. If not specified, generate reports for all users.",
		optional => 1,
	    }),
	    timespan => {
		description => "Select time span.",
		type => 'string',
		enum => ['today', 'yesterday', 'week'],
		default => 'today',
		optional => 1,
	    },
	    style => {
		description => "Spam report style. Default value is read from spam quarantine configuration.",
		type => 'string',
		enum => ['short', 'verbose', 'custom'],
		optional => 1,
	    },
	    redirect => get_standard_option('pmg-email-address', {
		description => "Redirect spam report email to this address.",
		optional => 1,
	    }),
	    debug => {
		description => "Debug mode. Print raw email to stdout instead of sending them.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    }
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $cinfo = PMG::ClusterConfig->new();
	my $role = $cinfo->{local}->{type} // '-';

	if (!(($role eq '-') || ($role eq 'master'))) {
	   warn "local node is not master - not sending spam report\n";
	   return;
	}

	my $cfg = PMG::Config->new();

	my $reportstyle = $param->{style} // $cfg->get('spamquar', 'reportstyle');

	# overwrite report style none when:
	# - explicit receiver specified
	# - when debug flag enabled
	if ($reportstyle eq 'none') {
	    $reportstyle = 'verbose' if $param->{debug} || defined($param->{receiver});
	}

	return if $reportstyle eq 'none'; # do nothing

	my $timespan = $param->{timespan} // 'today';

	my ($start, $end) = PMG::Utils::lookup_timespan($timespan);

	my $hostname = PVE::INotify::nodename();

	my $fqdn = $cfg->get('spamquar', 'hostname') //
	    PVE::Tools::get_fqdn($hostname);

	my $port = $cfg->get('spamquar', 'port') // 8006;

	my $protocol = $cfg->get('spamquar', 'protocol') // 'https';

	my $protocol_fqdn_port = "$protocol://$fqdn";
	if (($protocol eq 'https' && $port != 443) ||
	    ($protocol eq 'http' && $port != 80)) {
	    $protocol_fqdn_port .= ":$port";
	}

	my $authmode = $cfg->get ('spamquar', 'authmode') // 'ticket';

	my $global_data = {
	    protocol => $protocol,
	    port => $port,
	    fqdn => $fqdn,
	    hostname => $hostname,
	    date => strftime("%F", localtime($end - 1)),
	    timespan => $timespan,
	    items => [],
	    protocol_fqdn_port => $protocol_fqdn_port,
	    authmode => $authmode,
	};

	my $mailfrom = $cfg->get ('spamquar', 'mailfrom') //
	    "Proxmox Mail Gateway <postmaster>";

	my $dbh = PMG::DBTools::open_ruledb();

	my $target = $param->{receiver};
	my $redirect = $param->{redirect};

	if (defined($redirect) && !defined($target)) {
	    die "can't redirect mails for all users\n";
	}

	my $domains = PVE::INotify::read_file('domains');
	my $domainregex = PMG::Utils::domain_regex([keys %$domains]);

	my $template = "spamreport-${reportstyle}.tt";
	my $found = 0;
	foreach my $path (@$PMG::Config::tt_include_path) {
	    if (-f "$path/$template") { $found = 1; last; }
	}
	if (!$found) {
	    warn "unable to find template '$template' - using default\n";
	    $template = "spamreport-verbose.tt";
	}

	my $sth = $dbh->prepare(
	    "SELECT * FROM CMailStore, CMSReceivers " .
	    "WHERE time >= $start AND time < $end AND " .
	    ($target ? "pmail = ? AND " : '') .
	    "QType = 'S' AND CID = CMailStore_CID AND RID = CMailStore_RID " .
	    "AND Status = 'N' " .
	    "ORDER BY pmail, time, receiver");

	if ($target) {
	    $sth->execute(encode('UTF-8', $target));
	} else {
	    $sth->execute();
	}

	my $mailcount = 0;
	my $creceiver = '';
	my $data;

	my $tt = PMG::Config::get_template_toolkit();

	my $finalize = sub {

	    my $extern = ($domainregex && $creceiver !~ $domainregex);
	    if (!$extern) {
		$data->{mailcount} = $mailcount;
		my $sendto = $redirect ? $redirect : $creceiver;
		PMG::Utils::finalize_report($tt, $template, $data, $mailfrom, $sendto, $param->{debug});
	    }
	};

	while (my $ref = $sth->fetchrow_hashref()) {
	    my $decoded_pmail = PMG::Utils::try_decode_utf8($ref->{pmail});
	    if ($creceiver ne $decoded_pmail) {

		$finalize->() if $data;

		$data = clone($global_data);

		$creceiver = $decoded_pmail;
		$mailcount = 0;

		$data->{pmail} = encode_entities($decoded_pmail);
		$data->{pmail_raw} = $ref->{pmail};
		$data->{managehref} = "$protocol_fqdn_port/quarantine";
		if ($data->{authmode} ne 'ldap') {
		    $data->{ticket} = PMG::Ticket::assemble_quarantine_ticket($data->{pmail_raw});
		    my $esc_ticket = uri_escape($data->{ticket});
		    $data->{managehref} .= "?ticket=${esc_ticket}";
		}

	    }

	    push @{$data->{items}}, get_item_data($data, $ref);

	    $mailcount++;
	}

	$sth->finish();

	$finalize->() if $data;

	if (defined($target) && !$mailcount) {
	    print STDERR "no mails for '$target'\n";
	}

	return undef;
    }});

sub find_stale_files {
    my ($path, $lifetime, $purge) = @_;

    return if ! -d $path;

    my (undef, undef, undef, $mday, $mon, $year) = localtime(time());
    my $daystart = timelocal(0, 0, 0, $mday, $mon, $year);
    my $expire = $daystart - $lifetime*86400;

    my $wanted = sub {
	my $name = $File::Find::name;
	return if $name !~ m|^($path/.*)$|;
	$name = $1; # untaint
	my $stat = stat($name);
	return if ! -f _;
	return if $stat->mtime >= $expire;
	if ($purge) {
	    if (unlink($name)) {
		print "removed: $name\n";
	    }
	} else {
	    print "$name\n";
	}
    };

    find({ wanted => $wanted, no_chdir => 1 }, $path);
}

sub test_quarantine_files {
    my ($spamlifetime, $viruslifetime, $purge) = @_;

    print STDERR "searching for stale files\n" if !$purge;

    my $spooldir = $PMG::MailQueue::spooldir;

    find_stale_files ("$spooldir/spam", $spamlifetime, $purge);
    foreach my $dir (<"/var/spool/pmg/cluster/*/spam">) {
	next if $dir !~ m|^(/var/spool/pmg/cluster/\d+/spam)$|;
	$dir = $1; # untaint
	find_stale_files ($dir, $spamlifetime, $purge);
    }

    find_stale_files ("$spooldir/virus", $viruslifetime, $purge);
    foreach my $dir (<"/var/spool/pmg/cluster/*/virus">) {
	next if $dir !~ m|^(/var/spool/pmg/cluster/\d+/virus)$|;
	$dir = $1; # untaint
	find_stale_files ($dir, $viruslifetime, $purge);
    }
}

__PACKAGE__->register_method ({
    name => 'purge',
    path => 'purge',
    method => 'POST',
    description => "Cleanup Quarantine database. Remove entries older than configured quarantine lifetime.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    check => {
		description => "Only search for quarantine files older than configured quarantine lifetime. Just print found files, but do not remove them.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    }
	}
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::Config->new();

	my $spamlifetime = $cfg->get('spamquar', 'lifetime');
	my $viruslifetime = $cfg->get ('virusquar', 'lifetime');

	my $purge = !$param->{check};

	if ($purge) {
	    print STDERR "purging database\n";

	    my $dbh = PMG::DBTools::open_ruledb();

	    if (my $count = PMG::DBTools::purge_quarantine_database($dbh, 'S', $spamlifetime)) {
		print STDERR "removed $count spam quarantine files\n";
	    }

	    if (my $count = PMG::DBTools::purge_quarantine_database($dbh, 'V', $viruslifetime)) {
		print STDERR "removed $count virus quarantine files\n";
	    }

	    if (my $count = PMG::DBTools::purge_quarantine_database($dbh, 'A', $spamlifetime)) {
		print STDERR "removed $count attachment quarantine files\n";
	    }
	}

	test_quarantine_files($spamlifetime, $viruslifetime, $purge);

	return undef;
    }});


our $cmddef = {
    'purge' => [ __PACKAGE__, 'purge', []],
    'send' => [ __PACKAGE__, 'send', []],
    'status' => [ __PACKAGE__, 'status', []],
};

1;
