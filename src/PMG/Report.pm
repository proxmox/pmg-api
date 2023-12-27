package PMG::Report;

use strict;
use warnings;
use Mail::SpamAssassin::DnsResolver;

use PVE::Tools;
use PMG::Utils;

$ENV{'PATH'} = '/sbin:/bin:/usr/sbin:/usr/bin';

my $cmd_timeout = 10; # generous timeout

# NOTE: always add new sections to the report_order array!
my $report_def = {
    general => {
	title => 'general system info',
	cmds => [
	    'hostname',
	    'date -R',
	    'pmgversion --verbose',
	    'cat /etc/hosts',
	    'cat /etc/resolv.conf',
	    'top -b -n 1  | head -n 15',
	    'pmgsubscription get',
	    sub { check_dns_resolution() },
	    'cat /etc/apt/sources.list',
	    sub { dir2text('/etc/apt/sources.list.d/', '.*\.list' ) },
	],
    },
    storage => [
	'cat /etc/fstab',
	'findmnt --ascii',
	'df --human',
	'lsblk --ascii',
    ],
    network => [
	'ip -details -statistics address',
	'cat /etc/network/interfaces',
    ],
    firewall => [
	'iptables-save',
    ],
    cluster => [
	'pmgcm status',
    ],
    pmg => [
	'pmgconfig dump',
	sub { dir2text('/etc/pmg/','(?:domains|mynetworks|tls_policy|transport)' ) },
	'cat /etc/pmg/dkim/domains',
	sub { dir2text('/etc/postfix/','(?:clientaccess|senderaccess|rcptaccess)' ) },
	sub { dump_templates() },
	'pmgdb dump',
    ],
};

my @report_order = ('general', 'storage', 'network', 'firewall', 'cluster', 'pmg');

my $report = '';

# output the content of all the files of a directory
sub dir2text {
    my ($target_dir, $regexp) = @_;

    PVE::Tools::dir_glob_foreach($target_dir, $regexp, sub {
	my ($file) = @_;
	$report .=  "\n# cat $target_dir$file\n";
	$report .= PVE::Tools::file_get_contents($target_dir.$file)."\n";
    });
}

# command -v is the posix equivalent of 'which'
sub cmd_exists { system("command -v '$_[0]' > /dev/null 2>&1") == 0 }

sub generate {

    my $record_output = sub {
	$report .= shift . "\n";
    };

    my $run_cmd_params = {
	outfunc => $record_output,
	errfunc => $record_output,
	timeout => $cmd_timeout,
	noerr => 1, # avoid checking programs exit code
    };

    foreach my $section (@report_order) {
	my $s = $report_def->{$section};

	my $title = "info about $section";
	my $commands = $s;

	if (ref($s) eq 'HASH') {
	    $commands = $s->{cmds};
	    $title = $s->{title} if defined($s->{title});
	} elsif (ref($s) ne 'ARRAY') {
	    die "unknown report definition in section '$section'!";
	}

	$report .= "\n==== $title ====\n";
	foreach my $command (@$commands) {
	    eval {
		if (ref $command eq 'CODE') {
		    PVE::Tools::run_with_timeout($cmd_timeout, $command);
		} else {
		    $report .= "\n# $command\n";
		    PVE::Tools::run_command($command, %$run_cmd_params);
		}
	    };
	    $report .= "\nERROR: $@\n" if $@;
	}
    }

    return $report;
}

# using SpamAssassin's resolver, since the SA configuration can change which
# resolver is used and it uses only one resolver.
sub check_dns_resolution {

    my $sa = Mail::SpamAssassin->new ({
	debug => 0,
	local_tests_only => 0,
	home_dir_for_helpers => '/root',
	userstate_dir => '/root/.spamassassin',
	dont_copy_prefs   => 1,
	stop_at_threshold => 0,
    });
    $sa->init();
    $sa->{resolver}->load_resolver();

    my $packet = $sa->{resolver}->send('www.proxmox.com');
    my $answer = $packet->{answer}->[0];
    my $answertext = defined($answer) ? $answer->plain() : 'NXDOMAIN';

    $report .= "\n# resolve www.proxmox.com\n";
    $report .= $answertext . "\n";
}

sub dump_templates {
    my ($template_dir, $base_dir) = ('/etc/pmg/templates/', '/var/lib/pmg/templates');
    PVE::Tools::dir_glob_foreach($template_dir, '[^.].*', sub {
	my ($file) = @_;
	my $override_but_unmodified = 0;
	if ($file =~ /.*\.(?:tt|in).*/ && -e "$base_dir/$file") {
	    my $shipped = PVE::Tools::file_get_contents("$base_dir/$file", 1024*1024);
	    my $override = PVE::Tools::file_get_contents("$template_dir/$file", 1024*1024);
	    $override_but_unmodified = $shipped eq $override;
	}
	if ($file =~ /\.ucf-(?:dist|new|old)/) {
	    $report .= "\n# SKIP $file\n";
	} elsif ($override_but_unmodified) {
	    $report .= "\n# NOTE, found a unmodified template-override: $file\n";
	} else {
	    $report .=  "\n# cat $template_dir$file\n";
	    $report .= PVE::Tools::file_get_contents($template_dir.$file)."\n";
	}
    });
}

1;
