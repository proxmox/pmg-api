package PMG::CLI::pmg7to8;

use strict;
use warnings;

use Cwd ();

use PVE::INotify;
use PVE::JSONSchema;
use PVE::Tools qw(run_command split_list file_get_contents);

use PMG::API2::APT;
use PMG::API2::Certificates;
use PMG::API2::Cluster;
use PMG::RESTEnvironment;
use PMG::Utils;

use Term::ANSIColor;

use PVE::CLIHandler;

use base qw(PVE::CLIHandler);

my $nodename = PVE::INotify::nodename();

my $old_postgres_release = '13';
my $new_postgres_release = '15';

my $upgraded = 0; # set in check_pmg_packages

sub setup_environment {
    PMG::RESTEnvironment->setup_default_cli_env();
}

my ($min_pmg_major, $min_pmg_minor, $min_pmg_pkgrel) = (7, 3, 2);

my $counters = {
    pass => 0,
    skip => 0,
    warn => 0,
    fail => 0,
};

my $log_line = sub {
    my ($level, $line) = @_;

    $counters->{$level}++ if defined($level) && defined($counters->{$level});

    print uc($level), ': ' if defined($level);
    print "$line\n";
};

sub log_pass {
    print color('green');
    $log_line->('pass', @_);
    print color('reset');
}

sub log_info {
    $log_line->('info', @_);
}
sub log_skip {
    $log_line->('skip', @_);
}
sub log_warn {
    print color('yellow');
    $log_line->('warn', @_);
    print color('reset');
}
sub log_fail {
    print color('bold red');
    $log_line->('fail', @_);
    print color('reset');
}

my $print_header_first = 1;
sub print_header {
    my ($h) = @_;
    print "\n" if !$print_header_first;
    print "= $h =\n\n";
    $print_header_first = 0;
}

my $get_systemd_unit_state = sub {
    my ($unit, $suppress_stderr) = @_;

    my $state;
    my $filter_output = sub {
	$state = shift;
	chomp $state;
    };

    my %extra = (outfunc => $filter_output, noerr => 1);
    $extra{errfunc} = sub {  } if $suppress_stderr;

    eval {
	run_command(['systemctl', 'is-enabled', "$unit"], %extra);
	return if !defined($state);
	run_command(['systemctl', 'is-active', "$unit"], %extra);
    };

    return $state // 'unknown';
};

my $log_systemd_unit_state = sub {
    my ($unit, $no_fail_on_inactive) = @_;

    my $log_method = \&log_warn;

    my $state = $get_systemd_unit_state->($unit);
    if ($state eq 'active') {
	$log_method = \&log_pass;
    } elsif ($state eq 'inactive') {
	$log_method = $no_fail_on_inactive ? \&log_warn : \&log_fail;
    } elsif ($state eq 'failed') {
	$log_method = \&log_fail;
    }

    $log_method->("systemd unit '$unit' is in state '$state'");
};

my $versions;
my $get_pkg = sub {
    my ($pkg) = @_;

    $versions = eval { PMG::API2::APT->versions({ node => $nodename }) } if !defined($versions);

    if (!defined($versions)) {
	my $msg = "unable to retrieve package version information";
	$msg .= "- $@" if $@;
	log_fail("$msg");
	return undef;
    }

    my $pkgs = [ grep { $_->{Package} eq $pkg } @$versions ];
    if (!defined $pkgs || $pkgs == 0) {
	log_fail("unable to determine installed $pkg version.");
	return undef;
    } else {
	return $pkgs->[0];
    }
};

sub check_pmg_packages {
    print_header("CHECKING VERSION INFORMATION FOR PMG PACKAGES");

    print "Checking for package updates..\n";
    my $updates = eval { PMG::API2::APT->list_updates({ node => $nodename }); };
    if (!defined($updates)) {
	log_warn("$@") if $@;
	log_fail("unable to retrieve list of package updates!");
    } elsif (@$updates > 0) {
	my $pkgs = join(', ', map { $_->{Package} } @$updates);
	log_warn("updates for the following packages are available:\n  $pkgs");
    } else {
	log_pass("all packages up-to-date");
    }

    print "\nChecking proxmox-mailgateway package version..\n";
    my $pkg = 'proxmox-mailgateway';
    my $pmg = $get_pkg->($pkg);
    if (!defined($pmg)) {
	print "\n$pkg not found, checking for proxmox-mailgateway-container..\n";
	$pkg = 'proxmox-mailgateway-container';
    }
    if (defined(my $pmg = $get_pkg->($pkg))) {
	# TODO: update to native version for pmg8to9
	my $min_pmg_ver = "$min_pmg_major.$min_pmg_minor-$min_pmg_pkgrel";

	my ($maj, $min, $pkgrel) = $pmg->{OldVersion} =~ m/^(\d+)\.(\d+)[.-](\d+)/;

	if ($maj > $min_pmg_major) {
	    log_pass("already upgraded to Proxmox Mail Gateway " . ($min_pmg_major + 1));
	    $upgraded = 1;
	} elsif ($maj >= $min_pmg_major && $min >= $min_pmg_minor && $pkgrel >= $min_pmg_pkgrel) {
	    log_pass("$pkg package has version >= $min_pmg_ver");
	} else {
	    log_fail("$pkg package is too old, please upgrade to >= $min_pmg_ver!");
	}

	# FIXME: better differentiate between 6.2 from bullseye or bookworm
	my ($krunning, $kinstalled) = (qr/6\.(?:2\.(?:[2-9]\d+|1[6-8]|1\d\d+)|5)[^~]*$/, 'pve-kernel-6.2');
	if (!$upgraded) {
	    # we got a few that avoided 5.15 in cluster with mixed CPUs, so allow older too
	    ($krunning, $kinstalled) = (qr/(?:5\.(?:13|15)|6\.2)/, 'pve-kernel-5.15');
	}

	print "\nChecking running kernel version..\n";
	my $kernel_ver = $pmg->{RunningKernel};
	if (!defined($kernel_ver)) {
	    log_fail("unable to determine running kernel version.");
	} elsif ($kernel_ver =~ /^$krunning/) {
	    if ($upgraded) {
		log_pass("running new kernel '$kernel_ver' after upgrade.");
	    } else {
		log_pass("running kernel '$kernel_ver' is considered suitable for upgrade.");
	    }
	} elsif ($get_pkg->($kinstalled)) {
	    # with 6.2 kernel being available in both we might want to fine-tune the check?
	    log_warn("a suitable kernel ($kinstalled) is intalled, but an unsuitable ($kernel_ver) is booted, missing reboot?!");
	} else {
	    log_warn("unexpected running and installed kernel '$kernel_ver'.");
	}

	if ($upgraded && $kernel_ver =~ /^$krunning/) {
	    my $outdated_kernel_meta_pkgs = [];
	    for my $kernel_meta_version ('5.4', '5.11', '5.13', '5.15') {
		my $pkg = "pve-kernel-${kernel_meta_version}";
		if ($get_pkg->($pkg)) {
		    push @$outdated_kernel_meta_pkgs, $pkg;
		}
	    }
	    if (scalar(@$outdated_kernel_meta_pkgs) > 0) {
		log_info(
		    "Found outdated kernel meta-packages, taking up extra space on boot partitions.\n"
		    ."      After a successful upgrade, you can remove them using this command:\n"
		    ."      apt remove " . join(' ', $outdated_kernel_meta_pkgs->@*)
		);
	    }
	}
    } else {
	log_fail("$pkg package not found!");
    }
}

my sub check_max_length {
    my ($raw, $max_length, $warning) = @_;
    log_warn($warning) if defined($raw) && length($raw) > $max_length;
}

my $is_cluster = 0;
my $cluster_healthy = 0;

sub check_cluster_status {
    log_info("Checking if the cluster nodes are in sync");

    my $rpcenv = PMG::RESTEnvironment->get();
    my $ticket = PMG::Ticket::assemble_ticket($rpcenv->get_user());
    $rpcenv->set_ticket($ticket);

    my $nodes = PMG::API2::Cluster->status({});
    if (!scalar($nodes->@*)) {
	log_skip("no cluster, no sync status to check");
	$cluster_healthy = 1;
	return;
    }

    $is_cluster = 1;
    my $syncing = 0;
    my $errors = 0;

    for my $node ($nodes->@*) {
	if (!$node->{insync}) {
	    $syncing = 1;
	}
	if ($node->{conn_error}) {
	    $errors = 1;
	}
    }

    if ($errors) {
	log_fail("Cluster not healthy, please fix the cluster before continuing");
    } elsif ($syncing) {
	log_warn("Cluster currently syncing.");
    } else {
	log_pass("Cluster healthy and in sync.");
	$cluster_healthy = 1;
    }
}


sub check_running_postgres {
    my $version = PMG::Utils::get_pg_server_version();

    my $upgraded_db = 0;

    if ($upgraded) {
	if ($version ne $new_postgres_release) {
	    log_warn("Running postgres version is still $old_postgres_release. Please upgrade the database.");
	} else {
	    log_pass("After upgrade and running postgres version is $new_postgres_release.");
	    $upgraded_db = 1;
	}
    } else {
	if ($version ne $old_postgres_release) {
	    log_warn("Running postgres version '$version' is not '$old_postgres_release', was a previous upgrade finished?");
	} else {
	    log_pass("Before upgrade and running postgres version is $old_postgres_release.");
	}
    }

    return $upgraded_db;
}

sub check_services_disabled {
    my ($upgraded_db) = @_;
    my $unit_inactive = sub { return $get_systemd_unit_state->($_[0], 1) eq 'inactive' ? $_[0] : undef };

    my $services = [qw(postfix pmg-smtp-filter pmgpolicy pmgdaemon pmgproxy)];

    if ($is_cluster) {
	push $services->@*, 'pmgmirror', 'pmgtunnel';
    }

    my $active_list = [];
    my $inactive_list = [];
    for my $service ($services->@*) {
	if (!$unit_inactive->($service)) {
	    push $active_list->@*, $service;
	} else {
	    push $inactive_list->@*, $service;
	}
    }

    if (!$upgraded) {
	if (scalar($active_list->@*) < 1) {
	    log_pass("All services inactive.");
	} else {
	    my $msg = "Not upgraded but core services still active. Consider stopping and masking them for the upgrade: \n    ";
	    $msg .= join("\n    ", $active_list->@*);
	    log_warn($msg);
	}
    } else {
	if (scalar($inactive_list->@*) < 1) {
	    log_pass("All services active.");
	} elsif ($upgraded_db) {
	    my $msg = "Already upgraded DB, but not all services active again. Consider unmasking and starting them: \n    ";
	    $msg .= join("\n    ", $inactive_list->@*);
	    log_warn($msg);
	} else {
	    log_skip("Not all services active, but DB was not upgraded yet - please upgrade DB and then unmask and start services again.");
	}
    }
}

sub check_apt_repos {
    log_info("Checking if the suite for the Debian security repository is correct..");

    my $found = 0;

    my $dir = '/etc/apt/sources.list.d';
    my $in_dir = 0;

    # TODO: check that (original) debian and Proxmox MG mirrors are present.

    my $check_file = sub {
	my ($file) = @_;

	$file = "${dir}/${file}" if $in_dir;

	my $raw = eval { PVE::Tools::file_get_contents($file) };
	return if !defined($raw);
	my @lines = split(/\n/, $raw);

	my $number = 0;
	for my $line (@lines) {
	    $number++;

	    next if length($line) == 0; # split would result in undef then...

	    ($line) = split(/#/, $line);

	    next if $line !~ m/^deb[[:space:]]/; # is case sensitive

	    my $suite;

	    # catch any of
	    # https://deb.debian.org/debian-security
	    # http://security.debian.org/debian-security
	    # http://security.debian.org/
	    if ($line =~ m|https?://deb\.debian\.org/debian-security/?\s+(\S*)|i) {
		$suite = $1;
	    } elsif ($line =~ m|https?://security\.debian\.org(?:.*?)\s+(\S*)|i) {
		$suite = $1;
	    } else {
		next;
	    }

	    $found = 1;

	    my $where = "in ${file}:${number}";
	    # TODO: is this useful (for some other checks)?
	}
    };

    $check_file->("/etc/apt/sources.list");

    $in_dir = 1;

    PVE::Tools::dir_glob_foreach($dir, '^.*\.list$', $check_file);

    if (!$found) {
	# only warn, it might be defined in a .sources file or in a way not caaught above
	log_warn("No Debian security repository detected in /etc/apt/sources.list and " .
	    "/etc/apt/sources.list.d/*.list");
    }
}

sub check_time_sync {
    my $unit_active = sub { return $get_systemd_unit_state->($_[0], 1) eq 'active' ? $_[0] : undef };

    log_info("Checking for supported & active NTP service..");
    if ($unit_active->('systemd-timesyncd.service')) {
	log_warn(
	    "systemd-timesyncd is not the best choice for time-keeping on servers, due to only applying"
	    ." updates on boot.\n  While not necessary for the upgrade it's recommended to use one of:\n"
	    ."    * chrony (Default in new Proxmox VE installations)\n    * ntpsec\n    * openntpd\n"
	);
    } elsif ($unit_active->('ntp.service')) {
	log_info("Debian deprecated and removed the ntp package for Bookworm, but the system"
	    ." will automatically migrate to the 'ntpsec' replacement package on upgrade.");
    } elsif (my $active_ntp = ($unit_active->('chrony.service') || $unit_active->('openntpd.service') || $unit_active->('ntpsec.service'))) {
	log_pass("Detected active time synchronisation unit '$active_ntp'");
    } else {
	log_warn(
	    "No (active) time synchronisation daemon (NTP) detected, but synchronized systems are important,"
	    ." especially for cluster and/or ceph!"
	);
    }
}

sub check_bootloader {
    log_info("Checking bootloader configuration...");
    if (!$upgraded) {
	log_skip("not yet upgraded, no need to check the presence of systemd-boot");
	return;
    }

    if (! -f "/etc/kernel/proxmox-boot-uuids") {
	log_skip("proxmox-boot-tool not used for bootloader configuration");
	return;
    }

    if (! -d "/sys/firmware/efi") {
	log_skip("System booted in legacy-mode - no need for systemd-boot");
	return;
    }

    if ( -f "/usr/share/doc/systemd-boot/changelog.Debian.gz") {
	log_pass("systemd-boot is installed");
    } else {
	log_warn(
	    "proxmox-boot-tool is used for bootloader configuration in uefi mode"
	    . "but the separate systemd-boot package, existing in Debian Bookworm  is not installed"
	    . "initializing new ESPs will not work until the package is installed"
	);
    }
}

sub check_misc {
    print_header("MISCELLANEOUS CHECKS");
    my $ssh_config = eval { PVE::Tools::file_get_contents('/root/.ssh/config') };
    if (defined($ssh_config)) {
	log_fail("Unsupported SSH Cipher configured for root in /root/.ssh/config: $1")
	    if $ssh_config =~ /^Ciphers .*(blowfish|arcfour|3des).*$/m;
    } else {
	log_skip("No SSH config file found.");
    }

    check_time_sync();

    my $root_free = PVE::Tools::df('/', 10);
    log_warn("Less than 5 GB free space on root file system.")
	if defined($root_free) && $root_free->{avail} < 5 * 1000*1000*1000;

    log_info("Checking if the local node's hostname '$nodename' is resolvable..");
    my $local_ip = eval { PVE::Network::get_ip_from_hostname($nodename) };
    if ($@) {
	log_warn("Failed to resolve hostname '$nodename' to IP - $@");
    } else {
	log_info("Checking if resolved IP is configured on local node..");
	my $cidr = Net::IP::ip_is_ipv6($local_ip) ? "$local_ip/128" : "$local_ip/32";
	my $configured_ips = PVE::Network::get_local_ip_from_cidr($cidr);
	my $ip_count = scalar(@$configured_ips);

	if ($ip_count <= 0) {
	    log_fail("Resolved node IP '$local_ip' not configured or active for '$nodename'");
	} elsif ($ip_count > 1) {
	    log_warn("Resolved node IP '$local_ip' active on multiple ($ip_count) interfaces!");
	} else {
	    log_pass("Resolved node IP '$local_ip' configured and active on single interface.");
	}
    }

    log_info("Check node certificate's RSA key size");
    my $certs = PMG::API2::Certificates->info({ node => $nodename });
    my $certs_check = {
	'rsaEncryption' => {
	    minsize => 2048,
	    name => 'RSA',
	},
	'id-ecPublicKey' => {
	    minsize => 224,
	    name => 'ECC',
	},
    };

    my $certs_check_failed = 0;
    for my $cert (@$certs) {
	my ($type, $size, $fn) = $cert->@{qw(public-key-type public-key-bits filename)};

	if (!defined($type) || !defined($size)) {
	    log_warn("'$fn': cannot check certificate, failed to get it's type or size!");
	}

	my $check = $certs_check->{$type};
	if (!defined($check)) {
	    log_warn("'$fn': certificate's public key type '$type' unknown!");
	    next;
	}

	if ($size < $check->{minsize}) {
	    log_fail("'$fn', certificate's $check->{name} public key size is less than 2048 bit");
	    $certs_check_failed = 1;
	} else {
	    log_pass("Certificate '$fn' passed Debian Busters (and newer) security level for TLS connections ($size >= 2048)");
	}
    }

    check_apt_repos();
    check_bootloader();
}

my sub colored_if {
    my ($str, $color, $condition) = @_;
    return "". ($condition ? colored($str, $color) : $str);
}

__PACKAGE__->register_method ({
    name => 'checklist',
    path => 'checklist',
    method => 'GET',
    description => 'Check (pre-/post-)upgrade conditions.',
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	check_pmg_packages();
	check_cluster_status();
	my $upgraded_db = check_running_postgres();
	check_services_disabled($upgraded_db);
	check_misc();

	print_header("SUMMARY");

	my $total = 0;
	$total += $_ for values %$counters;

	print "TOTAL:    $total\n";
	print colored("PASSED:   $counters->{pass}\n", 'green');
	print "SKIPPED:  $counters->{skip}\n";
	print colored_if("WARNINGS: $counters->{warn}\n", 'yellow', $counters->{warn} > 0);
	print colored_if("FAILURES: $counters->{fail}\n", 'bold red', $counters->{fail} > 0);

	if ($counters->{warn} > 0 || $counters->{fail} > 0) {
	    my $color = $counters->{fail} > 0 ? 'bold red' : 'yellow';
	    print colored("\nATTENTION: Please check the output for detailed information!\n", $color);
	    print colored("Try to solve the problems one at a time and then run this checklist tool again.\n", $color) if $counters->{fail} > 0;
	}

	return undef;
    }});

our $cmddef = [ __PACKAGE__, 'checklist', [], {}];

1;
