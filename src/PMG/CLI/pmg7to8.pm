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

my $old_suite = 'bullseye';
my $new_suite = 'bookworm';

my $upgraded = 0; # set in check_pmg_packages

sub setup_environment {
    PMG::RESTEnvironment->setup_default_cli_env();
}

my ($min_pmg_major, $min_pmg_minor, $min_pmg_pkgrel) = (7, 3, 2);

my $counters = {
    pass => 0,
    skip => 0,
    notice => 0,
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
sub log_notice {
    print color('bold');
    $log_line->('notice', @_);
    print color('reset');
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

	if ($pkg eq 'proxmox-mailgateway-container') {
	    log_skip("Ignoring kernel version checks for $pkg meta-package");
	    return;
	}

	# FIXME: better differentiate between 6.2 from bullseye or bookworm
	my $kinstalled = 'proxmox-kernel-6.2';
	if (!$upgraded) {
	    # we got a few that avoided 5.15 in cluster with mixed CPUs, so allow older too
	    $kinstalled = 'pve-kernel-5.15';
	}

	my $kernel_version_is_expected = sub {
	    my ($version) = @_;

	    return $version =~ m/^(?:5\.(?:13|15)|6\.2)/ if !$upgraded;

	    if ($version =~ m/^6\.(?:2\.(?:[2-9]\d+|1[6-8]|1\d\d+)|5)[^~]*$/) {
		return 1;
	    } elsif ($version =~ m/^(\d+).(\d+)[^~]*-pve$/) {
		return $1 >= 6 && $2 >= 2;
	    }
	    return 0;
	};

	print "\nChecking running kernel version..\n";
	my $kernel_ver = $pmg->{RunningKernel};
	if (!defined($kernel_ver)) {
	    log_fail("unable to determine running kernel version.");
	} elsif ($kernel_version_is_expected->($kernel_ver)) {
	    if ($upgraded) {
		log_pass("running new kernel '$kernel_ver' after upgrade.");
	    } else {
		log_pass("running kernel '$kernel_ver' is considered suitable for upgrade.");
	    }
	} elsif ($get_pkg->($kinstalled)) {
	    # with 6.2 kernel being available in both we might want to fine-tune the check?
	    log_warn("a suitable kernel ($kinstalled) is installed, but an unsuitable ($kernel_ver) is booted, missing reboot?!");
	} else {
	    log_warn("unexpected running and installed kernel '$kernel_ver'.");
	}

	if ($upgraded && $kernel_version_is_expected->($kernel_ver)) {
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
	    log_fail("Running postgres version '$version' is not '$old_postgres_release', was a previous upgrade left unfinished?");
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
    log_info("Checking for package repository suite mismatches..");

    my $dir = '/etc/apt/sources.list.d';
    my $in_dir = 0;

    # TODO: check that (original) debian and Proxmox MG mirrors are present.

    my ($found_suite, $found_suite_where);
    my ($mismatches, $strange_suite);

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
	    if ($line =~ m|deb\s+\w+://\S+\s+(\S*)|i) {
		$suite = $1;
	    } else {
		next;
	    }
	    my $where = "in ${file}:${number}";

	    $suite =~ s/-(?:(?:proposed-)?updates|backports|security)$//;
	    if ($suite ne $old_suite && $suite ne $new_suite) {
		log_notice(
		    "found unusual suite '$suite', neither old '$old_suite' nor new '$new_suite'.."
		    ."\n    Affected file:line $where"
		    ."\n    Please assure this is shipping compatible packages for the upgrade!"
		);
		$strange_suite = 1;
		next;
	    }

	    if (!defined($found_suite)) {
		$found_suite = $suite;
		$found_suite_where = $where;
	    } elsif ($suite ne $found_suite) {
		if (!defined($mismatches)) {
		    $mismatches = [];
		    push $mismatches->@*,
			{ suite => $found_suite, where => $found_suite_where},
			{ suite => $suite, where => $where};
		} else {
		    push $mismatches->@*, { suite => $suite, where => $where};
		}
	    }
	}
    };

    $check_file->("/etc/apt/sources.list");

    $in_dir = 1;

    PVE::Tools::dir_glob_foreach($dir, '^.*\.list$', $check_file);

    if (defined($mismatches)) {
	my @mismatch_list = map { "found suite $_->{suite} at $_->{where}" } $mismatches->@*;

	log_fail(
	    "Found mixed old and new package repository suites, fix before upgrading! Mismatches:"
	    ."\n    " . join("\n    ", @mismatch_list)
	);
    } elsif ($strange_suite) {
	log_notice("found no suite mismatches, but found at least one strange suite");
    } else {
	log_pass("found no suite mismatch");
    }
}

sub check_time_sync {
    my $unit_active = sub { return $get_systemd_unit_state->($_[0], 1) eq 'active' ? $_[0] : undef };

    log_info("Checking for supported & active NTP service..");
    if ($unit_active->('systemd-timesyncd.service')) {
	log_warn(
	    "systemd-timesyncd is not the best choice for time-keeping on servers, due to only applying"
	    ." updates on boot.\n  It's recommended to use one of:\n"
	    ."    * chrony\n    * ntpsec\n    * openntpd\n"
	);
    } elsif ($unit_active->('ntp.service')) {
	log_info("Debian deprecated and removed the ntp package for Bookworm, but the system"
	    ." will automatically migrate to the 'ntpsec' replacement package on upgrade.");
    } elsif (my $active_ntp = ($unit_active->('chrony.service') || $unit_active->('openntpd.service') || $unit_active->('ntpsec.service'))) {
	log_pass("Detected active time synchronisation unit '$active_ntp'");
    } else {
	log_notice("No (active) time synchronisation daemon (NTP) detected");
    }
}

sub check_bootloader {
    log_info("Checking bootloader configuration...");

    if (! -d '/sys/firmware/efi') {
	log_skip("System booted in legacy-mode - no need for additional packages");
	return;
    }

    if ( -f "/etc/kernel/proxmox-boot-uuids") {
	if (!$upgraded) {
	    log_skip("not yet upgraded, no need to check the presence of systemd-boot");
	    return;
	}
	if ( -f "/usr/share/doc/systemd-boot/changelog.Debian.gz") {
	    log_pass("bootloader packages installed correctly");
	    return;
	}
	log_warn(
	    "proxmox-boot-tool is used for bootloader configuration in uefi mode"
	    . " but the separate systemd-boot package is not installed,"
	    . " initializing new ESPs will not work until the package is installed"
	);
	return;
    } elsif ( ! -f "/usr/share/doc/grub-efi-amd64/changelog.Debian.gz" ) {
	log_warn(
	    "System booted in uefi mode but grub-efi-amd64 meta-package not installed,"
	    . " new grub versions will not be installed to /boot/efi!"
	    . " Install grub-efi-amd64."
	);
	return;
    } else {
	log_pass("bootloader packages installed correctly");
    }
}

sub check_dkms_modules {
    if (defined($get_pkg->('proxmox-mailgateway-container'))) {
	log_skip("Ignore dkms in containers.");
	return;
    }

    log_info("Check for dkms modules...");

    my $count;
    my $set_count = sub {
	$count = scalar @_;
    };

    my $exit_code = eval {
	run_command(['dkms', 'status', '-k', '`uname -r`'], outfunc => $set_count, noerr => 1)
    };

    if ($exit_code != 0) {
	log_skip("could not get dkms status");
    } elsif (!$count) {
	log_pass("no dkms modules found");
    } else {
	log_warn("dkms modules found, this might cause issues during upgrade.");
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
    check_dkms_modules();

    my ($template_dir, $base_dir) = ('/etc/pmg/templates/', '/var/lib/pmg/templates');
    my @override_but_unmodified = ();
    PVE::Tools::dir_glob_foreach($base_dir, '.*\.(?:tt|in).*', sub {
	my ($filename) = @_;
	return if !-e "$template_dir/$filename";

	my $shipped = PVE::Tools::file_get_contents("$base_dir/$filename", 1024*1024);
	my $override = PVE::Tools::file_get_contents("$template_dir/$filename", 1024*1024);

	push @override_but_unmodified, $filename if $shipped eq $override;
    });
    if (scalar(@override_but_unmodified)) {
	my $msg = "Found overrides in '/etc/pmg/templates/' for template, but without modification."
	    ." Consider simply removing them: \n    "
	    . join("\n    ", @override_but_unmodified);
	log_notice($msg);
    }
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
