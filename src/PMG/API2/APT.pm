package PMG::API2::APT;

use strict;
use warnings;

use POSIX;
use File::stat ();
use IO::File;
use File::Basename;
use JSON;
use LWP::UserAgent;

use PVE::Tools qw(extract_param);
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::Exception;
use PVE::RESTHandler;
use PVE::JSONSchema qw(get_standard_option);

use PMG::RESTEnvironment;
use PMG::pmgcfg;
use PMG::Config;

use AptPkg::Cache;
use AptPkg::Version;
use AptPkg::PkgRecords;

my $get_apt_cache = sub {

    my $apt_cache = AptPkg::Cache->new() || die "unable to initialize AptPkg::Cache\n";

    return $apt_cache;
};

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index for apt (Advanced Package Tool).",
    permissions => {
	user => 'all',
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => "array",
	items => {
	    type => "object",
	    properties => {
		id => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{id}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $res = [
	    { id => 'changelog' },
	    { id => 'update' },
	    { id => 'versions' },
	];

	return $res;
    }});

my $get_pkgfile = sub {
    my ($veriter)  = @_;

    foreach my $verfile (@{$veriter->{FileList}}) {
	my $pkgfile = $verfile->{File};
	next if !$pkgfile->{Origin};
	return $pkgfile;
    }

    return undef;
};

my $get_changelog_url =sub {
    my ($pkgname, $info, $pkgver, $origin, $component) = @_;

    my $changelog_url;
    my $base = dirname($info->{FileName});
    if ($origin && $base) {
	$pkgver =~ s/^\d+://; # strip epoch
	my $srcpkg = $info->{SourcePkg} || $pkgname;
	if ($origin eq 'Debian') {
	    $base =~ s!pool/updates/!pool/!; # for security channel
	    $changelog_url = "http://packages.debian.org/changelogs/$base/" .
		"${srcpkg}_${pkgver}/changelog";
	} elsif ($origin eq 'Proxmox') {
	    if ($component eq 'pmg-enterprise') {
		$changelog_url = "https://enterprise.proxmox.com/debian/pmg/$base/" .
		    "${pkgname}_${pkgver}.changelog";
	    } else {
		$changelog_url = "http://download.proxmox.com/debian/pmg/$base/" .
		    "${pkgname}_${pkgver}.changelog";
	    }
	}
    }

    return $changelog_url;
};

my $assemble_pkginfo = sub {
    my ($pkgname, $info, $current_ver, $candidate_ver)  = @_;

    my $data = {
	Package => $info->{Name},
	Title => $info->{ShortDesc},
	Origin => 'unknown',
    };

    if (my $pkgfile = &$get_pkgfile($candidate_ver)) {
	$data->{Origin} = $pkgfile->{Origin};
	if (my $changelog_url = &$get_changelog_url($pkgname, $info, $candidate_ver->{VerStr},
						    $pkgfile->{Origin}, $pkgfile->{Component})) {
	    $data->{ChangeLogUrl} = $changelog_url;
	}
    }

    if (my $desc = $info->{LongDesc}) {
	$desc =~ s/^.*\n\s?//; # remove first line
	$desc =~ s/\n / /g;
	$data->{Description} = $desc;
    }

    foreach my $k (qw(Section Arch Priority)) {
	$data->{$k} = $candidate_ver->{$k};
    }

    $data->{Version} = $candidate_ver->{VerStr};
    $data->{OldVersion} = $current_ver->{VerStr} if $current_ver;

    return $data;
};

# we try to cache results
my $pmg_pkgstatus_fn = "/var/lib/pmg/pkgupdates";

my $read_cached_pkgstatus = sub {
    my $data = [];
    eval {
	my $jsonstr = PVE::Tools::file_get_contents($pmg_pkgstatus_fn, 5*1024*1024);
	$data = decode_json($jsonstr);
    };
    if (my $err = $@) {
	warn "error reading cached package status in $pmg_pkgstatus_fn\n";
    }
    return $data;
};

my $update_pmg_pkgstatus = sub {

    syslog('info', "update new package list: $pmg_pkgstatus_fn");

    my $notify_status = {};
    my $oldpkglist = &$read_cached_pkgstatus();
    foreach my $pi (@$oldpkglist) {
	$notify_status->{$pi->{Package}} = $pi->{NotifyStatus};
    }

    my $pkglist = [];

    my $cache = &$get_apt_cache();
    my $policy = $cache->policy;
    my $pkgrecords = $cache->packages();

    foreach my $pkgname (keys %$cache) {
	my $p = $cache->{$pkgname};
	next if !$p->{SelectedState} || ($p->{SelectedState} ne 'Install');
	my $current_ver = $p->{CurrentVer} || next;
	my $candidate_ver = $policy->candidate($p) || next;

	if ($current_ver->{VerStr} ne $candidate_ver->{VerStr}) {
	    my $info = $pkgrecords->lookup($pkgname);
	    my $res = &$assemble_pkginfo($pkgname, $info, $current_ver, $candidate_ver);
	    push @$pkglist, $res;

	    # also check if we need any new package
	    # Note: this is just a quick hack (not recursive as it should be), because
	    # I found no way to get that info from AptPkg
	    if (my $deps = $candidate_ver->{DependsList}) {
		my $found;
		my $req;
		for my $d (@$deps) {
		    if ($d->{DepType} eq 'Depends') {
			$found = $d->{TargetPkg}->{SelectedState} eq 'Install' if !$found;
			$req = $d->{TargetPkg} if !$req;

			if (!($d->{CompType} & AptPkg::Dep::Or)) {
			    if (!$found && $req) { # New required Package
				my $tpname = $req->{Name};
				my $tpinfo = $pkgrecords->lookup($tpname);
				my $tpcv = $policy->candidate($req);
				if ($tpinfo && $tpcv) {
				    my $res = &$assemble_pkginfo($tpname, $tpinfo, undef, $tpcv);
				    push @$pkglist, $res;
				}
			    }
			    undef $found;
			    undef $req;
			}
		    }
		}
	    }
	}
    }

    # keep notification status (avoid sending mails abou new packages more than once)
    foreach my $pi (@$pkglist) {
	if (my $ns = $notify_status->{$pi->{Package}}) {
	    $pi->{NotifyStatus} = $ns if $ns eq $pi->{Version};
	}
    }

    PVE::Tools::file_set_contents($pmg_pkgstatus_fn, encode_json($pkglist));

    return $pkglist;
};

__PACKAGE__->register_method({
    name => 'list_updates',
    path => 'update',
    method => 'GET',
    description => "List available updates.",
    protected => 1,
    proxyto => 'node',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
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

	if (my $st1 = File::stat::stat($pmg_pkgstatus_fn)) {
	    my $st2 = File::stat::stat("/var/cache/apt/pkgcache.bin");
	    my $st3 = File::stat::stat("/var/lib/dpkg/status");

	    if ($st2 && $st3 && $st2->mtime <= $st1->mtime && $st3->mtime <= $st1->mtime) {
		if (my $data = &$read_cached_pkgstatus()) {
		    return $data;
		}
	    }
	}

	my $pkglist = &$update_pmg_pkgstatus();

	return $pkglist;
    }});

__PACKAGE__->register_method({
    name => 'update_database',
    path => 'update',
    method => 'POST',
    description => "This is used to resynchronize the package index files from their sources (apt-get update).",
    protected => 1,
    proxyto => 'node',
    permissions => { check => [ 'admin' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    notify => {
		type => 'boolean',
		description => "Send notification mail about new packages (to email address specified for user 'root\@pam').",
		optional => 1,
		default => 0,
	    },
	    quiet => {
		type => 'boolean',
		description => "Only produces output suitable for logging, omitting progress indicators.",
		optional => 1,
		default => 0,
	    },
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();

	my $authuser = $rpcenv->get_user();

	my $realcmd = sub {
	    my $upid = shift;

	    my $pmg_cfg = PMG::Config->new();

	    my $http_proxy = $pmg_cfg->get('admin', 'http_proxy');
	    my $aptconf = "// no proxy configured\n";
	    if ($http_proxy) {
		$aptconf = "Acquire::http::Proxy \"${http_proxy}\";\n";
	    }
	    my $aptcfn = "/etc/apt/apt.conf.d/76pmgproxy";
	    PVE::Tools::file_set_contents($aptcfn, $aptconf);

	    my $cmd = ['apt-get', 'update'];

	    print "starting apt-get update\n" if !$param->{quiet};

	    if ($param->{quiet}) {
		PVE::Tools::run_command($cmd, outfunc => sub {}, errfunc => sub {});
	    } else {
		PVE::Tools::run_command($cmd);
	    }

	    my $pkglist = &$update_pmg_pkgstatus();

	    if ($param->{notify} && scalar(@$pkglist)) {

		my $mailfrom = "root";

		if (my $mailto = $pmg_cfg->get('admin', 'email', 1)) {

		    my $text .= "The following updates are available:\n\n";

		    my $count = 0;
		    foreach my $p (sort {$a->{Package} cmp $b->{Package} } @$pkglist) {
			next if $p->{NotifyStatus} && $p->{NotifyStatus} eq $p->{Version};
			$count++;
			if ($p->{OldVersion}) {
			    $text .= "$p->{Package}: $p->{OldVersion} ==> $p->{Version}\n";
			} else {
			    $text .= "$p->{Package}: $p->{Version} (new)\n";
			}
		    }

		    return if !$count;

		    my $hostname = `hostname -f` || PVE::INotify::nodename();
		    chomp $hostname;

		    my $subject = "New software packages available ($hostname)";
		    PVE::Tools::sendmail($mailto, $subject, $text, undef,
					 $mailfrom, 'Proxmox Mail Gateway');

		    foreach my $pi (@$pkglist) {
			$pi->{NotifyStatus} = $pi->{Version};
		    }

		    PVE::Tools::file_set_contents($pmg_pkgstatus_fn, encode_json($pkglist));
		}
	    }

	    return;
	};

	return $rpcenv->fork_worker('aptupdate', undef, $authuser, $realcmd);

    }});

__PACKAGE__->register_method({
    name => 'changelog',
    path => 'changelog',
    method => 'GET',
    description => "Get package changelogs.",
    proxyto => 'node',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    name => {
		description => "Package name.",
		type => 'string',
	    },
	    version => {
		description => "Package version.",
		type => 'string',
		optional => 1,
	    },
	},
    },
    returns => {
	type => "string",
    },
    code => sub {
	my ($param) = @_;

	my $pkgname = $param->{name};

	my $cache = &$get_apt_cache();
	my $policy = $cache->policy;
	my $p = $cache->{$pkgname} || die "no such package '$pkgname'\n";
	my $pkgrecords = $cache->packages();

	my $ver;
	if ($param->{version}) {
	    if (my $available = $p->{VersionList}) {
		for my $v (@$available) {
		    if ($v->{VerStr} eq $param->{version}) {
			$ver = $v;
			last;
		    }
		}
	    }
	    die "package '$pkgname' version '$param->{version}' is not available\n" if !$ver;
	} else {
	    $ver = $policy->candidate($p) || die "no installation candidate for package '$pkgname'\n";
	}

	my $info = $pkgrecords->lookup($pkgname);

	my $pkgfile = &$get_pkgfile($ver);
	my $url;

	die "changelog for '${pkgname}_$ver->{VerStr}' not available\n"
	    if !($pkgfile && ($url = &$get_changelog_url($pkgname, $info, $ver->{VerStr}, $pkgfile->{Origin}, $pkgfile->{Component})));

	my $data = "";

	my $pmg_cfg = PMG::Config->new();
	my $proxy = $pmg_cfg->get('admin', 'http_proxy');

	my $ua = LWP::UserAgent->new;
	$ua->agent("PMG/1.0");
	$ua->timeout(10);
	$ua->max_size(1024*1024);
	$ua->ssl_opts(verify_hostname => 0); # don't care for changelogs

	if ($proxy) {
	    $ua->proxy(['http', 'https'], $proxy);
	} else {
	    $ua->env_proxy;
	}

	my $username;
	my $pw;

	if ($pkgfile->{Origin} eq 'Proxmox' && $pkgfile->{Component} eq 'pmg-enterprise') {
	    my $info = PVE::INotify::read_file('subscription');
	    if ($info->{status} eq 'Active') {
		$username = $info->{key};
		$pw = PMG::Utils::get_hwaddress();
		$ua->credentials("enterprise.proxmox.com:443", 'pmg-enterprise-repository',
				 $username, $pw);
	    }
	}

	syslog('info', "GET $url\n");
	my $response = $ua->get($url);

        if ($response->is_success) {
            $data = $response->decoded_content;
        } else {
	    PVE::Exception::raise($response->message, code => $response->code);
        }

	return $data;
    }});

__PACKAGE__->register_method({
    name => 'versions',
    path => 'versions',
    method => 'GET',
    proxyto => 'node',
    description => "Get package information for important Proxmox packages.",
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
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

	my $cache = &$get_apt_cache();
	my $policy = $cache->policy;
	my $pkgrecords = $cache->packages();

	# order most important things first
	my @list = qw(proxmox-mailgateway pmg-api pmg-gui);

	my $aptver = $AptPkg::System::_system->versioning();
	my $byver = sub { $aptver->compare($cache->{$b}->{CurrentVer}->{VerStr}, $cache->{$a}->{CurrentVer}->{VerStr}) };
	push @list, sort $byver grep { /^pve-kernel-/ && $cache->{$_}->{CurrentState} eq 'Installed' } keys %$cache;

	my @opt_pack = qw(
	    libpve-apiclient-perl
	    proxmox-mailgateway-container
	    pve-firmware
	    zfsutils-linux
	);

	my @pkgs = qw(
	    clamav-daemon
	    libarchive-perl
	    libjs-extjs
	    libjs-framework7
	    libpve-common-perl
	    libpve-http-server-perl
	    libxdgmime-perl
	    lvm2
	    pmg-docs
	    pmg-log-tracker
	    postgresql-13
	    proxmox-mini-journalreader
	    proxmox-spamassassin
	    proxmox-widget-toolkit
	    pve-xtermjs
	    vncterm
	);

	push @list, (sort @pkgs, @opt_pack);

	my (undef, undef, $kernel_release) = POSIX::uname();
	my $pmgver =  PMG::pmgcfg::version_text();

	my $pkglist = [];
	foreach my $pkgname (@list) {
	    my $p = $cache->{$pkgname};
	    my $info = $pkgrecords->lookup($pkgname);
	    my $candidate_ver = defined($p) ? $policy->candidate($p) : undef;
	    my $res;
	    if (my $current_ver = $p->{CurrentVer}) {
		$res = &$assemble_pkginfo($pkgname, $info, $current_ver,
					  $candidate_ver || $current_ver);
	    } elsif ($candidate_ver) {
		$res = &$assemble_pkginfo($pkgname, $info, $candidate_ver,
					  $candidate_ver);
		delete $res->{OldVersion};
	    } else {
		next;
	    }
	    $res->{CurrentState} = $p->{CurrentState};

	    if (grep( /^$pkgname$/, @opt_pack)) {
		next if $res->{CurrentState} eq 'NotInstalled';
	    }

	    # hack: add some useful information (used by 'pmgversion -v')
	    if ($pkgname =~ /^proxmox-mailgateway(-container)?$/) {
		$res->{ManagerVersion} = $pmgver;
		$res->{RunningKernel} = $kernel_release;
		if ($pkgname eq 'proxmox-mailgateway-container') {
		    # another hack: replace proxmox-mailgateway with CT meta pkg
		    shift @$pkglist;
		    unshift @$pkglist, $res;
		    next;
		}
	    }

	    push @$pkglist, $res;
	}

	return $pkglist;
    }});

1;
