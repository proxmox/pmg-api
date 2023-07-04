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

use Proxmox::RS::APT::Repositories;

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
	    { id => 'repositories' },
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

my $assemble_pkginfo = sub {
    my ($pkgname, $info, $current_ver, $candidate_ver)  = @_;

    my $data = {
	Package => $info->{Name},
	Title => $info->{ShortDesc},
	Origin => 'unknown',
    };

    if (my $pkgfile = &$get_pkgfile($candidate_ver)) {
	$data->{Origin} = $pkgfile->{Origin};
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

	my $cmd = ['apt-get', 'changelog', '-qq'];
	if (my $version = $param->{version}) {
	    push @$cmd, "$pkgname=$version";
	} else {
	    push @$cmd, "$pkgname";
	}

	my $output = "";

	my $rc = PVE::Tools::run_command(
	    $cmd,
	    timeout => 10,
	    logfunc => sub {
		my $line = shift;
		$output .= "$line\n";
	    },
	    noerr => 1,
	);

	$output .= "RC: $rc" if $rc != 0;

	return $output;
    }});

__PACKAGE__->register_method({
    name => 'repositories',
    path => 'repositories',
    method => 'GET',
    proxyto => 'node',
    description => "Get APT repository information.",
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => "object",
	description => "Result from parsing the APT repository files in /etc/apt/.",
	properties => {
	    files => {
		type => "array",
		description => "List of parsed repository files.",
		items => {
		    type => "object",
		    properties => {
			path => {
			    type => "string",
			    description => "Path to the problematic file.",
			},
			'file-type' => {
			    type => "string",
			    enum => [ 'list', 'sources' ],
			    description => "Format of the file.",
			},
			repositories => {
			    type => "array",
			    description => "The parsed repositories.",
			    items => {
				type => "object",
				properties => {
				    Types => {
					type => "array",
					description => "List of package types.",
					items => {
					    type => "string",
					    enum => [ 'deb', 'deb-src' ],
					},
				    },
				    URIs => {
					description => "List of repository URIs.",
					type => "array",
					items => {
					    type => "string",
					},
				    },
				    Suites => {
					type => "array",
					description => "List of package distribuitions",
					items => {
					    type => "string",
					},
				    },
				    Components => {
					type => "array",
					description => "List of repository components",
					optional => 1, # not present if suite is absolute
					items => {
					    type => "string",
					},
				    },
				    Options => {
					type => "array",
					description => "Additional options",
					optional => 1,
					items => {
					    type => "object",
					    properties => {
						Key => {
						    type => "string",
						},
						Values => {
						    type => "array",
						    items => {
							type => "string",
						    },
						},
					    },
					},
				    },
				    Comment => {
					type => "string",
					description => "Associated comment",
					optional => 1,
				    },
				    FileType => {
					type => "string",
					enum => [ 'list', 'sources' ],
					description => "Format of the defining file.",
				    },
				    Enabled => {
					type => "boolean",
					description => "Whether the repository is enabled or not",
				    },
				},
			    },
			},
			digest => {
			    type => "array",
			    description => "Digest of the file as bytes.",
			    items => {
				type => "integer",
			    },
			},
		    },
		},
	    },
	    errors => {
		type => "array",
		description => "List of problematic repository files.",
		items => {
		    type => "object",
		    properties => {
			path => {
			    type => "string",
			    description => "Path to the problematic file.",
			},
			error => {
			    type => "string",
			    description => "The error message",
			},
		    },
		},
	    },
	    digest => {
		type => "string",
		description => "Common digest of all files.",
	    },
	    infos => {
		type => "array",
		description => "Additional information/warnings for APT repositories.",
		items => {
		    type => "object",
		    properties => {
			path => {
			    type => "string",
			    description => "Path to the associated file.",
			},
			index => {
			    type => "string",
			    description => "Index of the associated repository within the file.",
			},
			property => {
			    type => "string",
			    description => "Property from which the info originates.",
			    optional => 1,
			},
			kind => {
			    type => "string",
			    description => "Kind of the information (e.g. warning).",
			},
			message => {
			    type => "string",
			    description => "Information message.",
			}
		    },
		},
	    },
	    'standard-repos' => {
		type => "array",
		description => "List of standard repositories and their configuration status",
		items => {
		    type => "object",
		    properties => {
			handle => {
			    type => "string",
			    description => "Handle to identify the repository.",
			},
			name => {
			    type => "string",
			    description => "Display name of the repository.",
			},
			description => {
			    type => "string",
			    description => "Description of the repository.",
			},
			status => {
			    type => "boolean",
			    optional => 1,
			    description => "Indicating enabled/disabled status, if the " .
				"repository is configured.",
			},
		    },
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	return Proxmox::RS::APT::Repositories::repositories("pmg");
    }});

__PACKAGE__->register_method({
    name => 'add_repository',
    path => 'repositories',
    method => 'PUT',
    description => "Add a standard repository to the configuration",
    permissions => { check => [ 'admin' ] },
    protected => 1,
    proxyto => 'node',
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    handle => {
		type => 'string',
		description => "Handle that identifies a repository.",
	    },
	    digest => {
		type => "string",
		description => "Digest to detect modifications.",
		maxLength => 80,
		optional => 1,
	    },
	},
    },
    returns => {
	type => 'null',
    },
    code => sub {
	my ($param) = @_;

	Proxmox::RS::APT::Repositories::add_repository($param->{handle}, "pmg", $param->{digest});
    }});

__PACKAGE__->register_method({
    name => 'change_repository',
    path => 'repositories',
    method => 'POST',
    description => "Change the properties of a repository. Currently only allows enabling/disabling.",
    permissions => { check => [ 'admin' ] },
    protected => 1,
    proxyto => 'node',
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    path => {
		type => 'string',
		description => "Path to the containing file.",
	    },
	    index => {
		type => 'integer',
		description => "Index within the file (starting from 0).",
	    },
	    enabled => {
		type => 'boolean',
		description => "Whether the repository should be enabled or not.",
		optional => 1,
	    },
	    digest => {
		type => "string",
		description => "Digest to detect modifications.",
		maxLength => 80,
		optional => 1,
	    },
	},
    },
    returns => {
	type => 'null',
    },
    code => sub {
	my ($param) = @_;

	my $options = {};

	my $enabled = $param->{enabled};
	$options->{enabled} = int($enabled) if defined($enabled);

	Proxmox::RS::APT::Repositories::change_repository(
	    $param->{path},
	    int($param->{index}),
	    $options,
	    $param->{digest}
	);
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
	push @list, sort $byver grep { /^(?:pve|proxmox)-kernel-/ && $cache->{$_}->{CurrentState} eq 'Installed' } keys %$cache;

	my @opt_pack = qw(
	    ifupdown
	    ifupdown2
	    libpve-apiclient-perl
	    proxmox-mailgateway-container
	    proxmox-offline-mirror-helper
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
	    libproxmox-acme-perl
	    libproxmox-acme-plugins
	    libxdgmime-perl
	    lvm2
	    pmg-docs
	    pmg-i18n
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
