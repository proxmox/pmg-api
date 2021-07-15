package PMG::CLI::pmgversion;

use strict;
use warnings;
use POSIX qw();

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::INotify;
use PVE::CLIHandler;

use PMG::RESTEnvironment;
use PMG::pmgcfg;
use PMG::API2::APT;

use base qw(PVE::CLIHandler);

sub setup_environment {
    PMG::RESTEnvironment->setup_default_cli_env();
}

my $print_status = sub {
    my ($pkginfo) = @_;

    my $pkg = $pkginfo->{Package};

    my $version = "not correctly installed";
    if ($pkginfo->{OldVersion} && $pkginfo->{CurrentState} eq 'Installed') {
	$version = $pkginfo->{OldVersion};
    } elsif ($pkginfo->{CurrentState} eq 'ConfigFiles') {
	$version = 'residual config';
    }

    if ($pkginfo->{RunningKernel} && $pkginfo->{ManagerVersion}) {
	print "$pkg: $version (API: $pkginfo->{ManagerVersion}, running kernel: $pkginfo->{RunningKernel})\n";
    } else {
	print "$pkg: $version\n";
    }
};

__PACKAGE__->register_method ({
    name => 'pmgversion',
    path => 'pmgversion',
    method => 'GET',
    description => "Print version information for Proxmox Mail Gateway packages.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    verbose => {
		type => 'boolean',
		description => "List version details for important packages.",
		optional => 1,
		default => 0,
	    },
	}
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $pkgarray = PMG::API2::APT->versions({ node => 'localhost'});

	my $ver =  PMG::pmgcfg::package() . '/' . PMG::pmgcfg::version_text();
	my (undef, undef, $kver) = POSIX::uname();

	if (!$param->{verbose}) {
	    print "$ver (running kernel: $kver)\n";
	    return undef;
	}

	foreach my $pkg (@$pkgarray) {
	    $print_status->($pkg);
	}

	return undef;

    }});

our $cmddef = [ __PACKAGE__, 'pmgversion', []];

1;
