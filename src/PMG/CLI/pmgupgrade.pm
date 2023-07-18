package PMG::CLI::pmgupgrade;

use strict;
use warnings;
use File::stat ();

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::INotify;
use PVE::CLIHandler;

use PMG::RESTEnvironment;
use PMG::API2::APT;

use base qw(PVE::CLIHandler);

sub setup_environment {
    PMG::RESTEnvironment->setup_default_cli_env();
}

__PACKAGE__->register_method ({
    name => 'pmgupgrade',
    path => 'pmgupgrade',
    method => 'POST',
    description => "Upgrade Proxmox Mail Gateway",
    parameters => {
	additionalProperties => 0,
	properties => {
	    shell => {
		type => 'boolean',
		description => "Run an interactive shell after the update.",
		optional => 1,
		default => 0,
	    },
	}
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $nodename = PVE::INotify::nodename();

	my $st = File::stat::stat("/var/cache/apt/pkgcache.bin");
	if (!$st || (time() - $st->mtime) > (3*24*3600)) {
	    print "\nYour package database is out of date. " .
		"Please update that first.\n\n";
	    return undef;
	}

	my $cmdstr = 'apt-get dist-upgrade';

	print "Starting system upgrade: apt-get dist-upgrade\n";

	my $oldlist = PMG::API2::APT->list_updates({ node => $nodename});

	system('apt-get', 'dist-upgrade');

	my $pkglist = PMG::API2::APT->list_updates({ node => $nodename});

	print "\n";
	if (my $count = scalar(@$pkglist)) {
	    print "System not fully up to date (found $count new packages)\n\n";
	} else {
	    print "Your System is up-to-date\n\n";
	}

	my $newkernel;
	foreach my $p (@$oldlist) {
	    if (($p->{Package} =~ m/^(?:pve|proxmox)-kernel/) &&
		!grep { $_->{Package} eq $p->{Package} } @$pkglist) {
		$newkernel = 1;
		last;
	    }
	}

	if ($newkernel) {
	    print "\n";
	    print "Seems you installed a kernel update - Please consider rebooting\n" .
		"this node to activate the new kernel.\n\n";
	}

	if ($param->{shell}) {
	    print "starting shell\n";
	    system('/bin/bash -l');
	}

	return undef;
    }});

our $cmddef = [ __PACKAGE__, 'pmgupgrade', []];

1;
