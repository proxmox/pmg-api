package PMG::CLI::pmgsubscription;

use strict;
use warnings;

use PVE::Tools;
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::CLIHandler;

use PMG::RESTEnvironment;
use PMG::API2::Subscription;

use base qw(PVE::CLIHandler);

my $nodename = PVE::INotify::nodename();

sub setup_environment {
    PMG::RESTEnvironment->setup_default_cli_env();
}

our $cmddef = {
    update => [ 'PMG::API2::Subscription', 'update', undef, { node => $nodename } ],
    get => [ 'PMG::API2::Subscription', 'get', undef, { node => $nodename }, 
	     sub {
		 my $info = shift;
		 foreach my $k (sort keys %$info) {
		     print "$k: $info->{$k}\n";
		 }
	     }],
    set => [ 'PMG::API2::Subscription', 'set', ['key'], { node => $nodename } ],
};

1;
