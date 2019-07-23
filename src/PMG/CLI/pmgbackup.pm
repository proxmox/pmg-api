package PMG::CLI::pmgbackup;

use strict;
use warnings;
use Data::Dumper;

use PVE::Tools;
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::CLIHandler;

use PMG::RESTEnvironment;
use PMG::API2::Backup;

use base qw(PVE::CLIHandler);

my $nodename = PVE::INotify::nodename();

sub setup_environment {
    PMG::RESTEnvironment->setup_default_cli_env();
}

my $format_backup_list = sub {
    my ($data) = @_;

    foreach my $entry (@$data) {
	printf("%-30s %10d\n", $entry->{filename}, $entry->{size});
    }
};

our $cmddef = {
    backup => [ 'PMG::API2::Backup', 'backup', undef, { node => $nodename } ],
    restore => [ 'PMG::API2::Backup', 'restore', undef, { node => $nodename } ],
    list => [ 'PMG::API2::Backup', 'list', undef, { node => $nodename }, $format_backup_list ],
};

1;
