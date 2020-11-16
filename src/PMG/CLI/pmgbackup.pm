package PMG::CLI::pmgbackup;

use strict;
use warnings;
use Data::Dumper;
use POSIX qw(strftime);

use PVE::Tools;
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::CLIHandler;
use PVE::CLIFormatter;
use PVE::JSONSchema qw(get_standard_option);
use PVE::PTY;

use PMG::RESTEnvironment;
use PMG::API2::Backup;
use PMG::API2::PBS::Remote;
use PMG::API2::PBS::Job;

use base qw(PVE::CLIHandler);

my $nodename = PVE::INotify::nodename();

sub param_mapping {
    my ($name) = @_;

    my $password_map = PVE::CLIHandler::get_standard_mapping('pve-password', {
	func => sub {
	    my ($value) = @_;
	    return $value if $value;
	    return PVE::PTY::get_confirmed_password();
	},
    });

    my $enc_key_map = {
	name => 'encryption-key',
	desc => 'a file containing an encryption key, or the special value "autogen"',
	func => sub {
	    my ($value) = @_;
	    return $value if $value eq 'autogen';
	    return PVE::Tools::file_get_contents($value);
	}
    };


    my $mapping = {
	'create' => [ $password_map, $enc_key_map ],
	'update_config' => [ $password_map, $enc_key_map ],
    };
    return $mapping->{$name};
}


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
    remote => {
	list => ['PMG::API2::PBS::Remote', 'list', undef, undef,  sub {
	    my ($data, $schema, $options) = @_;
	    PVE::CLIFormatter::print_api_result($data, $schema, ['remote', 'server', 'datastore', 'username' ], $options);
	}, $PVE::RESTHandler::standard_output_options ],
	add => ['PMG::API2::PBS::Remote', 'create', ['remote'] ],
	remove => ['PMG::API2::PBS::Remote', 'delete', ['remote'] ],
	set => ['PMG::API2::PBS::Remote', 'update_config', ['remote'] ],
    },
    pbsjob => {
	list_backups => ['PMG::API2::PBS::Job', 'get_snapshots', ['remote'] , { node => $nodename },  sub {
	    my ($data, $schema, $options) = @_;
	    PVE::CLIFormatter::print_api_result($data, $schema, ['time', 'size'], $options);
	}, $PVE::RESTHandler::standard_output_options ],
	forget => ['PMG::API2::PBS::Job', 'forget_snapshot', ['remote', 'time'], { node => $nodename} ],
	run => ['PMG::API2::PBS::Job', 'run_backup', ['remote'], { node => $nodename} ],
	restore => ['PMG::API2::PBS::Job', 'restore', ['remote'], { node => $nodename} ],
    },
};

1;
