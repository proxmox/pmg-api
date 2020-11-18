package PMG::PBSSchedule;

use strict;
use warnings;

use PVE::Tools qw(run_command file_set_contents file_get_contents trim dir_glob_foreach);
use PVE::Systemd;

# note: not exactly cheap...
my sub next_calendar_event {
    my ($spec) = @_;

    my $res = '-';
    eval {
	run_command(
	    ['systemd-analyze', 'calendar', $spec],
	    noerr => 1,
	    outfunc => sub {
		my $line = shift;
		if ($line =~ /^\s*Next elapse:\s*(.+)$/) {
		    $res = $1;
		}
	    },
	);
    };
    return $res;
}

# systemd timer, filter optionally by a $remote
sub get_schedules {
    my ($filter_remote) = @_;

    my $result = [];

    my $systemd_dir = '/etc/systemd/system';

    dir_glob_foreach($systemd_dir, '^pmg-pbsbackup@.+\.timer$', sub {
	my ($filename) = @_;
	my $remote;
	if ($filename =~ /^pmg-pbsbackup\@(.+)\.timer$/) {
	    $remote = PVE::Systemd::unescape_unit($1);
	} else {
	    die "Unrecognized timer name!\n";
	}

	if (defined($filter_remote) && $filter_remote ne $remote) {
	    return; # next
	}

	my $unitfile = "$systemd_dir/$filename";
	my $unit = PVE::Systemd::read_ini($unitfile);
	my $timer = $unit->{'Timer'};

	push @$result, {
	    unitfile => $unitfile,
	    remote => $remote,
	    schedule => $timer->{'OnCalendar'},
	    delay => $timer->{'RandomizedDelaySec'},
	    'next-run' => next_calendar_event($timer->{'OnCalendar'}),
	};
    });

    return $result;

}

sub create_schedule {
    my ($remote, $schedule, $delay) = @_;

    my $unit_name = 'pmg-pbsbackup@' . PVE::Systemd::escape_unit($remote);
    #my $service_unit = $unit_name . '.service';
    my $timer_unit = $unit_name . '.timer';
    my $timer_unit_path = "/etc/systemd/system/$timer_unit";

    # create systemd timer
    run_command(
	['systemd-analyze', 'calendar', $schedule],
	errmsg => "Invalid schedule specification",
	outfunc => sub {},
    );
    run_command(
	['systemd-analyze', 'timespan', $delay],
	errmsg => "Invalid delay specification",
	outfunc => sub {},
    );
    my $timer = {
	'Unit' => {
	    'Description' => "Timer for PBS Backup to remote $remote",
	},
	'Timer' => {
	    'OnCalendar' => $schedule,
	    'RandomizedDelaySec' => $delay,
	},
	'Install' => {
	    'WantedBy' => 'timers.target',
	},
    };

    eval {
	PVE::Systemd::write_ini($timer, $timer_unit_path);
	run_command(['systemctl', 'daemon-reload']);
	run_command(['systemctl', 'enable', $timer_unit]);
	run_command(['systemctl', 'start', $timer_unit]);

    };
    if (my $err = $@) {
	die "Creating backup schedule for $remote failed: $err\n";
    }

    return;
}

sub delete_schedule {
    my ($remote) = @_;

    my $schedules = get_schedules($remote);

    die "Schedule for $remote not found!\n" if scalar(@$schedules) < 1;

    my $unit_name = 'pmg-pbsbackup@' . PVE::Systemd::escape_unit($remote);
    my $service_unit = $unit_name . '.service';
    my $timer_unit = $unit_name . '.timer';
    my $timer_unit_path = "/etc/systemd/system/$timer_unit";

    eval {
	run_command(['systemctl', 'disable', '--now', $timer_unit]);
	unlink($timer_unit_path) || die "delete '$timer_unit_path' failed - $!\n";
	run_command(['systemctl', 'daemon-reload']);

    };
    if (my $err = $@) {
	die "Removing backup schedule for $remote failed: $err\n";
    }

    return;
}

1;
