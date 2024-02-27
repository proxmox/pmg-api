package PMG::CLI::pmgdb;

use strict;
use warnings;
use Data::Dumper;
use Encode qw(encode);

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::INotify;
use PVE::CLIHandler;

use PMG::Utils;
use PMG::RESTEnvironment;
use PMG::DBTools;
use PMG::RuleDB;
use PMG::Cluster;
use PMG::ClusterConfig;
use PMG::Statistic;

use PMG::API2::RuleDB;

use base qw(PVE::CLIHandler);

sub setup_environment {
    PMG::RESTEnvironment->setup_default_cli_env();
}

sub print_objects {
    my ($ruledb, $og) = @_;

    my $objects = $ruledb->load_group_objects ($og->{id});

    foreach my $obj (@$objects) {
	my $type_text = $obj->otype_text();
	my $desc = encode('UTF-8', $obj->short_desc());
	print "    OBJECT $type_text $obj->{id}: $desc\n";
    }
}

sub print_rule {
    my ($ruledb, $rule, $rule_status) = @_;

    $ruledb->load_rule_attributes($rule);

    return if !$rule->{active} && $rule_status eq 'active';
    return if $rule->{active} && $rule_status eq 'inactive';

    my $direction = {
	0 => 'in',
	1 => 'out',
	2 => 'in+out',
    };
    my $active = $rule->{active} ? 'ACTIVE' : 'inactive';
    my $dir = $direction->{$rule->{direction}};
    my $rulename = encode('UTF-8', $rule->{name});

    print "RULE $rule->{id} (prio: $rule->{priority}, $dir, $active): $rulename\n";

    my $print_group = sub {
	my ($type, $og, $print_mode) = @_;
	my $oname = encode('UTF-8', $og->{name});
	my $mode = "";
	if ($print_mode) {
	    my $and = $og->{and} // 0;
	    my $invert = $og->{invert} // 0;
	    $mode = " (and=$and, invert=$invert)";
	}
	print "  $type group $og->{id}${mode}: $oname\n";
	print_objects($ruledb, $og);
    };

    my $print_type_mode = sub {
	my ($type) = @_;
	my $and = $rule->{"$type-and"};
	my $invert = $rule->{"$type-invert"};
	if (defined($and) || defined($invert)) {
	    my $print_type = uc($type);
	    print "  $print_type mode: and=" . ($and // 0) . " invert=". ($invert // 0) . "\n";
	}
    };

    my ($from, $to, $when, $what, $action) =
	$ruledb->load_groups($rule);

    $print_type_mode->("from") if scalar(@$from);
    foreach my $og (@$from) {
	$ruledb->load_group_attributes($og);
	$print_group->("FROM", $og, 1);
    }
    $print_type_mode->("to") if scalar(@$to);
    foreach my $og (@$to) {
	$ruledb->load_group_attributes($og);
	$print_group->("TO", $og, 1);
    }
    $print_type_mode->("when") if scalar(@$when);
    foreach my $og (@$when) {
	$ruledb->load_group_attributes($og);
	$print_group->("WHEN", $og, 1);
    }
    $print_type_mode->("what") if scalar(@$what);
    foreach my $og (@$what) {
	$ruledb->load_group_attributes($og);
	$print_group->("WHAT", $og, 1);
    }
    foreach my $og (@$action) {
	$print_group->("ACTION", $og);
    }
}

__PACKAGE__->register_method ({
    name => 'dump',
    path => 'dump',
    method => 'GET',
    description => "Print the PMG rule database.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    rules => {
		description => "Which rules should be printed",
		type => 'string',
		enum => [qw(all active inactive)],
		default => 'all',
		optional => 1,
	    },
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $rule_status = $param->{rules} // '';
	my $dbh = PMG::DBTools::open_ruledb("Proxmox_ruledb");
	my $ruledb = PMG::RuleDB->new($dbh);

	my $rules = $ruledb->load_rules();

	foreach my $rule (@$rules) {
	    print_rule($ruledb, $rule, $rule_status);
	}

	$ruledb->close();

	return undef;
    }});


__PACKAGE__->register_method ({
    name => 'delete',
    path => 'delete',
    method => 'DELETE',
    description => "Delete PMG rule database.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $list = PMG::DBTools::database_list();

	my $dbname = "Proxmox_ruledb";

	die "Database '$dbname' does not exist\n" if !$list->{$dbname};

	syslog('info', "delete rule database");

	PMG::DBTools::delete_ruledb($dbname);

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'init',
    path => 'init',
    method => 'POST',
    description => "Initialize/Upgrade the PMG rule database.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    force => {
		type => 'boolean',
		description => "Delete existing database.",
		optional => 1,
		default => 0,
	    },
	    statistics => {
		type => 'boolean',
		description => "Reset and update statistic database.",
		optional => 1,
		default => 0,
	    },
	}
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	PMG::Utils::cond_add_default_locale();

	my $list = PMG::DBTools::database_list();

	my $dbname = "Proxmox_ruledb";

	if (!$list->{$dbname} || $param->{force}) {

	    if ($list->{$dbname}) {
		print "Destroy existing rule database\n";
		PMG::DBTools::delete_ruledb($dbname);
	    }

	    print "Initialize rule database\n";

	    my $dbh = PMG::DBTools::create_ruledb ($dbname);
	    my $ruledb = PMG::RuleDB->new($dbh);
	    PMG::DBTools::init_ruledb($ruledb);

	    $dbh->disconnect();

	} else {

	    my $dbh = PMG::DBTools::open_ruledb("Proxmox_ruledb");
	    my $ruledb = PMG::RuleDB->new($dbh);

	    print "Analyzing/Upgrading existing Databases...";
	    PMG::DBTools::upgradedb ($ruledb);
	    print "done\n";

	    # reset and update statistic databases
	    if ($param->{statistics}) {
		print "Generating Proxmox Statistic Databases... ";
		PMG::Statistic::clear_stats($dbh);
		my $cinfo = PVE::INotify::read_file("cluster.conf");
		PMG::Statistic::update_stats($dbh, $cinfo);
		print "done\n";
	    }

	    $dbh->disconnect();
	}

	return undef;
    }});


__PACKAGE__->register_method ({
    name => 'update',
    path => 'update',
    method => 'POST',
    description => "Update the PMG statistic database.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $dbh = PMG::DBTools::open_ruledb("Proxmox_ruledb");
	print "Updating Proxmox Statistic Databases... ";
	my $cinfo = PVE::INotify::read_file("cluster.conf");
	PMG::Statistic::update_stats($dbh, $cinfo);
	print "done\n";
	$dbh->disconnect();

	return undef;
    }});

our $cmddef = {
    'dump' => [ __PACKAGE__, 'dump', []],
    delete => [ __PACKAGE__, 'delete', []],
    init => [ __PACKAGE__, 'init', []],
    reset => [ 'PMG::API2::RuleDB', 'reset_ruledb', []],
    update => [ __PACKAGE__, 'update', []],
};

1;
