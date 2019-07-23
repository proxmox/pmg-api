package PMG::CLI::pmgdb;

use strict;
use warnings;
use Data::Dumper;

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
	my $desc = $obj->short_desc ();
	print "    OBJECT $obj->{id}: $desc\n";
    }
}

sub print_rule {
    my ($ruledb, $rule) = @_;

    my $direction = {
	0 => 'in',
	1 => 'out',
	2 => 'in+out',
    };
    my $active = $rule->{active} ? 'active' : 'inactive';
    my $dir = $direction->{$rule->{direction}};

    print "Found RULE $rule->{id} (prio: $rule->{priority}, $dir, $active): $rule->{name}\n";

    my ($from, $to, $when, $what, $action) =
	$ruledb->load_groups($rule);

    foreach my $og (@$from) {
	print "  FOUND FROM GROUP $og->{id}: $og->{name}\n";
	print_objects($ruledb, $og);
    }
    foreach my $og (@$to) {
	print "  FOUND TO GROUP $og->{id}: $og->{name}\n";
	print_objects($ruledb, $og);
    }
    foreach my $og (@$when) {
	print "  FOUND WHEN GROUP $og->{id}: $og->{name}\n";
	print_objects($ruledb, $og);
    }
    foreach my $og (@$what) {
	print "  FOUND WHAT GROUP $og->{id}: $og->{name}\n";
	print_objects($ruledb, $og);
    }
    foreach my $og (@$action) {
	print "  FOUND ACTION GROUP $og->{id}: $og->{name}\n";
	print_objects($ruledb, $og);
    }
}

__PACKAGE__->register_method ({
    name => 'dump',
    path => 'dump',
    method => 'GET',
    description => "Print the PMG rule database.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $dbh = PMG::DBTools::open_ruledb("Proxmox_ruledb");
	my $ruledb = PMG::RuleDB->new($dbh);

	my $rules = $ruledb->load_rules();

	foreach my $rule (@$rules) {
	    print_rule($ruledb, $rule);
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
	print "Updateing Proxmox Statistic Databases... ";
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
