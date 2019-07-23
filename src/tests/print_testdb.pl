#!/usr/bin/perl 

use strict;
use warnings;
use DBI;
use lib '..';

use PVE::SafeSyslog;

use PMG::DBTools;
use PMG::RuleDB;

initlog($0, 'mail');

my $dbh = PMG::DBTools::open_ruledb("Proxmox_testdb");
my $ruledb = PMG::RuleDB->new($dbh);

# print settings

sub print_objects {
    my ($og) = @_;

    my $objects = $ruledb->load_group_objects($og->{id});

    foreach my $obj (@$objects) {
	my $desc = $obj->short_desc();
	print "    OBJECT $obj->{id}: $desc\n";
    }
}

sub print_rule {
    my $rule = shift;

    print "Found RULE $rule->{id}: $rule->{name}\n";

    my ($from, $to, $when, $what, $action) = 
	$ruledb->load_groups($rule);

    foreach my $og (@$from) {
	print "  FOUND FROM GROUP $og->{id}: $og->{name}\n";
	print_objects($og);
    }
    foreach my $og (@$to) {
	print "  FOUND TO GROUP $og->{id}: $og->{name}\n";
	print_objects($og);
    }
    foreach my $og (@$when) {
	print "  FOUND WHEN GROUP $og->{id}: $og->{name}\n";
	print_objects($og);
    }
    foreach my $og (@$what) {
	print "  FOUND WHAT GROUP $og->{id}: $og->{name}\n";
	print_objects($og);
    }
    foreach my $og (@$action) {
	print "  FOUND ACTION GROUP $og->{id}: $og->{name}\n";
	print_objects($og);
    }
}

my $rules = $ruledb->load_rules();

foreach my $rule (@$rules) {
    print_rule $rule;
}


$ruledb->close();

exit (0);
