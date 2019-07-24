#!/usr/bin/perl 

use strict;
use warnings;
use DBI;
use lib '..';

use PVE::SafeSyslog;

use PMG::DBTools;
use PMG::RuleDB;

initlog ($0, 'mail');

my $list = PMG::DBTools::database_list();

my $dbname = "Proxmox_testdb";

if ($list->{$dbname}) {

    print "Drop all connections from existing test database '$dbname'\n";
    my $dbh = PMG::DBTools::open_ruledb($dbname);
    $dbh->do(
	"SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity ".
	"WHERE pg_stat_activity.datname = '$dbname' AND pid <> pg_backend_pid()"
    );
    $dbh->disconnect();

    print "delete existing test database '$dbname'\n";
    PMG::DBTools::delete_ruledb($dbname);
}

my $dbh = PMG::DBTools::create_ruledb($dbname);
my $ruledb = PMG::RuleDB->new($dbh);

$ruledb->close();

exit (0);
