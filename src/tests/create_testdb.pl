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

    print "delete existing test database\n";
    PMG::DBTools::delete_ruledb($dbname);
}

my $dbh = PMG::DBTools::create_ruledb($dbname);
my $ruledb = PMG::RuleDB->new($dbh);

$ruledb->close();

exit (0);
