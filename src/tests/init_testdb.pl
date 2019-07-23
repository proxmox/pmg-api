#!/usr/bin/perl 

use strict;
use warnings;
use lib '..';
use DBI;

use PVE::SafeSyslog;

use PMG::DBTools;
use PMG::RuleDB;

initlog ($0, 'mail');

my $dbh = PMG::DBTools::open_ruledb("Proxmox_testdb");
my $ruledb = PMG::RuleDB->new($dbh);
	    
PMG::DBTools::init_ruledb($ruledb, 1 , 1);

$ruledb->close();

exit (0);
