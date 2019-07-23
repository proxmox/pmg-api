#!/usr/bin/perl

use strict;
use warnings;
use lib '..';

use Socket;
use IO::Socket::INET;
use DBI;

use PVE::SafeSyslog;

use PMG::DBTools;
use PMG::RuleDB;

my $greylist_delay = 3*60;
my $greylist_lifetime = 3600*24*2; #retry window
my $greylist_awlifetime = 3600*24*36;

initlog($0, 'mail');

system("systemctl stop pmgpolicy");

my $pidfile = "/var/run/pmgpolicy.pid";

system("kill `cat $pidfile`") if -f $pidfile;

system ("perl -I.. ../bin/pmgpolicy -d Proxmox_testdb -t");

sub reset_gldb {
    my $dbh = PMG::DBTools::open_ruledb("Proxmox_testdb");
    $dbh->do ("DELETE FROM CGreylist");
    $dbh->disconnect();
}

reset_gldb();

my $sock = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1', 
    PeerPort => 10022) ||
    die "unable to open socket -  $!";

$/ = "\n\n";

my $testtime = 1;
my $starttime = $testtime;

my $icount = 0;

sub gltest {
    my ($data, $ttime, $eres) = @_;
    
    $icount++;

    print $sock "testtime=$ttime\ninstance=$icount\n$data\n";
    $sock->flush;
    my $res = <$sock>;
    chomp $res;
    my $timediff = $ttime - $starttime;
    die "unectpexted result at time $timediff: $res != $eres\n$data" if !($res =~ m/^action=$eres(\s.*)?/);
}

# a normal record

my $data = <<_EOD;
request=smtpd_access_policy
protocol_state=RCPT
protocol_name=SMTP
client_address=1.2.3.4
client_name=test.domain.tld
helo_name=test.domain.tld
sender=test1\@test.domain.tld
recipient=test1\@proxmox.com
_EOD

# time 0
reset_gldb ();
gltest ($data, $testtime, 'defer');
gltest ($data, $testtime+$greylist_delay-3, 'defer');
gltest ($data, $testtime+$greylist_delay-1, 'defer');
gltest ($data, $testtime+$greylist_lifetime-1, 'dunno');
gltest ($data, $testtime+$greylist_lifetime-1+$greylist_awlifetime-1, 'dunno');
gltest ($data, $testtime+$greylist_lifetime-1+$greylist_awlifetime-1+$greylist_awlifetime, 'defer');

# time 0
reset_gldb ();
gltest ($data, $testtime, 'defer');
gltest ($data, $testtime+$greylist_delay-3, 'defer');
gltest ($data, $testtime+$greylist_delay-1, 'defer');
gltest ($data, $testtime+$greylist_lifetime+1, 'defer');
gltest ($data, $testtime+$greylist_lifetime+1+$greylist_delay-1, 'defer');
gltest ($data, $testtime+$greylist_lifetime+1+$greylist_delay+1, 'dunno');
gltest ($data, $testtime+$greylist_lifetime+1+$greylist_delay+1+$greylist_awlifetime-1, 'dunno');
gltest ($data, $testtime+$greylist_lifetime+1+$greylist_delay+1+$greylist_awlifetime-1+$greylist_awlifetime, 'defer');

# a record with sender = <> (bounce)

$data = <<_EOD;
request=smtpd_access_policy
protocol_state=RCPT
protocol_name=SMTP
client_address=1.2.3.4
client_name=test.domain.tld
helo_name=test.domain.tld
sender=
recipient=test1\@proxmox.com
_EOD

# time 0
reset_gldb ();

gltest ($data, $testtime, 'defer');
gltest ($data, $testtime+$greylist_delay-3, 'defer');
gltest ($data, $testtime+$greylist_delay-1, 'defer');
gltest ($data, $testtime+$greylist_lifetime-1, 'dunno');
gltest ($data, $testtime+$greylist_lifetime+1, 'defer');

# time 0
reset_gldb ();

gltest ($data, $testtime, 'defer');
gltest ($data, $testtime+$greylist_delay-3, 'defer');
gltest ($data, $testtime+$greylist_delay-1, 'defer');
gltest ($data, $testtime+$greylist_lifetime+1, 'defer');
gltest ($data, $testtime+$greylist_lifetime+1+$greylist_delay-1, 'defer');
gltest ($data, $testtime+$greylist_lifetime+1+$greylist_delay+1, 'dunno');
gltest ($data, $testtime+$greylist_lifetime+1+$greylist_delay+2, 'defer');


my $testdomain = "interspar.at";
my $testipok = "68.232.133.35";
my $testipfail = "1.2.3.4";

my $data_ok = <<_EOD;
request=smtpd_access_policy
protocol_state=RCPT
protocol_name=SMTP
client_address=$testipok
helo_name=$testdomain
sender=xyz\@$testdomain
recipient=testspf\@maurer-it.com
_EOD

gltest ($data_ok, $testtime, 'prepend'); # helo pass

$data_ok = <<_EOD;
request=smtpd_access_policy
protocol_state=RCPT
protocol_name=SMTP
client_address=$testipok
helo_name=
sender=xyz\@$testdomain
recipient=testspf\@proxmox.com
_EOD

gltest ($data_ok, $testtime, 'prepend'); # mform pass

$data_ok = <<_EOD;
request=smtpd_access_policy
protocol_state=RCPT
protocol_name=SMTP
client_address=88.198.105.243
helo_name=
sender=xyz\@$testdomain
recipient=testspf\@maurer-it.com
_EOD

# we currently hav no backup mx, so we cant test this
#gltest ($data_ok, $testtime, 'dunno'); # mail from backup mx

$testdomain = "openspf.org"; # rejects everything

my $data_fail = <<_EOD;
request=smtpd_access_policy
protocol_state=RCPT
protocol_name=SMTP
client_address=$testipfail
helo_name=$testdomain
sender=xyz\@$testdomain
recipient=testspf\@maurer-it.com
_EOD

gltest ($data_fail, $testtime, 'reject');

system("kill `cat $pidfile`") if -f $pidfile;

print "ALL TESTS OK\n";

system("systemctl start pmgpolicy");

exit (0);

