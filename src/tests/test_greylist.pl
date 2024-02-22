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

my $testdb = 'Proxmox_testdb';
my $testport = 10122;
my $testpidfn = "greylist-test-$$.pid";

system ("perl -I.. ../bin/pmgpolicy -d $testdb -t --port $testport --pidfile '$testpidfn'");

sub exit_test_pmgpolicy {
    my $pid = PVE::Tools::file_read_firstline($testpidfn);
    die "could not read pidfile: $!\n" if !$pid;

    die "could not find pid in pidfile\n" if $pid !~ m/^(\d+)$/;
    $pid = $1;

    kill ('TERM', $pid);
    unlink($testpidfn);
}

sub reset_gldb {
    my $dbh = PMG::DBTools::open_ruledb($testdb);
    $dbh->do ("DELETE FROM CGreylist");
    $dbh->disconnect();
}

reset_gldb();


my $sock;
for (my $tries = 0 ; $tries < 3 ; $tries++) {
    $sock = IO::Socket::INET->new(
	PeerAddr => '127.0.0.1',
	PeerPort => $testport);
    last if $sock;
    sleep 1;
}
die "unable to open socket -  $!" if !$sock;

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
    if ($res !~ m/^action=$eres(\s.*)?/) {
	my $timediff = $ttime - $starttime;
	exit_test_pmgpolicy();
	die "unexpected result at time $timediff: $res != $eres\n$data"
    }
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

# greylist ipv6
my $data6 = <<_EOD;
request=smtpd_access_policy
protocol_state=RCPT
protocol_name=SMTP
client_address=2001:db8::1
client_name=test.domain.tld
helo_name=test.domain.tld
sender=test1\@test.domain.tld
recipient=test1\@proxmox.com
_EOD

# time 0
reset_gldb ();
gltest ($data6, $testtime, 'defer');
gltest ($data6, $testtime+$greylist_delay-3, 'defer');
gltest ($data6, $testtime+$greylist_delay-1, 'defer');
gltest ($data6, $testtime+$greylist_lifetime-1, 'dunno');
gltest ($data6, $testtime+$greylist_lifetime-1+$greylist_awlifetime-1, 'dunno');
gltest ($data6, $testtime+$greylist_lifetime-1+$greylist_awlifetime-1+$greylist_awlifetime, 'defer');

# time 0
reset_gldb ();
gltest ($data6, $testtime, 'defer');
gltest ($data6, $testtime+$greylist_delay-3, 'defer');
gltest ($data6, $testtime+$greylist_delay-1, 'defer');
gltest ($data6, $testtime+$greylist_lifetime+1, 'defer');
gltest ($data6, $testtime+$greylist_lifetime+1+$greylist_delay-1, 'defer');
gltest ($data6, $testtime+$greylist_lifetime+1+$greylist_delay+1, 'dunno');
gltest ($data6, $testtime+$greylist_lifetime+1+$greylist_delay+1+$greylist_awlifetime-1, 'dunno');
gltest ($data6, $testtime+$greylist_lifetime+1+$greylist_delay+1+$greylist_awlifetime-1+$greylist_awlifetime, 'defer');


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

# we currently have no backup mx, so we can't test this
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

exit_test_pmgpolicy();

print "ALL TESTS OK\n";

$sock->close();

exit (0);
