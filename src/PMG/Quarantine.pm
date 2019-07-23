package PMG::Quarantine;

use strict;
use warnings;
use Net::SMTP;

use PVE::SafeSyslog;
use PVE::Tools;

use PMG::Utils;
use PMG::RuleDB;
use PMG::MailQueue;

sub add_to_blackwhite {
    my ($dbh, $username, $listname, $addrs, $delete) = @_;

    my $name = $listname eq 'BL' ? 'BL' : 'WL';
    my $oname = $listname eq 'BL' ? 'WL' : 'BL';
    my $qu = $dbh->quote ($username);

    my $sth = $dbh->prepare(
	"SELECT * FROM UserPrefs WHERE pmail = $qu AND (Name = 'BL' OR Name = 'WL')");
    $sth->execute();

    my $list = { 'WL' => {}, 'BL' => {} };

    while (my $ref = $sth->fetchrow_hashref()) {
	my $data = $ref->{data};
	$data =~ s/[,;]/ /g;
	my @alist = split('\s+', $data);

	my $tmp = {};
	foreach my $a (@alist) {
	    if ($a =~ m/^[[:ascii:]]+$/) {
		$tmp->{$a} = 1;
	    }
	}

	$list->{$ref->{name}} = $tmp;
    }

    $sth->finish;

    if ($addrs) {

	foreach my $v (@$addrs) {
	    die "email address '$v' is too long (> 512 characters)\n"
		if length($v) > 512;

	    if ($delete) {
		delete($list->{$name}->{$v});
	    } else {
		if ($v =~ m/[[:^ascii:]]/) {
		    die "email address '$v' contains invalid characters\n";
		}
		$list->{$name}->{$v} = 1;
		delete ($list->{$oname}->{$v});
	    }
	}

	my $wlist = $dbh->quote(join (',', keys %{$list->{WL}}) || '');
	my $blist = $dbh->quote(join (',', keys %{$list->{BL}}) || '');

	if (!$delete) {
	    my $maxlen = 200000;
	    die "whitelist size exceeds limit (> $maxlen bytes)\n"
		if length($wlist) > $maxlen;
	    die "blacklist size exceeds limit (> $maxlen bytes)\n"
		if length($blist) > $maxlen;
	}

	my $queries = "DELETE FROM UserPrefs WHERE pmail = $qu AND (Name = 'WL' OR Name = 'BL');";
	if (scalar(keys %{$list->{WL}})) {
	    $queries .=
	    "INSERT INTO UserPrefs (PMail, Name, Data, MTime) " .
	    "VALUES ($qu, 'WL', $wlist, EXTRACT (EPOCH FROM now()));";
	}
	if (scalar(keys %{$list->{BL}})) {
	    $queries .=
	    "INSERT INTO UserPrefs (PMail, Name, Data, MTime) " .
	    "VALUES ($qu, 'BL', $blist, EXTRACT (EPOCH FROM now()));";
	}
	$dbh->do($queries);
    }

    my $values =  [ keys %{$list->{$name}} ];

    return $values;
}

sub deliver_quarantined_mail {
    my ($dbh, $ref, $receiver) = @_;

    my $filename = $ref->{file};
    my $spooldir = $PMG::MailQueue::spooldir;
    my $path = "$spooldir/$filename";

    my $id = 'C' . $ref->{cid} . 'R' . $ref->{rid} . 'T' . $ref->{ticketid};;

    my $sender = 'postmaster'; # notify postmaster if something fails

    my $smtp;

    eval {
	my $smtp = Net::SMTP->new ('127.0.0.1', Port => 10025, Hello => 'quarantine') ||
	    die "unable to connect to localhost at port 10025\n";

	my $resid;

	if (!$smtp->mail($sender)) {
	    die sprintf("smtp from error - got: %s %s\n", $smtp->code, $smtp->message);
	}

	if (!$smtp->to($receiver)) {
	    die sprintf("smtp to error - got: %s %s\n", $smtp->code, $smtp->message);
	}

	$smtp->data();

	my $header = 1;

	open(my $fh, '<', $path) || die "unable to open file '$path' - $!\n";

	while (defined(my $line = <$fh>)) {
	    chomp $line;
	    if ($header && ($line =~ m/^\s*$/)) {
		$header = 0;
	    }

	    # skip Delivered-To and Return-Path (avoid problem with postfix
	    # forwarding loop detection (man local))
	    next if ($header && (($line =~ m/^Delivered-To:/i) || ($line =~ m/^Return-Path:/i)));

	    # rfc821 requires this
	    $line =~ s/^\./\.\./mg;
	    $smtp->datasend("$line\n");
	}
	close($fh);

	if ($smtp->dataend()) {
	    my (@msgs) = $smtp->message;
	    my ($last_msg) = $msgs[$#msgs];
	    ($resid) = $last_msg =~ m/Ok: queued as ([0-9A-Z]+)/;
	    if (!$resid) {
		die sprintf("smtp error - got: %s %s\n", $smtp->code, $smtp->message);
	    }
	} else {
	    die sprintf("sending data failed - got: %s %s\n", $smtp->code, $smtp->message);
	}

	my $sth = $dbh->prepare(
	    "UPDATE CMSReceivers SET Status='D', MTime = ? " .
	    "WHERE CMailStore_CID = ? AND CMailStore_RID = ? AND TicketID = ?");
	$sth->execute(time(), $ref->{cid}, $ref->{rid}, $ref->{ticketid});
	$sth->finish;
    };
    my $err = $@;

    $smtp->quit if $smtp;

    if ($err) {
	my $msg = "deliver quarantined mail '$id' ($path) failed: $err";
	syslog('err', $msg);
	die "$msg\n";
    }

    syslog('info', "delivered quarantined mail '$id' ($path)");

    return 1;
}

sub delete_quarantined_mail {
    my ($dbh, $ref) = @_;

    my $filename = $ref->{file};
    my $spooldir = $PMG::MailQueue::spooldir;
    my $path = "$spooldir/$filename";

    my $id = 'C' . $ref->{cid} . 'R' . $ref->{rid} . 'T' . $ref->{ticketid};;

    eval {
	my $sth = $dbh->prepare(
	    "UPDATE CMSReceivers SET Status='D', MTime = ? WHERE " .
	    "CMailStore_CID = ? AND CMailStore_RID = ? AND TicketID = ?");
	$sth->execute (time(), $ref->{cid}, $ref->{rid}, $ref->{ticketid});
	$sth->finish;
    };
    if (my $err = $@) {
	my $msg = "delete quarantined mail '$id' ($path) failed: $err";
	syslog ('err', $msg);
	die "$msg\n";
    }

    syslog ('info', "marked quarantined mail '$id' as deleted ($path)");

    return 1;
}


1;
