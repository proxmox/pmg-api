package PMG::Quarantine;

use strict;
use warnings;
use Encode qw(encode);

use PVE::SafeSyslog;
use PVE::Tools;

use PMG::Utils;
use PMG::RuleDB;
use PMG::MailQueue;
use PMG::MIMEUtils;

sub add_to_blackwhite {
    my ($dbh, $username, $listname, $addrs, $delete) = @_;

    my $name = $listname eq 'BL' ? 'BL' : 'WL';
    my $oname = $listname eq 'BL' ? 'WL' : 'BL';
    my $qu = $dbh->quote (encode('UTF-8', $username));

    my $sth = $dbh->prepare(
	"SELECT * FROM UserPrefs WHERE pmail = $qu AND (Name = 'BL' OR Name = 'WL')");
    $sth->execute();

    my $list = { 'WL' => {}, 'BL' => {} };

    while (my $ref = $sth->fetchrow_hashref()) {
	my $data = PMG::Utils::try_decode_utf8($ref->{data});
	$data =~ s/[,;]/ /g;
	my @alist = split('\s+', $data);

	my $tmp = {};
	foreach my $a (@alist) {
	    if ($a =~ m/^[^\s\\\@]+(?:\@[^\s\/\\\@]+)?$/) {
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
		if ($v =~ m/[\s\\]/) {
		    die "email address '$v' contains invalid characters\n";
		}
		$list->{$name}->{$v} = 1;
		delete ($list->{$oname}->{$v});
	    }
	}

	my $wlist = $dbh->quote(encode('UTF-8', join (',', sort keys %{$list->{WL}})) || '');
	my $blist = $dbh->quote(encode('UTF-8', join (',', sort keys %{$list->{BL}})) || '');

	if (!$delete) {
	    my $maxlen = 200000;
	    die "whitelist size exceeds limit (> $maxlen bytes)\n"
		if length($wlist) > $maxlen;
	    die "blacklist size exceeds limit (> $maxlen bytes)\n"
		if length($blist) > $maxlen;
	}

	my $queries = "DELETE FROM UserPrefs WHERE pmail = $qu AND (Name = 'WL' OR Name = 'BL');";

	$queries .= "INSERT INTO UserPrefs (PMail, Name, Data, MTime) " .
	    "VALUES ($qu, 'WL', $wlist, EXTRACT (EPOCH FROM now())::INTEGER);";

	$queries .= "INSERT INTO UserPrefs (PMail, Name, Data, MTime) " .
	    "VALUES ($qu, 'BL', $blist, EXTRACT (EPOCH FROM now())::INTEGER);";

	$dbh->do($queries);
    }

    my $values =  [ sort keys %{$list->{$name}} ];

    return $values;
}

sub deliver_quarantined_mail {
    my ($dbh, $ref, $receiver) = @_;

    my $filename = $ref->{file};
    my $spooldir = $PMG::MailQueue::spooldir;
    my $path = "$spooldir/$filename";

    my $id = 'C' . $ref->{cid} . 'R' . $ref->{rid} . 'T' . $ref->{ticketid};;

    my $parser = PMG::MIMEUtils::new_mime_parser({
	nested => 1,
	decode_bodies => 0,
	extract_uuencode => 0,
	dumpdir => "/tmp/.quarantine-$id-$receiver-$$/",
    });

    my $entity = $parser->parse_open("$path");
    PMG::MIMEUtils::fixup_multipart($entity);

    # delete Delivered-To and Return-Path (avoid problem with postfix
    # forwarding loop detection (man local))
    $entity->head->delete('Delivered-To');
    $entity->head->delete('Return-Path');

    my $sender = 'postmaster'; # notify postmaster if something fails

    eval {
	my ($qid, $code, $mess) = PMG::Utils::reinject_local_mail(
	    $entity, $sender, [$receiver], undef, 'quarantine');

	if (!$qid) {
	    die "$mess\n";
	}

	my $sth = $dbh->prepare(
	    "UPDATE CMSReceivers SET Status='D', MTime = ? " .
	    "WHERE CMailStore_CID = ? AND CMailStore_RID = ? AND TicketID = ?");
	$sth->execute(time(), $ref->{cid}, $ref->{rid}, $ref->{ticketid});
	$sth->finish;
    };
    my $err = $@;
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
