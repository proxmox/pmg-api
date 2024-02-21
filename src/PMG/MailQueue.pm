package PMG::MailQueue;

use strict;
use warnings;

use PVE::SafeSyslog;
use MIME::Parser;
use IO::File;
use Encode;
use File::Sync;
use File::Basename;
use File::Path;
use File::stat;
use Time::HiRes qw(gettimeofday);
use Mail::Header;

use PMG::LDAPSet;
use PMG::MIMEUtils;

our $spooldir = "/var/spool/pmg";

my $fileseq = rand 1000;

sub create_spooldirs {
    my ($lcid, $cleanup) = @_;

    # if requested, remove any stale date
    rmtree([
	"$spooldir/cluster",
	"$spooldir/active",
	"$spooldir/virus",
	"$spooldir/spam",
	"$spooldir/attachment",
    ]) if $cleanup;

    mkpath([
	"$spooldir/active",
	"$spooldir/spam",
	"$spooldir/virus",
	"$spooldir/attachment",
    ]);

    if ($lcid) {
	mkpath "$spooldir/cluster/$lcid/virus";
	mkpath "$spooldir/cluster/$lcid/spam";
	mkpath "$spooldir/cluster/$lcid/attachment";
    }
}

# called on service startup to remove any stale files
sub cleanup_active {

    while (my $file = <$spooldir/active/*>) {
	unlink $file;
    }

}

sub new_fileid {
    my ($dir, $subdir) = @_;

    # try to create a unique data file

    my ($sec, $usec) = gettimeofday ();
    my $fname = "$sec.$usec.$$." .  $fileseq++;
    my $path = "$dir/$subdir/$fname";
    my $fh;
    my $uid;
    my $subsubdir = '';

    if (!($fh = IO::File->new ($path, 'w+', 0600))) {
	die "unable to create file '$path': $! : ERROR";
    }

    if (my $st = stat ($fh)) {
	$uid = sprintf ("%X%X%05X", $st->ino, $sec, $usec);
	if ($subdir ne 'active') {
	    $subsubdir .= sprintf ("%02X/", $usec % 256);
	}
    } else {
	unlink $path;
	die "unable to stat file: $! : ERROR";
    }

    mkdir "$dir/$subdir/$subsubdir";

    my $subpath = "$subdir/$subsubdir$uid";

    if (!rename ($path, "$dir/$subpath")) {
	unlink $path;
	die "unable to rename file: ERROR";
    }

    return ($fh, $uid, $subpath);
}

sub new {
    my ($type, $from, $to) = @_;

    my $self = {};
    bless $self, $type;

    $self->{from} = $from;
    $self->{msgid} = "";

    $self->{sa_score} = undef;
    $self->{sa_max} = undef;
    $self->{sa_data} = undef;

    $self->{vinfo} = undef;
    $self->{bytes} = 0;
    $self->{rtime} = time;
    $self->{ptime_spam} = 0;
    $self->{ptime_virus} = 0;

    my ($fh, $uid, $path) = new_fileid ($spooldir, 'active');

    $self->{fh} = $fh;
    $self->{uid} = $uid;
    $self->{logid} = $uid;
    #$self->{logid} = sprintf ("%05X${uid}", $self->{rtime});
    $self->{dataname} = "$spooldir/$path";

    $self->{dumpdir} = "/tmp/.proxdump_${$}_$uid";

    $self->set_status ($to, 'undelivered');

    return $self;
}

sub set_status {
    my ($self, $targets, $state, $code, $message) = @_;

    foreach my $r (@$targets) {
	$self->{status}->{$r} = $state;
	$self->{status_code}->{$r} = $code;
	$self->{status_message}->{$r} = $message;
    }
}

sub quarantinedb_insert {
    my ($self, $ruledb, $lcid, $ldap, $qtype, $header, $sender, $file, $targets, $vars) = @_;

    eval {
	$sender = encode('UTF-8', $sender);
	my $dbh = $ruledb->{dbh};

	my $insert_cmds = "SELECT nextval ('cmailstore_id_seq'); INSERT INTO CMailStore " .
	    "(CID, RID, ID, Time, QType, Bytes, Spamlevel, Info, Header, Sender, File) VALUES (" .
	    "$lcid, currval ('cmailstore_id_seq'), currval ('cmailstore_id_seq'), ";

	my $spaminfo = $vars->{__spaminfo};
	my $sa_score = $spaminfo->{sa_score} || 0;

	$insert_cmds .= $self->{rtime} . ',';
	$insert_cmds .= $dbh->quote ($qtype) . ',';
	$insert_cmds .= $self->{bytes} . ',';
	$insert_cmds .= $sa_score . ',';

	if ($qtype eq 'V') {
	    $insert_cmds .= $dbh->quote ($self->{vinfo}) . ',';
	} else {

	    my $sscores = $spaminfo->{sa_data};
	    my $sainfo = 'NULL';
	    if (defined ($sscores) && @$sscores != -1) {
		$sainfo = '';
		foreach my $s (@$sscores) {
		    $sainfo .= ',' if $sainfo;
		    $sainfo .= sprintf ("%s:%s", $s->{rule}, $s->{score});
		}
		$sainfo = $dbh->quote ($sainfo);
	    }

	    $insert_cmds .= $sainfo . ',';
	}

	$insert_cmds .= $dbh->quote ($header) . ',';

	$insert_cmds .= $dbh->quote ($sender) . ',';
	$insert_cmds .= $dbh->quote ($file) . ');';

	my $now = time();

	my $tid = int(rand(0x0fffffff));

	foreach my $r (@$targets) {
	    my $pmail = get_primary_mail ($ldap, $r);
	    my $receiver;
	    if ($pmail eq lc ($r)) {
		$receiver = "NULL";
	    } else {
		$receiver = $dbh->quote (encode('UTF-8', $r));
	    }


	    $pmail = $dbh->quote (encode('UTF-8', $pmail));
	    $insert_cmds .= "INSERT INTO CMSReceivers " .
		"(CMailStore_CID, CMailStore_RID, PMail, Receiver, TicketID, Status, MTime) " .
		"VALUES ($lcid, currval ('cmailstore_id_seq'), $pmail, $receiver, $tid, 'N', $now); ";

	    # Note: Tuple (CID, RID, TicketID) must be unique
	    $tid = ($tid + 1) & 0x0fffffff;
	}

	$dbh->do ($insert_cmds);
    };

    my $err = $@;

    syslog ('err', "ERROR: $err") if $err;
}

sub get_primary_mail {
    my ($ldap, $mail) = @_;

    $mail = lc ($mail);

    return $mail if !$ldap;

    if (my $info = $ldap->account_info ($mail)) {
	return $info->{pmail};
    }

    return $mail;
}


sub extract_header_text {
    my ($entity) = @_;

    my $subject = $entity->head->get ('subject', 0);
    my $from = $entity->head->get ('from', 0);
    my $sender = $entity->head->get ('sender', 0);

    my $head = new Mail::Header;
    $head->add ('subject', $subject) if $subject;
    $head->add ('from', $from) if $from;
    $head->add ('sender', $sender) if $sender;

    my $header = $head->as_string();

    return $header;
}

sub fsync_file_and_dir {
    my $filename = shift;

    eval {
	my $fh = IO::File->new($filename) || die "unable to open file '$filename'";
	File::Sync::fsync ($fh) || die "fsync file '$filename' failed";
	close ($fh);

	my $dirname = dirname ($filename);
	my $dir = IO::File->new($dirname) || die "open dir '$dirname' failed";
	File::Sync::fsync ($dir) || die "fsync dir '$dirname' failed";
	close ($dir);
    };

    my $err = $@;

    if ($err) {
	syslog ('err', "ERROR: $err");
    }

}

my $subpath_map = {
    'V' => 'virus',
    'S' => 'spam',
    'A' => 'attachment',
};

sub quarantine_mail {
    my ($self, $ruledb, $qtype, $entity, $tg, $msginfo, $vars, $ldap) = @_;

    my $sender = $msginfo->{sender};

    my $header = extract_header_text ($entity);

    my $subpath = $subpath_map->{$qtype} // 'spam';

    my $lcid = $msginfo->{lcid};

    my ($fh, $uid, $path);

    eval {
	if ($lcid) {
	    my $subdir = "cluster/$lcid/$subpath";
	    ($fh, $uid, $path) = new_fileid ($spooldir, $subdir);
	} else {
	    ($fh, $uid, $path) = new_fileid ($spooldir, $subpath);
	}

	# there must be only one Return-Path
	$entity->head->delete ('Return-Path');

	# prepend Delivered-To and Return-Path (like QMAIL MAILDIR FORMAT)
	$entity->head->add ('Return-Path', encode('UTF-8', join (',', $sender)), 0);
	$entity->head->add ('Delivered-To', encode('UTF-8', join (',', @$tg)), 0);

	$entity->print ($fh);

	close ($fh);

	fsync_file_and_dir ("$spooldir/$path"); # make sure the file is on disk

	$self->quarantinedb_insert ($ruledb, $lcid, $ldap, $qtype, $header, $sender, $path, $tg, $vars);
    };

    my $err = $@;

    if ($err) {
	close ($fh) if $fh;
	unlink "$spooldir/$path" if $path;
	syslog ('err', "ERROR: $err");
	return undef;
    }

    return $uid;
}

#sub quarantine {
#    my ($self, $targets);
#
#    $self->set_status ($targets, 'quarantine');
#}

#sub spamreport {
#    my ($self, $targets);
#
#    $self->set_status ($targets, 'spam:report');
#}

#sub delay {
#    my ($self, $targets, $hm);
#
#    $self->set_status ($targets, "delay|$hm");
#}

sub msgid {
    my ($self, $msgid) = @_;

    if (defined ($msgid)) {
	$self->{msgid} = $msgid;
    }

    $self->{msgid};
}

sub close {
    my $self = shift;

    close ($self->{fh});

    rmtree $self->{dumpdir};

    unlink $self->{dataname};
}

sub _new_mime_parser {
    my ($self, $maxfiles) = shift;

    my $parser = PMG::MIMEUtils::new_mime_parser({
	nested => 1,
	ignore_errors => 1,
	extract_uuencode => 0,
	decode_bodies => 0,
	maxfiles => $maxfiles,
	dumpdir => $self->{dumpdir},
    });

    return $parser;
}

sub parse_mail {
    my ($self, $maxfiles) = shift;

    my $entity;
    my $ctime = time;

    my $parser = $self->_new_mime_parser ($maxfiles);

    $self->{fh}->seek (0, 0);

    eval {
	if (!($entity = $parser->read($self->{fh}))) {
	    die "$self->{logid}: unable to parse message: ERROR";
	}
    };

    die "$self->{logid}: unable to parse message - $@" if $@;

    PMG::MIMEUtils::fixup_multipart($entity);

    if ((my $idcount = $entity->head->count ('Message-Id')) > 0) {
	$self->msgid ($entity->head->get ('Message-Id', $idcount - 1));
    }

    # fixme: add parse_time to statistic database
    my $parse_time = time() - $ctime;

    # also save decoded data
    decode_entities ($parser, $self->{logid}, $entity);

    # we also remove all proxmox-marks from the mail and add an unique
    # id to each attachment.

    my $max_aid = PMG::Utils::remove_marks ($entity, 1);
    PMG::Utils::add_ct_marks ($entity);

    return ($entity, $max_aid);
}

sub decode_entities {
    my ($parser, $logid, $entity) = @_;

    PMG::MIMEUtils::traverse_mime_parts($entity, sub {
	my ($part) = @_;
	if ($part->bodyhandle && (my $path = $part->bodyhandle->path)) {

	    eval {
		my $head = $part->head;
		my $encoding = $head->mime_encoding;
		my $decoder = new MIME::Decoder $encoding;

		if (!$decoder || ($decoder eq 'none' || $decoder eq 'binary')) {

		    $part->{PMX_decoded_path} = $path; # no need to decode

		} else {

		    my $body = $parser->new_body_for ($head);
		    $body->binmode(1);
		    $body->is_encoded(0);

		    my $in = $part->bodyhandle->open ("r") ||
		    die "unable to read raw data '$path'";

		    my $decfh = $body->open ("w") ||
		    die "unable to open body: $!";

		    $decoder->decode ($in, $decfh);

		    $in->close;

		    $decfh->close ||
		    die "can't close bodyhandle: $!";

		    $part->{PMX_decoded_path} = $body->path;
		}
	    };

	    my $err = $@;

	    if ($err) {
		syslog ('err', "$logid: $err");
	    }

	}
    });
}

1;

__END__
