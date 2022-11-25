package PMG::Postfix;

use strict;
use warnings;
use Data::Dumper;
use File::Find;
use JSON;
use MIME::WordDecoder qw(mime_to_perl_string);

use PVE::Tools;

use PMG::Utils;

my $spooldir = "/var/spool/postfix";

my $postfix_rec_get = sub {
    my ($fh) = @_;

    my $r = getc($fh);
    return if !defined($r);

    my $l = 0;
    my $shift = 0;

    while (defined(my $lb = getc($fh))) {
	my $o = ord($lb);
	$l |= ($o & 0x7f) << $shift ;
	last if (($o & 0x80) == 0);
	$shift += 7;
	return if ($shift > 7);	# XXX: max rec len of 4096
    }

    my $d = "";
    return unless ($l == 0 || read($fh, $d, $l) == $l);
    return ($r, $l, $d);
};

my $postfix_qenv = sub {
    my ($filename) = @_;

    my $fh = new IO::File($filename, "r");
    return undef if !defined($fh);

    my $dlen;
    my $res = { receivers => [] };
    while (my ($r, $l, $d) = $postfix_rec_get->($fh)) {
	#print "test:$r:$l:$d\n";
	if ($r eq "C") { $dlen = $1 if $d =~ /^\s*(\d+)\s+\d+\s+\d+/; }
	elsif ($r eq 'T') { $res->{time} = $1 if $d =~ /^\s*(\d+)\s\d+/; }
	elsif ($r eq 'S') { $res->{sender} = $d; }
	elsif ($r eq 'R') { push @{$res->{receivers}}, $d; }
	elsif ($r eq 'N') {
	    if ($d =~ m/^Subject:\s+(.*)$/i) {
		$res->{subject} = $1;
	    } elsif (!$res->{messageid} && $d =~ m/^Message-Id:\s+<(.*)>$/i) {
		$res->{messageid} = $1;
	    }
	}
	#elsif ($r eq "M") { last unless defined $dlen; seek($fh, $dlen, 1); }
	elsif ($r eq "E") { last; }
    }

    return $res;
};

# Fixme: it is a bad idea to scan everything - list can be too large
sub show_deferred_queue {
    my $res;

    my $queue = 'deferred';

    my $callback = sub {
	my $path = $File::Find::name;
	my $filename = $_;

	my ($dev, $ino, $mode) = lstat($path);

	return if !defined($mode);
	return if !(-f _ && (($mode & 07777) == 0700));

	if (my $rec = $postfix_qenv->($path)) {
	    $rec->{queue} = $queue;
	    $rec->{qid} = $filename;
	    push @$res, $rec;
	}
    };

    find($callback, "$spooldir/deferred");

    return $res;
}

sub qshape {
    my ($queues) = @_;

    open(my $fh, '-|', '/usr/sbin/qshape', $queues) || die "ERROR: unable to run qshape: $!\n";

    my $line = <$fh>;
    if (!$line || !($line =~ m/^\s+T\s+5\s+10\s+20\s+40\s+80\s+160\s+320\s+640\s+1280\s+1280\+$/)) {
	die "ERROR: unable to parse qshape output: - $line";
    }

    my $count = 0;
    my $res = [];
    while (($count++ < 10000) && (defined($line = <$fh>))) {
	if ($line =~ m/^\s+(\S+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+)$/) {
	    my @d = split(/\s+/, $1);
	    push @$res, {
		domain => $d[0],
		total => $d[1],
		'5m' => $d[2],
		'10m' => $d[3],
		'20m' => $d[4],
		'40m' => $d[5],
		'80m' => $d[6],
		'160m' => $d[7],
		'320m' => $d[8],
		'640m' => $d[9],
		'1280m' => $d[10],
		'1280m+' => $d[11],
	    };
	}
    }

    return $res;
}

sub mailq {
    my ($queue, $filter, $start, $limit) = @_;

    open(my $fh, '-|', '/usr/sbin/postqueue', '-j') || die "ERROR: unable to run postqueue - $!\n";

    my $count = 0;

    $start = 0 if !$start;
    $limit = 50 if !$limit;

    my $res = [];
    my $line;
    while (defined($line = <$fh>)) {
	my $rec = decode_json($line);
	my $recipients = $rec->{recipients};
	next if $rec->{queue_name} ne $queue;

	foreach my $entry (@$recipients) {
	    if (!$filter || $entry->{address} =~ m/$filter/i ||
		$rec->{sender} =~ m/$filter/i) {
		next if $count++ < $start;
		next if $limit-- <= 0;

		my $data = {};
		foreach my $k (qw(queue_name queue_id arrival_time message_size sender)) {
		    $data->{$k} = $rec->{$k};
		}
		$data->{receiver} = $entry->{address};
		$data->{reason} = $entry->{delay_reason};
		push @$res, $data;
	    }
	}
    }

    return ($count, $res);
}

sub postcat {
    my ($queue_id, $header, $body, $decode) = @_;

    die "no option specified (select header or body or both)"
	if !($header || $body);

    my @opts = ();

    push @opts, '-h' if $header;
    push @opts, '-b' if $body;

    push @opts, '-q', $queue_id;

    open(my $fh, '-|', '/usr/sbin/postcat', @opts) || die "ERROR: unable to run postcat - $!\n";

    my $res = '';
    while (defined(my $line = <$fh>)) {
	if ($decode) {
	    $res .= PMG::Utils::decode_rfc1522($line);
	} else {
	    $res .= PMG::Utils::try_decode_utf8($line);
	}
    }

    return $res;
}

# flush all queues
sub flush_queues {
    PVE::Tools::run_command(['/usr/sbin/postqueue', '-f']);
}

# flush a single mail
sub flush_queued_mail {
    my ($queue_id) = @_;

    PVE::Tools::run_command(['/usr/sbin/postqueue', '-i', $queue_id]);
}

sub delete_queued_mail {
    my ($queue, $queue_id) = @_;

    PVE::Tools::run_command(['/usr/sbin/postsuper', '-d', $queue_id, $queue]);
}

sub delete_queue {
    my ($queue) = @_;

    my $cmd = ['/usr/sbin/postsuper', '-d', 'ALL'];
    push @$cmd, $queue if defined($queue);

    PVE::Tools::run_command($cmd);
}

sub discard_verify_cache {
    unlink "/var/lib/postfix/verify_cache.db";

    PMG::Utils::service_cmd('postfix', 'reload');
}

1;
