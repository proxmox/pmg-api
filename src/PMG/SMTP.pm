package PMG::SMTP;

use strict;
use warnings;
use IO::Socket;
use Encode;
use MIME::Entity;

use PVE::SafeSyslog;

use PMG::MailQueue;
use PMG::Utils;

sub new {
    my($this, $sock) = @_;

    my $class = ref($this) || $this;

    die("undefined socket: ERROR") if !defined($sock);

    my $self = {};
    $self->{sock} = $sock;
    $self->{lmtp} = undef;
    bless($self, $class);

    $self->reset();

    $self->reply ("220 Proxmox SMTP Ready.");
    return $self;
}

sub reset {
    my $self = shift;

    $self->{from} = undef;
    $self->{to} = [];
    $self->{queue} = undef;
    delete $self->{smtputf8};
    delete $self->{xforward};
    delete $self->{status};
    delete $self->{param};
}

sub abort {
    shift->{sock}->close();
}

sub reply {
    print {shift->{sock}} @_, "\r\n";;

}

sub loop {
    my ($self, $func, $data, $maxcount) = @_;

    my($cmd, $args);

    my $sock = $self->{sock};

    my $count = 0;

    while(<$sock>) {
	chomp;
	s/^\s+//;
	s/\s+$//;

	if (!length ($_)) {
	    $self->reply ("500 5.5.1 Error: bad syntax");
	    next;
	}
	($cmd, $args) = split(/\s+/, $_, 2);
	$cmd = lc ($cmd);

	if ($cmd eq 'helo' || $cmd eq 'ehlo' || $cmd eq 'lhlo') {
	    $self->reset();

	    $self->reply ("250-PIPELINING");
	    $self->reply ("250-ENHANCEDSTATUSCODES");
	    $self->reply ("250-8BITMIME");
	    $self->reply ("250-SMTPUTF8");
	    $self->reply ("250-DSN");
	    $self->reply ("250-XFORWARD NAME ADDR PROTO HELO");
	    $self->reply ("250 OK.");
	    $self->{lmtp} = 1 if ($cmd eq 'lhlo');
	    next;
	} elsif ($cmd eq 'xforward') {
	    my @tmp = split (/\s+/, $args);
	    foreach my $attr (@tmp) {
		my ($n, $v) = ($attr =~ /^(.*?)=(.*)$/);
		$self->{xforward}->{lc($n)} = $v;
	    }
	    $self->reply ("250 2.5.0 OK");
	    next;
	} elsif ($cmd eq 'noop') {
	    $self->reply ("250 2.5.0 OK");
	    next;
	} elsif ($cmd eq 'quit') {
	    $self->reply ("221 2.2.0 OK");
	    last;
	} elsif ($cmd eq 'rset') {
	    $self->reset();
	    $self->reply ("250 2.5.0 OK");
	    next;
	} elsif ($cmd eq 'mail') {
	    if ($args =~ m/^from:\s*<([^\s\>]*?)>( .*)?$/i) {
		delete $self->{to};
		my ($from, $opts) = ($1, $2 // '');

		for my $opt (split(' ', $opts)) {
		    if ($opt =~ /(ret|envid)=([^ =]+)/i ) {
			$self->{param}->{mail}->{$1} = $2;
		    } elsif ($opt =~ m/smtputf8/i) {
			$self->{smtputf8} = 1;
			$self->{param}->{mail}->{smtputf8} = 1;
			$from = decode('UTF-8', $from);
		    } else {
			#ignore everything else
		    }
		}
		$self->{from} = $from;
		$self->reply ('250 2.5.0 OK');
		next;
	    } else {
		$self->reply ("501 5.5.2 Syntax: MAIL FROM: <address>");
		next;
	    }
	} elsif ($cmd eq 'rcpt') {
	    if ($args =~ m/^to:\s*<([^\s\>]+?)>( .*)?$/i) {
		my $to = $self->{smtputf8} ? decode('UTF-8', $1) : $1;
		my $opts = $2 // '';
		push @{$self->{to}} , $to;
		for my $opt (split(' ', $opts)) {
		    if ($opt =~ /(notify|orcpt)=([^ =]+)/i ) {
			$self->{param}->{rcpt}->{$to}->{$1} = $2;
		    } else {
			#ignore everything else
		    }
		}
		$self->reply ('250 2.5.0 OK');
		next;
	    } else {
		$self->reply ("501 5.5.2 Syntax: RCPT TO: <address>");
		next;
	    }
	} elsif ($cmd eq 'data') {
	    if ($self->save_data ()) {
		eval { &$func ($data, $self); };
		if (my $err = $@) {
		    $data->{errors} = 1;
		    syslog ('err', $err);
		}

		my $cfg = $data->{pmg_cfg};

		if ($self->{lmtp}) {
		    foreach $a (@{$self->{to}}) {
			if ($self->{queue}->{status}->{$a} eq 'delivered') {
			    $self->reply ("250 2.5.0 OK ($self->{queue}->{logid})");
			} elsif ($self->{queue}->{status}->{$a} eq 'blocked') {
			    if ($cfg->get('mail', 'ndr_on_block')) {
				$self->reply ("554 5.7.1 Rejected for policy reasons ($self->{queue}->{logid})");
			    } else {
				$self->reply ("250 2.7.0 BLOCKED ($self->{queue}->{logid})");
			    }
			} elsif ($self->{queue}->{status}->{$a} eq 'error') {
			    my $code = $self->{queue}->{status_code}->{$a};
			    my $resp = substr($code, 0, 1);
			    my $mess = $self->{queue}->{status_message}->{$a};
			    $self->reply ("$code $resp.0.0 $mess");
			} else {
			    $self->reply ("451 4.4.0 detected undelivered mail to <$a>");
			}
		    }
		} else {
		    my $queueid = $self->{queue}->{logid};
		    my $qstat = $self->{queue}->{status};
		    my @rec = keys %$qstat;
		    my @success_rec = grep { $qstat->{$_} eq 'delivered' } @rec;
		    my @reject_rec = grep { $qstat->{$_} eq 'blocked' } @rec;

		    if (scalar(@reject_rec) == scalar(@rec)) {
			$self->reply ("554 5.7.1 Rejected for policy reasons ($queueid)");
		        syslog('info', "reject mail $queueid");
		    } elsif ((scalar(@reject_rec) + scalar(@success_rec)) == scalar(@rec)) {
			$self->reply ("250 2.5.0 OK ($queueid)");
			if ($cfg->get('mail', 'ndr_on_block')) {
			    my $dnsinfo = $cfg->get_host_dns_info();
			    generate_ndr($self->{from}, [ @reject_rec ], $dnsinfo->{fqdn}, $queueid) if scalar(@reject_rec);
			}
		    } else {
			$self->reply ("451 4.4.0 detected undelivered mail ($queueid)");
		    }
		}
	    }

	    $self->reset();

	    $count++;
	    last if $count >= $maxcount;
	    last if $data->{errors}; # abort if we find errors
	    next;
	}

	$self->reply ("500 5.5.1 Error: unknown command");
    }

    $self->{sock}->close;
    return $count;
}

sub save_data {
    my $self = shift;
    my $done = undef;

    if(!defined($self->{from})) {
	$self->reply ("503 5.5.1 Tell me who you are.");
	return 0;
    }

    if(!defined($self->{to})) {
	$self->reply ("503 5.5.1 Tell me who to send it.");
	return 0;
    }

    $self->reply ("354 End data with <CR><LF>.<CR><LF>");

    my $sock = $self->{sock};

    my $queue;

    eval {
	$queue = PMG::MailQueue->new ($self->{from}, $self->{to});

	while(<$sock>) {

	    if(/^\.\015\012$/) {
		$done = 1;
		last;
	    }

	    # RFC 2821 compliance.
	    s/^\.\./\./;

	    s/\015\012/\n/;

	    print {$queue->{fh}} $_;
	    $queue->{bytes} += length ($_);
	}

	$queue->{fh}->flush ();

	$self->{queue} = $queue;
    };
    if (my $err = $@) {
	syslog ('err', $err);
	$self->reply ("451 4.5.0 Local delivery failed: $err");
	return 0;
    }
    if(!defined($done)) {
	$self->reply ("451 4.5.0 Local delivery failed: unfinished data");
	return 0;
    }

    return 1;
}

sub generate_ndr {
    my ($sender, $receivers, $hostname, $queueid) = @_;

    my $ndr_text = <<EOF
This is the mail system at host $hostname.

I'm sorry to have to inform you that your message could not
be delivered to one or more recipients.

For further assistance, please send mail to postmaster.

If you do so, please include this problem report.
                   The mail system

554 5.7.1 Recipient address(es) rejected for policy reasons
EOF
;
    my $ndr = MIME::Entity->build(
	Type => 'multipart/report; report-type=delivery-status;',
	To => $sender,
	From => 'postmaster',
	Subject => 'Undelivered Mail');

    $ndr->attach(
	Data => $ndr_text,
	Type => 'text/plain; charset=utf-8',
	Encoding => '8bit');

    my $delivery_status = <<EOF
Reporting-MTA: dns; $hostname
X-Proxmox-Queue-ID: $queueid
X-Proxmox-Sender: rfc822; $sender
EOF
;
    foreach my $rec (@$receivers) {
	$delivery_status .= <<EOF
Final-Recipient: rfc822; $rec
Original-Recipient: rfc822;$rec
Action: failed
Status: 5.7.1
Diagnostic-Code: smtp; 554 5.7.1 Recipient address rejected for policy reasons

EOF
;
    }
    $ndr->attach(
	Data => $delivery_status,
	Type => 'message/delivery-status',
	Encoding => '7bit',
	Description => 'Delivery report');

    my $qid = PMG::Utils::reinject_local_mail($ndr, '', [$sender], undef, $hostname);
    if ($qid) {
	syslog('info', "sent NDR for rejecting recipients - $qid");
    } else {
	syslog('err', "sending NDR for rejecting recipients failed");
    }
}

1;
