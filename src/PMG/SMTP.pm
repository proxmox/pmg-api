package PMG::SMTP;

use strict;
use warnings;
use IO::Socket;
use Encode;

use PVE::SafeSyslog;

use PMG::MailQueue;

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
	    if ($args =~ m/^from:\s*<([^\s\>]*)>([^>]*)$/i) {
		delete $self->{to};
		my ($from, $opts) = ($1, $2);
		if ($opts =~ m/\sSMTPUTF8/) {
		    $self->{smtputf8} = 1;
		    $from = decode('UTF-8', $from);
		}
		$self->{from} = $from;
		$self->reply ('250 2.5.0 OK');
		next;
	    } else {
		$self->reply ("501 5.5.2 Syntax: MAIL FROM: <address>");
		next;
	    }
	} elsif ($cmd eq 'rcpt') {
	    if ($args =~ m/^to:\s*<([^\s\>]+)>[^>]*$/i) {
		my $to = $self->{smtputf8} ? decode('UTF-8', $1) : $1;
		push @{$self->{to}} , $to;
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

		if ($self->{lmtp}) {
		    foreach $a (@{$self->{to}}) {
			if ($self->{queue}->{status}->{$a} eq 'delivered') {
			    $self->reply ("250 2.5.0 OK ($self->{queue}->{logid})");
			} elsif ($self->{queue}->{status}->{$a} eq 'blocked') {
			    $self->reply ("250 2.7.0 BLOCKED ($self->{queue}->{logid})");
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
		    my $all_done = 1;

		    foreach $a (@{$self->{to}}) {
			if (!($self->{queue}->{status}->{$a} eq 'delivered' ||
			      $self->{queue}->{status}->{$a} eq 'blocked')) {
			    $all_done = 0;
			}
		    }
		    if ($all_done) {
			$self->reply ("250 2.5.0 OK ($self->{queue}->{logid})");
		    } else {
			$self->reply ("451 4.4.0 detected undelivered mail");
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

1;
