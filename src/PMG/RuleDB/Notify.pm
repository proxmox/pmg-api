package PMG::RuleDB::Notify;

use strict;
use warnings;
use DBI;
use MIME::Body;
use MIME::Head;
use MIME::Entity;
use MIME::Words qw(encode_mimewords);
use Encode qw(decode encode);

use PVE::SafeSyslog;

use PMG::Utils;
use PMG::ModGroup;
use PMG::RuleDB::Object;
use PMG::MailQueue;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 4002;
}

sub oclass {
    return 'action';
}

sub otype_text {
    return 'Notification';
}

sub final {
    return 0;
}

sub priority {
    return 89;
}

sub new {
    my ($type, $to, $subject, $body, $attach, $ogroup) = @_;

    my $class = ref($type) || $type;

    my $self = $class->SUPER::new($class->otype(), $ogroup);

    $to //= '__ADMIN__';
    $attach //= 'N';
    $subject //= 'Notification: __SUBJECT__';

    if (!defined($body)) {
	$body = <<EOB;
Proxmox Notification:

Sender:   __SENDER__
Receiver: __RECEIVERS__
Targets:  __TARGETS__

Subject: __SUBJECT__

Matching Rule: __RULE__

__RULE_INFO__

__VIRUS_INFO__
__SPAM_INFO__
EOB
    }
    $self->{to} = $to;
    $self->{subject} = $subject;
    $self->{body} = $body;
    $self->{attach} = $attach;

    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;

    my $class = ref($type) || $type;

    defined($value) || die "undefined object attribute: ERROR";

    my ($raw_subject, $raw_body, $attach);

    my $sth = $ruledb->{dbh}->prepare(
	"SELECT * FROM Attribut WHERE Object_ID = ?");

    $sth->execute($id);

    while (my $ref = $sth->fetchrow_hashref()) {
	$raw_subject = $ref->{value} if $ref->{name} eq 'subject';
	$raw_body = $ref->{value} if $ref->{name} eq 'body';
	$attach = $ref->{value} if $ref->{name} eq 'attach';
    }

    $sth->finish();

    # Note: db stores binary (ascii) data, so we need to convert to UTF-8 manually
    my $obj = $class->new($value,
			  decode('UTF-8', $raw_subject),
			  decode('UTF-8', $raw_body),
			  $attach, $ogroup);
    $obj->{id} = $id;

    # Note: Digest::SHA does not work with wide UTF8 characters
    $obj->{digest} = Digest::SHA::sha1_hex(
	$id, $obj->{to}, $raw_subject, $raw_body, $obj->{attach}, $ogroup);

    return $obj;
}

sub save {
    my ($self, $ruledb, $no_trans) = @_;

    defined($self->{ogroup}) || die "undefined object attribute: ERROR";
    defined($self->{to}) || die "undefined object attribute: ERROR";
    defined($self->{subject}) || die "undefined object attribute: ERROR";
    defined($self->{body}) || die "undefined object attribute: ERROR";

    $self->{attach} //= 'N';

    # Note: db stores binary (ascii) data, so we need to convert from UTF-8 manually

    if (defined ($self->{id})) {
	# update

	eval {
	    $ruledb->{dbh}->begin_work if !$no_trans;

	    $ruledb->{dbh}->do(
		"UPDATE Object SET Value = ? WHERE ID = ?",
		undef, $self->{to}, $self->{id});

	    $ruledb->{dbh}->do(
		"UPDATE Attribut SET Value = ? " .
		"WHERE Name = ? and Object_ID = ?",
		undef, encode('UTF-8', $self->{subject}), 'subject',  $self->{id});

	    $ruledb->{dbh}->do(
		"UPDATE Attribut SET Value = ? " .
		"WHERE Name = ? and Object_ID = ?",
		undef, encode('UTF-8', $self->{body}), 'body',  $self->{id});

	    $ruledb->{dbh}->do(
		"UPDATE Attribut SET Value = ? " .
		"WHERE Name = ? and Object_ID = ?",
		undef, $self->{attach}, 'attach',  $self->{id});

	    $ruledb->{dbh}->commit if !$no_trans;
	};
	if (my $err = $@) {
	    die $err if !$no_trans;
	    $ruledb->{dbh}->rollback;
	    syslog('err', $err);
	    return undef;
	}

    } else {
	# insert

	$ruledb->{dbh}->begin_work if !$no_trans;

	eval {

	    my $sth = $ruledb->{dbh}->prepare(
		"INSERT INTO Object (Objectgroup_ID, ObjectType, Value) " .
		"VALUES (?, ?, ?);");

	    $sth->execute($self->ogroup, $self->otype, $self->{to});

	    $self->{id} = PMG::Utils::lastid($ruledb->{dbh}, 'object_id_seq');

	    $sth->finish();

	    $ruledb->{dbh}->do("INSERT INTO Attribut " .
			       "(Object_ID, Name, Value) " .
			       "VALUES (?, ?, ?)", undef,
			       $self->{id}, 'subject',  encode('UTF-8', $self->{subject}));
	    $ruledb->{dbh}->do("INSERT INTO Attribut " .
			       "(Object_ID, Name, Value) " .
			       "VALUES (?, ?, ?)", undef,
			       $self->{id}, 'body',  encode('UTF-8', $self->{body}));
	    $ruledb->{dbh}->do("INSERT INTO Attribut " .
			       "(Object_ID, Name, Value) " .
			       "VALUES (?, ?, ?)", undef,
			       $self->{id}, 'attach', $self->{attach});

	    $ruledb->{dbh}->commit if !$no_trans;
	};
	if (my $err = $@) {
	    die $err if !$no_trans;
	    $ruledb->{dbh}->rollback;
	    syslog('err', $err);
	    return undef;
	}
    }

    return $self->{id};
}

sub execute {
    my ($self, $queue, $ruledb, $mod_group, $targets,
	$msginfo, $vars, $marks) = @_;

    my $original;

    my $from = 'postmaster';

    my $rulename = encode('UTF-8', $vars->{RULE} // 'unknown');

    my $body = PMG::Utils::subst_values($self->{body}, $vars);
    my $subject = PMG::Utils::subst_values_for_header($self->{subject}, $vars);
    my $to = PMG::Utils::subst_values_for_header($self->{to}, $vars);

    if ($to =~ m/^\s*$/) {
	# this happens if a notification is triggered by bounce mails
	# which notifies the sender <> - we just log and then ignore it
	syslog('info', "%s: notify <> (rule: %s, ignored)", $queue->{logid}, $rulename);
	return;
    }

    $to =~ s/[;,]/ /g;
    $to =~ s/\s+/,/g;

    my $top = MIME::Entity->build(
	Encoding    => 'quoted-printable',
	Charset => 'UTF-8',
	From    => $from,
	To      => $to,
	Subject => encode_mimewords(encode('UTF-8', $subject), "Charset" => "UTF-8"),
	Data => encode('UTF-8', $body));

    if ($self->{attach} eq 'O') {
	# attach original mail
	my $spooldir = $PMG::MailQueue::spooldir;
	my $path = "$spooldir/active/$queue->{uid}";
	$original = $top->attach(
	    Path => $path,
	    Filename => "original_message.eml",
	    Type => "message/rfc822",);
    }

    if ($msginfo->{testmode}) {
	my $fh = $msginfo->{test_fh};
	print $fh "notify: $self->{to}\n";
	print $fh "notify content:\n";

	if ($self->{attach} eq 'O') {
	    # make result reproducible for regression testing
	    $top->head->replace('content-type',
				'multipart/mixed; boundary="---=_1234567"');
	}
	$top->print ($fh);
	print $fh "notify end\n";
    } else {
	my @targets = split(/\s*,\s*/, $to);
	my $qid = PMG::Utils::reinject_local_mail(
	    $top, $from, \@targets, undef, $msginfo->{fqdn});
	foreach (@targets) {
	    my $target = encode('UTF-8', $_);
	    if ($qid) {
		syslog(
		    'info',
		    "%s: notify <%s> (rule: %s, %s)",
		    $queue->{logid},
		    $target,
		    $rulename,
		    $qid,
		);
	    } else {
		syslog (
		    'err',
		    "%s: notify <%s> (rule: %s) failed",
		    $queue->{logid},
		    $target,
		    $rulename,
		);
	    }
	}
    }
}

sub short_desc {
    my $self = shift;

    return "notify $self->{to}";
}

sub properties {
    my ($class) = @_;

    return {
	to => {
	    description => "The Receiver E-Mail address",
	    type => 'string',
	    maxLength => 200,
	},
	subject => {
	    description => "The Notification subject",
	    type => 'string',
	    maxLength => 100,
	},
	attach => {
	    description => "Attach original E-Mail",
	    type => 'boolean',
	    optional => 1,
	    default => 0,
	},
	body => {
	    description => "The Notification Body",
	    type => 'string',
	    maxLength => 2048
	}
    };
}

sub get {
    my ($self) = @_;

    return {
	to => $self->{to},
	subject => $self->{subject},
	body => $self->{body},
	attach => ($self->{attach} eq 'O') ? 1 : 0,
    };
}

sub update {
    my ($self, $param) = @_;

    $self->{to} = $param->{to};
    $self->{subject} = $param->{subject};
    $self->{body} = $param->{body};
    $self->{attach} = $param->{attach} ? 'O' : 'N';
}

1;

__END__

=head1 PMG::RuleDB::Notify

Notifications.
