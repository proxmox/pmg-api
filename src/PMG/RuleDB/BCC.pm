package PMG::RuleDB::BCC;

use strict;
use warnings;
use DBI;
use Encode qw(encode);

use PVE::SafeSyslog;

use PMG::Utils;
use PMG::ModGroup;
use PMG::DKIMSign;
use PMG::RuleDB::Object;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 4005;
}

sub oclass {
    return 'action';
}

sub otype_text {
    return 'BCC';
}

sub oisedit {
    return 1;
}

sub final {
    return 0;
}

sub priority {
    return 80;
}

sub new {
    my ($type, $target, $original, $ogroup) = @_;

    my $class = ref($type) || $type;

    my $self = $class->SUPER::new($class->otype(), $ogroup);

    $self->{target} = $target || 'receiver@domain.tld';

    defined ($original) || ($original = 1);

    $self->{original} = $original;

    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;

    my $class = ref($type) || $type;

    defined($value) || return undef;

    $value =~ m/^([01]):(.*)/ || return undef;

    my ($target, $original) = ($2, $1);

    my $obj = $class->new($target, $original, $ogroup);
    $obj->{id} = $id;

    $obj->{digest} = Digest::SHA::sha1_hex($id, $target, $original, $ogroup);

    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || die "undefined object attribute: ERROR";
    defined($self->{target}) || die "undefined object attribute: ERROR";
    defined($self->{original}) || die "undefined object attribute: ERROR";

    if ($self->{original}) {
	$self->{original} = 1;
    } else {
	$self->{original} = 0;
    }

    my $value = "$self->{original}:$self->{target}";

    if (defined($self->{id})) {
	# update

	$ruledb->{dbh}->do(
	    "UPDATE Object SET Value = ? WHERE ID = ?",
	    undef, $value, $self->{id});

    } else {
	# insert

	my $sth = $ruledb->{dbh}->prepare(
	    "INSERT INTO Object (Objectgroup_ID, ObjectType, Value) " .
	    "VALUES (?, ?, ?);");

	$sth->execute($self->{ogroup}, $self->otype, $value);

	$self->{id} = PMG::Utils::lastid($ruledb->{dbh}, 'object_id_seq');
    }

    return $self->{id};
}

sub execute {
    my ($self, $queue, $ruledb, $mod_group, $targets,
	$msginfo, $vars, $marks) = @_;

    my $subgroups = $mod_group->subgroups($targets, 1);

    my $rulename = encode('UTF-8', $vars->{RULE} // 'unknown');

    my $bcc_to = PMG::Utils::subst_values_for_header($self->{target}, $vars);

    if ($bcc_to =~ m/^\s*$/) {
	# this happens if a notification is triggered by bounce mails
	# which notifies the sender <> - we just log and then ignore it
	syslog('info', "%s: bcc to <> (rule: %s, ignored)", $queue->{logid}, $rulename);
	return;
    }

    my @bcc_targets = split (/\s*,\s*/, $bcc_to);

    if ($self->{original}) {
	$subgroups = [[\@bcc_targets, $mod_group->{entity}]];
    }

    foreach my $ta (@$subgroups) {
	my ($tg, $entity) = (@$ta[0], @$ta[1]);

	$entity = $entity->dup();
	PMG::Utils::remove_marks($entity);

	my $dkim = $msginfo->{dkim} // {};
	if ($dkim->{sign}) {
	    eval {
		$entity = PMG::DKIMSign::sign_entity($entity, $dkim, $msginfo->{sender});
	    };
	    if ($@) {
		syslog('warning',
		    "%s: Could not create DKIM-Signature - disabling Signing: $@",
		    $queue->{logid}
		);
	    }
	}

	if ($msginfo->{testmode}) {
	    my $fh = $msginfo->{test_fh};
	    print $fh "bcc from: $msginfo->{sender}\n";
	    printf $fh "bcc   to: %s\n", join (',', @$tg);
	    print $fh "bcc content:\n";
	    $entity->print ($fh);
	    print $fh "bcc end\n";
	} else {
	    my $param = {};
	    for my $bcc (@bcc_targets) {
		$param->{rcpt}->{$bcc}->{notify} = "never";
	    }
	    my $qid = PMG::Utils::reinject_mail(
		$entity, $msginfo->{sender}, \@bcc_targets,
		$msginfo->{xforward}, $msginfo->{fqdn}, $param);
	    foreach (@bcc_targets) {
		my $target = encode('UTF-8', $_);
		if ($qid) {
		    syslog(
			'info',
			"%s: bcc to <%s> (rule: %s, %s)",
			$queue->{logid},
			$target,
			$rulename,
			$qid,
		    );
		} else {
		    syslog(
			'err',
			"%s: bcc to <%s> (rule: %s) failed",
			$queue->{logid},
			$target,
			$rulename,
		    );
		}
	    }
	}
    }

    # warn if no subgroups
}

sub short_desc {
    my $self = shift;

    my $descr = "send bcc to: $self->{target}";

    $descr .= " (original)" if $self->{original};

    return $descr;
}

sub properties {
    my ($class) = @_;

    return {
	target => {
	    description => "Send a Blind Carbon Copy to this email address.",
	    type => 'string', format => 'email',
	},
	original =>{
	    description => "Send the original, unmodified mail.",
	    type => 'boolean',
	    optional => 1,
	    default => 1,
	},
    };
}

sub get {
    my ($self) = @_;

    return { 
	target => $self->{target}, 
	original => $self->{original},
    };
}

sub update {
    my ($self, $param) = @_;

    $self->{target} = $param->{target};
    $self->{original} = $param->{original} ? 1 : 0;
}

1;

__END__

=head1 PMG::RuleDB::BCC

Send BCC.
