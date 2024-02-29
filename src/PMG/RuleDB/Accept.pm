package PMG::RuleDB::Accept;

use strict;
use warnings;
use DBI;
use Encode;

use PVE::SafeSyslog;
use Digest::SHA;

use PMG::Utils;
use PMG::ModGroup;
use PMG::DKIMSign;
use PMG::RuleDB::Object;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 4000;
}

sub oclass {
    return 'action';
}

sub otype_text {
    return 'Accept';
}

sub oisedit {
    return 0;   
}

sub final {
    return 1;
}

sub priority {
    return 99;
}

sub new {
    my ($type, $ogroup) = @_;
    
    my $class = ref($type) || $type;
 
    my $self = $class->SUPER::new($class->otype(), $ogroup);
   
    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;
    
    my $class = ref($type) || $type;

    my $obj = $class->new($ogroup);
    $obj->{id} = $id;
    
    $obj->{digest} = Digest::SHA::sha1_hex($id, $ogroup);

    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || return undef;

    if (defined($self->{id})) {
	# update
	
	# nothing to update

    } else {
	# insert

	my $sth = $ruledb->{dbh}->prepare(
	    "INSERT INTO Object (Objectgroup_ID, ObjectType) VALUES (?, ?);");

	$sth->execute($self->ogroup, $self->otype);
    
	$self->{id} = PMG::Utils::lastid($ruledb->{dbh}, 'object_id_seq');
    }
	
    return $self->{id};
}

sub execute {
    my ($self, $queue, $ruledb, $mod_group, $targets, 
	$msginfo, $vars, $marks) = @_;

    my $dkim = $msginfo->{dkim} // {};
    my $subgroups = $mod_group->subgroups($targets, !$dkim->{sign});

    my $rulename = encode('UTF-8', $vars->{RULE} // 'unknown');

    foreach my $ta (@$subgroups) {
	my ($tg, $entity) = (@$ta[0], @$ta[1]);

	PMG::Utils::remove_marks($entity);

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
	    print $fh "accept from: $msginfo->{sender}\n";
	    printf $fh "accept   to: %s\n", join (',', @$tg);
	    print $fh "accept content:\n";

	    $entity->print($fh);
	    print $fh "accept end\n";
	    $queue->set_status($tg, 'delivered');
	} else {
	    my ($qid, $code, $mess) = PMG::Utils::reinject_mail(
		$entity, $msginfo->{sender}, $tg,
		$msginfo->{xforward}, $msginfo->{fqdn}, $msginfo->{param});
	    if ($qid) {
		foreach (@$tg) {
		    syslog('info', "%s: accept mail to <%s> (%s) (rule: %s)", $queue->{logid}, encode('UTF-8', $_), $qid, $rulename);
		}
		$queue->set_status ($tg, 'delivered', $qid);
	    } else {
		foreach (@$tg) {
		    syslog('err', "%s: reinject mail to <%s> (rule: %s) failed", $queue->{logid}, encode('UTF-8', $_), $rulename);
		}
		if ($code) {
		    my $resp = substr($code, 0, 1);
		    if ($resp eq '4' || $resp eq '5') {
			$queue->set_status($tg, 'error', $code, $mess);
		    }
		}
	    }
	}
    }

    # warn if no subgroups
}

sub short_desc {
    my $self = shift;

    return "accept message";
}

1;

__END__

=head1 PMG::RuleDB::Accept

Accept a message.
