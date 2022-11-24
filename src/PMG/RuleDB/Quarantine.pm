package PMG::RuleDB::Quarantine;

use strict;
use warnings;
use DBI;
use Digest::SHA;
use Encode qw(encode);

use PVE::SafeSyslog;

use PMG::Utils;
use PMG::ModGroup;
use PMG::RuleDB::Object;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 4006;
}

sub oclass {
    return 'action';
}

sub otype_text {
    return 'Quarantine';
}

sub oisedit {
    return 0;   
}

sub final {
    return 1;
}

sub priority {
    return 90;
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

    if (defined ($self->{id})) {
	# update
	
	# nothing to update

    } else {
	# insert
	my $sth = $ruledb->{dbh}->prepare (
	    "INSERT INTO Object (Objectgroup_ID, ObjectType) VALUES (?, ?);");

	$sth->execute($self->ogroup, $self->otype);

	$self->{id} = PMG::Utils::lastid($ruledb->{dbh}, 'object_id_seq'); 
    }
	
    return $self->{id};
}

sub execute {
    my ($self, $queue, $ruledb, $mod_group, $targets, 
	$msginfo, $vars, $marks, $ldap) = @_;
    
    my $subgroups = $mod_group->subgroups($targets, 1);

    my $rulename = encode('UTF-8', $vars->{RULE} // 'unknown');

    foreach my $ta (@$subgroups) {
	my ($tg, $entity) = (@$ta[0], @$ta[1]);

	PMG::Utils::remove_marks($entity);

	if ($queue->{vinfo}) {
	    if (my $qid = $queue->quarantine_mail($ruledb, 'V', $entity, $tg, $msginfo, $vars, $ldap)) {

		foreach (@$tg) {
		    syslog (
			'info',
			"$queue->{logid}: moved mail for <%s> to virus quarantine - %s (rule: %s)",
			encode('UTF-8',$_),
			$qid,
			$rulename,
		    );
		}

		$queue->set_status ($tg, 'delivered');
	    }

	} else {
	    if (my $qid = $queue->quarantine_mail($ruledb, 'S', $entity, $tg, $msginfo, $vars, $ldap)) {

		foreach (@$tg) {
		    syslog (
			'info',
			"$queue->{logid}: moved mail for <%s> to spam quarantine - %s (rule: %s)",
			encode('UTF-8',$_),
			$qid,
			$rulename,
		    );
		}

		$queue->set_status($tg, 'delivered');
	    }
	}
    }

    # warn if no subgroups
}

sub short_desc {
    my $self = shift;

    return 'Move to quarantine.';
}

1;
