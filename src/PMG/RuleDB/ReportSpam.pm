package PMG::RuleDB::ReportSpam;

# FIXME: remove with PMG 8.0

use strict;
use warnings;
use DBI;

use PVE::SafeSyslog;

use PMG::Utils;
use PMG::ModGroup;
use PMG::RuleDB::Object;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 4008;
}

sub oclass {
    return 'action';
}

sub otype_text {
    return 'Report Spam';
}

sub oisedit {
    return 0;   
}

sub final {
    return 1;
}

sub priority {
    return 97;
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

    syslog('warning', "%s: deprecated action 'Attach' will be removed with PMG 8.0.",
	   $queue->{logid},);

    my $rulename = $vars->{RULE} // 'unknown';

    my $subgroups = $mod_group->subgroups($targets);

    foreach my $ta (@$subgroups) {
	my ($tg, $entity) = (@$ta[0], @$ta[1]);

	if ($msginfo->{testmode}) {
	    my $fh = $msginfo->{test_fh};
	    print $fh "report as spam\n";
	} else {

	    my $spamtest = $queue->{sa};

	    $queue->{fh}->seek (0, 0);
	    *SATMP = \*{$queue->{fh}};
	    my $mail = $spamtest->parse(\*SATMP);

	    $spamtest->report_as_spam($mail);
	    
	    $mail->finish();	
	}
	syslog('info', "%s: report mail as spam (rule: %s)", $queue->{logid}, $rulename);
	$queue->set_status ($tg, 'delivered');
    }
}

sub short_desc {
    my $self = shift;

    return "";
}

1;
__END__

=head1 PMG::RuleDB::ReportSpam

Report as SPAM.
