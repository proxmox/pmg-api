package PMG::RuleDB::Attach;

# FIXME: remove with PMG 8.0

use strict;
use warnings;
use DBI;
use Digest::SHA;

use PVE::SafeSyslog;

use PMG::Utils;
use PMG::ModGroup;
use PMG::RuleDB::Object;
use PMG::MailQueue;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 4004;
}

sub oclass {
    return 'action';
}

sub otype_text {
    return 'Attach';
}

sub oisedit {
    return 0;
}

sub final {
    return 0;
}

sub priority {
    return 49;
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

    my $obj = $class->new ($ogroup);
    $obj->{id} = $id;

    $obj->{digest} = Digest::SHA::sha1_hex($id, $ogroup);

    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || die "undefined object attribute: ERROR";

    if (defined ($self->{id})) {
	# update not needed
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

    my $subgroups = $mod_group->subgroups($targets);

    foreach my $ta (@$subgroups) {
	my ($tg, $entity) = (@$ta[0], @$ta[1]);

	my $spooldir = $PMG::MailQueue::spooldir;
	my $path = "$spooldir/active/$queue->{uid}";
	$entity->attach(
	    Path => $path,
	    Filename => "original_message.eml",
	    Disposition => "attachment",
	    Type => "message/rfc822");
    }
}

sub short_desc {
    my $self = shift;

    return "attach original mail";
}


1;

__END__

=head1 PMG::RuleDB::Attach

Attach original mail.
