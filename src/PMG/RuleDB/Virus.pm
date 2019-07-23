package PMG::RuleDB::Virus;

use strict;
use warnings;
use DBI;
use Digest::SHA;

use PMG::Utils;
use PMG::RuleDB::Object;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 3001;
}

sub oclass {
    return 'what';
}

sub otype_text {
    return 'Virus Filter';
}

sub oisedit {
    return 0;   
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

sub what_match {
    my ($self, $queue, $entity, $msginfo) = @_;

    if ($queue->{vinfo}) {
	return [];
    } 

    return undef;
}

sub short_desc {
    my $self = shift;
    
    return "active";
}

sub properties {
    my ($class) = @_;

    return { };
}

sub get {
    my ($self) = @_;

    return { };
}

sub update {
    my ($self, $param) = @_;
}

1;

__END__

=head1 PMG::RuleDB::Virus

Virus filter
