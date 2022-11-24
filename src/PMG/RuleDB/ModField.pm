package PMG::RuleDB::ModField;

use strict;
use warnings;
use DBI;
use Digest::SHA;
use Encode qw(encode decode);

use PMG::Utils;
use PMG::ModGroup;
use PMG::RuleDB::Object;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 4003;
}

sub oclass {
    return 'action';
}

sub otype_text {
    return 'Header Attribute';
}

sub final {
    return 0;
}

sub priority {
    return 10;
}

sub new {
    my ($type, $field, $field_value, $ogroup) = @_;
    
    my $class = ref($type) || $type;
 
    my $self = $class->SUPER::new($class->otype(), $ogroup);
   
    $self->{field} = $field;
    $self->{field_value} = $field_value;

    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;
    
    my $class = ref($type) || $type;

    defined($value) || return undef;

    my ($field, $field_value) = $value =~ m/^([^\:]*)\:(.*)$/;

    (defined($field) && defined($field_value)) || return undef;

    my $dec_field_value = PMG::Utils::try_decode_utf8($field_value);

    my $obj = $class->new($field, $dec_field_value, $ogroup);
    $obj->{id} = $id;

    $obj->{digest} = Digest::SHA::sha1_hex($id, $field, $field_value, $ogroup);
    
    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || return undef;

    my $new_value = encode('UTF-8', "$self->{field}:$self->{field_value}");

    if (defined ($self->{id})) {
	# update
	
	$ruledb->{dbh}->do(
	    "UPDATE Object SET Value = ? WHERE ID = ?", 
	    undef, $new_value, $self->{id});

    } else {
	# insert

	my $sth = $ruledb->{dbh}->prepare(
	    "INSERT INTO Object (Objectgroup_ID, ObjectType, Value) " .
	    "VALUES (?, ?, ?);");

	$sth->execute($self->ogroup, $self->otype, $new_value);
    
	$self->{id} = PMG::Utils::lastid($ruledb->{dbh}, 'object_id_seq'); 
    }
	
    return $self->{id};
}

sub execute {
    my ($self, $queue, $ruledb, $mod_group, $targets, 
	$msginfo, $vars, $marks) = @_;

    my $fvalue = PMG::Utils::subst_values_for_header($self->{field_value}, $vars);

    my $subgroups = $mod_group->subgroups($targets);

    foreach my $ta (@$subgroups) {
	my ($tg, $e) = (@$ta[0], @$ta[1]);
	$e->head->replace($self->{field}, $fvalue);
    }
}

sub short_desc {
    my $self = shift;

    return "modify field: $self->{field}:$self->{field_value}";
}

sub properties {
    my ($class) = @_;

    return {
	field => {
	    description => "The Field",
	    type => 'string',
	    pattern => '[0-9a-zA-Z\/\\\[\]\+\-\.\*\_]+',
	    maxLength => 1024,
	},
	value => {
	    description => "The Value",
	    type => 'string',
	    maxLength => 1024,
	},
    };
}

sub get {
    my ($self) = @_;

    return {
	field => $self->{field},
	value => $self->{field_value},
    };
}

sub update {
    my ($self, $param) = @_;

    $self->{field_value} = $param->{value};
    $self->{field} = $param->{field};
}

1;

__END__

=head1 PMG::RuleDB::ModField

Modify fields of a message.
