package PMG::RuleDB::MatchField;

use strict;
use warnings;
use DBI;
use Digest::SHA;
use Encode qw(encode);
use MIME::Words;

use PVE::SafeSyslog;

use PMG::Utils;
use PMG::RuleDB::Object;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 3002;
}

sub oclass {
    return 'what';
}

sub otype_text {
    return 'Match Field';
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

    defined($value) || die "undefined value: ERROR";;

    my ($field, $field_value) = $value =~ m/^([^:]*)\:(.*)$/;

    defined($field) || die "undefined object attribute: ERROR";
    defined($field_value) || die "undefined object attribute: ERROR";

    my $decoded_field_value = PMG::Utils::try_decode_utf8($field_value);
    # use known constructor, bless afterwards (because sub class can have constructor
    # with other parameter signature).
    my $obj =  PMG::RuleDB::MatchField->new($field, $decoded_field_value, $ogroup);
    bless $obj, $class;

    $obj->{id} = $id;

    $obj->{digest} = Digest::SHA::sha1_hex($id, $field, $field_value, $ogroup);

    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || die "undefined ogroup: ERROR";

    my $regex = $self->{field_value};

    PMG::Utils::test_regex($regex);

    my $new_value = "$self->{field}:$regex";
    $new_value =~ s/\\/\\\\/g;
    $new_value = encode('UTF-8', $new_value);

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

sub parse_entity {
    my ($self, $entity) = @_;

    return undef if !$self->{field};

    my $res;

    if (my $id = $entity->head->mime_attr ('x-proxmox-tmp-aid')) {
	chomp $id;

	for my $value ($entity->head->get_all($self->{field})) {
	    chomp $value;

	    my $decvalue = PMG::Utils::decode_rfc1522($value);
	    $decvalue = PMG::Utils::try_decode_utf8($decvalue);

	    eval {
		if ($decvalue =~ m|$self->{field_value}|i) {
		    push @$res, $id;
		}
	    };
	    warn "invalid regex: $@\n" if $@;
	}
    }

    foreach my $part ($entity->parts)  {
	if (my $match = $self->parse_entity($part)) {
	    push @$res, @$match;
	}
    }

    return $res;
}

sub what_match {
    my ($self, $queue, $entity, $msginfo) = @_;

    return $self->parse_entity ($entity);
}

sub short_desc {
    my $self = shift;

    return "$self->{field}=$self->{field_value}";
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

=head1 PMG::RuleDB::MatchField

Match Header Fields
