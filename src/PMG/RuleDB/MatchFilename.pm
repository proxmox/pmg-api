package PMG::RuleDB::MatchFilename;

use strict;
use warnings;
use DBI;
use Digest::SHA;
use Encode qw(encode);
use MIME::Words;

use PMG::Utils;
use PMG::RuleDB::Object;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 3004;
}

sub oclass {
    return 'what';
}

sub otype_text {
    return 'Match Filename';
}

sub new {
    my ($type, $fname, $ogroup) = @_;
    
    my $class = ref($type) || $type;

    my $self = $class->SUPER::new($class->otype(), $ogroup);

    $self->{fname} = $fname;
    
    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;
    
    my $class = ref($type) || $type;

    defined($value) || die "undefined value: ERROR";;
    my $decvalue = PMG::Utils::try_decode_utf8($value);

    my $obj = $class->new($decvalue, $ogroup);
    $obj->{id} = $id;

    $obj->{digest} = Digest::SHA::sha1_hex($id, $value, $ogroup);
    
    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || die "undefined ogroup: ERROR";

    my $new_value = $self->{fname};

    PMG::Utils::test_regex("^${new_value}\$");

    $new_value =~ s/\\/\\\\/g;
    $new_value = encode('UTF-8', $new_value);

    if (defined($self->{id})) {
	# update
	
	$ruledb->{dbh}->do("UPDATE Object SET Value = ? WHERE ID = ?", 
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

    my $res;

    if (my $id = $entity->head->mime_attr('x-proxmox-tmp-aid')) {
	chomp $id;

	if (my $value = PMG::Utils::extract_filename($entity->head)) {
	    eval {
		if ($value =~ m|^$self->{fname}$|i) {
		    push @$res, $id;
		}
	    };
	    warn "invalid regex: $@\n" if $@;
	}
    }

    foreach my $part ($entity->parts)  {
	if (my $match = $self->parse_entity ($part)) {
	    push @$res, @$match;
	}
    }

    return $res;
}

sub what_match {
    my ($self, $queue, $entity, $msginfo) = @_;

    return $self->parse_entity($entity);
}

sub short_desc {
    my $self = shift;
    
    return "filename=$self->{fname}";
}

sub properties {
    my ($class) = @_;

    return {
	filename => {
	    description => "Filename filter",
	    type => 'string',
	    maxLength => 1024,
	},
    };
}

sub get {
    my ($self) = @_;

    return { filename => $self->{fname} };
}

sub update {
    my ($self, $param) = @_;

    $self->{fname} = $param->{filename};
}

1;
__END__

=head1 PMG::RuleDB::MatchFilename

Match Header Filename
