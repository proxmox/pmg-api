package PMG::RuleDB::ContentTypeFilter;

use strict;
use warnings;
use DBI;

use PVE::SafeSyslog;
use MIME::Words;

use PMG::RuleDB::MatchField;

use base qw(PMG::RuleDB::MatchField);

my $oldtypemap = {
    'application/x-msdos-program' => 'application/x-ms-dos-executable',
    'application/java-vm' => 'application/x-java',
    'application/x-javascript' => 'application/javascript',
};

sub otype {
    return 3003;
}

sub otype_text {
    return 'ContentType Filter';
}

sub new {
    my ($type, $fvalue, $ogroup, $only_content) = @_;

    my $class = ref($type) || $type;

    # translate old values
    if ($fvalue && (my $nt = $oldtypemap->{$fvalue})) {
	$fvalue = $nt;
    }

    my $self = $class->SUPER::new('content-type', $fvalue, $ogroup);
    $self->{only_content} = $only_content;

    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;

    my $class = ref($type) || $type;

    my $obj = $class->SUPER::load_attr($ruledb, $id, $ogroup, $value);

    # translate old values
    if ($obj->{field_value} && (my $nt = $oldtypemap->{$obj->{field_value}})) {
	$obj->{field_value} = $nt;
    }

    my $sth = $ruledb->{dbh}->prepare(
	"SELECT * FROM Attribut WHERE Object_ID = ?");

    $sth->execute($id);

    $obj->{only_content} = 0;

    while (my $ref = $sth->fetchrow_hashref()) {
	if ($ref->{name} eq 'only_content') {
	    $obj->{only_content} = $ref->{value};
	}
    }

    $sth->finish();

    $obj->{id} = $id;

    $obj->{digest} = Digest::SHA::sha1_hex( $id, $value, $ogroup, $obj->{only_content});

    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    if (defined($self->{id})) {
	#update - clean old attribut entries
	$ruledb->{dbh}->do(
	    "DELETE FROM Attribut WHERE Object_ID = ?",
	    undef, $self->{id});
    }

    $self->{id} = $self->SUPER::save($ruledb);

    if (defined($self->{only_content})) {
	$ruledb->{dbh}->do(
	    "INSERT INTO Attribut (Value, Name, Object_ID) VALUES (?, 'only_content', ?) ".
	    "ON CONFLICT(Object_ID, Name) DO UPDATE SET Value = Excluded.Value ",
	    undef, $self->{only_content},  $self->{id});
    }

    return $self->{id};
}

sub parse_entity {
    my ($self, $entity) = @_;

    my $res;

    # test regex for validity
    eval { "" =~ m|$self->{field_value}|; };
    if (my $err = $@) {
	warn "invalid regex: $err\n";
	return $res;
    }

    # match subtypes? We currently do exact matches only.

    if (my $id = $entity->head->mime_attr ('x-proxmox-tmp-aid')) {
	chomp $id;

	my $header_ct = $entity->{PMX_header_ct};

	my $magic_ct = $entity->{PMX_magic_ct};

	my $glob_ct = $entity->{PMX_glob_ct};

	my $check_only_content = ${self}->{only_content} // 1;

	if ($magic_ct && $magic_ct =~ m|$self->{field_value}|) {
	    push @$res, $id;
	} elsif (!$check_only_content) {
	    if ($header_ct && $header_ct =~ m|$self->{field_value}|) {
		push @$res, $id;
	    } elsif ($glob_ct && $glob_ct =~ m|$self->{field_value}|) {
		push @$res, $id;
	    }
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

    return $self->parse_entity ($entity);
}

sub properties {
    my ($class) = @_;

    return {
	contenttype => {
	    description => "Content Type",
	    type => 'string',
	    pattern => '[0-9a-zA-Z\/\\\[\]\+\-\.\*\_]+',
	    maxLength => 1024,
	},
	'only-content' => {
	    description => "use content-type from scanning only (ignore filename and header)",
	    type => 'boolean',
	    optional => 1,
	    default => 0,
	},
    };
}

sub get {
    my ($self) = @_;

    return {
	contenttype => $self->{field_value},
	'only-content' => $self->{only_content},
    };
}

sub update {
    my ($self, $param) = @_;

    $self->{field_value} = $param->{contenttype};

    if (defined($param->{'only-content'}) && $param->{'only-content'} == 1) {
	$self->{only_content} = 1;
    } else {
	delete $self->{only_content};
    }
}

1;

__END__

=head1 PMG::RuleDB::ContentTypeFilter

Content type filter.
