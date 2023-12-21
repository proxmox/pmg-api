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
    my ($type, $fvalue, $ogroup) = @_;

    my $class = ref($type) || $type;

    # translate old values
    if ($fvalue && (my $nt = $oldtypemap->{$fvalue})) {
	$fvalue = $nt;
    }

    my $self = $class->SUPER::new('content-type', $fvalue, $ogroup);

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

    return $obj;
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

	my $header_ct = $entity->head->mime_attr ('content-type');

	my $magic_ct = $entity->{PMX_magic_ct};

	my $glob_ct = $entity->{PMX_glob_ct};

	if ($header_ct && $header_ct =~ m|$self->{field_value}|) {
	    push @$res, $id;
	} elsif ($magic_ct && $magic_ct =~ m|$self->{field_value}|) {
	    push @$res, $id;
	} elsif ($glob_ct && $glob_ct =~ m|$self->{field_value}|) {
	    push @$res, $id;
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
    };
}

sub get {
    my ($self) = @_;

    return { contenttype => $self->{field_value} };
}

sub update {
    my ($self, $param) = @_;

    $self->{field_value} = $param->{contenttype};
}

1;

__END__

=head1 PMG::RuleDB::ContentTypeFilter

Content type filter.
