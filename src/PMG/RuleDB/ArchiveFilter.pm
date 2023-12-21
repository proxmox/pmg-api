package PMG::RuleDB::ArchiveFilter;

use strict;
use warnings;
use DBI;
use MIME::Words;

use PVE::SafeSyslog;

use PMG::RuleDB::ContentTypeFilter;

use base qw(PMG::RuleDB::ContentTypeFilter);

sub otype {
    return 3005;
}

sub otype_text {
    return 'Archive Filter';
}

my $pmtypes = {
    'proxmox/unreadable-archive' => undef,
};

sub new {
    my ($type, $fvalue, $ogroup) = @_;
    
    my $class = ref($type) || $type;

    my $self = $class->SUPER::new ($fvalue, $ogroup);
    
    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;
    
    my $class = ref($type) || $type;

    my $obj = $class->SUPER::load_attr($ruledb, $id, $ogroup, $value);

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
	} else {
	    # match inside archives 
	    if (my $cts = $entity->{PMX_content_types}) {
		foreach my $ct (keys %$cts) {
		    if ($ct =~ m|$self->{field_value}|) {
			push @$res, $id;
			last;
		    }
		}
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

1;

__END__

=head1 PMG::RuleDB::ArchiveFilter

Content type filter for Archives
