package PMG::RuleDB::MatchArchiveFilename;

use strict;
use warnings;

use PMG::Utils;
use PMG::RuleDB::MatchFilename;

use base qw(PMG::RuleDB::MatchFilename);

sub otype {
    return 3006;
}

sub oclass {
    return 'what';
}

sub otype_text {
    return 'Match Archive Filename';
}

sub parse_entity {
    my ($self, $entity) = @_;

    my $res;

    # test regex for validity
    eval { "" =~ m|^$self->{fname}$|i; };
    if (my $err = $@) {
	warn "invalid regex: $err\n";
	return $res;
    }

    if (my $id = $entity->head->mime_attr('x-proxmox-tmp-aid')) {
	chomp $id;

	my $fn = PMG::Utils::extract_filename($entity->head);
	if (defined($fn) && $fn =~ m|^$self->{fname}$|i) {
	    push @$res, $id;
	} elsif (my $filenames = $entity->{PMX_filenames}) {
	    # Match inside archives
	    for my $fn (keys %$filenames) {
		if ($fn =~ m|^$self->{fname}$|i) {
		    push @$res, $id;
		    last;
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

1;
__END__

=head1 PMG::RuleDB::MatchArchiveFilename

Match Archive Filename
