package PMG::RuleDB::Domain;

use strict;
use warnings;
use DBI;

use PMG::RuleDB::WhoRegex;

use base qw(PMG::RuleDB::WhoRegex);

sub otype {
    return 1002;
}

sub otype_text {
    return 'Domain';
}

sub new {
    my ($type, $address, $ogroup) = @_;

    my $class = ref($type) || $type;

    $address //= 'domain.tld';

    my $self = $class->SUPER::new($address, $ogroup);

    return $self;
}

sub who_match {
    my ($self, $addr) = @_;

    my @parts = split('@', $addr);

    return undef if scalar(@parts) < 2;

    my $domain = $parts[-1]; # last element
    return lc $domain eq lc $self->{address};
}

sub short_desc {
    my $self = shift;

    my $desc = $self->{address};

    return $desc;
}

sub properties {
    my ($class) = @_;

    return {
	domain => {
	    description => "DNS domain name (Sender).",
	    type => 'string', format => 'dns-name',
	},
    };
}

sub get {
    my ($self) = @_;

    return { domain => $self->{address} };
}

sub update {
    my ($self, $param) = @_;

    $self->{address} = $param->{domain};
}

1;
__END__

=head1 PMG::RuleDB::Domain

A WHO object to check email domains.

=head2 Attributes

=head3 address

An Email domain. We use case insensitive compares.

=head2 Examples

    $obj = PMG::RuleDB::Domain->new ('yourdomain.com');
