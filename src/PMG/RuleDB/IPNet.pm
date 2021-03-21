package PMG::RuleDB::IPNet;

use strict;
use warnings;
use DBI;
use Net::CIDR::Lite;

use PMG::Utils;
use PMG::RuleDB::WhoRegex;

use base qw(PMG::RuleDB::WhoRegex);

sub otype {
    return 1004;
}

sub otype_text {
    return 'IP Network';
}

sub new {
    my ($type, $address, $ogroup) = @_;
    
    my $class = ref($type) || $type;
 
    $address //= '127.0.0.1/32';

    my $self = $class->SUPER::new($address, $ogroup);

    return $self;
}

sub who_match {
    my ($self, $addr, $ip) = @_;

    return 0 if !$ip;

    my $cidr = Net::CIDR::Lite->new;
    $cidr->add($self->{address});

    return $cidr->find($ip);
}

sub properties {
    my ($class) = @_;

    return {
	cidr => {
	    description => "Network address in CIDR notation.",
	    type => 'string', format => 'CIDR',
	},
    };
}

sub get {
    my ($self) = @_;

    return { cidr => $self->{address} };
}

sub update {
    my ($self, $param) = @_;

    $self->{address} = $param->{cidr};
}

1;

__END__

=head1 PMG::RuleDB::IPNet

A WHO object to check sender IP addresses.

=head2 Attributes

=head3 address

An IP address/network (CIDR representation).

=head2 Examples

    $obj = PMG::RuleDB::IPNet->new ('192.168.2.0/20');

