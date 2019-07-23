package PMG::SMTPPrinter;

use strict;
use warnings;

sub new {
    my ($class, $smtp) = @_;

    my $self = { smtp => $smtp };

    return bless $self;
}

sub print {
    my ($self, $line) = @_;

    $self->{smtp}->datasend ($line);
}

1;
