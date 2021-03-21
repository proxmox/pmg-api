package PMG::AtomicFile;

use strict;
use IO::AtomicFile;

use base qw(IO::AtomicFile);

sub new {
    my $class = shift;
    
    my $self = $class->SUPER::new(@_);
    
    return $self;
}

sub DESTROY {
    # don't close automatically (explicit close required to commit changes)
}

1;
