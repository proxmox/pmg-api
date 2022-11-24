package PMG::RuleDB::Rule;

use strict;
use warnings;
use DBI;

use PMG::RuleDB;

# FIXME: log failures ?

sub new {
    my ($type, $name, $priority, $active, $direction) = @_;

    my $self = { 
	name => PMG::Utils::try_decode_utf8($name) // '',
	priority => $priority // 0,
	active => $active // 0,
    }; 
    
    if (!defined($direction)) {
        $self->{direction} = 2;
    } else {        
        $self->{direction} = $direction;
    }
    
    bless $self, $type;

    return $self;
}

sub name { 
    my ($self, $v) = @_; 

    if (defined ($v)) {
	$self->{name} = $v;
    }

    $self->{name}; 
}

sub priority { 
    my ($self, $v) = @_; 

    if (defined ($v)) {
	$self->{priority} = $v;
    }
    
    $self->{priority}; 
}

sub direction { 
    my ($self, $v) = @_; 

    if (defined ($v)) {
	$self->{direction} = $v;
    }
    
    $self->{direction}; 
}

sub active { 
    my ($self, $v) = @_; 

    if (defined ($v)) {
	$self->{active} = $v;
    }

    $self->{active}; 
}

sub id { 
    my $self = shift; 

    $self->{id}; 
}

1;
