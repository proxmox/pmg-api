package PMG::RuleDB::Group;

use strict;
use warnings;
use DBI;

use PMG::RuleDB;

# FIXME: log failures ?

sub new {
    my ($type, $name, $info, $class) = @_;

    my $self = {
	name => PMG::Utils::try_decode_utf8($name),
	info => PMG::Utils::try_decode_utf8($info),
	class => $class,
    };

    bless $self, $type;

    return $self;
}

sub gtype {
    my ($self, $str) = @_;

    if ($str eq "from") { return 0; }
    if ($str eq "to") { return 1; }
    if ($str eq "when") { return 2; }
    if ($str eq "what") { return 3; }
    if ($str eq "action") { return 4; }
    if ($str eq "greylist") { return 5; }

    return -1;
}

sub name {
    my ($self, $v) = @_;

    if (defined ($v)) {
	$self->{name} = $v;
    }

    $self->{name};
}

sub info {
    my ($self, $v) = @_;

    if (defined ($v)) {
	$self->{info} = $v;
    }

    $self->{info};
}

sub class {
    my ($self, $v) = @_;

    if (defined ($v)) {
	$self->{class} = $v;
    }

    $self->{class};
}

sub id {
    my ($self, $v) = @_;

    if (defined ($v)) {
	$self->{id}=$v;
    }

    $self->{id};
}

1;
