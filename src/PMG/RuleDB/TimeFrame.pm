package PMG::RuleDB::TimeFrame;

use strict;
use warnings;
use DBI;
use Digest::SHA;

use PMG::Utils;
use PMG::RuleDB::Object;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 2000;
}

sub oclass {
    return 'when';
}

sub otype_text {
    return 'TimeFrame';
}

my $hm_to_minutes = sub {
    my ($hm) = @_;

    if ($hm =~ m/^(\d+):(\d+)$/) {
        my @tmp = split(/:/, $hm);
	return $tmp[0]*60+$tmp[1];
    }
    return 0;
};

my $minutes_to_hm = sub {
    my ($minutes) = @_;

    my $hour = int($minutes/60);
    my $rest = int($minutes%60);

    return sprintf("%02d:%02d", $hour, $rest);
};

sub new {
    my ($type, $start, $end, $ogroup) = @_;

    my $class = ref($type) || $type;

    my $self = $class->SUPER::new($class->otype(), $ogroup);

    $start //= "00:00";
    $end //= "24:00";

    # Note: allow H:i or integer format
    if ($start =~ m/:/) {
	$start = $hm_to_minutes->($start);
    }
    if ($end =~ m/:/) {
	$end = $hm_to_minutes->($end);
    }

    $self->{start} = $start;
    $self->{end} = $end;

    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;

    my $class = ref($type) || $type;

    defined($value) || return undef;

    my ($sh, $sm, $eh, $em) = $value =~ m/(\d+):(\d+)-(\d+):(\d+)/;

    my $start = $sh*60+$sm;
    my $end = $eh*60+$em;

    my $obj = $class->new($start, $end, $ogroup);
    $obj->{id} = $id;

    $obj->{digest} = Digest::SHA::sha1_hex ($id, $start, $end, $ogroup);

    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || return undef;
    defined($self->{start}) || return undef;
    defined($self->{end}) || return undef;

    my $start = $minutes_to_hm->($self->{start});
    my $end = $minutes_to_hm->($self->{end});

    my $v = "$start-$end";

    if (defined ($self->{id})) {
	# update

	$ruledb->{dbh}->do(
	    "UPDATE Object SET Value = ? WHERE ID = ?", undef, $v, $self->{id});

    } else {
	# insert

	my $sth = $ruledb->{dbh}->prepare(
	    "INSERT INTO Object " .
	    "(Objectgroup_ID, ObjectType, Value) " .
	    "VALUES (?, ?, ?);");

	$sth->execute($self->ogroup, $self->otype, $v);

	$self->{id} = PMG::Utils::lastid($ruledb->{dbh}, 'object_id_seq');
    }

    return $self->{id};
}

sub when_match {
    my ($self, $t) = @_;

    my ($sec,$min,$hour) = localtime($t);

    my $amin = $hour*60 + $min;

    if ($self->{end} >= $self->{start}) {

	return $amin >= $self->{start} && $amin <= $self->{end};

    } else {

	return  ($amin <= $self->{end}) || ($amin >= $self->{start});
    }
}

sub short_desc {
    my $self = shift;

    my $start = $minutes_to_hm->($self->{start});
    my $end = $minutes_to_hm->($self->{end});

    return "$start-$end";
}

sub properties {
    my ($class) = @_;

    return {
	start => {
	    description => "Start time in `H:i` format (00:00).",
	    type => 'string',
	    pattern => '\d?\d:\d?\d',
	},
	end => {
	    description => "End time in `H:i` format (00:00).",
	    type => 'string',
	    pattern => '\d?\d:\d?\d',
	},
    };
}

sub get {
    my ($self) = @_;

    return {
	start => $minutes_to_hm->($self->{start}),
	end => $minutes_to_hm->($self->{end}),
    };
}

sub update {
    my ($self, $param) = @_;

    $self->{start} = $hm_to_minutes->($param->{start});
    $self->{end} = $hm_to_minutes->($param->{end});
}


1;

__END__

=head1 PMG::RuleDB::TimeFrame

A WHEN object to check for a specific daytime.

=head2 Attributes

=head3 start

Start time im minutes since 00:00.

=head3 end

End time im minutes since 00:00.

=head2 Examples

    $obj = PMG::RuleDB::TimeFrame->new(8*60+15, 16*60+30);

Represent: 8:15 to 16:30

Note: End time is allowed to be smaller that start time.
