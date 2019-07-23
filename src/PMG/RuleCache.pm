package PMG::RuleCache;

use strict;
use warnings;
use DBI;

use PVE::SafeSyslog;

use PMG::Utils;
use PMG::RuleDB;
use Digest::SHA;

my $ocache_size = 1023;

sub new {
    my ($type, $ruledb) = @_;

    my $self;

    $self->{ruledb} = $ruledb;
    $self->{ocache} = ();

    bless $self, $type;

    my $rules = ();

    my $dbh = $ruledb->{dbh};

    my $sha1 = Digest::SHA->new;

    eval {
	$dbh->begin_work;

	# read a consistent snapshot
	$dbh->do("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");

	my $sth = $dbh->prepare(
	    "SELECT ID, Name, Priority, Active, Direction FROM Rule " .
	    "where Active > 0 " .
	    "ORDER BY Priority DESC");

	$sth->execute();

	while (my $ref = $sth->fetchrow_hashref()) {
	    my $ruleid = $ref->{id};
	    my $rule = PMG::RuleDB::Rule->new(
		$ref->{name}, $ref->{priority}, $ref->{active},
		$ref->{direction});

	    $rule->{id} = $ruleid;
	    push @$rules, $rule;

	    $sha1->add(join(',', $ref->{id}, $ref->{name}, $ref->{priority}, $ref->{active},
			    $ref->{direction}) . "|");

	    my ($from, $to, $when, $what, $action);

	    my $sth1 = $dbh->prepare(
		"SELECT Objectgroup_ID, Grouptype FROM RuleGroup " .
		"where RuleGroup.Rule_ID = '$ruleid' " .
		"ORDER BY Grouptype, Objectgroup_ID");

	    $sth1->execute();
	    while (my $ref1 = $sth1->fetchrow_hashref()) {
		my $gtype = $ref1->{grouptype};
		my $groupid = $ref1->{objectgroup_id};

		# emtyp groups differ from non-existent groups!

		if ($gtype == 0) {      #from
		    $from = [] if !defined ($from);
		} elsif ($gtype == 1) { # to
		    $to = [] if !defined ($to);
		} elsif ($gtype == 2) { # when
		    $when = [] if !defined ($when);
		} elsif ($gtype == 3) { # what
		    $what = [] if !defined ($what);
		} elsif ($gtype == 4) { # action
		    $action = [] if !defined ($action);
		}

		my $sth2 = $dbh->prepare(
		    "SELECT ID FROM Object where Objectgroup_ID = '$groupid' " .
		    "ORDER BY ID");
		$sth2->execute();
		while (my $ref2 = $sth2->fetchrow_hashref()) {
		    my $objid = $ref2->{'id'};
		    my $obj = $self->_get_object($objid);

		    $sha1->add (join (',', $objid, $gtype, $groupid) . "|");
		    $sha1->add ($obj->{digest}, "|");

		    if ($gtype == 0) {      #from
			push @$from, $obj;
		    } elsif ($gtype == 1) { # to
			push @$to,  $obj;
		    } elsif ($gtype == 2) { # when
			push @$when,  $obj;
		    } elsif ($gtype == 3) { # what
			push @$what,  $obj;
			if ($obj->otype == PMG::RuleDB::ArchiveFilter->otype) {
			    if ($rule->{direction} == 0) {
				$self->{archivefilter_in} = 1;
			    } elsif ($rule->{direction} == 1) {
				$self->{archivefilter_out} = 1;
			    } else {
				$self->{archivefilter_in} = 1;
				$self->{archivefilter_out} = 1;
			    }
			}
		    } elsif ($gtype == 4) { # action
			push @$action, $obj;
			$self->{"$ruleid:final"} = 1 if $obj->final();
		    }
		}
		$sth2->finish();
	    }

	    $sth1->finish();

	    $self->{"$ruleid:from"} = $from;
	    $self->{"$ruleid:to"} =  $to;
	    $self->{"$ruleid:when"} = $when;
	    $self->{"$ruleid:what"} = $what;
	    $self->{"$ruleid:action"} = $action;
	}

	# Cache Greylist Exclusion
	$sth = $dbh->prepare(
	    "SELECT object.id FROM object, objectgroup " .
	    "WHERE class = 'greylist' AND " .
	    "objectgroup.id = object.objectgroup_id " .
	    "ORDER BY object.id");

	$sth->execute();
	my $grey_excl_sender = ();
	my $grey_excl_receiver = ();
	while (my $ref2 = $sth->fetchrow_hashref()) {
	    my $obj = $self->_get_object ($ref2->{'id'});

	    if ($obj->receivertest()) {
		push @$grey_excl_receiver, $obj;
	    } else {
		push @$grey_excl_sender, $obj;
	    }
	    $sha1->add ($ref2->{'id'}, "|");
	    $sha1->add ($obj->{digest}, "|");
	}

	$self->{"greylist:sender"} = $grey_excl_sender;
	$self->{"greylist:receiver"} = $grey_excl_receiver;

	$sth->finish();
    };
    my $err = $@;

    $dbh->rollback; # end transaction

    syslog ('err', "unable to load rulecache : $err") if $err;

    $self->{rules} = $rules;

    $self->{digest} = $sha1->hexdigest;

    return $self;
}

sub final {
    my ($self, $ruleid) = @_;

    defined($ruleid) || die "undefined rule id: ERROR";

    return $self->{"$ruleid:final"};
}

sub rules {
    my ($self) = @_;

    $self->{rules};
}

sub _get_object {
    my ($self, $objid) = @_;

    my $cid = $objid % $ocache_size;

    my $obj = $self->{ocache}[$cid];

    if (!defined ($obj) || $obj->{id} != $objid) {
	$obj = $self->{ruledb}->load_object($objid);
	$self->{ocache}[$cid] = $obj;
    }

    $obj || die "unable to get object $objid: ERROR";

    return $obj;
}

sub get_actions {
    my ($self, $ruleid) = @_;

    defined($ruleid) || die "undefined rule id: ERROR";

    return $self->{"$ruleid:action"};
}

sub greylist_match {
    my ($self, $addr, $ip) = @_;

    my $grey = $self->{"greylist:sender"};

    foreach my $obj (@$grey) {
	if ($obj->who_match ($addr, $ip)) {
	    return 1;
	}
    }

    return 0;
}

sub greylist_match_receiver {
    my ($self, $addr) = @_;

    my $grey = $self->{"greylist:receiver"};

    foreach my $obj (@$grey) {
	if ($obj->who_match($addr)) {
	    return 1;
	}
    }

    return 0;
}

sub from_match {
    my ($self, $ruleid, $addr, $ip, $ldap) = @_;

    my $from = $self->{"$ruleid:from"};

    return 1 if !defined ($from);

    foreach my $obj (@$from) {
	return 1 if $obj->who_match($addr, $ip, $ldap);
    }

    return 0;
}

sub to_match {
    my ($self, $ruleid, $addr, $ldap) = @_;

    my $to = $self->{"$ruleid:to"};

    return 1 if !defined ($to);

    foreach my $obj (@$to) {
	return 1 if $obj->who_match($addr, undef, $ldap);
    }

    return 0;
}

sub when_match {
    my ($self, $ruleid, $time) = @_;

    my $when = $self->{"$ruleid:when"};

    return 1 if !defined ($when);

    foreach my $obj (@$when) {
	return 1 if $obj->when_match($time);
    }

    return 0;
}

sub what_match {
    my ($self, $ruleid, $queue, $element, $msginfo, $dbh) = @_;

    my $what = $self->{"$ruleid:what"};

    my $res;

    # $res->{marks} is used by mark specific actions like remove-attachments
    # $res->{$target}->{marks} is only used in apply_rules() to exclude some
    # targets (spam blacklist and whitelist)

    if (!defined ($what)) {
	# match all targets
	foreach my $target (@{$msginfo->{targets}}) {
	    $res->{$target}->{marks} = [];
	}

	$res->{marks} = [];
	return $res;
    }

    my $marks;

    foreach my $obj (@$what) {
	if (!$obj->can('what_match_targets')) {
	    if (my $match = $obj->what_match($queue, $element, $msginfo, $dbh)) {
		push @$marks, @$match;
	    }
	}
    }

    foreach my $target (@{$msginfo->{targets}}) {
	$res->{$target}->{marks} = $marks;
	$res->{marks} = $marks;
    }

    foreach my $obj (@$what) {
	if ($obj->can ("what_match_targets")) {
	    my $target_info;
	    if ($target_info = $obj->what_match_targets($queue, $element, $msginfo, $dbh)) {
		foreach my $k (keys %$target_info) {
		    my $cmarks = $target_info->{$k}->{marks}; # make a copy
		    $res->{$k} = $target_info->{$k};
		    push @{$res->{$k}->{marks}}, @$cmarks if $cmarks;
		}
	    }
	}
    }

    return $res;
}

1;
