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

    my $type_map =  {
	0 => "from",
	1 => "to",
	2 => "when",
	3 => "what",
	4 => "action",
    };

    eval {
	$dbh->begin_work;

	# read a consistent snapshot
	$dbh->do("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");

	my $sth = $dbh->prepare(
	    "SELECT ID, Name, Priority, Active, Direction FROM Rule " .
	    "where Active > 0 " .
	    "ORDER BY Priority DESC, ID DESC");

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

	    $self->{"$ruleid:from"} = { groups => [] };
	    $self->{"$ruleid:to"} =  { groups => [] };
	    $self->{"$ruleid:when"} = { groups => [] };
	    $self->{"$ruleid:what"} = { groups => [] };
	    $self->{"$ruleid:action"} = { groups => [] };

	    my $attribute_sth = $dbh->prepare("SELECT * FROM Rule_Attributes WHERE Rule_ID = ? ORDER BY Name");
	    $attribute_sth->execute($ruleid);

	    my $rule_attributes = [];
	    while (my $ref = $attribute_sth->fetchrow_hashref()) {
		if ($ref->{name} =~ m/^(from|to|when|what)-(and|invert)$/) {
		    my $type = $1;
		    my $prop = $2;
		    my $value = $ref->{value};
		    $self->{"${ruleid}:${type}"}->{$prop} = $value;

		    $sha1->add("${ruleid}:${type}-${prop}=${value}|");
		}
	    }

	    my $sth1 = $dbh->prepare(
		"SELECT Objectgroup_ID, Grouptype FROM RuleGroup " .
		"where RuleGroup.Rule_ID = '$ruleid' " .
		"ORDER BY Grouptype, Objectgroup_ID");

	    $sth1->execute();
	    while (my $ref1 = $sth1->fetchrow_hashref()) {
		my $gtype = $ref1->{grouptype};
		my $groupid = $ref1->{objectgroup_id};
		my $objects = [];

		my $sth2 = $dbh->prepare(
		    "SELECT ID FROM Object where Objectgroup_ID = '$groupid' " .
		    "ORDER BY ID");
		$sth2->execute();
		while (my $ref2 = $sth2->fetchrow_hashref()) {
		    my $objid = $ref2->{'id'};
		    my $obj = $self->_get_object($objid);

		    $sha1->add (join (',', $objid, $gtype, $groupid) . "|");
		    $sha1->add ($obj->{digest}, "|");

		    push @$objects, $obj;

		    if ($gtype == 3) { # what
			if ($obj->otype == PMG::RuleDB::ArchiveFilter->otype ||
			    $obj->otype == PMG::RuleDB::MatchArchiveFilename->otype)
			{
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
			$self->{"$ruleid:final"} = 1 if $obj->final();
		    }
		}
		$sth2->finish();

		my $group = {
		    objects => $objects,
		};

		my $objectgroup_sth = $dbh->prepare("SELECT * FROM Objectgroup_Attributes WHERE Objectgroup_ID = ?");
		$objectgroup_sth->execute($groupid);

		while (my $ref = $objectgroup_sth->fetchrow_hashref()) {
		    $group->{and} = $ref->{value} if $ref->{name} eq 'and';
		    $group->{invert} = $ref->{value} if $ref->{name} eq 'invert';
		}
		$sha1->add (join(',', $groupid, $group->{and} // 0, $group->{invert} // 0), "|");

		my $type = $type_map->{$gtype};
		push $self->{"$ruleid:$type"}->{groups}->@*, $group;
	    }

	    $sth1->finish();
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

    my $actions = $self->{"$ruleid:action"};

    return undef if scalar($actions->{groups}->@*) == 0;

    my $res = [];
    for my $action ($actions->{groups}->@*) {
	push $res->@*, $action->{objects}->@*;
    }
    return $res;
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

    return 1 if scalar($from->{groups}->@*) == 0;

    # postfix prefixes ipv6 addresses with IPv6:
    if (defined($ip) && $ip =~ /^IPv6:(.*)/) {
	$ip = $1;
    }

    for my $group ($from->{groups}->@*) {
	for my $obj ($group->{objects}->@*) {
	    return 1 if $obj->who_match($addr, $ip, $ldap);
	}
    }

    return 0;
}

sub to_match {
    my ($self, $ruleid, $addr, $ldap) = @_;

    my $to = $self->{"$ruleid:to"};

    return 1 if scalar($to->{groups}->@*) == 0;

    for my $group ($to->{groups}->@*) {
	for my $obj ($group->{objects}->@*) {
	    return 1 if $obj->who_match($addr, undef, $ldap);
	}
    }


    return 0;
}

sub when_match {
    my ($self, $ruleid, $time) = @_;

    my $when = $self->{"$ruleid:when"};

    return 1 if scalar($when->{groups}->@*) == 0;

    for my $group ($when->{groups}->@*) {
	for my $obj ($group->{objects}->@*) {
	    return 1 if $obj->when_match($time);
	}
    }

    return 0;
}

sub what_match {
    my ($self, $ruleid, $queue, $element, $msginfo, $dbh) = @_;

    my $what = $self->{"$ruleid:what"};

    my $marks;
    my $spaminfo;

    if (scalar($what->{groups}->@*) == 0) {
	# match all targets
	foreach my $target (@{$msginfo->{targets}}) {
	    $marks->{$target} = [];
	}
	return ($marks, $spaminfo);
    }

    for my $group ($what->{groups}->@*) {
	for my $obj ($group->{objects}->@*) {
	    if (!$obj->can('what_match_targets')) {
		if (my $match = $obj->what_match($queue, $element, $msginfo, $dbh)) {
		    for my $target ($msginfo->{targets}->@*) {
			push $marks->{$target}->@*, $match->@*;
		    }
		}
	    } else {
		if (my $target_info = $obj->what_match_targets($queue, $element, $msginfo, $dbh)) {
		    foreach my $k (keys $target_info->%*) {
			push $marks->{$k}->@*, $target_info->{$k}->{marks}->@*;
			# only save spaminfo once
			$spaminfo = $target_info->{$k}->{spaminfo} if !defined($spaminfo);
		    }
		}
	    }
	}
    }

    return ($marks, $spaminfo);
}

1;
