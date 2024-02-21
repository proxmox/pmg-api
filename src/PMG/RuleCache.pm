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

    return match_list_with_mode($from->{groups}, $from->{and}, $from->{invert}, sub {
	my ($group) = @_;
	my $list = $group->{objects};
	return match_list_with_mode($list, $group->{and}, $group->{invert}, sub {
	    my ($obj) = @_;
	    return $obj->who_match($addr, $ip, $ldap);
	});
    });
}

sub to_match {
    my ($self, $ruleid, $addr, $ldap) = @_;

    my $to = $self->{"$ruleid:to"};

    return 1 if scalar($to->{groups}->@*) == 0;

    return match_list_with_mode($to->{groups}, $to->{and}, $to->{invert}, sub {
	my ($group) = @_;
	my $list = $group->{objects};
	return match_list_with_mode($list, $group->{and}, $group->{invert}, sub {
	    my ($obj) = @_;
	    return $obj->who_match($addr, undef, $ldap);
	});
    });
}

sub when_match {
    my ($self, $ruleid, $time) = @_;

    my $when = $self->{"$ruleid:when"};

    return 1 if scalar($when->{groups}->@*) == 0;

    return match_list_with_mode($when->{groups}, $when->{and}, $when->{invert}, sub {
	my ($group) = @_;
	my $list = $group->{objects};
	return match_list_with_mode($list, $group->{and}, $group->{invert}, sub {
	    my ($obj) = @_;
	    return $obj->when_match($time);
	});
    });
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

    my $what_matches = {};

    for my $group ($what->{groups}->@*) {
	my $group_matches = {};
	my $and = $group->{and};
	my $invert = $group->{invert};
	for my $obj ($group->{objects}->@*) {
	    if (!$obj->can('what_match_targets')) {
		my $match = $obj->what_match($queue, $element, $msginfo, $dbh);
		for my $target ($msginfo->{targets}->@*) {
		    if (defined($match)) {
			push $group_matches->{$target}->@*, $match;
		    } else {
			push $group_matches->{$target}->@*, undef;
		    }
		}
	    } else {
		my $target_info = $obj->what_match_targets($queue, $element, $msginfo, $dbh);
		for my $target ($msginfo->{targets}->@*) {
		    my $match = $target_info->{$target};
		    if (defined($match)) {
			push $group_matches->{$target}->@*, $match->{marks};
			# only save spaminfo once
			$spaminfo = $match->{spaminfo} if !defined($spaminfo);
		    } else {
			push $group_matches->{$target}->@*, undef;
		    }
		}
	    }
	}

	for my $target (keys $group_matches->%*) {
	    my $matches = group_match_and_invert($group_matches->{$target}, $and, $invert, $msginfo);
	    push $what_matches->{$target}->@*, $matches;
	}
    }

    for my $target (keys $what_matches->%*) {
	my $target_marks = what_match_and_invert($what_matches->{$target}, $what->{and}, $what->{invert});
	$marks->{$target} = $target_marks;
    }

    return ($marks, $spaminfo);
}

# combines matches of groups
# this is only binary, and if it matches, 'or' combines the marks
# so that all found marks are included
#
# this way we can create rules like:
#
# ---
# What is and combined:
# group1: match filename .*\.pdf
# group2: spamlevel >= 3
# ACTION: remove attachments
# ---
# which would remove attachments for all *.pdf filenames where
# the spamlevel is >= 3
sub what_match_and_invert($$$) {
    my ($matches, $and, $invert) = @_;

    my $match_result = match_list_with_mode($matches, $and, $invert, sub {
	my ($match) = @_;
	return defined($match);
    });

    if ($match_result) {
	my $res = [];
	for my $match ($matches->@*) {
	    push $res->@*, $match->@* if defined($match);
	}
	return $res;
    } else {
	return undef;
    }
}

# combines group matches according to and/invert
# since we want match groups per mime part, we must
# look at the marks and possibly invert them
sub group_match_and_invert($$$$) {
    my ($group_matches, $and, $invert, $msginfo) = @_;

    my $encountered_parts = 0;
    if ($and) {
	my $set = {};
	my $count = scalar($group_matches->@*);
	for my $match ($group_matches->@*) {
	    if (!defined($match)) {
		$set = {};
		last;
	    }

	    if (scalar($match->@*) > 0) {
		$encountered_parts = 1;
		$set->{$_}++ for $match->@*;
	    } else {
		$set->{$_}++ for (1..$msginfo->{max_aid});
	    }
	}

	$group_matches = undef;
	for my $key (keys $set->%*) {
	    if ($set->{$key} == $count) {
		push $group_matches->@*, $key;
	    }
	}
	if (defined($group_matches) && scalar($group_matches->@*) == $count && !$encountered_parts) {
	    $group_matches = [];
	}
    } else {
	my $set = {};
	for my $match ($group_matches->@*) {
	    next if !defined($match);
	    if (scalar($match->@*) == 0) {
		$set->{$_} = 1 for (1..$msginfo->{max_aid});
	    } else {
		$encountered_parts = 1;
		$set->{$_} = 1 for $match->@*;
	    }
	}

	my $count = scalar(keys $set->%*);
	if ($count == $msginfo->{max_aid} && !$encountered_parts) {
	    $group_matches = [];
	} elsif ($count == 0) {
	    $group_matches = undef;
	} else {
	    $group_matches = [keys $set->%*];
	}
    }

    if ($invert) {
	$group_matches = invert_mark_list($group_matches, $msginfo->{max_aid});
    }

    return $group_matches;
}

# calls sub with each element of $list, and and/ors/inverts the result
sub match_list_with_mode($$$$) {
    my ($list, $and, $invert, $sub) = @_;

    $and //= 0;
    $invert //= 0;

    for my $el ($list->@*) {
	my $res = $sub->($el);
	if (!$and) {
	    return !$invert if $res;
	} else {
	    return $invert if !$res;
	}
    }

    return $and != $invert;
}

# inverts a list of marks with the remaining ones of the mail
# examples:
# mail has [1,2,3,4,5]
#
# undef => [1,2,3,4,5]
# [1,2] => [3,4,5]
# [1,2,3,4,5] => undef
# [] => undef // [] means the whole mail matched
sub invert_mark_list($$) {
    my ($list, $max_aid) = @_;

    if (defined($list)) {
	my $length = scalar($list->@*);
	if ($length == 0 || $length == ($max_aid - 1)) {
	    return undef;
	}
    }

    $list //= [];

    my $set = {};
    $set->{$_} = 1 for $list->@*;

    my $new_list = [];
    for (my $i = 1; $i <= $max_aid; $i++) {
	if (!$set->{$i}) {
	    push $new_list->@*, $i;
	}
    }

    return $new_list;
}

1;
