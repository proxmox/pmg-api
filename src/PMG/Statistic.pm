package PMG::Statistic;

use strict;
use warnings;
use DBI;
use Encode qw(encode);
use Time::Local;
use Time::Zone;

use PVE::SafeSyslog;

use PMG::ClusterConfig;
use PMG::RuleDB;

sub new {
    my ($self, $start, $end) = @_;

    $self = {};

    bless($self);

    if (defined($start) && defined($end)) {
        $self->timespan($start, $end);
    } else {
	my $ctime = time();
        $self->timespan($ctime, $ctime - 24*3600);
    }

    return $self;
}

sub clear_stats {
    my ($dbh) = @_;

    eval {
	$dbh->begin_work;

	$dbh->do ("LOCK TABLE StatInfo");
	$dbh->do ("LOCK TABLE ClusterInfo");

	$dbh->do ("DELETE FROM Statinfo");
	$dbh->do ("DELETE FROM DailyStat");
	$dbh->do ("DELETE FROM LocalStat");
	$dbh->do ("DELETE FROM DomainStat");
	$dbh->do ("DELETE FROM VirusInfo");
	$dbh->do ("DELETE FROM ClusterInfo WHERE name = 'lastmt_DomainStat'");
	$dbh->do ("DELETE FROM ClusterInfo WHERE name = 'lastmt_DailyStat'");
	$dbh->do ("DELETE FROM ClusterInfo WHERE name = 'lastmt_LocalStat'");
	$dbh->do ("DELETE FROM ClusterInfo WHERE name = 'lastmt_VirusInfo'");

	$dbh->commit;
    };
    if ($@) {
	$dbh->rollback;
	die $@;
    }
}

sub update_stats_generic  {
    my ($dbh, $statinfoid, $select, $update, $insert) = @_;

    my $todo = 0;
    my $maxentries = 100000;


    eval {
	$dbh->begin_work;

	$dbh->do("LOCK TABLE StatInfo IN EXCLUSIVE MODE");

	my $sth = $dbh->prepare("SELECT last_value FROM cstatistic_id_seq");
	$sth->execute();
	my $maxinfo = $sth->fetchrow_hashref();
	goto COMMIT if !$maxinfo;
	my $last_value = $maxinfo->{last_value};
	goto COMMIT if !defined ($last_value);

	$sth = $dbh->prepare("SELECT ivalue as value FROM StatInfo WHERE NAME = '$statinfoid'");
	$sth->execute();
	my $statinfo = $sth->fetchrow_hashref();

	my $startid = $statinfo ? $statinfo->{value} : 0;
	goto COMMIT if $startid > $last_value;

	my $endid = $startid + $maxentries;
	$endid = $last_value + 1 if $endid > $last_value;
	$todo = $last_value + 1 - $endid;

	my $timezone = tz_local_offset();;

	$select =~ s/__timezone__/$timezone/g;
	$select =~ s/__startid__/$startid/g;
	$select =~ s/__endid__/$endid/g;

	$sth = $dbh->prepare($select);
	$sth->execute();

	my $cmd = "";
        #print "TEST:$last_value:$endid:$todo\n";

	while (my $ref = $sth->fetchrow_hashref()) {
	    if ($ref->{exists}) {
		$cmd .= &$update($ref);
	    } else {
		$cmd .= &$insert($ref);
	    }
	}

	$dbh->do ($cmd) if $cmd;

	$sth->finish();

	if ($statinfo) {
	    $dbh->do("UPDATE StatInfo SET ivalue = $endid WHERE NAME = '$statinfoid'");
	} else {
	    $dbh->do("INSERT INTO StatInfo VALUES ('$statinfoid', $endid)");
	}

      COMMIT:
	$dbh->commit;
    };

    if ($@) {
	$dbh->rollback;
	die $@;
    }

    return $todo;
}

sub update_stats_dailystat  {
    my ($dbh, $cinfo) = @_;

    my $role = $cinfo->{local}->{type} // '-';
    return 0 if !(($role eq '-') || ($role eq 'master'));

    my $select = "SELECT sub.*, dailystat.time IS NOT NULL as exists FROM " .
	"(SELECT COUNT (CASE WHEN direction THEN 1 ELSE NULL END) as count_in, " .
	"COUNT (CASE WHEN NOT direction THEN 1 ELSE NULL END) as count_out, " .
	"SUM (CASE WHEN direction THEN bytes ELSE NULL END) / (1024.0*1024) as bytes_in, " .
	"SUM (CASE WHEN NOT direction THEN bytes ELSE NULL END) / (1024.0*1024) as bytes_out, " .
	"COUNT (CASE WHEN virusinfo IS NOT NULL AND direction THEN 1 ELSE NULL END) AS virus_in, " .
	"COUNT (CASE WHEN virusinfo IS NOT NULL AND NOT direction THEN 1 ELSE NULL END) AS virus_out, " .
	"COUNT (CASE WHEN virusinfo IS NULL AND direction AND ptime > 0 AND spamlevel >= 3 THEN 1 ELSE NULL END) as spam_in, " .
	"COUNT (CASE WHEN virusinfo IS NULL AND NOT direction AND ptime > 0 AND spamlevel >= 3 THEN 1 ELSE NULL END) as spam_out, " .
	"COUNT (CASE WHEN virusinfo IS NULL AND direction AND sender = '' THEN 1 ELSE NULL END) as bounces_in, " .
	"COUNT (CASE WHEN virusinfo IS NULL AND NOT direction AND sender = '' THEN 1 ELSE NULL END) as bounces_out, " .
	"COUNT (CASE WHEN virusinfo IS NULL AND ptime = 0 AND spamlevel = 5 THEN 1 ELSE NULL END) as glcount, " .
	"COUNT (CASE WHEN virusinfo IS NULL AND ptime = 0 AND spamlevel = 4 THEN 1 ELSE NULL END) as spfcount, " .
	"sum (cstatistic.ptime) / 1000.0 as ptimesum, " .
	"((cstatistic.time + __timezone__) / 3600) * 3600 as hour " .
	"from cstatistic where id >= __startid__ and id < __endid__ group by hour) as sub " .
	"left join dailystat on (sub.hour = dailystat.time)";

    my $update = sub {
	my $ref = shift;
	my @values = ();
	my $sql = '';

	push @values, "CountIn = CountIn + $ref->{count_in}" if $ref->{count_in};
	push @values, "CountOut = CountOut + $ref->{count_out}" if $ref->{count_out};
	push @values, "BytesIn = BytesIn + $ref->{bytes_in}" if $ref->{bytes_in};
	push @values, "BytesOut = BytesOut + $ref->{bytes_out}" if $ref->{bytes_out};
	push @values, "VirusIn = VirusIn + $ref->{virus_in}" if $ref->{virus_in};
	push @values, "VirusOut = VirusOut + $ref->{virus_out}" if $ref->{virus_out};
	push @values, "SpamIn = SpamIn + $ref->{spam_in}" if $ref->{spam_in};
	push @values, "SpamOut = SpamOut + $ref->{spam_out}" if $ref->{spam_out};
	push @values, "BouncesIn = BouncesIn + $ref->{bounces_in}" if $ref->{bounces_in};
	push @values, "BouncesOut = BouncesOut + $ref->{bounces_out}" if $ref->{bounces_out};
	push @values, "GreylistCount = GreylistCount + $ref->{glcount}" if $ref->{glcount};
	push @values, "SPFCount = SPFCount + $ref->{spfcount}" if $ref->{spfcount};
	push @values, "PTimeSum = PTimeSum + $ref->{ptimesum}" if $ref->{ptimesum};
	push @values, "MTime = EXTRACT(EPOCH FROM now())::INTEGER";

	if (scalar (@values)) {
	    $sql .= "UPDATE dailystat SET ";
	    $sql .= join (',', @values);
	    $sql .= " WHERE time = $ref->{hour};";
	}
	return $sql;
    };

    my $insert = sub {
	my $ref = shift;

	my $sql = "INSERT INTO dailystat " .
	    "(Time,CountIn,CountOut,BytesIn,BytesOut,VirusIn,VirusOut,SpamIn,SpamOut," .
	    "BouncesIn,BouncesOut,GreylistCount,SPFCount,RBLCount,PTimeSum,Mtime) " .
	    "VALUES ($ref->{hour}," . ($ref->{count_in} || 0) . ',' . ($ref->{count_out} || 0) . ',' .
	    ($ref->{bytes_in} || 0) . ',' . ($ref->{bytes_out} || 0) . ',' .
	    ($ref->{virus_in} || 0) . ',' . ($ref->{virus_out} || 0) . ',' .
	    ($ref->{spam_in} || 0) . ',' . ($ref->{spam_out} || 0) . ',' .
	    ($ref->{bounces_in} || 0) . ',' . ($ref->{bounces_out} || 0) . ',' .
	    ($ref->{glcount} || 0) . ',' . ($ref->{spfcount} || 0) . ',0,' . ($ref->{ptimesum} || 0) .
	    ",EXTRACT(EPOCH FROM now())::INTEGER);";

	return $sql;
    };

    return update_stats_generic ($dbh, 'dailystat_index', $select, $update, $insert);

}

sub update_stats_domainstat_in  {
    my ($dbh, $cinfo) = @_;

    my $role = $cinfo->{local}->{type} // '-';
    return 0 if !(($role eq '-') || ($role eq 'master'));

    my $sub1 = "select distinct cstatistic_cid, cstatistic_rid, " .
	"lower(substring(receiver from position ('\@' in receiver) + 1)) as domain, " .
	"((cstatistic.time + __timezone__) / 86400) * 86400 as day " .
	"from CStatistic, CReceivers where cid = cstatistic_cid AND rid = cstatistic_rid AND " .
	"id >= __startid__ and id < __endid__ AND direction " .
	"group by cstatistic_cid, cstatistic_rid, day, domain";


    my $select = "SELECT sub.*, domainstat.time IS NOT NULL as exists FROM " .
	"(SELECT day, domain, COUNT (id) as count_in, SUM (bytes) / (1024.0*1024) as bytes_in, " .
	"COUNT (CASE WHEN virusinfo IS NOT NULL THEN 1 ELSE NULL END) AS virus_in, " .
	"COUNT (CASE WHEN virusinfo IS NULL AND spamlevel >= 3 THEN 1 ELSE NULL END) as spam_in, " .
	"COUNT (CASE WHEN virusinfo IS NULL AND sender = '' THEN 1 ELSE NULL END) as bounces_in, " .
	"sum (cstatistic.ptime) / 1000.0 as ptimesum " .
	"from cstatistic, ($sub1) as ddb " .
	"WHERE ddb.cstatistic_cid = cstatistic.cid AND ddb.cstatistic_rid = cstatistic.rid GROUP BY day, domain) as sub " .
	"left join domainstat on (day = domainstat.time and sub.domain = domainstat.domain)";

    my $update = sub {
	my $ref = shift;
	my @values = ();
	my $sql = '';

	push @values, "CountIn = CountIn + $ref->{count_in}" if $ref->{count_in};
	push @values, "BytesIn = BytesIn + $ref->{bytes_in}" if $ref->{bytes_in};
	push @values, "VirusIn = VirusIn + $ref->{virus_in}" if $ref->{virus_in};
	push @values, "SpamIn = SpamIn + $ref->{spam_in}" if $ref->{spam_in};
	push @values, "BouncesIn = BouncesIn + $ref->{bounces_in}" if $ref->{bounces_in};
	push @values, "PTimeSum = PTimeSum + $ref->{ptimesum}" if $ref->{ptimesum};
	push @values, "MTime = EXTRACT(EPOCH FROM now())::INTEGER";

	if (scalar (@values)) {
	    $sql .= "UPDATE domainstat SET ";
	    $sql .= join (',', @values);
	    $sql .= " WHERE time = $ref->{day} and domain = " . $dbh->quote($ref->{domain}) . ';';
	}
	return $sql;
    };

    my $insert = sub {
	my $ref = shift;

	my $sql .= "INSERT INTO domainstat values ($ref->{day}, " .  $dbh->quote($ref->{domain}) . ',' .
		    ($ref->{count_in} || 0) . ',0,' .
		    ($ref->{bytes_in} || 0) . ',0,' .
		    ($ref->{virus_in} || 0) . ',0,' .
		    ($ref->{spam_in} || 0) . ',0,' .
		    ($ref->{bounces_in} || 0) . ',0,' .
		    ($ref->{ptimesum} || 0) .
		    ",EXTRACT(EPOCH FROM now())::INTEGER);";

	return $sql;
    };

    update_stats_generic ($dbh, 'domainstat_in_index', $select, $update, $insert);

}

sub update_stats_domainstat_out  {
    my ($dbh, $cinfo) = @_;

    my $role = $cinfo->{local}->{type} // '-';
    return 0 if !(($role eq '-') || ($role eq 'master'));

    my $select = "SELECT sub.*, domainstat.time IS NOT NULL as exists FROM " .
	"(SELECT COUNT (ID) as count_out, SUM (bytes) / (1024.0*1024) as bytes_out, " .
	"COUNT (CASE WHEN virusinfo IS NOT NULL THEN 1 ELSE NULL END) AS virus_out, " .
	"COUNT (CASE WHEN virusinfo IS NULL AND spamlevel >= 3 THEN 1 ELSE NULL END) as spam_out, " .
	"COUNT (CASE WHEN virusinfo IS NULL AND sender = '' THEN 1 ELSE NULL END) as bounces_out, " .
	"sum (cstatistic.ptime) / 1000.0 as ptimesum, " .
	"((cstatistic.time + __timezone__) / 86400) * 86400 as day, " .
	"lower(substring(sender from position ('\@' in sender) + 1)) as domain " .
	"from cstatistic where id >= __startid__ and id < __endid__ and not direction " .
	"group by day, domain) as sub " .
	"left join domainstat on (day = domainstat.time and sub.domain = domainstat.domain)";

    my $update = sub {
	my $ref = shift;
	my @values = ();
	my $sql = '';

	push @values, "CountOut = CountOut + $ref->{count_out}" if $ref->{count_out};
	push @values, "BytesOut = BytesOut + $ref->{bytes_out}" if $ref->{bytes_out};
	push @values, "VirusOut = VirusOut + $ref->{virus_out}" if $ref->{virus_out};
	push @values, "SpamOut = SpamOut + $ref->{spam_out}" if $ref->{spam_out};
	push @values, "BouncesOut = BouncesOut + $ref->{bounces_out}" if $ref->{bounces_out};
	push @values, "PTimeSum = PTimeSum + $ref->{ptimesum}" if $ref->{ptimesum};
	push @values, "MTime = EXTRACT(EPOCH FROM now())::INTEGER";

	if (scalar (@values)) {
	    $sql .= "UPDATE domainstat SET ";
	    $sql .= join (',', @values);
	    $sql .= " WHERE time = $ref->{day} and domain = " . $dbh->quote($ref->{domain}) . ';';
	}
	return $sql;
    };

    my $insert = sub {
	my $ref = shift;

	my $sql .= "INSERT INTO domainstat values ($ref->{day}, " .  $dbh->quote($ref->{domain}) .
	    ',0,' . ($ref->{count_out} || 0) .
	    ',0,' . ($ref->{bytes_out} || 0) .
	    ',0,' . ($ref->{virus_out} || 0) .
	    ',0,' . ($ref->{spam_out} || 0) .
	    ',0,' . ($ref->{bounces_out} || 0) .
	    ','. ($ref->{ptimesum} || 0) .
	    ",EXTRACT(EPOCH FROM now())::INTEGER);";

	return $sql;
    };

    update_stats_generic ($dbh, 'domainstat_out_index', $select, $update, $insert);

}

sub update_stats_virusinfo  {
    my ($dbh, $cinfo) = @_;

    my $role = $cinfo->{local}->{type} // '-';
    return 0 if !(($role eq '-') || ($role eq 'master'));

    my $select = "SELECT sub.*, virusinfo.time IS NOT NULL as exists FROM " .
	"(SELECT ((cstatistic.time + __timezone__) / 86400) * 86400 as day, " .
	"count (virusinfo) as count, virusinfo AS name " .
	"FROM cstatistic WHERE id >= __startid__ AND id < __endid__ AND virusinfo IS NOT NULL " .
	"group by day, name) as sub " .
	"left join VirusInfo on (day = virusinfo.time and sub.name = virusinfo.name)";

    my $update = sub {
	my $ref = shift;
	my @values = ();
	my $sql = '';

	push @values, "Count = Count + $ref->{count}" if $ref->{count};
	push @values, "MTime = EXTRACT(EPOCH FROM now())::INTEGER";

	if (scalar (@values)) {
	    $sql .= "UPDATE VirusInfo SET ";
	    $sql .= join (',', @values);
	    $sql .= " WHERE time = $ref->{day} and Name = " . $dbh->quote($ref->{name}) . ';';
	}
	return $sql;
    };

    my $insert = sub {
	my $ref = shift;

	my $sql .= "INSERT INTO VirusInfo values ($ref->{day}, " .  $dbh->quote($ref->{name}) .
	    ',' . ($ref->{count} || 0) .
	    ",EXTRACT(EPOCH FROM now())::INTEGER);";

	return $sql;
    };

    update_stats_generic ($dbh, 'virusinfo_index', $select, $update, $insert);

}


sub update_stats  {
    my ($dbh, $cinfo) = @_;

    while (update_stats_dailystat ($dbh, $cinfo) > 0) {};
    while (update_stats_domainstat_in ($dbh, $cinfo) > 0) {};
    while (update_stats_domainstat_out ($dbh, $cinfo) > 0) {};
    while (update_stats_virusinfo ($dbh, $cinfo) > 0) {};
}

sub total_mail_stat {
    my ($self, $rdb) = @_;

    my ($from, $to) = $self->localdayspan();

    my ($sth, $ref);
    my $glcount = 0;

#    this is to slow for high volume sites
#    $sth = $rdb->{dbh}->prepare("SELECT COUNT(DISTINCT Instance) AS GL FROM CGreylist " .
#				"WHERE passed = 0 AND rctime >= ? AND rctime < ? ");
#    $sth->execute($from, $to);
#    $ref = $sth->fetchrow_hashref();
#    $glcount = $ref->{gl};

    my $cmds = "SELECT sum(CountIn) + $glcount AS count_in, sum(CountOut) AS count_out, " .
	"sum (VirusIn) AS viruscount_in, sum (VirusOut) AS viruscount_out, " .
	"sum (SpamIn) AS spamcount_in, sum (SpamOut) AS spamcount_out, " .
	"sum (BytesIn)*1024*1024 AS bytes_in, sum (BytesOut)*1024*1024 AS bytes_out, " .
	"sum (BouncesIn) AS bounces_in, sum (BouncesOut) AS bounces_out, " .
	"sum (GreylistCount) + $glcount as glcount, " .
	"sum (SPFCount) as spfcount, " .
	"sum (RBLCount) as rbl_rejects, " .
	"sum(PTimeSum)/(sum(CountIn) + $glcount + sum(CountOut)) AS avptime " .
	"FROM DailyStat where time >= $from and time < $to";

    $sth = $rdb->{dbh}->prepare($cmds);
    $sth->execute();
    $ref = $sth->fetchrow_hashref();
    $sth->finish();

    foreach my $k (keys %$ref) { $ref->{$k} += 0; } # convert to numbers

    if (!$ref->{avptime}) {
	$ref->{count_in} = $ref->{count_out} = $ref->{viruscount_in} = $ref->{viruscount_out} =
	    $ref->{spamcount_in} = $ref->{spamcount_out} = $ref->{glcount} = $ref->{spfcount} =
	    $ref->{rbl_rejects} = $ref->{bounces_in} = $ref->{bounces_out} = $ref->{bytes_in} =
	    $ref->{bytes_out} = $ref->{avptime} = 0;
    }

    $ref->{count} = $ref->{count_in} + $ref->{count_out};

    $ref->{junk_in} = $ref->{viruscount_in} + $ref->{spamcount_in} + $ref->{glcount} +
	$ref->{spfcount} + $ref->{rbl_rejects};

    $ref->{junk_out} = $ref->{viruscount_out} + $ref->{spamcount_out};

    return $ref;
}

sub total_spam_stat {
    my ($self, $rdb) = @_;
    my ($from, $to) = $self->timespan();

    my $sth = $rdb->{dbh}->prepare(
        "SELECT spamlevel, COUNT(spamlevel) AS count FROM CStatistic"
        ." WHERE virusinfo IS NULL and time >= ? AND time < ? AND ptime > 0 AND spamlevel > 0 "
        ." GROUP BY spamlevel ORDER BY spamlevel"
    );
    $sth->execute($from, $to);

    my $res = $sth->fetchall_arrayref({});

    $sth->finish();

    return $res;
}

sub total_virus_stat {
    my ($self, $rdb, $order) = @_;

    my ($from, $to) = $self->localdayspan();

    $order = "count" if !$order;

    my @oa = split (',', $order);

    $order = join (' DESC, ', @oa);
    $order .= ' DESC';

    my $sth = $rdb->{dbh}->prepare(
	"SELECT Name, SUM (Count) as count FROM VirusInfo WHERE time >= ? AND time < ? "
	." GROUP BY name ORDER BY $order, name"
    );

    $sth->execute($from, $to);

    my $res = $sth->fetchall_arrayref({});

    $sth->finish();

    return $res;
}

sub rule_count {
    my ($self, $rdb) = @_;

    my $sth = $rdb->{dbh}->prepare("SELECT id, name, count from rule order by count desc, name");
    $sth->execute();

    my $res = $sth->fetchall_arrayref({});
    $sth->finish();

    return $res;
}

sub total_domain_stat {
    my ($self, $rdb) = @_;

    my ($from, $to) = $self->localdayspan();

    my $query = "SELECT domain, SUM (CountIn) AS count_in, SUM (CountOut) AS count_out," .
	"SUM (BytesIn)*1024*1024 AS bytes_in, SUM (BytesOut)*1024*1024 AS bytes_out, " .
	"SUM (VirusIn) AS viruscount_in, SUM (VirusOut) AS viruscount_out," .
	"SUM (SpamIn) as spamcount_in, SUM (SpamOut) as spamcount_out " .
	"FROM DomainStat where time >= $from AND time < $to " .
	"GROUP BY domain ORDER BY domain ASC";

    my $sth = $rdb->{dbh}->prepare($query);
    $sth->execute();

    my $res = $sth->fetchall_arrayref({});

    $sth->finish();

    return $res;
}

sub clear_rule_count {
    my ($self, $rdb, $id) = @_;

    if (defined($id)) {
	$rdb->{dbh}->do ("UPDATE rule set count = 0 where id = ?", undef, $id);
    } else {
	$rdb->{dbh}->do("UPDATE rule set count = 0");
    }
}

sub query_cond_good_mail {
    my ($self, $from, $to) = @_;
    return "time >= $from AND time < $to AND bytes > 0 AND sender IS NOT NULL";
}

sub query_active_workers {
    my ($self) = @_;
    my ($from, $to) = $self->timespan();

    my $start = $from - (3600*24)*90; # from - 90 days
    my $cond_good_mail = $self->query_cond_good_mail ($start, $to);

    return "SELECT DISTINCT sender as worker FROM CStatistic WHERE $cond_good_mail AND NOT direction";
}

my $compute_sql_orderby = sub {
    my ($sorters, $sort_default, $sort_always_prop) = @_;

    my $has_default_sort;

    my $orderby = '';

    foreach my $obj (@$sorters) {
	$has_default_sort = 1 if $obj->{property} eq $sort_always_prop;
	$orderby .= ', ' if $orderby;
	$orderby .= "$obj->{property} $obj->{direction}"
    }

    $orderby .= $sort_default if !$orderby;

    $orderby .= ", $sort_always_prop" if !$has_default_sort;

    return $orderby;
};

sub user_stat_to_perlstring {
    my ($entry) = @_;

    my $res = { };

    for my $a (keys %$entry) {
	if ($a eq 'receiver' || $a eq 'sender' || $a eq 'contact') {
	    $res->{$a} = PMG::Utils::try_decode_utf8($entry->{$a});
	} else {
	    $res->{$a} = $entry->{$a};
	}
    }

    return $res;
}

my sub get_filter_text {
    my ($dbh, $field, $filter) = @_;

    if (!$filter || !$field) {
	return '';
    }

    my $pattern = $dbh->quote(encode('UTF-8', "%${filter}%"));

    return "AND ${field} like ${pattern} ";
}

sub user_stat_contact_details {
    my ($self, $rdb, $receiver, $limit, $sorters, $filter) = @_;

    my ($from, $to) = $self->timespan();

    my $orderby = $compute_sql_orderby->($sorters, 'time ASC', 'sender');

    my $cond_good_mail = $self->query_cond_good_mail ($from, $to);

    my $filter_text = get_filter_text($rdb->{dbh}, 'sender', $filter);

    my $query = "SELECT * FROM CStatistic, CReceivers " .
	"WHERE cid = cstatistic_cid AND rid = cstatistic_rid AND $cond_good_mail " .
	"AND NOT direction AND sender != '' AND receiver = ? " .
	$filter_text .
	"ORDER BY $orderby limit $limit";

    my $sth = $rdb->{dbh}->prepare($query);

    $sth->execute(encode('UTF-8',$receiver));

    my $res = [];
    while (my $ref = $sth->fetchrow_hashref()) {
	push @$res, user_stat_to_perlstring($ref);
    }

    $sth->finish();

    return $res;
}

sub user_stat_contact {
    my ($self, $rdb, $limit, $sorters, $filter, $advfilter) = @_;

    my ($from, $to) = $self->timespan();

    my $orderby = $compute_sql_orderby->($sorters, 'count DESC', 'contact');

    my $cond_good_mail = $self->query_cond_good_mail($from, $to);

    my $filter_text = get_filter_text($rdb->{dbh}, 'receiver', $filter);

    my $query = "SELECT receiver as contact, count(*) AS count, sum (bytes) AS bytes, " .
	"count (virusinfo) as viruscount " .
	"FROM CStatistic, CReceivers " .
	"WHERE cid = cstatistic_cid AND rid = cstatistic_rid " .
	$filter_text .
	"AND $cond_good_mail AND NOT direction AND sender != '' ";

    if ($advfilter) {
	my $active_workers = $self->query_active_workers ();

	$query .= "AND receiver NOT IN ($active_workers) ";
    }

    $query .="GROUP BY contact ORDER BY $orderby limit $limit";
    my $sth = $rdb->{dbh}->prepare($query);

    $sth->execute();

    my $res = [];
    while (my $ref = $sth->fetchrow_hashref()) {
	push @$res, user_stat_to_perlstring($ref);
    }

    $sth->finish();

    return $res;
}

sub user_stat_sender_details {
    my ($self, $rdb, $sender, $limit, $sorters, $filter) = @_;

    my ($from, $to) = $self->timespan();

    my $orderby = $compute_sql_orderby->($sorters, 'time ASC', 'receiver');

    my $cond_good_mail = $self->query_cond_good_mail($from, $to);

    my $filter_text = get_filter_text($rdb->{dbh}, 'receiver', $filter);

    my $sth = $rdb->{dbh}->prepare(
	"SELECT " .
	"blocked, bytes, ptime, sender, receiver, spamlevel, time, virusinfo " .
	"FROM CStatistic, CReceivers " .
	"WHERE cid = cstatistic_cid AND rid = cstatistic_rid AND " .
	"$cond_good_mail AND NOT direction AND sender = ? " .
	$filter_text .
	"ORDER BY $orderby limit $limit");

    $sth->execute(encode('UTF-8',$sender));

    my $res = [];
    while (my $ref = $sth->fetchrow_hashref()) {
	push @$res, user_stat_to_perlstring($ref);
    }

    $sth->finish();

    return $res;
}

sub user_stat_sender {
    my ($self, $rdb, $limit, $sorters, $filter) = @_;

    my ($from, $to) = $self->timespan();

    my $orderby = $compute_sql_orderby->($sorters, 'count DESC', 'sender');

    my $cond_good_mail = $self->query_cond_good_mail ($from, $to);

    my $filter_text = get_filter_text($rdb->{dbh}, 'sender', $filter);

    my $query = "SELECT sender,count(*) AS count, sum (bytes) AS bytes, " .
	"count (virusinfo) as viruscount, " .
	"count (CASE WHEN spamlevel >= 3 THEN 1 ELSE NULL END) as spamcount " .
	"FROM CStatistic WHERE $cond_good_mail AND NOT direction AND sender != '' " .
	$filter_text .
	"GROUP BY sender ORDER BY $orderby limit $limit";

    my $sth = $rdb->{dbh}->prepare($query);
    $sth->execute();

    my $res = [];
    while (my $ref = $sth->fetchrow_hashref()) {
	push @$res, user_stat_to_perlstring($ref);
    }

    $sth->finish();

    return $res;
}

sub user_stat_receiver_details {
    my ($self, $rdb, $receiver, $limit, $sorters, $filter) = @_;

    my ($from, $to) = $self->timespan();

    my $orderby = $compute_sql_orderby->($sorters, 'time ASC', 'sender');

    my $cond_good_mail = $self->query_cond_good_mail($from, $to);

    my $filter_text = get_filter_text($rdb->{dbh}, 'sender', $filter);

    my $sth = $rdb->{dbh}->prepare(
	"SELECT blocked, bytes, ptime, sender, receiver, spamlevel, time, virusinfo " .
	"FROM CStatistic, CReceivers " .
	"WHERE cid = cstatistic_cid AND rid = cstatistic_rid AND $cond_good_mail AND receiver = ? " .
	$filter_text .
	"ORDER BY $orderby limit $limit");

    $sth->execute(encode('UTF-8',$receiver));

    my $res = [];
    while (my $ref = $sth->fetchrow_hashref()) {
	push @$res, user_stat_to_perlstring($ref);
    }

    $sth->finish();

    return $res;
}

sub user_stat_receiver {
    my ($self, $rdb, $limit, $sorters, $filter, $advfilter) = @_;

    my ($from, $to) = $self->timespan();

    my $orderby = $compute_sql_orderby->($sorters, 'count DESC', 'receiver');

    my $cond_good_mail = $self->query_cond_good_mail ($from, $to) . " AND " .
	"receiver IS NOT NULL AND receiver != ''";

    my $filter_text = get_filter_text($rdb->{dbh}, 'receiver', $filter);

    my $query = "SELECT receiver, " .
	"count(*) AS count, " .
	"sum (bytes) AS bytes, " .
	"count (virusinfo) as viruscount, " .
	"count (CASE WHEN spamlevel >= 3 THEN 1 ELSE NULL END) as spamcount ";

    if ($advfilter) {
	my $active_workers = $self->query_active_workers ();

	$query .= "FROM CStatistic, CReceivers, ($active_workers) as workers ";

	$query .= "WHERE cid = cstatistic_cid AND rid = cstatistic_rid AND worker=receiver ";

    } else {
	$query .= "FROM CStatistic, CReceivers ";

	$query .= "WHERE cid = cstatistic_cid AND rid = cstatistic_rid ";
    }

    $query .= "AND $cond_good_mail and direction " .
	$filter_text .
	"GROUP BY receiver ORDER BY $orderby LIMIT $limit";

    my $sth = $rdb->{dbh}->prepare($query);
    $sth->execute();

    my $res = [];
    while (my $ref = $sth->fetchrow_hashref()) {
	push @$res, user_stat_to_perlstring($ref);
    }

    $sth->finish();

    return $res;
}

sub postscreen_stat {
    my ($self, $rdb) = @_;

    my ($from, $to) = $self->localhourspan();
    my $timezone = tz_local_offset();;

    my $cmd = "SELECT " .
	"sum(rblcount) as rbl_rejects, " .
	"sum(PregreetCount) as pregreet_rejects " .
	"FROM LocalStat WHERE time >= $from AND time < $to";

    my $sth = $rdb->{dbh}->prepare($cmd);
    $sth->execute();
    my $res = $sth->fetchrow_hashref();
    $sth->finish();

    return $res;
}

sub postscreen_stat_graph {
    my ($self, $rdb, $span) = @_;
    my $res;

    my ($from, $to) = $self->localhourspan();
    my $timezone = tz_local_offset();;

    my $cmd = "SELECT " .
	"(time - $from) / $span AS index, " .
	"sum(rblcount) as rbl_rejects, " .
	"sum(PregreetCount) as pregreet_rejects " .
	"FROM LocalStat WHERE time >= $from AND time < $to " .
	"GROUP BY index ORDER BY index";

    my $sth = $rdb->{dbh}->prepare($cmd);
    $sth->execute ();

    my $max_entry = int(($to - $from) / $span);
    while (my $ref = $sth->fetchrow_hashref()) {
	my $i = $ref->{index};
	$res->[$i] = $ref;
	$max_entry = $i if $i > $max_entry;
    }

    for my $i (0..$max_entry) {
	$res->[$i] //= { index => $i, rbl_rejects => 0, pregreet_rejects => 0};

	my $d = $res->[$i];
	$d->{time} = $from + $i*$span - $timezone;
    }
    $sth->finish();

    return $res;
}

sub recent_mailcount {
    my ($self, $rdb, $span) = @_;
    my $res;

    my ($from, $to) = $self->timespan();

    my $cmd = "SELECT".
	"(time - $from) / $span AS index, ".
	"COUNT (CASE WHEN direction THEN 1 ELSE NULL END) as count_in, ".
	"COUNT (CASE WHEN NOT direction THEN 1 ELSE NULL END) as count_out, ".
	"SUM (CASE WHEN direction THEN bytes ELSE 0 END) as bytes_in, ".
	"SUM (CASE WHEN NOT direction THEN bytes ELSE 0 END) as bytes_out, ".
	"SUM (ptime) / 1000.0 as ptimesum, ".
	"COUNT (CASE WHEN virusinfo IS NOT NULL AND direction THEN 1 ELSE NULL END) as virus_in, ".
	"COUNT (CASE WHEN virusinfo IS NOT NULL AND NOT direction THEN 1 ELSE NULL END) as virus_out, ".
	"COUNT (CASE WHEN virusinfo IS NULL AND direction AND spamlevel >= 3 THEN 1 ELSE NULL END) as spam_in, ".
	"COUNT (CASE WHEN virusinfo IS NULL AND NOT direction AND spamlevel >= 3 THEN 1 ELSE NULL END) as spam_out ".
	"FROM cstatistic ".
	"WHERE time >= $from AND time < $to ".
	"GROUP BY index ORDER BY index";

    my $sth =  $rdb->{dbh}->prepare($cmd);

    $sth->execute ();

    while (my $ref = $sth->fetchrow_hashref()) {
	@$res[$ref->{index}] = $ref;
    }

    $sth->finish();

    my $c = int(($to - $from) / $span);

    for (my $i = 0; $i < $c; $i++) {
	@$res[$i] //= {
	    index => $i,
	    count => 0, count_in => 0, count_out => 0,
	    spam => 0, spam_in => 0, spam_out => 0,
	    virus => 0, virus_in => 0, virus_out => 0,
	    bytes => 0, bytes_in => 0, bytes_out => 0,
	    };

	my $d = @$res[$i];

	$d->{time} = $from + $i*$span;
	$d->{count} = $d->{count_in} + $d->{count_out};
	$d->{spam} = $d->{spam_in} + $d->{spam_out};
	$d->{virus} = $d->{virus_in} + $d->{virus_out};
	$d->{bytes} = $d->{bytes_in} + $d->{bytes_out};
	$d->{timespan} = $span+0;
	$d->{ptimesum} += 0;
    }

    return $res;
}

sub recent_receivers {
    my ($self, $rdb, $limit) = @_;
    my $res = [];

    my ($from, $to) = $self->timespan();

    my $cmd = "SELECT ".
	"COUNT(receiver) as count, receiver ".
	"FROM CStatistic, CReceivers ".
	"WHERE time >= ? ".
	"AND cid = cstatistic_cid ".
	"AND rid = cstatistic_rid ".
	"AND blocked = false ".
	"AND direction = true ".
	"GROUP BY receiver ORDER BY count DESC LIMIT ?;";

    my $sth =  $rdb->{dbh}->prepare($cmd);

    $sth->execute ($from, $limit);
    while (my $ref = $sth->fetchrow_hashref()) {
	push @$res, user_stat_to_perlstring($ref);
    }
    $sth->finish();

    return $res;
}

sub traffic_stat_graph {
    my ($self, $rdb, $span) = @_;
    my $res;

    my ($from, $to) = $self->localhourspan();
    my $timezone = tz_local_offset();;

    my $cmd = "SELECT " .
	"(time - $from) / $span AS index, " .
	"sum(CountIn) as count_in, sum(CountOut) as count_out, " .
	"sum(VirusIn) as viruscount_in, sum (VirusOut) as viruscount_out, " .
	"sum(SpamIn) + sum (GreylistCount) + sum (SPFCount) + sum (RBLCount) as spamcount_in, " .
	"sum(SpamOut) as spamcount_out, " .
	"sum(BouncesIn) as bounces_in, " .
	"sum(BouncesOut) as bounces_out " .
	"FROM DailyStat WHERE time >= $from AND time < $to " .
	"GROUP BY index ORDER BY index";

    my $sth =  $rdb->{dbh}->prepare($cmd);
    $sth->execute ();

    my $max_entry = int(($to - $from) / $span);
    while (my $ref = $sth->fetchrow_hashref()) {
	my $i = $ref->{index};
	$res->[$i] = $ref;
	$max_entry = $i if $i > $max_entry;
    }

    for my $i (0..$max_entry) {
	$res->[$i] //= {
	    index => $i,
	    count => 0, count_in => 0, count_out => 0,
	    spamcount_in => 0, spamcount_out => 0,
	    viruscount_in => 0, viruscount_out => 0,
	    bounces_in => 0, bounces_out => 0 };

	my $d = $res->[$i];

	$d->{time} = $from + $i*$span - $timezone;
	$d->{count} = $d->{count_in} + $d->{count_out};
    }
    $sth->finish();

    return $res;
}

sub traffic_stat_day_dist {
    my ($self, $rdb) = @_;
    my $res;

    my ($from, $to) = $self->localhourspan();

    my $cmd = "SELECT " .
	"((time - $from) / 3600) % 24 AS index, " .
	"sum(CountIn) as count_in, sum(CountOut) as count_out, " .
	"sum(VirusIn) as viruscount_in, sum (VirusOut) as viruscount_out, " .
	"sum(SpamIn) + sum (GreylistCount) + sum (SPFCount) + sum (RBLCount) as spamcount_in, " .
	"sum(SpamOut) as spamcount_out, " .
	"sum(BouncesIn) as bounces_in, sum(BouncesOut) as bounces_out " .
	"FROM DailyStat WHERE time >= $from AND time < $to " .
	"GROUP BY index ORDER BY index";

    my $sth =  $rdb->{dbh}->prepare($cmd);

    $sth->execute ();

    while (my $ref = $sth->fetchrow_hashref()) {
	@$res[$ref->{index}] = $ref;
    }

    for (my $i = 0; $i < 24; $i++) {
	@$res[$i] //= {
	    index => $i,
	    count => 0, count_in => 0, count_out => 0,
	    spamcount_in => 0, spamcount_out => 0,
	    viruscount_in => 0, viruscount_out => 0,
	    bounces_in => 0, bounces_out => 0 };

	my $d = @$res[$i];
	$d->{count} = $d->{count_in} + $d->{count_out};
    }
    $sth->finish();

    return $res;
}

sub timespan {
    my ($self, $from, $to) = @_;

    if (defined ($from) && defined ($to)) {
	$self->{from} = $from;
	$self->{to} = $to;
    }

    return ($self->{from}, $self->{to});
}

sub localdayspan {
    my ($self) = @_;

    my ($from, $to) = $self->timespan();

    my $timezone = tz_local_offset();;
    $from = int(($from + $timezone)/86400) * 86400;
    $to = int(($to + $timezone)/86400) * 86400;

    $to += 86400 if $from == $to;

    return ($from, $to);
}

sub localhourspan {
    my ($self) = @_;

    my ($from, $to) = $self->timespan();

    my $timezone = tz_local_offset();;
    $from = int(($from + $timezone)/3600) * 3600;
    $to = int(($to + $timezone)/3600) * 3600;

    $to += 3600 if $from == $to;

    return ($from, $to);
}


1;
