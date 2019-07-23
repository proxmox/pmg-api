package PMG::Backup;

use strict;
use warnings;
use Data::Dumper;
use File::Basename;
use File::Path;

use PVE::Tools;

use PMG::pmgcfg;
use PMG::AtomicFile;

my $sa_custom_config_fn = "/etc/mail/spamassassin/custom.cf";

sub dump_table {
    my ($dbh, $table, $ofh, $seq, $seqcol) = @_;

    my $sth = $dbh->column_info(undef, undef, $table, undef);

    my $attrs = $sth->fetchall_arrayref({});

    my @col_arr;
    foreach my $ref (@$attrs) {
	push @col_arr, $ref->{COLUMN_NAME};
    }

    $sth->finish();

    my $cols = join (', ', @col_arr);
    $cols || die "unable to fetch column definitions: ERROR";

    print $ofh "COPY $table ($cols) FROM stdin;\n";

    my $cmd = "COPY $table ($cols) TO STDOUT";
    $dbh->do($cmd);

    my $data = '';
    while ($dbh->pg_getcopydata($data) >= 0) {
	print $ofh $data;
    }

    print $ofh "\\.\n\n";

    if ($seq && $seqcol) {
	print $ofh "SELECT setval('$seq', max($seqcol)) FROM $table;\n\n";
    }
}

sub dumpdb {
    my ($ofh) = @_;

    print $ofh "SET client_encoding = 'SQL_ASCII';\n";
    print $ofh "SET check_function_bodies = false;\n\n";

    my $dbh = PMG::DBTools::open_ruledb();

    print $ofh "BEGIN TRANSACTION;\n\n";

    eval {
	$dbh->begin_work;

	# read a consistent snapshot
	$dbh->do("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");

	dump_table($dbh, 'attribut', $ofh);
	dump_table($dbh, 'object', $ofh, 'object_id_seq', 'id');
	dump_table($dbh, 'objectgroup', $ofh, 'objectgroup_id_seq', 'id');
	dump_table($dbh, 'rule', $ofh, 'rule_id_seq', 'id');
	dump_table($dbh, 'rulegroup', $ofh);
	dump_table($dbh, 'userprefs', $ofh);

	# we do not save the following tables: cgreylist, cmailstore, cmsreceivers, clusterinfo
    };
    my $err = $@;

    $dbh->rollback(); # end read-only transaction

    $dbh->disconnect();

    die $err if $err;

    print $ofh "COMMIT TRANSACTION;\n\n";
}

sub dumpstatdb {
    my ($ofh) = @_;

    print $ofh "SET client_encoding = 'SQL_ASCII';\n";
    print $ofh "SET check_function_bodies = false;\n\n";

    my $dbh = PMG::DBTools::open_ruledb();

    eval {
	$dbh->begin_work;

	# read a consistent snapshot
	$dbh->do("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");

	print $ofh "BEGIN TRANSACTION;\n\n";

	dump_table($dbh, 'dailystat', $ofh);
	dump_table($dbh, 'domainstat', $ofh);
	dump_table($dbh, 'virusinfo', $ofh);
	dump_table($dbh, 'localstat', $ofh);

	# drop/create the index is a little bit faster (20%)

	print $ofh "DROP INDEX cstatistic_time_index;\n\n";
	print $ofh "ALTER TABLE cstatistic DROP CONSTRAINT cstatistic_id_key;\n\n";
	print $ofh "ALTER TABLE cstatistic DROP CONSTRAINT cstatistic_pkey;\n\n";
	dump_table($dbh, 'cstatistic', $ofh, 'cstatistic_id_seq', 'id');
	print $ofh "ALTER TABLE ONLY cstatistic ADD CONSTRAINT cstatistic_pkey PRIMARY KEY (cid, rid);\n\n";
	print $ofh "ALTER TABLE ONLY cstatistic ADD CONSTRAINT cstatistic_id_key UNIQUE (id);\n\n";
	print $ofh "CREATE INDEX CStatistic_Time_Index ON CStatistic (Time);\n\n";

	print $ofh "DROP INDEX CStatistic_ID_Index;\n\n";
	dump_table($dbh, 'creceivers', $ofh);
	print $ofh "CREATE INDEX CStatistic_ID_Index ON CReceivers (CStatistic_CID, CStatistic_RID);\n\n";

	dump_table($dbh, 'statinfo', $ofh);

	print $ofh "COMMIT TRANSACTION;\n\n";
    };
    my $err = $@;

    $dbh->rollback(); # end read-only transaction

    $dbh->disconnect();

    die $err if $err;
}

sub pmg_backup {
    my ($filename, $include_statistics) = @_;

    my $time = time;
    my $dirname = "/tmp/proxbackup_$$.$time";
    my $dbfn = "Proxmox_ruledb.sql";
    my $statfn = "Proxmox_statdb.sql";
    my $tarfn = "config_backup.tar";
    my $sigfn = "proxmox_backup_v1.md5";
    my $verfn = "version.txt";

    eval {

	my $targetdir = dirname($filename);
	mkdir $targetdir; # try to create target dir
	-d $targetdir ||
	    die "unable to access target directory '$targetdir'\n";

	# create a temporary directory
	mkdir $dirname;

	# dump the database first
	my $fh = PMG::AtomicFile->open("$dirname/$dbfn", "w") ||
	    die "cant open '$dirname/$dbfn' - $! :ERROR";

	dumpdb($fh);

	$fh->close(1);

	if ($include_statistics) {
	    # dump the statistic db
	    my $sfh = PMG::AtomicFile->open("$dirname/$statfn", "w") ||
		die "cant open '$dirname/$statfn' - $! :ERROR";

	    dumpstatdb($sfh);

	    $sfh->close(1);
	}

	my $pkg = PMG::pmgcfg::package();
	my $ver = PMG::pmgcfg::version();

	my $vfh = PMG::AtomicFile->open ("$dirname/$verfn", "w") ||
	    die "cant open '$dirname/$verfn' - $! :ERROR";

	$time = time;
	my $now = localtime;
	print $vfh "product: $pkg\nversion: $ver\nbackuptime:$time:$now\n";
	$vfh->close(1);

	my $extra_cfgs =  [];

	push @$extra_cfgs, $sa_custom_config_fn;

	#push @$extra_cfgs, '/etc/postfix/tls_policy';

	my $extradb = $include_statistics ? $statfn : '';

	my $extra = join(' ', @$extra_cfgs);

	system("/bin/tar cf $dirname/$tarfn -C / " .
	       "/etc/pmg $extra>/dev/null 2>&1") == 0 ||
	       die "unable to create system configuration backup: ERROR";

	system("cd $dirname; md5sum $tarfn $dbfn $extradb $verfn> $sigfn") == 0 ||
	    die "unable to create backup signature: ERROR";

	system("rm -f $filename; tar czf $filename -C $dirname $verfn $sigfn $dbfn $extradb $tarfn") == 0 ||
	    die "unable to create backup archive: ERROR";
    };
    my $err = $@;

    rmtree $dirname;

    if ($err) {
	unlink $filename;
	die $err;
    }
}

sub pmg_restore {
    my ($filename, $restore_database, $restore_config, $restore_statistics) = @_;

    my $dbname = 'Proxmox_ruledb';

    my $time = time;
    my $dirname = "/tmp/proxrestore_$$.$time";
    my $dbfn = "Proxmox_ruledb.sql";
    my $statfn = "Proxmox_statdb.sql";
    my $tarfn = "config_backup.tar";
    my $sigfn = "proxmox_backup_v1.md5";

    eval {
	# create a temporary directory
	mkdir $dirname;

	system("cd $dirname; tar xzf $filename >/dev/null 2>&1") == 0 ||
	    die "unable to extract backup archive: ERROR";

	system("cd $dirname; md5sum -c $sigfn") == 0 ||
	    die "proxmox backup signature check failed: ERROR";

	if ($restore_config) {
	    # restore the tar file
	    mkdir "$dirname/config/";
	    system("tar xpf $dirname/$tarfn -C $dirname/config/") == 0 ||
		die "unable to restore configuration tar archive: ERROR";

	    -d "$dirname/config/etc/pmg" ||
		die "backup does not contain a valid system configuration directory (/etc/pmg)\n";
	    # unlink unneeded files
	    unlink "$dirname/config/etc/pmg/cluster.conf"; # never restore cluster config
	    rmtree "$dirname/config/etc/pmg/master";

	    # remove current config, but keep directory for INotify
	    rmtree("/etc/pmg", { keep_root => 1 });
	    # copy files
	    system("cp -a $dirname/config/etc/pmg/* /etc/pmg/") == 0 ||
		die "unable to restore system configuration: ERROR";

	    if (-f "$dirname/config/${sa_custom_config_fn}") {
		my $data = PVE::Tools::file_get_contents(
		    "$dirname/config/${sa_custom_config_fn}", 1024*1024);
		PVE::Tools::file_set_contents($sa_custom_config_fn, $data);
	    }

	    my $cfg = PMG::Config->new();
	    my $ruledb = PMG::RuleDB->new();
	    my $rulecache = PMG::RuleCache->new($ruledb);
	    $cfg->rewrite_config($rulecache, 1);
	}

	if ($restore_database) {
	    # recreate the database

	    # stop all services accessing the database
	    PMG::Utils::service_wait_stopped(40, $PMG::Utils::db_service_list);

	    print "Destroy existing rule database\n";
	    PMG::DBTools::delete_ruledb($dbname);

	    print "Create new database\n";
	    my $dbh = PMG::DBTools::create_ruledb($dbname);

	    system("cat $dirname/$dbfn|psql $dbname >/dev/null 2>&1") == 0 ||
		die "unable to restore rule database: ERROR";

	    if ($restore_statistics) {
		if (-f "$dirname/$statfn") {
		    system("cat $dirname/$statfn|psql $dbname >/dev/null 2>&1") == 0 ||
			die "unable to restore statistic database: ERROR";
		}
	    }

	    print STDERR "run analyze to speed up database queries\n";
	    PMG::DBTools::postgres_admin_cmd('psql', { input => 'analyze;' }, $dbname);

	    print "Analyzing/Upgrading existing Databases...";
	    my $ruledb = PMG::RuleDB->new($dbh);
	    PMG::DBTools::upgradedb($ruledb);
	    print "done\n";

	    # cleanup old spam/virus storage
	    PMG::MailQueue::create_spooldirs(0, 1);

	    my $cfg = PMG::Config->new();
	    my $rulecache = PMG::RuleCache->new($ruledb);
	    $cfg->rewrite_config($rulecache, 1);

	    # and restart services as soon as possible
	    foreach my $service (reverse @$PMG::Utils::db_service_list) {
		eval { PVE::Tools::run_command(['systemctl', 'start', $service]); };
		warn $@ if $@;
	    }
	}
    };
    my $err = $@;

    rmtree $dirname;

    die $err if $err;
}

1;
