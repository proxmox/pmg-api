package PMG::DBTools;

use strict;
use warnings;

use POSIX ":sys_wait_h";
use POSIX qw(:signal_h getuid);
use DBI;
use Time::Local;

use PVE::SafeSyslog;
use PVE::Tools;

use PMG::Utils;
use PMG::RuleDB;
use PMG::MailQueue;
use PMG::Config;

our $default_db_name = "Proxmox_ruledb";

our $cgreylist_merge_sql =
    'INSERT INTO CGREYLIST (IPNet,Host,Sender,Receiver,Instance,RCTime,' .
    'ExTime,Delay,Blocked,Passed,MTime,CID) ' .
    'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' .
    'ON CONFLICT (IPNet,Sender,Receiver) DO UPDATE SET ' .
    'Host = CASE WHEN CGREYLIST.MTime >= excluded.MTime THEN CGREYLIST.Host ELSE excluded.Host END,' .
    'CID = GREATEST(CGREYLIST.CID, excluded.CID), RCTime = LEAST(CGREYLIST.RCTime, excluded.RCTime),' .
    'ExTime = GREATEST(CGREYLIST.ExTime, excluded.ExTime),' .
    'Delay = GREATEST(CGREYLIST.Delay, excluded.Delay),' .
    'Blocked = GREATEST(CGREYLIST.Blocked, excluded.Blocked),' .
    'Passed = GREATEST(CGREYLIST.Passed, excluded.Passed)';

sub open_ruledb {
    my ($database, $host, $port) = @_;

    $port //= 5432;

    $database //= $default_db_name;

    if ($host) {

	# Note: pmgtunnel uses UDP sockets inside directory '/var/run/pmgtunnel',
	# and the cluster 'cid' as port number. You can connect to the
	# socket with: host => /var/run/pmgtunnel, port => $cid

	my $dsn = "dbi:Pg:dbname=$database;host=$host;port=$port;";

	my $timeout = 5;
	# only low level alarm interface works for DBI->connect
	my $mask = POSIX::SigSet->new(SIGALRM);
	my $action = POSIX::SigAction->new(sub { die "connect timeout\n" }, $mask);
	my $oldaction = POSIX::SigAction->new();
	sigaction(SIGALRM, $action, $oldaction);

	my $rdb;

	eval {
	    alarm($timeout);
	    $rdb = DBI->connect($dsn, 'root', undef,
				{ PrintError => 0, RaiseError => 1 });
	    alarm(0);
	};
	alarm(0);
	sigaction(SIGALRM, $oldaction);  # restore original handler

	die $@ if $@;

	return $rdb;
    } else {
	my $dsn = "DBI:Pg:dbname=$database;host=/var/run/postgresql;port=$port";

	my $dbh = DBI->connect($dsn, $> == 0 ? 'root' : 'www-data', undef,
			       { PrintError => 0, RaiseError => 1 });

	return $dbh;
    }
}

sub postgres_admin_cmd {
    my ($cmd, $options, @params) = @_;

    $cmd = ref($cmd) ? $cmd : [ $cmd ];

    my $save_uid = POSIX::getuid();
    my $pg_uid = getpwnam('postgres') || die "getpwnam postgres failed\n";

    PVE::Tools::setresuid(-1, $pg_uid, -1) ||
	die "setresuid postgres ($pg_uid) failed - $!\n";

    PVE::Tools::run_command([@$cmd, '-U', 'postgres', @params], %$options);

    PVE::Tools::setresuid(-1, $save_uid, -1) ||
	die "setresuid back failed - $!\n";
}

sub delete_ruledb {
    my ($dbname) = @_;

    postgres_admin_cmd('dropdb', undef, $dbname);
}

sub database_list {

    my $database_list = {};

    my $parser = sub {
	my $line = shift;

	my ($name, $owner) = map { PVE::Tools::trim($_) } split(/\|/, $line);
	return if !$name || !$owner;

	$database_list->{$name} = { owner => $owner };
    };

    postgres_admin_cmd('psql', { outfunc => $parser }, '--list', '--quiet', '--tuples-only');

    return $database_list;
}

my $cgreylist_ctablecmd =  <<__EOD;
    CREATE TABLE CGreylist
    (IPNet VARCHAR(16) NOT NULL,
     Host INTEGER NOT NULL,
     Sender VARCHAR(255) NOT NULL,
     Receiver VARCHAR(255) NOT NULL,
     Instance VARCHAR(255),
     RCTime INTEGER NOT NULL,
     ExTime INTEGER NOT NULL,
     Delay INTEGER NOT NULL DEFAULT 0,
     Blocked INTEGER NOT NULL,
     Passed INTEGER NOT NULL,
     CID INTEGER NOT NULL,
     MTime INTEGER NOT NULL,
     PRIMARY KEY (IPNet, Sender, Receiver));

    CREATE INDEX CGreylist_Instance_Sender_Index ON CGreylist (Instance, Sender);

    CREATE INDEX CGreylist_ExTime_Index ON CGreylist (ExTime);

    CREATE INDEX CGreylist_MTime_Index ON CGreylist (MTime);
__EOD

my $clusterinfo_ctablecmd =  <<__EOD;
    CREATE TABLE ClusterInfo
    (CID INTEGER NOT NULL,
     Name VARCHAR NOT NULL,
     IValue INTEGER,
     SValue VARCHAR,
     PRIMARY KEY (CID, Name))
__EOD

my $local_stat_ctablecmd =  <<__EOD;
    CREATE TABLE LocalStat
    (Time INTEGER NOT NULL,
     RBLCount INTEGER DEFAULT 0 NOT NULL,
     PregreetCount INTEGER DEFAULT 0 NOT NULL,
     CID INTEGER NOT NULL,
     MTime INTEGER NOT NULL,
     PRIMARY KEY (Time, CID));

    CREATE INDEX LocalStat_MTime_Index ON LocalStat (MTime);
__EOD


my $daily_stat_ctablecmd =  <<__EOD;
    CREATE TABLE DailyStat
    (Time INTEGER NOT NULL UNIQUE,
     CountIn INTEGER NOT NULL,
     CountOut INTEGER NOT NULL,
     BytesIn REAL NOT NULL,
     BytesOut REAL NOT NULL,
     VirusIn INTEGER NOT NULL,
     VirusOut INTEGER NOT NULL,
     SpamIn INTEGER NOT NULL,
     SpamOut INTEGER NOT NULL,
     BouncesIn INTEGER NOT NULL,
     BouncesOut INTEGER NOT NULL,
     GreylistCount INTEGER NOT NULL,
     SPFCount INTEGER NOT NULL,
     PTimeSum REAL NOT NULL,
     MTime INTEGER NOT NULL,
     RBLCount INTEGER DEFAULT 0 NOT NULL,
     PRIMARY KEY (Time));

    CREATE INDEX DailyStat_MTime_Index ON DailyStat (MTime);

__EOD

my $domain_stat_ctablecmd =  <<__EOD;
    CREATE TABLE DomainStat
    (Time INTEGER NOT NULL,
     Domain VARCHAR(255) NOT NULL,
     CountIn INTEGER NOT NULL,
     CountOut INTEGER NOT NULL,
     BytesIn REAL NOT NULL,
     BytesOut REAL NOT NULL,
     VirusIn INTEGER NOT NULL,
     VirusOut INTEGER NOT NULL,
     SpamIn INTEGER NOT NULL,
     SpamOut INTEGER NOT NULL,
     BouncesIn INTEGER NOT NULL,
     BouncesOut INTEGER NOT NULL,
     PTimeSum REAL NOT NULL,
     MTime INTEGER NOT NULL,
     PRIMARY KEY (Time, Domain));

    CREATE INDEX DomainStat_MTime_Index ON DomainStat (MTime);
__EOD

my $statinfo_ctablecmd =  <<__EOD;
    CREATE TABLE StatInfo
    (Name VARCHAR(255) NOT NULL UNIQUE,
     IValue INTEGER,
     SValue VARCHAR(255),
     PRIMARY KEY (Name))
__EOD

my $virusinfo_stat_ctablecmd = <<__EOD;
    CREATE TABLE VirusInfo
    (Time INTEGER NOT NULL,
     Name VARCHAR NOT NULL,
     Count INTEGER NOT NULL,
     MTime INTEGER NOT NULL,
     PRIMARY KEY (Time, Name));

    CREATE INDEX VirusInfo_MTime_Index ON VirusInfo (MTime);

__EOD

# mail storage table
# QTypes
# V - Virus quarantine
# S - Spam quarantine
# D - Delayed Mails - not implemented
# A - Held for Audit - not implemented
# Status
# N - new
# D - deleted

my $cmailstore_ctablecmd =  <<__EOD;
    CREATE TABLE CMailStore
    (CID INTEGER DEFAULT 0 NOT NULL,
     RID INTEGER NOT NULL,
     ID SERIAL UNIQUE,
     Time INTEGER NOT NULL,
     QType "char" NOT NULL,
     Bytes INTEGER NOT NULL,
     Spamlevel INTEGER NOT NULL,
     Info VARCHAR NULL,
     Sender VARCHAR(255) NOT NULL,
     Header VARCHAR NOT NULL,
     File VARCHAR(255) NOT NULL,
     PRIMARY KEY (CID, RID));
    CREATE INDEX CMailStore_Time_Index ON CMailStore (Time);

    CREATE TABLE CMSReceivers
    (CMailStore_CID INTEGER NOT NULL,
     CMailStore_RID INTEGER NOT NULL,
     PMail VARCHAR(255) NOT NULL,
     Receiver VARCHAR(255),
     TicketID INTEGER NOT NULL,
     Status "char" NOT NULL,
     MTime INTEGER NOT NULL);

    CREATE INDEX CMailStore_ID_Index ON CMSReceivers (CMailStore_CID, CMailStore_RID);

    CREATE INDEX CMSReceivers_MTime_Index ON CMSReceivers (MTime);

__EOD

my $cstatistic_ctablecmd =  <<__EOD;
    CREATE TABLE CStatistic
    (CID INTEGER DEFAULT 0 NOT NULL,
     RID INTEGER NOT NULL,
     ID SERIAL UNIQUE,
     Time INTEGER NOT NULL,
     Bytes INTEGER NOT NULL,
     Direction Boolean NOT NULL,
     Spamlevel INTEGER NOT NULL,
     VirusInfo VARCHAR(255) NULL,
     PTime INTEGER NOT NULL,
     Sender VARCHAR(255) NOT NULL,
     PRIMARY KEY (CID, RID));

    CREATE INDEX CStatistic_Time_Index ON CStatistic (Time);

    CREATE TABLE CReceivers
    (CStatistic_CID INTEGER NOT NULL,
     CStatistic_RID INTEGER NOT NULL,
     Receiver VARCHAR(255) NOT NULL,
     Blocked Boolean NOT NULL);

    CREATE INDEX CStatistic_ID_Index ON CReceivers (CStatistic_CID, CStatistic_RID);
__EOD

# user preferences (black an whitelists, ...)
# Name: perference name ('BL' -> blacklist, 'WL' -> whitelist)
# Data: arbitrary data
my $userprefs_ctablecmd =  <<__EOD;
    CREATE TABLE UserPrefs
    (PMail VARCHAR,
     Name VARCHAR(255),
     Data VARCHAR,
     MTime INTEGER NOT NULL,
     PRIMARY KEY (PMail, Name));

    CREATE INDEX UserPrefs_MTime_Index ON UserPrefs (MTime);

__EOD

sub cond_create_dbtable {
    my ($dbh, $name, $ctablecmd) = @_;

    eval {
	$dbh->begin_work;

	my $cmd = "SELECT tablename FROM pg_tables " .
	    "WHERE tablename = lower ('$name')";

	my $sth = $dbh->prepare($cmd);

	$sth->execute();

	if (!(my $ref = $sth->fetchrow_hashref())) {
	    $dbh->do ($ctablecmd);
	}

	$sth->finish();

	$dbh->commit;
    };
    if (my $err = $@) {
	$dbh->rollback;
       	die $err;
    }
}

sub database_column_exists {
    my ($dbh, $table, $column) = @_;

    my $sth = $dbh->prepare(
	"SELECT column_name FROM information_schema.columns " .
	"WHERE table_name = ? and column_name = ?");
    $sth->execute(lc($table), lc($column));
    my $res = $sth->fetchrow_hashref();
    return defined($res);
}

my $createdb = sub {
    my ($dbname) = @_;
    postgres_admin_cmd(
	'createdb',
	undef,
	'-E', 'sql_ascii',
	'-T', 'template0',
	'--lc-collate=C',
	'--lc-ctype=C',
	$dbname,
    );
};

sub create_ruledb {
    my ($dbname) = @_;

    $dbname = $default_db_name if !$dbname;

    my $silent_opts = { outfunc => sub {}, errfunc => sub {} };
    # make sure we have user 'root'
    eval { postgres_admin_cmd('createuser',  $silent_opts, '-D', 'root'); };
    # also create 'www-data' (and give it read-only access below)
    eval { postgres_admin_cmd('createuser',  $silent_opts, '-I', '-D', 'www-data'); };

    # use sql_ascii to avoid any character set conversions, and be compatible with
    # older postgres versions (update from 8.1 must be possible)

    $createdb->($dbname);

    my $dbh = open_ruledb($dbname);

    # make sure 'www-data' can read all tables
    $dbh->do("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO \"www-data\"");

    $dbh->do (
<<EOD
	      CREATE TABLE Attribut
	      (Object_ID INTEGER NOT NULL,
	       Name VARCHAR(20) NOT NULL,
	       Value BYTEA NULL,
	       PRIMARY KEY (Object_ID, Name));

	      CREATE INDEX Attribut_Object_ID_Index ON Attribut(Object_ID);

	      CREATE TABLE Object
	      (ID SERIAL UNIQUE,
	       ObjectType INTEGER NOT NULL,
	       Objectgroup_ID INTEGER NOT NULL,
	       Value BYTEA NULL,
	       PRIMARY KEY (ID));

	      CREATE TABLE Objectgroup
	      (ID SERIAL UNIQUE,
	       Name VARCHAR(255) NOT NULL,
	       Info VARCHAR(255) NULL,
	       Class  VARCHAR(10) NOT NULL,
	       PRIMARY KEY (ID));

	      CREATE TABLE Rule
	      (ID SERIAL UNIQUE,
	       Name VARCHAR(255) NULL,
	       Priority INTEGER NOT NULL,
	       Active INTEGER NOT NULL DEFAULT 0,
	       Direction INTEGER NOT NULL DEFAULT 2,
	       Count INTEGER NOT NULL DEFAULT 0,
	       PRIMARY KEY (ID));

	      CREATE TABLE RuleGroup
	      (Objectgroup_ID INTEGER NOT NULL,
	       Rule_ID INTEGER NOT NULL,
	       Grouptype INTEGER NOT NULL,
	       PRIMARY KEY (Objectgroup_ID, Rule_ID, Grouptype));

	      $cgreylist_ctablecmd;

	      $clusterinfo_ctablecmd;

	      $local_stat_ctablecmd;

	      $daily_stat_ctablecmd;

	      $domain_stat_ctablecmd;

	      $statinfo_ctablecmd;

	      $cmailstore_ctablecmd;

	      $cstatistic_ctablecmd;

	      $userprefs_ctablecmd;

	      $virusinfo_stat_ctablecmd;
EOD
	      );

    return $dbh;
}

sub cond_create_action_quarantine {
    my ($ruledb) = @_;

    my $dbh = $ruledb->{dbh};

    eval {
	my $sth = $dbh->prepare(
	    "SELECT * FROM Objectgroup, Object " .
	    "WHERE Object.ObjectType = ? AND Objectgroup.Class = ? " .
	    "AND Object.objectgroup_id = Objectgroup.id");

	my $otype = PMG::RuleDB::Quarantine::otype();
	if ($sth->execute($otype, 'action') <= 0) {
	    my $obj = PMG::RuleDB::Quarantine->new ();
	    my $txt = decode_entities(PMG::RuleDB::Quarantine->otype_text);
	    my $quarantine = $ruledb->create_group_with_obj
		($obj, $txt, 'Move to quarantine.');
	}
    };
}

sub cond_create_std_actions {
    my ($ruledb) = @_;

    cond_create_action_quarantine($ruledb);

    #cond_create_action_report_spam($ruledb);
}


sub upgradedb {
    my ($ruledb) = @_;

    my $dbh = $ruledb->{dbh};

    # make sure we do not use slow sequential scans when upgraing
    # database (before analyze can gather statistics)
    $dbh->do("set enable_seqscan = false");

    my $tables = {
	'LocalStat', $local_stat_ctablecmd,
	'DailyStat', $daily_stat_ctablecmd,
	'DomainStat', $domain_stat_ctablecmd,
	'StatInfo', $statinfo_ctablecmd,
	'CMailStore', $cmailstore_ctablecmd,
	'UserPrefs', $userprefs_ctablecmd,
	'CGreylist', $cgreylist_ctablecmd,
	'CStatistic', $cstatistic_ctablecmd,
	'ClusterInfo', $clusterinfo_ctablecmd,
	'VirusInfo', $virusinfo_stat_ctablecmd,
    };

    foreach my $table (keys %$tables) {
	cond_create_dbtable($dbh, $table, $tables->{$table});
    }

    cond_create_std_actions($ruledb);

    # upgrade tables here if necessary
    if (!database_column_exists($dbh, 'LocalStat', 'PregreetCount')) {
	$dbh->do("ALTER TABLE LocalStat ADD COLUMN " .
		 "PregreetCount INTEGER DEFAULT 0 NOT NULL");
    }

    eval { $dbh->do("ALTER TABLE LocalStat DROP CONSTRAINT localstat_time_key"); };
    # ignore errors here


    # add missing TicketID to CMSReceivers
    if (!database_column_exists($dbh, 'CMSReceivers', 'TicketID')) {
	eval {
	    $dbh->begin_work;
	    $dbh->do("CREATE SEQUENCE cmsreceivers_ticketid_seq");
	    $dbh->do("ALTER TABLE CMSReceivers ADD COLUMN " .
		     "TicketID INTEGER NOT NULL " .
		     "DEFAULT nextval('cmsreceivers_ticketid_seq')");
	    $dbh->do("ALTER TABLE CMSReceivers ALTER COLUMN " .
		     "TicketID DROP DEFAULT");
	    $dbh->do("DROP SEQUENCE cmsreceivers_ticketid_seq");
	    $dbh->commit;
	};
	if (my $err = $@) {
	    $dbh->rollback;
	    die $err;
	}
    }

    # update obsolete content type names
    eval {
	$dbh->do("UPDATE Object " .
		 "SET value = 'content-type:application/java-vm' ".
		 "WHERE objecttype = 3003 " .
		 "AND value = 'content-type:application/x-java-vm';");
    };

    foreach my $table (keys %$tables) {
	eval { $dbh->do("ANALYZE $table"); };
	warn $@ if $@;
    }

    reload_ruledb();
}

sub init_ruledb {
    my ($ruledb, $reset, $testmode) = @_;

    my $dbh = $ruledb->{dbh};

    if (!$reset) {
	# Greylist Objectgroup
	my $greylistgroup = PMG::RuleDB::Group->new
	    ("GreyExclusion", "-", "greylist");
	$ruledb->save_group ($greylistgroup);

    } else {
	# we do not touch greylist objects
	my $glids = "SELECT object.ID FROM Object, Objectgroup WHERE " .
	    "objectgroup_id = objectgroup.id and class = 'greylist'";

	$dbh->do ("DELETE FROM Rule; " .
		  "DELETE FROM RuleGroup; " .
		  "DELETE FROM Attribut WHERE Object_ID NOT IN ($glids); " .
		  "DELETE FROM Object WHERE ID NOT IN ($glids); " .
		  "DELETE FROM Objectgroup WHERE class != 'greylist';");
    }

    # WHO Objects

     # Blacklist
    my $obj =  PMG::RuleDB::EMail->new ('nomail@fromthisdomain.com');
    my $blacklist = $ruledb->create_group_with_obj(
	$obj, 'Blacklist', 'Global blacklist');

    # Whitelist
    $obj = PMG::RuleDB::EMail->new('mail@fromthisdomain.com');
    my $whitelist = $ruledb->create_group_with_obj(
	$obj, 'Whitelist', 'Global whitelist');

    # WHEN Objects

    # Working hours
    $obj = PMG::RuleDB::TimeFrame->new(8*60, 16*60);
    my $working_hours =$ruledb->create_group_with_obj($obj, 'Office Hours' ,
						      'Usual office hours');

    # WHAT Objects

    # Images
    $obj = PMG::RuleDB::ContentTypeFilter->new('image/.*');
    my $img_content = $ruledb->create_group_with_obj(
	$obj, 'Images', 'All kinds of graphic files');

    # Multimedia
    $obj = PMG::RuleDB::ContentTypeFilter->new('audio/.*');
    my $mm_content = $ruledb->create_group_with_obj(
	$obj, 'Multimedia', 'Audio and Video');

    $obj = PMG::RuleDB::ContentTypeFilter->new('video/.*');
    $ruledb->group_add_object($mm_content, $obj);

    # Office Files
    $obj = PMG::RuleDB::ContentTypeFilter->new('application/vnd\.ms-excel');
    my $office_content = $ruledb->create_group_with_obj(
	$obj, 'Office Files', 'Common Office Files');

    $obj = PMG::RuleDB::ContentTypeFilter->new(
	'application/vnd\.ms-powerpoint');

    $ruledb->group_add_object($office_content, $obj);

    $obj = PMG::RuleDB::ContentTypeFilter->new('application/msword');
    $ruledb->group_add_object ($office_content, $obj);

    $obj = PMG::RuleDB::ContentTypeFilter->new(
	'application/vnd\.openxmlformats-officedocument\..*');
    $ruledb->group_add_object($office_content, $obj);

    $obj = PMG::RuleDB::ContentTypeFilter->new(
	'application/vnd\.oasis\.opendocument\..*');
    $ruledb->group_add_object($office_content, $obj);

    $obj = PMG::RuleDB::ContentTypeFilter->new(
	'application/vnd\.stardivision\..*');
    $ruledb->group_add_object($office_content, $obj);

    $obj = PMG::RuleDB::ContentTypeFilter->new(
	'application/vnd\.sun\.xml\..*');
    $ruledb->group_add_object($office_content, $obj);

    # Dangerous Content
    $obj = PMG::RuleDB::ContentTypeFilter->new(
	'application/x-ms-dos-executable');
    my $exe_content = $ruledb->create_group_with_obj(
	$obj, 'Dangerous Content', 'executable files and partial messages');

    $obj = PMG::RuleDB::ContentTypeFilter->new('application/x-java');
    $ruledb->group_add_object($exe_content, $obj);
    $obj = PMG::RuleDB::ContentTypeFilter->new('application/javascript');
    $ruledb->group_add_object($exe_content, $obj);
    $obj = PMG::RuleDB::ContentTypeFilter->new('application/x-executable');
    $ruledb->group_add_object($exe_content, $obj);
    $obj = PMG::RuleDB::ContentTypeFilter->new('application/x-ms-dos-executable');
    $ruledb->group_add_object($exe_content, $obj);
    $obj = PMG::RuleDB::ContentTypeFilter->new('message/partial');
    $ruledb->group_add_object($exe_content, $obj);
    $obj = PMG::RuleDB::MatchFilename->new('.*\.(vbs|pif|lnk|shs|shb)');
    $ruledb->group_add_object($exe_content, $obj);
    $obj = PMG::RuleDB::MatchFilename->new('.*\.\{.+\}');
    $ruledb->group_add_object($exe_content, $obj);

    # Virus
    $obj = PMG::RuleDB::Virus->new();
    my $virus = $ruledb->create_group_with_obj(
	$obj, 'Virus', 'Matches virus infected mail');

    # WHAT Objects

    # Spam
    $obj = PMG::RuleDB::Spam->new(3);
    my $spam3 = $ruledb->create_group_with_obj(
	$obj, 'Spam (Level 3)', 'Matches possible spam mail');

    $obj = PMG::RuleDB::Spam->new(5);
    my $spam5 = $ruledb->create_group_with_obj(
	$obj, 'Spam (Level 5)', 'Matches possible spam mail');

    $obj = PMG::RuleDB::Spam->new(10);
    my $spam10 = $ruledb->create_group_with_obj(
	$obj, 'Spam (Level 10)', 'Matches possible spam mail');

    # ACTIONS

    # Mark Spam
    $obj = PMG::RuleDB::ModField->new('X-SPAM-LEVEL', '__SPAM_INFO__');
    my $mod_spam_level = $ruledb->create_group_with_obj(
	$obj, 'Modify Spam Level',
	'Mark mail as spam by adding a header tag.');

    # Mark Spam
    $obj = PMG::RuleDB::ModField->new('subject', 'SPAM: __SUBJECT__');
    my $mod_spam_subject = $ruledb->create_group_with_obj(
	$obj, 'Modify Spam Subject',
	'Mark mail as spam by modifying the subject.');

    # Remove matching attachments
    $obj = PMG::RuleDB::Remove->new(0);
    my $remove = $ruledb->create_group_with_obj(
	$obj, 'Remove attachments', 'Remove matching attachments');

    # Remove all attachments
    $obj = PMG::RuleDB::Remove->new(1);
    my $remove_all = $ruledb->create_group_with_obj(
	$obj, 'Remove all attachments', 'Remove all attachments');

    # Accept
    $obj = PMG::RuleDB::Accept->new();
    my $accept = $ruledb->create_group_with_obj(
	$obj, 'Accept', 'Accept mail for Delivery');

    # Block
    $obj = PMG::RuleDB::Block->new ();
    my $block = $ruledb->create_group_with_obj($obj, 'Block', 'Block mail');

    # Quarantine
    $obj = PMG::RuleDB::Quarantine->new();
    my $quarantine = $ruledb->create_group_with_obj(
	$obj, 'Quarantine', 'Move mail to quarantine');

    # Notify Admin
    $obj = PMG::RuleDB::Notify->new('__ADMIN__');
    my $notify_admin = $ruledb->create_group_with_obj(
	$obj, 'Notify Admin', 'Send notification');

    # Notify Sender
    $obj = PMG::RuleDB::Notify->new('__SENDER__');
    my $notify_sender = $ruledb->create_group_with_obj(
	$obj, 'Notify Sender', 'Send notification');

    # Add Disclaimer
    $obj = PMG::RuleDB::Disclaimer->new ();
    my $add_discl = $ruledb->create_group_with_obj(
	$obj, 'Disclaimer', 'Add Disclaimer');

    # Attach original mail
    #$obj = Proxmox::RuleDB::Attach->new ();
    #my $attach_orig = $ruledb->create_group_with_obj ($obj, 'Attach Original Mail',
    #					      'Attach Original Mail');

    ####################### RULES ##################################

    ## Block Dangerous  Files
    my $rule = PMG::RuleDB::Rule->new ('Block Dangerous Files', 93, 1, 0);
    $ruledb->save_rule ($rule);

    $ruledb->rule_add_what_group ($rule, $exe_content);
    $ruledb->rule_add_action ($rule, $remove);

    ## Block Viruses
    $rule = PMG::RuleDB::Rule->new ('Block Viruses', 96, 1, 0);
    $ruledb->save_rule ($rule);

    $ruledb->rule_add_what_group ($rule, $virus);
    $ruledb->rule_add_action ($rule, $notify_admin);

    if ($testmode) {
	$ruledb->rule_add_action ($rule, $block);
    } else {
	$ruledb->rule_add_action ($rule, $quarantine);
    }

    ## Virus Alert
    $rule = PMG::RuleDB::Rule->new ('Virus Alert', 96, 1, 1);
    $ruledb->save_rule ($rule);

    $ruledb->rule_add_what_group ($rule, $virus);
    $ruledb->rule_add_action ($rule, $notify_sender);
    $ruledb->rule_add_action ($rule, $notify_admin);
    $ruledb->rule_add_action ($rule, $block);

    ## Blacklist
    $rule = PMG::RuleDB::Rule->new ('Blacklist', 98, 1, 0);
    $ruledb->save_rule ($rule);

    $ruledb->rule_add_from_group ($rule, $blacklist);
    $ruledb->rule_add_action ($rule, $block);

    ## Modify header
    if (!$testmode) {
	$rule = PMG::RuleDB::Rule->new ('Modify Header', 90, 1, 0);
	$ruledb->save_rule ($rule);
	$ruledb->rule_add_action ($rule, $mod_spam_level);
    }

    ## Whitelist
    $rule = PMG::RuleDB::Rule->new ('Whitelist', 85, 1, 0);
    $ruledb->save_rule ($rule);

    $ruledb->rule_add_from_group ($rule, $whitelist);
    $ruledb->rule_add_action ($rule, $accept);

    if ($testmode) {
	$rule = PMG::RuleDB::Rule->new ('Mark Spam', 80, 1, 0);
	$ruledb->save_rule ($rule);

	$ruledb->rule_add_what_group ($rule, $spam10);
	$ruledb->rule_add_action ($rule, $mod_spam_level);
	$ruledb->rule_add_action ($rule, $mod_spam_subject);
    } else {
	# Quarantine/Mark Spam (Level 3)
	$rule = PMG::RuleDB::Rule->new ('Quarantine/Mark Spam (Level 3)', 80, 1, 0);
	$ruledb->save_rule ($rule);

	$ruledb->rule_add_what_group ($rule, $spam3);
	$ruledb->rule_add_action ($rule, $mod_spam_subject);
	$ruledb->rule_add_action ($rule, $quarantine);
	#$ruledb->rule_add_action ($rule, $count_spam);
    }

    # Quarantine/Mark Spam (Level 5)
    $rule = PMG::RuleDB::Rule->new ('Quarantine/Mark Spam (Level 5)', 81, 0, 0);
    $ruledb->save_rule ($rule);

    $ruledb->rule_add_what_group ($rule, $spam5);
    $ruledb->rule_add_action ($rule, $mod_spam_subject);
    $ruledb->rule_add_action ($rule, $quarantine);

    ## Block Spam Level 10
    $rule = PMG::RuleDB::Rule->new ('Block Spam (Level 10)', 82, 0, 0);
    $ruledb->save_rule ($rule);

    $ruledb->rule_add_what_group ($rule, $spam10);
    $ruledb->rule_add_action ($rule, $block);

    ## Block Outgoing Spam
    $rule = PMG::RuleDB::Rule->new ('Block outgoing Spam', 70, 0, 1);
    $ruledb->save_rule ($rule);

    $ruledb->rule_add_what_group ($rule, $spam3);
    $ruledb->rule_add_action ($rule, $notify_admin);
    $ruledb->rule_add_action ($rule, $notify_sender);
    $ruledb->rule_add_action ($rule, $block);

    ## Add disclaimer
    $rule = PMG::RuleDB::Rule->new ('Add Disclaimer', 60, 0, 1);
    $ruledb->save_rule ($rule);
    $ruledb->rule_add_action ($rule, $add_discl);

    # Block Multimedia Files
    $rule = PMG::RuleDB::Rule->new ('Block Multimedia Files', 87, 0, 2);
    $ruledb->save_rule ($rule);

    $ruledb->rule_add_what_group ($rule, $mm_content);
    $ruledb->rule_add_action ($rule, $remove);

    #$ruledb->rule_add_from_group ($rule, $anybody);
    #$ruledb->rule_add_from_group ($rule, $trusted);
    #$ruledb->rule_add_to_group ($rule, $anybody);
    #$ruledb->rule_add_what_group ($rule, $ct_filter);
    #$ruledb->rule_add_action ($rule, $add_discl);
    #$ruledb->rule_add_action ($rule, $remove);
    #$ruledb->rule_add_action ($rule, $bcc);
    #$ruledb->rule_add_action ($rule, $storeq);
    #$ruledb->rule_add_action ($rule, $accept);

    cond_create_std_actions ($ruledb);

    reload_ruledb();
}

sub get_remote_time {
    my ($rdb) = @_;

    my $sth = $rdb->prepare("SELECT EXTRACT (EPOCH FROM TIMESTAMP (0) WITH TIME ZONE 'now') as ctime;");
    $sth->execute();
    my $ctinfo = $sth->fetchrow_hashref();
    $sth->finish ();

    return $ctinfo ? $ctinfo->{ctime} : 0;
}

sub init_masterdb {
    my ($lcid, $database) = @_;

    die "got unexpected cid for new master" if !$lcid;

    my $dbh;

    eval {
	$dbh = open_ruledb($database);

	$dbh->begin_work;

	print STDERR "update quarantine database\n";
	$dbh->do ("UPDATE CMailStore SET CID = $lcid WHERE CID = 0;" .
		  "UPDATE CMSReceivers SET CMailStore_CID = $lcid WHERE CMailStore_CID = 0;");

	print STDERR "update statistic database\n";
	$dbh->do ("UPDATE CStatistic SET CID = $lcid WHERE CID = 0;" .
		  "UPDATE CReceivers SET CStatistic_CID = $lcid WHERE CStatistic_CID = 0;");

	print STDERR "update greylist database\n";
	$dbh->do ("UPDATE CGreylist SET CID = $lcid WHERE CID = 0;");

	print STDERR "update localstat database\n";
	$dbh->do ("UPDATE LocalStat SET CID = $lcid WHERE CID = 0;");

	$dbh->commit;
    };
    my $err = $@;

    if ($dbh) {
	$dbh->rollback if $err;
	$dbh->disconnect();
    }

    die $err if $err;
}

sub purge_statistic_database {
    my ($dbh, $statlifetime) = @_;

    return if $statlifetime <= 0;

    my (undef, undef, undef, $mday, $mon, $year) = localtime(time());
    my $end = timelocal(0, 0, 0, $mday, $mon, $year);
    my $start = $end - $statlifetime*86400;

    # delete statistics older than $start

    my $rows = 0;

    eval {
	$dbh->begin_work;

	my $sth = $dbh->prepare("DELETE FROM CStatistic WHERE time < $start");
	$sth->execute;
	$rows = $sth->rows;
	$sth->finish;

	if ($rows > 0) {
	    $sth = $dbh->prepare(
		"DELETE FROM CReceivers WHERE NOT EXISTS " .
		"(SELECT * FROM CStatistic WHERE CID = CStatistic_CID AND RID = CStatistic_RID)");

	    $sth->execute;
	}
	$dbh->commit;
    };
    if (my $err = $@) {
	$dbh->rollback;
	die $err;
    }

    return $rows;
}

sub purge_quarantine_database {
    my ($dbh, $qtype, $lifetime) = @_;

    my $spooldir = $PMG::MailQueue::spooldir;

    my (undef, undef, undef, $mday, $mon, $year) = localtime(time());
    my $end = timelocal(0, 0, 0, $mday, $mon, $year);
    my $start = $end - $lifetime*86400;

    my $sth = $dbh->prepare(
	"SELECT file FROM CMailStore WHERE time < $start AND QType = '$qtype'");

    $sth->execute();

    my $count = 0;

    while (my $ref = $sth->fetchrow_hashref()) {
	my $filename = "$spooldir/$ref->{file}";
	$count++ if unlink($filename);
    }

    $sth->finish();

    $dbh->do(
	"DELETE FROM CMailStore WHERE time < $start AND QType = '$qtype';" .
	"DELETE FROM CMSReceivers WHERE NOT EXISTS " .
	"(SELECT * FROM CMailStore WHERE CID = CMailStore_CID AND RID = CMailStore_RID)");

    return $count;
}

sub get_quarantine_count {
    my ($dbh, $qtype) = @_;

    # Note;: We try to estimate used disk space - each mail
    # is stored in an extra file ...

    my $bs = 4096;

    my $sth = $dbh->prepare(
	"SELECT count(ID) as count,  sum (ceil((Bytes+$bs-1)/$bs)*$bs) / (1024*1024) as mbytes, " .
	"avg(Bytes) as avgbytes, avg(Spamlevel) as avgspam " .
	"FROM CMailStore WHERE QType = ?");

    $sth->execute($qtype);

    my $ref = $sth->fetchrow_hashref();

    $sth->finish;

    foreach my $k (qw(count mbytes avgbytes avgspam)) {
	$ref->{$k} //= 0;
    }

    return $ref;
}

sub copy_table {
    my ($ldb, $rdb, $table) = @_;

    $table = lc($table);

    my $sth = $ldb->column_info(undef, undef, $table, undef);
    my $attrs = $sth->fetchall_arrayref({});

    my @col_arr;
    foreach my $ref (@$attrs) {
	push @col_arr, $ref->{COLUMN_NAME};
    }

    $sth->finish();

    my $cols = join(', ', @col_arr);
    $cols || die "unable to fetch column definitions of table '$table' : ERROR";

    $rdb->do("COPY $table ($cols) TO STDOUT");

    my $data = '';

    eval {
	$ldb->do("COPY $table ($cols) FROM stdin");

	while ($rdb->pg_getcopydata($data) >= 0) {
	    $ldb->pg_putcopydata($data);
	}

	$ldb->pg_putcopyend();
    };
    if (my $err = $@) {
	$ldb->pg_putcopyend();
	die $err;
    }
}

sub copy_selected_data {
    my ($dbh, $select_sth, $table, $attrs, $callback) = @_;

    my $count = 0;

    my $insert_sth = $dbh->prepare(
	"INSERT INTO ${table}(" . join(',', @$attrs) . ') ' .
	'VALUES (' . join(',', ('?') x scalar(@$attrs)) . ')');

    while (my $ref = $select_sth->fetchrow_hashref()) {
	$callback->($ref) if $callback;
	$count++;
	$insert_sth->execute(map { $ref->{$_} } @$attrs);
    }

    return $count;
}

sub update_master_clusterinfo {
    my ($clientcid) = @_;

    my $dbh = open_ruledb();

    $dbh->do("DELETE FROM ClusterInfo WHERE CID = $clientcid");

    my @mt = ('CMSReceivers', 'CGreylist', 'UserPrefs', 'DomainStat', 'DailyStat', 'LocalStat', 'VirusInfo');

    foreach my $table (@mt) {
	$dbh->do ("INSERT INTO ClusterInfo (cid, name, ivalue) select $clientcid, 'lastmt_$table', " .
		  "EXTRACT(EPOCH FROM now())");
    }
}

sub update_client_clusterinfo {
    my ($mastercid) = @_;

    my $dbh = open_ruledb();

    $dbh->do ("DELETE FROM StatInfo"); # not needed at node

    $dbh->do ("DELETE FROM ClusterInfo WHERE CID = $mastercid");

    $dbh->do ("INSERT INTO ClusterInfo (cid, name, ivalue) select $mastercid, 'lastid_CMailStore', " .
	      "COALESCE (max (rid), -1) FROM CMailStore WHERE cid = $mastercid");

    $dbh->do ("INSERT INTO ClusterInfo (cid, name, ivalue) select $mastercid, 'lastid_CStatistic', " .
	      "COALESCE (max (rid), -1) FROM CStatistic WHERE cid = $mastercid");

    my @mt = ('CMSReceivers', 'CGreylist', 'UserPrefs', 'DomainStat', 'DailyStat', 'LocalStat', 'VirusInfo');

    foreach my $table (@mt) {
	$dbh->do ("INSERT INTO ClusterInfo (cid, name, ivalue) select $mastercid, 'lastmt_$table', " .
		  "COALESCE (max (mtime), 0) FROM $table");
    }
}

sub create_clusterinfo_default {
    my ($dbh, $rcid, $name, $ivalue, $svalue) = @_;

    my $sth = $dbh->prepare("SELECT * FROM ClusterInfo WHERE CID = ? AND Name = ?");
    $sth->execute($rcid, $name);
    if (!$sth->fetchrow_hashref()) {
	$dbh->do("INSERT INTO ClusterInfo (CID, Name, IValue, SValue) " .
		 "VALUES (?, ?, ?, ?)", undef,
		 $rcid, $name, $ivalue, $svalue);
    }
    $sth->finish();
}

sub read_int_clusterinfo {
    my ($dbh, $rcid, $name) = @_;

    my $sth = $dbh->prepare(
	"SELECT ivalue as value FROM ClusterInfo " .
	"WHERE cid = ? AND NAME = ?");
    $sth->execute($rcid, $name);
    my $cinfo = $sth->fetchrow_hashref();
    $sth->finish();

    return $cinfo->{value};
}

sub write_maxint_clusterinfo {
    my ($dbh, $rcid, $name, $value) = @_;

    $dbh->do("UPDATE ClusterInfo SET ivalue = GREATEST(ivalue, ?) " .
	     "WHERE cid = ? AND name = ?", undef,
	     $value, $rcid, $name);
}

sub init_nodedb {
    my ($cinfo) = @_;

    my $ni = $cinfo->{master};

    die "no master defined - unable to sync data from master\n" if !$ni;

    my $master_ip = $ni->{ip};
    my $master_cid = $ni->{cid};
    my $master_name = $ni->{name};

    my $fn = "/tmp/masterdb$$.tar";
    unlink $fn;

    my $dbname = $default_db_name;

    eval {
	print STDERR "copying master database from '${master_ip}'\n";

	open (my $fh, ">", $fn) || die "open '$fn' failed - $!\n";

	my $cmd = ['/usr/bin/ssh', '-o', 'BatchMode=yes',
		   '-o', "HostKeyAlias=${master_name}", $master_ip,
		   'pg_dump', $dbname, '-F', 'c' ];

	PVE::Tools::run_command($cmd, output => '>&' . fileno($fh));

	close($fh);

	my $size = -s $fn;

	print STDERR "copying master database finished (got $size bytes)\n";

	print STDERR "delete local database\n";

	postgres_admin_cmd('dropdb', undef, $dbname , '--if-exists');

	print STDERR "create new local database\n";

	$createdb->($dbname);

	print STDERR "insert received data into local database\n";

	my $mess;
	my $parser = sub {
	    my $line = shift;

	    if ($line =~ m/restoring data for table \"(.+)\"/) {
		print STDERR "restoring table $1\n";
	    } elsif (!$mess && ($line =~ m/creating (INDEX|CONSTRAINT)/)) {
		$mess = "creating indexes";
		print STDERR "$mess\n";
	    }
	};

	my $opts = {
	    outfunc => $parser,
	    errfunc => $parser,
	    errmsg => "pg_restore failed"
	};

	postgres_admin_cmd('pg_restore', $opts, '-d', $dbname, '-v', $fn);

	print STDERR "run analyze to speed up database queries\n";

	postgres_admin_cmd('psql', { input => 'analyze;' }, $dbname);

	update_client_clusterinfo($master_cid);
    };

    my $err = $@;

    unlink $fn;

    die $err if $err;
}

sub cluster_sync_status {
    my ($cinfo) = @_;

    my $dbh;

    my $minmtime;

    foreach my $ni (values %{$cinfo->{ids}}) {
	next if $cinfo->{local}->{cid} == $ni->{cid}; # skip local CID
	$minmtime->{$ni->{cid}} = 0;
    }

    eval {
	$dbh = open_ruledb();

	my $sth = $dbh->prepare(
	    "SELECT cid, MIN (ivalue) as minmtime FROM ClusterInfo " .
	    "WHERE name = 'lastsync' AND ivalue > 0 " .
	    "GROUP BY cid");

	$sth->execute();

	while (my $info = $sth->fetchrow_hashref()) {
	    foreach my $ni (values %{$cinfo->{ids}}) {
		next if $cinfo->{local}->{cid} == $ni->{cid}; # skip local CID
		if ($ni->{cid} == $info->{cid}) { # node exists
		    $minmtime->{$ni->{cid}} = $info->{minmtime};
		}
	    }
	}

	$sth->finish();
    };
    my $err = $@;

    $dbh->disconnect() if $dbh;

    syslog('err', $err) if $err;

    return $minmtime;
}

sub load_mail_data {
    my ($dbh, $cid, $rid, $ticketid) = @_;

    my $sth = $dbh->prepare(
	"SELECT * FROM CMailStore, CMSReceivers WHERE " .
	"CID = ? AND RID = ? AND TicketID = ? AND " .
	"CID = CMailStore_CID AND RID = CMailStore_RID");
    $sth->execute($cid, $rid, $ticketid);

    my $res = $sth->fetchrow_hashref();

    $sth->finish();

    die "no such mail (C${cid}R${rid}T${ticketid})\n" if !defined($res);

    return $res;
}

sub reload_ruledb {
    my ($ruledb) = @_;

    # Note: we pass $ruledb when modifying SMTP whitelist
    if (defined($ruledb)) {
	eval {
	    my $rulecache = PMG::RuleCache->new($ruledb);
	    PMG::Config::rewrite_postfix_whitelist($rulecache);
	};
	if (my $err = $@) {
	    warn "problems updating SMTP whitelist - $err";
	}
    }

    my $pid_file = '/var/run/pmg-smtp-filter.pid';
    my $pid = PVE::Tools::file_read_firstline($pid_file);

    return 0 if !$pid;

    return 0 if $pid !~ m/^(\d+)$/;
    $pid = $1; # untaint

    return kill (10, $pid); # send SIGUSR1
}

1;
