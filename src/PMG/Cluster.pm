package PMG::Cluster;

use strict;
use warnings;
use Data::Dumper;
use Socket;
use File::Path;
use Time::HiRes qw (gettimeofday tv_interval);

use PVE::SafeSyslog;
use PVE::Tools;
use PVE::INotify;
use PVE::APIClient::LWP;
use PVE::Network;

use PMG::Utils;
use PMG::Config;
use PMG::ClusterConfig;
use PMG::RuleDB;
use PMG::RuleCache;
use PMG::MailQueue;
use PMG::Fetchmail;
use PMG::Ticket;

sub remote_node_ip {
    my ($nodename, $noerr) = @_;

    my $cinfo = PMG::ClusterConfig->new();

    foreach my $entry (values %{$cinfo->{ids}}) {
	if ($entry->{name} eq $nodename) {
	    my $ip = $entry->{ip};
	    return $ip if !wantarray;
	    my $family = PVE::Tools::get_host_address_family($ip);
	    return ($ip, $family);
	}
    }

    # fallback: try to get IP by other means
    if ($nodename eq 'localhost' || $nodename eq PVE::INotify::nodename()) {
	return PVE::Network::get_local_ip();
    } else {
	return PVE::Network::get_ip_from_hostname($nodename, $noerr);
    }
}

sub get_master_node {
    my ($cinfo) = @_;

    $cinfo = PMG::ClusterConfig->new() if !$cinfo;

    return $cinfo->{master}->{name} if defined($cinfo->{master});

    return 'localhost';
}

sub read_local_ssl_cert_fingerprint {
    my $cert_path = "/etc/pmg/pmg-api.pem";

    my $cert;
    eval {
	my $bio = Net::SSLeay::BIO_new_file($cert_path, 'r');
	$cert = Net::SSLeay::PEM_read_bio_X509($bio);
	Net::SSLeay::BIO_free($bio);
    };
    if (my $err = $@) {
	die "unable to read certificate '$cert_path' - $err\n";
    }

    if (!defined($cert)) {
	die "unable to read certificate '$cert_path' - got empty value\n";
    }

    my $fp;
    eval {
	$fp = Net::SSLeay::X509_get_fingerprint($cert, 'sha256');
    };
    if (my $err = $@) {
	die "unable to get fingerprint for '$cert_path' - $err\n";
    }

    if (!defined($fp) || $fp eq '') {
	die "unable to get fingerprint for '$cert_path' - got empty value\n";
    }

    return $fp;
}

my $hostrsapubkey_fn = '/etc/ssh/ssh_host_rsa_key.pub';
my $rootrsakey_fn = '/root/.ssh/id_rsa';
my $rootrsapubkey_fn = '/root/.ssh/id_rsa.pub';

sub read_local_cluster_info {

    my $res = {};

    my $hostrsapubkey = PVE::Tools::file_read_firstline($hostrsapubkey_fn);
    $hostrsapubkey =~ s/^.*ssh-rsa\s+//i;
    $hostrsapubkey =~ s/\s+root\@\S+\s*$//i;

    my $sshpubkeypattern = PMG::ClusterConfig::Node::valid_ssh_pubkey_regex();
    die "unable to parse ${hostrsapubkey_fn}\n"
	if $hostrsapubkey !~ m/$sshpubkeypattern/;

    my $nodename = PVE::INotify::nodename();

    $res->{name} = $nodename;

    $res->{ip} = PVE::Network::get_local_ip();

    $res->{hostrsapubkey} = $hostrsapubkey;

    if (! -f $rootrsapubkey_fn) {
	unlink $rootrsakey_fn;
	my $cmd = ['ssh-keygen', '-t', 'rsa', '-N', '', '-b', '2048',
		   '-f', $rootrsakey_fn];
	PMG::Utils::run_silent_cmd($cmd);
    }

    my $rootrsapubkey = PVE::Tools::file_read_firstline($rootrsapubkey_fn);
    $rootrsapubkey =~ s/^.*ssh-rsa\s+//i;
    $rootrsapubkey =~ s/\s+root\@\S+\s*$//i;

    die "unable to parse ${rootrsapubkey_fn}\n"
	if $rootrsapubkey !~ m/$sshpubkeypattern/;

    $res->{rootrsapubkey} = $rootrsapubkey;

    $res->{fingerprint} = read_local_ssl_cert_fingerprint();

    return $res;
}

# X509 Certificate cache helper

my $cert_cache_nodes = {};
my $cert_cache_timestamp = time();
my $cert_cache_fingerprints = {};

sub update_cert_cache {

    $cert_cache_timestamp = time();

    $cert_cache_fingerprints = {};
    $cert_cache_nodes = {};

    my $cinfo = PMG::ClusterConfig->new();

    foreach my $entry (values %{$cinfo->{ids}}) {
	my $node = $entry->{name};
	my $fp = $entry->{fingerprint};
	if ($node && $fp) {
	    $cert_cache_fingerprints->{$fp} = 1;
	    $cert_cache_nodes->{$node} = $fp;
	}
    }
}

# load and cache cert fingerprint once
sub initialize_cert_cache {
    my ($node) = @_;

    update_cert_cache()
	if defined($node) && !defined($cert_cache_nodes->{$node});
}

sub check_cert_fingerprint {
    my ($cert) = @_;

    # clear cache every 30 minutes at least
    update_cert_cache() if time() - $cert_cache_timestamp >= 60*30;

    # get fingerprint of server certificate
    my $fp;
    eval {
	$fp = Net::SSLeay::X509_get_fingerprint($cert, 'sha256');
    };
    return 0 if $@ || !defined($fp) || $fp eq ''; # error

    my $check = sub {
	for my $expected (keys %$cert_cache_fingerprints) {
	    return 1 if $fp eq $expected;
	}
	return 0;
    };

    return 1 if $check->();

    # clear cache and retry at most once every minute
    if (time() - $cert_cache_timestamp >= 60) {
	syslog ('info', "Could not verify remote node certificate '$fp' with list of pinned certificates, refreshing cache");
	update_cert_cache();
	return $check->();
    }

    return 0;
}

my $sshglobalknownhosts = "/etc/ssh/ssh_known_hosts2";
my $rootsshauthkeys = "/root/.ssh/authorized_keys";
my $ssh_rsa_id = "/root/.ssh/id_rsa.pub";

sub update_ssh_keys {
    my ($cinfo) = @_;

    my $old = '';
    my $data = '';

    foreach my $node (values %{$cinfo->{ids}}) {
	$data .= "$node->{ip} ssh-rsa $node->{hostrsapubkey}\n";
	$data .= "$node->{name} ssh-rsa $node->{hostrsapubkey}\n";
    }

    $old = PVE::Tools::file_get_contents($sshglobalknownhosts, 1024*1024)
	if -f $sshglobalknownhosts;

    PVE::Tools::file_set_contents($sshglobalknownhosts, $data)
	if $old ne $data;

    $data = '';
    $old = '';

    # always add ourself
    if (-f $ssh_rsa_id) {
	my $pub = PVE::Tools::file_get_contents($ssh_rsa_id);
	chomp($pub);
	$data .= "$pub\n";
    }

    foreach my $node (values %{$cinfo->{ids}}) {
	$data .= "ssh-rsa $node->{rootrsapubkey} root\@$node->{name}\n";
    }

    if (-f $rootsshauthkeys) {
	my $mykey = PVE::Tools::file_get_contents($rootsshauthkeys, 128*1024);
	chomp($mykey);
	$data .= "$mykey\n";
    }

    my $newdata = "";
    my $vhash = {};
    my @lines = split(/\n/, $data);
    foreach my $line (@lines) {
	if ($line !~ /^#/ && $line =~ m/(^|\s)ssh-(rsa|dsa)\s+(\S+)\s+\S+$/) {
            next if $vhash->{$3}++;
	}
	$newdata .= "$line\n";
    }

    $old = PVE::Tools::file_get_contents($rootsshauthkeys, 1024*1024)
	if -f $rootsshauthkeys;

    PVE::Tools::file_set_contents($rootsshauthkeys, $newdata, 0600)
	if $old ne $newdata;
}

my $cfgdir = '/etc/pmg';
my $syncdir = "$cfgdir/master";

my $cond_commit_synced_file = sub {
    my ($filename, $dstfn) = @_;

    $dstfn = "$cfgdir/$filename" if !defined($dstfn);
    my $srcfn = "$syncdir/$filename";

    if (! -f $srcfn) {
	unlink $dstfn;
	return;
    }

    my $new = PVE::Tools::file_get_contents($srcfn, 1024*1024);

    if (-f $dstfn) {
	my $old = PVE::Tools::file_get_contents($dstfn, 1024*1024);
	return 0 if $new eq $old;
    }

    # set mtime (touch) to avoid time drift problems
    utime(undef, undef, $srcfn);

    rename($srcfn, $dstfn) ||
	die "cond_rename_file '$filename' failed - $!\n";

    print STDERR "updated $dstfn\n";

    return 1;
};

my $ssh_command = sub {
    my ($host_key_alias, @args) = @_;

    my $cmd = ['ssh', '-l', 'root', '-o', 'BatchMode=yes'];
    push @$cmd, '-o', "HostKeyAlias=${host_key_alias}" if $host_key_alias;
    push @$cmd, @args if @args;
    return $cmd;
};

sub get_remote_cert_fingerprint {
    my ($ni) = @_;

    my $ssh_cmd = $ssh_command->(
        $ni->{name},
        $ni->{ip},
        'openssl x509 -noout -fingerprint -sha256 -in /etc/pmg/pmg-api.pem'
    );
    my $fp;
    eval {
	PVE::Tools::run_command($ssh_cmd, outfunc => sub {
	    my ($line) = @_;
	    if ($line =~ m/SHA256 Fingerprint=((?:[a-f0-9]{2}:){31}[a-f0-9]{2})/i) {
		$fp = $1;
	    }
	});
	die "parsing failed\n" if !$fp;
    };
    die "unable to get remote node fingerprint from '$ni->{name}': $@\n" if $@;

    return $fp;
}

sub trigger_update_fingerprints {
    my ($cinfo) = @_;

    my $master = $cinfo->{master} || die "unable to lookup master node\n";
    my $cached_fp = { $master->{fingerprint} => 1 };

    # if running on master the current fingerprint for the API-connection is needed
    # in addition (to prevent races with restarting pmgproxy
    if ($cinfo->{local}->{type} eq 'master') {
	my $new_fp = PMG::Cluster::read_local_ssl_cert_fingerprint();
	$cached_fp->{$new_fp} = 1;
    }

    my $ticket = PMG::Ticket::assemble_ticket('root@pam');
    my $csrftoken = PMG::Ticket::assemble_csrf_prevention_token('root@pam');
    my $conn = PVE::APIClient::LWP->new(
	ticket => $ticket,
	csrftoken => $csrftoken,
	cookie_name => 'PMGAuthCookie',
	host => $master->{ip},
	cached_fingerprints => $cached_fp,
	);

    $conn->post("/config/cluster/update-fingerprints", {});
    return undef;
}

my $rsync_command = sub {
    my ($host_key_alias, @args) = @_;

    my $ssh_cmd = join(' ', @{$ssh_command->($host_key_alias)});

    my $cmd = ['rsync', "--rsh=$ssh_cmd",  '-q', @args];

    return $cmd;
};

sub sync_quarantine_files {
    my ($host_ip, $host_name, $flistname, $rcid) = @_;

    my $spooldir = $PMG::MailQueue::spooldir;

    mkdir "$spooldir/cluster/";
    my $syncdir = "$spooldir/cluster/$rcid";
    mkdir $syncdir;

    my $cmd = $rsync_command->(
	$host_name, '--timeout', '10', "[${host_ip}]:$spooldir", $spooldir,
	'--files-from', $flistname);

    PVE::Tools::run_command($cmd);
}

sub sync_spooldir {
    my ($host_ip, $host_name, $rcid) = @_;

    my $spooldir = $PMG::MailQueue::spooldir;

    mkdir "$spooldir/cluster/";
    my $syncdir = "$spooldir/cluster/$rcid";
    mkdir $syncdir;

    my $cmd = $rsync_command->(
	$host_name, '-aq', '--timeout', '10', "[${host_ip}]:$syncdir/", $syncdir);

    foreach my $incl (('spam/', 'spam/*', 'spam/*/*', 'virus/', 'virus/*', 'virus/*/*')) {
	push @$cmd, '--include', $incl;
    }

    push @$cmd, '--exclude', '*';

    PVE::Tools::run_command($cmd);
}

sub sync_master_quar {
    my ($host_ip, $host_name) = @_;

    my $spooldir = $PMG::MailQueue::spooldir;

    my $syncdir = "$spooldir/cluster/";
    mkdir $syncdir;

    my $cmd = $rsync_command->(
	$host_name, '-aq', '--timeout', '10', "[${host_ip}]:$syncdir", $syncdir);

    PVE::Tools::run_command($cmd);
}

sub sync_config_from_master {
    my ($master_name, $master_ip, $noreload) = @_;

    mkdir $syncdir;
    File::Path::remove_tree($syncdir, {keep_root => 1});

    my $sa_conf_dir = "/etc/mail/spamassassin";
    my $sa_custom_cf = "custom.cf";
    my $sa_rules_cf = "pmg-scores.cf";

    my $cmd = $rsync_command->(
	$master_name, '-aq',
	"[${master_ip}]:$cfgdir/*",
	"[${master_ip}]:${sa_conf_dir}/${sa_custom_cf}",
	"[${master_ip}]:${sa_conf_dir}/${sa_rules_cf}",
	"$syncdir/",
	'--exclude', 'master/',
	'--exclude', '*~',
	'--exclude', '*.db',
	'--exclude', 'pmg-api.pem',
	'--exclude', 'pmg-tls.pem',
	);

    my $errmsg = "syncing master configuration from '${master_ip}' failed";
    PVE::Tools::run_command($cmd, errmsg => $errmsg);

    # verify that the remote host is cluster master
    open (my $fh, '<', "$syncdir/cluster.conf") ||
	die "unable to open synced cluster.conf - $!\n";

    my $cinfo = PMG::ClusterConfig::read_cluster_conf('cluster.conf', $fh);

    if (!$cinfo->{master} || ($cinfo->{master}->{ip} ne $master_ip)) {
	die "host '$master_ip' is not cluster master\n";
    }

    my $role = $cinfo->{'local'}->{type} // '-';
    die "local node '$cinfo->{local}->{name}' not part of cluster\n"
	if $role eq '-';

    die "local node '$cinfo->{local}->{name}' is new cluster master\n"
	if $role eq 'master';

    $cond_commit_synced_file->('cluster.conf');

    update_ssh_keys($cinfo); # rewrite ssh keys

    PMG::Fetchmail::update_fetchmail_default(0); # disable on slave

    my $files = [
	'pmg-authkey.key',
	'pmg-authkey.pub',
	'pmg-csrf.key',
	'ldap.conf',
	'user.conf',
	'tfa.json',
	'domains',
	'mynetworks',
	'transport',
	'tls_policy',
	'tls_inbound_domains',
	'fetchmailrc',
	];

    foreach my $filename (@$files) {
	$cond_commit_synced_file->($filename);
    }

    my $dirs = [
	'templates',
	'dkim',
	'pbs',
	'acme',
    ];

    foreach my $dir (@$dirs) {
	my $srcdir = "$syncdir/$dir";

	if ( -d $srcdir ) {
	    my $cmd = ['rsync', '-aq', '--delete-after', "$srcdir/", "$cfgdir/$dir"];
	    PVE::Tools::run_command($cmd);
	}

    }

    my $force_restart = {};

    for my $file (($sa_custom_cf, $sa_rules_cf)) {
	if ($cond_commit_synced_file->($file, "${sa_conf_dir}/${file}")) {
	    $force_restart->{'pmg-smtp-filter'} = 1;
	}
    }

    $cond_commit_synced_file->('pmg.conf');

    return $force_restart;
}

sub sync_ruledb_from_master {
    my ($ldb, $rdb, $ni, $ticket) = @_;

    my $ruledb = PMG::RuleDB->new($ldb);
    my $rulecache = PMG::RuleCache->new($ruledb);

    my $conn = PVE::APIClient::LWP->new(
	ticket => $ticket,
	cookie_name => 'PMGAuthCookie',
	host => $ni->{ip},
	cached_fingerprints => {
	    $ni->{fingerprint} => 1,
	});

    my $digest = $conn->get("/config/ruledb/digest", {});

    return if $digest eq $rulecache->{digest}; # no changes

    syslog('info', "detected rule database changes - starting sync from '$ni->{ip}'");

    eval {
	$ldb->begin_work;

	$ldb->do("DELETE FROM Rule");
	$ldb->do("DELETE FROM RuleGroup");
	$ldb->do("DELETE FROM ObjectGroup");
	$ldb->do("DELETE FROM Object");
	$ldb->do("DELETE FROM Attribut");

	eval {
	    $rdb->begin_work;

	    # read a consistent snapshot
	    $rdb->do("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");

	    PMG::DBTools::copy_table($ldb, $rdb, "Rule");
	    PMG::DBTools::copy_table($ldb, $rdb, "RuleGroup");
	    PMG::DBTools::copy_table($ldb, $rdb, "ObjectGroup");
	    PMG::DBTools::copy_table($ldb, $rdb, "Object", 'value');
	    PMG::DBTools::copy_table($ldb, $rdb, "Attribut", 'value');
	    PMG::DBTools::copy_table($ldb, $rdb, "Rule_Attributes");
	    PMG::DBTools::copy_table($ldb, $rdb, "Objectgroup_Attributes");
	};

	$rdb->rollback; # end transaction

	die $@ if $@;

	# update sequences

	$ldb->do("SELECT setval('rule_id_seq', max(id)+1) FROM Rule");
	$ldb->do("SELECT setval('object_id_seq', max(id)+1) FROM Object");
	$ldb->do("SELECT setval('objectgroup_id_seq', max(id)+1) FROM ObjectGroup");

	$ldb->commit;
    };
    if (my $err = $@) {
	$ldb->rollback;
	die $err;
    }

    PMG::DBTools::reload_ruledb();

    syslog('info', "finished rule database sync from host '$ni->{ip}'");
}

sub sync_quarantine_db {
    my ($ldb, $rdb, $ni, $rsynctime_ref) = @_;

    my $rcid = $ni->{cid};

    my $maxmails = 100000;

    my $mscount = 0;

    my $ctime = PMG::DBTools::get_remote_time($rdb);

    my $maxcount = 1000;

    my $count;

    PMG::DBTools::create_clusterinfo_default($ldb, $rcid, 'lastid_CMailStore', -1, undef);

    do { # get new values

	$count = 0;

	my $flistname = "/tmp/quarantinefilelist.$$";

	eval {
	    $ldb->begin_work;

	    open(my $flistfh, '>', $flistname) ||
		die "unable to open file '$flistname' - $!\n";

	    my $lastid = PMG::DBTools::read_int_clusterinfo($ldb, $rcid, 'lastid_CMailStore');

	    # sync CMailStore

	    my $sth = $rdb->prepare(
		"SELECT * from CMailstore WHERE cid = ? AND rid > ? " .
		"ORDER BY cid,rid LIMIT ?");
	    $sth->execute($rcid, $lastid, $maxcount);

	    my $maxid;
	    my $callback = sub {
		my $ref = shift;
		$maxid = $ref->{rid};
		my $filename = $ref->{file};
		 # skip files generated before cluster was created
		return if $filename !~ m!^cluster/!;
		print $flistfh "$filename\n";
	    };

	    my $attrs = [qw(cid rid time qtype bytes spamlevel info sender header file)];
	    $count += PMG::DBTools::copy_selected_data($ldb, $sth, 'CMailStore', $attrs, $callback);

	    close($flistfh);

	    my $starttime = [ gettimeofday() ];
	    sync_quarantine_files($ni->{ip}, $ni->{name}, $flistname, $rcid);
	    $$rsynctime_ref += tv_interval($starttime);

	    if ($maxid) {
		# sync CMSReceivers

		$sth = $rdb->prepare(
		    "SELECT * from CMSReceivers WHERE " .
		    "CMailStore_CID = ? AND CMailStore_RID > ?  " .
		    "AND CMailStore_RID <= ?");
		$sth->execute($rcid, $lastid, $maxid);

		$attrs = [qw(cmailstore_cid cmailstore_rid pmail receiver ticketid status mtime)];
		PMG::DBTools::copy_selected_data($ldb, $sth, 'CMSReceivers', $attrs);

		PMG::DBTools::write_maxint_clusterinfo($ldb, $rcid, 'lastid_CMailStore', $maxid);
	    }

	    $ldb->commit;
	};
	my $err = $@;

	unlink $flistname;

	if ($err) {
	    $ldb->rollback;
	    die $err;
	}

	$mscount += $count;

    } while (($count >= $maxcount) && ($mscount < $maxmails));

    PMG::DBTools::create_clusterinfo_default($ldb, $rcid, 'lastmt_CMSReceivers', 0, undef);

    eval { # synchronize status updates
	$ldb->begin_work;

	my $lastmt = PMG::DBTools::read_int_clusterinfo($ldb, $rcid, 'lastmt_CMSReceivers');

	my $sth = $rdb->prepare ("SELECT * from CMSReceivers WHERE mtime >= ? AND status != 'N'");
	$sth->execute($lastmt);

	my $update_sth = $ldb->prepare(
	    "UPDATE CMSReceivers SET status = ? WHERE " .
	    "CMailstore_CID = ? AND CMailstore_RID = ? AND TicketID = ?");
	while (my $ref = $sth->fetchrow_hashref()) {
	    $update_sth->execute($ref->{status}, $ref->{cmailstore_cid},
				 $ref->{cmailstore_rid}, $ref->{ticketid});
	}

	PMG::DBTools::write_maxint_clusterinfo($ldb, $rcid, 'lastmt_CMSReceivers', $ctime);

	$ldb->commit;
    };
    if (my $err = $@) {
	$ldb->rollback;
	die $err;
    }

    return $mscount;
}

sub sync_statistic_db {
    my ($ldb, $rdb, $ni) = @_;

    my $rcid = $ni->{cid};

    my $maxmails = 100000;

    my $mscount = 0;

    my $maxcount = 1000;

    my $count;

    PMG::DBTools::create_clusterinfo_default(
	$ldb, $rcid, 'lastid_CStatistic', -1, undef);

    do { # get new values

	$count = 0;

	eval {
	    $ldb->begin_work;

	    my $lastid = PMG::DBTools::read_int_clusterinfo(
		$ldb, $rcid, 'lastid_CStatistic');

	    # sync CStatistic

	    my $sth = $rdb->prepare(
		"SELECT * from CStatistic " .
		"WHERE cid = ? AND rid > ? " .
		"ORDER BY cid, rid LIMIT ?");
	    $sth->execute($rcid, $lastid, $maxcount);

	    my $maxid;
	    my $callback = sub {
		my $ref = shift;
		$maxid = $ref->{rid};
	    };

	    my $attrs = [qw(cid rid time bytes direction spamlevel ptime virusinfo sender)];
	    $count += PMG::DBTools::copy_selected_data($ldb, $sth, 'CStatistic', $attrs, $callback);

	    if ($maxid) {
		# sync CReceivers

		$sth = $rdb->prepare(
		    "SELECT * from CReceivers WHERE " .
		    "CStatistic_CID = ? AND CStatistic_RID > ? AND CStatistic_RID <= ?");
		$sth->execute($rcid, $lastid, $maxid);

		$attrs = [qw(cstatistic_cid cstatistic_rid blocked receiver)];
		PMG::DBTools::copy_selected_data($ldb, $sth, 'CReceivers', $attrs);
	    }

	    PMG::DBTools::write_maxint_clusterinfo ($ldb, $rcid, 'lastid_CStatistic', $maxid);

	    $ldb->commit;
	};
	if (my $err = $@) {
	    $ldb->rollback;
	    die $err;
	}

	$mscount += $count;

    } while (($count >= $maxcount) && ($mscount < $maxmails));

    return $mscount;
}

my $sync_generic_mtime_db = sub {
    my ($ldb, $rdb, $ni, $table, $selectfunc, $mergefunc) = @_;

    my $ctime = PMG::DBTools::get_remote_time($rdb);

    PMG::DBTools::create_clusterinfo_default($ldb, $ni->{cid}, "lastmt_$table", 0, undef);

    my $lastmt = PMG::DBTools::read_int_clusterinfo($ldb, $ni->{cid}, "lastmt_$table");

    my $sql_cmd = $selectfunc->($ctime, $lastmt);

    my $sth = $rdb->prepare($sql_cmd);

    $sth->execute();

    my $updates = 0;

    eval {
	# use transaction to speedup things
	my $max = 1000; # UPDATE MAX ENTRIES AT ONCE
	my $count = 0;
	while (my $ref = $sth->fetchrow_hashref()) {
	    $ldb->begin_work if !$count;
	    $mergefunc->($ref);
	    if (++$count >= $max) {
		$count = 0;
		$ldb->commit;
	    }
	    $updates++;
	}

	$ldb->commit if $count;
    };
    if (my $err = $@) {
	$ldb->rollback;
	die $err;
    }

    PMG::DBTools::write_maxint_clusterinfo($ldb, $ni->{cid}, "lastmt_$table", $ctime);

    return $updates;
};

sub sync_localstat_db {
    my ($dbh, $rdb, $ni) = @_;

    my $rcid = $ni->{cid};

    my $selectfunc = sub {
	my ($ctime, $lastmt) = @_;
	return "SELECT * from LocalStat WHERE mtime >= $lastmt AND cid = $rcid";
    };

    my $merge_sth = $dbh->prepare(
	'INSERT INTO LocalStat (Time, RBLCount, PregreetCount, CID, MTime) ' .
	'VALUES (?, ?, ?, ?, ?) ' .
	'ON CONFLICT (Time, CID) DO UPDATE SET ' .
	'RBLCount = excluded.RBLCount, PregreetCount = excluded.PregreetCount, MTime = excluded.MTime');

    my $mergefunc = sub {
	my ($ref) = @_;

	$merge_sth->execute($ref->{time}, $ref->{rblcount}, $ref->{pregreetcount}, $ref->{cid}, $ref->{mtime});
    };

    return $sync_generic_mtime_db->($dbh, $rdb, $ni, 'LocalStat', $selectfunc, $mergefunc);
}

sub sync_greylist_db {
    my ($dbh, $rdb, $ni) = @_;

    my $selectfunc = sub {
	my ($ctime, $lastmt) = @_;
	return "SELECT * from CGreylist WHERE extime >= $ctime AND " .
	    "mtime >= $lastmt AND CID != 0";
    };

    my $merge_sth = $dbh->prepare(PMG::DBTools::cgreylist_merge_sql());
    my $mergefunc = sub {
	my ($ref) = @_;

	my $ipnet = $ref->{ipnet};
	$ipnet .= '.0/24' if $ipnet !~ /\/\d+$/;
	$merge_sth->execute(
	    $ipnet, $ref->{sender}, $ref->{receiver},
	    $ref->{instance}, $ref->{rctime}, $ref->{extime}, $ref->{delay},
	    $ref->{blocked}, $ref->{passed}, 0, $ref->{cid});
    };

    return $sync_generic_mtime_db->($dbh, $rdb, $ni, 'CGreylist', $selectfunc, $mergefunc);
}

sub sync_userprefs_db {
    my ($dbh, $rdb, $ni) = @_;

    my $selectfunc = sub {
	my ($ctime, $lastmt) = @_;

	return "SELECT * from UserPrefs WHERE mtime >= $lastmt";
    };

    my $merge_sth = $dbh->prepare(
	"INSERT INTO UserPrefs (PMail, Name, Data, MTime) " .
	'VALUES (?, ?, ?, ?) ' .
	'ON CONFLICT (PMail, Name) DO UPDATE SET ' .
	# Note: MTime = 0 ==> this is just a copy from somewhere else, not modified
	'MTime = CASE WHEN excluded.MTime >= UserPrefs.MTime THEN 0 ELSE UserPrefs.MTime END, ' .
	'Data = CASE WHEN excluded.MTime >= UserPrefs.MTime THEN excluded.Data ELSE UserPrefs.Data END');

    my $mergefunc = sub {
	my ($ref) = @_;

	$merge_sth->execute($ref->{pmail}, $ref->{name}, $ref->{data}, $ref->{mtime});
    };

    return $sync_generic_mtime_db->($dbh, $rdb, $ni, 'UserPrefs', $selectfunc, $mergefunc);
}

sub sync_domainstat_db {
    my ($dbh, $rdb, $ni) = @_;

    my $selectfunc = sub {
	my ($ctime, $lastmt) = @_;
	return "SELECT * from DomainStat WHERE mtime >= $lastmt";
    };

    my $merge_sth = $dbh->prepare(
	'INSERT INTO Domainstat ' .
	'(Time,Domain,CountIn,CountOut,BytesIn,BytesOut,VirusIn,VirusOut,SpamIn,SpamOut,' .
	'BouncesIn,BouncesOut,PTimeSum,Mtime) ' .
	'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) ' .
	'ON CONFLICT (Time, Domain) DO UPDATE SET ' .
	'CountIn = excluded.CountIn, CountOut = excluded.CountOut, ' .
	'BytesIn = excluded.BytesIn, BytesOut = excluded.BytesOut, ' .
	'VirusIn = excluded.VirusIn, VirusOut = excluded.VirusOut, ' .
	'SpamIn = excluded.SpamIn, SpamOut = excluded.SpamOut, ' .
	'BouncesIn = excluded.BouncesIn, BouncesOut = excluded.BouncesOut, ' .
	'PTimeSum = excluded.PTimeSum, MTime = excluded.MTime');

    my $mergefunc = sub {
	my ($ref) = @_;

	$merge_sth->execute(
	    $ref->{time}, $ref->{domain}, $ref->{countin}, $ref->{countout},
	    $ref->{bytesin}, $ref->{bytesout},
	    $ref->{virusin}, $ref->{virusout}, $ref->{spamin}, $ref->{spamout},
	    $ref->{bouncesin}, $ref->{bouncesout}, $ref->{ptimesum}, $ref->{mtime});
    };

    return $sync_generic_mtime_db->($dbh, $rdb, $ni, 'DomainStat', $selectfunc, $mergefunc);
}

sub sync_dailystat_db {
    my ($dbh, $rdb, $ni) = @_;

    my $selectfunc = sub {
	my ($ctime, $lastmt) = @_;
	return "SELECT * from DailyStat WHERE mtime >= $lastmt";
    };

    my $merge_sth = $dbh->prepare(
	'INSERT INTO DailyStat ' .
	'(Time,CountIn,CountOut,BytesIn,BytesOut,VirusIn,VirusOut,SpamIn,SpamOut,' .
	'BouncesIn,BouncesOut,GreylistCount,SPFCount,RBLCount,PTimeSum,Mtime) ' .
	'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ' .
	'ON CONFLICT (Time) DO UPDATE SET ' .
	'CountIn = excluded.CountIn, CountOut = excluded.CountOut, ' .
	'BytesIn = excluded.BytesIn, BytesOut = excluded.BytesOut, ' .
	'VirusIn = excluded.VirusIn, VirusOut = excluded.VirusOut, ' .
	'SpamIn = excluded.SpamIn, SpamOut = excluded.SpamOut, ' .
	'BouncesIn = excluded.BouncesIn, BouncesOut = excluded.BouncesOut, ' .
	'GreylistCount = excluded.GreylistCount, SPFCount = excluded.SpfCount, ' .
	'RBLCount = excluded.RBLCount, ' .
	'PTimeSum = excluded.PTimeSum, MTime = excluded.MTime');

    my $mergefunc = sub {
	my ($ref) = @_;

	$merge_sth->execute(
	    $ref->{time}, $ref->{countin}, $ref->{countout},
	    $ref->{bytesin}, $ref->{bytesout},
	    $ref->{virusin}, $ref->{virusout}, $ref->{spamin}, $ref->{spamout},
	    $ref->{bouncesin}, $ref->{bouncesout}, $ref->{greylistcount},
	    $ref->{spfcount}, $ref->{rblcount}, $ref->{ptimesum}, $ref->{mtime});
    };

    return $sync_generic_mtime_db->($dbh, $rdb, $ni, 'DailyStat', $selectfunc, $mergefunc);
}

sub sync_virusinfo_db {
    my ($dbh, $rdb, $ni) = @_;

    my $selectfunc = sub {
	my ($ctime, $lastmt) = @_;
	return "SELECT * from VirusInfo WHERE mtime >= $lastmt";
    };

    my $merge_sth = $dbh->prepare(
	'INSERT INTO VirusInfo (Time,Name,Count,MTime) ' .
	'VALUES (?,?,?,?) ' .
	'ON CONFLICT (Time,Name) DO UPDATE SET ' .
	'Count = excluded.Count , MTime = excluded.MTime');

    my $mergefunc = sub {
	my ($ref) = @_;

	$merge_sth->execute($ref->{time}, $ref->{name}, $ref->{count}, $ref->{mtime});
    };

    return $sync_generic_mtime_db->($dbh, $rdb, $ni, 'VirusInfo', $selectfunc, $mergefunc);
}

sub sync_deleted_nodes_from_master {
    my ($ldb, $masterdb, $cinfo, $masterni, $rsynctime_ref) = @_;

    my $rsynctime = 0;

    my $cid_hash = {}; # fast lookup
    foreach my $ni (values %{$cinfo->{ids}}) {
	$cid_hash->{$ni->{cid}} = $ni;
    }

    my $spooldir = $PMG::MailQueue::spooldir;

    my $maxcid = $cinfo->{master}->{maxcid} // 0;

    for (my $rcid = 1; $rcid <= $maxcid; $rcid++) {
	next if $cid_hash->{$rcid};

	my $done_marker = "$spooldir/cluster/$rcid/.synced-deleted-node";

	next if -f $done_marker; # already synced

	syslog('info', "syncing deleted node $rcid from master '$masterni->{ip}'");

	my $starttime = [ gettimeofday() ];
	sync_spooldir($masterni->{ip}, $masterni->{name}, $rcid);
	$$rsynctime_ref += tv_interval($starttime);

	my $fake_ni = {
	    ip => $masterni->{ip},
	    name => $masterni->{name},
	    cid => $rcid,
	};

	sync_quarantine_db($ldb, $masterdb, $fake_ni);

	sync_statistic_db ($ldb, $masterdb, $fake_ni);

	open(my $fh, ">>",  $done_marker);
   }
}


1;
