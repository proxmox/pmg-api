package PMG::Utils;

use strict;
use warnings;
use utf8;
# compat for older perl code which allows arbitrary binary data (including invalid UTF-8)
# TODO: can we remove this (as our perl source texts should be all UTF-8 compatible)?
no utf8;

use Cwd;
use DBI;
use Data::Dumper;
use Digest::MD5;
use Digest::SHA;
use Encode;
use File::Basename;
use File::stat;
use File::stat;
use Filesys::Df;
use HTML::Entities;
use IO::File;
use JSON;
use MIME::Entity;
use MIME::Parser;
use MIME::Words;
use Net::Cmd;
use Net::IP;
use Net::SMTP;
use POSIX qw(strftime);
use RRDs;
use Socket;
use Time::HiRes qw (gettimeofday);
use Time::Local;
use Xdgmime;

use PMG::AtomicFile;
use PMG::MIMEUtils;
use PMG::MailQueue;
use PMG::SMTPPrinter;
use PVE::Network;
use PVE::ProcFSTools;
use PVE::SafeSyslog;
use PVE::Tools;

use base 'Exporter';

our @EXPORT_OK = qw(
postgres_admin_cmd
try_decode_utf8
);

my $valid_pmg_realms = ['pam', 'pmg', 'quarantine'];

PVE::JSONSchema::register_standard_option('realm', {
    description => "Authentication domain ID",
    type => 'string',
    enum => $valid_pmg_realms,
    maxLength => 32,
});

PVE::JSONSchema::register_standard_option('pmg-starttime', {
    description => "Only consider entries newer than 'starttime' (unix epoch). Default is 'now - 1day'.",
    type => 'integer',
    minimum => 0,
    optional => 1,
});

PVE::JSONSchema::register_standard_option('pmg-endtime', {
    description => "Only consider entries older than 'endtime' (unix epoch). This is set to '<start> + 1day' by default.",
    type => 'integer',
    minimum => 1,
    optional => 1,
});

PVE::JSONSchema::register_format('pmg-userid', \&verify_username);
sub verify_username {
    my ($username, $noerr) = @_;

    $username = '' if !$username;
    my $len = length($username);
    if ($len < 3) {
	die "user name '$username' is too short\n" if !$noerr;
	return undef;
    }
    if ($len > 64) {
	die "user name '$username' is too long ($len > 64)\n" if !$noerr;
	return undef;
    }

    # we only allow a limited set of characters. Colons aren't allowed, because we store usernames
    # with colon separated lists! slashes aren't allowed because it is used as pve API delimiter
    # also see "man useradd"
    my $realm_list = join('|', @$valid_pmg_realms);
    if ($username =~ m!^([^\s:/]+)\@(${realm_list})$!) {
	return wantarray ? ($username, $1, $2) : $username;
    }

    die "value '$username' does not look like a valid user name\n" if !$noerr;

    return undef;
}

PVE::JSONSchema::register_standard_option('userid', {
    description => "User ID",
    type => 'string', format => 'pmg-userid',
    minLength => 4,
    maxLength => 64,
});

PVE::JSONSchema::register_standard_option('username', {
    description => "Username (without realm)",
    type => 'string',
    pattern => '[^\s:\/\@]{1,60}',
    maxLength => 64,
});

PVE::JSONSchema::register_standard_option('pmg-email-address', {
    description => "Email Address (allow most characters).",
    type => 'string',
    pattern => '(?:[^\s\\\@]+\@[^\s\/\\\@]+)',
    maxLength => 512,
    minLength => 3,
});

PVE::JSONSchema::register_standard_option('pmg-whiteblacklist-entry-list', {
    description => "White/Blacklist entry list (allow most characters). Can contain globs",
    type => 'string',
    pattern => '(?:[^\s\/\\\;\,]+)(?:\,[^\s\/\\\;\,]+)*',
    minLength => 3,
});

sub lastid {
    my ($dbh, $seq) = @_;

    return $dbh->last_insert_id(
	undef, undef, undef, undef, { sequence => $seq});
}

# quote all regex operators
sub quote_regex {
    my $val = shift;

    $val =~ s/([\(\)\[\]\/\}\+\*\?\.\|\^\$\\])/\\$1/g;

    return $val;
}

sub file_older_than {
    my ($filename, $lasttime) = @_;

    my $st = stat($filename);

    return 0 if !defined($st);

    return ($lasttime >= $st->ctime);
}

sub extract_filename {
    my ($head) = @_;

    if (my $value = $head->recommended_filename()) {
	chomp $value;
	if (my $decvalue = MIME::Words::decode_mimewords($value)) {
	    $decvalue =~ s/\0/ /g;
	    $decvalue = PVE::Tools::trim($decvalue);
	    return $decvalue;
	}
    }

    return undef;
}

sub remove_marks {
    my ($entity, $add_id) = @_;

    my $id = 1;

    PMG::MIMEUtils::traverse_mime_parts($entity, sub {
	my ($part) = @_;
	foreach my $tag (grep {/^x-proxmox-tmp/i} $part->head->tags) {
	    $part->head->delete($tag);
	}

	$part->head->replace('X-Proxmox-tmp-AID', $id) if $add_id;

	$id++;
    });

    return $id - 1; # return max AID
}

sub subst_values {
    my ($body, $dh) = @_;

    return if !$body;

    foreach my $k (keys %$dh) {
	my $v = $dh->{$k};
	if (defined($v)) {
	    $body =~ s/__\Q${k}\E__/$v/gs;
	}
    }

    return $body;
}

sub subst_values_for_header {
    my ($header, $dh) = @_;

    my $res = '';
    foreach my $line (split('\r?\n\s*', subst_values ($header, $dh))) {
	$res .= "\n" if $res;
	$res .= MIME::Words::encode_mimewords(encode('UTF-8', $line), 'Charset' => 'UTF-8');
    }

    # support for multiline values (i.e. __SPAM_INFO__)
    $res =~ s/\n/\n\t/sg; # indent content
    $res =~ s/\n\s*\n//sg;   # remove empty line
    $res =~ s/\n?\s*$//s;    # remove trailing spaces

    return $res;
}

# detects the need for setting smtputf8 based on pmg.conf, addresses and headers
sub reinject_local_mail {
    my ($entity, $sender, $targets, $xforward, $me) = @_;

    my $cfg = PMG::Config->new();

    my $params;
    if ( $cfg->get('mail', 'smtputf8' )) {
	my $needs_smtputf8 = 0;

	$needs_smtputf8 = 1 if ($sender =~ /[^\p{PosixPrint}]/);

	foreach my $target (@$targets) {
	    if ($target =~ /[^\p{PosixPrint}]/) {
		$needs_smtputf8 = 1;
		last;
	    }
	}

	if (!$needs_smtputf8 && $entity->head()->as_string() =~ /([^\p{PosixPrint}\n\r\t])/) {
	    $needs_smtputf8 = 1;
	}

	$params->{mail}->{smtputf8} = $needs_smtputf8;
    }

    return reinject_mail($entity, $sender, $targets, $xforward, $me, $params);
}

sub reinject_mail {
    my ($entity, $sender, $targets, $xforward, $me, $params) = @_;

    my $smtp;
    my $resid;
    my $rescode;
    my $resmess;

    eval {
	my $smtp = Net::SMTP->new('::FFFF:127.0.0.1', Port => 10025, Hello => $me) ||
	    die "unable to connect to localhost at port 10025";

	if (defined($xforward)) {
	    my $xfwd;

	    foreach my $attr (keys %{$xforward}) {
		$xfwd .= " $attr=$xforward->{$attr}";
	    }

	    if ($xfwd && $smtp->command("XFORWARD", $xfwd)->response() != CMD_OK) {
		syslog('err', "xforward error - got: %s %s", $smtp->code, scalar($smtp->message));
	    }
	}

	my $mail_opts = " BODY=8BITMIME";
	my $sender_addr = encode('UTF-8', $smtp->_addr($sender));
	if (defined($params->{mail})) {
	    if (delete $params->{mail}->{smtputf8}) {
		$mail_opts .= " SMTPUTF8";
	    }

	    my $mailparams = $params->{mail};
	    for my $p (keys %$mailparams) {
		$mail_opts .= " $p=$mailparams->{$p}";
	    }
	}

	if (!$smtp->_MAIL("FROM:" . $sender_addr . $mail_opts)) {
	    my @msgs = $smtp->message;
	    $resmess = $msgs[$#msgs];
	    $rescode = $smtp->code;
	    die sprintf("smtp from error - got: %s %s\n", $rescode, $resmess);
	}

	foreach my $target (@$targets) {
	    my $rcpt_addr;
	    my $rcpt_opts = '';
	    if (defined($params->{rcpt}->{$target})) {
		my $rcptparams = $params->{rcpt}->{$target};
		for my $p (keys %$rcptparams) {
		    $rcpt_opts .= " $p=$rcptparams->{$p}";
		}
	    }
	    $rcpt_addr = encode('UTF-8', $smtp->_addr($target));

	    if (!$smtp->_RCPT("TO:" . $rcpt_addr . $rcpt_opts)) {
		my @msgs = $smtp->message;
		$resmess = $msgs[$#msgs];
		$rescode = $smtp->code;
		die sprintf("smtp to error - got: %s %s\n", $rescode, $resmess);
	    }
	}

	# Output the head:
	#$entity->sync_headers ();
	$smtp->data();

	my $out = PMG::SMTPPrinter->new($smtp);
	$entity->print($out);

	# make sure we always have a newline at the end of the mail
	# else dataend() fails
	$smtp->datasend("\n");

	if ($smtp->dataend()) {
	    my @msgs = $smtp->message;
	    $resmess = $msgs[$#msgs];
	    ($resid) = $resmess =~ m/Ok: queued as ([0-9A-Z]+)/;
	    $rescode = $smtp->code;
	    if (!$resid) {
		die sprintf("unexpected SMTP result - got: %s %s : WARNING\n", $smtp->code, $resmess);
	    }
	} else {
	    my @msgs = $smtp->message;
	    $resmess = $msgs[$#msgs];
	    $rescode = $smtp->code;
	    die sprintf("sending data failed - got: %s %s : ERROR\n", $smtp->code, $resmess);
	}
    };
    my $err = $@;

    $smtp->quit if $smtp;

    if ($err) {
	syslog ('err', $err);
    }

    return wantarray ? ($resid, $rescode, $resmess) : $resid;
}

sub analyze_custom_check {
    my ($queue, $dname, $pmg_cfg) = @_;

    my $enable_custom_check = $pmg_cfg->get('admin', 'custom_check');
    return undef if !$enable_custom_check;

    my $timeout = 60*5;
    my $customcheck_exe = $pmg_cfg->get('admin', 'custom_check_path');
    my $customcheck_apiver = 'v1';
    my ($csec, $usec) = gettimeofday();

    my $vinfo;
    my $spam_score;

    eval {

	my $log_err = sub {
	    my ($errmsg) = @_;
	    $errmsg =~ s/%/%%/;
	    syslog('err', $errmsg);
	};

	my $customcheck_output_apiver;
	my $have_result;
	my $parser = sub {
	    my ($line) = @_;

	    my $result_flag;
	    if ($line =~ /^v\d$/) {
		die "api version already defined!\n" if defined($customcheck_output_apiver);
		$customcheck_output_apiver = $line;
		die "api version mismatch - expected $customcheck_apiver, got $customcheck_output_apiver !\n"
		    if ($customcheck_output_apiver ne $customcheck_apiver);
	    } elsif ($line =~ /^SCORE: (-?[0-9]+|.[0-9]+|[0-9]+.[0-9]+)$/) {
		$spam_score = $1;
		$result_flag = 1;
	    } elsif ($line =~ /^VIRUS: (.+)$/) {
		$vinfo = $1;
		$result_flag = 1;
	    } elsif ($line =~ /^OK$/) {
		$result_flag = 1;
	    } else {
		die "got unexpected output!\n";
	    }
	    die "got more than 1 result outputs\n" if ( $have_result && $result_flag);
	    $have_result = $result_flag;
	};

	PVE::Tools::run_command([$customcheck_exe, $customcheck_apiver, $dname],
	    errmsg => "$queue->{logid} custom check error",
	    errfunc => $log_err, outfunc => $parser, timeout => $timeout);

	die "no api version returned\n" if !defined($customcheck_output_apiver);
	die "no result output!\n" if !$have_result;
    };
    my $err = $@;

    if ($vinfo) {
	syslog('info', "$queue->{logid}: virus detected: $vinfo (custom)");
    }

    my ($csec_end, $usec_end) = gettimeofday();
    $queue->{ptime_custom} =
	int (($csec_end-$csec)*1000 + ($usec_end - $usec)/1000);

    if ($err) {
	syslog ('err', $err);
	$vinfo = undef;
	$queue->{errors} = 1;
    }

    $queue->{vinfo_custom} = $vinfo;
    $queue->{spam_custom} = $spam_score;

    return ($vinfo, $spam_score);
}

sub analyze_virus_clam {
    my ($queue, $dname, $pmg_cfg) = @_;

    my $timeout = 60*5;
    my $vinfo;

    my $clamdscan_opts = "--stdout";

    my ($csec, $usec) = gettimeofday();

    my $previous_alarm;

    eval {

	$previous_alarm = alarm($timeout);

	$SIG{ALRM} = sub {
	    die "$queue->{logid}: Maximum time ($timeout sec) exceeded. " .
		"virus analyze (clamav) failed: ERROR";
	};

	open(CMD, "/usr/bin/clamdscan $clamdscan_opts '$dname'|") ||
	    die "$queue->{logid}: can't exec clamdscan: $! : ERROR";

	my $ifiles;

	my $response = '';
	while (defined(my $line = <CMD>)) {
	    if ($line =~ m/^$dname.*:\s+([^ :]*)\s+FOUND$/) {
		# we just use the first detected virus name
		$vinfo = $1 if !$vinfo;
	    } elsif ($line =~ m/^Infected files:\s(\d*)$/i) {
		$ifiles = $1;
	    }

	    $response .= $line;
	}

	close(CMD);

	alarm(0); # avoid race conditions

	if (!defined($ifiles)) {
	    die "$queue->{logid}: got undefined output from " .
		"virus detector: $response : ERROR";
	}

	if ($vinfo) {
	    syslog('info', "$queue->{logid}: virus detected: $vinfo (clamav)");
	}
    };
    my $err = $@;

    alarm($previous_alarm);

    my ($csec_end, $usec_end) = gettimeofday();
    $queue->{ptime_clam} =
	int (($csec_end-$csec)*1000 + ($usec_end - $usec)/1000);

    if ($err) {
	syslog ('err', $err);
	$vinfo = undef;
	$queue->{errors} = 1;
    }

    $queue->{vinfo_clam} = $vinfo;

    return $vinfo ? "$vinfo (clamav)" : undef;
}

sub analyze_virus_avast {
    my ($queue, $dname, $pmg_cfg) = @_;

    my $timeout = 60*5;
    my $vinfo;

    my ($csec, $usec) = gettimeofday();

    my $previous_alarm;

    eval {

	$previous_alarm = alarm($timeout);

	$SIG{ALRM} = sub {
	    die "$queue->{logid}: Maximum time ($timeout sec) exceeded. " .
		"virus analyze (avast) failed: ERROR";
	};

	open(my $cmd, '-|', 'scan', $dname) ||
	    die "$queue->{logid}: can't exec avast scan: $! : ERROR";

	my $response = '';
	while (defined(my $line = <$cmd>)) {
	    if ($line =~ m/^$dname\s+(.*\S)\s*$/) {
		# we just use the first detected virus name
		$vinfo = $1 if !$vinfo;
	    }

	    $response .= $line;
	}

	close($cmd);

	alarm(0); # avoid race conditions

	if ($vinfo) {
	    syslog('info', "$queue->{logid}: virus detected: $vinfo (avast)");
	}
    };
    my $err = $@;

    alarm($previous_alarm);

    my ($csec_end, $usec_end) = gettimeofday();
    $queue->{ptime_clam} =
	int (($csec_end-$csec)*1000 + ($usec_end - $usec)/1000);

    if ($err) {
	syslog ('err', $err);
	$vinfo = undef;
	$queue->{errors} = 1;
    }

    return undef if !$vinfo;

    $queue->{vinfo_avast} = $vinfo;

    return "$vinfo (avast)";
}

sub analyze_virus {
    my ($queue, $filename, $pmg_cfg, $testmode) = @_;

    # TODO: support other virus scanners?

    if ($testmode) {
	my $vinfo_clam = analyze_virus_clam($queue, $filename, $pmg_cfg);
	my $vinfo_avast = analyze_virus_avast($queue, $filename, $pmg_cfg);

	return $vinfo_avast || $vinfo_clam;
    }

    my $enable_avast  = $pmg_cfg->get('admin', 'avast');

    if ($enable_avast) {
	if (my $vinfo = analyze_virus_avast($queue, $filename, $pmg_cfg)) {
	    return $vinfo;
	}
    }

    my $enable_clamav = $pmg_cfg->get('admin', 'clamav');

    if ($enable_clamav) {
	if (my $vinfo = analyze_virus_clam($queue, $filename, $pmg_cfg)) {
	    return $vinfo;
	}
    }

    return undef;
}

sub magic_mime_type_for_file {
    my ($filename) = @_;

    # we do not use get_mime_type_for_file, because that considers
    # filename extensions - we only want magic type detection

    my $bufsize = Xdgmime::xdg_mime_get_max_buffer_extents();
    die "got strange value for max_buffer_extents" if $bufsize > 4096*10;

    my $ct = "application/octet-stream";

    my $fh = IO::File->new("<$filename") ||
	die "unable to open file '$filename' - $!";

    my ($buf, $len);
    if (($len = $fh->read($buf, $bufsize)) > 0) {
	$ct = xdg_mime_get_mime_type_for_data($buf, $len);
    }
    $fh->close();

    die "unable to read file '$filename' - $!" if ($len < 0);

    return $ct;
}

sub add_ct_marks {
    my ($entity) = @_;

    if (my $path = $entity->{PMX_decoded_path}) {

	# set a reasonable default if magic does not give a result
	$entity->{PMX_magic_ct} = $entity->head->mime_attr('content-type');

	if (my $ct = magic_mime_type_for_file($path)) {
	    if ($ct ne 'application/octet-stream' || !$entity->{PMX_magic_ct}) {
		$entity->{PMX_magic_ct} = $ct;
	    }
	}

	my $filename = $entity->head->recommended_filename;
	$filename = basename($path) if !defined($filename) || $filename eq '';

	if (my $ct = xdg_mime_get_mime_type_from_file_name($filename)) {
	    $entity->{PMX_glob_ct} = $ct;
	}
    }

    foreach my $part ($entity->parts)  {
	add_ct_marks ($part);
    }
}

# x509 certificate utils

# only write output if something fails
sub run_silent_cmd {
    my ($cmd) = @_;

    my $outbuf = '';

    my $record_output = sub {
	$outbuf .= shift;
	$outbuf .= "\n";
    };

    eval {
	PVE::Tools::run_command($cmd, outfunc => $record_output,
				errfunc => $record_output);
    };
    my $err = $@;

    if ($err) {
	print STDERR $outbuf;
	die $err;
    }
}

my $proxmox_tls_cert_fn = "/etc/pmg/pmg-tls.pem";

sub gen_proxmox_tls_cert {
    my ($force) = @_;

    my $resolv = PVE::INotify::read_file('resolvconf');
    my $domain = $resolv->{search};

    my $company = $domain; # what else ?
    my $cn = "*.$domain";

   return if !$force && -f $proxmox_tls_cert_fn;

    my $sslconf = <<__EOD__;
RANDFILE = /root/.rnd
extensions = v3_req

[ req ]
default_bits = 4096
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
string_mask = nombstr

[ req_distinguished_name ]
organizationalUnitName = Proxmox Mail Gateway
organizationName = $company
commonName = $cn

[ v3_req ]
basicConstraints = CA:FALSE
nsCertType = server
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
__EOD__

    my $cfgfn = "/tmp/pmgtlsconf-$$.tmp";
    my $fh = IO::File->new ($cfgfn, "w");
    print $fh $sslconf;
    close ($fh);

    eval {
	my $cmd = ['openssl', 'req', '-batch', '-x509', '-new', '-sha256',
		   '-config', $cfgfn, '-days', 3650, '-nodes',
		   '-out', $proxmox_tls_cert_fn,
		   '-keyout', $proxmox_tls_cert_fn];
	run_silent_cmd($cmd);
    };

    if (my $err = $@) {
	unlink $proxmox_tls_cert_fn;
	unlink $cfgfn;
	die "unable to generate proxmox certificate request:\n$err";
    }

    unlink $cfgfn;
}

sub find_local_network_for_ip {
    my ($ip, $noerr) = @_;

    my $testip = Net::IP->new($ip);

    my $isv6 = $testip->version == 6;
    my $routes = $isv6 ?
	PVE::ProcFSTools::read_proc_net_ipv6_route() :
	PVE::ProcFSTools::read_proc_net_route();

    foreach my $entry (@$routes) {
	my $mask;
	if ($isv6) {
	    $mask = $entry->{prefix};
	    next if !$mask; # skip the default route...
	} else {
	    $mask = $PVE::Network::ipv4_mask_hash_localnet->{$entry->{mask}};
	    next if !defined($mask);
	}
	my $cidr = "$entry->{dest}/$mask";
	my $testnet = Net::IP->new($cidr);
	my $overlap = $testnet->overlaps($testip);
	if ($overlap == $Net::IP::IP_B_IN_A_OVERLAP ||
	    $overlap == $Net::IP::IP_IDENTICAL)
	{
	    return $cidr;
	}
    }

    return undef if $noerr;

    die "unable to detect local network for ip '$ip'\n";
}

my $service_aliases = {
    'postfix' =>  'postfix@-',
};

sub lookup_real_service_name {
    my $alias = shift;

    if ($alias eq 'postgres') {
	my $pg_ver = get_pg_server_version();
	return "postgresql\@${pg_ver}-main";
    }

    return $service_aliases->{$alias} // $alias;
}

sub get_full_service_state {
    my ($service) = @_;

    my $res;

    my $parser = sub {
	my $line = shift;
	if ($line =~ m/^([^=\s]+)=(.*)$/) {
	    $res->{$1} = $2;
	}
    };

    $service = lookup_real_service_name($service);
    PVE::Tools::run_command(['systemctl', 'show', $service], outfunc => $parser);

    return $res;
}

our $db_service_list = [
    'pmgpolicy', 'pmgmirror', 'pmgtunnel', 'pmg-smtp-filter' ];

sub service_wait_stopped {
    my ($timeout, $service_list) = @_;

    my $starttime = time();

    foreach my $service (@$service_list) {
	PVE::Tools::run_command(['systemctl', 'stop', $service]);
    }

    while (1) {
	my $wait = 0;

	foreach my $service (@$service_list) {
	    my $ss = get_full_service_state($service);
	    my $state = $ss->{ActiveState} // 'unknown';

	    if ($state ne 'inactive') {
		if ((time() - $starttime) > $timeout) {
		    syslog('err', "unable to stop services (got timeout)");
		    $wait = 0;
		    last;
		}
		$wait = 1;
	    }
	}

	last if !$wait;

	sleep(1);
    }
}

sub service_cmd {
    my ($service, $cmd) = @_;

    die "unknown service command '$cmd'\n"
	if $cmd !~ m/^(start|stop|restart|reload|reload-or-restart)$/;

    if ($service eq 'pmgdaemon' || $service eq 'pmgproxy') {
	die "invalid service cmd '$service $cmd': refusing to stop essential service!\n"
	    if $cmd eq 'stop';
    } elsif ($service eq 'fetchmail') {
	# use restart instead of start - else it does not start 'exited' unit
	# after setting START_DAEMON=yes in /etc/default/fetchmail
	$cmd = 'restart' if $cmd eq 'start';
    }

    $service = lookup_real_service_name($service);
    PVE::Tools::run_command(['systemctl', $cmd, $service]);
};

sub run_postmap {
    my ($filename) = @_;

    # make sure the file exists (else postmap fails)
    IO::File->new($filename, 'a', 0644);

    my $mtime_src = (CORE::stat($filename))[9] //
	die "unable to read mtime of $filename\n";

    my $mtime_dst = (CORE::stat("$filename.db"))[9] // 0;

    # if not changed, do nothing
    return if $mtime_src <= $mtime_dst;

    eval {
	PVE::Tools::run_command(
	    ['/usr/sbin/postmap', $filename],
	    errmsg => "unable to update postfix table $filename");
    };
    my $err = $@;

    warn $err if $err;
}

sub clamav_dbstat {

    my $res = [];

    my $read_cvd_info = sub {
	my ($dbname, $dbfile) = @_;

        my $header;
	my $fh = IO::File->new("<$dbfile");
	if (!$fh) {
	    warn "can't open ClamAV Database $dbname ($dbfile) - $!\n";
	    return;
	}
	$fh->read($header, 512);
	$fh->close();

	## ClamAV-VDB:16 Mar 2016 23-17 +0000:57:4218790:60:06386f34a16ebeea2733ab037f0536be:
	if ($header =~ m/^(ClamAV-VDB):([^:]+):(\d+):(\d+):/) {
	    my ($ftype, $btime, $version, $nsigs) = ($1, $2, $3, $4);
	    push @$res, {
		name => $dbname,
		type => $ftype,
		build_time => $btime,
		version => $version,
		nsigs => $nsigs,
	    };
	} else {
	    warn "unable to parse ClamAV Database $dbname ($dbfile)\n";
	}
    };

    # main database
    my $filename = "/var/lib/clamav/main.inc/main.info";
    $filename = "/var/lib/clamav/main.cvd" if ! -f $filename;

    $read_cvd_info->('main', $filename) if -f $filename;

    # daily database
    $filename = "/var/lib/clamav/daily.inc/daily.info";
    $filename = "/var/lib/clamav/daily.cvd" if ! -f $filename;
    $filename = "/var/lib/clamav/daily.cld" if ! -f $filename;

    $read_cvd_info->('daily', $filename) if -f $filename;

    $filename = "/var/lib/clamav/bytecode.cvd";
    $read_cvd_info->('bytecode', $filename) if -f $filename;

    my $ss_dbs_fn = "/var/lib/clamav-unofficial-sigs/configs/ss-include-dbs.txt";
    my $ss_dbs_files = {};
    if (my $ssfh = IO::File->new("<${ss_dbs_fn}")) {
	while (defined(my $line = <$ssfh>)) {
	    chomp $line;
	    $ss_dbs_files->{$line} = 1;
	}
    }
    my $last = 0;
    my $nsigs = 0;
    foreach $filename (</var/lib/clamav/*>) {
	my $fn = basename($filename);
	next if !$ss_dbs_files->{$fn};

	my $fh = IO::File->new("<$filename");
	next if !defined($fh);
	my $st = stat($fh);
	next if !$st;
	my $mtime = $st->mtime();
	$last = $mtime if $mtime > $last;
	while (defined(my $line = <$fh>)) { $nsigs++; }
    }

    if ($nsigs > 0) {
	push @$res, {
	    name => 'sanesecurity',
	    type => 'unofficial',
	    build_time => strftime("%d %b %Y %H-%M %z", localtime($last)),
	    nsigs => $nsigs,
	};
    }

    return $res;
}

# RRD related code
my $rrd_dir = "/var/lib/rrdcached/db";
my $rrdcached_socket = "/var/run/rrdcached.sock";

my $rrd_def_node = [
    "DS:loadavg:GAUGE:120:0:U",
    "DS:maxcpu:GAUGE:120:0:U",
    "DS:cpu:GAUGE:120:0:U",
    "DS:iowait:GAUGE:120:0:U",
    "DS:memtotal:GAUGE:120:0:U",
    "DS:memused:GAUGE:120:0:U",
    "DS:swaptotal:GAUGE:120:0:U",
    "DS:swapused:GAUGE:120:0:U",
    "DS:roottotal:GAUGE:120:0:U",
    "DS:rootused:GAUGE:120:0:U",
    "DS:netin:DERIVE:120:0:U",
    "DS:netout:DERIVE:120:0:U",

    "RRA:AVERAGE:0.5:1:70", # 1 min avg - one hour
    "RRA:AVERAGE:0.5:30:70", # 30 min avg - one day
    "RRA:AVERAGE:0.5:180:70", # 3 hour avg - one week
    "RRA:AVERAGE:0.5:720:70", # 12 hour avg - one month
    "RRA:AVERAGE:0.5:10080:70", # 7 day avg - one year

    "RRA:MAX:0.5:1:70", # 1 min max - one hour
    "RRA:MAX:0.5:30:70", # 30 min max - one day
    "RRA:MAX:0.5:180:70", # 3 hour max - one week
    "RRA:MAX:0.5:720:70", # 12 hour max - one month
    "RRA:MAX:0.5:10080:70", # 7 day max - one year
];

sub cond_create_rrd_file {
    my ($filename, $rrddef) = @_;

    return if -f $filename;

    my @args = ($filename);

    push @args, "--daemon" => "unix:${rrdcached_socket}"
	if -S $rrdcached_socket;

    push @args, '--step', 60;

    push @args, @$rrddef;

    # print "TEST: " . join(' ', @args) . "\n";

    RRDs::create(@args);
    my $err = RRDs::error;
    die "RRD error: $err\n" if $err;
}

sub update_node_status_rrd {

    my $filename = "$rrd_dir/pmg-node-v1.rrd";
    cond_create_rrd_file($filename, $rrd_def_node);

    my ($avg1, $avg5, $avg15) = PVE::ProcFSTools::read_loadavg();

    my $stat = PVE::ProcFSTools::read_proc_stat();

    my $netdev = PVE::ProcFSTools::read_proc_net_dev();

    my ($uptime) = PVE::ProcFSTools::read_proc_uptime();

    my $cpuinfo = PVE::ProcFSTools::read_cpuinfo();

    my $maxcpu = $cpuinfo->{cpus};

    # traffic from/to physical interface cards
    my $netin = 0;
    my $netout = 0;
    foreach my $dev (keys %$netdev) {
	next if $dev !~ m/^$PVE::Network::PHYSICAL_NIC_RE$/;
	$netin += $netdev->{$dev}->{receive};
	$netout += $netdev->{$dev}->{transmit};
    }

    my $meminfo = PVE::ProcFSTools::read_meminfo();

    my $dinfo = df('/', 1); # output is bytes

    my $ctime = time();

    # everything not free is considered to be used
    my $dused = $dinfo->{blocks} - $dinfo->{bfree};

    my $data = "$ctime:$avg1:$maxcpu:$stat->{cpu}:$stat->{wait}:" .
	"$meminfo->{memtotal}:$meminfo->{memused}:" .
	"$meminfo->{swaptotal}:$meminfo->{swapused}:" .
	"$dinfo->{blocks}:$dused:$netin:$netout";


    my @args = ($filename);

    push @args, "--daemon" => "unix:${rrdcached_socket}"
	if -S $rrdcached_socket;

    push @args, $data;

    # print "TEST: " . join(' ', @args) . "\n";

    RRDs::update(@args);
    my $err = RRDs::error;
    die "RRD error: $err\n" if $err;
}

sub create_rrd_data {
    my ($rrdname, $timeframe, $cf) = @_;

    my $rrd = "${rrd_dir}/$rrdname";

    my $setup = {
	hour =>  [ 60, 70 ],
	day  =>  [ 60*30, 70 ],
	week =>  [ 60*180, 70 ],
	month => [ 60*720, 70 ],
	year =>  [ 60*10080, 70 ],
    };

    my ($reso, $count) = @{$setup->{$timeframe}};
    my $ctime  = $reso*int(time()/$reso);
    my $req_start = $ctime - $reso*$count;

    $cf = "AVERAGE" if !$cf;

    my @args = (
	"-s" => $req_start,
	"-e" => $ctime - 1,
	"-r" => $reso,
	);

    push @args, "--daemon" => "unix:${rrdcached_socket}"
	if -S $rrdcached_socket;

    my ($start, $step, $names, $data) = RRDs::fetch($rrd, $cf, @args);

    my $err = RRDs::error;
    die "RRD error: $err\n" if $err;

    die "got wrong time resolution ($step != $reso)\n"
	if $step != $reso;

    my $res = [];
    my $fields = scalar(@$names);
    for my $line (@$data) {
	my $entry = { 'time' => $start };
	$start += $step;
	for (my $i = 0; $i < $fields; $i++) {
	    my $name = $names->[$i];
	    if (defined(my $val = $line->[$i])) {
		$entry->{$name} = $val;
	    } else {
		# leave empty fields undefined
		# maybe make this configurable?
	    }
	}
	push @$res, $entry;
    }

    return $res;
}

sub decode_to_html {
    my ($charset, $data) = @_;

    my $res = $data;

    eval { $res = encode_entities(decode($charset, $data)); };

    return $res;
}

# assume enc contains utf-8 and mime-encoded data returns a perl-string (with wide characters)
sub decode_rfc1522 {
    my ($enc) = @_;

    my $res = '';

    return '' if !$enc;

    eval {
	foreach my $r (MIME::Words::decode_mimewords($enc)) {
	    my ($d, $cs) = @$r;
	    if ($d) {
		if ($cs) {
		    $res .= decode($cs, $d);
		} else {
		    $res .= try_decode_utf8($d);
		}
	    }
	}
    };

    $res = $enc if $@;

    return $res;
}

sub rfc1522_to_html {
    my ($enc) = @_;

    my $res = eval { encode_entities(decode_rfc1522($enc)) };
    return $enc if $@;

    return $res;
}

# RFC 2047 B-ENCODING http://rfc.net/rfc2047.html
# (Q-Encoding is complex and error prone)
sub bencode_header {
    my $txt = shift;

    my $CRLF = "\015\012";

    # Nonprintables (controls + x7F + 8bit):
    my $NONPRINT = "\\x00-\\x1F\\x7F-\\xFF";

    # always use utf-8 (work with japanese character sets)
    $txt = encode("UTF-8", $txt);

    return $txt if $txt !~ /[$NONPRINT]/o;

    my $res = '';

    while ($txt =~ s/^(.{1,42})//sm) {
	my $t = MIME::Words::encode_mimeword ($1, 'B', 'UTF-8');
	$res .= $res ? "\015\012\t$t" : $t;
    }

    return $res;
}

sub user_bl_description {
    return 'From: address is in the user block-list';
}

sub load_sa_descriptions {
    my ($additional_dirs) = @_;

    my @dirs = ('/usr/share/spamassassin',
		'/usr/share/spamassassin-extra');

    push @dirs, @$additional_dirs if @$additional_dirs;

    my $res = {};

    my $parse_sa_file = sub {
	my ($file) = @_;

	open(my $fh,'<', $file);
	return if !defined($fh);

	while (defined(my $line = <$fh>)) {
	    if ($line =~ m/^(?:\s*)describe\s+(\S+)\s+(.*)\s*$/) {
		my ($name, $desc) = ($1, $2);
		next if $res->{$name};
		$res->{$name}->{desc} = $desc;
		if ($desc =~ m|[\(\s](http:\/\/\S+\.[^\s\.\)]+\.[^\s\.\)]+)|i) {
		    $res->{$name}->{url} = $1;
		}
	    }
	}
	close($fh);
    };

    foreach my $dir (@dirs) {
	foreach my $file (<$dir/*.cf>) {
	    $parse_sa_file->($file);
	}
    }

    $res->{'ClamAVHeuristics'}->{desc} = "ClamAV heuristic tests";
    $res->{'USER_IN_BLACKLIST'}->{desc} = user_bl_description();;
    $res->{'USER_IN_BLOCKLIST'}->{desc} = user_bl_description();;

    return $res;
}

sub format_uptime {
    my ($uptime) = @_;

    my $days = int($uptime/86400);
    $uptime -= $days*86400;

    my $hours = int($uptime/3600);
    $uptime -= $hours*3600;

    my $mins = $uptime/60;

    if ($days) {
	my $ds = $days > 1 ? 'days' : 'day';
	return sprintf "%d $ds %02d:%02d", $days, $hours, $mins;
    } else {
	return sprintf "%02d:%02d", $hours, $mins;
    }
}

sub finalize_report {
    my ($tt, $template, $data, $mailfrom, $receiver, $debug) = @_;

    my $html = '';

    $tt->process($template, $data, \$html) ||
	die $tt->error() . "\n";

    my $title;
    if ($html =~ m|^\s*<title>(.*)</title>|m) {
	$title = $1;
    } else {
	die "unable to extract template title\n";
    }

    my $top = MIME::Entity->build(
	Type    => "multipart/related",
	To      => $data->{pmail_raw},
	From    => $mailfrom,
	Subject => bencode_header(decode_entities($title)));

    $top->attach(
	Data     => $html,
	Type     => "text/html",
	Encoding => $debug ? 'binary' : 'quoted-printable');

    if ($debug) {
	$top->print();
	return;
    }
    # we use an empty envelope sender (we don't want to receive NDRs)
    PMG::Utils::reinject_local_mail ($top, '', [$receiver], undef, $data->{fqdn});
}

sub lookup_timespan {
    my ($timespan) = @_;

    my (undef, undef, undef, $mday, $mon, $year) = localtime(time());
    my $daystart = timelocal(0, 0, 0, $mday, $mon, $year);

    my $start;
    my $end;

    if ($timespan eq 'today') {
	$start = $daystart;
	$end = $start + 86400;
    } elsif ($timespan eq 'yesterday') {
	$end = $daystart;
	$start = $end - 86400;
    } elsif ($timespan eq 'week') {
	$end = $daystart;
	$start = $end - 7*86400;
    } else {
	die "internal error";
    }

    return ($start, $end);
}

my $rbl_scan_last_cursor;
my $rbl_scan_start_time = time();

sub scan_journal_for_rbl_rejects {

    # example postscreen log entry for RBL rejects
    # Aug 29 08:00:36 proxmox postfix/postscreen[11266]: NOQUEUE: reject: RCPT from [x.x.x.x]:1234: 550 5.7.1 Service unavailable; client [x.x.x.x] blocked using zen.spamhaus.org; from=<xxxx>, to=<yyyy>, proto=ESMTP, helo=<zzz>

    # example for PREGREET reject
    # Dec  7 06:57:11 proxmox postfix/postscreen[32084]: PREGREET 14 after 0.23 from [x.x.x.x]:63492: EHLO yyyyy\r\n

    my $identifier = 'postfix/postscreen';

    my $rbl_count = 0;
    my $pregreet_count = 0;

    my $parser = sub {
	my $log = decode_json(shift);

	$rbl_scan_last_cursor = $log->{__CURSOR} if defined($log->{__CURSOR});

	my $message = $log->{MESSAGE};
	return if !defined($message);

	if ($message =~ m/^NOQUEUE:\sreject:.*550 5.7.1 Service unavailable/) {
	    $rbl_count++;
	} elsif ($message =~ m/^PREGREET\s\d+\safter\s/) {
	    $pregreet_count++;
	}
    };

    # limit to last 5000 lines to avoid long delays
    my $cmd = ['journalctl', '-o', 'json', '--output-fields', '__CURSOR,MESSAGE',
	'--no-pager', '--identifier', $identifier, '-n', 5000];

    if (defined($rbl_scan_last_cursor)) {
	push @$cmd, "--after-cursor=${rbl_scan_last_cursor}";
    } else {
	push @$cmd, "--since=@" . $rbl_scan_start_time;
    }

    PVE::Tools::run_command($cmd, outfunc => $parser);

    return ($rbl_count, $pregreet_count);
}

my $hwaddress;
my $hwaddress_st = {};

sub get_hwaddress {
    my $fn = '/etc/ssh/ssh_host_rsa_key.pub';
    my $st = stat($fn);

    if (defined($hwaddress)
	&& $hwaddress_st->{mtime} == $st->mtime
	&& $hwaddress_st->{ino} == $st->ino
	&& $hwaddress_st->{dev} == $st->dev) {
	return $hwaddress;
    }

    my $sshkey = PVE::Tools::file_get_contents($fn);
    $hwaddress = uc(Digest::MD5::md5_hex($sshkey));
    $hwaddress_st->@{'mtime', 'ino', 'dev'} = ($st->mtime, $st->ino, $st->dev);

    return $hwaddress;
}

my $default_locale = "en_US.UTF-8 UTF-8";

sub cond_add_default_locale {

    my $filename = "/etc/locale.gen";

    open(my $infh, "<", $filename) || return;

    while (defined(my $line = <$infh>)) {
	if ($line =~ m/^\Q${default_locale}\E/) {
	    # already configured
	    return;
	}
    }

    seek($infh, 0, 0) // return; # seek failed

    open(my $outfh, ">", "$filename.tmp") || return;

    my $done;
    while (defined(my $line = <$infh>)) {
	if ($line =~ m/^#\s*\Q${default_locale}\E.*/) {
	    print $outfh "${default_locale}\n" if !$done;
	    $done = 1;
	} else {
	    print $outfh $line;
	}
    }

    print STDERR "generation pmg default locale\n";

    rename("$filename.tmp", $filename) || return; # rename failed

    system("dpkg-reconfigure locales -f noninteractive");
}

sub postgres_admin_cmd {
    my ($cmd, $options, @params) = @_;

    $cmd = ref($cmd) ? $cmd : [ $cmd ];

    my $save_uid = POSIX::getuid();
    my $pg_uid = getpwnam('postgres') || die "getpwnam postgres failed\n";

    # cd to / to prevent warnings on EPERM (e.g. when running in /root)
    my $cwd = getcwd() || die "getcwd failed - $!\n";
    ($cwd) = ($cwd =~ m|^(/.*)$|); #untaint
    chdir('/') || die "could not chdir to '/' - $!\n";
    PVE::Tools::setresuid(-1, $pg_uid, -1) ||
	die "setresuid postgres ($pg_uid) failed - $!\n";

    PVE::Tools::run_command([@$cmd, '-U', 'postgres', @params], %$options);

    PVE::Tools::setresuid(-1, $save_uid, -1) ||
	die "setresuid back failed - $!\n";

    chdir("$cwd") || die "could not chdir back to old working dir ($cwd) - $!\n";
}

sub get_pg_server_version {
    my $major_ver;
    my $parser = sub {
	my $line = shift;
	# example output:
	# 9.6.13
	# 11.4 (Debian 11.4-1)
	# see https://www.postgresql.org/support/versioning/
	my ($first_comp) = ($line =~ m/^\s*([0-9]+)/);
	if ($first_comp < 10) {
	    ($major_ver) = ($line =~ m/^([0-9]+\.[0-9]+)\.[0-9]+/);
	} else {
	    $major_ver = $first_comp;
	}

    };
    eval {
	postgres_admin_cmd('psql', { outfunc => $parser }, '--quiet',
	'--tuples-only', '--no-align', '--command', 'show server_version;');
    };

    die "Unable to determine currently running Postgresql server version\n"
	if ($@ || !defined($major_ver));

    return $major_ver;
}

sub reload_smtp_filter {

    my $pid_file = '/run/pmg-smtp-filter.pid';
    my $pid = PVE::Tools::file_read_firstline($pid_file);

    return 0 if !$pid;

    return 0 if $pid !~ m/^(\d+)$/;
    $pid = $1; # untaint

    return kill (10, $pid); # send SIGUSR1
}

sub domain_regex {
    my ($domains) = @_;

    my @ra;
    foreach my $d (@$domains) {
	# skip domains with non-DNS name characters
	next if $d =~ m/[^A-Za-z0-9\-\.]/;
	if ($d =~ m/^\.(.*)$/) {
	    my $dom = $1;
	    $dom =~ s/\./\\\./g;
	    push @ra, $dom;
	    push @ra, "\.\*\\.$dom";
	} else {
	    $d =~ s/\./\\\./g;
	    push @ra, $d;
	}
    }

    my $re = join ('|', @ra);

    my $regex = qr/\@($re)$/i;

    return $regex;
}

sub read_sa_channel {
    my ($filename) = @_;

    my $content = PVE::Tools::file_get_contents($filename);
    my $channel = {
	filename => $filename,
    };

    ($channel->{keyid}) = ($content =~ /^KEYID=([a-fA-F0-9]+)$/m);
    die "no KEYID in $filename!\n" if !defined($channel->{keyid});
    ($channel->{channelurl}) = ($content =~ /^CHANNELURL=(.+)$/m);
    die "no CHANNELURL in $filename!\n" if !defined($channel->{channelurl});
    ($channel->{gpgkey}) = ($content =~ /(?:^|\n)(-----BEGIN PGP PUBLIC KEY BLOCK-----.+-----END PGP PUBLIC KEY BLOCK-----)(?:\n|$)/s);
    die "no GPG public key in $filename!\n" if !defined($channel->{gpgkey});

    return $channel;
};

sub local_spamassassin_channels {

    my $res = [];

    my $local_channel_dir = '/etc/mail/spamassassin/channel.d/';

    PVE::Tools::dir_glob_foreach($local_channel_dir, '.*\.conf', sub {
	my ($filename) = @_;
	my $channel = read_sa_channel($local_channel_dir.$filename);
	push(@$res, $channel);
    });

    return $res;
}

sub update_local_spamassassin_channels {
    my ($verbose) = @_;
    # import all configured channel's gpg-keys to sa-update's keyring
    my $localchannels = PMG::Utils::local_spamassassin_channels();
    for my $channel (@$localchannels) {
	my $importcmd = ['sa-update', '--import', $channel->{filename}];
	push @$importcmd, '-v' if $verbose;

	print "Importing gpg key from $channel->{filename}\n" if $verbose;
	PVE::Tools::run_command($importcmd);
    }

    my $fresh_updates = 0;

    for my $channel (@$localchannels) {
	my $cmd = ['sa-update', '--channel', $channel->{channelurl}, '--gpgkey', $channel->{keyid}];
	push @$cmd, '-v' if $verbose;

	print "Updating $channel->{channelurl}\n" if $verbose;
	my $ret = PVE::Tools::run_command($cmd, noerr => 1);
	die "updating $channel->{channelurl} failed - sa-update exited with $ret\n" if $ret >= 2;

	$fresh_updates = 1 if $ret == 0;
    }

    return $fresh_updates
}

sub get_existing_object_id {
    my ($dbh, $obj_id, $obj_type, $value) = @_;

    my $sth = $dbh->prepare("SELECT id FROM Object WHERE ".
	"Objectgroup_ID = ? AND ".
	"ObjectType = ? AND ".
	"Value = ?"
    );
    $sth->execute($obj_id, $obj_type, $value);

    if (my $ref = $sth->fetchrow_hashref()) {
	return $ref->{id};
    }

    return;
}

sub try_decode_utf8 {
    my ($data) = @_;
    return eval { decode('UTF-8', $data, 1) } // $data;
}

sub test_regex {
    my ($regex) = @_;

    # some errors in regex only create warnings e.g. m/^*foo/ others actually cause a
    # die e.g. m/*foo/ - treat a warn die here
    local $SIG{__WARN__} = sub { die @_ };
    eval { "" =~ m/$regex/i; };
    die "invalid regex: $@\n" if $@;

    return undef;
}

1;
