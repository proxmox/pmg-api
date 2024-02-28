package PMG::Config::Base;

use strict;
use warnings;
use URI;
use Data::Dumper;

use PVE::Tools;
use PVE::JSONSchema qw(get_standard_option);
use PVE::SectionConfig;
use PVE::Network;

use base qw(PVE::SectionConfig);

my $defaultData = {
    propertyList => {
	type => { description => "Section type." },
	section => {
	    description => "Section ID.",
	    type => 'string', format => 'pve-configid',
	},
    },
};

sub private {
    return $defaultData;
}

sub format_section_header {
    my ($class, $type, $sectionId) = @_;

    die "internal error ($type ne $sectionId)" if $type ne $sectionId;

    return "section: $type\n";
}


sub parse_section_header {
    my ($class, $line) = @_;

    if ($line =~ m/^section:\s*(\S+)\s*$/) {
	my $section = $1;
	my $errmsg = undef; # set if you want to skip whole section
	eval { PVE::JSONSchema::pve_verify_configid($section); };
	$errmsg = $@ if $@;
	my $config = {}; # to return additional attributes
	return ($section, $section, $errmsg, $config);
    }
    return undef;
}

package PMG::Config::Admin;

use strict;
use warnings;

use base qw(PMG::Config::Base);

sub type {
    return 'admin';
}

sub properties {
    return {
	advfilter => {
	    description => "Enable advanced filters for statistic.",
	    verbose_description => <<EODESC,
Enable advanced filters for statistic.

If this is enabled, the receiver statistic are limited to active ones
(receivers which also sent out mail in the 90 days before), and the contact
statistic will not contain these active receivers.
EODESC
	    type => 'boolean',
	    default => 0,
	},
	dailyreport => {
	    description => "Send daily reports.",
	    type => 'boolean',
	    default => 1,
	},
	statlifetime => {
	    description => "User Statistics Lifetime (days)",
	    type => 'integer',
	    default => 7,
	    minimum => 1,
	},
	demo => {
	    description => "Demo mode - do not start SMTP filter.",
	    type => 'boolean',
	    default => 0,
	},
	email => {
	    description => "Administrator E-Mail address.",
	    type => 'string', format => 'email',
	    default => 'admin@domain.tld',
	},
	http_proxy => {
	    description => "Specify external http proxy which is used for downloads (example: 'http://username:password\@host:port/')",
	    type => 'string',
	    pattern => "http://.*",
	},
	avast => {
	    description => "Use Avast Virus Scanner (/usr/bin/scan). You need to buy and install 'Avast Core Security' before you can enable this feature.",
	    type => 'boolean',
	    default => 0,
	},
	clamav => {
	    description => "Use ClamAV Virus Scanner. This is the default virus scanner and is enabled by default.",
	    type => 'boolean',
	    default => 1,
	},
	custom_check => {
	    description => "Use Custom Check Script. The script has to take the defined arguments and can return Virus findings or a Spamscore.",
	    type => 'boolean',
	    default => 0,
	},
	custom_check_path => {
	    description => "Absolute Path to the Custom Check Script",
	    type => 'string', pattern => '^/([^/\0]+\/)+[^/\0]+$',
	    default => '/usr/local/bin/pmg-custom-check',
	},
	dkim_sign => {
	    description => "DKIM sign outbound mails with the configured Selector.",
	    type => 'boolean',
	    default => 0,
	},
	dkim_sign_all_mail => {
	    description => "DKIM sign all outgoing mails irrespective of the Envelope From domain.",
	    type => 'boolean',
	    default => 0,
	},
	dkim_selector => {
	    description => "Default DKIM selector",
	    type => 'string', format => 'dns-name', #see RFC6376 3.1
	},
	'dkim-use-domain' => {
	    description => "Whether to sign using the domain found in the header or the envelope.",
	    type => 'string',
	    enum => [qw(header envelope)],
	    default => 'envelope',
	},
    };
}

sub options {
    return {
	advfilter => { optional => 1 },
	avast => { optional => 1 },
	clamav => { optional => 1 },
	statlifetime => { optional => 1 },
	dailyreport => { optional => 1 },
	demo => { optional => 1 },
	email => { optional => 1 },
	http_proxy => { optional => 1 },
	custom_check => { optional => 1 },
	custom_check_path => { optional => 1 },
	dkim_sign => { optional => 1 },
	dkim_sign_all_mail => { optional => 1 },
	dkim_selector => { optional => 1 },
	'dkim-use-domain' => { optional => 1 },
    };
}

package PMG::Config::Spam;

use strict;
use warnings;

use base qw(PMG::Config::Base);

sub type {
    return 'spam';
}

sub properties {
    return {
	languages => {
	    description => "This option is used to specify which languages are considered OK for incoming mail.",
	    type => 'string',
	    pattern => '(all|([a-z][a-z])+( ([a-z][a-z])+)*)',
	    default => 'all',
	},
	use_bayes => {
	    description => "Whether to use the naive-Bayesian-style classifier.",
	    type => 'boolean',
	    default => 0,
	},
	use_awl => {
	    description => "Use the Auto-Whitelist plugin.",
	    type => 'boolean',
	    default => 0,
	},
	use_razor => {
	    description => "Whether to use Razor2, if it is available.",
	    type => 'boolean',
	    default => 1,
	},
	wl_bounce_relays => {
	    description => "Whitelist legitimate bounce relays.",
	    type => 'string',
	},
	clamav_heuristic_score => {
	    description => "Score for ClamAV heuristics (Encrypted Archives/Documents, PhishingScanURLs, ...).",
	    type => 'integer',
	    minimum => 0,
	    maximum => 1000,
	    default => 3,
	},
	bounce_score => {
	    description => "Additional score for bounce mails.",
	    type => 'integer',
	    minimum => 0,
	    maximum => 1000,
	    default => 0,
	},
	rbl_checks => {
	    description => "Enable real time blacklists (RBL) checks.",
	    type => 'boolean',
	    default => 1,
	},
	maxspamsize => {
	    description => "Maximum size of spam messages in bytes.",
	    type => 'integer',
	    minimum => 64,
	    default => 256*1024,
	},
	extract_text => {
	    description => "Extract text from attachments (doc, pdf, rtf, images) and scan for spam.",
	    type => 'boolean',
	    default => 0,
	},
    };
}

sub options {
    return {
	use_awl => { optional => 1 },
	use_razor => { optional => 1 },
	wl_bounce_relays => { optional => 1 },
	languages => { optional => 1 },
	use_bayes => { optional => 1 },
	clamav_heuristic_score => { optional => 1 },
	bounce_score => { optional => 1 },
	rbl_checks => { optional => 1 },
	maxspamsize => { optional => 1 },
	extract_text => { optional => 1 },
    };
}

package PMG::Config::SpamQuarantine;

use strict;
use warnings;

use base qw(PMG::Config::Base);

sub type {
    return 'spamquar';
}

sub properties {
    return {
	lifetime => {
	    description => "Quarantine life time (days)",
	    type => 'integer',
	    minimum => 1,
	    default => 7,
	},
	authmode => {
	    description => "Authentication mode to access the quarantine interface. Mode 'ticket' allows login using tickets sent with the daily spam report. Mode 'ldap' requires to login using an LDAP account. Finally, mode 'ldapticket' allows both ways.",
	    type => 'string',
	    enum => [qw(ticket ldap ldapticket)],
	    default => 'ticket',
	},
	reportstyle => {
	    description => "Spam report style.",
	    type => 'string',
	    enum => [qw(none short verbose custom)],
	    default => 'verbose',
	},
	viewimages => {
	    description => "Allow to view images.",
	    type => 'boolean',
	    default => 1,
	},
	allowhrefs => {
	    description => "Allow to view hyperlinks.",
	    type => 'boolean',
	    default => 1,
	},
	hostname => {
	    description => "Quarantine Host. Useful if you run a Cluster and want users to connect to a specific host.",
	    type => 'string', format => 'address',
	},
	port => {
	    description => "Quarantine Port. Useful if you have a reverse proxy or port forwarding for the webinterface. Only used for the generated Spam report.",
	    type => 'integer',
	    minimum => 1,
	    maximum => 65535,
	    default => 8006,
	},
	protocol => {
	    description => "Quarantine Webinterface Protocol. Useful if you have a reverse proxy for the webinterface. Only used for the generated Spam report.",
	    type => 'string',
	    enum => [qw(http https)],
	    default => 'https',
	},
	mailfrom => {
	    description => "Text for 'From' header in daily spam report mails.",
	    type => 'string',
	},
	quarantinelink => {
	    description => "Enables user self-service for Quarantine Links. Caution: this is accessible without authentication",
	    type => 'boolean',
	    default => 0,
	},
    };
}

sub options {
    return {
	mailfrom => { optional => 1 },
	hostname => { optional => 1 },
	lifetime => { optional => 1 },
	authmode => { optional => 1 },
	reportstyle => { optional => 1 },
	viewimages => { optional => 1 },
	allowhrefs => { optional => 1 },
	port => { optional => 1 },
	protocol => { optional => 1 },
	quarantinelink => { optional => 1 },
    };
}

package PMG::Config::VirusQuarantine;

use strict;
use warnings;

use base qw(PMG::Config::Base);

sub type {
    return 'virusquar';
}

sub properties {
    return {};
}

sub options {
    return {
	lifetime => { optional => 1 },
	viewimages => { optional => 1 },
	allowhrefs => { optional => 1 },
    };
}

package PMG::Config::ClamAV;

use strict;
use warnings;

use base qw(PMG::Config::Base);

sub type {
    return 'clamav';
}

sub properties {
    return {
	dbmirror => {
	    description => "ClamAV database mirror server.",
	    type => 'string',
	    default => 'database.clamav.net',
	},
	archiveblockencrypted => {
	    description => "Whether to mark encrypted archives and documents as heuristic virus match. A match does not necessarily result in an immediate block, it just raises the Spam Score by 'clamav_heuristic_score'.",
	    type => 'boolean',
	    default => 0,
	},
	archivemaxrec => {
	    description => "Nested archives are scanned recursively, e.g. if a ZIP archive contains a TAR  file,  all files within it will also be scanned. This options specifies how deeply the process should be continued. Warning: setting this limit too high may result in severe damage to the system.",
	    type => 'integer',
	    minimum => 1,
	    default => 5,
	},
	archivemaxfiles => {
	    description => "Number of files to be scanned within an archive, a document, or any other kind of container. Warning: disabling this limit or setting it too high may result in severe damage to the system.",
	    type => 'integer',
	    minimum => 0,
	    default => 1000,
	},
	archivemaxsize => {
	    description => "Files larger than this limit (in bytes) won't be scanned.",
	    type => 'integer',
	    minimum => 1000000,
	    default => 25000000,
	},
	maxscansize => {
	    description => "Sets the maximum amount of data (in bytes) to be scanned for each input file.",
	    type => 'integer',
	    minimum => 1000000,
	    default => 100000000,
	},
	maxcccount => {
	    description => "This option sets the lowest number of Credit Card or Social Security numbers found in a file to generate a detect.",
	    type => 'integer',
	    minimum => 0,
	    default => 0,
	},
	# FIXME: remove for PMG 8.0 - https://blog.clamav.net/2021/04/are-you-still-attempting-to-download.html
	safebrowsing => {
	    description => "Enables support for Google Safe Browsing. (deprecated option, will be ignored)",
	    type => 'boolean',
	    default => 0
	},
	scriptedupdates => {
	    description => "Enables ScriptedUpdates (incremental download of signatures)",
	    type => 'boolean',
	    default => 1
	},
    };
}

sub options {
    return {
	archiveblockencrypted => { optional => 1 },
	archivemaxrec => { optional => 1 },
	archivemaxfiles => { optional => 1 },
	archivemaxsize => { optional => 1 },
	maxscansize  => { optional => 1 },
	dbmirror => { optional => 1 },
	maxcccount => { optional => 1 },
	safebrowsing => { optional => 1 }, # FIXME: remove for PMG 8.0
	scriptedupdates => { optional => 1},
    };
}

package PMG::Config::Mail;

use strict;
use warnings;

use PVE::ProcFSTools;

use base qw(PMG::Config::Base);

sub type {
    return 'mail';
}

my $physicalmem = 0;
sub physical_memory {

    return $physicalmem if $physicalmem;

    my $info = PVE::ProcFSTools::read_meminfo();
    my $total = int($info->{memtotal} / (1024*1024));

    return $total;
}

# heuristic for optimal number of smtp-filter servers
sub get_max_filters {
    my $max_servers = 5;
    my $per_server_memory_usage = 150;

    my $memory = physical_memory();

    my $base_memory_usage; # the estimated base load of the system
    if ($memory < 3840) { # 3.75 GiB
	my $memory_gb = sprintf('%.1f', $memory/1024.0);
	my $warn_str = $memory <= 1900 ? 'minimum 2' : 'recommended 4';
	warn "system memory size of $memory_gb GiB is below the ${warn_str}+ GiB limit!\n";

	$base_memory_usage = int($memory * 0.625); # for small system assume 5/8 for base system
	$base_memory_usage = 512 if $base_memory_usage < 512;
    } else {
	$base_memory_usage = 2560; # 2.5 GiB
    }
    my $add_servers = int(($memory - $base_memory_usage)/$per_server_memory_usage);
    $max_servers += $add_servers if $add_servers > 0;
    $max_servers = 40 if  $max_servers > 40;

    return $max_servers - 2;
}

sub get_max_smtpd {
    # estimate optimal number of smtpd daemons

    my $max_servers = 25;
    my $servermem = 20;
    my $memory = physical_memory();
    my $add_servers = int(($memory - 512)/$servermem);
    $max_servers += $add_servers if $add_servers > 0;
    $max_servers = 100 if  $max_servers > 100;
    return $max_servers;
}

sub get_max_policy {
    # estimate optimal number of proxpolicy servers
    my $max_servers = 2;
    my $memory = physical_memory();
    $max_servers = 5 if  $memory >= 500;
    return $max_servers;
}

sub properties {
    return {
	int_port => {
	    description => "SMTP port number for outgoing mail (trusted).",
	    type => 'integer',
	    minimum => 1,
	    maximum => 65535,
	    default => 26,
	},
	ext_port => {
	    description => "SMTP port number for incoming mail (untrusted). This must be a different number than 'int_port'.",
	    type => 'integer',
	    minimum => 1,
	    maximum => 65535,
	    default => 25,
	},
	relay => {
	    description => "The default mail delivery transport (incoming mails).",
	    type => 'string', format => 'address',
	},
	relayprotocol => {
	    description => "Transport protocol for relay host.",
	    type => 'string',
	    enum => [qw(smtp lmtp)],
	    default => 'smtp',
	},
	relayport => {
	    description => "SMTP/LMTP port number for relay host.",
	    type => 'integer',
	    minimum => 1,
	    maximum => 65535,
	    default => 25,
	},
	relaynomx => {
	    description => "Disable MX lookups for default relay (SMTP only, ignored for LMTP).",
	    type => 'boolean',
	    default => 0,
	},
	smarthost => {
	    description => "When set, all outgoing mails are deliverd to the specified smarthost."
	        ." (postfix option `default_transport`)",
	    type => 'string', format => 'address',
	},
	smarthostport => {
	    description => "SMTP port number for smarthost. (postfix option `default_transport`)",
	    type => 'integer',
	    minimum => 1,
	    maximum => 65535,
	    default => 25,
	},
	banner => {
	    description => "ESMTP banner.",
	    type => 'string',
	    maxLength => 1024,
	    default => 'ESMTP Proxmox',
	},
	max_filters => {
	    description => "Maximum number of pmg-smtp-filter processes.",
	    type => 'integer',
	    minimum => 3,
	    maximum => 40,
	    default => get_max_filters(),
	},
	max_policy => {
	    description => "Maximum number of pmgpolicy processes.",
	    type => 'integer',
	    minimum => 2,
	    maximum => 10,
	    default => get_max_policy(),
	},
	max_smtpd_in => {
	    description => "Maximum number of SMTP daemon processes (in).",
	    type => 'integer',
	    minimum => 3,
	    maximum => 100,
	    default => get_max_smtpd(),
	},
	max_smtpd_out => {
	    description => "Maximum number of SMTP daemon processes (out).",
	    type => 'integer',
	    minimum => 3,
	    maximum => 100,
	    default => get_max_smtpd(),
	},
	conn_count_limit => {
	    description => "How many simultaneous connections any client is allowed to make to this service. To disable this feature, specify a limit of 0.",
	    type => 'integer',
	    minimum => 0,
	    default => 50,
	},
	conn_rate_limit => {
	    description => "The maximal number of connection attempts any client is allowed to make to this service per minute. To disable this feature, specify a limit of 0.",
	    type => 'integer',
	    minimum => 0,
	    default => 0,
	},
	message_rate_limit => {
	    description => "The maximal number of message delivery requests that any client is allowed to make to this service per minute.To disable this feature, specify a limit of 0.",
	    type => 'integer',
	    minimum => 0,
	    default => 0,
	},
	hide_received => {
	    description => "Hide received header in outgoing mails.",
	    type => 'boolean',
	    default => 0,
	},
	maxsize => {
	    description => "Maximum email size. Larger mails are rejected. (postfix option `message_size_limit`)",
	    type => 'integer',
	    minimum => 1024,
	    default => 1024*1024*10,
	},
	dwarning => {
	    description => "SMTP delay warning time (in hours). (postfix option `delay_warning_time`)",
	    type => 'integer',
	    minimum => 0,
	    default => 4,
	},
	tls => {
	    description => "Enable TLS.",
	    type => 'boolean',
	    default => 0,
	},
	tlslog => {
	    description => "Enable TLS Logging.",
	    type => 'boolean',
	    default => 0,
	},
	tlsheader => {
	    description => "Add TLS received header.",
	    type => 'boolean',
	    default => 0,
	},
	spf => {
	    description => "Use Sender Policy Framework.",
	    type => 'boolean',
	    default => 1,
	},
	greylist => {
	    description => "Use Greylisting for IPv4.",
	    type => 'boolean',
	    default => 1,
	},
	greylistmask4 => {
	    description => "Netmask to apply for greylisting IPv4 hosts",
	    type => 'integer',
	    minimum => 0,
	    maximum => 32,
	    default => 24,
	},
	greylist6 => {
	    description => "Use Greylisting for IPv6.",
	    type => 'boolean',
	    default => 0,
	},
	greylistmask6 => {
	    description => "Netmask to apply for greylisting IPv6 hosts",
	    type => 'integer',
	    minimum => 0,
	    maximum => 128,
	    default => 64,
	},
	helotests => {
	    description => "Use SMTP HELO tests. (postfix option `smtpd_helo_restrictions`)",
	    type => 'boolean',
	    default => 0,
	},
	rejectunknown => {
	    description => "Reject unknown clients. (postfix option `reject_unknown_client_hostname`)",
	    type => 'boolean',
	    default => 0,
	},
	rejectunknownsender => {
	    description => "Reject unknown senders. (postfix option `reject_unknown_sender_domain`)",
	    type => 'boolean',
	    default => 0,
	},
	verifyreceivers => {
	    description => "Enable receiver verification. The value specifies the numerical reply"
	        ." code when the Postfix SMTP server rejects a recipient address."
	        ." (postfix options `reject_unknown_recipient_domain`, `reject_unverified_recipient`,"
	        ." and `unverified_recipient_reject_code`)",
	    type => 'string',
	    enum => ['450', '550'],
	},
	dnsbl_sites => {
	    description => "Optional list of DNS white/blacklist domains (postfix option `postscreen_dnsbl_sites`).",
	    type => 'string', format => 'dnsbl-entry-list',
	},
	dnsbl_threshold => {
	    description => "The inclusive lower bound for blocking a remote SMTP client, based on"
	        ." its combined DNSBL score (postfix option `postscreen_dnsbl_threshold`).",
	    type => 'integer',
	    minimum => 0,
	    default => 1
	},
	before_queue_filtering => {
	    description => "Enable before queue filtering by pmg-smtp-filter",
	    type => 'boolean',
	    default => 0
	},
	ndr_on_block => {
	    description => "Send out NDR when mail gets blocked",
	    type => 'boolean',
	    default => 0
	},
	smtputf8 => {
	    description => "Enable SMTPUTF8 support in Postfix and detection for locally generated mail (postfix option `smtputf8_enable`)",
	    type => 'boolean',
	    default => 1
	},
	'filter-timeout' => {
	    description => "Timeout for the processing of one mail (in seconds)  (postfix option"
		." `smtpd_proxy_timeout` and `lmtp_data_done_timeout`)",
	    type => 'integer',
	    default => 600,
	    minimum => 2,
	    maximum => 86400
	},
    };
}

sub options {
    return {
	int_port => { optional => 1 },
	ext_port => { optional => 1 },
	smarthost => { optional => 1 },
	smarthostport => { optional => 1 },
	relay => { optional => 1 },
	relayprotocol => { optional => 1 },
	relayport => { optional => 1 },
	relaynomx => { optional => 1 },
	dwarning => { optional => 1 },
	max_smtpd_in => { optional => 1 },
	max_smtpd_out => { optional => 1 },
	greylist => { optional => 1 },
	greylistmask4 => { optional => 1 },
	greylist6 => { optional => 1 },
	greylistmask6 => { optional => 1 },
	helotests => { optional => 1 },
	tls => { optional => 1 },
	tlslog => { optional => 1 },
	tlsheader => { optional => 1 },
	spf => { optional => 1 },
	maxsize => { optional => 1 },
	banner => { optional => 1 },
	max_filters => { optional => 1 },
	max_policy => { optional => 1 },
	hide_received => { optional => 1 },
	rejectunknown => { optional => 1 },
	rejectunknownsender => { optional => 1 },
	conn_count_limit => { optional => 1 },
	conn_rate_limit => { optional => 1 },
	message_rate_limit => { optional => 1 },
	verifyreceivers => { optional => 1 },
	dnsbl_sites => { optional => 1 },
	dnsbl_threshold => { optional => 1 },
	before_queue_filtering => { optional => 1 },
	ndr_on_block => { optional => 1 },
	smtputf8 => { optional => 1 },
	'filter-timeout' => { optional => 1 },
    };
}

package PMG::Config;

use strict;
use warnings;
use IO::File;
use Data::Dumper;
use Template;

use PVE::SafeSyslog;
use PVE::Tools qw($IPV4RE $IPV6RE);
use PVE::INotify;
use PVE::JSONSchema;

use PMG::Cluster;
use PMG::Utils;

PMG::Config::Admin->register();
PMG::Config::Mail->register();
PMG::Config::SpamQuarantine->register();
PMG::Config::VirusQuarantine->register();
PMG::Config::Spam->register();
PMG::Config::ClamAV->register();

# initialize all plugins
PMG::Config::Base->init();

PVE::JSONSchema::register_format(
    'transport-domain', \&pmg_verify_transport_domain);

sub pmg_verify_transport_domain {
    my ($name, $noerr) = @_;

    # like dns-name, but can contain leading dot
    my $namere = "([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)";

    if ($name !~ /^\.?(${namere}\.)*${namere}$/) {
	   return undef if $noerr;
	   die "value does not look like a valid transport domain\n";
    }
    return $name;
}

PVE::JSONSchema::register_format(
    'transport-domain-or-email', \&pmg_verify_transport_domain_or_email);

sub pmg_verify_transport_domain_or_email {
    my ($name, $noerr) = @_;

    my $namere = "([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)";

    # email address
    if ($name =~ m/^(?:[^\s\/\@]+\@)(${namere}\.)*${namere}$/) {
	return $name;
    }

    # like dns-name, but can contain leading dot
    if ($name !~ /^\.?(${namere}\.)*${namere}$/) {
	   return undef if $noerr;
	   die "value does not look like a valid transport domain or email address\n";
    }
    return $name;
}

PVE::JSONSchema::register_format(
    'dnsbl-entry', \&pmg_verify_dnsbl_entry);

sub pmg_verify_dnsbl_entry {
    my ($name, $noerr) = @_;

    # like dns-name, but can contain trailing filter and weight: 'domain=<FILTER>*<WEIGHT>'
    # see http://www.postfix.org/postconf.5.html#postscreen_dnsbl_sites
    # we don't implement the ';' separated numbers in pattern, because this
    # breaks at PVE::JSONSchema::split_list
    my $namere = "([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)";

    my $dnsbloctet = qr/[0-9]+|\[(?:[0-9]+\.\.[0-9]+)\]/;
    my $filterre = qr/=$dnsbloctet(:?\.$dnsbloctet){3}/;
    if ($name !~ /^(${namere}\.)*${namere}(:?${filterre})?(?:\*\-?\d+)?$/) {
	   return undef if $noerr;
	   die "value '$name' does not look like a valid dnsbl entry\n";
    }
    return $name;
}

sub new {
    my ($type) = @_;

    my $class = ref($type) || $type;

    my $cfg = PVE::INotify::read_file("pmg.conf");

    return bless $cfg, $class;
}

sub write {
    my ($self) = @_;

    PVE::INotify::write_file("pmg.conf", $self);
}

my $lockfile = "/var/lock/pmgconfig.lck";

sub lock_config {
    my ($code, $errmsg) = @_;

    my $p = PVE::Tools::lock_file($lockfile, undef, $code);
    if (my $err = $@) {
	$errmsg ? die "$errmsg: $err" : die $err;
    }
}

# set section values
sub set {
    my ($self, $section, $key, $value) = @_;

    my $pdata = PMG::Config::Base->private();

    my $plugin = $pdata->{plugins}->{$section};
    die "no such section '$section'" if !$plugin;

    if (defined($value)) {
	my $tmp = PMG::Config::Base->check_value($section, $key, $value, $section, 0);
	$self->{ids}->{$section} = { type => $section } if !defined($self->{ids}->{$section});
	$self->{ids}->{$section}->{$key} = PMG::Config::Base->decode_value($section, $key, $tmp);
    } else {
	if (defined($self->{ids}->{$section})) {
	    delete $self->{ids}->{$section}->{$key};
	}
    }

    return undef;
}

# get section value or default
sub get {
    my ($self, $section, $key, $nodefault) = @_;

    my $pdata = PMG::Config::Base->private();
    my $schema = $pdata->{propertyList}->{$key} // die "no schema for property '$section/$key'\n";
    my $options = $pdata->{options}->{$section} // die "no options for section '$section/$key'\n";

    die "no such property '$section/$key'\n"
	if !(defined($schema) && defined($options) && defined($options->{$key}));

    my $values = $self->{ids}->{$section};
    return $values->{$key} if defined($values) && defined($values->{$key});

    return undef if $nodefault;

    return $schema->{default};
}

# get a whole section with default value
sub get_section {
    my ($self, $section) = @_;

    my $pdata = PMG::Config::Base->private();
    return undef if !defined($pdata->{options}->{$section});

    my $res = {};

    foreach my $key (keys %{$pdata->{options}->{$section}}) {

	my $pdesc = $pdata->{propertyList}->{$key};

	if (defined($self->{ids}->{$section}) &&
	    defined(my $value = $self->{ids}->{$section}->{$key})) {
	    $res->{$key} = $value;
	    next;
	}
	$res->{$key} = $pdesc->{default};
    }

    return $res;
}

# get a whole config with default values
sub get_config {
    my ($self) = @_;

    my $pdata = PMG::Config::Base->private();

    my $res = {};

    foreach my $type (keys %{$pdata->{plugins}}) {
	my $plugin = $pdata->{plugins}->{$type};
	$res->{$type} = $self->get_section($type);
    }

    return $res;
}

sub read_pmg_conf {
    my ($filename, $fh) = @_;

    my $raw;
    $raw = do { local $/ = undef; <$fh> } if defined($fh);

    return  PMG::Config::Base->parse_config($filename, $raw);
}

sub write_pmg_conf {
    my ($filename, $fh, $cfg) = @_;

    my $raw = PMG::Config::Base->write_config($filename, $cfg);

    PVE::Tools::safe_print($filename, $fh, $raw);
}

PVE::INotify::register_file('pmg.conf', "/etc/pmg/pmg.conf",
			    \&read_pmg_conf,
			    \&write_pmg_conf,
			    undef, always_call_parser => 1);

# parsers/writers for other files

my $domainsfilename = "/etc/pmg/domains";

sub postmap_pmg_domains {
    PMG::Utils::run_postmap($domainsfilename);
}

sub read_pmg_domains {
    my ($filename, $fh) = @_;

    my $domains = {};

    my $comment = '';
    if (defined($fh)) {
	while (defined(my $line = <$fh>)) {
	    chomp $line;
	    next if $line =~ m/^\s*$/;
	    if ($line =~ m/^#(.*)\s*$/) {
		$comment = $1;
		next;
	    }
	    if ($line =~ m/^(\S+)\s.*$/) {
		my $domain = $1;
		$domains->{$domain} = {
		    domain => $domain, comment => $comment };
		$comment = '';
	    } else {
		warn "parse error in '$filename': $line\n";
		$comment = '';
	    }
	}
    }

    return $domains;
}

sub write_pmg_domains {
    my ($filename, $fh, $domains) = @_;

    foreach my $domain (sort keys %$domains) {
	my $comment = $domains->{$domain}->{comment};
	PVE::Tools::safe_print($filename, $fh, "#$comment\n")
	    if defined($comment) && $comment !~ m/^\s*$/;

	PVE::Tools::safe_print($filename, $fh, "$domain 1\n");
    }
}

PVE::INotify::register_file('domains', $domainsfilename,
			    \&read_pmg_domains,
			    \&write_pmg_domains,
			    undef, always_call_parser => 1);

my $dkimdomainsfile = '/etc/pmg/dkim/domains';

PVE::INotify::register_file('dkimdomains', $dkimdomainsfile,
			    \&read_pmg_domains,
			    \&write_pmg_domains,
			    undef, always_call_parser => 1);

my $mynetworks_filename = "/etc/pmg/mynetworks";

sub read_pmg_mynetworks {
    my ($filename, $fh) = @_;

    my $mynetworks = {};

    my $comment = '';
    if (defined($fh)) {
	while (defined(my $line = <$fh>)) {
	    chomp $line;
	    next if $line =~ m/^\s*$/;
	    if ($line =~ m!^((?:$IPV4RE|$IPV6RE))/(\d+)\s*(?:#(.*)\s*)?$!) {
		my ($network, $prefix_size, $comment) = ($1, $2, $3);
		my $cidr = "$network/${prefix_size}";
		# FIXME: Drop unused `network_address` and `prefix_size` with PMG 8.0
		$mynetworks->{$cidr} = {
		    cidr => $cidr,
		    network_address => $network,
		    prefix_size => $prefix_size,
		    comment => $comment // '',
		};
	    } else {
		warn "parse error in '$filename': $line\n";
	    }
	}
    }

    return $mynetworks;
}

sub write_pmg_mynetworks {
    my ($filename, $fh, $mynetworks) = @_;

    foreach my $cidr (sort keys %$mynetworks) {
	my $data = $mynetworks->{$cidr};
	my $comment = $data->{comment} // '*';
	PVE::Tools::safe_print($filename, $fh, "$cidr #$comment\n");
    }
}

PVE::INotify::register_file('mynetworks', $mynetworks_filename,
			    \&read_pmg_mynetworks,
			    \&write_pmg_mynetworks,
			    undef, always_call_parser => 1);

PVE::JSONSchema::register_format(
    'tls-policy', \&pmg_verify_tls_policy);

# TODO: extend to parse attributes of the policy
my $VALID_TLS_POLICY_RE = qr/none|may|encrypt|dane|dane-only|fingerprint|verify|secure/;
sub pmg_verify_tls_policy {
    my ($policy, $noerr) = @_;

    if ($policy !~ /^$VALID_TLS_POLICY_RE\b/) {
	   return undef if $noerr;
	   die "value '$policy' does not look like a valid tls policy\n";
    }
    return $policy;
}

PVE::JSONSchema::register_format(
    'tls-policy-strict', \&pmg_verify_tls_policy_strict);

sub pmg_verify_tls_policy_strict {
    my ($policy, $noerr) = @_;

    if ($policy !~ /^$VALID_TLS_POLICY_RE$/) {
	return undef if $noerr;
	die "value '$policy' does not look like a valid tls policy\n";
    }
    return $policy;
}

PVE::JSONSchema::register_format(
    'transport-domain-or-nexthop', \&pmg_verify_transport_domain_or_nexthop);

sub pmg_verify_transport_domain_or_nexthop {
    my ($name, $noerr) = @_;

    if (pmg_verify_transport_domain($name, 1)) {
	return $name;
    } elsif ($name =~ m/^(\S+)(?::\d+)?$/) {
	my $nexthop = $1;
	if ($nexthop =~ m/^\[(.*)\]$/) {
	    $nexthop = $1;
	}
	return $name if pmg_verify_transport_address($nexthop, 1);
    } else {
	   return undef if $noerr;
	   die "value does not look like a valid domain or next-hop\n";
    }
}

sub read_tls_policy {
    my ($filename, $fh) = @_;

    return {} if !defined($fh);

    my $tls_policy = {};

    while (defined(my $line = <$fh>)) {
	chomp $line;
	next if $line =~ m/^\s*$/;
	next if $line =~ m/^#(.*)\s*$/;

	my $parse_error = sub {
	    my ($err) = @_;
	    warn "parse error in '$filename': $line - $err\n";
	};

	if ($line =~ m/^(\S+)\s+(.+)\s*$/) {
	    my ($destination, $policy) = ($1, $2);

	    eval {
		pmg_verify_transport_domain_or_nexthop($destination);
		pmg_verify_tls_policy($policy);
	    };
	    if (my $err = $@) {
		$parse_error->($err);
		next;
	    }

	    $tls_policy->{$destination} = {
		    destination => $destination,
		    policy => $policy,
	    };
	} else {
	    $parse_error->('wrong format');
	}
    }

    return $tls_policy;
}

sub write_tls_policy {
    my ($filename, $fh, $tls_policy) = @_;

    return if !$tls_policy;

    foreach my $destination (sort keys %$tls_policy) {
	my $entry = $tls_policy->{$destination};
	PVE::Tools::safe_print(
	    $filename, $fh, "$entry->{destination} $entry->{policy}\n");
    }
}

my $tls_policy_map_filename = "/etc/pmg/tls_policy";
PVE::INotify::register_file('tls_policy', $tls_policy_map_filename,
			    \&read_tls_policy,
			    \&write_tls_policy,
			    undef, always_call_parser => 1);

sub postmap_tls_policy {
    PMG::Utils::run_postmap($tls_policy_map_filename);
}

sub read_tls_inbound_domains {
    my ($filename, $fh) = @_;

    return {} if !defined($fh);

    my $domains = {};

    while (defined(my $line = <$fh>)) {
	chomp $line;
	next if $line =~ m/^\s*$/;
	next if $line =~ m/^#(.*)\s*$/;

	my $parse_error = sub {
	    my ($err) = @_;
	    warn "parse error in '$filename': $line - $err\n";
	};

	if ($line =~ m/^(\S+) reject_plaintext_session$/) {
	    my $domain = $1;

	    eval { pmg_verify_transport_domain($domain) };
	    if (my $err = $@) {
		$parse_error->($err);
		next;
	    }

	    $domains->{$domain} = 1;
	} else {
	    $parse_error->('wrong format');
	}
    }

    return $domains;
}

sub write_tls_inbound_domains {
    my ($filename, $fh, $domains) = @_;

    return if !$domains;

    foreach my $domain (sort keys %$domains) {
	PVE::Tools::safe_print($filename, $fh, "$domain reject_plaintext_session\n");
    }
}

my $tls_inbound_domains_map_filename = "/etc/pmg/tls_inbound_domains";
PVE::INotify::register_file('tls_inbound_domains', $tls_inbound_domains_map_filename,
			    \&read_tls_inbound_domains,
			    \&write_tls_inbound_domains,
			    undef, always_call_parser => 1);

sub postmap_tls_inbound_domains {
    PMG::Utils::run_postmap($tls_inbound_domains_map_filename);
}

my $transport_map_filename = "/etc/pmg/transport";

sub postmap_pmg_transport {
    PMG::Utils::run_postmap($transport_map_filename);
}

PVE::JSONSchema::register_format(
    'transport-address', \&pmg_verify_transport_address);

sub pmg_verify_transport_address {
    my ($name, $noerr) = @_;

    if ($name =~ m/^ipv6:($IPV6RE)$/i) {
	return $name;
    } elsif (PVE::JSONSchema::pve_verify_address($name, 1)) {
	return $name;
    } else {
	return undef if $noerr;
	die "value does not look like a valid address\n";
    }
}

sub read_transport_map {
    my ($filename, $fh) = @_;

    return [] if !defined($fh);

    my $res = {};

    my $comment = '';

    while (defined(my $line = <$fh>)) {
	chomp $line;
	next if $line =~ m/^\s*$/;
	if ($line =~ m/^#(.*)\s*$/) {
	    $comment = $1;
	    next;
	}

	my $parse_error = sub {
	    my ($err) = @_;
	    warn "parse error in '$filename': $line - $err";
	    $comment = '';
	};

	if ($line =~ m/^(\S+)\s+(?:(lmtp):inet|(smtp)):(\S+):(\d+)\s*$/) {
	    my ($domain, $protocol, $host, $port) = ($1, ($2 or $3), $4, $5);

	    eval { pmg_verify_transport_domain_or_email($domain); };
	    if (my $err = $@) {
		$parse_error->($err);
		next;
	    }
	    my $use_mx = 1;
	    if ($host =~ m/^\[(.*)\]$/) {
		$host = $1;
		$use_mx = 0;
	    }
	    $use_mx = 0 if ($protocol eq "lmtp");

	    eval { pmg_verify_transport_address($host); };
	    if (my $err = $@) {
		$parse_error->($err);
		next;
	    }

	    my $data = {
		domain => $domain,
		protocol => $protocol,
		host => $host,
		port => $port,
		use_mx => $use_mx,
		comment => $comment,
	    };
	    $res->{$domain} = $data;
	    $comment = '';
	} else {
	    $parse_error->('wrong format');
	}
    }

    return $res;
}

sub write_transport_map {
    my ($filename, $fh, $tmap) = @_;

    return if !$tmap;

    foreach my $domain (sort keys %$tmap) {
	my $data = $tmap->{$domain};

	my $comment = $data->{comment};
	PVE::Tools::safe_print($filename, $fh, "#$comment\n")
	    if defined($comment) && $comment !~ m/^\s*$/;

	my $bracket_host = !$data->{use_mx};

	if ($data->{protocol} eq 'lmtp') {
	    $bracket_host = 0;
	    $data->{protocol} .= ":inet";
	}
	$bracket_host = 1 if $data->{host} =~ m/^(?:$IPV4RE|(?:ipv6:)?$IPV6RE)$/i;
	my $host = $bracket_host ? "[$data->{host}]" : $data->{host};

	PVE::Tools::safe_print($filename, $fh, "$data->{domain} $data->{protocol}:$host:$data->{port}\n");
    }
}

PVE::INotify::register_file('transport', $transport_map_filename,
			    \&read_transport_map,
			    \&write_transport_map,
			    undef, always_call_parser => 1);

# config file generation using templates

sub get_host_dns_info {
    my ($self) = @_;

    my $dnsinfo = {};
    my $nodename = PVE::INotify::nodename();

    $dnsinfo->{hostname} = $nodename;
    my $resolv = PVE::INotify::read_file('resolvconf');

    my $domain = $resolv->{search} // 'localdomain';
    # postfix will not parse a hostname with trailing '.'
    $domain =~ s/^(.*)\.$/$1/;
    $dnsinfo->{domain} = $domain;

    $dnsinfo->{fqdn} = "$nodename.$domain";

    return $dnsinfo;
}

sub get_template_vars {
    my ($self) = @_;

    my $vars = { pmg => $self->get_config() };

    my $dnsinfo = get_host_dns_info();
    $vars->{dns} = $dnsinfo;
    my $int_ip = PMG::Cluster::remote_node_ip($dnsinfo->{hostname});
    $vars->{ipconfig}->{int_ip} = $int_ip;

    my $transportnets = {};
    my $mynetworks = {
	'127.0.0.0/8' => 1,
	'[::1]/128', => 1,
    };

    if (my $tmap = PVE::INotify::read_file('transport')) {
	foreach my $domain (keys %$tmap) {
	    my $data = $tmap->{$domain};
	    my $host = $data->{host};
	    if ($host =~ m/^$IPV4RE$/) {
		$transportnets->{"$host/32"} = 1;
		$mynetworks->{"$host/32"} = 1;
	    } elsif ($host =~ m/^(?:ipv6:)?($IPV6RE)$/i) {
		$transportnets->{"[$1]/128"} = 1;
		$mynetworks->{"[$1]/128"} = 1;
	    }
	}
    }

    $vars->{postfix}->{transportnets} = join(' ', sort keys %$transportnets);

    if (defined($int_ip)) { # we cannot really do anything and the loopback nets are already added
	if (my $int_net_cidr = PMG::Utils::find_local_network_for_ip($int_ip, 1)) {
	    if ($int_net_cidr =~ m/^($IPV6RE)\/(\d+)$/) {
		$mynetworks->{"[$1]/$2"} = 1;
	    } else {
		$mynetworks->{$int_net_cidr} = 1;
	    }
	} else {
	    if ($int_ip =~ m/^$IPV6RE$/) {
		$mynetworks->{"[$int_ip]/128"} = 1;
	    } else {
		$mynetworks->{"$int_ip/32"} = 1;
	    }
	}
    }

    my $netlist = PVE::INotify::read_file('mynetworks');
    foreach my $cidr (keys %$netlist) {
	my $ip = PVE::Network::IP_from_cidr($cidr);

	if (!$ip) {
	    warn "failed to parse mynetworks entry '$cidr', ignoring\n";
	} elsif ($ip->version() == 4) {
	    $mynetworks->{$ip->prefix()} = 1;
	} else {
	    my $address = '[' . $ip->short() . ']/' . $ip->prefixlen();
	    $mynetworks->{$address} = 1;
	}
    }

    # add default relay to mynetworks
    if (my $relay = $self->get('mail', 'relay')) {
	if ($relay =~ m/^$IPV4RE$/) {
	    $mynetworks->{"$relay/32"} = 1;
	} elsif ($relay =~ m/^$IPV6RE$/) {
	    $mynetworks->{"[$relay]/128"} = 1;
	} else {
	    # DNS name - do nothing ?
	}
    }

    $vars->{postfix}->{mynetworks} = join(' ', sort keys %$mynetworks);

    # normalize dnsbl_sites
    my @dnsbl_sites = PVE::Tools::split_list($vars->{pmg}->{mail}->{dnsbl_sites});
    if (scalar(@dnsbl_sites)) {
	$vars->{postfix}->{dnsbl_sites} = join(',', @dnsbl_sites);
    }

    $vars->{postfix}->{dnsbl_threshold} = $self->get('mail', 'dnsbl_threshold');

    my $usepolicy = 0;
    $usepolicy = 1 if $self->get('mail', 'greylist') ||
	$self->get('mail', 'greylist6') || $self->get('mail', 'spf');
    $vars->{postfix}->{usepolicy} = $usepolicy;

    if (!defined($int_ip)) {
	warn "could not get node IP, falling back to loopback '127.0.0.1'\n";
	$vars->{postfix}->{int_ip} = '127.0.0.1';
    } elsif ($int_ip =~ m/^$IPV6RE$/) {
        $vars->{postfix}->{int_ip} = "[$int_ip]";
    } else {
        $vars->{postfix}->{int_ip} = $int_ip;
    }

    my $wlbr = $dnsinfo->{fqdn};
    foreach my $r (PVE::Tools::split_list($vars->{pmg}->{spam}->{wl_bounce_relays})) {
	$wlbr .= " $r"
    }
    $vars->{composed}->{wl_bounce_relays} = $wlbr;

    if (my $proxy = $vars->{pmg}->{admin}->{http_proxy}) {
	eval {
	    my $uri = URI->new($proxy);
	    my $host = $uri->host;
	    my $port = $uri->port // 8080;
	    if ($host) {
		my $data = { host => $host, port => $port };
		if (my $ui = $uri->userinfo) {
		    my ($username, $pw) = split(/:/, $ui, 2);
		    $data->{username} = $username;
		    $data->{password} = $pw if defined($pw);
		}
		$vars->{proxy} = $data;
	    }
	};
	warn "parse http_proxy failed - $@" if $@;
    }
    $vars->{postgres}->{version} = PMG::Utils::get_pg_server_version();

    return $vars;
}

# reads the $filename and checks if it's equal as the $cmp string passed
my sub file_content_equals_str {
    my ($filename, $cmp) = @_;

    return if !-f $filename;
    my $current = PVE::Tools::file_get_contents($filename, 128*1024);
    return defined($current) && $current eq $cmp; # no change
}

# use one global TT cache
our $tt_include_path = ['/etc/pmg/templates' ,'/var/lib/pmg/templates' ];

my $template_toolkit;

sub get_template_toolkit {

    return $template_toolkit if $template_toolkit;

    $template_toolkit = Template->new({ INCLUDE_PATH => $tt_include_path });

    return $template_toolkit;
}

# rewrite file from template
# return true if file has changed
sub rewrite_config_file {
    my ($self, $tmplname, $dstfn) = @_;

    my $demo = $self->get('admin', 'demo');

    if ($demo) {
	my $demosrc = "$tmplname.demo";
	$tmplname = $demosrc if -f "/var/lib/pmg/templates/$demosrc";
    }

    my ($perm, $uid, $gid);

    if ($dstfn eq '/etc/clamav/freshclam.conf') {
	# needed if file contains a HTTPProxyPasswort

	$uid = getpwnam('clamav');
	$gid = getgrnam('adm');
	$perm = 0600;
    }

    my $tt = get_template_toolkit();

    my $vars = $self->get_template_vars();

    my $output = '';

    $tt->process($tmplname, $vars, \$output) || die $tt->error() . "\n";

    return 0 if file_content_equals_str($dstfn, $output); # no change -> nothing to do

    PVE::Tools::file_set_contents($dstfn, $output, $perm);

    if (defined($uid) && defined($gid)) {
	chown($uid, $gid, $dstfn);
    }

    return 1;
}

# rewrite spam configuration
sub rewrite_config_spam {
    my ($self) = @_;

    my $use_awl = $self->get('spam', 'use_awl');
    my $use_bayes = $self->get('spam', 'use_bayes');
    my $use_razor = $self->get('spam', 'use_razor');

    my $changes = 0;

    # delete AW and bayes databases if those features are disabled
    if (!$use_awl) {
	$changes = 1 if unlink '/root/.spamassassin/auto-whitelist';
    }

    if (!$use_bayes) {
	$changes = 1 if unlink '/root/.spamassassin/bayes_journal';
	$changes = 1 if unlink '/root/.spamassassin/bayes_seen';
	$changes = 1 if unlink '/root/.spamassassin/bayes_toks';
    }

    # make sure we have the custom SA files (else cluster sync fails)
    IO::File->new('/etc/mail/spamassassin/custom.cf', 'a', 0644);
    IO::File->new('/etc/mail/spamassassin/pmg-scores.cf', 'a', 0644);

    $changes = 1 if $self->rewrite_config_file(
	'local.cf.in', '/etc/mail/spamassassin/local.cf');

    $changes = 1 if $self->rewrite_config_file(
	'init.pre.in', '/etc/mail/spamassassin/init.pre');

    $changes = 1 if $self->rewrite_config_file(
	'v310.pre.in', '/etc/mail/spamassassin/v310.pre');

    $changes = 1 if $self->rewrite_config_file(
	'v320.pre.in', '/etc/mail/spamassassin/v320.pre');

    $changes = 1 if $self->rewrite_config_file(
	'v342.pre.in', '/etc/mail/spamassassin/v342.pre');

    $changes = 1 if $self->rewrite_config_file(
	'v400.pre.in', '/etc/mail/spamassassin/v400.pre');

    if ($use_razor) {
	mkdir "/root/.razor";

	$changes = 1 if $self->rewrite_config_file(
	    'razor-agent.conf.in', '/root/.razor/razor-agent.conf');

	if (! -e '/root/.razor/identity') {
	    eval {
		my $timeout = 30;
		PVE::Tools::run_command(['razor-admin', '-discover'], timeout => $timeout);
		PVE::Tools::run_command(['razor-admin', '-register'], timeout => $timeout);
	    };
	    my $err = $@;
	    syslog('info', "registering razor failed: $err") if $err;
	}
    }

    return $changes;
}

# rewrite ClamAV configuration
sub rewrite_config_clam {
    my ($self) = @_;

    return $self->rewrite_config_file(
	'clamd.conf.in', '/etc/clamav/clamd.conf');
}

sub rewrite_config_freshclam {
    my ($self) = @_;

    return $self->rewrite_config_file(
	'freshclam.conf.in', '/etc/clamav/freshclam.conf');
}

sub rewrite_config_postgres {
    my ($self) = @_;

    my $pg_maj_version = PMG::Utils::get_pg_server_version();
    my $pgconfdir = "/etc/postgresql/$pg_maj_version/main";

    my $changes = 0;

    $changes = 1 if $self->rewrite_config_file(
	'pg_hba.conf.in', "$pgconfdir/pg_hba.conf");

    $changes = 1 if $self->rewrite_config_file(
	'postgresql.conf.in', "$pgconfdir/postgresql.conf");

    return $changes;
}

# rewrite /root/.forward
sub rewrite_dot_forward {
    my ($self) = @_;

    my $dstfn = '/root/.forward';

    my $email = $self->get('admin', 'email');

    my $output = '';
    if ($email && $email =~ m/\s*(\S+)\s*/) {
	$output = "$1\n";
    } else {
	# empty .forward does not forward mails (see man local)
    }
    return 0 if file_content_equals_str($dstfn, $output); # no change -> nothing to do

    PVE::Tools::file_set_contents($dstfn, $output);

    return 1;
}

my $write_smtp_whitelist = sub {
    my ($filename, $data, $action) = @_;

    $action = 'OK' if !$action;

    my $new = '';
    foreach my $k (sort keys %$data) {
	$new .= "$k $action\n";
    }
    return 0 if file_content_equals_str($filename, $new); # no change -> nothing to do

    PVE::Tools::file_set_contents($filename, $new);

    PMG::Utils::run_postmap($filename);

    return 1;
};

sub rewrite_postfix_whitelist {
    my ($rulecache) = @_;

    # see man page for regexp_table for postfix regex table format

    # we use a hash to avoid duplicate entries in regex tables
    my $tolist = {};
    my $fromlist = {};
    my $clientlist = {};

    foreach my $obj (@{$rulecache->{"greylist:receiver"}}) {
	my $oclass = ref($obj);
	if ($oclass eq 'PMG::RuleDB::Receiver') {
	    my $addr = PMG::Utils::quote_regex($obj->{address});
	    $tolist->{"/^$addr\$/"} = 1;
	} elsif ($oclass eq 'PMG::RuleDB::ReceiverDomain') {
	    my $addr = PMG::Utils::quote_regex($obj->{address});
	    $tolist->{"/^.+\@$addr\$/"} = 1;
	} elsif ($oclass eq 'PMG::RuleDB::ReceiverRegex') {
	    my $addr = $obj->{address};
	    $addr =~ s|/|\\/|g;
	    $tolist->{"/^$addr\$/"} = 1;
	}
    }

    foreach my $obj (@{$rulecache->{"greylist:sender"}}) {
	my $oclass = ref($obj);
	my $addr = PMG::Utils::quote_regex($obj->{address});
	if ($oclass eq 'PMG::RuleDB::EMail') {
	    my $addr = PMG::Utils::quote_regex($obj->{address});
	    $fromlist->{"/^$addr\$/"} = 1;
	} elsif ($oclass eq 'PMG::RuleDB::Domain') {
	    my $addr = PMG::Utils::quote_regex($obj->{address});
	    $fromlist->{"/^.+\@$addr\$/"} = 1;
	} elsif ($oclass eq 'PMG::RuleDB::WhoRegex') {
	    my $addr = $obj->{address};
	    $addr =~ s|/|\\/|g;
	    $fromlist->{"/^$addr\$/"} = 1;
	} elsif ($oclass eq 'PMG::RuleDB::IPAddress') {
	    $clientlist->{$obj->{address}} = 1;
	} elsif ($oclass eq 'PMG::RuleDB::IPNet') {
	    $clientlist->{$obj->{address}} = 1;
	}
    }

    $write_smtp_whitelist->("/etc/postfix/senderaccess", $fromlist);
    $write_smtp_whitelist->("/etc/postfix/rcptaccess", $tolist);
    $write_smtp_whitelist->("/etc/postfix/clientaccess", $clientlist);
    $write_smtp_whitelist->("/etc/postfix/postscreen_access", $clientlist, 'permit');
};

# rewrite /etc/postfix/*
sub rewrite_config_postfix {
    my ($self, $rulecache) = @_;

    # make sure we have required files (else postfix start fails)
    IO::File->new($transport_map_filename, 'a', 0644);

    my $changes = 0;

    if ($self->get('mail', 'tls')) {
	eval {
	    PMG::Utils::gen_proxmox_tls_cert();
	};
	syslog ('info', "generating certificate failed: $@") if $@;
    }

    $changes = 1 if $self->rewrite_config_file(
	'main.cf.in', '/etc/postfix/main.cf');

    $changes = 1 if $self->rewrite_config_file(
	'master.cf.in', '/etc/postfix/master.cf');

    # make sure we have required files (else postfix start fails)
    # Note: postmap need a valid /etc/postfix/main.cf configuration
    postmap_pmg_domains();
    postmap_pmg_transport();
    postmap_tls_policy();
    postmap_tls_inbound_domains();

    rewrite_postfix_whitelist($rulecache) if $rulecache;

    # make sure aliases.db is up to date
    system('/usr/bin/newaliases');

    return $changes;
}

#parameters affecting services w/o config-file (pmgpolicy, pmg-smtp-filter)
my $pmg_service_params = {
    mail => {
	hide_received => 1,
	ndr_on_block => 1,
	smtputf8 => 1,
    },
    admin => {
	dkim_selector => 1,
	dkim_sign => 1,
	dkim_sign_all_mail => 1,
	'dkim-use-domain' => 1,
    },
};

my $smtp_filter_cfg = '/run/pmg-smtp-filter.cfg';
my $smtp_filter_cfg_lock = '/run/pmg-smtp-filter.cfg.lck';

sub dump_smtp_filter_config {
    my ($self) = @_;

    my $conf = '';
    my $val;
    foreach my $sec (sort keys %$pmg_service_params) {
	my $conf_sec = $self->{ids}->{$sec} // {};
	foreach my $key (sort keys %{$pmg_service_params->{$sec}}) {
	    $val = $conf_sec->{$key};
	    $conf .= "$sec.$key:$val\n" if defined($val);
	}
    }

    return $conf;
}

sub compare_smtp_filter_config {
    my ($self) = @_;

    my $ret = 0;
    my $old;
    eval {
	$old = PVE::Tools::file_get_contents($smtp_filter_cfg);
    };

    if (my $err = $@) {
	syslog ('warning', "reloading pmg-smtp-filter: $err");
	$ret = 1;
    } else {
	my $new = $self->dump_smtp_filter_config();
	$ret = 1 if $old ne $new;
    }

    $self->write_smtp_filter_config() if $ret;

    return $ret;
}

# writes the parameters relevant for pmg-smtp-filter to /run/ for comparison
# on config change
sub write_smtp_filter_config {
    my ($self) = @_;

    PVE::Tools::lock_file($smtp_filter_cfg_lock, undef, sub {
	PVE::Tools::file_set_contents($smtp_filter_cfg,
	    $self->dump_smtp_filter_config());
    });

    die $@ if $@;
}

sub rewrite_config {
    my ($self, $rulecache, $restart_services, $force_restart) = @_;

    $force_restart = {} if ! $force_restart;

    my $log_restart = sub {
	syslog ('info', "configuration change detected for '$_[0]', restarting");
    };

    if (($self->rewrite_config_postfix($rulecache) && $restart_services) ||
	$force_restart->{postfix}) {
	$log_restart->('postfix');
	PMG::Utils::service_cmd('postfix', 'reload');
    }

    if ($self->rewrite_dot_forward() && $restart_services) {
	# no need to restart anything
    }

    if ($self->rewrite_config_postgres() && $restart_services) {
	# do nothing (too many side effects)?
	# does not happen anyways, because config does not change.
    }

    if (($self->rewrite_config_spam() && $restart_services) ||
	$force_restart->{spam}) {
	$log_restart->('pmg-smtp-filter');
	PMG::Utils::service_cmd('pmg-smtp-filter', 'restart');
    }

    if (($self->rewrite_config_clam() && $restart_services) ||
	$force_restart->{clam}) {
	$log_restart->('clamav-daemon');
	PMG::Utils::service_cmd('clamav-daemon', 'restart');
    }

    if (($self->rewrite_config_freshclam() && $restart_services) ||
	$force_restart->{freshclam}) {
	$log_restart->('clamav-freshclam');
	PMG::Utils::service_cmd('clamav-freshclam', 'restart');
    }

    if (($self->compare_smtp_filter_config() && $restart_services) ||
	$force_restart->{spam}) {
	syslog ('info', "scheduled reload for pmg-smtp-filter");
	PMG::Utils::reload_smtp_filter();
    }
}

1;
