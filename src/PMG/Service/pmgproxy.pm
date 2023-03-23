package PMG::Service::pmgproxy;

use strict;
use warnings;

use PVE::SafeSyslog;
use PVE::Daemon;
use HTTP::Response;
use URI;
use URI::Escape;

use URI::QueryParam;
use Data::Dumper;

use PVE::Tools;
use PVE::APIServer::Formatter;
use PVE::APIServer::Formatter::Standard;
use PVE::APIServer::Formatter::HTML;
use PVE::APIServer::AnyEvent;
use PVE::APIServer::Utils;

use PMG::HTTPServer;
use PMG::API2;
use PMG::Config;

use Template;

use base qw(PVE::Daemon);

my $cmdline = [$0, @ARGV];

my %daemon_options = (
    max_workers => 3,
    restart_on_error => 5,
    stop_wait_time => 15,
    leave_children_open_on_reload => 1,
    setuid => 'www-data',
    setgid => 'www-data',
    pidfile => '/run/pmgproxy/pmgproxy.pid',
);

my $daemon = __PACKAGE__->new('pmgproxy', $cmdline, %daemon_options);

sub add_dirs {
    my ($result_hash, $alias, $subdir) = @_;

    PVE::APIServer::AnyEvent::add_dirs($result_hash, $alias, $subdir);
}

my $gui_base_dir = "/usr/share/javascript/pmg-gui";
my $extjs_dir = "/usr/share/javascript/extjs/";
my $fontawesome_dir = "/usr/share/fonts-font-awesome";
my $xtermjs_dir = '/usr/share/pve-xtermjs';
my $framework7_dir = '/usr/share/javascript/framework7';
my $widgettoolkit_dir = '/usr/share/javascript/proxmox-widget-toolkit';

sub init {
    my ($self) = @_;

    my $proxyconf = PVE::APIServer::Utils::read_proxy_config($self->{name});

    my $accept_lock_fn = "/var/lock/pmgproxy.lck";

    my $lockfh = IO::File->new(">>${accept_lock_fn}") ||
	die "unable to open lock file '${accept_lock_fn}' - $!\n";

    my $listen_ip = $proxyconf->{LISTEN_IP};
    my $socket = $self->create_reusable_socket(8006, $listen_ip);

    my $dirs = {};

    add_dirs($dirs, '/pve2/locale/', '/usr/share/pmg-i18n/');
    add_dirs($dirs, '/pve2/ext6/', $extjs_dir);
    add_dirs($dirs, '/pve2/images/' => "$gui_base_dir/images/");
    add_dirs($dirs, '/pve2/css/' => "$gui_base_dir/css/");
    add_dirs($dirs, '/pve2/js/' => "$gui_base_dir/js/");
    add_dirs($dirs, '/fontawesome/css/' => "$fontawesome_dir/css/");
    add_dirs($dirs, '/fontawesome/fonts/' => "$fontawesome_dir/fonts/");
    add_dirs($dirs, '/framework7/fonts/' => "$framework7_dir/fonts/");
    add_dirs($dirs, '/framework7/css/' => "$framework7_dir/css/");
    add_dirs($dirs, '/framework7/js/' => "$framework7_dir/js/");
    add_dirs($dirs, '/xtermjs/' => "$xtermjs_dir/");
    add_dirs($dirs, '/pmg-docs/' => '/usr/share/pmg-docs/');
    add_dirs($dirs, '/pmg-docs/api-viewer/extjs/' => $extjs_dir);
    add_dirs($dirs, '/pwt/css/' => "$widgettoolkit_dir/css/");
    add_dirs($dirs, '/pwt/images/' =>  "$widgettoolkit_dir/images/");
    add_dirs($dirs, '/pwt/themes/' => "$widgettoolkit_dir/themes/");

    $self->{server_config} = {
	title => 'Proxmox Mail Gateway API',
	cookie_name => 'PMGAuthCookie',
	keep_alive => 100,
	max_conn => 500,
	max_requests => 1000,
	lockfile => $accept_lock_fn,
	socket => $socket,
	lockfh => $lockfh,
	debug => $self->{debug},
	trusted_env => 0, # not trusted, anyone can connect
	logfile => '/var/log/pmgproxy/pmgproxy.log',
	allow_from => $proxyconf->{ALLOW_FROM},
	deny_from => $proxyconf->{DENY_FROM},
	policy => $proxyconf->{POLICY},
	ssl => {
	    cert_file => '/etc/pmg/pmg-api.pem',
	    dh => 'skip2048',
	    cipher_list => $proxyconf->{CIPHERS},
	    ciphersuites => $proxyconf->{CIPHERSUITES},
	    honor_cipher_order => $proxyconf->{HONOR_CIPHER_ORDER},
	},
	compression => $proxyconf->{COMPRESSION},
	# Note: there is no authentication for those pages and dirs!
	pages => {
	    '/' => sub { get_index($self->{nodename}, @_) },
	    '/quarantine' => sub { get_index($self->{nodename}, @_) },
	    # avoid authentication when accessing favicon
	    '/favicon.ico' => {
		file => '/usr/share/doc/pmg-api/favicon.ico',
	    },
	    '/proxmoxlib.js' => {
		file => '/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js',
	    },
	    '/qrcode.min.js' => {
		file => '/usr/share/javascript/qrcodejs/qrcode.min.js',
	    },
	},
	dirs => $dirs,
    };

    if (defined($proxyconf->{DHPARAMS})) {
	$self->{server_config}->{ssl}->{dh_file} = $proxyconf->{DHPARAMS};
    }
    if (defined($proxyconf->{DISABLE_TLS_1_2})) {
	$self->{server_config}->{ssl}->{tlsv1_2} = !$proxyconf->{DISABLE_TLS_1_2};
    }
    if (defined($proxyconf->{DISABLE_TLS_1_3})) {
	$self->{server_config}->{ssl}->{tlsv1_3} = !$proxyconf->{DISABLE_TLS_1_3};
    }
}

sub run {
    my ($self) = @_;

    my $server = PMG::HTTPServer->new(%{$self->{server_config}});
    $server->run();
}

$daemon->register_start_command();
$daemon->register_restart_command(1);
$daemon->register_stop_command();
$daemon->register_status_command();

our $cmddef = {
    start => [ __PACKAGE__, 'start', []],
    restart => [ __PACKAGE__, 'restart', []],
    stop => [ __PACKAGE__, 'stop', []],
    status => [ __PACKAGE__, 'status', [], undef, sub { print shift . "\n";} ],
};

my $template_toolkit;

sub get_template_toolkit {

    return $template_toolkit if $template_toolkit;

    $template_toolkit = Template->new(
	{ INCLUDE_PATH => [$gui_base_dir, $xtermjs_dir]});

    return $template_toolkit;
}

sub is_phone {
    my ($ua) = @_;

    return 0 if !$ua;

    if ($ua =~ m/(
	iPhone|
	iPod|
	Windows\ Phone|
	Android|
	BlackBerry
	)/xi) {
	return 1;
    }

    return 0;
}

sub get_index {
    my ($nodename, $server, $r, $args) = @_;

    my $lang = 'en';
    my $username;
    my $token = 'null';
    my $quarantine = ($r->uri->path() =~ m/quarantine$/);
    my $mobile = is_phone($r->header('User-Agent'));
    if (defined($args->{mobile})) {
	$mobile = $args->{mobile} ? 1 : 0;
    }

    my $theme = "";

    if (my $cookie = $r->header('Cookie')) {
	if (my $newlang = ($cookie =~ /(?:^|\s)PMGLangCookie=([^;]*)/)[0]) {
	    if ($newlang =~ m/^[a-z]{2,3}(_[A-Z]{2,3})?$/) {
		$lang = $newlang;
	    }
	}

	if (my $newtheme = ($cookie =~ /(?:^|\s)PMGThemeCookie=([^;]*)/)[0]) {
	    # theme names need to be kebab case, with each segment a maximum of 10 characters long
	    # and at most 6 segments
	    if ($newtheme =~ m/^[a-z]{1,10}(-[a-z]{1,10}){0,5}$/) {
		$theme = $newtheme;
	    }
	}

	my $ticket = PVE::APIServer::Formatter::extract_auth_value($cookie, $server->{cookie_name});

	if ($ticket =~ m/^PMGQUAR:/) {
	    $username = PMG::Ticket::verify_quarantine_ticket($ticket, 1);
	} else {
	    $username = PMG::Ticket::verify_ticket($ticket, undef, 1);
	}
    } else {
	if (defined($args->{ticket})) {
	    my $ticket = uri_unescape($args->{ticket});
	    $username = PMG::Ticket::verify_quarantine_ticket($ticket, 1);
	}
    }

    if ($theme eq "") {
	$theme = "auto"
    }

    $token = PMG::Ticket::assemble_csrf_prevention_token($username)
	if defined($username);

    my $langfile = 0;

    if (-f  "/usr/share/pmg-i18n/pmg-lang-$lang.js") {
	$langfile = 1;
    }

    my $wtversionraw = PVE::Tools::file_read_firstline("$widgettoolkit_dir/proxmoxlib.js");
    my $wtversion = '';
    if ($wtversionraw =~ m|^// (.*)$|) {
	$wtversion = $1;
    };

    my $versionraw = PVE::Tools::file_read_firstline("$gui_base_dir/js/pmgmanagerlib.js");
    my $version = '';
    if ($versionraw =~ m|^// (.*)$|) {
	$version = $1;
    };

    my $cfg = PMG::Config->new();
    my $quarantinelink = $cfg->get('spamquar', 'quarantinelink');

    $username = '' if !$username;

    my $page = '';

    my $vars = {
	lang => $lang,
	langfile => $langfile,
	username => $username,
	token => $token,
	console => $args->{console},
	nodename => $nodename,
	debug => $args->{debug} || $server->{debug},
	version => $version,
	wtversion => $wtversion,
	quarantinelink => $quarantinelink,
	theme => $theme,
    };

    my $template_name;
    if (defined($args->{console}) && $args->{xtermjs}) {
	$template_name = "index.html.tpl"; # fixme: use better name
    } elsif ($mobile && $quarantine) {
	$template_name = "pmg-mobile-index.html.tt";
    } else {
	$template_name = "pmg-index.html.tt";
    }

    my $tt = get_template_toolkit();

    $tt->process($template_name, $vars, \$page) ||
	die $tt->error() . "\n";

    my $headers = HTTP::Headers->new(Content_Type => "text/html; charset=utf-8");
    my $resp = HTTP::Response->new(200, "OK", $headers, $page);

    return $resp;
}

1;
