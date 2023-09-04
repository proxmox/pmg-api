package PMG::PBSConfig;

# section config implementation for PBS integration in PMG

use strict;
use warnings;

use PVE::Tools qw(extract_param);
use PVE::SectionConfig;
use PVE::JSONSchema qw(get_standard_option);
use PVE::PBSClient;

use base qw(PVE::SectionConfig);

my $inotify_file_id = 'pmg-pbs.conf';
my $secret_dir = '/etc/pmg/pbs';
my $config_filename = "${secret_dir}/pbs.conf";

my %prune_option = (
    optional => 1,
    type => 'integer', minimum => '0',
    format_description => 'N',
);

my %prune_properties = (
    'keep-last' => {
	%prune_option,
	description => 'Keep the last <N> backups.',
    },
    'keep-hourly' => {
	%prune_option,
	description => 'Keep backups for the last <N> different hours. If there is'
	    .' more than one backup for a single hour, only the latest one is kept.'
    },
    'keep-daily' => {
	%prune_option,
	description => 'Keep backups for the last <N> different days. If there is'
	    .' more than one backup for a single day, only the latest one is kept.'
    },
    'keep-weekly' => {
	%prune_option,
	description => 'Keep backups for the last <N> different weeks. If there is'
	    .'more than one backup for a single week, only the latest one is kept.'
    },
    'keep-monthly' => {
	%prune_option,
	description => 'Keep backups for the last <N> different months. If there is'
	    .' more than one backup for a single month, only the latest one is kept.'
    },
    'keep-yearly' => {
	%prune_option,
	description => 'Keep backups for the last <N> different years. If there is'
	    .' more than one backup for a single year, only the latest one is kept.'
    },
);

my $defaultData = {
    propertyList => {
	type => { description => "Section type." },
	remote => {
	    description => "Proxmox Backup Server ID.",
	    type => 'string', format => 'pve-configid',
	},
    },
};

my $SAFE_ID_RE = '(?:[A-Za-z0-9_][A-Za-z0-9._\-]*)';
my $NS_RE = "(?:${SAFE_ID_RE}/){0,7}(?:${SAFE_ID_RE})?";

sub properties {
    return {
	datastore => {
	    description => "Proxmox Backup Server datastore name.",
	    pattern => $SAFE_ID_RE,
	    type => 'string',
	},
	namespace => {
	    type => 'string',
	    description => "Proxmox Backup Server namespace in the datastore, defaults to the root NS.",
	    pattern => $NS_RE,
	    maxLength => 256,
	},
	server => {
	    description => "Proxmox Backup Server address.",
	    type => 'string', format => 'address',
	    maxLength => 256,
	},
	disable => {
	    description => "Flag to disable (deactivate) the entry.",
	    type => 'boolean',
	    optional => 1,
	},
	password => {
	    description => "Password or API token secret for the user on the"
		." Proxmox Backup Server.",
	    type => 'string',
	    optional => 1,
	},
	port => {
	    description => "Non-default port for Proxmox Backup Server.",
	    optional => 1,
	    type => 'integer',
	    minimum => 1,
	    maximum => 65535,
	    default => 8007,
	},
	username => get_standard_option('pmg-email-address', {
	    description => "Username or API token ID on the Proxmox Backup Server"
	}),
	fingerprint => get_standard_option('fingerprint-sha256'),
	notify => {
	    description => "Specify when to notify via e-mail",
	    type => 'string',
	    enum => [ 'always', 'error', 'never' ],
	    optional => 1,
	},
	'include-statistics' => {
	    description => "Include statistics in scheduled backups",
	    type => 'boolean',
	    optional => 1,
	},
	%prune_properties,
    };
}

sub options {
    return {
	server => {},
	datastore => {},
	namespace => { optional => 1 },
	disable => { optional => 1 },
	username => { optional => 1 },
	password => { optional => 1 },
	port => { optional => 1 },
	fingerprint => { optional => 1 },
	notify => { optional => 1 },
	'include-statistics' => { optional => 1 },
	'keep-last' => { optional => 1 },
	'keep-hourly' =>  { optional => 1 },
	'keep-daily' => { optional => 1 },
	'keep-weekly' => { optional => 1 },
	'keep-monthly' => { optional => 1 },
	'keep-yearly' => { optional => 1 },
    };
}

sub type {
    return 'pbs';
}

sub private {
    return $defaultData;
}

sub prune_options {
    my ($self, $remote) = @_;

    my $remote_cfg = $self->{ids}->{$remote};

    my $res = {};
    my $pruning_setup;
    foreach my $keep_opt (keys %prune_properties) {
	if (defined($remote_cfg->{$keep_opt})) {
	    $pruning_setup = 1;
	    $res->{$keep_opt} = $remote_cfg->{$keep_opt};
	}
    }
    return $pruning_setup ? $res : undef;
}

sub new {
    my ($type) = @_;

    my $class = ref($type) || $type;

    my $cfg = PVE::INotify::read_file($inotify_file_id);

    $cfg->{secret_dir} = $secret_dir;

    return bless $cfg, $class;
}

sub write {
    my ($self) = @_;

    PVE::INotify::write_file($inotify_file_id, $self);
}

sub lock_config {
    my ($code, $errmsg) = @_;

    my $lockfile = "/var/lock/pmgpbsconfig.lck";

    my $p = PVE::Tools::lock_file($lockfile, undef, $code);
    if (my $err = $@) {
	$errmsg ? die "$errmsg: $err" : die $err;
    }
}

__PACKAGE__->register();
__PACKAGE__->init();

sub read_pmg_pbs_conf {
    my ($filename, $fh) = @_;

    my $raw = defined($fh) ? do { local $/ = undef; <$fh> } : '';

    return __PACKAGE__->parse_config($filename, $raw);
}

sub write_pmg_pbs_conf {
    my ($filename, $fh, $cfg) = @_;

    my $raw = __PACKAGE__->write_config($filename, $cfg);

    PVE::Tools::safe_print($filename, $fh, $raw);
}

PVE::INotify::register_file(
    $inotify_file_id,
    $config_filename,
    \&read_pmg_pbs_conf,
    \&write_pmg_pbs_conf,
    undef,
    always_call_parser => 1
);

1;
