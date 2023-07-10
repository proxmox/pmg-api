package PMG::NodeConfig;

use strict;
use warnings;

use Digest::SHA;

use PVE::INotify;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Tools;

use PMG::API2::ACMEPlugin;
use PMG::CertHelpers;

# register up to 5 domain names per node for now
my $MAXDOMAINS = 5;

my $inotify_file_id = 'pmg-node-config.conf';
my $config_filename = '/etc/pmg/node.conf';
my $lockfile = "/var/lock/pmg-node-config.lck";

my $acme_domain_desc = {
    domain => {
	type => 'string',
	format => 'pmg-acme-domain',
	format_description => 'domain',
	description => 'domain for this node\'s ACME certificate',
	default_key => 1,
    },
    plugin => {
	type => 'string',
	format => 'pve-configid',
	description => 'The ACME plugin ID',
	format_description => 'name of the plugin configuration',
	optional => 1,
	default => 'standalone',
    },
    alias => {
	type => 'string',
	format => 'pmg-acme-alias',
	format_description => 'domain',
	description => 'Alias for the Domain to verify ACME Challenge over DNS',
	optional => 1,
    },
    usage => {
	type => 'string',
	format => 'pmg-certificate-type-list',
	format_description => 'usage list',
	description => 'Whether this domain is used for the API, SMTP or both',
    },
};

my $acmedesc = {
    account => get_standard_option('pmg-acme-account-name'),
};

my $confdesc = {
    acme => {
	type => 'string',
	description => 'Node specific ACME settings.',
	format => $acmedesc,
	optional => 1,
    },
    map {(
	"acmedomain$_" => {
	    type => 'string',
	    description => 'ACME domain and validation plugin',
	    format => $acme_domain_desc,
	    optional => 1,
	},
    )} (0..$MAXDOMAINS),
};

sub acme_config_schema : prototype(;$) {
    my ($overrides) = @_;

    $overrides //= {};

    return {
	type => 'object',
	additionalProperties => 0,
	properties => {
	    %$confdesc,
	    %$overrides,
	},
    }
}

my $config_schema = acme_config_schema();

# Parse the config's acme property string if it exists.
#
# Returns nothing if the entry is not set.
sub parse_acme : prototype($) {
    my ($cfg) = @_;
    my $data = $cfg->{acme};
    if (defined($data)) {
	return PVE::JSONSchema::parse_property_string($acmedesc, $data);
    }
    return; # empty list otherwise
}

# Turn the acme object into a property string.
sub print_acme : prototype($) {
    my ($acme) = @_;
    return PVE::JSONSchema::print_property_string($acmedesc, $acme);
}

# Parse a domain entry from the config.
sub parse_domain : prototype($) {
    my ($data) = @_;
    return PVE::JSONSchema::parse_property_string($acme_domain_desc, $data);
}

# Turn a domain object into a property string.
sub print_domain : prototype($) {
    my ($domain) = @_;
    return PVE::JSONSchema::print_property_string($acme_domain_desc, $domain);
}

sub read_pmg_node_config {
    my ($filename, $fh) = @_;
    my $raw = defined($fh) ? do { local $/ = undef; <$fh> } : '';
    my $digest = Digest::SHA::sha1_hex($raw);
    my $conf = PVE::JSONSchema::parse_config($config_schema, $filename, $raw);
    $conf->{digest} = $digest;
    return $conf;
}

sub write_pmg_node_config {
    my ($filename, $fh, $cfg) = @_;
    my $raw = PVE::JSONSchema::dump_config($config_schema, $filename, $cfg);

    # higher level ACME sanity checking
    get_acme_conf($cfg);
    PVE::Tools::safe_print($filename, $fh, $raw);
}

PVE::INotify::register_file($inotify_file_id, $config_filename,
			    \&read_pmg_node_config,
			    \&write_pmg_node_config,
			    undef,
			    always_call_parser => 1);

sub lock_config {
    my ($code) = @_;
    my $p = PVE::Tools::lock_file($lockfile, undef, $code);
    die $@ if $@;
    return $p;
}

sub load_config {
    # auto-adds the standalone plugin if no config is there for backwards
    # compatibility, so ALWAYS call the cfs registered parser
    return PVE::INotify::read_file($inotify_file_id);
}

sub write_config {
    my ($self) = @_;
    return PVE::INotify::write_file($inotify_file_id, $self);
}

# we always convert domain values to lower case, since DNS entries are not case
# sensitive and ACME implementations might convert the ordered identifiers
# to lower case
# FIXME: Could also be shared between PVE and PMG
sub get_acme_conf {
    my ($conf, $noerr) = @_;

    $conf //= {};

    my $res = {};
    if (defined($conf->{acme})) {
	$res = eval {
	    PVE::JSONSchema::parse_property_string($acmedesc, $conf->{acme})
	};
	if (my $err = $@) {
	    return undef if $noerr;
	    die $err;
	}
	my $standalone_domains = delete($res->{domains}) // '';
	$res->{domains} = {};
	for my $domain (split(";", $standalone_domains)) {
	    $domain = lc($domain);
	    die "duplicate domain '$domain' in ACME config properties\n"
		if defined($res->{domains}->{$domain});

	    $res->{domains}->{$domain}->{plugin} = 'standalone';
	    $res->{domains}->{$domain}->{_configkey} = 'acme';
	}
    }

    $res->{account} //= 'default';

    for my $index (0..$MAXDOMAINS) {
	my $domain_rec = $conf->{"acmedomain$index"};
	next if !defined($domain_rec);

	my $parsed = eval {
	    PVE::JSONSchema::parse_property_string($acme_domain_desc, $domain_rec)
	};
	if (my $err = $@) {
	    return undef if $noerr;
	    die $err;
	}
	my $domain = lc(delete $parsed->{domain});
	if (my $exists = $res->{domains}->{$domain}) {
	    return undef if $noerr;
	    die "duplicate domain '$domain' in ACME config properties"
	        ." 'acmedomain$index' and '$exists->{_configkey}'\n";
	}
	$parsed->{plugin} //= 'standalone';

	my $plugins = PMG::API2::ACMEPlugin::load_config();
	my $plugin_id = $parsed->{plugin};
	if ($plugin_id ne 'standalone') {
	    die "plugin '$plugin_id' for domain '$domain' not found!\n"
		if !$plugins->{ids}->{$plugin_id};
	}

	# validation for wildcard domain names happens on the domain w/o
	# wildcard - see https://tools.ietf.org/html/rfc8555#section-7.1.3
	if ($domain =~ /^\*\.(.*)$/ ) {
	    $res->{validationtarget}->{$1} = $domain;
	    die "wildcard domain validation for '$domain' needs a dns-01 plugin.\n"
		if $plugins->{ids}->{$plugin_id}->{type} ne 'dns';

	}

	$parsed->{_configkey} = "acmedomain$index";
	$res->{domains}->{$domain} = $parsed;
    }

    return $res;
}

# Helper to filter the domains hash. Returns `undef` if the list is empty.
sub filter_domains_by_type : prototype($$) {
    my ($domains, $type) = @_;

    return undef if !$domains || !%$domains;

    my $out = {};

    foreach my $domain (keys %$domains) {
	my $entry = $domains->{$domain};
	if (grep { $_ eq $type } PVE::Tools::split_list($entry->{usage})) {
	    $out->{$domain} = $entry;
	}
    }

    return undef if !%$out;
    return $out;
}

1;
