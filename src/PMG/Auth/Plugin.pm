package PMG::Auth::Plugin;

use strict;
use warnings;

use Digest::SHA;
use Encode;

use PVE::INotify;
use PVE::JSONSchema qw(get_standard_option);
use PVE::SectionConfig;
use PVE::Tools;

use base qw(PVE::SectionConfig);

my $realm_cfg_id = "realms.cfg";
my $lockfile = "/var/lock/pmg-realms.lck";

sub realm_cfg_id {
    return $realm_cfg_id;
}

sub read_realms_conf {
    my ($filename, $fh) = @_;

    my $raw;
    $raw = do { local $/ = undef; <$fh> } if defined($fh);

    return PMG::Auth::Plugin->parse_config($filename, $raw);
}

sub write_realms_conf {
    my ($filename, $fh, $cfg) = @_;

    my $raw = PMG::Auth::Plugin->write_config($filename, $cfg);

    PVE::Tools::safe_print($filename, $fh, $raw);
}

PVE::INotify::register_file(
    $realm_cfg_id,
    "/etc/pmg/realms.cfg",
    \&read_realms_conf,
    \&write_realms_conf,
    undef,
    always_call_parser => 1,
);

sub lock_realm_config {
    my ($code, $errmsg) = @_;

    PVE::Tools::lock_file($lockfile, undef, $code);
    if (my $err = $@) {
	$errmsg ? die "$errmsg: $err" : die $err;
    }
}

sub is_valid_realm {
    my ($realm) = @_;
    return 0 if !$realm;
    return 1 if $realm eq 'pam' || $realm eq 'quarantine'; # built-in ones

    my $cfg = PVE::INotify::read_file(PMG::Auth::Plugin::realm_conf_id());
    return exists($cfg->{ids}->{$realm}) ? 1 : 0;
}

PVE::JSONSchema::register_format('pmg-realm', \&is_valid_realm);

PVE::JSONSchema::register_standard_option('realm', {
    description => "Authentication domain ID",
    type => 'string',
    format => 'pmg-realm',
    maxLength => 32,
});

my $realm_regex = qr/[A-Za-z][A-Za-z0-9\.\-_]+/;

sub pmg_verify_realm {
    my ($realm, $noerr) = @_;

    if ($realm !~ m/^${realm_regex}$/) {
	return undef if $noerr;
	die "value does not look like a valid realm\n";
    }
    return $realm;
}

my $defaultData = {
    propertyList => {
	type => { description => "Realm type." },
	realm => get_standard_option('realm'),
    },
};

sub private {
    return $defaultData;
}

sub parse_section_header {
    my ($class, $line) = @_;

    if ($line =~ m/^(\S+):\s*(\S+)\s*$/) {
	my ($type, $realm) = (lc($1), $2);
	my $errmsg = undef; # set if you want to skip whole section
	eval { pmg_verify_realm($realm); };
	$errmsg = $@ if $@;
	my $config = {}; # to return additional attributes
	return ($type, $realm, $errmsg, $config);
    }
    return undef;
}

sub parse_config {
    my ($class, $filename, $raw) = @_;

    my $cfg = $class->SUPER::parse_config($filename, $raw);

    my $default;
    foreach my $realm (keys %{$cfg->{ids}}) {
	my $data = $cfg->{ids}->{$realm};
	# make sure there is only one default marker
	if ($data->{default}) {
	    if ($default) {
		delete $data->{default};
	    } else {
		$default = $realm;
	    }
	}

	if ($data->{comment}) {
	    $data->{comment} = PVE::Tools::decode_text($data->{comment});
	}

    }

    # add default realms
    $cfg->{ids}->{pmg}->{type} = 'pmg'; # force type
    $cfg->{ids}->{pmg}->{comment} = "Proxmox Mail Gateway authentication server"
	if !$cfg->{ids}->{pmg}->{comment};
    $cfg->{ids}->{pmg}->{default} = 1
	if !$cfg->{ids}->{pmg}->{default};

    $cfg->{ids}->{pam}->{type} = 'pam'; # force type
    $cfg->{ids}->{pam}->{comment} = "Linux PAM standard authentication"
	if !$cfg->{ids}->{pam}->{comment};

    return $cfg;
};

sub write_config {
    my ($class, $filename, $cfg) = @_;

    foreach my $realm (keys %{$cfg->{ids}}) {
	my $data = $cfg->{ids}->{$realm};
	if ($data->{comment}) {
	    $data->{comment} = PVE::Tools::encode_text($data->{comment});
	}
    }

    $class->SUPER::write_config($filename, $cfg);
}

sub authenticate_user {
    my ($class, $config, $realm, $username, $password) = @_;

    die "overwrite me";
}

sub store_password {
    my ($class, $config, $realm, $username, $password) = @_;

    my $type = $class->type();

    die "can't set password on auth type '$type'\n";
}

sub delete_user {
    my ($class, $config, $realm, $username) = @_;

    # do nothing by default
}

# called during addition of realm (before the new realm config got written)
# `password` is moved to %param to avoid writing it out to the config
# die to abort addition if there are (grave) problems
# NOTE: runs in a realm config *locked* context
sub on_add_hook {
    my ($class, $realm, $config, %param) = @_;
    # do nothing by default
}

# called during realm configuration update (before the updated realm config got
# written). `password` is moved to %param to avoid writing it out to the config
# die to abort the update if there are (grave) problems
# NOTE: runs in a realm config *locked* context
sub on_update_hook {
    my ($class, $realm, $config, %param) = @_;
    # do nothing by default
}

# called during deletion of realms (before the new realm config got written)
# and if the activate check on addition fails, to cleanup all storage traces
# which on_add_hook may have created.
# die to abort deletion if there are (very grave) problems
# NOTE: runs in a realm config *locked* context
sub on_delete_hook {
    my ($class, $realm, $config) = @_;
    # do nothing by default
}

# called during addition and updates of realms (before the new realm config gets written)
# die to abort addition/update in case the connection/bind fails
# NOTE: runs in a realm config *locked* context
sub check_connection {
    my ($class, $realm, $config, %param) = @_;
    # do nothing by default
}

1;
