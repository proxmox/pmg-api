package PMG::TFAConfig;

use strict;
use warnings;

use PVE::Tools;
use PVE::INotify;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Exception qw(raise);

use PMG::Utils;
use PMG::UserConfig;

use base 'PMG::RS::TFA';

my $inotify_file_id = 'pmg-tfa.json';
my $config_filename = '/etc/pmg/tfa.json';

sub new {
    my ($type) = @_;

    my $class = ref($type) || $type;

    my $cfg = PVE::INotify::read_file($inotify_file_id);

    return bless $cfg, $class;
}

sub write {
    my ($self) = @_;

    PVE::INotify::write_file($inotify_file_id, $self);
}

# This lives in `UserConfig` in order to enforce lock order.
sub lock_config {
    return PMG::UserConfig::lock_tfa_config(@_);
}

my sub read_tfa_conf : prototype($$) {
    my ($filename, $fh) = @_;

    my $raw;
    if ($fh) {
	$raw = do { local $/ = undef; <$fh> };
    } else {
	$raw = '{}';
    }

    my $cfg = PMG::RS::TFA->new($raw);

    # Purge invalid users:
    my $usercfg = PMG::UserConfig->new();
    foreach my $user ($cfg->users()->@*) {
	if (!$usercfg->lookup_user_data($user, 1)) {
	    $cfg->remove_user($user);
	}
    }

    return $cfg;
}

my sub write_tfa_conf : prototype($$$) {
    my ($filename, $fh, $cfg) = @_;

    chmod(0600, $fh);

    PVE::Tools::safe_print($filename, $fh, $cfg->SUPER::write());
}

PVE::INotify::register_file(
    $inotify_file_id,
    $config_filename,
    \&read_tfa_conf,
    \&write_tfa_conf,
    undef,
    always_call_parser => 1,
    # the parser produces a rust TfaConfig object, Clone::clone would break this
    noclone => 1,
);

1;
