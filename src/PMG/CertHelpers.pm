package PMG::CertHelpers;

use strict;
use warnings;

use PVE::Certificate;
use PVE::JSONSchema;
use PVE::Tools;

use constant {
    API_CERT => '/etc/pmg/pmg-api.pem',
    SMTP_CERT => '/etc/pmg/pmg-tls.pem',
};

my $account_prefix = '/etc/pmg/acme/accounts';

# TODO: Move `pve-acme-account-name` to common and reuse instead of this.
PVE::JSONSchema::register_standard_option('pmg-acme-account-name', {
    description => 'ACME account config file name.',
    type => 'string',
    format => 'pve-configid',
    format_description => 'name',
    optional => 1,
    default => 'default',
});

PVE::JSONSchema::register_standard_option('pmg-acme-account-contact', {
    type => 'string',
    format => 'email-list',
    description => 'Contact email addresses.',
});

PVE::JSONSchema::register_standard_option('pmg-acme-directory-url', {
    type => 'string',
    description => 'URL of ACME CA directory endpoint.',
    pattern => '^https?://.*',
});

PVE::JSONSchema::register_format('pmg-certificate-type', sub {
    my ($type, $noerr) = @_;

    if ($type =~ /^(?: api | smtp )$/x) {
	return $type;
    }
    return undef if $noerr;
    die "value '$type' does not look like a valid certificate type\n";
});

PVE::JSONSchema::register_standard_option('pmg-certificate-type', {
    type => 'string',
    description => 'The TLS certificate type (API or SMTP certificate).',
    enum => ['api', 'smtp'],
});

PVE::JSONSchema::register_format('pmg-acme-domain', sub {
    my ($domain, $noerr) = @_;

    my $label = qr/[a-z0-9][a-z0-9_-]*/i;

    return $domain if $domain =~ /^(?:\*\.)?$label(?:\.$label)+$/;
    return undef if $noerr;
    die "value '$domain' does not look like a valid domain name!\n";
});

PVE::JSONSchema::register_format('pmg-acme-alias', sub {
    my ($alias, $noerr) = @_;

    my $label = qr/[a-z0-9_][a-z0-9_-]*/i;

    return $alias if $alias =~ /^$label(?:\.$label)+$/;
    return undef if $noerr;
    die "value '$alias' does not look like a valid alias name!\n";
});

my $local_cert_lock = '/var/lock/pmg-certs.lock';
my $local_acme_lock = '/var/lock/pmg-acme.lock';

sub cert_path : prototype($) {
    my ($type) = @_;
    if ($type eq 'api') {
	return API_CERT;
    } elsif ($type eq 'smtp') {
	return SMTP_CERT;
    } else {
	die "unknown certificate type '$type'\n";
    }
}

sub cert_lock {
    my ($timeout, $code, @param) = @_;

    my $res = PVE::Tools::lock_file($local_cert_lock, $timeout, $code, @param);
    die $@ if $@;
    return $res;
}

sub set_cert_file {
    my ($cert, $cert_path, $force) = @_;

    my ($old_cert, $info);

    my $cert_path_old = "${cert_path}.old";

    die "Custom certificate file exists but force flag is not set.\n"
	if !$force && -e $cert_path;

    PVE::Tools::file_copy($cert_path, $cert_path_old) if -e $cert_path;

    eval {
	my $gid = undef;
	if ($cert_path eq &API_CERT) {
	    $gid = getgrnam('www-data') ||
		die "user www-data not in group file\n";
	}

	if (defined($gid)) {
	    my $cert_path_tmp = "${cert_path}.tmp";
	    PVE::Tools::file_set_contents($cert_path_tmp, $cert, 0640);
	    if (!chown(-1, $gid, $cert_path_tmp)) {
		my $msg =
		    "failed to change group ownership of '$cert_path_tmp' to www-data ($gid): $!\n";
		unlink($cert_path_tmp);
		die $msg;
	    }
	    if (!rename($cert_path_tmp, $cert_path)) {
		my $msg =
		    "failed to rename '$cert_path_tmp' to '$cert_path': $!\n";
		unlink($cert_path_tmp);
		die $msg;
	    }
	} else {
	    PVE::Tools::file_set_contents($cert_path, $cert, 0600);
	}

	$info = PVE::Certificate::get_certificate_info($cert_path);
    };
    my $err = $@;

    if ($err) {
	if (-e $cert_path_old) {
	    eval {
		warn "Attempting to restore old certificate file..\n";
		PVE::Tools::file_copy($cert_path_old, $cert_path);
	    };
	    warn "$@\n" if $@;
	}
	die "Setting certificate files failed - $err\n"
    }

    unlink $cert_path_old;

    return $info;
}

sub lock_acme {
    my ($account_name, $timeout, $code, @param) = @_;

    my $file = "$local_acme_lock.$account_name";

    my $res = PVE::Tools::lock_file($file, $timeout, $code, @param);
    die $@ if $@;
    return $res;
}

sub acme_account_dir {
    return $account_prefix;
}

sub list_acme_accounts {
    my $accounts = [];

    return $accounts if ! -d $account_prefix;

    PVE::Tools::dir_glob_foreach($account_prefix, qr/[^.]+.*/, sub {
	my ($name) = @_;

	push @$accounts, $name
	    if PVE::JSONSchema::pve_verify_configid($name, 1);
    });

    return $accounts;
}
