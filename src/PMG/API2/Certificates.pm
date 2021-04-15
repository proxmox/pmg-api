package PMG::API2::Certificates;

use strict;
use warnings;

use PVE::Certificate;
use PVE::Exception qw(raise raise_param_exc);
use PVE::JSONSchema qw(get_standard_option);
use PVE::Tools qw(extract_param file_get_contents file_set_contents);

use PMG::CertHelpers;
use PMG::NodeConfig;
use PMG::RS::Acme;
use PMG::RS::CSR;

use PMG::API2::ACMEPlugin;

use base qw(PVE::RESTHandler);

my $acme_account_dir = PMG::CertHelpers::acme_account_dir();

sub first_typed_pem_entry : prototype($$) {
    my ($label, $data) = @_;

    if ($data =~ /^(-----BEGIN \Q$label\E-----\n.*?\n-----END \Q$label\E-----)$/ms) {
	return $1;
    }
    return undef;
}

sub pem_private_key : prototype($) {
    my ($data) = @_;
    return first_typed_pem_entry('PRIVATE KEY', $data);
}

sub pem_certificate : prototype($) {
    my ($data) = @_;
    return first_typed_pem_entry('CERTIFICATE', $data);
}

my sub restart_after_cert_update : prototype($) {
    my ($type) = @_;

    if ($type eq 'api') {
	print "Restarting pmgproxy\n";
	PVE::Tools::run_command(['systemctl', 'reload-or-restart', 'pmgproxy']);

	my $cinfo = PMG::ClusterConfig->new();
	if (scalar(keys %{$cinfo->{ids}})) {
	    print "Notify cluster about new fingerprint\n";
	    PMG::Cluster::trigger_update_fingerprints($cinfo);
	}
    }
};

my sub update_cert : prototype($$$$$) {
    my ($type, $cert_path, $certificate, $force, $restart) = @_;
    my $code = sub {
	print "Setting custom certificate file $cert_path\n";
	my $info = PMG::CertHelpers::set_cert_file($certificate, $cert_path, $force);

	restart_after_cert_update($type) if $restart;

	return $info;
    };
    return PMG::CertHelpers::cert_lock(10, $code);
};

my sub set_smtp : prototype($$) {
    my ($on, $reload) = @_;

    my $code = sub {
	my $cfg = PMG::Config->new();
	# check if value actually would change
	if (!$cfg->get('mail', 'tls') != !$on) {
	    print "Rewriting postfix config\n";
	    $cfg->set('mail', 'tls', $on);
	    $cfg->write();
	    $cfg->rewrite_config_postfix();
	}

	if ($reload) {
	    print "Reloading postfix\n";
	    PMG::Utils::service_cmd('postfix', 'reload');
	}
    };
    PMG::Config::lock_config($code, "failed to reload postfix");
}

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    permissions => { user => 'all' },
    description => "Node index.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{name}" } ],
    },
    code => sub {
	my ($param) = @_;

	return [
	    { name => 'acme' },
	    { name => 'custom' },
	    { name => 'info' },
	    { name => 'config' },
	];
    },
});

__PACKAGE__->register_method ({
    name => 'info',
    path => 'info',
    method => 'GET',
    permissions => { user => 'all' },
    proxyto => 'node',
    protected => 1,
    description => "Get information about the node's certificates.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => 'array',
	items => get_standard_option('pve-certificate-info'),
    },
    code => sub {
	my ($param) = @_;

	my $res = [];
	for my $path (&PMG::CertHelpers::API_CERT, &PMG::CertHelpers::SMTP_CERT) {
	    eval {
		my $info = PVE::Certificate::get_certificate_info($path);
		push @$res, $info if $info;
	    };
	}
	return $res;
    },
});

__PACKAGE__->register_method ({
    name => 'custom_cert_index',
    path => 'custom',
    method => 'GET',
    permissions => { user => 'all' },
    description => "Certificate index.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{type}" } ],
    },
    code => sub {
	my ($param) = @_;

	return [
	    { type => 'api' },
	    { type => 'smtp' },
	];
    },
});

__PACKAGE__->register_method ({
    name => 'upload_custom_cert',
    path => 'custom/{type}',
    method => 'POST',
    permissions => { check => [ 'admin' ] },
    description => 'Upload or update custom certificate chain and key.',
    protected => 1,
    proxyto => 'node',
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    certificates => {
		type => 'string',
		format => 'pem-certificate-chain',
		description => 'PEM encoded certificate (chain).',
	    },
	    key => {
		type => 'string',
		description => 'PEM encoded private key.',
		format => 'pem-string',
		optional => 0,
	    },
	    type => get_standard_option('pmg-certificate-type'),
	    force => {
		type => 'boolean',
		description => 'Overwrite existing custom or ACME certificate files.',
		optional => 1,
		default => 0,
	    },
	    restart => {
		type => 'boolean',
		description => 'Restart services.',
		optional => 1,
		default => 0,
	    },
	},
    },
    returns => get_standard_option('pve-certificate-info'),
    code => sub {
	my ($param) = @_;

	my $type = extract_param($param, 'type'); # also used to know which service to restart
	my $cert_path = PMG::CertHelpers::cert_path($type);

	my $certs = extract_param($param, 'certificates');
	$certs = PVE::Certificate::strip_leading_text($certs);

	my $key = extract_param($param, 'key');
	if ($key) {
	    $key = PVE::Certificate::strip_leading_text($key);
	    $certs = "$key\n$certs";
	} else {
	    my $private_key = pem_private_key($certs);
	    if (!defined($private_key)) {
		my $old = file_get_contents($cert_path);
		$private_key = pem_private_key($old);
		if (!defined($private_key)) {
		    raise_param_exc({
			'key' => "Attempted to upload custom certificate without (existing) key."
		    })
		}

		# copy the old certificate's key:
		$certs = "$key\n$certs";
	    }
	}

	my $info;

	PMG::CertHelpers::cert_lock(10, sub {
	    $info = update_cert($type, $cert_path, $certs, $param->{force}, $param->{restart});
	});

	if ($type eq 'smtp') {
	    set_smtp(1, $param->{restart});
	}

	return $info;
    }});

__PACKAGE__->register_method ({
    name => 'remove_custom_cert',
    path => 'custom/{type}',
    method => 'DELETE',
    permissions => { check => [ 'admin' ] },
    description => 'DELETE custom certificate chain and key.',
    protected => 1,
    proxyto => 'node',
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    type => get_standard_option('pmg-certificate-type'),
	    restart => {
		type => 'boolean',
		description => 'Restart pmgproxy.',
		optional => 1,
		default => 0,
	    },
	},
    },
    returns => {
	type => 'null',
    },
    code => sub {
	my ($param) = @_;

	my $type = extract_param($param, 'type');
	my $cert_path = PMG::CertHelpers::cert_path($type);

	my $code = sub {
	    print "Deleting custom certificate files\n";
	    unlink $cert_path;
	    PMG::Ticket::generate_api_cert(0) if $type eq 'api';

	    if ($param->{restart}) {
		restart_after_cert_update($type);
	    }
	};

	PMG::CertHelpers::cert_lock(10, $code);

	if ($type eq 'smtp') {
	    set_smtp(0, $param->{restart});
	}

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'acme_cert_index',
    path => 'acme',
    method => 'GET',
    permissions => { user => 'all' },
    description => "ACME Certificate index.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{type}" } ],
    },
    code => sub {
	my ($param) = @_;

	return [
	    { type => 'api' },
	    { type => 'smtp' },
	];
    },
});

my $order_certificate = sub {
    my ($acme, $acme_node_config) = @_;

    my $plugins = PMG::API2::ACMEPlugin::load_config();

    print "Placing ACME order\n";
    my ($order_url, $order) = $acme->new_order([ sort keys %{$acme_node_config->{domains}} ]);
    print "Order URL: $order_url\n";
    for my $auth_url (@{$order->{authorizations}}) {
	print "\nGetting authorization details from '$auth_url'\n";
	my $auth = $acme->get_authorization($auth_url);

	# force lower case, like get_acme_conf does
	my $domain = lc($auth->{identifier}->{value});
	if ($auth->{status} eq 'valid') {
	    print "$domain is already validated!\n";
	} else {
	    print "The validation for $domain is pending!\n";

	    my $domain_config = $acme_node_config->{domains}->{$domain};
	    if (!defined($domain_config)) {
		# wildcard domains are validated through the basedomain
		my $vtarget = $acme_node_config->{validationtarget}->{$domain} // '';
		$domain_config = $acme_node_config->{domains}->{$vtarget};
	    }
	    die "no config for domain '$domain'\n" if !$domain_config;

	    my $plugin_id = $domain_config->{plugin};

	    my $plugin_cfg = $plugins->{ids}->{$plugin_id};
	    die "plugin '$plugin_id' for domain '$domain' not found!\n"
		if !$plugin_cfg;

	    my $data = {
		plugin => $plugin_cfg,
		alias => $domain_config->{alias},
	    };

	    my $plugin = PVE::ACME::Challenge->lookup($plugin_cfg->{type});
	    $plugin->setup($acme, $auth, $data);

	    print "Triggering validation\n";
	    eval {
		die "no validation URL returned by plugin '$plugin_id' for domain '$domain'\n"
		    if !defined($data->{url});

		$acme->request_challenge_validation($data->{url});

		print "Sleeping for 5 seconds\n";
		sleep 5;
		while (1) {
		    $auth = $acme->get_authorization($auth_url);
		    if ($auth->{status} eq 'pending') {
			print "Status is still 'pending', trying again in 10 seconds\n";
			sleep 10;
			next;
		    } elsif ($auth->{status} eq 'valid') {
			print "Status is 'valid', domain '$domain' OK!\n";
			last;
		    }
		    my $error = "validating challenge '$auth_url' failed - status: $auth->{status}";
		    for (@{$auth->{challenges}}) {
			$error .= ", $_->{error}->{detail}" if $_->{error}->{detail};
		    }
		    die "$error\n";
		}
	    };
	    my $err = $@;
	    eval { $plugin->teardown($acme, $auth, $data) };
	    warn "$@\n" if $@;
	    die $err if $err;
	}
    }
    print "\nAll domains validated!\n";
    print "\nCreating CSR\n";
    # Currently we only support dns entries, so extract those from the order:
    my $san = [
	map {
	    $_->{value}
	} grep {
	    $_->{type} eq 'dns'
	} $order->{identifiers}->@*
    ];
    die "DNS identifiers are required to generate a CSR.\n" if !scalar @$san;
    my ($csr_der, $key) = PMG::RS::CSR::generate_csr($san, {});

    my $finalize_error_cnt = 0;
    print "Checking order status\n";
    while (1) {
	$order = $acme->get_order($order_url);
	if ($order->{status} eq 'pending') {
	    print "still pending, trying to finalize order\n";
	    # FIXME
	    # to be compatible with and without the order ready state we try to
	    # finalize even at the 'pending' state and give up after 5
	    # unsuccessful tries this can be removed when the letsencrypt api
	    # definitely has implemented the 'ready' state
	    eval {
		$acme->finalize_order($order->{finalize}, $csr_der);
	    };
	    if (my $err = $@) {
		die $err if $finalize_error_cnt >= 5;

		$finalize_error_cnt++;
		warn $err;
	    }
	    sleep 5;
	    next;
	} elsif ($order->{status} eq 'ready') {
	    print "Order is ready, finalizing order\n";
	    $acme->finalize_order($order->{finalize}, $csr_der);
	    sleep 5;
	    next;
	} elsif ($order->{status} eq 'processing') {
	    print "still processing, trying again in 30 seconds\n";
	    sleep 30;
	    next;
	} elsif ($order->{status} eq 'valid') {
	    print "valid!\n";
	    last;
	}
	die "order status: $order->{status}\n";
    }

    print "\nDownloading certificate\n";
    my $cert = $acme->get_certificate($order->{certificate});

    return ($cert, $key);
};

# Filter domains and raise an error if the list becomes empty.
my $filter_domains = sub {
    my ($acme_config, $type) = @_;

    my $domains = PMG::NodeConfig::filter_domains_by_type($acme_config->{domains}, $type);

    if (!$domains) {
	raise("No domains configured for type '$type'\n", 400);
    }

    $acme_config->{domains} = $domains;
};

__PACKAGE__->register_method ({
    name => 'new_acme_cert',
    path => 'acme/{type}',
    method => 'POST',
    permissions => { check => [ 'admin' ] },
    description => 'Order a new certificate from ACME-compatible CA.',
    protected => 1,
    proxyto => 'node',
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    type => get_standard_option('pmg-certificate-type'),
	    force => {
		type => 'boolean',
		description => 'Overwrite existing custom certificate.',
		optional => 1,
		default => 0,
	    },
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $type = extract_param($param, 'type'); # also used to know which service to restart
	my $cert_path = PMG::CertHelpers::cert_path($type);
	raise_param_exc({'force' => "Custom certificate exists but 'force' is not set."})
	    if !$param->{force} && -e $cert_path;

	my $node_config = PMG::NodeConfig::load_config();
	my $acme_config = PMG::NodeConfig::get_acme_conf($node_config);
	raise("ACME domain list in configuration is missing!", 400)
	    if !($acme_config && $acme_config->{domains} && $acme_config->{domains}->%*);

	$filter_domains->($acme_config, $type);

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();

	my $realcmd = sub {
	    STDOUT->autoflush(1);
	    my $account = $acme_config->{account};
	    my $account_file = "${acme_account_dir}/${account}";
	    die "ACME account config file '$account' does not exist.\n"
		if ! -e $account_file;

	    print "Loading ACME account details\n";
	    my $acme = PMG::RS::Acme->load($account_file);

	    my ($cert, $key) = $order_certificate->($acme, $acme_config);
	    my $certificate = "$key\n$cert";

	    update_cert($type, $cert_path, $certificate, $param->{force}, 1);

	    if ($type eq 'smtp') {
		set_smtp(1, 1);
	    }

	    die "$@\n" if $@;
	};

	return $rpcenv->fork_worker("acmenewcert", undef, $authuser, $realcmd);
    }});

__PACKAGE__->register_method ({
    name => 'renew_acme_cert',
    path => 'acme/{type}',
    method => 'PUT',
    permissions => { check => [ 'admin' ] },
    description => "Renew existing certificate from CA.",
    protected => 1,
    proxyto => 'node',
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    type => get_standard_option('pmg-certificate-type'),
	    force => {
		type => 'boolean',
		description => 'Force renewal even if expiry is more than 30 days away.',
		optional => 1,
		default => 0,
	    },
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $type = extract_param($param, 'type'); # also used to know which service to restart
	my $cert_path = PMG::CertHelpers::cert_path($type);

	raise("No current (custom) certificate found, please order a new certificate!\n")
	    if ! -e $cert_path;

	my $expires_soon = PVE::Certificate::check_expiry($cert_path, time() + 30*24*60*60);
	raise_param_exc({'force' => "Certificate does not expire within the next 30 days, and 'force' is not set."})
	    if !$expires_soon && !$param->{force};

	my $node_config = PMG::NodeConfig::load_config();
	my $acme_config = PMG::NodeConfig::get_acme_conf($node_config);
	raise("ACME domain list in configuration is missing!", 400)
	    if !$acme_config || !$acme_config->{domains}->%*;

	$filter_domains->($acme_config, $type);

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();

	my $old_cert = PVE::Tools::file_get_contents($cert_path);

	my $realcmd = sub {
	    STDOUT->autoflush(1);
	    my $account = $acme_config->{account};
	    my $account_file = "${acme_account_dir}/${account}";
	    die "ACME account config file '$account' does not exist.\n"
		if ! -e $account_file;

	    print "Loading ACME account details\n";
	    my $acme = PMG::RS::Acme->load($account_file);

	    my ($cert, $key) = $order_certificate->($acme, $acme_config);
	    my $certificate = "$key\n$cert";

	    update_cert($type, $cert_path, $certificate, 1, 1);

	    if (defined($old_cert)) {
		print "Revoking old certificate\n";
		eval {
		    $old_cert = pem_certificate($old_cert)
			or die "no certificate section found in '$cert_path'\n";
		    $acme->revoke_certificate($old_cert, undef);
		};
		warn "Revoke request to CA failed: $@" if $@;
	    }
	};

	return $rpcenv->fork_worker("acmerenew", undef, $authuser, $realcmd);
    }});

__PACKAGE__->register_method ({
    name => 'revoke_acme_cert',
    path => 'acme/{type}',
    method => 'DELETE',
    permissions => { check => [ 'admin' ] },
    description => "Revoke existing certificate from CA.",
    protected => 1,
    proxyto => 'node',
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    type => get_standard_option('pmg-certificate-type'),
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $type = extract_param($param, 'type'); # also used to know which service to restart
	my $cert_path = PMG::CertHelpers::cert_path($type);

	my $node_config = PMG::NodeConfig::load_config();
	my $acme_config = PMG::NodeConfig::get_acme_conf($node_config);
	raise("ACME domain list in configuration is missing!", 400)
	    if !$acme_config || !$acme_config->{domains}->%*;

	$filter_domains->($acme_config, $type);

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();

	my $cert = PVE::Tools::file_get_contents($cert_path);
	$cert = pem_certificate($cert)
	    or die "no certificate section found in '$cert_path'\n";

	my $realcmd = sub {
	    STDOUT->autoflush(1);
	    my $account = $acme_config->{account};
	    my $account_file = "${acme_account_dir}/${account}";
	    die "ACME account config file '$account' does not exist.\n"
		if ! -e $account_file;

	    print "Loading ACME account details\n";
	    my $acme = PMG::RS::Acme->load($account_file);

	    print "Revoking old certificate\n";
	    eval { $acme->revoke_certificate($cert, undef) };
	    if (my $err = $@) {
		# is there a better check?
		die "Revoke request to CA failed: $err" if $err !~ /"Certificate is expired"/;
	    }

	    my $code = sub {
		print "Deleting certificate files\n";
		unlink $cert_path;
		PMG::Ticket::generate_api_cert(0) if $type eq 'api';

		restart_after_cert_update($type);
	    };

	    PMG::CertHelpers::cert_lock(10, $code);

	    if ($type eq 'smtp') {
		set_smtp(0, 1);
	    }
	};

	return $rpcenv->fork_worker("acmerevoke", undef, $authuser, $realcmd);
    }});

1;
