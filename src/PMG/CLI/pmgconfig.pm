package PMG::CLI::pmgconfig;

use strict;
use warnings;
use IO::File;
use Data::Dumper;

use Term::ReadLine;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::INotify;
use PVE::CLIHandler;
use PVE::JSONSchema qw(get_standard_option);

use PMG::RESTEnvironment;
use PMG::RuleDB;
use PMG::RuleCache;
use PMG::Cluster;
use PMG::LDAPConfig;
use PMG::LDAPSet;
use PMG::Config;
use PMG::Ticket;

use PMG::API2::ACME;
use PMG::API2::ACMEPlugin;
use PMG::API2::Certificates;
use PMG::API2::DKIMSign;

use base qw(PVE::CLIHandler);

my $nodename = PVE::INotify::nodename();

sub setup_environment {
    PMG::RESTEnvironment->setup_default_cli_env();
}

my $upid_exit = sub {
    my $upid = shift;
    my $status = PVE::Tools::upid_read_status($upid);
    print "Task $status\n";
    exit($status eq 'OK' ? 0 : -1);
};

sub param_mapping {
    my ($name) = @_;

    my $load_file_and_encode = sub {
	my ($filename) = @_;

	return PVE::ACME::Challenge->encode_value('string', 'data', PVE::Tools::file_get_contents($filename));
    };

    my $mapping = {
	'upload_custom_cert' => [
	    'certificates',
	    'key',
	],
	'add_plugin' => [
	    ['data', $load_file_and_encode, "File with one key-value pair per line, will be base64url encode for storage in plugin config.", 0],
	],
	'update_plugin' => [
	    ['data', $load_file_and_encode, "File with one key-value pair per line, will be base64url encode for storage in plugin config.", 0],
	],
    };

    return $mapping->{$name};
}

__PACKAGE__->register_method ({
    name => 'dump',
    path => 'dump',
    method => 'POST',
    description => "Print configuration setting which can be used in templates.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::Config->new();
	my $vars = $cfg->get_template_vars();

	foreach my $realm (sort keys %$vars) {
	    foreach my $section (sort keys %{$vars->{$realm}}) {
		my $secvalue = $vars->{$realm}->{$section} // '';
		if (ref($secvalue)) {
		    foreach my $key (sort keys %{$vars->{$realm}->{$section}}) {
			my $value = $vars->{$realm}->{$section}->{$key} // '';
			print "$realm.$section.$key = $value\n";
		    }
		} else {
		    print "$realm.$section = $secvalue\n";
		}
	    }
	}

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'sync',
    path => 'sync',
    method => 'POST',
    description => "Synchronize Proxmox Mail Gateway configurations with system configuration.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    restart => {
		description => "Restart services if necessary.",
		type => 'boolean',
		default => 0,
		optional => 1,
	    },
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::Config->new();

	my $ruledb = PMG::RuleDB->new();
	my $rulecache = PMG::RuleCache->new($ruledb);

	$cfg->rewrite_config($rulecache, $param->{restart});

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'ldapsync',
    path => 'ldapsync',
    method => 'POST',
    description => "Synchronize the LDAP database.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $ldap_cfg = PVE::INotify::read_file("pmg-ldap.conf");
	PMG::LDAPSet::ldap_resync($ldap_cfg, 1);

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'apicert',
    path => 'apicert',
    method => 'POST',
    description => "Generate /etc/pmg/pmg-api.pem (self signed certificate for GUI and REST API).",
    parameters => {
	additionalProperties => 0,
	properties => {
	    force => {
		description => "Overwrite existing certificate.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    },
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	PMG::Ticket::generate_api_cert($param->{force});

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'tlscert',
    path => 'tlscert',
    method => 'POST',
    description => "Generate /etc/pmg/pmg-tls.pem (self signed certificate for encrypted SMTP traffic).",
    parameters => {
	additionalProperties => 0,
	properties => {
	    force => {
		description => "Overwrite existing certificate.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    },
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	PMG::Utils::gen_proxmox_tls_cert($param->{force});

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'init',
    path => 'init',
    method => 'POST',
    description => "Generate required files in /etc/pmg/",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::Config->new();

	PMG::Ticket::generate_api_cert();
	PMG::Ticket::generate_csrf_key();
	PMG::Ticket::generate_auth_key();

	if ($cfg->get('mail', 'tls')) {
	    PMG::Utils::gen_proxmox_tls_cert();
	}

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'acme_register',
    path => 'acme_register',
    method => 'POST',
    description => "Register a new ACME account with a compatible CA.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    name => get_standard_option('pmg-acme-account-name'),
	    contact => get_standard_option('pmg-acme-account-contact'),
	    directory => get_standard_option('pmg-acme-directory-url', {
		optional => 1,
	    }),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $custom_directory = 1;
	if (!$param->{directory}) {
	    my $directories = PMG::API2::ACME->get_directories({});
	    print "Directory endpoints:\n";
	    my $i = 0;
	    while ($i < @$directories) {
		print $i, ") ", $directories->[$i]->{name}, " (", $directories->[$i]->{url}, ")\n";
		$i++;
	    }
	    print $i, ") Custom\n";

	    my $term = Term::ReadLine->new('pmgconfig');
	    my $get_dir_selection = sub {
		my $selection = $term->readline("Enter selection: ");
		if ($selection =~ /^(\d+)$/) {
		    $selection = $1;
		    if ($selection == $i) {
			$param->{directory} = $term->readline("Enter custom URL: ");
			return;
		    } elsif ($selection < $i && $selection >= 0) {
			$param->{directory} = $directories->[$selection]->{url};
			$custom_directory = 0;
			return;
		    }
		}
		print "Invalid selection.\n";
	    };

	    my $attempts = 0;
	    while (!$param->{directory}) {
		die "Aborting.\n" if $attempts > 3;
		$get_dir_selection->();
		$attempts++;
	    }
	}

	print "\nAttempting to fetch Terms of Service from '$param->{directory}'..\n";
	my $meta = PMG::API2::ACME->get_meta({ directory => $param->{directory} });
	if ($meta->{termsOfService}) {
	    my $tos = $meta->{termsOfService};
	    print "Terms of Service: $tos\n";
	    my $term = Term::ReadLine->new('pmgconfig');
	    my $agreed = $term->readline('Do you agree to the above terms? [y|N]: ');
	    die "Cannot continue without agreeing to ToS, aborting.\n"
		if ($agreed !~ /^y$/i);

	    $param->{tos_url} = $tos;
	} else {
	    print "No Terms of Service found, proceeding.\n";
	}

	my $eab_enabled = $meta->{externalAccountRequired};
	if (!$eab_enabled && $custom_directory) {
	    my $term = Term::ReadLine->new('pmgconfig');
	    my $agreed = $term->readline('Do you want to use external account binding? [y|N]: ');
	    $eab_enabled = ($agreed =~ /^y$/i);
	} elsif ($eab_enabled) {
	    print "The CA requires external account binding.\n";
	}
	if ($eab_enabled) {
	    print "You should have received a key id and a key from your CA.\n";
	    my $term = Term::ReadLine->new('pmgconfig');
	    my $eab_kid = $term->readline('Enter EAB key id: ');
	    my $eab_hmac_key = $term->readline('Enter EAB key: ');

	    $param->{'eab-kid'} = $eab_kid;
	    $param->{'eab-hmac-key'} = $eab_hmac_key;
	}

	print "\nAttempting to register account with '$param->{directory}'..\n";

	$upid_exit->(PMG::API2::ACME->register_account($param));
    }});

my $print_cert_info = sub {
    my ($schema, $cert, $options) = @_;

    my $order = [qw(filename fingerprint subject issuer notbefore notafter public-key-type public-key-bits san)];
    PVE::CLIFormatter::print_api_result(
	$cert, $schema, $order, { %$options, noheader => 1, sort_key => 0 });
};

our $cmddef = {
    'dump' => [ __PACKAGE__, 'dump', []],
    sync => [ __PACKAGE__, 'sync', []],
    ldapsync => [ __PACKAGE__, 'ldapsync', []],
    apicert => [ __PACKAGE__, 'apicert', []],
    tlscert => [ __PACKAGE__, 'tlscert', []],
    init => [ __PACKAGE__, 'init', []],
    dkim_set => [ 'PMG::API2::DKIMSign', 'set_selector', []],
    dkim_record => [ 'PMG::API2::DKIMSign', 'get_selector_info', [], undef,
	sub {
	    my ($res) = @_;
	    die "no dkim_selector configured\n" if !defined($res->{record});
	    print "$res->{record}\n";
	}],

    cert => {
	info => [ 'PMG::API2::Certificates', 'info', [], { node => $nodename }, sub {
	    my ($res, $schema, $options) = @_;

	    if (!$options->{'output-format'} || $options->{'output-format'} eq 'text') {
		for my $cert (sort { $a->{filename} cmp $b->{filename} } @$res) {
		    $print_cert_info->($schema->{items}, $cert, $options);
		}
	    } else {
		PVE::CLIFormatter::print_api_result($res, $schema, undef, $options);
	    }

	}, $PVE::RESTHandler::standard_output_options],
	set => [ 'PMG::API2::Certificates', 'upload_custom_cert', ['type', 'certificates', 'key'], { node => $nodename }, sub {
	    my ($res, $schema, $options) = @_;
	    $print_cert_info->($schema, $res, $options);
	}, $PVE::RESTHandler::standard_output_options],
	delete => [ 'PMG::API2::Certificates', 'remove_custom_cert', ['type', 'restart'], { node => $nodename } ],
    },

    acme => {
	account => {
	    list => [ 'PMG::API2::ACME', 'account_index', [], {}, sub {
		my ($res) = @_;
		for my $acc (@$res) {
		    print "$acc->{name}\n";
		}
	    }],
	    register => [ __PACKAGE__, 'acme_register', ['name', 'contact'], {}, $upid_exit ],
	    deactivate => [ 'PMG::API2::ACME', 'deactivate_account', ['name'], {}, $upid_exit ],
	    info => [ 'PMG::API2::ACME', 'get_account', ['name'], {}, sub {
		my ($data, $schema, $options) = @_;
		PVE::CLIFormatter::print_api_result($data, $schema, undef, $options);
	    }, $PVE::RESTHandler::standard_output_options],
	    update => [ 'PMG::API2::ACME', 'update_account', ['name'], {}, $upid_exit ],
	},
	cert => {
	    order => [ 'PMG::API2::Certificates', 'new_acme_cert', ['type'], { node => $nodename }, $upid_exit ],


	    renew => [ 'PMG::API2::Certificates', 'renew_acme_cert', ['type'], { node => $nodename }, $upid_exit ],
	    revoke => [ 'PMG::API2::Certificates', 'revoke_acme_cert', ['type'], { node => $nodename }, $upid_exit ],
	},
	plugin => {
	    list => [ 'PMG::API2::ACMEPlugin', 'index', [], {}, sub {
		my ($data, $schema, $options) = @_;
		PVE::CLIFormatter::print_api_result($data, $schema, undef, $options);
	    }, $PVE::RESTHandler::standard_output_options ],
	    config => [ 'PMG::API2::ACMEPlugin', 'get_plugin_config', ['id'], {}, sub {
		my ($data, $schema, $options) = @_;
		PVE::CLIFormatter::print_api_result($data, $schema, undef, $options);
	    }, $PVE::RESTHandler::standard_output_options ],
	    add => [ 'PMG::API2::ACMEPlugin', 'add_plugin', ['type', 'id'] ],
	    set => [ 'PMG::API2::ACMEPlugin', 'update_plugin', ['id'] ],
	    remove => [ 'PMG::API2::ACMEPlugin', 'delete_plugin', ['id'] ],
	},

    },
};


1;
