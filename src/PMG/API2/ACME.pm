package PMG::API2::ACME;

use strict;
use warnings;

use File::Path;

use PVE::Exception qw(raise_param_exc);
use PVE::JSONSchema qw(get_standard_option);
use PVE::Tools qw(extract_param);

use PVE::ACME::Challenge;

use PMG::RESTEnvironment;
use PMG::RS::Acme;
use PMG::CertHelpers;

use PMG::API2::ACMEPlugin;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    subclass => "PMG::API2::ACMEPlugin",
    path => 'plugins',
});

# FIXME: Put this list in pve-common or proxmox-acme{,-rs}?
my $acme_directories = [
    {
	name => 'Let\'s Encrypt V2',
	url => 'https://acme-v02.api.letsencrypt.org/directory',
    },
    {
	name => 'Let\'s Encrypt V2 Staging',
	url => 'https://acme-staging-v02.api.letsencrypt.org/directory',
    },
];
my $acme_default_directory_url = $acme_directories->[0]->{url};
my $account_contact_from_param = sub {
    my @addresses = PVE::Tools::split_list(extract_param($_[0], 'contact'));
    return [ map { "mailto:$_" } @addresses ];
};
my $acme_account_dir = PMG::CertHelpers::acme_account_dir();

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    permissions => { user => 'all' },
    description => "ACME index.",
    parameters => {
	additionalProperties => 0,
	properties => {
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
	    { name => 'account' },
	    { name => 'tos' },
	    { name => 'meta' },
	    { name => 'directories' },
	    { name => 'plugins' },
	    { name => 'challenge-schema' },
	];
    }});

__PACKAGE__->register_method ({
    name => 'account_index',
    path => 'account',
    method => 'GET',
    permissions => { check => [ 'admin', 'audit' ] },
    description => "ACME account index.",
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
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

	my $accounts = PMG::CertHelpers::list_acme_accounts();
	return [ map { { name => $_ }  } @$accounts ];
    }});

# extract the optional account name and fill in the default, also return the file name
my sub extract_account_name : prototype($) {
    my ($param) = @_;

    my $account_name = extract_param($param, 'name') // 'default';
    my $account_file = "${acme_account_dir}/${account_name}";

    return ($account_name, $account_file);
}

__PACKAGE__->register_method ({
    name => 'register_account',
    path => 'account',
    method => 'POST',
    description => "Register a new ACME account with CA.",
    proxyto => 'master',
    permissions => { check => [ 'admin' ] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    name => get_standard_option('pmg-acme-account-name'),
	    contact => get_standard_option('pmg-acme-account-contact'),
	    tos_url => {
		type => 'string',
		description => 'URL of CA TermsOfService - setting this indicates agreement.',
		optional => 1,
	    },
	    directory => get_standard_option('pmg-acme-directory-url', {
		default => $acme_default_directory_url,
		optional => 1,
	    }),
	    'eab-kid' => {
		type => 'string',
		description => 'Key Identifier for External Account Binding.',
		requires => 'eab-hmac-key',
		optional => 1,
	    },
	    'eab-hmac-key' => {
		type => 'string',
		description => 'HMAC key for External Account Binding.',
		requires => 'eab-kid',
		optional => 1,
	    },
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();

	my ($account_name, $account_file) = extract_account_name($param);
	mkpath $acme_account_dir if ! -e $acme_account_dir;

	raise_param_exc({'name' => "ACME account config file '${account_name}' already exists."})
	    if -e $account_file;

	my $directory = extract_param($param, 'directory') // $acme_default_directory_url;
	my $contact = $account_contact_from_param->($param);
	my $eab_kid = extract_param($param, 'eab-kid');
	my $eab_hmac_key = extract_param($param, 'eab-hmac-key');

	my $realcmd = sub {
	    PMG::CertHelpers::lock_acme($account_name, 10, sub {
		die "ACME account config file '${account_name}' already exists.\n"
		    if -e $account_file;

		print "Registering new ACME account..\n";
		my $acme = PMG::RS::Acme->new($directory);
		eval {
		    $acme->new_account($account_file, defined($param->{tos_url}), $contact, undef, $eab_kid, $eab_hmac_key);
		};
		if (my $err = $@) {
		    unlink $account_file;
		    die "Registration failed: $err\n";
		}
		my $location = $acme->location();
		print "Registration successful, account URL: '$location'\n";
	    });
	};

	return $rpcenv->fork_worker('acmeregister', undef, $authuser, $realcmd);
    }});

my $update_account = sub {
    my ($param, $msg, $force_deactivate, %info) = @_;

    my ($account_name, $account_file) = extract_account_name($param);

    raise_param_exc({'name' => "ACME account config file '${account_name}' does not exist."})
	if ! -e $account_file;


    my $rpcenv = PMG::RESTEnvironment->get();
    my $authuser = $rpcenv->get_user();

    my $realcmd = sub {
	PMG::CertHelpers::lock_acme($account_name, 10, sub {
	    die "ACME account config file '${account_name}' does not exist.\n"
		if ! -e $account_file;

	    my $acme = PMG::RS::Acme->load($account_file);
	    eval {
		$acme->update_account(\%info);
	    };
	    if (my $err = $@) {
		die $err if !$force_deactivate;
		warn "got error, but forced to continue - $err\n";
	    }
	    if ($info{status} && $info{status} eq 'deactivated') {
		my $deactivated_name;
		for my $i (0..100) {
		    my $candidate = "${acme_account_dir}/_deactivated_${account_name}_${i}";
		    if (! -e $candidate) {
			$deactivated_name = $candidate;
			last;
		    }
		}
		if ($deactivated_name) {
		    print "Renaming account file from '$account_file' to '$deactivated_name'\n";
		    rename($account_file, $deactivated_name) or
			warn ".. failed - $!\n";
		} else {
		    warn "No free slot to rename deactivated account file '$account_file', leaving in place\n";
		}
	    }
	});
    };

    return $rpcenv->fork_worker("acme${msg}", undef, $authuser, $realcmd);
};

__PACKAGE__->register_method ({
    name => 'update_account',
    path => 'account/{name}',
    method => 'PUT',
    description => "Update existing ACME account information with CA. Note: not specifying any new account information triggers a refresh.",
    proxyto => 'master',
    permissions => { check => [ 'admin' ] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    name => get_standard_option('pmg-acme-account-name'),
	    contact => get_standard_option('pmg-acme-account-contact', {
		optional => 1,
	    }),
	},
    },
    returns => {
	type => 'string',
    },
    code => sub {
	my ($param) = @_;

	my $contact = $account_contact_from_param->($param);
	if (scalar @$contact) {
	    return $update_account->($param, 'update', 0, contact => $contact);
	} else {
	    return $update_account->($param, 'refresh', 0);
	}
    }});

__PACKAGE__->register_method ({
    name => 'get_account',
    path => 'account/{name}',
    method => 'GET',
    description => "Return existing ACME account information.",
    protected => 1,
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    name => get_standard_option('pmg-acme-account-name'),
	},
    },
    returns => {
	type => 'object',
	additionalProperties => 0,
	properties => {
	    account => {
		type => 'object',
		optional => 1,
		renderer => 'yaml',
	    },
	    directory => get_standard_option('pmg-acme-directory-url', {
		optional => 1,
	    }),
	    location => {
		type => 'string',
		optional => 1,
	    },
	    tos => {
		type => 'string',
		optional => 1,
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my ($account_name, $account_file) = extract_account_name($param);

	raise_param_exc({'name' => "ACME account config file '${account_name}' does not exist."})
	    if ! -e $account_file;

	my $acme = PMG::RS::Acme->load($account_file);
	my $data = $acme->account();

	return {
	    account => $data->{account},
	    tos => $data->{tos},
	    location => $data->{location},
	    directory => $data->{directoryUrl},
	};
    }});

__PACKAGE__->register_method ({
    name => 'deactivate_account',
    path => 'account/{name}',
    method => 'DELETE',
    description => "Deactivate existing ACME account at CA.",
    protected => 1,
    proxyto => 'master',
    permissions => { check => [ 'admin' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    name => get_standard_option('pmg-acme-account-name'),
	    force => {
		type => 'boolean',
		description =>
		    'Delete account data even if the server refuses to deactivate the account.',
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

	my $force_deactivate = extract_param($param, 'force');

	return $update_account->($param, 'deactivate', $force_deactivate, status => 'deactivated');
    }});

# TODO: deprecated, remove with pmg 9
__PACKAGE__->register_method ({
    name => 'get_tos',
    path => 'tos',
    method => 'GET',
    description => "Retrieve ACME TermsOfService URL from CA. Deprecated, please use /config/acme/meta.",
    permissions => { user => 'all' },
    parameters => {
	additionalProperties => 0,
	properties => {
	    directory => get_standard_option('pmg-acme-directory-url', {
		default => $acme_default_directory_url,
		optional => 1,
	    }),
	},
    },
    returns => {
	type => 'string',
	optional => 1,
	description => 'ACME TermsOfService URL.',
    },
    code => sub {
	my ($param) = @_;

	my $directory = extract_param($param, 'directory') // $acme_default_directory_url;

	my $acme = PMG::RS::Acme->new($directory);
	my $meta = $acme->get_meta();

	return $meta ? $meta->{termsOfService} : undef;
    }});

__PACKAGE__->register_method ({
    name => 'get_meta',
    path => 'meta',
    method => 'GET',
    description => "Retrieve ACME Directory Meta Information",
    permissions => { user => 'all' },
    parameters => {
	additionalProperties => 0,
	properties => {
	    directory => get_standard_option('pmg-acme-directory-url', {
		default => $acme_default_directory_url,
		optional => 1,
	    }),
	},
    },
    returns => {
	type => 'object',
	additionalProperties => 1,
	properties => {
	    termsOfService => {
		description => 'ACME TermsOfService URL.',
		type => 'string',
		optional => 1,
	    },
	    externalAccountRequired => {
		description => 'EAB Required',
		type => 'boolean',
		optional => 1,
	    },
	    website => {
		description => 'URL to more information about the ACME server.',
		type => 'string',
		optional => 1,
	    },
	    caaIdentities => {
		description => 'Hostnames referring to the ACME servers.',
		type => 'array',
		items => {
		    type => 'string',
		},
		optional => 1,
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $directory = extract_param($param, 'directory') // $acme_default_directory_url;

	my $acme = PVE::ACME->new(undef, $directory);
	my $meta = $acme->get_meta();

	return $meta;
    }});

__PACKAGE__->register_method ({
    name => 'get_directories',
    path => 'directories',
    method => 'GET',
    description => "Get named known ACME directory endpoints.",
    permissions => { user => 'all' },
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => 'object',
	    additionalProperties => 0,
	    properties => {
		name => {
		    type => 'string',
		},
		url => get_standard_option('pmg-acme-directory-url'),
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	return $acme_directories;
    }});

__PACKAGE__->register_method ({
    name => 'challenge-schema',
    path => 'challenge-schema',
    method => 'GET',
    description => "Get schema of ACME challenge types.",
    permissions => { user => 'all' },
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => 'object',
	    additionalProperties => 0,
	    properties => {
		id => {
		    type => 'string',
		},
		name => {
		    description => 'Human readable name, falls back to id',
		    type => 'string',
		},
		type => {
		    type => 'string',
		},
		schema => {
		    type => 'object',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $plugin_type_enum = PVE::ACME::Challenge->lookup_types();

	my $res = [];

	for my $type (@$plugin_type_enum) {
	    my $plugin = PVE::ACME::Challenge->lookup($type);
	    next if !$plugin->can('get_supported_plugins');

	    my $plugin_type = $plugin->type();
	    my $plugins = $plugin->get_supported_plugins();
	    for my $id (sort keys %$plugins) {
		my $schema = $plugins->{$id};
		push @$res, {
		    id => $id,
		    name => $schema->{name} // $id,
		    type => $plugin_type,
		    schema => $schema,
		};
	    }
	}

	return $res;
    }});

1;
