package PMG::API2::TFA;

use strict;
use warnings;

use HTTP::Status qw(:constants);

use PVE::Exception qw(raise raise_perm_exc raise_param_exc);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;

use PMG::AccessControl;
use PMG::RESTEnvironment;
use PMG::TFAConfig;
use PMG::UserConfig;
use PMG::Utils;

use base qw(PVE::RESTHandler);

my $OPTIONAL_PASSWORD_SCHEMA = {
    description => "The current password.",
    type => 'string',
    optional => 1, # Only required if not root@pam
    minLength => 5,
    maxLength => 64
};

my $TFA_TYPE_SCHEMA = {
    type => 'string',
    description => 'TFA Entry Type.',
    enum => [qw(totp u2f webauthn recovery)],
};

my %TFA_INFO_PROPERTIES = (
    id => {
	type => 'string',
	description => 'The id used to reference this entry.',
    },
    description => {
	type => 'string',
	description => 'User chosen description for this entry.',
    },
    created => {
	type => 'integer',
	description => 'Creation time of this entry as unix epoch.',
    },
    enable => {
	type => 'boolean',
	description => 'Whether this TFA entry is currently enabled.',
	optional => 1,
	default => 1,
    },
);

my $TYPED_TFA_ENTRY_SCHEMA = {
    type => 'object',
    description => 'TFA Entry.',
    properties => {
	type => $TFA_TYPE_SCHEMA,
	%TFA_INFO_PROPERTIES,
    },
};

my $TFA_ID_SCHEMA = {
    type => 'string',
    description => 'A TFA entry id.',
};

my $TFA_UPDATE_INFO_SCHEMA = {
    type => 'object',
    properties => {
	id => {
	    type => 'string',
	    description => 'The id of a newly added TFA entry.',
	},
	challenge => {
	    type => 'string',
	    optional => 1,
	    description =>
		'When adding u2f entries, this contains a challenge the user must respond to in'
		.' order to finish the registration.'
	},
	recovery => {
	    type => 'array',
	    optional => 1,
	    description =>
		'When adding recovery codes, this contains the list of codes to be displayed to'
		.' the user',
	    items => {
		type => 'string',
		description => 'A recovery entry.'
	    },
	},
    },
};

# Set TFA to enabled if $tfa_cfg is passed, or to disabled if $tfa_cfg is undef,
# When enabling we also merge the old user.cfg keys into the $tfa_cfg.
my sub set_user_tfa_enabled : prototype($$$) {
    my ($userid, $realm, $tfa_cfg) = @_;

    PMG::UserConfig::lock_config(sub {
	my $cfg = PMG::UserConfig->new();
	my $user = $cfg->lookup_user_data($userid);

	# We had the 'keys' property available in PMG for a while, but never used it.
	# If the keys property had been used by someone, let's just error out here.
	my $keys = $user->{keys};
	die "user has an unsupported 'keys' value, please remove\n"
	    if defined($keys) && $keys ne 'x';

	$user->{keys} = $tfa_cfg ? 'x' : undef;

	$cfg->write();
    }, "enabling/disabling TFA for the user failed");
}

# Only root may modify root, regular users need to specify their password.
#
# Returns the userid returned from `verify_username`.
# Or ($userid, $realm) in list context.
my sub check_permission_password : prototype($$$$) {
    my ($rpcenv, $authuser, $userid, $password) = @_;

    ($userid, my $ruid, my $realm) = PMG::Utils::verify_username($userid);
    raise("no access from quarantine\n") if $realm eq 'quarantine';

    raise_perm_exc() if $userid eq 'root@pam' && $authuser ne 'root@pam';

    # Regular users need to confirm their password to change TFA settings.
    if ($authuser ne 'root@pam') {
	raise_param_exc({ 'password' => 'password is required to modify TFA data' })
	    if !defined($password);

	PMG::AccessControl::authenticate_user($userid, $password, 1);
    }

    return wantarray ? ($userid, $realm) : $userid;
}

my sub check_permission_self : prototype($$) {
    my ($rpcenv, $userid) = @_;

    my $authuser = $rpcenv->get_user();

    ($userid, my $ruid, my $realm) = PMG::Utils::verify_username($userid);
    raise("no access from quarantine\n") if $realm eq 'quarantine';

    if ($authuser eq 'root@pam') {
	# OK - root can change anything
    } else {
	if ($realm eq 'pmg' && $authuser eq $userid) {
	    # OK - each enable user can see their own data
	    PMG::AccessControl::check_user_enabled($rpcenv->{usercfg}, $userid);
	} else {
	    raise_perm_exc();
	}
    }
}

__PACKAGE__->register_method ({
    name => 'list_user_tfa',
    path => '{userid}',
    method => 'GET',
    proxyto => 'master',
    permissions => {
	description => 'Each user is allowed to view their own TFA entries.'
	    .' Only root can view entries of another user.',
	user => 'all',
    },
    protected => 1, # else we can't access shadow files
    allowtoken => 0, # we don't want tokens to change the regular user's TFA settings
    description => 'List TFA configurations of users.',
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid'),
	}
    },
    returns => {
	description => "A list of the user's TFA entries.",
	type => 'array',
	items => $TYPED_TFA_ENTRY_SCHEMA,
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	check_permission_self($rpcenv, $param->{userid});

	my $tfa_cfg = PMG::TFAConfig->new();
	return $tfa_cfg->api_list_user_tfa($param->{userid});
    }});

__PACKAGE__->register_method ({
    name => 'get_tfa_entry',
    path => '{userid}/{id}',
    method => 'GET',
    proxyto => 'master',
    permissions => {
	description => 'Each user is allowed to view their own TFA entries.'
	    .' Only root can view entries of another user.',
	user => 'all',
    },
    protected => 1, # else we can't access shadow files
    allowtoken => 0, # we don't want tokens to change the regular user's TFA settings
    description => 'Fetch a requested TFA entry if present.',
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid'),
	    id => $TFA_ID_SCHEMA,
	}
    },
    returns => $TYPED_TFA_ENTRY_SCHEMA,
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	check_permission_self($rpcenv, $param->{userid});

	my $tfa_cfg = PMG::TFAConfig->new();
	my $id = $param->{id};
	my $entry = $tfa_cfg->api_get_tfa_entry($param->{userid}, $id);
	raise("No such tfa entry '$id'", code => HTTP::Status::HTTP_NOT_FOUND) if !$entry;
	return $entry;
    }});

__PACKAGE__->register_method ({
    name => 'delete_tfa',
    path => '{userid}/{id}',
    method => 'DELETE',
    proxyto => 'master',
    permissions => {
	description => 'Each user is allowed to modify their own TFA entries.'
	    .' Only root can modify entries of another user.',
	#user => 'all', # we do not support TFA for quarantine users currently
	check => [ 'admin', 'qmanager', 'audit' ],
    },
    protected => 1, # else we can't access shadow files
    allowtoken => 0, # we don't want tokens to change the regular user's TFA settings
    description => 'Delete a TFA entry by ID.',
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid'),
	    id => $TFA_ID_SCHEMA,
	    password => $OPTIONAL_PASSWORD_SCHEMA,
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	check_permission_self($rpcenv, $param->{userid});

	my $authuser = $rpcenv->get_user();
	my $userid =
	    check_permission_password($rpcenv, $authuser, $param->{userid}, $param->{password});

	my $has_entries_left = PMG::TFAConfig::lock_config(sub {
	    my $tfa_cfg = PMG::TFAConfig->new();
	    my $has_entries_left = $tfa_cfg->api_delete_tfa($userid, $param->{id});
	    $tfa_cfg->write();
	    return $has_entries_left;
	});

	if (!$has_entries_left) {
	    set_user_tfa_enabled($userid, undef, undef);
	}
    }});

__PACKAGE__->register_method ({
    name => 'list_tfa',
    path => '',
    method => 'GET',
    proxyto => 'master',
    permissions => {
	description => "Returns all or just the logged-in user, depending on privileges.",
	user => 'all',
    },
    protected => 1, # else we can't access shadow files
    allowtoken => 0, # we don't want tokens to change the regular user's TFA settings
    description => 'List TFA configurations of users.',
    parameters => {
	additionalProperties => 0,
	properties => {}
    },
    returns => {
	description => "The list tuples of user and TFA entries.",
	type => 'array',
	items => {
	    type => 'object',
	    properties => {
		userid => {
		    type => 'string',
		    description => 'User this entry belongs to.',
		},
		entries => {
		    type => 'array',
		    items => $TYPED_TFA_ENTRY_SCHEMA,
		},
		'totp-locked' => {
		    type => 'boolean',
		    optional => 1,
		    description => 'True if the user is currently locked out of TOTP factors.',
		},
		'tfa-locked-until' => {
		    type => 'integer',
		    optional => 1,
		    description =>
			'Contains a timestamp until when a user is locked out of 2nd factors.',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();
	my $top_level_allowed = ($authuser eq 'root@pam');

	my $tfa_cfg = PMG::TFAConfig->new();
	return $tfa_cfg->api_list_tfa($authuser, $top_level_allowed);
    }});

__PACKAGE__->register_method ({
    name => 'add_tfa_entry',
    path => '{userid}',
    method => 'POST',
    proxyto => 'master',
    permissions => {
	description => 'Each user is allowed to modify their own TFA entries.'
	    .' Only root can modify entries of another user.',
	#user => 'all', # we do not support TFA for quarantine users currently
	check => [ 'admin', 'qmanager', 'audit' ],
    },
    protected => 1, # else we can't access shadow files
    allowtoken => 0, # we don't want tokens to change the regular user's TFA settings
    description => 'Add a TFA entry for a user.',
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid'),
            type => $TFA_TYPE_SCHEMA,
	    description => {
		type => 'string',
		description => 'A description to distinguish multiple entries from one another',
		maxLength => 255,
		optional => 1,
	    },
	    totp => {
		type => 'string',
		description => "A totp URI.",
		optional => 1,
	    },
	    value => {
		type => 'string',
		description =>
		    'The current value for the provided totp URI, or a Webauthn/U2F'
		    .' challenge response',
		optional => 1,
	    },
	    challenge => {
		type => 'string',
		description => 'When responding to a u2f challenge: the original challenge string',
		optional => 1,
	    },
	    password => $OPTIONAL_PASSWORD_SCHEMA,
	},
    },
    returns => $TFA_UPDATE_INFO_SCHEMA,
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	check_permission_self($rpcenv, $param->{userid});
	my $authuser = $rpcenv->get_user();
	my ($userid, $realm) =
	    check_permission_password($rpcenv, $authuser, $param->{userid}, $param->{password});

	my $type = delete $param->{type};
	my $value = delete $param->{value};

	return PMG::TFAConfig::lock_config(sub {
	    my $tfa_cfg = PMG::TFAConfig->new();

	    set_user_tfa_enabled($userid, $realm, $tfa_cfg);
	    my $origin = undef;
	    if (!$tfa_cfg->has_webauthn_origin()) {
		$origin = 'https://'.$rpcenv->get_request_host(1);
	    }

	    my $response = $tfa_cfg->api_add_tfa_entry(
		$userid,
		$param->{description},
		$param->{totp},
		$value,
		$param->{challenge},
		$type,
		$origin,
	    );

	    $tfa_cfg->write();

	    return $response;
	});
    }});

__PACKAGE__->register_method ({
    name => 'update_tfa_entry',
    path => '{userid}/{id}',
    method => 'PUT',
    proxyto => 'master',
    permissions => {
	description => 'Each user is allowed to modify their own TFA entries.'
	    .' Only root can modify entries of another user.',
	#user => 'all', # we do not support TFA for quarantine users currently
	check => [ 'admin', 'qmanager', 'audit' ],
    },
    protected => 1, # else we can't access shadow files
    allowtoken => 0, # we don't want tokens to change the regular user's TFA settings
    description => 'Add a TFA entry for a user.',
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid', {
		completion => \&PVE::AccessControl::complete_username,
	    }),
	    id => $TFA_ID_SCHEMA,
	    description => {
		type => 'string',
		description => 'A description to distinguish multiple entries from one another',
		maxLength => 255,
		optional => 1,
	    },
	    enable => {
		type => 'boolean',
		description => 'Whether the entry should be enabled for login.',
		optional => 1,
	    },
	    password => $OPTIONAL_PASSWORD_SCHEMA,
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	check_permission_self($rpcenv, $param->{userid});
	my $authuser = $rpcenv->get_user();
	my $userid =
	    check_permission_password($rpcenv, $authuser, $param->{userid}, $param->{password});

	PMG::TFAConfig::lock_config(sub {
	    my $tfa_cfg = PMG::TFAConfig->new();

	    $tfa_cfg->api_update_tfa_entry(
		$userid,
		$param->{id},
		$param->{description},
		$param->{enable},
	    );

	    $tfa_cfg->write();
	});
    }});

1;
