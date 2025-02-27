package PMG::API2::OIDC;

use strict;
use warnings;

use PVE::Tools qw(extract_param lock_file);
use Proxmox::RS::OIDC;

use PVE::Exception qw(raise raise_perm_exc raise_param_exc);
use PVE::SafeSyslog;
use PVE::INotify;
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;

use PMG::AccessControl;
use PMG::Auth::OIDC;
use PMG::Auth::Plugin;
use PMG::RESTEnvironment;

use base qw(PVE::RESTHandler);

my $oidc_state_path = "/var/lib/pmg";

my $lookup_oidc_auth = sub {
    my ($realm, $redirect_url) = @_;

    my $cfg = PVE::INotify::read_file(PMG::Auth::Plugin::realm_conf_id());
    my $ids = $cfg->{ids};

    die "authentication domain '$realm' does not exist\n" if !$ids->{$realm};

    my $config = $ids->{$realm};
    die "wrong realm type ($config->{type} != oidc)\n" if $config->{type} ne "oidc";

    my $oidc_config = {
	issuer_url => $config->{'issuer-url'},
	client_id => $config->{'client-id'},
	client_key => $config->{'client-key'},
    };
    $oidc_config->{prompt} = $config->{'prompt'} if defined($config->{'prompt'});

    my $scopes = $config->{'scopes'} // 'email profile';
    $oidc_config->{scopes} = [ PVE::Tools::split_list($scopes) ];

    if (defined(my $acr = $config->{'acr-values'})) {
	$oidc_config->{acr_values} = [ PVE::Tools::split_list($acr) ];
    }

    my $oidc = Proxmox::RS::OIDC->discover($oidc_config, $redirect_url);
    return ($config, $oidc);
};

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
    permissions => {
	user => 'all',
    },
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		subdir => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($param) = @_;

	return [
	    { subdir => 'auth-url' },
	    { subdir => 'login' },
	];
    }});

__PACKAGE__->register_method ({
    name => 'auth_url',
    path => 'auth-url',
    method => 'POST',
    protected => 1,
    description => "Get the OpenId Connect Authorization Url for the specified realm.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    realm => {
		description => "Authentication domain ID",
		type => 'string',
		pattern => qr/[A-Za-z][A-Za-z0-9\.\-_]+/,
		maxLength => 32,
	    },
	    'redirect-url' => {
		description => "Redirection Url. The client should set this to the used server url (location.origin).",
		type => 'string',
		maxLength => 255,
	    },
	},
    },
    returns => {
	type => "string",
	description => "Redirection URL.",
    },
    permissions => { user => 'world' },
    code => sub {
	my ($param) = @_;

	my $realm = extract_param($param, 'realm');
	my $redirect_url = extract_param($param, 'redirect-url');

	my ($config, $oidc) = $lookup_oidc_auth->($realm, $redirect_url);
	my $url = $oidc->authorize_url($oidc_state_path , $realm);

	return $url;
    }});

__PACKAGE__->register_method ({
    name => 'login',
    path => 'login',
    method => 'POST',
    protected => 1,
    description => " Verify OpenID Connect authorization code and create a ticket.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    'state' => {
		description => "OpenId Connect state.",
		type => 'string',
		maxLength => 1024,
            },
	    code => {
		description => "OpenId Connect authorization code.",
		type => 'string',
		maxLength => 4096,
            },
	    'redirect-url' => {
		description => "Redirection Url. The client should set this to the used server url (location.origin).",
		type => 'string',
		maxLength => 255,
	    },
	},
    },
    returns => {
	properties => {
	    role => { type => 'string', optional => 1},
	    username => { type => 'string' },
	    ticket => { type => 'string' },
	    CSRFPreventionToken => { type => 'string' },
	},
    },
    permissions => { user => 'world' },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();

	my $res;
	eval {
	    my ($realm, $private_auth_state) = Proxmox::RS::OIDC::verify_public_auth_state(
		$oidc_state_path, $param->{'state'});

	    my $redirect_url = extract_param($param, 'redirect-url');

	    my ($config, $oidc) = $lookup_oidc_auth->($realm, $redirect_url);

	    my $info = $oidc->verify_authorization_code($param->{code}, $private_auth_state);
	    my $subject = $info->{'sub'};

	    my $unique_name;

	    my $user_attr = $config->{'username-claim'} // 'sub';
	    if (defined($info->{$user_attr})) {
		$unique_name = $info->{$user_attr};
	    } elsif ($user_attr eq 'subject') { # stay compat with old versions
		$unique_name = $subject;
	    } elsif ($user_attr eq 'username') { # stay compat with old versions
		my $username = $info->{'preferred_username'};
		die "missing claim 'preferred_username'\n" if !defined($username);
		$unique_name =  $username;
	    } else {
		# neither the attr nor fallback are defined in info..
		die "missing configured claim '$user_attr' in returned info object\n";
	    }

	    my $username = "${unique_name}\@${realm}";
	    # first, check if $username respects our naming conventions
	    PMG::Utils::verify_username($username);
	    if ($config->{'autocreate'} && !$rpcenv->check_user_exist($username, 1)) {
		die "cannot auto-create users on stand-by nodes, please log in to the active master\n"
		    if !$rpcenv->check_node_is_master(1);
		my $code = sub {
		    my $usercfg = PMG::UserConfig->new();

		    my $entry = { enable => 1 };
		    if (my $email = $info->{'email'}) {
			$entry->{email} = $email;
		    }
		    if (defined(my $given_name = $info->{'given_name'})) {
			$entry->{firstname} = $given_name;
		    }
		    if (defined(my $family_name = $info->{'family_name'})) {
			$entry->{lastname} = $family_name;
		    }

		    # NOTE: 'autocreate-role' is deprecated and has less priority than the more
		    # flexible 'autocreate-role-assignment'
		    $entry->{role} = $config->{'autocreate-role'} // 'audit'; # default
		    if (my $role_assignment_raw = $config->{'autocreate-role-assignment'}) {
			my $role_assignment =
			    PMG::Auth::OIDC::parse_autocreate_role_assignment($role_assignment_raw);

			if ($role_assignment->{source} eq 'fixed') {
			    $entry->{role} = $role_assignment->{'fixed-role'};
			} elsif ($role_assignment->{source} eq 'from-claim') {
			    my $role_attr = $role_assignment->{'role-claim'};
			    if (my $role = $info->{$role_attr}) {
				$role = lc($role); # normalize to lower-case
				die "required '$role_attr' role-claim attribute not found, cannot autocreate user\n"
				    if $role !~ /^(?:admin|qmanager|audit|helpdesk)$/;
				$entry->{role} = $role;
			    } else {
				die "required '$role_attr' role-claim attribute not found, cannot autocreate user\n";
			    }
			} else {
			    die "unknown role assignment source '$role_assignment->{source}' - implement me";
			}
		    }
		    $entry->{userid} = $username;
		    $entry->{username} = $unique_name;
		    $entry->{realm} = $realm;

		    die "User '$username' already exists\n"
			if $usercfg->{$username};

		    $usercfg->{$username} = $entry;

		    $usercfg->write();
		};
		PMG::UserConfig::lock_config($code, "autocreate openid connect user failed");
	    }
	    my $role = $rpcenv->check_user_enabled($username);

	    my $ticket = PMG::Ticket::assemble_ticket($username);
	    my $csrftoken = PMG::Ticket::assemble_csrf_prevention_token($username);

	    $res = {
		ticket => $ticket,
		username => $username,
		CSRFPreventionToken => $csrftoken,
		role => $role,
	    };

	};
	if (my $err = $@) {
	    my $clientip = $rpcenv->get_client_ip() || '';
	    syslog('err', "openid connect authentication failure; rhost=$clientip msg=$err");
	    # do not return any info to prevent user enumeration attacks
	    die PVE::Exception->new("authentication failure $err\n", code => 401);
	}

	syslog('info', "successful openid connect auth for user '$res->{username}'");

	return $res;
    }});
