package PMG::API2::AccessControl;

use strict;
use warnings;

use PVE::Exception qw(raise raise_perm_exc);
use PVE::SafeSyslog;
use PMG::RESTEnvironment;
use PVE::RESTHandler;
use PVE::JSONSchema qw(get_standard_option);

use PMG::Utils;
use PMG::UserConfig;
use PMG::AccessControl;
use PMG::API2::Users;
use PMG::API2::TFA;
use PMG::TFAConfig;

use Data::Dumper;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Users",
    path => 'users',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::TFA",
    path => 'tfa',
});

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

	my $res = [
	    { subdir => 'ticket' },
	    { subdir => 'password' },
	    { subdir => 'users' },
	];

	return $res;
    }});

my sub create_or_verify_ticket : prototype($$$$$$) {
    my ($rpcenv, $username, $pw_or_ticket, $path, $otp, $tfa_challenge) = @_;

    my $ticketuser;
    my $aad;

    if ($pw_or_ticket =~ m/^PMGQUAR:/) {
	my $ticketuser = PMG::Ticket::verify_quarantine_ticket($pw_or_ticket);
	if ($ticketuser eq $username) {
	    my $csrftoken = PMG::Ticket::assemble_csrf_prevention_token($username);

	    return {
		role => 'quser',
		ticket => $pw_or_ticket,
		username => $username,
		CSRFPreventionToken => $csrftoken,
	    };
	}
    }

    my $role = PMG::AccessControl::check_user_enabled($rpcenv->{usercfg}, $username);

    my $tfa_challenge_is_ticket = 1;

    if (!$tfa_challenge) {
	$tfa_challenge_is_ticket = 0;
	($ticketuser, undef, $tfa_challenge) = PMG::Ticket::verify_ticket($pw_or_ticket, undef, 1);
	die "No ticket\n" if $tfa_challenge;

	if ($ticketuser && ($ticketuser eq 'root@pam' || $ticketuser eq $username)) {
	    # valid ticket. Note: root@pam can create tickets for other users
	} elsif ($path && PMG::Ticket::verify_vnc_ticket($pw_or_ticket, $username, $path, 1)) {
	    # valid vnc ticket for $path
	} else {
	    ($username, $tfa_challenge) =
		PMG::AccessControl::authenticate_user($username, $pw_or_ticket, 0);
	    $pw_or_ticket = $otp;
	}
    }

    if (defined($path)) {
	# verify only
	return { username => $username };
    }

    if ($tfa_challenge && $pw_or_ticket) {
	if ($tfa_challenge_is_ticket) {
	    (undef, undef, $tfa_challenge) = PMG::Ticket::verify_ticket($tfa_challenge, $username, 0);
	}
	PMG::TFAConfig::lock_config(sub {
	    my $tfa_cfg = PMG::TFAConfig->new();

	    my $origin = undef;
	    if (!$tfa_cfg->has_webauthn_origin()) {
		my $rpcenv = PMG::RESTEnvironment->get();
		$origin = 'https://'.$rpcenv->get_request_host(1);
	    }
	    my $result = $tfa_cfg->authentication_verify2(
		$username,
		$tfa_challenge,
		$pw_or_ticket,
		$origin,
	    );

	    if (!$result) {
		# Sanity check, should be unreachable.
		die "2nd factor failed\n";
	    }

	    if ($result->{'needs-saving'}) {
		$tfa_cfg->write();
	    }

	    if ($result->{'totp-limit-reached'}) {
		# FIXME: Notify/Send-mail to the user (or admin/root if none configured)
		die "failed 2nd factor: TOTP limit reached, locked\n";
	    }
	    if ($result->{'tfa-limit-reached'}) {
		# FIXME: Notify/Send-mail to the user (or admin/root if none configured)
		die "failed 2nd factor: TFA limit reached, user locked out\n";
	    }
	    if (!$result->{'result'}) {
		# "Regular" failure.
		die "failed 2nd factor\n";
	    }
	    # Otherwise TFA succeeded.
	});

	$tfa_challenge = undef;
    }

    my $ticket_data;
    my %extra;
    if ($tfa_challenge) {
	$ticket_data = '!tfa!' . $tfa_challenge;
	$aad = $username;
	$extra{NeedTFA} = 1;
    } else {
	$ticket_data = $username;
    }

    my $ticket = PMG::Ticket::assemble_ticket($ticket_data, $aad);
    my $csrftoken = PMG::Ticket::assemble_csrf_prevention_token($username);

    return {
	role => $role,
	ticket => $ticket,
	username => $username,
	CSRFPreventionToken => $csrftoken,
	%extra,
    };
};


__PACKAGE__->register_method ({
    name => 'get_ticket',
    path => 'ticket',
    method => 'GET',
    permissions => { user => 'world' },
    description => "Dummy. Useful for formatters which want to priovde a login page.",
    parameters => {
	additionalProperties => 0,
    },
    returns => { type => "null" },
    code => sub { return undef; }});

__PACKAGE__->register_method ({
    name => 'create_ticket',
    path => 'ticket',
    method => 'POST',
    permissions => {
	description => "You need to pass valid credientials.",
	user => 'world'
    },
    protected => 1, # else we can't access shadow files
    description => "Create or verify authentication ticket.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    username => {
		description => "User name",
		type => 'string',
		maxLength => 64,
	    },
	    realm => get_standard_option('realm', {
		description => "You can optionally pass the realm using this parameter. Normally the realm is simply added to the username <username>\@<relam>.",
		optional => 1,
	    }),
	    password => {
		description => "The secret password. This can also be a valid ticket.",
		type => 'string',
	    },
	    otp => {
		description => "One-time password for Two-factor authentication.",
		type => 'string',
		optional => 1,
	    },
	    path => {
		description => "Verify ticket, and check if user have access on 'path'",
		type => 'string',
		optional => 1,
		maxLength => 64,
	    },
	    'tfa-challenge' => {
		type => 'string',
		description => "The signed TFA challenge string the user wants to respond to.",
		optional => 1,
	    },
	}
    },
    returns => {
	type => "object",
	properties => {
	    username => { type => 'string' },
	    ticket => { type => 'string', optional => 1},
	    CSRFPreventionToken => { type => 'string', optional => 1 },
	    role => { type => 'string', optional => 1},
	}
    },
    code => sub {
	my ($param) = @_;

	my $username = $param->{username};

	if ($username !~ m/\@(pam|pmg|quarantine)$/) {
	    my $realm = $param->{realm} // 'quarantine';
	    $username .= "\@$realm";
	}

	$username = 'root@pam' if $username eq 'root@pmg';

	my $rpcenv = PMG::RESTEnvironment->get();

	my $res;
	eval {
	    $res = create_or_verify_ticket($rpcenv, $username,
		    $param->{password}, $param->{path}, $param->{otp}, $param->{'tfa-challenge'});
	};
	if (my $err = $@) {
	    my $clientip = $rpcenv->get_client_ip() || '';
	    syslog('err', "authentication failure; rhost=$clientip user=$username msg=$err");
	    # do not return any info to prevent user enumeration attacks
	    die PVE::Exception->new("authentication failure\n", code => 401);
	}

	syslog('info', "successful auth for user '$username'");

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'change_passsword',
    path => 'password',
    method => 'PUT',
    protected => 1, # else we can't access shadow files
    permissions => {
	description => "Each user is allowed to change his own password. Only root can change the password of another user.",
	user => 'all',
    },
    description => "Change user password.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid'),
	    password => {
		description => "The new password.",
		type => 'string',
		minLength => 5,
		maxLength => 64,
	    },
	}
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();

	my ($userid, $ruid, $realm) = PMG::Utils::verify_username($param->{userid});

	if ($authuser eq 'root@pam') {
	    # OK - root can change anything
	} else {
	    if ($realm eq 'pmg' && $authuser eq $userid) {
		# OK - each enable user can change its own password
		PMG::AccessControl::check_user_enabled($rpcenv->{usercfg}, $userid);
	    } else {
		raise_perm_exc();
	    }
	}

	PMG::AccessControl::set_user_password($userid, $param->{password});

	syslog('info', "changed password for user '$userid'");

	return undef;
    }});

1;
