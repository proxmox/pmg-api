package PMG::Auth::OIDC;

use strict;
use warnings;

use PVE::Tools;
use PMG::Auth::Plugin;

use base qw(PMG::Auth::Plugin);

sub type {
    return 'oidc';
}

sub properties {
    return {
	'issuer-url' => {
	    description => "OpenID Connect Issuer Url",
	    type => 'string',
	    maxLength => 256,
	    pattern => qr/^(https?):\/\/([a-zA-Z0-9.-]+)(:[0-9]{1,5})?(\/[^\s]*)?$/,
	},
	'client-id' => {
	    description => "OpenID Connect Client ID",
	    type => 'string',
	    maxLength => 256,
	    pattern => qr/^[a-zA-Z0-9._:-]+$/,
	},
	'client-key' => {
	    description => "OpenID Connect Client Key",
	    type => 'string',
	    optional => 1,
	    maxLength => 256,
	    pattern => qr/^[a-zA-Z0-9._:-]+$/,
	},
	autocreate => {
	    description => "Automatically create users if they do not exist.",
	    optional => 1,
	    type => 'boolean',
	    default => 0,
	},
	'autocreate-role' => {
	    description => "Automatically create users with a specific role.",
	    type => 'string',
	    enum => ['admin', 'qmanager', 'audit', 'helpdesk'],
	    default => 'audit',
	    optional => 1,
	},
	'username-claim' => {
	    description => "OpenID Connect claim used to generate the unique username.",
	    type => 'string',
	    optional => 1,
	    default => 'sub',
	    pattern => qr/^[a-zA-Z0-9._:-]+$/,
	},
	prompt => {
	    description => "Specifies whether the Authorization Server prompts the End-User for"
	        ." reauthentication and consent.",
	    type => 'string',
	    pattern => '(?:none|login|consent|select_account|\S+)', # \S+ is the extension variant
	    optional => 1,
	},
	scopes => {
	    description => "Specifies the scopes (user details) that should be authorized and"
	        ." returned, for example 'email' or 'profile'.",
	    type => 'string', # format => 'some-safe-id-list', # FIXME: TODO
	    default => "email profile",
	    pattern => qr/^[a-zA-Z0-9._:-]+$/,
	    optional => 1,
	},
	'acr-values' => {
	    description => "Specifies the Authentication Context Class Reference values that the"
		."Authorization Server is being requested to use for the Auth Request.",
	    type => 'string', # format => 'some-safe-id-list', # FIXME: TODO
	    pattern => qr/^[a-zA-Z0-9._:-]+$/,
	    optional => 1,
	},
   };
}

sub options {
    return {
	'issuer-url' => {},
	'client-id' => {},
	'client-key' => { optional => 1 },
	autocreate => { optional => 1 },
	'autocreate-role' => { optional => 1 },
	'username-claim' => { optional => 1, fixed => 1 },
	prompt => { optional => 1 },
	scopes => { optional => 1 },
	'acr-values' => { optional => 1 },
	default => { optional => 1 },
	comment => { optional => 1 },
    };
}

sub authenticate_user {
    my ($class, $config, $realm, $username, $password) = @_;

    die "OpenID Connect realm does not allow password verification.\n";
}

1;
