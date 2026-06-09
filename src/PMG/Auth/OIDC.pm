package PMG::Auth::OIDC;

use strict;
use warnings;

use PVE::Tools;
use PVE::JSONSchema qw(parse_property_string);

use PMG::Auth::Plugin;

use base qw(PMG::Auth::Plugin);

sub type {
    return 'oidc';
}

my $autocreate_role_assignment_format = {
    source => {
        type => 'string',
        enum => ['fixed', 'from-claim'],
        default => 'fixed',
        description => "How the access role for a newly auto-created user should be selected.",
    },
    'fixed-role' => {
        type => 'string',
        enum => ['admin', 'qmanager', 'audit', 'helpdesk'],
        default => 'audit',
        optional => 1,
        description => "The fixed role that should be assigned to auto-created users.",
    },
    'role-claim' => {
        description => "OIDC claim used to assign the unique username.",
        type => 'string',
        format_description => 'Role claim.',
        default => 'role',
        optional => 1,
        pattern => qr/^[a-zA-Z0-9._:-]+$/,
    },
};

sub parse_autocreate_role_assignment {
    my ($raw) = @_;
    return undef if !$raw or !length($raw);

    my $role_assignment = parse_property_string($autocreate_role_assignment_format, $raw);
    $role_assignment->{'fixed-role'} = 'audit'
        if $role_assignment->{'source'} eq 'fixed' && !defined($role_assignment->{'fixed-role'});

    $role_assignment->{'role-claim'} = 'role'
        if $role_assignment->{'source'} eq 'from-claim'
        && !defined($role_assignment->{'role-claim'});

    return $role_assignment;
}

sub properties {
    return {
        'issuer-url' => {
            description => "OpenID Connect Issuer Url",
            type => 'string',
            maxLength => 256,
            pattern => qr/^(https?):\/\/([a-zA-Z0-9.-]+)(:[0-9]{1,5})?(\/[^\s]*)?$/,
        },
        # See RFC 6749, Appendix A for the allowed pattern for `client-id` and
        # `client-key`.
        # https://www.rfc-editor.org/rfc/rfc6749#appendix-A
        # tl;dr: anything ASCII in the (inclusive) range 0x20-0x7E
        'client-id' => {
            description => "OpenID Connect Client ID",
            type => 'string',
            maxLength => 256,
            pattern => qr/^[\x20-\x7E]+$/,
        },
        'client-key' => {
            description => "OpenID Connect Client Key",
            type => 'string',
            optional => 1,
            maxLength => 256,
            pattern => qr/^[\x20-\x7E]+$/,
        },
        autocreate => {
            description => "Automatically create users if they do not exist.",
            optional => 1,
            type => 'boolean',
            default => 0,
        },
        'autocreate-role' => { # NOTE: deprecated since the beginning, just here for compat
            description => "Automatically create users with a specific role."
                . " NOTE: Deprecated, favor 'autocreate-role-assignment'",
            type => 'string',
            enum => ['admin', 'qmanager', 'audit', 'helpdesk'],
            default => 'audit',
            optional => 1,
        },
        'autocreate-role-assignment' => {
            description => "Defines which role should be assigned to auto-created users.",
            type => 'string',
            format => $autocreate_role_assignment_format,
            default => 'source=fixed,fixed-role=auditor',
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
                . " reauthentication and consent.",
            type => 'string',
            pattern => '(?:none|login|consent|select_account|\S+)', # \S+ is the extension variant
            optional => 1,
        },
        scopes => {
            description => "Specifies the scopes (user details) that should be authorized and"
                . " returned, for example 'email' or 'profile'.",
            type => 'string', # format => 'some-safe-id-list', # FIXME: TODO
            default => "email profile",
            pattern => qr/^[a-zA-Z0-9._:-]+$/,
            optional => 1,
        },
        'acr-values' => {
            description =>
                "Specifies the Authentication Context Class Reference values that the"
                . "Authorization Server is being requested to use for the Auth Request.",
            type => 'string', # format => 'some-safe-id-list', # FIXME: TODO
            pattern => qr/^[a-zA-Z0-9._:-]+$/,
            optional => 1,
        },
        'audiences' => {
            description =>
                "A list of audiences that the OpenID Issuer may include that are accepted in "
                . "addition to 'client-id'.",
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
        'autocreate-role' => { optional => 1 }, # NOTE: deprecated in favor of 'autocreate-role-assignment'
        'autocreate-role-assignment' => { optional => 1 },
        'username-claim' => { optional => 1, fixed => 1 },
        prompt => { optional => 1 },
        scopes => { optional => 1 },
        'acr-values' => { optional => 1 },
        audiences => { optional => 1 },
        default => { optional => 1 },
        comment => { optional => 1 },
    };
}

sub authenticate_user {
    my ($class, $config, $realm, $username, $password) = @_;

    die "OpenID Connect realm does not allow password verification.\n";
}

1;
