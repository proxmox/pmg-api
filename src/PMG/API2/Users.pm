package PMG::API2::Users;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;
use PVE::Exception qw(raise_perm_exc);

use PMG::RESTEnvironment;
use PMG::UserConfig;
use PMG::TFAConfig;

use base qw(PVE::RESTHandler);

my $extract_userdata = sub {
    my ($entry) = @_;

    my $res = {};
    foreach my $k (keys %$entry) {
	$res->{$k} = $entry->{$k} if $k ne 'crypt_pass';
    }

    return $res;
};

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "List users.",
    proxyto => 'master',
    protected => 1,
    permissions => { check => [ 'admin', 'qmanager', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		userid => { type => 'string'},
		enable => { type => 'boolean'},
		role => { type => 'string'},
		comment => { type => 'string', optional => 1},
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
	links => [ { rel => 'child', href => "{userid}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::UserConfig->new();
	my $tfa_cfg = PMG::TFAConfig->new();

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();
	my $role = $rpcenv->get_role();

	my $res = [];

	foreach my $userid (sort keys %$cfg) {
	    next if $role eq 'qmanager' && $authuser ne $userid;
	    my $entry = $extract_userdata->($cfg->{$userid});
	    if (defined($tfa_cfg)) {
		if (my $data = $tfa_cfg->tfa_lock_status($userid)) {
		    for (qw(totp-locked tfa-locked-until)) {
			$entry->{$_} = $data->{$_} if exists($data->{$_});
		    }
		}
	    }
	    push @$res, $entry;
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'create',
    path => '',
    method => 'POST',
    proxyto => 'master',
    protected => 1,
    description => "Create new user",
    parameters => $PMG::UserConfig::create_schema,
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $cfg = PMG::UserConfig->new();

	    die "User '$param->{userid}' already exists\n"
		if $cfg->{$param->{userid}};

	    my $entry = {};
	    foreach my $k (keys %$param) {
		my $v = $param->{$k};
		if ($k eq 'password') {
		    $entry->{crypt_pass} = PVE::Tools::encrypt_pw($v);
		} else {
		    $entry->{$k} = $v;
		}
	    }

	    $entry->{enable} //= 0;
	    $entry->{expire} //= 0;
	    $entry->{role} //= 'audit';

	    $cfg->{$param->{userid}} = $entry;

	    $cfg->write();
	};

	PMG::UserConfig::lock_config($code, "create user failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'read',
    path => '{userid}',
    method => 'GET',
    description => "Read User data.",
    permissions => { check => [ 'admin', 'qmanager', 'audit' ] },
    proxyto => 'master',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid'),
	},
    },
    returns => {
	type => "object",
	properties => {},
    },
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::UserConfig->new();

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();
	my $role = $rpcenv->get_role();

	raise_perm_exc()
	    if $role eq 'qmanager' && $authuser ne $param->{userid};

	my $data = $cfg->lookup_user_data($param->{userid});

	my $res = $extract_userdata->($data);

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'write',
    path => '{userid}',
    method => 'PUT',
    description => "Update user data.",
    protected => 1,
    proxyto => 'master',
    parameters => $PMG::UserConfig::update_schema,
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $cfg = PMG::UserConfig->new();

	    my $userid = extract_param($param, 'userid');

	    my $entry = $cfg->lookup_user_data($userid);

	    my $delete_str = extract_param($param, 'delete');
	    die "no options specified\n"
		if !$delete_str && !scalar(keys %$param);

	    foreach my $k (PVE::Tools::split_list($delete_str)) {
		delete $entry->{$k};
	    }

	    foreach my $k (keys %$param) {
		my $v = $param->{$k};
		if ($k eq 'password') {
		    $entry->{crypt_pass} = PVE::Tools::encrypt_pw($v);
		} else {
		    $entry->{$k} = $v;
		}
	    }

	    $cfg->write();
	};

	PMG::UserConfig::lock_config($code, "update user failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'delete',
    path => '{userid}',
    method => 'DELETE',
    description => "Delete a user.",
    protected => 1,
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid'),
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $cfg = PMG::UserConfig->new();

	    $cfg->lookup_user_data($param->{userid}); # user exists?

	    delete $cfg->{$param->{userid}};

	    $cfg->write();
	};

	PMG::UserConfig::lock_config($code, "delete user failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'unlock_tfa',
    path => '{userid}/unlock-tfa',
    method => 'PUT',
    protected => 1,
    description => "Unlock a user's TFA authentication.",
    permissions => { check => [ 'admin' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid'),
	},
    },
    returns => { type => 'boolean' },
    code => sub {
        my ($param) = @_;

        my $userid = extract_param($param, "userid");

	my $user_was_locked = PMG::TFAConfig::lock_config(sub {
	    my $tfa_cfg = PMG::TFAConfig->new();
	    my $was_locked = $tfa_cfg->api_unlock_tfa($userid);
	    $tfa_cfg->write() if $was_locked;
	    return $was_locked;
	});

	return $user_was_locked;
    }});


1;
