package PMG::API2::AuthRealm;

use strict;
use warnings;

use PVE::Exception qw(raise_param_exc);
use PVE::INotify;
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);

use PMG::AccessControl;
use PMG::Auth::Plugin;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Authentication realm index.",
    permissions => {
	description => "Anyone can access that, because we need that list for the login box (before"
	    ." the user is authenticated).",
	user => 'world',
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
		realm => { type => 'string' },
		type => { type => 'string' },
		comment => {
		    description => "A comment. The GUI use this text when you select a"
			." authentication realm on the login window.",
		    type => 'string',
		    optional => 1,
		},
	    },
	},
	links => [ { rel => 'child', href => "{realm}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $res = [];

	my $cfg = PVE::INotify::read_file(PMG::Auth::Plugin->realm_conf_id());
	my $ids = $cfg->{ids};

	for my $realm (keys %$ids) {
	    my $d = $ids->{$realm};
	    my $entry = { realm => $realm, type => $d->{type} };
	    $entry->{comment} = $d->{comment} if $d->{comment};
	    $entry->{default} = 1 if $d->{default};
	    push @$res, $entry;
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'create',
    protected => 1,
    path => '',
    method => 'POST',
    permissions => { check => [ 'admin' ] },
    description => "Add an authentication server.",
    parameters => PMG::Auth::Plugin->createSchema(0),
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	# always extract, add it with hook
	my $password = extract_param($param, 'password');

	PMG::Auth::Plugin::lock_realm_config(
	    sub {
		my $cfg = PVE::INotify::read_file(PMG::Auth::Plugin->realm_conf_id());
		my $ids = $cfg->{ids};

		my $realm = extract_param($param, 'realm');
		PMG::Auth::Plugin::pmg_verify_realm($realm);
		my $type = $param->{type};
		my $check_connection = extract_param($param, 'check-connection');

		die "authentication realm '$realm' already exists\n"
		    if $ids->{$realm};

		die "unable to use reserved name '$realm'\n"
		    if ($realm eq 'pam' || $realm eq 'pmg' || $realm eq 'quarantine');

		die "unable to create builtin type '$type'\n"
		    if ($type eq 'pam' || $type eq 'pmg');

		my $plugin = PMG::Auth::Plugin->lookup($type);
		my $config = $plugin->check_config($realm, $param, 1, 1);

		if ($config->{default}) {
		    for my $r (keys %$ids) {
			delete $ids->{$r}->{default};
		    }
		}

		$ids->{$realm} = $config;

		my $opts = $plugin->options();
		if (defined($password) && !defined($opts->{password})) {
		    $password = undef;
		    warn "ignoring password parameter";
		}
		$plugin->on_add_hook($realm, $config, password => $password);

		PVE::INotify::write_file(PMG::Auth::Plugin->realm_conf_id(), $cfg);
	    },
	    "add auth server failed",
	);
	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'update',
    path => '{realm}',
    method => 'PUT',
    permissions => { check => [ 'admin' ] },
    description => "Update authentication server settings.",
    protected => 1,
    parameters => PMG::Auth::Plugin->updateSchema(0),
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	# always extract, update in hook
	my $password = extract_param($param, 'password');

	PMG::Auth::Plugin::lock_realm_config(
	    sub {
		my $cfg = PVE::INotify::read_file(PMG::Auth::Plugin->realm_conf_id());
		my $ids = $cfg->{ids};

		my $digest = extract_param($param, 'digest');
		PVE::SectionConfig::assert_if_modified($cfg, $digest);

		my $realm = extract_param($param, 'realm');
		my $type = $ids->{$realm}->{type};
		my $check_connection = extract_param($param, 'check-connection');

		die "authentication realm '$realm' does not exist\n"
		    if !$ids->{$realm};

		my $delete_str = extract_param($param, 'delete');
		die "no options specified\n"
		    if !$delete_str && !scalar(keys %$param) && !defined($password);

		my $delete_pw = 0;
		for my $opt (PVE::Tools::split_list($delete_str)) {
		    delete $ids->{$realm}->{$opt};
		    $delete_pw = 1 if $opt eq 'password';
		}

		my $plugin = PMG::Auth::Plugin->lookup($type);
		my $config = $plugin->check_config($realm, $param, 0, 1);

		if ($config->{default}) {
		    for my $r (keys %$ids) {
			delete $ids->{$r}->{default};
		    }
		}

		for my $p (keys %$config) {
		    $ids->{$realm}->{$p} = $config->{$p};
		}

		my $opts = $plugin->options();
		if ($delete_pw || defined($password)) {
		    $plugin->on_update_hook($realm, $config, password => $password);
		} else {
		    $plugin->on_update_hook($realm, $config);
		}

		PVE::INotify::write_file(PMG::Auth::Plugin->realm_conf_id(), $cfg);
	    },
	    "update auth server failed"
	);
	return undef;
    }});

# fixme: return format!
__PACKAGE__->register_method ({
    name => 'read',
    path => '{realm}',
    method => 'GET',
    description => "Get auth server configuration.",
    permissions => { check => [ 'admin', 'qmanager', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    realm =>  get_standard_option('realm'),
	},
    },
    returns => {},
    code => sub {
	my ($param) = @_;

	my $cfg = PVE::INotify::read_file(PMG::Auth::Plugin->realm_conf_id());

	my $realm = $param->{realm};

	my $data = $cfg->{ids}->{$realm};
	die "authentication realm '$realm' does not exist\n" if !$data;

	my $type = $data->{type};

	$data->{digest} = $cfg->{digest};

	return $data;
    }});


__PACKAGE__->register_method ({
    name => 'delete',
    path => '{realm}',
    method => 'DELETE',
    permissions => { check => [ 'admin' ] },
    description => "Delete an authentication server.",
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    realm =>  get_standard_option('realm'),
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PMG::Auth::Plugin::lock_realm_config(
	    sub {
		my $cfg = PVE::INotify::read_file(PMG::Auth::Plugin->realm_conf_id());
		my $ids = $cfg->{ids};
		my $realm = $param->{realm};

		die "authentication realm '$realm' does not exist\n" if !$ids->{$realm};

		my $plugin = PMG::Auth::Plugin->lookup($ids->{$realm}->{type});

		$plugin->on_delete_hook($realm, $ids->{$realm});

		delete $ids->{$realm};

		PVE::INotify::write_file(PMG::Auth::Plugin->realm_conf_id(), $cfg);
	    },
	    "delete auth server failed",
	);
	return undef;
    }});

1;
