package PMG::API2::LDAP;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use HTTP::Status qw(:constants);
use Storable qw(dclone);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;

use PMG::LDAPConfig;
use PMG::LDAPCache;
use PMG::LDAPSet;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "List configured LDAP profiles.",
    proxyto => 'master',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
    	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		profile => { type => 'string'},
		disable => { type => 'boolean' },
		server1 => { type => 'string'},
		server2 => { type => 'string', optional => 1},
		comment => { type => 'string', optional => 1},
		gcount => { type => 'integer', optional => 1},
		mcount => { type => 'integer', optional => 1},
		ucount => { type => 'integer', optional => 1},
		mode => { type => 'string'},
	    },
	},
	links => [ { rel => 'child', href => "{profile}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $ldap_cfg = PMG::LDAPConfig->new();

	my $ldap_set = PMG::LDAPSet->new_from_ldap_cfg($ldap_cfg, 1);

	my $res = [];

	if (defined($ldap_cfg)) {
	    foreach my $profile (keys %{$ldap_cfg->{ids}}) {
		my $d = $ldap_cfg->{ids}->{$profile};
		my $entry = {
		    profile => $profile,
		    disable => $d->{disable} ? 1 : 0,
		    server1 => $d->{server1},
		    mode => $d->{mode} // 'ldap',
		};
		$entry->{server2} = $d->{server2} if defined($d->{server2});
		$entry->{comment} = $d->{comment} if defined($d->{comment});

		if (my $d = $ldap_set->{$profile}) {
		    foreach my $k (qw(gcount mcount ucount)) {
			my $v = $d->{$k};
			$entry->{$k} = $v if defined($v);
		    }
		}

		push @$res, $entry;
	    }
	}

	return $res;
    }});

my $forced_ldap_sync = sub {
    my ($profile, $config) = @_;

    my $ldapcache = PMG::LDAPCache->new(
	id => $profile, syncmode => 2, %$config);

    die $ldapcache->{errors} if $ldapcache->{errors};

    die "unable to find valid email addresses\n"
	if !$ldapcache->{mcount};
};

__PACKAGE__->register_method ({
    name => 'create',
    path => '',
    method => 'POST',
    proxyto => 'master',
    permissions => { check => [ 'admin' ] },
    protected => 1,
    description => "Add LDAP profile.",
    parameters => PMG::LDAPConfig->createSchema(1),
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $cfg = PMG::LDAPConfig->new();

	    $cfg->{ids} //= {};

	    my $ids = $cfg->{ids};

	    my $profile = extract_param($param, 'profile');
	    my $type = $param->{type};

	    die "LDAP profile '$profile' already exists\n"
		if $ids->{$profile};

	    my $config = PMG::LDAPConfig->check_config($profile, $param, 1, 1);

	    $ids->{$profile} = $config;

	    $forced_ldap_sync->($profile, $config)
		if !$config->{disable};

	    $cfg->write();
	};

	PMG::LDAPConfig::lock_config($code, "add LDAP profile failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'profile_index',
    path => '{profile}',
    method => 'GET',
    description => "Directory index",
    permissions => {
	user => 'all',
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    profile => {
		description => "Profile ID.",
		type => 'string', format => 'pve-configid',
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		subdir => { type => 'string'},
	    },
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($param) = @_;

	return [
	    { subdir => 'config' },
	    { subdir => 'sync' },
	    { subdir => 'users' },
	    { subdir => 'groups' },
	];
    }});

__PACKAGE__->register_method ({
    name => 'read_config',
    path => '{profile}/config',
    method => 'GET',
    description => "Get LDAP profile configuration.",
    proxyto => 'master',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    profile => {
		description => "Profile ID.",
		type => 'string', format => 'pve-configid',
	    },
	},
    },
    returns => {},
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::LDAPConfig->new();

	my $profile = $param->{profile};

	my $data = $cfg->{ids}->{$profile};
	die "LDAP profile '$profile' does not exist\n" if !$data;

	# we do not want to get the password over the api
	delete $data->{bindpw};

	$data->{digest} = $cfg->{digest};

	return $data;
    }});

__PACKAGE__->register_method ({
    name => 'update_config',
    path => '{profile}/config',
    method => 'PUT',
    description => "Update LDAP profile settings.",
    permissions => { check => [ 'admin' ] },
    protected => 1,
    proxyto => 'master',
    parameters => PMG::LDAPConfig->updateSchema(),
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $cfg = PMG::LDAPConfig->new();
	    my $ids = $cfg->{ids};

	    my $digest = extract_param($param, 'digest');
	    PVE::SectionConfig::assert_if_modified($cfg, $digest);

	    my $profile = extract_param($param, 'profile');

	    die "LDAP profile '$profile' does not exist\n"
		if !$ids->{$profile};

	    my $delete_str = extract_param($param, 'delete');
	    die "no options specified\n"
		if !$delete_str && !scalar(keys %$param);

	    foreach my $opt (PVE::Tools::split_list($delete_str)) {
		delete $ids->{$profile}->{$opt};
	    }

	    my $config = PMG::LDAPConfig->check_config($profile, $param, 0, 1);

	    foreach my $p (keys %$config) {
		$ids->{$profile}->{$p} = $config->{$p};
	    }

	    $forced_ldap_sync->($profile, $ids->{$profile})
		if !$config->{disable};

	    $cfg->write();
	};

	PMG::LDAPConfig::lock_config($code, "update LDAP profile failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'sync_profile',
    path => '{profile}/sync',
    method => 'POST',
    description => "Synchronice LDAP users to local database.",
    permissions => { check => [ 'admin' ] },
    protected => 1,
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    profile => {
		description => "Profile ID.",
		type => 'string', format => 'pve-configid',
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::LDAPConfig->new();
	my $ids = $cfg->{ids};

	my $profile = extract_param($param, 'profile');

	die "LDAP profile '$profile' does not exist\n"
	    if !$ids->{$profile};

	my $config = $ids->{$profile};

	if ($config->{disable}) {
	    die "LDAP profile '$profile' is disabled\n";
	} else {
	    $forced_ldap_sync->($profile, $config)
	}

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'delete',
    path => '{profile}',
    method => 'DELETE',
    description => "Delete an LDAP profile",
    permissions => { check => [ 'admin' ] },
    protected => 1,
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    profile => {
		description => "Profile ID.",
		type => 'string', format => 'pve-configid',
	    },
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $cfg = PMG::LDAPConfig->new();
	    my $ids = $cfg->{ids};

	    my $profile = $param->{profile};

	    die "LDAP profile '$profile' does not exist\n"
		if !$ids->{$profile};

	    delete $ids->{$profile};

	    PMG::LDAPCache->delete($profile);

	    $cfg->write();
	};

	PMG::LDAPConfig::lock_config($code, "delete LDAP profile failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'profile_list_users',
    path => '{profile}/users',
    method => 'GET',
    description => "List LDAP users.",
    permissions => { check => [ 'admin', 'audit' ] },
    protected => 1,
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    profile => {
		description => "Profile ID.",
		type => 'string', format => 'pve-configid',
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		dn => { type => 'string'},
		account => { type => 'string'},
		pmail => { type => 'string'},
	    },
	},
	links => [ { rel => 'child', href => "{pmail}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::LDAPConfig->new();
	my $ids = $cfg->{ids};

	my $profile = $param->{profile};

	die "LDAP profile '$profile' does not exist\n"
	    if !$ids->{$profile};

	my $config = $ids->{$profile};

	return [] if $config->{disable};

	my $ldapcache = PMG::LDAPCache->new(
	    id => $profile, syncmode => 1, %$config);

	return $ldapcache->list_users();
    }});

__PACKAGE__->register_method ({
    name => 'address_list',
    path => '{profile}/users/{email}',
    method => 'GET',
    description => "Get all email addresses for the specified user.",
    permissions => { check => [ 'admin', 'audit' ] },
    protected => 1,
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    profile => {
		description => "Profile ID.",
		type => 'string', format => 'pve-configid',
	    },
	    email => get_standard_option('pmg-email-address', {
		description => "Email address.",
	    }),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		primary => { type => 'boolean'},
		email => { type => 'string'},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::LDAPConfig->new();
	my $ids = $cfg->{ids};

	my $profile = $param->{profile};

	die "LDAP profile '$profile' does not exist\n"
	    if !$ids->{$profile};

	my $config = $ids->{$profile};

	die "profile '$profile' is disabled\n" if $config->{disable};

	my $ldapcache = PMG::LDAPCache->new(
	    id => $profile, syncmode => 1, %$config);

	my $res = $ldapcache->list_addresses($param->{email});

	die "unable to find ldap user with email address '$param->{email}'\n"
	    if !$res;

	return $res;

    }});

__PACKAGE__->register_method ({
    name => 'profile_list_groups',
    path => '{profile}/groups',
    method => 'GET',
    description => "List LDAP groups.",
    permissions => { check => [ 'admin', 'audit' ] },
    protected => 1,
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    profile => {
		description => "Profile ID.",
		type => 'string', format => 'pve-configid',
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		dn => { type => 'string'},
		gid => { type => 'number' },
	    },
	},
	links => [ { rel => 'child', href => "{gid}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::LDAPConfig->new();
	my $ids = $cfg->{ids};

	my $profile = $param->{profile};

	die "LDAP profile '$profile' does not exist\n"
	    if !$ids->{$profile};

	my $config = $ids->{$profile};

	return [] if $config->{disable};

	my $ldapcache = PMG::LDAPCache->new(
	    id => $profile, syncmode => 1, %$config);

	return $ldapcache->list_groups();
    }});

__PACKAGE__->register_method ({
    name => 'profile_list_group_members',
    path => '{profile}/groups/{gid}',
    method => 'GET',
    description => "List LDAP group members.",
    permissions => { check => [ 'admin', 'audit' ] },
    protected => 1,
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    profile => {
		description => "Profile ID.",
		type => 'string', format => 'pve-configid',
	    },
	    gid => {
		description => "Group ID",
		type => 'number',
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		dn => { type => 'string'},
		account => { type => 'string' },
		pmail => { type => 'string' },
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $cfg = PMG::LDAPConfig->new();
	my $ids = $cfg->{ids};

	my $profile = $param->{profile};

	die "LDAP profile '$profile' does not exist\n"
	    if !$ids->{$profile};

	my $config = $ids->{$profile};

	return [] if $config->{disable};

	my $ldapcache = PMG::LDAPCache->new(
	    id => $profile, syncmode => 1, %$config);

	return $ldapcache->list_users($param->{gid});
    }});

1;
