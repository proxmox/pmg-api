package PMG::API2::SACustom;

use strict;
use warnings;

use PVE::SafeSyslog;
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;
use PVE::Tools qw(extract_param);
use PVE::Exception qw(raise_param_exc);

use PMG::RESTEnvironment;
use PMG::Utils;
use PMG::SACustom;

use base qw(PVE::RESTHandler);

my $score_properties = {
    name => {
	type => 'string',
	description => "The name of the rule.",
	pattern => '[a-zA-Z\_\-\.0-9]+',
    },
    score => {
	type => 'number',
	description => "The score the rule should be valued at.",
    },
    comment => {
	type => 'string',
	description => 'The Comment.',
	optional => 1,
    },
};

sub json_config_properties {
    my ($props, $optional) = @_;

    foreach my $opt (keys %$score_properties) {
	# copy values and not the references
	foreach my $prop (keys %{$score_properties->{$opt}}) {
	    $props->{$opt}->{$prop} = $score_properties->{$opt}->{$prop};
	}
	if ($optional->{$opt}) {
	    $props->{$opt}->{optional} = 1;
	}
    }

    return $props;
}

__PACKAGE__->register_method({
    name => 'list_scores',
    path => '',
    method => 'GET',
    description => "List custom scores.",
    #    protected => 1,
    permissions => { check => [ 'admin', 'audit' ] },
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => { },
    },
    returns => {
	type => 'array',
	items => {
	    type => 'object',
	    properties => json_config_properties({
		digest => get_standard_option('pve-config-digest'),
	    },
	    {
		# mark all properties optional, so that we can have
		# one entry with only digest, and all others without digest
		name => 1,
		score => 1,
		comment => 1,
	    }),
	},
	links => [ { rel => 'child', href => "{name}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();

	my $tmp = PVE::INotify::read_file('pmg-scores.cf', 1);

	my $changes = $tmp->{changes};
	$restenv->set_result_attrib('changes', $changes) if $changes;

	my $res = [];

	for my $rule (sort keys %{$tmp->{data}}) {
	    push @$res, $tmp->{data}->{$rule};
	}

	my $digest = PMG::SACustom::calc_digest($tmp->{data});

	push @$res, {
	    digest => $digest,
	};

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'apply_score_changes',
    path => '',
    method => 'PUT',
    protected => 1,
    description => "Apply custom score changes.",
    proxyto => 'master',
    permissions => { check => [ 'admin' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    'restart-daemon' => {
		type => 'boolean',
		description => 'If set, also restarts pmg-smtp-filter. '.
			       'This is necessary for the changes to work.',
		default => 0,
		optional => 1,
	    },
	    digest => get_standard_option('pve-config-digest'),
	},
    },
    returns => { type => "string" },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();

	my $user = $restenv->get_user();

	my $config = PVE::INotify::read_file('pmg-scores.cf');

	my $digest = PMG::SACustom::calc_digest($config);
	PVE::Tools::assert_if_modified($digest, $param->{digest})
	    if $param->{digest};

	my $realcmd = sub {
	    my $upid = shift;

	    PMG::SACustom::apply_changes();
	    if ($param->{'restart-daemon'}) {
		syslog('info', "re-starting service pmg-smtp-filter: $upid\n");
		PMG::Utils::service_cmd('pmg-smtp-filter', 'restart');
	    }
	};

	return $restenv->fork_worker('applycustomscores', undef, $user, $realcmd);
    }});

__PACKAGE__->register_method({
    name => 'revert_score_changes',
    path => '',
    method => 'DELETE',
    protected => 1,
    description => "Revert custom score changes.",
    proxyto => 'master',
    permissions => { check => [ 'admin' ] },
    parameters => {
	additionalProperties => 0,
	properties => { },
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	unlink PMG::SACustom::get_shadow_path();

	return undef;
    }});


__PACKAGE__->register_method({
    name => 'create_score',
    path => '',
    method => 'POST',
    description => "Create custom SpamAssassin score",
    protected => 1,
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => json_config_properties({
	    digest => get_standard_option('pve-config-digest'),
	}),
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $name = extract_param($param, 'name');
	my $score = extract_param($param, 'score');
	my $comment = extract_param($param, 'comment');

	my $code = sub {
	    my $config = PVE::INotify::read_file('pmg-scores.cf');

	    my $digest = PMG::SACustom::calc_digest($config);
	    PVE::Tools::assert_if_modified($digest, $param->{digest})
		if $param->{digest};

	    $config->{$name} = {
		name => $name,
		score => $score,
		comment => $comment,
	    };

	    PVE::INotify::write_file('pmg-scores.cf', $config);
	};

	PVE::Tools::lock_file("/var/lock/pmg-scores.cf.lck", 10, $code);
	die $@ if $@;

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'get_score',
    path => '{name}',
    method => 'GET',
    description => "Get custom SpamAssassin score",
    protected => 1,
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    name => {
		type => 'string',
		description => "The name of the rule.",
		pattern => '[a-zA-Z\_\-\.0-9]+',
	    },
	},
    },
    returns => {
	type => 'object',
	properties => json_config_properties(),
    },
    code => sub {
	my ($param) = @_;

	my $name = extract_param($param, 'name');
	my $config = PVE::INotify::read_file('pmg-scores.cf');

	raise_param_exc({ name => "$name not found" })
	    if !$config->{$name};

	return $config->{$name};
    }});

__PACKAGE__->register_method({
    name => 'edit_score',
    path => '{name}',
    method => 'PUT',
    description => "Edit custom SpamAssassin score",
    protected => 1,
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => json_config_properties({
	    digest => get_standard_option('pve-config-digest'),
	}),
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $name = extract_param($param, 'name');
	my $score = extract_param($param, 'score');
	my $comment = extract_param($param, 'comment');

	my $code = sub {
	    my $config = PVE::INotify::read_file('pmg-scores.cf');

	    my $digest = PMG::SACustom::calc_digest($config);
	    PVE::Tools::assert_if_modified($digest, $param->{digest})
		if $param->{digest};

	    $config->{$name} = {
		name => $name,
		score => $score,
		comment => $comment,
	    };

	    PVE::INotify::write_file('pmg-scores.cf', $config);
	};

	PVE::Tools::lock_file("/var/lock/pmg-scores.cf.lck", 10, $code);
	die $@ if $@;

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'delete_score',
    path => '{name}',
    method => 'DELETE',
    description => "Edit custom SpamAssassin score",
    protected => 1,
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    name => {
		type => 'string',
		description => "The name of the rule.",
		pattern => '[a-zA-Z\_\-\.0-9]+',
	    },
	    digest => get_standard_option('pve-config-digest'),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $name = extract_param($param, 'name');

	my $code = sub {
	    my $config = PVE::INotify::read_file('pmg-scores.cf');

	    my $digest = PMG::SACustom::calc_digest($config);
	    PVE::Tools::assert_if_modified($digest, $param->{digest})
		if $param->{digest};

	    delete $config->{$name};

	    PVE::INotify::write_file('pmg-scores.cf', $config);
	};

	PVE::Tools::lock_file("/var/lock/pmg-scores.cf.lck", 10, $code);
	die $@ if $@;

	return undef;
    }});

1;
