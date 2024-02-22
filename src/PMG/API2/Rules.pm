package PMG::API2::Rules;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use HTTP::Status qw(:constants);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;

use PMG::Config;

use PMG::RuleDB;
use PMG::DBTools;
use PMG::API2::ObjectGroupHelpers;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    id => {
		description => "Rule ID.",
		type => 'integer',
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

	my $rdb = PMG::RuleDB->new();

	$rdb->load_rule($param->{id}); # test if rule exist

	return [
	    { subdir => 'config' },
	    { subdir => 'from' },
	    { subdir => 'to' },
	    { subdir => 'when' },
	    { subdir => 'what' },
	    { subdir => 'actions' },
	];

    }});

__PACKAGE__->register_method ({
    name => 'delete_rule',
    path => '',
    method => 'DELETE',
    description => "Delete rule.",
    proxyto => 'master',
    protected => 1,
    permissions => { check => [ 'admin' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    id => {
		description => "Rule ID.",
		type => 'integer',
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();

	$rdb->load_rule($param->{id}); # test if rule exist

	$rdb->delete_rule($param->{id});

	PMG::DBTools::reload_ruledb();

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'config',
    path => 'config',
    method => 'GET',
    description => "Get common rule properties.",
    proxyto => 'master',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    id => {
		description => "Rule ID.",
		type => 'integer',
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
	    id => { type => 'integer'},
	    name => { type => 'string' },
	    active => { type => 'boolean' },
	    direction => { type => 'integer' },
	    priority => { type => 'integer' },
	},
    },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();

	my $rule = $rdb->load_rule($param->{id});

	my ($from, $to, $when, $what, $action) =
	    $rdb->load_groups($rule);

	my $data = PMG::API2::ObjectGroupHelpers::format_rule(
	    $rule, $from, $to, $when, $what, $action);

	return $data;
   }});

my $rule_params = {
    direction => {
	description => "Rule direction. Value `0` matches incoming mails, value `1` matches outgoing mails, and value `2` matches both directions.",
	type => 'integer',
	minimum => 0,
	maximum => 2,
	optional => 1,
    },
    active => {
	description => "Flag to activate rule.",
	type => 'boolean',
	optional => 1,
    },
    'what-and' => {
	description => "Flag to 'and' combine WHAT group matches.",
	type => 'boolean',
	default => 0,
	optional => 1,
    },
    'what-invert' => {
	description => "Flag to invert WHAT group matches.",
	type => 'boolean',
	default => 0,
	optional => 1,
    },
    'when-and' => {
	description => "Flag to 'and' combine WHEN group matches.",
	type => 'boolean',
	default => 0,
	optional => 1,
    },
    'when-invert' => {
	description => "Flag to invert WHEN group matches.",
	type => 'boolean',
	default => 0,
	optional => 1,
    },
    'from-and' => {
	description => "Flag to 'and' combine FROM group matches.",
	type => 'boolean',
	default => 0,
	optional => 1,
    },
    'from-invert' => {
	description => "Flag to invert FROM group matches.",
	type => 'boolean',
	default => 0,
	optional => 1,
    },
    'to-and' => {
	description => "Flag to 'and' combine TO group matches.",
	type => 'boolean',
	default => 0,
	optional => 1,
    },
    'to-invert' => {
	description => "Flag to invert TO group matches.",
	type => 'boolean',
	default => 0,
	optional => 1,
    },
};

sub get_rule_params {
    my ($base) = @_;
    $base //= {};
    return {
	$base->%*,
	$rule_params->%*
    };
}


__PACKAGE__->register_method ({
    name => 'update_config',
    path => 'config',
    method => 'PUT',
    description => "Set rule properties.",
    proxyto => 'master',
    protected => 1,
    permissions => { check => [ 'admin' ] },
    parameters => {
	additionalProperties => 0,
	properties => get_rule_params({
	    id => {
		description => "Rule ID.",
		type => 'integer',
	    },
	    name => {
		description => "Rule name",
		type => 'string',
		optional => 1,
	    },
	    priority => {
		description => "Rule priority.",
		type => 'integer',
		minimum => 0,
		maximum => 100,
		optional => 1,
	    },
	}),
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	my $id = extract_param($param, 'id');

	die "no options specified\n"
	    if !scalar(keys %$param);

	my $rdb = PMG::RuleDB->new();

	my $rule = $rdb->load_rule($id);

	my $keys = ["name", "priority"];
	push $keys->@*, keys get_rule_params()->%*;

	for my $key ($keys->@*) {
	    $rule->{$key} = $param->{$key} if defined($param->{$key});
	}

	$rdb->save_rule($rule);

	PMG::DBTools::reload_ruledb();

	return undef;
   }});

my $register_rule_group_api = sub {
    my ($name) = @_;

    __PACKAGE__->register_method ({
	name => $name,
	path => $name,
	method => 'GET',
	description => "Get '$name' group list.",
	proxyto => 'master',
	permissions => { check => [ 'admin', 'audit' ] },
	parameters => {
	    additionalProperties => 0,
	    properties => {
		id => {
		    description => "Rule ID.",
		    type => 'integer',
		},
	    },
	},
	returns => {
	    type => 'array',
	    items => {
		type => "object",
		properties => {
		    id => { type => 'integer' },
		},
	    },
	},
	code => sub {
	    my ($param) = @_;

	    my $rdb = PMG::RuleDB->new();

	    my $rule = $rdb->load_rule($param->{id});

	    my $group_hash = $rdb->load_groups_by_name($rule);

	    return PMG::API2::ObjectGroupHelpers::format_object_group(
		$group_hash->{$name});
	}});

    __PACKAGE__->register_method ({
	name => "add_${name}_group",
	path => $name,
	method => 'POST',
	description => "Add  group to '$name' list.",
	proxyto => 'master',
	protected => 1,
	permissions => { check => [ 'admin' ] },
	parameters => {
	    additionalProperties => 0,
	    properties => {
		id => {
		    description => "Rule ID.",
		    type => 'integer',
		},
		ogroup => {
		    description => "Groups ID.",
		    type => 'integer',
		},
	    },
	},
	returns => { type => 'null' },
	code => sub {
	    my ($param) = @_;

	    my $rdb = PMG::RuleDB->new();

	    my $rule = $rdb->load_rule($param->{id});

	    $rdb->rule_add_group($param->{id}, $param->{ogroup}, $name);

	    PMG::DBTools::reload_ruledb();

	    return undef;
	}});

    __PACKAGE__->register_method ({
	name => "delete_${name}_group",
	path => "$name/{ogroup}",
	method => 'DELETE',
	description => "Delete group from '$name' list.",
	proxyto => 'master',
	protected => 1,
	permissions => { check => [ 'admin' ] },
	parameters => {
	    additionalProperties => 0,
	    properties => {
		id => {
		    description => "Rule ID.",
		    type => 'integer',
		},
		ogroup => {
		    description => "Groups ID.",
		    type => 'integer',
		},
	    },
	},
	returns => { type => 'null' },
	code => sub {
	    my ($param) = @_;

	    my $rdb = PMG::RuleDB->new();

	    my $rule = $rdb->load_rule($param->{id});

	    $rdb->rule_remove_group($param->{id}, $param->{ogroup}, $name);

	    PMG::DBTools::reload_ruledb();

	    return undef;
	}});

};

$register_rule_group_api->('from');
$register_rule_group_api->('to');
$register_rule_group_api->('when');
$register_rule_group_api->('what');
$register_rule_group_api->('action');

1;
