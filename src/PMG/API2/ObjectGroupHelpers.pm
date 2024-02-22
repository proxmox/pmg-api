package PMG::API2::ObjectGroupHelpers;

use strict;
use warnings;

use PVE::INotify;
use PVE::RESTHandler;
use PVE::JSONSchema qw(get_standard_option);
use PMG::RESTEnvironment;
use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);

use PMG::DBTools;
use PMG::RuleDB;

sub format_rule {
    my ($rule, $from, $to, $when, $what, $action) = @_;

    my $cond_create_group = sub {
	my ($res, $name, $groupdata) = @_;

	return if !$groupdata;

	$res->{$name} = format_object_group($groupdata);
    };

    my $data = {
	id =>  $rule->{id},
	name => $rule->{name},
	priority => $rule->{priority},
	active => $rule->{active},
	direction => $rule->{direction},
    };
    my $types = [qw(what when from to)];
    my $attributes = [qw(and invert)];
    for my $type ($types->@*) {
	for my $attribute ($attributes->@*) {
	    my $opt = "${type}-${attribute}";
	    $data->{$opt} = $rule->{$opt} if defined($rule->{$opt});
	}
    }

    $cond_create_group->($data, 'from', $from);
    $cond_create_group->($data, 'to', $to);
    $cond_create_group->($data, 'when', $when);
    $cond_create_group->($data, 'what', $what);
    $cond_create_group->($data, 'action', $action);

    return $data;
}

sub format_object_group {
    my ($ogroups) = @_;

    my $res = [];
    foreach my $og (@$ogroups) {
	my $group = { id => $og->{id}, name => $og->{name}, info => $og->{info} };
	$group->{and} = $og->{and} if defined($og->{and});
	$group->{invert} = $og->{invert} if defined($og->{invert});
	push @$res, $group;
    }
    return $res;
}

my $group_attributes = {
    and => {
	description => "If set to 1, objects in this group are 'and' combined.",
	type => 'boolean',
	default => 0,
	optional => 1,
    },
    invert => {
	description => "If set to 1, the resulting match is inverted.",
	type => 'boolean',
	default => 0,
	optional => 1,
    },
};

sub register_group_list_api {
    my ($apiclass, $oclass) = @_;

    $apiclass->register_method({
	name => "list_${oclass}_groups",
	path => $oclass,
	method => 'GET',
	description => "Get list of '$oclass' groups.",
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
		    id => { type => 'integer' },
		},
	    },
	},
	code => sub {
	    my ($param) = @_;

	    my $rdb = PMG::RuleDB->new();

	    my $ogroups = $rdb->load_objectgroups($oclass);

	    return format_object_group($ogroups);
	}});

    my $additional_parameters = {};
    if ($oclass =~ /^(?:what|when|who)$/i) {
	$additional_parameters = { $group_attributes->%* };
    }

    $apiclass->register_method({
	name => "create_${oclass}_group",
	path => $oclass,
	method => 'POST',
	description => "Create a new '$oclass' group.",
	proxyto => 'master',
	protected => 1,
	permissions => { check => [ 'admin' ] },
	parameters => {
	    additionalProperties => 0,
	    properties => {
		name => {
		    description => "Group name.",
		    type => 'string',
		    maxLength => 255,
		},
		info => {
		    description => "Informational comment.",
		    type => 'string',
		    maxLength => 255,
		    optional => 1,
		},
		$additional_parameters->%*,
	    },
	},
	returns => { type => 'integer' },
	code => sub {
	    my ($param) = @_;

	    my $rdb = PMG::RuleDB->new();

	    my $og = PMG::RuleDB::Group->new(
		$param->{name}, $param->{info} // '', $oclass);

	    for my $prop (qw(and invert)) {
		$og->{$prop} = $param->{$prop} if defined($param->{$prop});
	    }

	    return $rdb->save_group($og);
	}});
}

sub register_delete_object_group_api {
    my ($apiclass, $oclass, $path) = @_;

    $apiclass->register_method({
	name => 'delete_{$oclass}_group',
	path => $path,
	method => 'DELETE',
	description => "Delete a '$oclass' group.",
	proxyto => 'master',
	protected => 1,
	permissions => { check => [ 'admin' ] },
	parameters => {
	    additionalProperties => 0,
	    properties => {
		ogroup => {
		    description => "Object Group ID.",
		    type => 'integer',
		},
	    },
	},
	returns => { type => 'null' },
	code => sub {
	    my ($param) = @_;

	    my $rdb = PMG::RuleDB->new();

	    $rdb->delete_group($param->{ogroup});

	    return undef;
	}});
}

sub register_object_group_config_api {
    my ($apiclass, $oclass, $path) = @_;

    $apiclass->register_method({
	name => 'get_config',
	path => $path,
	method => 'GET',
	description => "Get '$oclass' group properties",
	proxyto => 'master',
	permissions => { check => [ 'admin', 'audit' ] },
	parameters => {
	    additionalProperties => 0,
	    properties => {
		ogroup => {
		    description => "Object Group ID.",
		    type => 'integer',
		},
	    },
	},
	returns => {
	    type => "object",
	    properties => {
		id => { type => 'integer'},
		name => { type => 'string' },
		info => { type => 'string' },
	    },
	},
	code => sub {
	    my ($param) = @_;

	    my $rdb = PMG::RuleDB->new();

	    my $list = $rdb->load_objectgroups($oclass, $param->{ogroup});
	    my $og = shift @$list ||
		die "$oclass group '$param->{ogroup}' not found\n";

	    return {
		id => $og->{id},
		name => $og->{name},
		info => $og->{info},
	    };

	}});

    my $additional_parameters = {};
    if ($oclass =~ /^(?:what|when|who)$/i) {
	$additional_parameters = { $group_attributes->%* };
    }

    $apiclass->register_method({
	name => 'set_config',
	path => $path,
	method => 'PUT',
	description => "Modify '$oclass' group properties",
	proxyto => 'master',
	protected => 1,
	permissions => { check => [ 'admin' ] },
	parameters => {
	    additionalProperties => 0,
	    properties => {
		ogroup => {
		    description => "Object Group ID.",
		    type => 'integer',
		},
		name => {
		    description => "Group name.",
		    type => 'string',
		    maxLength => 255,
		    optional => 1,
		},
		info => {
		    description => "Informational comment.",
		    type => 'string',
		    maxLength => 255,
		    optional => 1,
		},
		$additional_parameters->%*,
	    },
	},
	returns => { type => "null" },
	code => sub {
	    my ($param) = @_;

	    my $rdb = PMG::RuleDB->new();

	    my $ogroup = extract_param($param, 'ogroup');

	    die "no options specified\n"
		if !scalar(keys %$param);

	    my $list = $rdb->load_objectgroups($oclass, $ogroup);
	    my $og = shift @$list ||
		die "$oclass group '$ogroup' not found\n";

	    for my $prop (qw(name info and invert)) {
		$og->{$prop} = $param->{$prop} if defined($param->{$prop});
	    }

	    $rdb->save_group($og);

	    PMG::DBTools::reload_ruledb();

	    return undef;
	}});
}

sub register_objects_api {
    my ($apiclass, $oclass, $path) = @_;

    $apiclass->register_method({
	name => 'objects',
	path => $path,
	method => 'GET',
	description => "List '$oclass' group objects.",
	proxyto => 'master',
	permissions => { check => [ 'admin', 'audit' ] },
	parameters => {
	    additionalProperties => 0,
	    properties => {
		ogroup => {
		    description => "Object Group ID.",
		    type => 'integer',
		},
	    },
	},
	returns => {
	    type => 'array',
	    items => {
		type => "object",
		properties => {
		    id => { type => 'integer'},
		},
	    },
	    links => [ { rel => 'child', href => "{id}" } ],
	},
	code => sub {
	    my ($param) = @_;

	    my $rdb = PMG::RuleDB->new();

	    my $og = $rdb->load_group_objects($param->{ogroup});

	    my $res = [];

	    foreach my $obj (@$og) {
		push @$res, $obj->get_data();
	    }

	    return $res;
	}});

    $apiclass->register_method({
	name => 'delete_object',
	path => 'objects/{id}',
	method => 'DELETE',
	description => "Remove an object from the '$oclass' group.",
	proxyto => 'master',
	protected => 1,
	permissions => { check => [ 'admin' ] },
	parameters => {
	    additionalProperties => 0,
	    properties => {
		ogroup => {
		    description => "Object Group ID.",
		    type => 'integer',
		},
		id => {
		    description => "Object ID.",
		    type => 'integer',
		},
	    },
	},
	returns => { type => 'null' },
	code => sub {
	    my ($param) = @_;

	    my $rdb = PMG::RuleDB->new();

	    my $obj = $rdb->load_object($param->{id});

	    die "object '$param->{id}' does not exists\n" if !defined($obj);

	    $rdb->delete_object($obj);

	    PMG::DBTools::reload_ruledb();

	    return undef;
	}});
}

1;
