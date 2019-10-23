package PMG::API2::Action;

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

use PMG::RuleDB::BCC;
use PMG::RuleDB;

use base qw(PVE::RESTHandler);

my $id_property = {
    description => "Action Object ID.",
    type => 'string',
    pattern => '\d+_\d+',
};

my $format_action_object = sub {
    my ($og, $action) = @_;

    my $data = $action->get_data();
    $data->{id} = "$data->{ogroup}_$data->{id}";
    $data->{name} = $og->{name};
    $data->{info} = $og->{info};
    $data->{editable} = $action->oisedit();

    return $data;
};

my $load_action_with_og = sub {
    my ($rdb, $id, $exp_otype) = @_;

    die "internal error" if $id !~ m/^(\d+)_(\d+)$/;
    my ($ogroup, $objid) = ($1, $2);

    my $list = $rdb->load_objectgroups('action', $ogroup);
    my $og = shift @$list ||
	die "action group '$ogroup' not found\n";

    my $action = $rdb->load_object_full($objid, $ogroup, $exp_otype);

    return ($og, $action);
};

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
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
		subdir => { type => 'string'},
	    },
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($param) = @_;

	return [
	    { subdir => 'objects' },
	    { subdir => 'bcc' },
	    { subdir => 'field' },
	    { subdir => 'notification' },
	    { subdir => 'disclaimer' },
	    { subdir => 'removeattachments' },
	];

    }});

__PACKAGE__->register_method ({
    name => 'list_actions',
    path => 'objects',
    method => 'GET',
    description => "List 'actions' objects.",
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
		id => $id_property,
	    },
	},
	links => [ { rel => 'child', href => "{id}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();

	my $ogroups = $rdb->load_objectgroups('action');
	my $res = [];
	foreach my $og (@$ogroups) {
	    my $action = $og->{action};
	    next if !$action;
	    push @$res, $format_action_object->($og, $action);
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'delete_action',
    path => 'objects/{id}',
    method => 'DELETE',
    description => "Delete 'actions' object.",
    proxyto => 'master',
    protected => 1,
    permissions => { check => [ 'admin' ] },
    parameters => {
	additionalProperties => 0,
	properties => { id => $id_property }
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();
	# test if object exists
	my ($og, $action) = $load_action_with_og->($rdb, $param->{id});

	die "unable to delete standard actions\n" if !$action->oisedit();

	$rdb->delete_group($og->{id});

	return undef;
    }});

my $register_action_api = sub {
    my ($class, $name) = @_;

    my $otype = $class->otype();
    my $otype_text = $class->otype_text();
    my $properties = $class->properties();

    my $create_properties = {
	name => {
	    description => "Action name.",
	    type => 'string',
	    maxLength => 255,
	},
	info => {
	    description => "Informational comment.",
	    type => 'string',
	    maxLength => 255,
	    optional => 1,
	},
    };
    my $update_properties = {
	id => $id_property,
	name => {
	    description => "Action name.",
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
    };
    my $read_properties = { id => $id_property };

    foreach my $key (keys %$properties) {
	$create_properties->{$key} = $properties->{$key};
	$update_properties->{$key} = $properties->{$key};
    }

    __PACKAGE__->register_method ({
	name => $name,
	path => $name,
	method => 'POST',
	description => "Create '$otype_text' object.",
	proxyto => 'master',
	protected => 1,
	permissions => { check => [ 'admin' ] },
	parameters => {
	    additionalProperties => 0,
	    properties => $create_properties,
	},
	returns => {
	    description => "The object ID.",
	    type => 'string',
	},
	code => sub {
	    my ($param) = @_;

	    my $rdb = PMG::RuleDB->new();

	    my $obj = $rdb->get_object($otype);
	    $obj->update($param);

	    my $og = $rdb->create_group_with_obj($obj, $param->{name}, $param->{info});

	    return "$og->{id}_$obj->{id}";
	}});

    __PACKAGE__->register_method ({
	name => "read_$name",
	path => "$name/{id}",
	method => 'GET',
	description => "Read '$otype_text' object settings.",
	proxyto => 'master',
	permissions => { check => [ 'admin', 'audit' ] },
	parameters => {
	    additionalProperties => 0,
	    properties => $read_properties,
	},
	returns => {
	    type => "object",
	    properties => {
		id => { type => 'string'},
	    },
	},
	code => sub {
	    my ($param) = @_;

	    my $rdb = PMG::RuleDB->new();

	    my ($og, $action) = $load_action_with_og->($rdb, $param->{id}, $otype);

	    return $format_action_object->($og, $action);
	}});

    __PACKAGE__->register_method ({
	name => "update_$name",
	path => "$name/{id}",
	method => 'PUT',
	description => "Update '$otype_text' object.",
	proxyto => 'master',
	protected => 1,
	permissions => { check => [ 'admin' ] },
	parameters => {
	    additionalProperties => 0,
	    properties => $update_properties,
	},
	returns => { type => 'null' },
	code => sub {
	    my ($param) = @_;

	    my $rdb = PMG::RuleDB->new();

	    my ($og, $action) = $load_action_with_og->($rdb, $param->{id}, $otype);

	    my $name = extract_param($param, 'name');
	    my $info = extract_param($param, 'info');

	    if (defined($name) || defined($info)) {
		$og->{name} = $name if defined($name);
		$og->{info} = $info if defined($info);
		$rdb->save_group($og);

		return undef if !scalar(keys %$param); # we are done
	    }

	    die "no options specified\n"
		if !scalar(keys %$param);

	    $action->update($param);

	    $action->save($rdb);

	    PMG::DBTools::reload_ruledb();

	    return undef;
	}});

};

$register_action_api->('PMG::RuleDB::BCC', 'bcc');
$register_action_api->('PMG::RuleDB::ModField', 'field');
$register_action_api->('PMG::RuleDB::Notify', 'notification');
$register_action_api->('PMG::RuleDB::Disclaimer', 'disclaimer');
$register_action_api->('PMG::RuleDB::Remove', 'removeattachments');

1;
