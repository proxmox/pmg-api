package PMG::API2::RuleDB;

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
use PMG::RuleCache;

use PMG::API2::ObjectGroupHelpers;
use PMG::API2::Who;
use PMG::API2::When;
use PMG::API2::What;
use PMG::API2::Action;
use PMG::API2::Rules;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
    parameters => {
    	additionalProperties => 0,
	properties => {},
    },
    permissions => { check => [ 'admin', 'audit' ] },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{name}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $result = [
	    { name => 'digest' },
	    { name => 'action' },
	    { name => 'rules' },
	    { name => 'what' },
	    { name => 'when' },
	    { name => 'who' },
	];

	return $result;
    }});

__PACKAGE__->register_method ({
    name => 'reset_ruledb',
    path => '',
    method => 'POST',
    description => "Reset PMG rule database back to factory defaults.",
    permissions => { check => [ 'admin' ] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {}
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	my $dbh = PMG::DBTools::open_ruledb("Proxmox_ruledb");
	my $ruledb = PMG::RuleDB->new($dbh);
	PMG::DBTools::init_ruledb($ruledb, 1);

	return undef;
   }});

__PACKAGE__->register_method({
    name => 'ruledb_digest',
    path => 'digest',
    method => 'GET',
    description => "Returns the rule database digest. This is used internally for cluster synchronization.",
    # always run on local node, root@pam only
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    permissions => { check => [ 'admin', 'audit' ] },
    returns => { type => 'string' },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();
	my $rulecache = PMG::RuleCache->new($rdb);

	return $rulecache->{digest};
    }});

__PACKAGE__->register_method({
    name => 'list_rules',
    path => 'rules',
    method => 'GET',
    description => "Get list of rules.",
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
	links => [ { rel => 'child', href => "{id}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();

	my $rules = $rdb->load_rules();

	my $res = [];

	my $cond_create_group = sub {
	    my ($res, $name, $groupdata) = @_;

	    return if !$groupdata;

	    $res->{$name} = PMG::API2::ObjectGroupHelpers::format_object_group($groupdata);
	};

	foreach my $rule (@$rules) {
	    my ($from, $to, $when, $what, $action) =
		$rdb->load_groups($rule);

	    my $data = PMG::API2::ObjectGroupHelpers::format_rule(
		$rule, $from, $to, $when, $what, $action);

	    push @$res, $data;
	}

	$rdb->close();

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'create_rule',
    path => 'rules',
    method => 'POST',
    description => "Create new rule.",
    proxyto => 'master',
    protected => 1,
    permissions => { check => [ 'admin' ] },
    parameters => {
	additionalProperties => 0,
	properties => PMG::API2::Rules::get_rule_params({
	    name => {
		description => "Rule name",
		type => 'string',
	    },
	    priority => {
		description => "Rule priority.",
		type => 'integer',
		minimum => 0,
		maximum => 100,
	    },
	}),
    },
    returns => { type => 'integer' },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();

	my $rule = PMG::RuleDB::Rule->new ($param->{name}, $param->{priority});

	for my $key (keys PMG::API2::Rules::get_rule_params()->%*) {
	    $rule->{$key} = $param->{$key} if defined($param->{$key});
	}

	return $rdb->save_rule($rule);
    }});

__PACKAGE__->register_method ({
    subclass => 'PMG::API2::Rules',
    path => 'rules/{id}',
});


__PACKAGE__->register_method ({
    subclass => 'PMG::API2::Action',
    path => 'action',
});

PMG::API2::ObjectGroupHelpers::register_group_list_api(__PACKAGE__, 'what');
PMG::API2::ObjectGroupHelpers::register_group_list_api(__PACKAGE__, 'when');
PMG::API2::ObjectGroupHelpers::register_group_list_api(__PACKAGE__, 'who');

__PACKAGE__->register_method ({
    subclass => 'PMG::API2::Who',
    path => 'who/{ogroup}',
});

__PACKAGE__->register_method ({
    subclass => 'PMG::API2::When',
    path => 'when/{ogroup}',
});

__PACKAGE__->register_method ({
    subclass => 'PMG::API2::What',
    path => 'what/{ogroup}',
});


1;
