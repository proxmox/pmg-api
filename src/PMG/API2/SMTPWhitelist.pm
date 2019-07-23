package PMG::API2::SMTPWhitelist;

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

use PMG::RuleDB::WhoRegex;
use PMG::RuleDB::ReceiverRegex;
use PMG::RuleDB::EMail;
use PMG::RuleDB::Receiver;
use PMG::RuleDB::IPAddress;
use PMG::RuleDB::IPNet;
use PMG::RuleDB::Domain;
use PMG::RuleDB::ReceiverDomain;
use PMG::RuleDB;

use base qw(PVE::RESTHandler);

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
	    { subdir => 'email' },
	    { subdir => 'receiver' },
	    { subdir => 'domain' },
	    { subdir => 'receiver_domain' },
	    { subdir => 'regex' },
	    { subdir => 'receiver_regex' },
	    { subdir => 'ip' },
	    { subdir => 'network' },
	];

    }});

__PACKAGE__->register_method ({
    name => 'objects',
    path => 'objects',
    method => 'GET',
    description => "Get list of all SMTP whitelist entries.",
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
		id => { type => 'integer'},
	    },
	},
	links => [ { rel => 'child', href => "{id}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $rdb = PMG::RuleDB->new();

	my $gid = $rdb->greylistexclusion_groupid();

	my $og = $rdb->load_group_objects($gid);

	my $res = [];

	foreach my $obj (@$og) {
	    push @$res, $obj->get_data();
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'delete_object',
    path => 'objects/{id}',
    method => 'DELETE',
    description => "Remove an object from the SMTP whitelist.",
    proxyto => 'master',
    permissions => { check => [ 'admin' ] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
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

	PMG::DBTools::reload_ruledb($rdb);

	return undef;
    }});


PMG::RuleDB::EMail->register_api(__PACKAGE__, 'email', undef, 1);
PMG::RuleDB::Receiver->register_api(__PACKAGE__, 'receiver', undef, 1);

PMG::RuleDB::Domain->register_api(__PACKAGE__, 'domain', undef, 1);
PMG::RuleDB::ReceiverDomain->register_api(__PACKAGE__, 'receiver_domain', undef, 1);

PMG::RuleDB::WhoRegex->register_api(__PACKAGE__, 'regex', undef, 1);
PMG::RuleDB::ReceiverRegex->register_api(__PACKAGE__, 'receiver_regex', undef, 1);

PMG::RuleDB::IPAddress->register_api(__PACKAGE__, 'ip', undef, 1);
PMG::RuleDB::IPNet->register_api(__PACKAGE__, 'network', undef, 1);

1;
