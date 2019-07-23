package PMG::API2::Who;

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
use PMG::RuleDB::EMail;
use PMG::RuleDB::IPAddress;
use PMG::RuleDB::IPNet;
use PMG::RuleDB::Domain;
use PMG::RuleDB::LDAP;
use PMG::RuleDB::LDAPUser;
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
		subdir => { type => 'string'},
	    },
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($param) = @_;

	return [
	    { subdir => 'config' },
	    { subdir => 'objects' },
	    { subdir => 'email' },
	    { subdir => 'domain' },
	    { subdir => 'regex' },
	    { subdir => 'ip' },
	    { subdir => 'network' },
	    { subdir => 'ldap' },
	];

    }});

PMG::API2::ObjectGroupHelpers::register_delete_object_group_api(__PACKAGE__, 'who', '');
PMG::API2::ObjectGroupHelpers::register_object_group_config_api(__PACKAGE__, 'who', 'config');
PMG::API2::ObjectGroupHelpers::register_objects_api(__PACKAGE__, 'who', 'objects');

PMG::RuleDB::EMail->register_api(__PACKAGE__, 'email');
PMG::RuleDB::Domain->register_api(__PACKAGE__, 'domain');
PMG::RuleDB::WhoRegex->register_api(__PACKAGE__, 'regex');
PMG::RuleDB::IPAddress->register_api(__PACKAGE__, 'ip');
PMG::RuleDB::IPNet->register_api(__PACKAGE__, 'network');
PMG::RuleDB::LDAP->register_api(__PACKAGE__, 'ldap');
PMG::RuleDB::LDAPUser->register_api(__PACKAGE__, 'ldapuser');

1;
