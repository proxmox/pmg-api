package PMG::API2::Config;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use HTTP::Status qw(:constants);
use Storable qw(dclone);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use Time::HiRes qw();

use PMG::Config;
use PMG::API2::RuleDB;
use PMG::API2::LDAP;
use PMG::API2::Domains;
use PMG::API2::Transport;
use PMG::API2::Cluster;
use PMG::API2::MyNetworks;
use PMG::API2::SMTPWhitelist;
use PMG::API2::MimeTypes;
use PMG::API2::Fetchmail;
use PMG::API2::DestinationTLSPolicy;
use PMG::API2::InboundTLSDomains;
use PMG::API2::DKIMSign;
use PMG::API2::SACustom;
use PMG::API2::PBS::Remote;
use PMG::API2::ACME;
use PMG::API2::TFAConfig;

use base qw(PVE::RESTHandler);

my $section_type_enum = PMG::Config::Base->lookup_types();

__PACKAGE__->register_method ({
    subclass => "PMG::API2::RuleDB",
    path => 'ruledb',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::SMTPWhitelist",
    path => 'whitelist',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::LDAP",
    path => 'ldap',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Domains",
    path => 'domains',
			      });

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Fetchmail",
    path => 'fetchmail',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Transport",
    path => 'transport',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::MyNetworks",
    # set fragment delimiter (no subdirs) - we need that, because CIDRs
    # contain a slash '/'
    fragmentDelimiter => '',
    path => 'mynetworks',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::Cluster",
    path => 'cluster',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::MimeTypes",
    path => 'mimetypes',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::DestinationTLSPolicy",
    path => 'tlspolicy',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::InboundTLSDomains",
    path => 'tls-inbound-domains',
});

__PACKAGE__->register_method({
    subclass => "PMG::API2::DKIMSign",
    path => 'dkim',
});

__PACKAGE__->register_method({
    subclass => "PMG::API2::SACustom",
    path => 'customscores',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::PBS::Remote",
    path => 'pbs',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::ACME",
    path => 'acme',
});

__PACKAGE__->register_method ({
    subclass => "PMG::API2::TFAConfig",
    path => 'tfa',
});

__PACKAGE__->register_method ({
    name => 'index', 
    path => '',
    method => 'GET',
    description => "Directory index.",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => { section => { type => 'string'} },
	},
	links => [ { rel => 'child', href => "{section}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $res = [ map { { section => $_ } } $section_type_enum->@* ];

	push @$res, { section => 'acme' };
	push @$res, { section => 'cluster' };
	push @$res, { section => 'dkim' };
	push @$res, { section => 'domains' };
	push @$res, { section => 'fetchmail' };
	push @$res, { section => 'ldap' };
	push @$res, { section => 'mimetypes' };
	push @$res, { section => 'mynetworks' };
	push @$res, { section => 'pbs' };
	push @$res, { section => 'regextest' };
	push @$res, { section => 'ruledb' };
	push @$res, { section => 'tfa' };
	push @$res, { section => 'tlspolicy' };
	push @$res, { section => 'tls-inbound-domains' };
	push @$res, { section => 'transport' };
	push @$res, { section => 'users' };
	push @$res, { section => 'whitelist' };

	return $res;
    }});

my $api_read_config_section = sub {
    my ($section) = @_;

    my $cfg = PMG::Config->new();

    my $data = dclone($cfg->{ids}->{$section} // {});
    $data->{digest} = $cfg->{digest};
    delete $data->{type};

    return $data;
};

my $api_update_config_section = sub {
   my ($section, $param) = @_;

   my $code = sub {
       my $cfg = PMG::Config->new();
       my $ids = $cfg->{ids};

       my $digest = extract_param($param, 'digest');
       PVE::SectionConfig::assert_if_modified($cfg, $digest);

       my $delete_str = extract_param($param, 'delete');
       die "no options specified\n"
	   if !$delete_str && !scalar(keys %$param);

       foreach my $opt (PVE::Tools::split_list($delete_str)) {
	   delete $ids->{$section}->{$opt};
       }

       my $plugin = PMG::Config::Base->lookup($section);
       my $config = $plugin->check_config($section, $param, 0, 1);

       foreach my $p (keys %$config) {
	   $ids->{$section}->{$p} = $config->{$p};
       }

       $cfg->write();

       $cfg->rewrite_config(undef, 1);
   };

   PMG::Config::lock_config($code, "update config section '$section' failed");
};

foreach my $section (@$section_type_enum) {

    my $plugin = PMG::Config::Base->lookup($section);

    __PACKAGE__->register_method ({
	name => "read_${section}_section",
	path => $section,
	method => 'GET',
	proxyto => 'master',
	permissions => { check => [ 'admin', 'audit' ] },
	description => "Read $section configuration properties.",
	parameters => {
	    additionalProperties => 0,
	    properties => {},
	},
	returns => { type => 'object' },
	code => sub {
	    my ($param) = @_;

	    return $api_read_config_section->($section);
	}});

    __PACKAGE__->register_method ({
	name => "update_${section}_section",
	path => $section,
	method => 'PUT',
	proxyto => 'master',
	protected => 1,
	permissions => { check => [ 'admin' ] },
	description => "Update $section configuration properties.",
	parameters => $plugin->updateSchema(1),
	returns => { type => 'null' },
	code => sub {
	    my ($param) = @_;

	    $api_update_config_section->($section, $param);

	    return undef;
	}});
}

__PACKAGE__->register_method({
    name => 'regextest',
    path => 'regextest',
    method => 'POST',
    protected => 0,
    permissions => { check => [ 'admin', 'qmanager', 'audit' ] },
    description => "Test Regex ignoring case",
    parameters => {
	additionalProperties => 0,
	properties => {
	    regex => {
		type => 'string',
		description => 'The Regex to test',
		maxLength => 1024,
	    },
	    text => {
		type => 'string',
		description => 'The String to test',
		maxLength => 1024,
	    }
	},
    },
    returns => {
	type => 'number',
    },
    code => sub {
	my ($param) = @_;

	my $text = $param->{text};
	my $regex = $param->{regex};

	my $regex_check = sub {
	    my $start_time = [Time::HiRes::gettimeofday];
	    my $match = 0;
	    if ($text =~ /$regex/i) {
		$match = 1;
	    }
	    my $elapsed = Time::HiRes::tv_interval($start_time) * 1000;
	    die "The Regular Expression '$regex' did not match the text '$text' (elapsed time: $elapsed ms)\n"
		if !$match;
	    return $elapsed;
	};

	my $elapsed = PVE::Tools::run_fork_with_timeout(2, $regex_check);
	if ($elapsed eq '') {
	    die "The Regular Expression timed out\n";
	}

	return $elapsed;
    }});

1;
