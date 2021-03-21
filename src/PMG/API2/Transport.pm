package PMG::API2::Transport;

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

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "List transport map entries.",
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
		domain => { type => 'string' },
		host => { type => 'string' },
		protocol => { type => 'string' },
		port => { type => 'integer' },
		use_mx => { type => 'boolean' },
		comment => { type => 'string'},
	    },
	},
	links => [ { rel => 'child', href => "{domain}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $tmap = PVE::INotify::read_file('transport');

	my $res = [];

	foreach my $domain (sort keys %$tmap) {
	    push @$res, $tmap->{$domain};
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'create',
    path => '',
    method => 'POST',
    proxyto => 'master',
    protected => 1,
    permissions => { check => [ 'admin' ] },
    description => "Add transport map entry.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    domain => {
		description => "Domain name.",
		type => 'string', format => 'transport-domain-or-email',
	    },
	    host => {
		description => "Target host (name or IP address).",
		type => 'string', format => 'transport-address',
	    },
	    protocol => {
		description => "Transport protocol.",
		type => 'string',
		enum => [qw(smtp lmtp)],
		default => 'smtp',
		optional => 1,
	    },
	    port => {
		description => "Transport port.",
		type => 'integer',
		minimum => 1,
		maximum => 65535,
		optional => 1,
		default => 25,
	    },
	    use_mx => {
		description => "Enable MX lookups (SMTP).",
		type => 'boolean',
		optional => 1,
		default => 1,
	    },
	    comment => {
		description => "Comment.",
		type => 'string',
		optional => 1,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $tmap = PVE::INotify::read_file('transport');

	    die "Transport map entry '$param->{domain}' already exists\n"
		if $tmap->{$param->{domain}};

	    $tmap->{$param->{domain}} = {
		domain => $param->{domain},
		host => $param->{host},
		protocol => $param->{protocol} // 'smtp',
		port => $param->{port} // 25,
		use_mx => $param->{use_mx} // 1,
		comment => $param->{comment} // '',
	    };

	    PVE::INotify::write_file('transport', $tmap);

	    PMG::Config::postmap_pmg_transport();
	};

	PMG::Config::lock_config($code, "add transport map entry failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'read',
    path => '{domain}',
    method => 'GET',
    description => "Read transport map entry.",
    proxyto => 'master',
    permissions => { check => [ 'admin', 'audit' ] },
    parameters => {
	additionalProperties => 0,
	properties => {
	    domain => {
		description => "Domain name.",
		type => 'string', format => 'transport-domain-or-email',
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
	    domain => { type => 'string'},
	    host => { type => 'string'},
	    protocol => { type => 'string'},
	    port => { type => 'integer'},
	    use_mx => { type => 'boolean'},
	    comment => { type => 'string'},
	},
    },
    code => sub {
	my ($param) = @_;

	my $tmap = PVE::INotify::read_file('transport');

	if (my $entry = $tmap->{$param->{domain}}) {
	    return $entry;
	}

	die "Transport map entry '$param->{domain}' does not exist\n";
    }});

__PACKAGE__->register_method ({
    name => 'write',
    path => '{domain}',
    method => 'PUT',
    description => "Update transport map entry.",
    protected => 1,
    permissions => { check => [ 'admin' ] },
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    domain => {
		description => "Domain name.",
		type => 'string', format => 'transport-domain-or-email',
	    },
	    host => {
		description => "Target host (name or IP address).",
		type => 'string', format => 'transport-address',
		optional => 1,
	    },
	    protocol => {
		description => "Transport protocol.",
		type => 'string',
	    enum => [qw(smtp lmtp)],
		default => 'smtp',
		optional => 1,
	    },
	    port => {
		description => "Transport port.",
		type => 'integer',
		minimum => 1,
		maximum => 65535,
		optional => 1,
	    },
	    use_mx => {
		description => "Enable MX lookups (SMTP).",
		type => 'boolean',
		optional => 1,
	    },
	    comment => {
		description => "Comment.",
		type => 'string',
		optional => 1,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $tmap = PVE::INotify::read_file('transport');

	    my $domain = extract_param($param, 'domain');

	    my $data = $tmap->{$domain};

	    die "Transport map entry '$param->{domain}' does not exist\n" if !$data;

	    die "no options specified\n" if !scalar(keys %$param);

	    for my $prop (qw(host protocol port use_mx comment)) {
		$data->{$prop} = $param->{$prop} if defined($param->{$prop});
	    }

	    PVE::INotify::write_file('transport', $tmap);

	    PMG::Config::postmap_pmg_transport();
	};

	PMG::Config::lock_config($code, "update transport map entry failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'delete',
    path => '{domain}',
    method => 'DELETE',
    description => "Delete a transport map entry",
    protected => 1,
    permissions => { check => [ 'admin' ] },
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    domain => {
		description => "Domain name.",
		type => 'string', format => 'transport-domain-or-email',
	    },
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {

	    my $tmap = PVE::INotify::read_file('transport');

	    die "Transport map entry '$param->{domain}' does not exist\n"
		if !$tmap->{$param->{domain}};

	    delete $tmap->{$param->{domain}};

	    PVE::INotify::write_file('transport', $tmap);

	    PMG::Config::postmap_pmg_transport();
	};

	PMG::Config::lock_config($code, "delete transport map entry failed");

	return undef;
    }});

1;
