package PMG::API2::Fetchmail;

use strict;
use warnings;
use Data::Dumper;
use Clone 'clone';

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;

use PMG::Config;
use PMG::Fetchmail;

use base qw(PVE::RESTHandler);

my $fetchmail_properties = {
    id => {
	description => "Unique ID",
	type => 'string',
	pattern => '[A-Za-z0-9]+',
	maxLength => 16,
    },
    enable => {
	description => "Flag to enable or disable polling.",
	type => 'boolean',
	default => 0,
	optional => 1,
    },
    server => {
	description => "Server address (IP or DNS name).",
	type => 'string', format => 'address',
	optional => 1,
    },
    protocol => {
	description => "Specify  the  protocol to use when communicating with the remote mailserver",
	type => 'string',
	enum => [ 'pop3', 'imap' ],
	optional => 1,
    },
    port => {
	description => "Port number.",
	type => 'integer',
	minimum => 1,
	maximum => 65535,
	optional => 1,
    },
    interval => {
	description => "Only check this site every <interval> poll cycles. A poll cycle is 5 minutes.",
	type => 'integer',
	minimum => 1,
	maximum => 24*12*7,
	optional => 1,
    },
    ssl => {
	description => "Use SSL.",
	type => 'boolean',
	optional => 1,
	default => 0,
    },
    keep => {
	description => "Keep retrieved messages on the remote mailserver.",
	type => 'boolean',
	optional => 1,
	default => 0,
    },
    user => {
	description => "The user identification to be used when logging in to the server",
	type => 'string',
	minLength => 1,
	maxLength => 64,
	optional => 1,
    },
    pass => {
	description => "The password used tfor server login.",
	type => 'string',
	maxLength => 64,
	optional => 1,
    },
    target => get_standard_option('pmg-email-address', {
	description => "The target email address (where to deliver fetched mails).",
	optional => 1,
    }),
};

our $fetchmail_create_properties = clone($fetchmail_properties);
delete $fetchmail_create_properties->{id};
foreach my $k (qw(server protocol user pass target)) {
    delete $fetchmail_create_properties->{$k}->{optional};
}

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "List fetchmail users.",
    permissions => { check => [ 'admin', 'audit' ] },
    proxyto => 'master',
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => $fetchmail_properties,
	},
	links => [ { rel => 'child', href => "{id}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $fmcfg = PVE::INotify::read_file('fetchmailrc');

	my $res = [];

	foreach my $id (sort keys %$fmcfg) {
	    push @$res, $fmcfg->{$id};
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'read',
    path => '{id}',
    method => 'GET',
    description => "Read fetchmail user configuration.",
    proxyto => 'master',
    permissions => { check => [ 'admin', 'audit' ] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    id => $fetchmail_properties->{id},
	},
    },
    returns => {
	type => "object",
	properties => $fetchmail_properties,
    },
    code => sub {
	my ($param) = @_;

	my $fmcfg = PVE::INotify::read_file('fetchmailrc');

	my $data = $fmcfg->{$param->{id}};
	die "Fetchmail entry '$param->{id}' does not exist\n"
	    if !$data;

	return $data;
    }});

__PACKAGE__->register_method ({
    name => 'create',
    path => '',
    method => 'POST',
    description => "Create fetchmail user configuration.",
    protected => 1,
    permissions => { check => [ 'admin' ] },
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => $fetchmail_create_properties,
    },
    returns => $fetchmail_properties->{id},
    code => sub {
	my ($param) = @_;

	my $id;

	my $code = sub {

	    my $fmcfg = PVE::INotify::read_file('fetchmailrc');

	    for (my $i = 0; $i < 9999; $i++) {
		my $tmpid = sprintf("proxmox%04d", $i);
		if (!defined($fmcfg->{$tmpid})) {
		    $id = $tmpid;
		    last;
		}
	    }
	    die "unable to find free Fetchmail entry ID\n"
		if !defined($id);

	    my $entry = { id => $id };
	    foreach my $k (keys %$param) {
		$entry->{$k} = $param->{$k};
	    }

	    $fmcfg->{$id} = $entry;

	    PVE::INotify::write_file('fetchmailrc', $fmcfg);
	};

	PMG::Config::lock_config($code, "update fechtmail configuration failed");

	return $id;
    }});

__PACKAGE__->register_method ({
    name => 'write',
    path => '{id}',
    method => 'PUT',
    description => "Update fetchmail user configuration.",
    protected => 1,
    permissions => { check => [ 'admin' ] },
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => $fetchmail_properties,
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $id = extract_param($param, 'id');

	my $code = sub {

	    my $fmcfg = PVE::INotify::read_file('fetchmailrc');

	    my $data = $fmcfg->{$id};
	    die "Fetchmail entry '$id' does not exist\n"
		if !$data;

	    foreach my $k (keys %$param) {
		$data->{$k} = $param->{$k};
	    }

	    PVE::INotify::write_file('fetchmailrc', $fmcfg);
	};

	PMG::Config::lock_config($code, "update fechtmail configuration failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'delete',
    path => '{id}',
    method => 'DELETE',
    description => "Delete a fetchmail configuration entry.",
    protected => 1,
    permissions => { check => [ 'admin' ] },
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    id => $fetchmail_properties->{id},
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $id = extract_param($param, 'id');

	my $code = sub {

	    my $fmcfg = PVE::INotify::read_file('fetchmailrc');

	    die "Fetchmail entry '$id' does not exist\n"
		if !$fmcfg->{$id};

	    delete $fmcfg->{$id};

	    PVE::INotify::write_file('fetchmailrc', $fmcfg);
	};

	PMG::Config::lock_config($code, "delete fechtmail configuration failed");

	return undef;
    }});

1;
