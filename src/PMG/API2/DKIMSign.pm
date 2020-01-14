package PMG::API2::DKIMSign;

use strict;
use warnings;

use PVE::Tools qw(extract_param dir_glob_foreach);
use PVE::JSONSchema qw(get_standard_option);
use PVE::Exception qw(raise_param_exc);
use PVE::RESTHandler;

use PMG::Config;
use PMG::DKIMSign;

use PMG::API2::DKIMSignDomains;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method({
    subclass => "PMG::API2::DKIMSignDomains",
    path => 'domains',
});

__PACKAGE__->register_method({
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

	return [
	    { section => 'domains'},
	    { section => 'selector'},
	    { section => 'selectors'}
	];
    }});

__PACKAGE__->register_method({
    name => 'set_selector',
    path => 'selector',
    method => 'POST',
    description => "Generate a new private key for selector. All future mail will be signed with the new key!",
    protected => 1,
    permissions => { check => [ 'admin' ] },
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => {
	    selector => {
		description => "DKIM Selector",
		type => 'string', format => 'dns-name',
	    },
	    keysize => {
		description => "Number of bits for the RSA-Key",
		type => 'integer', minimum => 1024
	    },
	    force => {
		description => "Overwrite existing key",
		type => 'boolean', optional => 1
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;
	my $selector = extract_param($param, 'selector');
	my $keysize = extract_param($param, 'keysize');
	my $force = extract_param($param, 'force');

	PMG::DKIMSign::set_selector($selector, $keysize, $force);

	return undef;
    }});

sub pmg_verify_dkim_pubkey_record {
    my ($rec, $noerr) = @_;

    if ($rec !~ /\._domainkey\tIN\tTXT\t\( "v=DKIM1; h=sha256; k=rsa; ".+ \)  ; ----- DKIM key/ms ) {
	return undef if $noerr;
	die "value does not look like a valid DKIM TXT record\n";
    }

    return $rec
}

PVE::JSONSchema::register_format(
    'pmg-dkim-record', \&pmg_verify_dkim_pubkey_record);

__PACKAGE__->register_method({
    name => 'get_selector_info',
    path => 'selector',
    method => 'GET',
    description => "Get the public key for the configured selector, prepared as DKIM TXT record",
    protected => 1,
    permissions => { check => [ 'admin' ] },
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => { },
    },
    returns => {
	type => 'object',
	properties => {
	    selector => { type => 'string', format => 'dns-name', optional => 1 },
	    keysize => { type => 'integer', minimum => 1024 , optional => 1},
	    record => { type => 'string', format => 'pmg-dkim-record', optional => 1},
	},
    },
    code => sub {
	my $cfg = PMG::Config->new();
	my $selector = $cfg->get('admin', 'dkim_selector');

	return {} if !defined($selector);

	my ($record, $size);
	eval { ($record, $size) = PMG::DKIMSign::get_selector_info($selector); };
	return {selector => $selector} if $@;

	return { selector => $selector, keysize => $size, record => $record };
    }});

__PACKAGE__->register_method({
    name => 'get_selector_list',
    path => 'selectors',
    method => 'GET',
    description => "Get a list of all existing selectors",
    protected => 1,
    permissions => { check => [ 'admin' ] },
    proxyto => 'master',
    parameters => {
	additionalProperties => 0,
	properties => { },
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => { selector => { type => 'string', format => 'dns-name' } },
	},
	links => [ { rel => 'child', href => "{selector}" } ],
    },
    code => sub {
	my $res = [];

	my @selectors = dir_glob_foreach('/etc/pmg/dkim/', '.*\.private', sub {
	    my ($sel) = @_;
	    $sel =~ s/\.private$//;
	    push @$res, { selector => $sel };
	});

	return $res;
    }});

1;
