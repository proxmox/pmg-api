package PMG::API2::Postfix;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;

use PMG::Postfix;

use base qw(PVE::RESTHandler);

my $postfix_queues = ['deferred', 'active', 'incoming', 'hold'];

my $queue_name_option = {
    description => "Postfix queue name.",
    type => 'string',
    enum => $postfix_queues,
};

my $queue_id_option = {
    description => "The Message queue ID.",
    type => 'string',
    pattern => '[a-zA-Z0-9]+',
    minLength => 8,
    maxLength => 20,
};

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    permissions => { user => 'all' },
    description => "Directory index.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
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
	    { name => 'queue' },
	    { name => 'qshape' },
	    { name => 'flush_queues' },
	    { name => 'discard_verify_cache' },
	];

	return $result;
    }});

__PACKAGE__->register_method ({
    name => 'qshape',
    path => 'qshape',
    method => 'GET',
    permissions => { check => [ 'admin', 'audit' ] },
    protected => 1,
    proxyto => 'node',
    description => "Print Postfix queue domain and age distribution.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    queue => {
		description => $queue_name_option->{description},
		type => 'string',
		enum => $postfix_queues,
		default => 'deferred',
		optional => 1,
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
    },
    code => sub {
	my ($param) = @_;

	my $queue = $param->{queue} || 'deferred';

	my $res = PMG::Postfix::qshape($queue);

	return $res;
    }});


__PACKAGE__->register_method ({
    name => 'queue_index',
    path => 'queue',
    method => 'GET',
    permissions => { user => 'all' },
    description => "Directory index.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
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

	my $res = [];
	foreach my $queue (@$postfix_queues) {
	    push @$res, { name => $queue };
	}
	return $res;
   }});

__PACKAGE__->register_method ({
    name => 'mailq',
    path => 'queue/{queue}',
    method => 'GET',
    permissions => { check => [ 'admin', 'audit' ] },
    protected => 1,
    proxyto => 'node',
    description => "List the mail queue for a specific domain.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    queue => $queue_name_option,
	    start => {
		type => 'integer',
		minimum => 0,
		optional => 1,
	    },
	    limit => {
		type => 'integer',
		minimum => 0,
		optional => 1,
	    },
	    filter => {
		description => "Filter string.",
		type => 'string',
		maxLength => 64,
		optional => 1,
	    },
	    sortfield => {
		description => "Sort field.",
		type => 'string',
		optional => 1,
		enum => ['arrival_time', 'message_size', 'sender', 'receiver', 'reason'],
	    },
	    sortdir => {
		description => "Sort direction.",
		type => 'string',
		optional => 1,
		enum => ['ASC', 'DESC'],
		requires => 'sortfield',
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{queue_id}" } ],
     },
    code => sub {
	my ($param) = @_;

	my $restenv = PMG::RESTEnvironment->get();

	my ($count, $res) = PMG::Postfix::mailq(
	    $param->{queue}, $param->{filter}, $param->{start}, $param->{limit});

	$restenv->set_result_attrib('total', $count);

	my $sortfield = $param->{sortfield};
	if (defined($sortfield)) {
	    my $sort_func = sub {
		my ($c, $d) = ($param->{sortdir} eq 'DESC') ? ($b, $a) : ($a, $b);
		if ($sortfield eq 'message_size' || $sortfield eq 'arrival_time') {
		    return $c->{$sortfield} <=> $d->{$sortfield};
		} else {
		    return $c->{$sortfield} cmp $d->{$sortfield};
		}
	    };

	    $res = [ sort $sort_func @$res ] ;
	}


	return $res;
    }});


__PACKAGE__->register_method ({
    name => 'read_queued_mail',
    path => 'queue/{queue}/{queue_id}',
    method => 'GET',
    permissions => { check => [ 'admin' ] },
    protected => 1,
    proxyto => 'node',
    description => "Get the contents of a queued mail.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    queue => $queue_name_option,
	    queue_id => $queue_id_option,
	    header => {
		description => "Show message header content.",
		type => 'boolean',
		default => 1,
		optional => 1,
	    },
	    body => {
		description => "Include body content.",
		type => 'boolean',
		default => 0,
		optional => 1,
	    },
	    'decode-header' => {
		description => "Decodes the header fields.",
		type => 'boolean',
		default => 0,
		optional => 1,
	    },
	},
    },
    returns => { type => 'string' },
    code => sub {
	my ($param) = @_;

	$param->{header} //= 1;

	return PMG::Postfix::postcat($param->@{qw(queue_id header body decode-header)});
    }});

__PACKAGE__->register_method ({
    name => 'flush_queued_mail',
    path => 'queue/{queue}/{queue_id}',
    method => 'POST',
    permissions => { check => [ 'admin' ] },
    protected => 1,
    proxyto => 'node',
    description => "Schedule immediate delivery of deferred mail with the specified queue ID.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    queue => $queue_name_option,
	    queue_id => $queue_id_option,
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PMG::Postfix::flush_queued_mail($param->{queue_id});

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'delete_queued_mail',
    path => 'queue/{queue}/{queue_id}',
    method => 'DELETE',
    permissions => { check => [ 'admin' ] },
    protected => 1,
    proxyto => 'node',
    description => "Delete one message with the named queue ID.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    queue => $queue_name_option,
	    queue_id => $queue_id_option,
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PMG::Postfix::delete_queued_mail($param->{queue}, $param->{queue_id});

	return undef;
    }});


__PACKAGE__->register_method ({
    name => 'delete_all_queues',
    path => 'queue',
    method => 'DELETE',
    description => "Delete all mails in all posfix queues.",
    proxyto => 'node',
    permissions => { check => [ 'admin' ] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PMG::Postfix::delete_queue();

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'delete_queue',
    path => 'queue/{queue}',
    method => 'DELETE',
    description => "Delete all mails in the queue.",
    proxyto => 'node',
    permissions => { check => [ 'admin' ] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    queue => $queue_name_option,
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PMG::Postfix::delete_queue($param->{queue});

	return undef;
    }});


__PACKAGE__->register_method ({
    name => 'flush_queues',
    path => 'flush_queues',
    method => 'POST',
    description => "Flush the queue: attempt to deliver all queued mail.",
    proxyto => 'node',
    permissions => { check => [ 'admin' ] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PMG::Postfix::flush_queues();

	return undef;
    }});


__PACKAGE__->register_method ({
    name => 'discard_verify_cache',
    path => 'discard_verify_cache',
    method => 'POST',
    description => "Discards the address verification cache.",
    proxyto => 'node',
    permissions => { check => [ 'admin' ] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PMG::Postfix::discard_verify_cache();

	return undef;
    }});

1;
