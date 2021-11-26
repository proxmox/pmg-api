package PMG::HTTPServer;

use strict;
use warnings;

use PVE::SafeSyslog;
use PVE::INotify;
use PVE::Tools;
use PVE::APIServer::AnyEvent;
use PVE::Exception qw(raise_param_exc);
use PMG::RESTEnvironment;

use PMG::Ticket;
use PMG::Cluster;
use PMG::API2;

use Data::Dumper;

use base('PVE::APIServer::AnyEvent');

use HTTP::Status qw(:constants);


sub new {
    my ($this, %args) = @_;

    my $class = ref($this) || $this;

    my $self = $class->SUPER::new(%args);

    $self->{rpcenv} = PMG::RESTEnvironment->init(
	$self->{trusted_env} ? 'priv' : 'pub', atfork =>  sub { $self->atfork_handler() });

    return $self;
}


sub generate_csrf_prevention_token {
    my ($username) = @_;

    return PMG::Ticket::assemble_csrf_prevention_token ($username);
}

sub auth_handler {
    my ($self, $method, $rel_uri, $ticket, $token, $api_token, $peer_host) = @_;

    my $rpcenv = $self->{rpcenv};

    # set environment variables
    $rpcenv->set_user(undef);
    $rpcenv->set_role(undef);
    $rpcenv->set_language('C');
    $rpcenv->set_client_ip($peer_host);

    $rpcenv->init_request();

    my $require_auth = 1;

    # explicitly allow some calls without auth
    if (($rel_uri eq '/access/domains' && $method eq 'GET') ||
	($rel_uri eq '/quarantine/sendlink' && ($method eq 'GET' || $method eq 'POST')) ||
	($rel_uri eq '/access/ticket' && ($method eq 'GET' || $method eq 'POST'))) {
	$require_auth = 0;
    }

    my ($username, $age);

    if ($require_auth) {

	die "API tokens not implemented\n" if $api_token;

	die "No ticket\n" if !$ticket;

	if ($ticket =~ m/^PMGQUAR:/) {
	    ($username, $age) = PMG::Ticket::verify_quarantine_ticket($ticket);
	    $rpcenv->set_user($username);
	    $rpcenv->set_role('quser');
	} else {
	    ($username, $age, my $tfa) = PMG::Ticket::verify_ticket($ticket, undef, 0);
	    # TFA tickets don't return a username, and return a tfa challenge, either is enough to
	    # fail here:
	    die "No ticket\n" if !$username || $tfa;
	    my $role = PMG::AccessControl::check_user_enabled($self->{usercfg}, $username);
	    $rpcenv->set_user($username);
	    $rpcenv->set_role($role);
	}

	$rpcenv->set_ticket($ticket);

	my $euid = $>;
	PMG::Ticket::verify_csrf_prevention_token($username, $token)
	    if ($euid != 0) && ($method ne 'GET');
    }

    return {
	ticket => $ticket,
	token => $token,
	userid => $username,
	age => $age,
	isUpload => 0,
    };
}

sub rest_handler {
    my ($self, $clientip, $method, $rel_uri, $auth, $params, $format) = @_;

    my $rpcenv = $self->{rpcenv};
    $rpcenv->set_format($format);

    my $resp = {
	status => HTTP_NOT_IMPLEMENTED,
	message => "Method '$method $rel_uri' not implemented",
    };

    my ($handler, $info);

    eval {
	my $uri_param = {};
	($handler, $info) = PMG::API2->find_handler($method, $rel_uri, $uri_param);
	return if !$handler || !$info;

	foreach my $p (keys %{$params}) {
	    if (defined($uri_param->{$p})) {
		raise_param_exc({$p =>  "duplicate parameter (already defined in URI)"});
	    }
	    $uri_param->{$p} = $params->{$p};
	}

	# check access permissions
	$rpcenv->check_api2_permissions($info->{permissions}, $uri_param);

	if (my $pn = $info->{proxyto}) {

	    my $node;
	    if ($pn eq 'master') {
		$node = PMG::Cluster::get_master_node();
	    } else {
		$node = $uri_param->{$pn};
		raise_param_exc({$pn =>  "proxy parameter '$pn' does not exists"}) if !$node;
	    }

	    if ($node ne 'localhost' && $node ne PVE::INotify::nodename()) {
		die "unable to proxy file uploads" if $auth->{isUpload};
		my $remip = $self->remote_node_ip($node);
		$resp = { proxy => $remip, proxynode => $node, proxy_params => $params };
		return;
	    }
	}

	my $euid = $>;
	if ($info->{protected} && ($euid != 0)) {
	    $resp = { proxy => 'localhost' , proxy_params => $params };
	    return;
	}

	if (my $pn = $info->{proxyto}) {
	    if ($pn eq 'master') {
		$rpcenv->check_node_is_master();
	    }
	}


	my $result = $handler->handle($info, $uri_param);

	$resp = {
	    info => $info, # useful to format output
	    status => HTTP_OK,
	};

	if ($info->{download}) {
	    my $type =  $info->{returns}->{type};
	    if ($type eq 'string' || $type eq 'object') {
		$resp->{download} = $result;
	    } else {
		die "API calls which trigger downloads need to have return type 'string' or 'object' - internal error"
	    }

	} else {
	    $resp->{data} = $result;
	}

	if (my $count = $rpcenv->get_result_attrib('total')) {
	    $resp->{total} = $count;
	}

	if (my $diff = $rpcenv->get_result_attrib('changes')) {
	    $resp->{changes} = $diff;
	}
    };
    my $err = $@;

    $rpcenv->set_user(undef); # clear after request
    $rpcenv->set_role(undef); # clear after request
    $rpcenv->set_format(undef); # clear after request

    if ($err) {
	$resp = { info => $info };
	if (ref($err) eq "PVE::Exception") {
	    $resp->{status} = $err->{code} || HTTP_INTERNAL_SERVER_ERROR;
	    $resp->{errors} = $err->{errors} if $err->{errors};
	    $resp->{message} = $err->{msg};
	} else {
	    $resp->{status} =  HTTP_INTERNAL_SERVER_ERROR;
	    $resp->{message} = $err;
	}
    }

    return $resp;
}

sub check_cert_fingerprint {
    my ($self, $cert) = @_;

    return PMG::Cluster::check_cert_fingerprint($cert);
}

sub initialize_cert_cache {
    my ($self, $node) = @_;

    PMG::Cluster::initialize_cert_cache($node);
}

sub remote_node_ip {
    my ($self, $node) = @_;

    my $remip = PMG::Cluster::remote_node_ip($node);

    die "unable to get remote IP address for node '$node'\n" if !$remip;

    return $remip;
}

1;
