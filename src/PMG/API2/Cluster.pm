package PMG::API2::Cluster;

use strict;
use warnings;
use Data::Dumper;

use PVE::SafeSyslog;
use PVE::Tools qw(extract_param);
use HTTP::Status qw(:constants);
use Storable qw(dclone);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;
use PVE::APIClient::LWP;

use PMG::RESTEnvironment;
use PMG::ClusterConfig;
use PMG::Cluster;
use PMG::DBTools;
use PMG::MailQueue;

use PMG::API2::Nodes;

use base qw(PVE::RESTHandler);

sub cluster_join {
    my ($cinfo, $conn_setup) = @_;

    my $conn = PVE::APIClient::LWP->new(%$conn_setup);

    my $info = PMG::Cluster::read_local_cluster_info();

    my $res = $conn->post("/config/cluster/nodes", $info);

    foreach my $node (@$res) {
	$cinfo->{ids}->{$node->{cid}} = $node;
    }

    eval {
	print STDERR "stop all services accessing the database\n";
	# stop all services accessing the database
	PMG::Utils::service_wait_stopped(40, $PMG::Utils::db_service_list);

	print STDERR "save new cluster configuration\n";
	$cinfo->write();

	PMG::Cluster::update_ssh_keys($cinfo);

	print STDERR "cluster node successfully joined\n";

	$cinfo = PMG::ClusterConfig->new(); # reload

	my $role = $cinfo->{'local'}->{type} // '-';
	die "local node '$cinfo->{local}->{name}' not part of cluster\n"
	    if $role eq '-';

	die "got unexpected role '$role' for local node '$cinfo->{local}->{name}'\n"
	    if $role ne 'node';

	my $cid = $cinfo->{'local'}->{cid};

	PMG::MailQueue::create_spooldirs($cid);

	PMG::Cluster::sync_config_from_master($cinfo->{master}->{name}, $cinfo->{master}->{ip});

	PMG::DBTools::init_nodedb($cinfo);

	my $cfg = PMG::Config->new();
	my $ruledb = PMG::RuleDB->new();
	my $rulecache = PMG::RuleCache->new($ruledb);

	$cfg->rewrite_config($rulecache, 1);

	print STDERR "syncing quarantine data\n";
	PMG::Cluster::sync_master_quar($cinfo->{master}->{ip}, $cinfo->{master}->{name});
	print STDERR "syncing quarantine data finished\n";
    };
    my $err = $@;

    foreach my $service (reverse @$PMG::Utils::db_service_list) {
	eval { PVE::Tools::run_command(['systemctl', 'start', $service]); };
	warn $@ if $@;
    }

    die $err if $err;
}

__PACKAGE__->register_method({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
    permissions => { user => 'all' },
    parameters => {
	additionalProperties => 0,
	properties => {},
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
	    { name => 'nodes' },
	    { name => 'status' },
	    { name => 'create' },
	    { name => 'join' },
	    { name => 'update-fingerprints' },
        ];

	return $result;
    }});

__PACKAGE__->register_method({
    name => 'nodes',
    path => 'nodes',
    method => 'GET',
    description => "Cluster node index.",
    # always read local file
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    permissions => { check => [ 'admin', 'qmanager', 'audit' ] },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		type => { type => 'string' },
		cid => { type => 'integer' },
		ip => { type => 'string' },
		name => { type => 'string' },
		hostrsapubkey => { type => 'string' },
		rootrsapubkey => { type => 'string' },
		fingerprint => { type => 'string' },
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $cinfo = PMG::ClusterConfig->new();

	if (scalar(keys %{$cinfo->{ids}})) {
	    my $role = $cinfo->{local}->{type} // '-';
	    if ($role eq '-') {
		die "local node '$cinfo->{local}->{name}' not part of cluster\n";
	    }
	}

	return PVE::RESTHandler::hash_to_array($cinfo->{ids}, 'cid');
    }});

__PACKAGE__->register_method({
    name => 'status',
    path => 'status',
    method => 'GET',
    description => "Cluster node status.",
    # always read local file
    parameters => {
	additionalProperties => 0,
	properties => {
	    list_single_node => {
		description => "List local node if there is no cluster defined. Please note that RSA keys and fingerprint are not valid in that case.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    },
	},
    },
    permissions => { check => [ 'admin', 'qmanager', 'audit' ] },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		type => { type => 'string' },
		cid => { type => 'integer' },
		ip => { type => 'string' },
		name => { type => 'string' },
		hostrsapubkey => { type => 'string' },
		rootrsapubkey => { type => 'string' },
		fingerprint => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{cid}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $cinfo = PMG::ClusterConfig->new();
	my $nodename = PVE::INotify::nodename();

	my $res = [];
	if (scalar(keys %{$cinfo->{ids}})) {
	    my $role = $cinfo->{local}->{type} // '-';
	    if ($role eq '-') {
		die "local node '$cinfo->{local}->{name}' not part of cluster\n";
	    }
	    $res = PVE::RESTHandler::hash_to_array($cinfo->{ids}, 'cid');

	} elsif ($param->{list_single_node}) {
	    my $ni = { type => '-' };
	    foreach my $k (qw(ip name cid)) {
		$ni->{$k} = $cinfo->{local}->{$k};
	    }
	    foreach my $k (qw(hostrsapubkey rootrsapubkey fingerprint)) {
		$ni->{$k} = '-'; # invalid
	    }
	    $res = [ $ni ];
	}

	my $rpcenv = PMG::RESTEnvironment->get();
        my $authuser = $rpcenv->get_user();
	my $ticket = $rpcenv->get_ticket();

	foreach my $ni (@$res) {
	    my $info;
	    eval {
		if ($ni->{cid} eq $cinfo->{local}->{cid}) {
		    $info = PMG::API2::NodeInfo->status({ node => $nodename });
		} else {
		    my $conn = PVE::APIClient::LWP->new(
			ticket => $ticket,
			cookie_name => 'PMGAuthCookie',
			host => $ni->{ip},
			cached_fingerprints => {
			    $ni->{fingerprint} => 1,
			});

		    $info = $conn->get("/nodes/localhost/status", {});
		}
	    };
	    if (my $err = $@) {
		$ni->{conn_error} = "$err"; # convert $err to string
		next;
	    }
	    foreach my $k (keys %$info) {
		$ni->{$k} = $info->{$k} if !defined($ni->{$k});
	    }
	}

	return $res;
    }});

my $add_node_schema = PMG::ClusterConfig::Node->createSchema(1);
delete  $add_node_schema->{properties}->{cid};

__PACKAGE__->register_method({
    name => 'add_node',
    path => 'nodes',
    method => 'POST',
    description => "Add an node to the cluster config.",
    proxyto => 'master',
    protected => 1,
    parameters => $add_node_schema,
    returns => {
	description => "Returns the resulting node list.",
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		cid => { type => 'integer' },
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $code = sub {
	    my $cinfo = PMG::ClusterConfig->new();

	    die "no cluster defined\n" if !scalar(keys %{$cinfo->{ids}});

	    my $master = $cinfo->{master} || die "unable to lookup master node\n";

	    my $next_cid;
	    foreach my $cid (keys %{$cinfo->{ids}}) {
		my $d = $cinfo->{ids}->{$cid};

		if ($d->{type} eq 'node' && $d->{ip} eq $param->{ip} && $d->{name} eq $param->{name}) {
		    $next_cid = $cid; # allow overwrite existing node data
		    last;
		}

		if ($d->{ip} eq $param->{ip}) {
		    die "ip address '$param->{ip}' is already used by existing node $d->{name}\n";
		}

		if ($d->{name} eq $param->{name}) {
		    die "node with name '$param->{name}' already exists\n";
		}
	    }

	    if (!defined($next_cid)) {
		$next_cid = ++$master->{maxcid};
	    }

	    # create spooldir for new node to prevent problems if it gets
	    # delete from the cluster before being synced initially
	    PMG::MailQueue::create_spooldirs($master->{maxcid});

	    my $node = {
		type => 'node',
		cid => $master->{maxcid},
	    };

	    foreach my $k (qw(ip name hostrsapubkey rootrsapubkey fingerprint)) {
		$node->{$k} = $param->{$k};
	    }

	    $cinfo->{ids}->{$node->{cid}} = $node;

	    $cinfo->write();

	    PMG::DBTools::update_master_clusterinfo($node->{cid});

	    PMG::Cluster::update_ssh_keys($cinfo);

	    return PVE::RESTHandler::hash_to_array($cinfo->{ids}, 'cid');
	};

	return PMG::ClusterConfig::lock_config($code, "add node failed");
    }});

__PACKAGE__->register_method({
    name => 'create',
    path => 'create',
    method => 'POST',
    description => "Create initial cluster config with current node as master.",
    # always read local file
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    protected => 1,
    returns => { type => 'string' },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
        my $authuser = $rpcenv->get_user();

	my $realcmd = sub {
	    my $cinfo = PMG::ClusterConfig->new();

	    die "cluster already defined\n" if scalar(keys %{$cinfo->{ids}});

	    my $info = PMG::Cluster::read_local_cluster_info();

	    my $cid = 1;

	    $info->{type} = 'master';

	    $info->{maxcid} = $cid,

	    $cinfo->{ids}->{$cid} = $info;

	    eval {
		print STDERR "stop all services accessing the database\n";
		# stop all services accessing the database
		PMG::Utils::service_wait_stopped(40, $PMG::Utils::db_service_list);

		print STDERR "save new cluster configuration\n";
		$cinfo->write();

		PMG::DBTools::init_masterdb($cid);

		PMG::MailQueue::create_spooldirs($cid);

		print STDERR "cluster master successfully created\n";
	    };
	    my $err = $@;

	    foreach my $service (reverse @$PMG::Utils::db_service_list) {
		eval { PVE::Tools::run_command(['systemctl', 'start', $service]); };
		warn $@ if $@;
	    }

	    die $err if $err;
	};

	my $code = sub {
	    return $rpcenv->fork_worker('clustercreate', undef, $authuser, $realcmd);
	};

	return PMG::ClusterConfig::lock_config($code, "create cluster failed");
    }});

__PACKAGE__->register_method({
    name => 'join',
    path => 'join',
    method => 'POST',
    description => "Join local node to an existing cluster.",
    # always read local file
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    master_ip => {
		description => "IP address.",
		type => 'string', format => 'ip',
	    },
	    fingerprint => {
		description => "SSL certificate fingerprint.",
		type => 'string',
		pattern => '^(:?[A-Z0-9][A-Z0-9]:){31}[A-Z0-9][A-Z0-9]$',
	    },
	    password => {
		description => "Superuser password.",
		type => 'string',
		maxLength => 128,
	    },
	},
    },
    returns => { type => 'string' },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
        my $authuser = $rpcenv->get_user();

	my $realcmd = sub {
	    my $cinfo = PMG::ClusterConfig->new();

	    die "cluster already defined\n" if scalar(keys %{$cinfo->{ids}});

	    my $setup = {
		username => 'root@pam',
		password => $param->{password},
		cookie_name => 'PMGAuthCookie',
		host => $param->{master_ip},
		cached_fingerprints => {
		    $param->{fingerprint} => 1,
		}
	    };

	    cluster_join($cinfo, $setup);
	};

	my $code = sub {
	    return $rpcenv->fork_worker('clusterjoin', undef, $authuser, $realcmd);
	};

	return PMG::ClusterConfig::lock_config($code, "cluster join failed");
    }});

__PACKAGE__->register_method({
    name => 'update_fingerprints',
    path => 'update-fingerprints',
    method => 'POST',
    description => "Update API certificate fingerprints (by fetching it via ssh).",
    proxyto => 'master',
    protected => 1,
    parameters => {
	additionalProperties => 0,
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $code = sub {
	    my $cinfo = PMG::ClusterConfig->new();

	    die "no cluster defined\n" if !scalar(keys %{$cinfo->{ids}});

	    my $localcid = $cinfo->{local}->{cid};

	    foreach my $cid (sort keys %{$cinfo->{ids}}) {
		my $fp;
		if ($cid == $localcid) {
		    $fp = PMG::Cluster::read_local_ssl_cert_fingerprint();
		} else {
		    $fp = PMG::Cluster::get_remote_cert_fingerprint($cinfo->{ids}->{$cid});
		}
		$cinfo->{ids}->{$cid}->{fingerprint} = $fp;
	    }

	    $cinfo->write();

	    return;
	};

	PMG::ClusterConfig::lock_config($code, "update fingerprints failed");
    }});

1;
