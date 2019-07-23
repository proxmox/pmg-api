package PMG::RESTEnvironment;

use strict;
use warnings;

use PVE::INotify;
use PVE::RESTEnvironment;
use PVE::Exception qw(raise_perm_exc);

use PMG::Cluster;
use PMG::ClusterConfig;
use PMG::AccessControl;

use base qw(PVE::RESTEnvironment);

my $nodename = PVE::INotify::nodename();

# initialize environment - must be called once at program startup
sub init {
    my ($class, $type, %params) = @_;

    $class = ref($class) || $class;

    my $self = $class->SUPER::init($type, %params);

    $self->{cinfo} = {};
    $self->{usercfg} = {};
    $self->{ticket} = undef;
 
    return $self;
};

# init_request - must be called before each RPC request
sub init_request {
    my ($self, %params) = @_;
    
    $self->SUPER::init_request(%params);
    
    $self->{ticket} = undef;
    $self->{role} = undef;
    $self->{format} = undef;
    $self->{cinfo} = PVE::INotify::read_file("cluster.conf");
    $self->{usercfg} = PVE::INotify::read_file("pmg-user.conf");
}

sub setup_default_cli_env {
    my ($class, $username) = @_;

    $class->SUPER::setup_default_cli_env($username);

    my $rest_env = $class->get();
    $rest_env->set_role('root');
}

sub set_format {
    my ($self, $ticket) = @_;

    $self->{format} = $ticket;
}

sub get_format {
    my ($self) = @_;

    return $self->{format} // 'json';
}

sub set_ticket {
    my ($self, $ticket) = @_;

    $self->{ticket} = $ticket;
}

sub get_ticket {
    my ($self) = @_;

    return $self->{ticket};
}

sub set_role {
    my ($self, $user) = @_;

    $self->{role} = $user;
}

sub get_role {
    my ($self) = @_;

    return $self->{role};
}

sub check_node_is_master {
    my ($self, $noerr);

    my $master = PMG::Cluster::get_master_node($self->{cinfo});

    return 1 if $master eq 'localhost' || $master eq $nodename;

    return undef if $noerr;

    die "this node ('$nodename') is not the master node\n";
}

sub check_api2_permissions {
    my ($self, $perm, $uri_param) = @_;

    my $username = $self->get_user(1);

    return 1 if !$username && $perm->{user} && $perm->{user} eq 'world';

    raise_perm_exc("user == null") if !$username;

    return 1 if $username eq 'root@pam';

    raise_perm_exc('user != root@pam') if !$perm;

    return 1 if $perm->{user} && $perm->{user} eq 'all';

    my $role = $self->{role};

    if (my $allowed_roles = $perm->{check}) {
	if ($role eq 'helpdesk') {
	    # helpdesk is qmanager + audit
	    return 1 if grep { $_ eq 'audit' } @$allowed_roles;
	    return 1 if grep { $_ eq 'qmanager' } @$allowed_roles;
	}
	return 1 if grep { $_ eq $role } @$allowed_roles;
    }

    raise_perm_exc();
}

1;
