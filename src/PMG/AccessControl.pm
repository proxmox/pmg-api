package PMG::AccessControl;

use strict;
use warnings;
use Authen::PAM;

use PVE::Tools;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Exception qw(raise raise_perm_exc);

use PMG::UserConfig;
use PMG::LDAPConfig;
use PMG::LDAPSet;
use PMG::TFAConfig;

sub normalize_path {
    my $path = shift;

    $path =~ s|/+|/|g;
    $path =~ s|/$||;
    $path = '/' if !$path;
    $path = "/$path" if $path !~ m|^/|;
    return undef if $path !~ m|^[[:alnum:]\.\-\_\/]+$|;

    return $path;
}

# password should be utf8 encoded
# Note: some plugins delay/sleep if auth fails
#
# returns ($username, $tfa_challenge)
sub authenticate_user : prototype($$$) {
    my ($username, $password, $skip_tfa) = @_;

    die "no username specified\n" if !$username;

    my ($ruid, $realm);

    ($username, $ruid, $realm) = PMG::Utils::verify_username($username);

    if ($realm eq 'pam') {
	die "invalid pam user (only root allowed)\n" if $ruid ne 'root';
	authenticate_pam_user($ruid, $password);
    } elsif ($realm eq 'pmg') {
	my $usercfg = PMG::UserConfig->new();
	$usercfg->authenticate_user($username, $password);
    } elsif ($realm eq 'quarantine') {
	my $ldap_cfg = PMG::LDAPConfig->new();
	my $ldap = PMG::LDAPSet->new_from_ldap_cfg($ldap_cfg, 1);

	if (my $ldapinfo = $ldap->account_info($ruid, $password)) {
	    my $pmail = $ldapinfo->{pmail};
	    return ($pmail . '@quarantine', undef);
	}
	die "ldap login failed\n";
    } else {
	die "no such realm '$realm'\n";
    }

    return ($username, undef) if $skip_tfa;

    my $tfa = PMG::TFAConfig->new();

    my $origin = undef;
    if (!$tfa->has_webauthn_origin()) {
	my $rpcenv = PMG::RESTEnvironment->get();
	$origin = 'https://'.$rpcenv->get_request_host(1);
    }

    my $tfa_challenge = $tfa->authentication_challenge($username, $origin);

    return ($username, $tfa_challenge);
}

sub set_user_password {
    my ($username, $password) = @_;

    my ($ruid, $realm);
    
    ($username, $ruid, $realm) = PMG::Utils::verify_username($username);

    if ($realm eq 'pam') {
	die "invalid pam user (only root allowed)\n" if $ruid ne 'root';

	my $cmd = ['usermod'];

	my $epw = PVE::Tools::encrypt_pw($password);

	push @$cmd, '-p', $epw, $ruid;

	PVE::Tools::run_command($cmd, errmsg => "change password for '$ruid' failed");

    } elsif ($realm eq 'pmg') {
	PMG::UserConfig->set_user_password($username, $password);
    } else {
	die "no such realm '$realm'\n";
    }
}

# test if user exists and is enabled
# returns: role
sub check_user_enabled {
    my ($usercfg, $username, $noerr) = @_;

    my ($ruid, $realm);

    ($username, $ruid, $realm) = PMG::Utils::verify_username($username, 1);

    if ($realm && $ruid) {
	if ($realm eq 'pam') {
	    return 'root' if $ruid eq 'root';
	} elsif ($realm eq 'pmg') {
	    my $usercfg = PMG::UserConfig->new();
	    my $data = $usercfg->lookup_user_data($username, $noerr);
	    return $data->{role} if $data && $data->{enable};
	} elsif ($realm eq 'quarantine') {
	    return 'quser';
	}
    }

    raise_perm_exc("user '$username' is disabled") if !$noerr;

    return undef;
}

sub authenticate_pam_user {
    my ($username, $password) = @_;

    # user need to be able to read /etc/passwd /etc/shadow

    my $pamh = Authen::PAM->new('proxmox-mailgateway-auth', $username, sub {
	my @res;
	while(@_) {
	    my $msg_type = shift;
	    my $msg = shift;
	    push @res, (0, $password);
	}
	push @res, 0;
	return @res;
    });

    if (my $rpcenv = PMG::RESTEnvironment->get()) {
	if (my $ip = $rpcenv->get_client_ip()) {
	    $pamh->pam_set_item(PAM_RHOST(), $ip);
	}
    }

    if (!ref($pamh)) {
	my $err = $pamh->pam_strerror($pamh);
	die "Error during PAM init: $err";
    }

    my $res;

    if (($res = $pamh->pam_authenticate(0)) != PAM_SUCCESS) {
	my $err = $pamh->pam_strerror($res);
	die "auth failed: $err\n";
    }

    if (($res = $pamh->pam_acct_mgmt(0)) != PAM_SUCCESS) {
	my $err = $pamh->pam_strerror($res);
	die "auth failed: $err\n";
    }

    $pamh = 0; # call destructor

    return 1;
}

1;
