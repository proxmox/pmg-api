package PMG::LDAPSet;

use strict;
use warnings;

use PVE::SafeSyslog;

use PMG::LDAPCache;
use PMG::LDAPConfig;

sub new_from_ldap_cfg {
    my ($self, $ldap_cfg, $syncmode, $serverid) = @_;
    my $type = ref($self) || $self;

    my $ids = [];

    if ($serverid) {
	$ids = [ $serverid ];
    } else {
	$ids = [ keys %{$ldap_cfg->{ids}} ];
    }

    $self = bless {}, $type;

    foreach my $id (@$ids) {

	# fixme: does it work?
	my $data = $ldap_cfg->{ids}->{$id};
	next if !ref($data);
	next if $data->{disable};

	$data->{syncmode} = $syncmode;
	$data->{id} = $id;

	$self->{$id} = PMG::LDAPCache->new(%$data);
    }

    return $self;
}

sub ldap_resync {
    my ($ldap_cfg, $tostderr) = @_;

    my $ldap = __PACKAGE__->new_from_ldap_cfg($ldap_cfg, 1);

    foreach my $p (@{$ldap->ids()}) {
	my $server = $ldap->{$p}->{server1};

	my $msg = "start syncing ldap profile '${p}' (${server})";
	syslog('info', $msg);
	print STDERR "$msg\n" if $tostderr;

	$ldap->{$p}->update(2);

	my $errors = $ldap->{$p}->{errors};
	print STDERR $errors if $tostderr && $errors;

	my $gcount = $ldap->{$p}->{gcount};
	my $ucount = $ldap->{$p}->{ucount};
	my $mcount = $ldap->{$p}->{mcount};

	if ($errors) {
	    $msg = "aborted syncing ldap profile '${p}' (${server}): " .
		"keep old data, $ucount accounts, $mcount addresses, $gcount groups";
	} else {
	    $msg = "finished syncing ldap profile '${p}' (${server}): " .
		"found $ucount accounts, $mcount addresses, $gcount groups";
	}
	syslog('info', $msg);
	print STDERR "$msg\n" if $tostderr;
    }
}

sub ids {
    my ($self) = @_;

    my $ids = [];

    foreach my $id (keys %$self) {
	next if ref($self->{$id}) ne 'PMG::LDAPCache';
	push @$ids, $id;
    }

    return $ids;
}

sub update {
    my ($self, $syncmode) = @_;
    foreach my $id (@{$self->ids()}) {
	$self->{$id}->update($syncmode);
    }
}

sub groups {
    my ($self, $id) = @_;

    if (!($self->{$id} && ref($self->{$id}) eq 'PMG::LDAPCache')) {
	syslog('warning', "WARNING: trying to query non-existent ldap profile '$id'");
	return undef;
    }

    return $self->{$id}->groups();
}

sub mail_exists {
    my ($self, $mail, $id) = @_;

    if ($id) {
	if (!($self->{$id} &&  ref($self->{$id}) eq 'PMG::LDAPCache')) {
	    syslog('warning', "WARNING: trying to query non-existent ldap profile '$id'");
	    return undef;
	}
	return  $self->{$id}->mail_exists($mail);
    }

    foreach $id (@{$self->ids()}) {
	my $res = $self->{$id}->mail_exists($mail);
	return $res if $res;
    }

    return 0;
}

sub account_exists {
    my ($self, $account, $id) = @_;

    if (!($self->{$id} && ref($self->{$id}) eq 'PMG::LDAPCache')) {
	syslog('warning', "WARNING: trying to query non-existent ldap profile '$id'");
	return undef;
    }

    return $self->{$id}->account_exists($account);
}

sub account_has_address {
    my ($self, $account, $mail, $id) = @_;

    if (!($self->{$id} && ref($self->{$id}) eq 'PMG::LDAPCache')) {
	syslog('warning', "WARNING: trying to query non-existent ldap profile '$id'");
	return undef;
    }

    return  $self->{$id}->account_has_address($account, $mail);
}

sub user_in_group {
    my ($self, $mail, $group, $id) = @_;

    if (!($self->{$id} && ref($self->{$id}) eq 'PMG::LDAPCache')) {
	syslog('warning', "WARNING: trying to query non-existent ldap profile '$id'");
	return undef;
    }

    return  $self->{$id}->user_in_group($mail, $group);
}

sub account_info {
    my ($self, $mail, $password) = @_;

    foreach my $id (@{$self->ids()}) {
	if ($self->{$id}->mail_exists($mail)) {
	    if (my $res = $self->{$id}->account_info($mail)) {
		$res->{profile} = $id;

		if (defined($password)) {
		    if (my $ldap = $self->{$id}->ldap_connect()) {
			my $mesg = $ldap->bind($res->{dn}, password => $password);
			return undef if ($mesg->code);
		    } else {
			return undef;
		    }
		}

		return $res;
	    }
	}
    }

    return undef;
}

1;
