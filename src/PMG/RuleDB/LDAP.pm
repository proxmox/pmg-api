package PMG::RuleDB::LDAP;

use strict;
use warnings;
use DBI;
use Encode qw(encode);

use PVE::Exception qw(raise_param_exc);

use PMG::Utils;
use PMG::RuleDB::Object;
use PMG::LDAPCache;
use PMG::LDAPSet;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 1005;
}

sub oclass {
    return 'who';
}

sub otype_text {
    return 'LDAP Group';
}

sub new {
    my ($type, $ldapgroup, $profile, $ogroup) = @_;

    my $class = ref($type) || $type;

    my $self = $class->SUPER::new($class->otype(), $ogroup);

    $self->{ldapgroup} = $ldapgroup // '';
    $self->{profile} = $profile // '';

    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;

    my $class = ref($type) || $type;

    defined($value) || die "undefined value: ERROR";

    my $decoded = PMG::Utils::try_decode_utf8($value);

    my $obj;
    if ($decoded =~ m/^([^:]*):(.*)$/) {
	$obj = $class->new($2, $1, $ogroup);
	$obj->{digest} = Digest::SHA::sha1_hex($id, encode('UTF-8', $2), encode('UTF-8', $1), $ogroup);
    } else {
	$obj = $class->new($decoded, '', $ogroup);
	$obj->{digest} = Digest::SHA::sha1_hex($id, $value, '#', $ogroup);
    }

    $obj->{id} = $id;

    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || die "undefined ogroup: ERROR";
    defined($self->{ldapgroup}) || die "undefined ldap group: ERROR";
    defined($self->{profile}) || die "undefined ldap profile: ERROR";

    my $grp = $self->{ldapgroup};
    my $profile = $self->{profile};

    my $confdata = encode('UTF-8', "$profile:$grp");

    if (defined ($self->{id})) {
	# update

	$ruledb->{dbh}->do(
	    "UPDATE Object SET Value = ? WHERE ID = ?",
	    undef, $confdata, $self->{id});

    } else {
	# insert

	# check if it exists first
	if (my $id = PMG::Utils::get_existing_object_id(
	    $ruledb->{dbh},
	    $self->{ogroup},
	    $self->otype(),
	    $confdata
	)) {
	    return $id;
	}

	my $sth = $ruledb->{dbh}->prepare(
	    "INSERT INTO Object (Objectgroup_ID, ObjectType, Value) " .
	    "VALUES (?, ?, ?);");

	$sth->execute($self->{ogroup}, $self->otype, $confdata);

	$self->{id} = PMG::Utils::lastid($ruledb->{dbh}, 'object_id_seq');
    }

    return $self->{id};
}

sub test_ldap {
    my ($ldap, $addr, $group, $profile) = @_;

    if ($group eq '') {
	return $ldap->mail_exists($addr, $profile);
    } elsif ($group eq '-') {
	return !$ldap->mail_exists($addr, $profile);
    } elsif ($profile) {
	return $ldap->user_in_group ($addr, $group, $profile);
    } else {
	# fail if we have a real $group without $profile
	return 0;
    }
}

sub who_match {
    my ($self, $addr, $ip, $ldap) = @_;

    return 0 if !$ldap;

    return test_ldap($ldap, $addr, $self->{ldapgroup}, $self->{profile});
}

sub short_desc {
    my ($self) = @_;

    my $desc;

    my $profile = $self->{profile};
    my $group = $self->{ldapgroup};

    if ($group eq '') {
	$desc = "Existing LDAP address";
	if ($profile) {
	    $desc .= ", profile '$profile'";
	} else {
	    $desc .= ", any profile";
	}
    } elsif ($group eq '-') {
	$desc = "Unknown LDAP address";
	if ($profile) {
	    $desc .= ", profile '$profile'";
	} else {
	    $desc .= ", any profile";
	}
    } elsif ($profile) {
	$desc = "LDAP group '$group', profile '$profile'";
    } else {
	$desc = "LDAP group without profile - fail always";
    }

    return $desc;
}

sub properties {
    my ($class) = @_;

    return {
	mode => {
	    description => "Operational mode. You can either match 'any' user, match when no such user exists with 'none', or match when the user is member of a specific group.",
	    type => 'string',
	    enum => ['any', 'none', 'group'],
	},
	profile => {
	    description => "Profile ID.",
	    type => 'string', format => 'pve-configid',
	    optional => 1,
	},
	group => {
	    description => "LDAP Group DN",
	    type => 'string',
	    maxLength => 1024,
	    minLength => 1,
	    optional => 1,
	},
    };
}

sub get {
    my ($self) = @_;

    my $group = $self->{ldapgroup};
    my $profile = $self->{profile},

    my $data = {};

    if ($group eq '') {
	$data->{mode} = 'any';
    } elsif ($group eq '-') {
	$data->{mode} = 'none';
    } else {
	$data->{mode} = 'group';
	$data->{group} = $group;
    }

    $data->{profile} = $profile if $profile ne '';

    return $data;
 }

sub update {
    my ($self, $param) = @_;

    my $mode = $param->{mode};

    if (defined(my $profile = $param->{profile})) {
	my $cfg = PVE::INotify::read_file("pmg-ldap.conf");
	my $config = $cfg->{ids}->{$profile};
	die "LDAP profile '$profile' does not exist\n" if !$config;

	if (defined(my $group = $param->{group})) {
	    my $ldapcache = PMG::LDAPCache->new(
		id => $profile, syncmode => 1, %$config);

	    die "LDAP group '$group' does not exist\n"
		if !$ldapcache->group_exists($group);
	}
    }

    if ($mode eq 'any') {
	raise_param_exc({ group => "parameter not allwed with mode '$mode'"})
	    if defined($param->{group});
	$self->{ldapgroup} = '';
	$self->{profile} = $param->{profile} // '';
    } elsif ($mode eq 'none') {
	raise_param_exc({ group => "parameter not allwed with mode '$mode'"})
	    if defined($param->{group});
	$self->{ldapgroup} = '-';
	$self->{profile} = $param->{profile} // '';
    } elsif ($mode eq 'group') {
	raise_param_exc({ group => "parameter is required with mode '$mode'"})
	    if !defined($param->{group});
	$self->{ldapgroup} = $param->{group};
	raise_param_exc({ profile => "parameter is required with mode '$mode'"})
	    if !defined($param->{profile});
	$self->{profile} = $param->{profile};
    } else {
	die "internal error"; # just to me sure
    }
}

1;

__END__

=head1 PMG::RuleDB::LDAP

A WHO object to check LDAP groups

=head2 Attributes

=head3 ldapgroup

An LDAP group (ignore case).

=head3 profile

The LDAP profile name

=head2 Examples

    $obj = PMG::RuleDB::LDAP>new ('groupname', 'profile_name');
