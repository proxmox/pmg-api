package PMG::UserConfig;

use strict;
use warnings;

use Clone 'clone';
use Scalar::Util 'weaken';

use PVE::Tools;
use PVE::INotify;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Exception qw(raise);

use PMG::Utils;

my $inotify_file_id = 'pmg-user.conf';
my $config_filename = '/etc/pmg/user.conf';

my $tfa_inotify_file_id = 'pmg-tfa.json';
my $tfa_config_filename = '/etc/pmg/tfa.json';

sub new {
    my ($type) = @_;

    my $class = ref($type) || $type;

    my $cfg = PVE::INotify::read_file($inotify_file_id);

    return bless $cfg, $class;
}

sub write {
    my ($self) = @_;

    PVE::INotify::write_file($inotify_file_id, $self);
}

my $lockfile = "/var/lock/pmguser.lck";
my $tfa_lockfile = "/var/lock/pmgtfa.lck";

# Locking both config files together is only ever allowed in one order:
#  1) tfa config
#  2) user config
# If we permit the other way round, too, we might end up deadlocking!
my $user_config_locked;
sub lock_config {
    my ($code, $errmsg) = @_;

    my $locked = 1;
    $user_config_locked = \$locked;
    weaken $user_config_locked; # make this scope guard signal safe...

    my $p = PVE::Tools::lock_file($lockfile, undef, $code);
    $user_config_locked = undef;
    if (my $err = $@) {
	$errmsg ? die "$errmsg: $err" : die $err;
    }
}

# This lives here in order to enforce lock order.
sub lock_tfa_config {
    my ($code, $errmsg) = @_;

    die "tfa config lock cannot be acquired while holding user config lock\n"
	if ($user_config_locked && $$user_config_locked);

    my $res = PVE::Tools::lock_file($tfa_lockfile, undef, $code);
    if (my $err = $@) {
	$errmsg ? die "$errmsg: $err" : die $err;
    }

    return $res;
}

my $schema = {
    additionalProperties => 0,
    properties => {
	userid => get_standard_option('userid'),
	username => get_standard_option('username', { optional => 1 }),
	realm => {
	    description => "Authentication realm.",
	    type => 'string',
	    enum => ['pam', 'pmg'],
	    default => 'pmg',
	    optional => 1,
	},
	email => {
	    description => "Users E-Mail address.",
	    type => 'string', format => 'email',
	    optional => 1,
	},
	expire => {
	    description => "Account expiration date (seconds since epoch). '0' means no expiration date.",
	    type => 'integer',
	    minimum => 0,
	    default => 0,
	    optional => 1,
	},
	enable => {
	    description => "Flag to enable or disable the account.",
	    type => 'boolean',
	    default => 0,
	    optional => 1,
	},
	crypt_pass => {
	    description => "Encrypted password (see `man crypt`)",
	    type => 'string',
	    pattern => '\$\d\$[a-zA-Z0-9\.\/]+\$[a-zA-Z0-9\.\/]+',
	    optional => 1,
	},
	role => {
	    description => "User role. Role 'root' is reserved for the Unix Superuser.",
	    type => 'string',
	    enum => ['root', 'admin', 'helpdesk', 'qmanager', 'audit'],
	},
	firstname => {
	    description => "First name.",
	    type => 'string',
	    maxLength => 64,
	    optional => 1,
	},
	lastname => {
	    description => "Last name.",
	    type => 'string',
	    maxLength => 64,
	    optional => 1,
	},
	keys => {
	    description => "Keys for two factor auth (yubico).",
	    type => 'string',
	    maxLength => 128,
	    optional => 1,
	},
	comment => {
	    description => "Comment.",
	    type => 'string',
	    optional => 1,
	},
    },
};

our $create_schema = clone($schema);
delete $create_schema->{properties}->{username};
delete $create_schema->{properties}->{realm};
$create_schema->{properties}->{password} = {
    description => "Password",
    type => 'string',
    maxLength => 32,
    minLength => 5,
    optional => 1,
};

our $update_schema = clone($create_schema);
$update_schema->{properties}->{role}->{optional} = 1;
$update_schema->{properties}->{delete} = {
    type => 'string', format => 'pve-configid-list',
    description => "A list of settings you want to delete.",
    maxLength => 4096,
    optional => 1,
};

my $verify_entry = sub {
    my ($entry) = @_;

    my $errors = {};
    my $userid = $entry->{userid};
    if (defined(my $username = $entry->{username})) {
	if ($userid !~ /^\Q$username\E\@/) {
	    $errors->{'username'} = 'invalid username for userid';
	}
    } else {
	# make sure the username's length is checked
	$entry->{username} = ($userid =~ s/\@.*$//r);
    }
    PVE::JSONSchema::check_prop($entry, $schema, '', $errors);
    if (scalar(%$errors)) {
	raise "verify entry failed\n", errors => $errors;
    }
};

my $fixup_root_properties = sub {
    my ($cfg) = @_;

    $cfg->{'root@pam'}->{userid} = 'root@pam';
    $cfg->{'root@pam'}->{username} = 'root';
    $cfg->{'root@pam'}->{realm} = 'pam';
    $cfg->{'root@pam'}->{enable} = 1;
    $cfg->{'root@pam'}->{expire} = 0;
    $cfg->{'root@pam'}->{comment} = 'Unix Superuser';
    $cfg->{'root@pam'}->{role} = 'root';
    delete $cfg->{'root@pam'}->{crypt_pass};
};

sub read_user_conf {
    my ($filename, $fh) = @_;

    my $cfg = {};

    if ($fh) {

	my $comment = '';

	while (defined(my $line = <$fh>)) {
	    next if $line =~ m/^\s*$/;
	    if ($line =~ m/^#(.*)$/) {
		$comment = $1;
		next;
	    }

	    if ($line =~ m/^
               (?<userid>(?:[^\s:]+)) :
               (?<enable>[01]?) :
               (?<expire>\d*) :
               (?<crypt_pass>(?:[^\s:]*)) :
               (?<role>[a-z]+) :
               (?<email>(?:[^\s:]*)) :
               (?<firstname>(?:[^:]*)) :
               (?<lastname>(?:[^:]*)) :
               (?<keys>(?:[^:]*)) :
               $/x
	    ) {
		my $d = {
		    username => $+{userid},
		    userid => $+{userid} . '@pmg',
		    realm => 'pmg',
		    enable => $+{enable} || 0,
		    expire => $+{expire} || 0,
		    role => $+{role},
		};
		$d->{comment} = $comment if $comment;
		$comment = '';
		foreach my $k (qw(crypt_pass email firstname lastname keys)) {
		    $d->{$k} = $+{$k} if $+{$k};
		}
		eval {
		    $verify_entry->($d);
		    $cfg->{$d->{userid}} = $d;
		    die "role 'root' is reserved\n"
			if $d->{role} eq 'root' && $d->{userid} ne 'root@pmg';
		};
		if (my $err = $@) {
		    warn "$filename: $err";
		}
	    } else {
		warn "$filename: ignore invalid line $.\n";
		$comment = '';
	    }
	}
    }

    # hack: we list root@pam here (root@pmg is an alias for root@pam)
    $cfg->{'root@pam'} = $cfg->{'root@pmg'} // {};
    delete $cfg->{'root@pmg'};
    $cfg->{'root@pam'} //= {};

    $fixup_root_properties->($cfg);

    return $cfg;
}

sub write_user_conf {
    my ($filename, $fh, $cfg) = @_;

    my $raw = '';

    $fixup_root_properties->($cfg);

    foreach my $userid (keys %$cfg) {
	my $d = $cfg->{$userid};

	$d->{userid} = $userid;

	die "invalid userid '$userid'\n" if $userid eq 'root@pmg';
	$verify_entry->($d);
	$cfg->{$d->{userid}} = $d;

	if ($d->{userid} ne 'root@pam') {
	    die "role 'root' is reserved\n" if $d->{role} eq 'root';
	    die "unable to add users for realm '$d->{realm}'\n"
		if $d->{realm} && $d->{realm} ne 'pmg';
	}

	my $line;

	if ($userid eq 'root@pam') {
	    $line = 'root:';
	    $d->{crypt_pass} = '',
	    $d->{expire} = '0',
	    $d->{role} = 'root';
	} else {
	    next if $userid !~ m/^(?<username>.+)\@pmg$/;
	    $line = "$+{username}:";
	}

	for my $k (qw(enable expire crypt_pass role email firstname lastname keys)) {
	    $line .= ($d->{$k} // '') . ':';
	}
	if (my $comment = $d->{comment}) {
	    my $firstline = (split /\n/, $comment)[0]; # only allow one line
	    $raw .= "#$firstline\n";
	}
	$raw .= $line . "\n";
    }

    my $gid = getgrnam('www-data');
    chown(0, $gid, $fh);
    chmod(0640, $fh);

    PVE::Tools::safe_print($filename, $fh, $raw);
}

PVE::INotify::register_file($inotify_file_id, $config_filename,
			    \&read_user_conf,
			    \&write_user_conf,
			    undef,
			    always_call_parser => 1);

sub lookup_user_data {
    my ($self, $username, $noerr) = @_;

    return $self->{$username} if $self->{$username};

    die "no such user ('$username')\n" if !$noerr;

    return undef;
}

sub authenticate_user {
    my ($self, $username, $password) = @_;

    die "no password\n" if !$password;

    my $data = $self->lookup_user_data($username);

    my $ctime = time();
    my $expire = $data->{expire};

    die "account expired\n" if $expire && ($expire < $ctime);

    if ($data->{crypt_pass}) {
	my $encpw = crypt($password, $data->{crypt_pass});
        die "invalid credentials\n" if ($encpw ne $data->{crypt_pass});
    } else {
	die "no password set\n";
    }

    return 1;
}

sub set_user_password {
    my ($class, $username, $password) = @_;

    lock_config(sub {
	my $cfg = $class->new();
	my $data = $cfg->lookup_user_data($username); # user exists
	my $epw = PVE::Tools::encrypt_pw($password);
	$data->{crypt_pass} = $epw;
	$cfg->write();
    });
}

1;
