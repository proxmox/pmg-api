package PMG::Fetchmail;

use strict;
use warnings;
use Data::Dumper;

use PVE::Tools;
use PVE::INotify;

use PMG::Utils;
use PMG::Config;
use PMG::ClusterConfig;

my $inotify_file_id = 'fetchmailrc';
my $config_filename = '/etc/pmg/fetchmailrc';
my $config_link_filename = '/etc/fetchmailrc';

my $fetchmail_default_id = 'fetchmail_default';
my $fetchmail_default_filename = '/etc/default/fetchmail';

sub read_fetchmail_default {
    my ($filename, $fh) = @_;

    if (defined($fh)) {
	while (defined(my $line = <$fh>)) {
	    if ($line =~ m/^START_DAEMON=yes\s*$/) {
		return 1;
	    }
	}
    }

    return 0;
}

sub write_fetchmail_default {
    my ($filename, $fh, $enable) = @_;

    open (my $orgfh, "<", $filename);

    my $wrote_start_daemon = 0;

    my $write_start_daemon_line = sub {

	return if $wrote_start_daemon;  # only once
	$wrote_start_daemon = 1;

	if ($enable) {
	    print $fh "START_DAEMON=yes\n";
	} else {
	    print $fh "START_DAEMON=no\n";
	}
    };

    if (defined($orgfh)) {
	while (defined(my $line = <$orgfh>)) {
	    if ($line =~ m/^#?START_DAEMON=.*$/) {
		$write_start_daemon_line->();
	    } else {
		print $fh $line;
	    }
	}
    } else {
	$write_start_daemon_line->();
    }
}

PVE::INotify::register_file(
    $fetchmail_default_id, $fetchmail_default_filename,
    \&read_fetchmail_default,
    \&write_fetchmail_default,
    undef,
    always_call_parser => 1);

my $set_fetchmail_defaults = sub {
    my ($item) = @_;

    $item->{protocol} //= 'pop3';
    $item->{interval} //= 1;
    $item->{enable} //= 0;

    if (!$item->{port}) {
	if ($item->{protocol} eq 'pop3') {
	    if ($item->{ssl}) {
		$item->{port} = 995;
	    } else {
		$item->{port} = 110;
	    }
	} elsif ($item->{protocol} eq 'imap') {
	    if ($item->{ssl}) {
		$item->{port} = 993;
	    } else {
		$item->{port} = 143;
	    }
	} else {
	    die "unknown fetchmail protocol '$item->{protocol}'\n";
	}
    }

    return $item;
};

sub read_fetchmail_conf {
    my ($filename, $fh) = @_;

    my $cfg = {};

    if ($fh) {

	# scan for proxmox marker - skip non proxmox lines
	while (defined(my $line = <$fh>)) {
	    last if $line =~ m/^\#\s+proxmox\s+settings.*$/;
	}
	# now parse the rest

	my $data = '';
	my $linenr = 0;

	my $get_next_token = sub {

	    do {
		while ($data =~ /\G("([^"]*)"|\S+|)(?:\s|$)/g) {
		    my ($token, $string) = ($1, $2);
		    if ($1 ne '') {
			$string =~ s/\\x([0-9A-Fa-f]{2})/chr(hex($1))/eg
			    if defined($string);
			return wantarray ? ($token, $string) : $token;
		    }
		}
		$data = <$fh>;
		$linenr = $fh->input_line_number();
	    } while (defined($data));

	    return undef; # EOF
	};

	my $get_token_argument = sub {
	    my ($token, $string) = $get_next_token->();
	    die "line $linenr: missing token argument\n" if !$token;
	    return $string // $token;
	};

	my $finalize_item = sub {
	    my ($item) = @_;
	    $cfg->{$item->{id}} = $item;
	};

	my $item;
	while (my ($token, $string) = $get_next_token->()) {
	    last if !defined($token);
	    if ($token eq 'poll' || $token eq 'skip') {
		$finalize_item->($item) if defined($item);
		my $id = $get_token_argument->();
		$item = { id => $id };
		$item->{enable} = $token eq 'poll' ? 1 : 0;
		next;
	    }

	    die "line $linenr: unexpected token '$token'\n"
		if !defined($item);

	    if ($token eq 'user') {
		$item->{user} = $get_token_argument->();
	    } elsif ($token eq 'via') {
		$item->{server} = $get_token_argument->();
	    } elsif ($token eq 'pass') {
		$item->{pass} = $get_token_argument->();
	    } elsif ($token eq 'to') {
		$item->{target} = $get_token_argument->();
	    } elsif ($token eq 'protocol') {
		$item->{protocol} = $get_token_argument->();
	    } elsif ($token eq 'port') {
		$item->{port} = $get_token_argument->();
	    } elsif ($token eq 'interval') {
		$item->{interval} = $get_token_argument->();
	    } elsif ($token eq 'ssl' || $token eq 'keep' ||
		     $token eq 'dropdelivered') {
		$item->{$token} = 1;
	    } else {
		die "line $linenr: unexpected token '$token' inside entry '$item->{id}'\n";
	    }
	}
	$finalize_item->($item) if defined($item);
    }

    return $cfg;
}

sub write_fetchmail_conf {
    my ($filename, $fh, $fmcfg) = @_;

    my $data = {};

    # Note: we correctly quote data here to make fetchmailrc.tt simpler

    my $entry_count = 0;

    foreach my $id (keys %$fmcfg) {
	my $org = $fmcfg->{$id};
	my $item = { id => $id };
	$entry_count++;
	foreach my $k (keys %$org) {
	    my $v = $org->{$k};
	    $v =~ s/([^A-Za-z0-9\:\@\-\._~])/sprintf "\\x%02x",ord($1)/eg;
	    $item->{$k} = $v;
	}
	$set_fetchmail_defaults->($item);
	my $options = [ 'dropdelivered' ];
	push @$options, 'ssl' if $item->{ssl};
	push @$options, 'keep' if $item->{keep};
	$item->{options} = join(' ', @$options);
	$data->{$id} = $item;
    }

    my $raw = '';

    my $pmgcfg = PMG::Config->new();
    my $vars = $pmgcfg->get_template_vars();
    $vars->{fetchmail_users} = $data;

    my $tt = PMG::Config::get_template_toolkit();
    $tt->process('fetchmailrc.tt', $vars, \$raw) ||
	die $tt->error() . "\n";

    my (undef, undef, $uid, $gid) = getpwnam('fetchmail');
    chown($uid, $gid, $fh) if defined($uid) && defined($gid);
    chmod(0600, $fh);

    PVE::Tools::safe_print($filename, $fh, $raw);

    update_fetchmail_default($entry_count);
}

sub update_fetchmail_default {
    my ($enable) = @_;

    my $cinfo = PMG::ClusterConfig->new();

    my $is_enabled = PVE::INotify::read_file('fetchmail_default');
    my $role = $cinfo->{local}->{type} // '-';
    if (($role eq '-') || ($role eq 'master')) {
	if (!!$enable != !!$is_enabled) {
	    PVE::INotify::write_file('fetchmail_default', $enable);
	    PMG::Utils::service_cmd('fetchmail', 'restart');
	}
	if (! -e $config_link_filename) {
	    symlink ($config_filename, $config_link_filename);
	}
    } else {
	if ($is_enabled) {
	    PVE::INotify::write_file('fetchmail_default', 0);
	}
	if (-e $config_link_filename) {
	    unlink $config_link_filename;
	}
    }
}

PVE::INotify::register_file(
    $inotify_file_id, $config_filename,
    \&read_fetchmail_conf,
    \&write_fetchmail_conf,
    undef,
    always_call_parser => 1);

1;
