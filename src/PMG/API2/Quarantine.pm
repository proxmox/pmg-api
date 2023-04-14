package PMG::API2::Quarantine;

use strict;
use warnings;

use Time::Local;
use Time::Zone;
use Data::Dumper;
use Encode;
use File::Path;
use IO::File;
use MIME::Entity;
use URI::Escape qw(uri_escape);
use File::stat ();

use Mail::Header;
use Mail::SpamAssassin;

use PVE::SafeSyslog;
use PVE::Exception qw(raise_param_exc raise_perm_exc);
use PVE::Tools qw(extract_param);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RESTHandler;
use PVE::INotify;
use PVE::APIServer::Formatter;

use PMG::Utils qw(try_decode_utf8);
use PMG::AccessControl;
use PMG::Config;
use PMG::DBTools;
use PMG::HTMLMail;
use PMG::Quarantine;
use PMG::MailQueue;
use PMG::MIMEUtils;

use base qw(PVE::RESTHandler);

my $spamdesc;

my $extract_pmail = sub {
    my ($authuser, $role) = @_;

    if ($authuser =~ m/^(.+)\@quarantine$/) {
	return $1;
    }
    raise_param_exc({ pmail => "got unexpected authuser '$authuser' with role '$role'"});
};

my $verify_optional_pmail = sub {
    my ($authuser, $role, $pmail_param) = @_;

    my $pmail;
    if ($role eq 'quser') {
	$pmail = $extract_pmail->($authuser, $role);
	raise_param_exc({ pmail => "parameter not allowed with role '$role'"})
	    if defined($pmail_param) && ($pmail ne $pmail_param);
    } else {
	raise_param_exc({ pmail => "parameter required with role '$role'"})
	    if !defined($pmail_param);
	$pmail = $pmail_param;
    }
    return $pmail;
};

sub decode_spaminfo {
    my ($info) = @_;

    my $res = [];
    return $res if !defined($info);

    my $saversion = Mail::SpamAssassin->VERSION;

    my $salocaldir = "/var/lib/spamassassin/$saversion/updates_spamassassin_org";
    my $sacustomdir = "/etc/mail/spamassassin";
    my $kamdir = "/var/lib/spamassassin/$saversion/kam_sa-channels_mcgrail_com";

    $spamdesc = PMG::Utils::load_sa_descriptions([$salocaldir, $sacustomdir, $kamdir]) if !$spamdesc;

    foreach my $test (split (',', $info)) {
	my ($name, $score) = split (':', $test);

	my $info = { name => $name, score => $score + 0, desc => '-' };
	if (my $si = $spamdesc->{$name}) {
	    $info->{desc} = $si->{desc};
	    $info->{url} = $si->{url} if defined($si->{url});
	}
	push @$res, $info;
    }

    return $res;
}

my $extract_email = sub {
    my $data = shift;

    return $data if !$data;

    if ($data =~ m/^.*\s(\S+)\s*$/) {
	$data = $1;
    }

    if ($data =~ m/^<([^<>\s]+)>$/) {
	$data = $1;
    }

    if ($data !~ m/[\s><]/ && $data =~ m/^(.+\@[^\.]+\..*[^\.]+)$/) {
	$data = $1;
    } else {
	$data = undef;
    }

    return $data;
};

my $get_real_sender = sub {
    my ($ref) = @_;

    my @lines = split('\n', $ref->{header});
    my $head = Mail::Header->new(\@lines);

    my @fromarray = split ('\s*,\s*', $head->get ('from') || $ref->{sender});
    my $from =  $extract_email->($fromarray[0]) || $ref->{sender};;
    my $sender = $extract_email->($head->get ('sender'));

    return $sender if $sender;

    return $from;
};

my $parse_header_info = sub {
    my ($ref) = @_;

    my $res = { subject => '', from => '' };

    my @lines = split('\n', $ref->{header});
    my $head = Mail::Header->new(\@lines);

    $res->{subject} = PMG::Utils::decode_rfc1522(PVE::Tools::trim($head->get('subject'))) // '';

    $res->{from} = PMG::Utils::decode_rfc1522(PVE::Tools::trim($head->get('from') || $ref->{sender})) // '';

    my $sender = PMG::Utils::decode_rfc1522(PVE::Tools::trim($head->get('sender')));
    $res->{sender} = $sender if $sender && ($sender ne $res->{from});

    $res->{envelope_sender} = try_decode_utf8($ref->{sender});
    $res->{receiver} = try_decode_utf8($ref->{receiver} // $ref->{pmail});
    $res->{id} = 'C' . $ref->{cid} . 'R' . $ref->{rid} . 'T' . $ref->{ticketid};
    $res->{time} = $ref->{time};
    $res->{bytes} = $ref->{bytes};

    my $qtype = $ref->{qtype};

    if ($qtype eq 'V') {
	$res->{virusname} = $ref->{info};
	$res->{spamlevel} = 0;
    } elsif ($qtype eq 'S') {
	$res->{spamlevel} = $ref->{spamlevel} // 0;
    }

    return $res;
};

my $pmail_param_type = get_standard_option('pmg-email-address', {
    description => "List entries for the user with this primary email address. Quarantine users cannot specify this parameter, but it is required for all other roles.",
    optional => 1,
});

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    permissions => { user => 'all' },
    description => "Directory index.",
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
	    { name => 'whitelist' },
	    { name => 'blacklist' },
	    { name => 'content' },
	    { name => 'spam' },
	    { name => 'spamusers' },
	    { name => 'spamstatus' },
	    { name => 'virus' },
	    { name => 'virusstatus' },
	    { name => 'quarusers' },
	    { name => 'attachment' },
	    { name => 'listattachments' },
	    { name => 'download' },
	    { name => 'sendlink' },
	];

	return $result;
    }});


my $read_or_modify_user_bw_list = sub {
    my ($listname, $param, $addrs, $delete) = @_;

    my $rpcenv = PMG::RESTEnvironment->get();
    my $authuser = $rpcenv->get_user();
    my $role = $rpcenv->get_role();

    my $pmail = $verify_optional_pmail->($authuser, $role, $param->{pmail});

    my $dbh = PMG::DBTools::open_ruledb();

    my $list = PMG::Quarantine::add_to_blackwhite(
	$dbh, $pmail, $listname, $addrs, $delete);

    my $res = [];
    foreach my $a (@$list) { push @$res, { address => $a }; }
    return $res;
};

__PACKAGE__->register_method ({
    name => 'whitelist',
    path => 'whitelist',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    description => "Show user whitelist.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    pmail => $pmail_param_type,
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		address => {
		    type => "string",
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	return $read_or_modify_user_bw_list->('WL', $param);
    }});

__PACKAGE__->register_method ({
    name => 'whitelist_add',
    path => 'whitelist',
    method => 'POST',
    description => "Add user whitelist entries.",
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    pmail => $pmail_param_type,
	    address => get_standard_option('pmg-whiteblacklist-entry-list', {
		description => "The address you want to add.",
	    }),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $addresses = [split(',', $param->{address})];
	$read_or_modify_user_bw_list->('WL', $param, $addresses);

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'whitelist_delete_base',
    path => 'whitelist',
    method => 'DELETE',
    description => "Delete user whitelist entries.",
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    pmail => $pmail_param_type,
	    address => get_standard_option('pmg-whiteblacklist-entry-list', {
		pattern => '',
		description => "The address, or comma-separated list of addresses, you want to remove.",
	    }),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $addresses = [split(',', $param->{address})];
	$read_or_modify_user_bw_list->('WL', $param, $addresses, 1);

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'blacklist',
    path => 'blacklist',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    description => "Show user blacklist.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    pmail => $pmail_param_type,
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		address => {
		    type => "string",
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	return $read_or_modify_user_bw_list->('BL', $param);
    }});

__PACKAGE__->register_method ({
    name => 'blacklist_add',
    path => 'blacklist',
    method => 'POST',
    description => "Add user blacklist entries.",
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    pmail => $pmail_param_type,
	    address => get_standard_option('pmg-whiteblacklist-entry-list', {
		description => "The address you want to add.",
	    }),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $addresses = [split(',', $param->{address})];
	$read_or_modify_user_bw_list->('BL', $param, $addresses);

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'blacklist_delete_base',
    path => 'blacklist',
    method => 'DELETE',
    description => "Delete user blacklist entries.",
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    pmail => $pmail_param_type,
	    address => get_standard_option('pmg-whiteblacklist-entry-list', {
		pattern => '',
		description => "The address, or comma-separated list of addresses, you want to remove.",
	    }),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $addresses = [split(',', $param->{address})];
	$read_or_modify_user_bw_list->('BL', $param, $addresses, 1);

	return undef;
    }});


my $quar_type_map = {
    spam => 'S',
    attachment => 'A',
    virus => 'V',
};

__PACKAGE__->register_method ({
    name => 'spamusers',
    path => 'spamusers',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    description => "Get a list of receivers of spam in the given timespan (Default the last 24 hours).",
    parameters => {
	additionalProperties => 0,
	properties => {
	    starttime => get_standard_option('pmg-starttime'),
	    endtime => get_standard_option('pmg-endtime'),
	    'quarantine-type' => {
		description => 'Query this type of quarantine for users.',
		type => 'string',
		default => 'spam',
		optional => 1,
		enum => [keys $quar_type_map->%*],
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		mail => {
		    description => 'the receiving email',
		    type => 'string',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();

	my $res = [];

	my $dbh = PMG::DBTools::open_ruledb();

	my $start = $param->{starttime} // (time - 86400);
	my $end = $param->{endtime} // ($start + 86400);

	my $quar_type = $param->{'quarantine-type'} // 'spam';

	my $sth = $dbh->prepare(
	    "SELECT DISTINCT pmail " .
	    "FROM CMailStore, CMSReceivers WHERE " .
	    "time >= $start AND time < $end AND " .
	    "QType = ? AND CID = CMailStore_CID AND RID = CMailStore_RID " .
	    "AND Status = 'N' ORDER BY pmail");

	$sth->execute($quar_type_map->{$quar_type});

	while (my $ref = $sth->fetchrow_hashref()) {
	    push @$res, { mail => PMG::Utils::try_decode_utf8($ref->{pmail}) };
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'spamstatus',
    path => 'spamstatus',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    description => "Get Spam Quarantine Status",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => "object",
	properties => {
	    count => {
		description => 'Number of stored mails.',
		type => 'integer',
	    },
	    mbytes => {
		description => "Estimated disk space usage in MByte.",
		type => 'number',
	    },
	    avgbytes => {
		description => "Average size of stored mails in bytes.",
		type => 'number',
	    },
	    avgspam => {
		description => "Average spam level.",
		type => 'number',
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $dbh = PMG::DBTools::open_ruledb();
	my $ref =  PMG::DBTools::get_quarantine_count($dbh, 'S');

	return $ref;
    }});

__PACKAGE__->register_method ({
    name => 'quarusers',
    path => 'quarusers',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    description => "Get a list of users with whitelist/blacklist settings.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    list => {
		type => 'string',
		description => 'If set, limits the result to the given list.',
		enum => ['BL', 'WL'],
		optional => 1,
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		mail => {
		    description => 'the receiving email',
		    type => 'string',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $authuser = $rpcenv->get_user();

	my $res = [];

	my $dbh = PMG::DBTools::open_ruledb();

	my $sth;
	if ($param->{list}) {
	    $sth = $dbh->prepare("SELECT DISTINCT pmail FROM UserPrefs WHERE name = ? ORDER BY pmail");
	    $sth->execute($param->{list});
	} else {
	    $sth = $dbh->prepare("SELECT DISTINCT pmail FROM UserPrefs ORDER BY pmail");
	    $sth->execute();
	}

	while (my $ref = $sth->fetchrow_hashref()) {
	    push @$res, { mail => PMG::Utils::try_decode_utf8($ref->{pmail}) };
	}

	return $res;
    }});

my $quarantine_api = sub {
    my ($param, $quartype, $check_pmail) = @_;

    my $rpcenv = PMG::RESTEnvironment->get();
    my $authuser = $rpcenv->get_user();
    my $role = $rpcenv->get_role();

    my $start = $param->{starttime} // (time - 86400);
    my $end = $param->{endtime} // ($start + 86400);


    my $dbh = PMG::DBTools::open_ruledb();

    my $sth;
    my $pmail;
    if ($check_pmail || $role eq 'quser') {
	$pmail = $verify_optional_pmail->($authuser, $role, $param->{pmail});
	$sth = $dbh->prepare(
	    "SELECT * FROM CMailStore, CMSReceivers WHERE pmail = ?"
	    ." AND time >= $start AND time < $end AND QType = '$quartype' AND CID = CMailStore_CID"
	    ." AND RID = CMailStore_RID AND Status = 'N' ORDER BY pmail, time, receiver"
	);
    } else {
	$sth = $dbh->prepare(
	    "SELECT * FROM CMailStore, CMSReceivers WHERE time >= $start AND time < $end"
	    ." AND QType = '$quartype' AND CID = CMailStore_CID AND RID = CMailStore_RID"
	    ." AND Status = 'N' ORDER BY time, receiver"
	);
    }

    if ($check_pmail || $role eq 'quser') {
	$sth->execute(encode('UTF-8', $pmail));
    } else {
	$sth->execute();
    }

    my $res = [];
    while (my $ref = $sth->fetchrow_hashref()) {
	push @$res, $parse_header_info->($ref);
    }

    return $res;
};

__PACKAGE__->register_method ({
    name => 'spam',
    path => 'spam',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    description => "Get a list of quarantined spam mails in the given timeframe (default the last 24 hours) for the given user.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    starttime => get_standard_option('pmg-starttime'),
	    endtime => get_standard_option('pmg-endtime'),
	    pmail => $pmail_param_type,
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		id => {
		    description => 'Unique ID',
		    type => 'string',
		},
		bytes => {
		    description => "Size of raw email.",
		    type => 'integer' ,
		},
		envelope_sender => {
		    description => "SMTP envelope sender.",
		    type => 'string',
		},
		from => {
		    description => "Header 'From' field.",
		    type => 'string',
		},
		sender => {
		    description => "Header 'Sender' field.",
		    type => 'string',
		    optional => 1,
		},
		receiver => {
		    description => "Receiver email address",
		    type => 'string',
		},
		subject => {
		    description => "Header 'Subject' field.",
		    type => 'string',
		},
		time => {
		    description => "Receive time stamp",
		    type => 'integer',
		},
		spamlevel => {
		    description => "Spam score.",
		    type => 'number',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;
	return $quarantine_api->($param, 'S', defined($param->{pmail}));
    }});

__PACKAGE__->register_method ({
    name => 'virus',
    path => 'virus',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit' ] },
    description => "Get a list of quarantined virus mails in the given timeframe (default the last 24 hours).",
    parameters => {
	additionalProperties => 0,
	properties => {
	    starttime => get_standard_option('pmg-starttime'),
	    endtime => get_standard_option('pmg-endtime'),
	    pmail => $pmail_param_type,
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		id => {
		    description => 'Unique ID',
		    type => 'string',
		},
		bytes => {
		    description => "Size of raw email.",
		    type => 'integer' ,
		},
		envelope_sender => {
		    description => "SMTP envelope sender.",
		    type => 'string',
		},
		from => {
		    description => "Header 'From' field.",
		    type => 'string',
		},
		sender => {
		    description => "Header 'Sender' field.",
		    type => 'string',
		    optional => 1,
		},
		receiver => {
		    description => "Receiver email address",
		    type => 'string',
		},
		subject => {
		    description => "Header 'Subject' field.",
		    type => 'string',
		},
		time => {
		    description => "Receive time stamp",
		    type => 'integer',
		},
		virusname => {
		    description => "Virus name.",
		    type => 'string',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;
	return $quarantine_api->($param, 'V', defined($param->{pmail}));
    }});

__PACKAGE__->register_method ({
    name => 'attachment',
    path => 'attachment',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit' ] },
    description => "Get a list of quarantined attachment mails in the given timeframe (default the last 24 hours).",
    parameters => {
	additionalProperties => 0,
	properties => {
	    starttime => get_standard_option('pmg-starttime'),
	    endtime => get_standard_option('pmg-endtime'),
	    pmail => $pmail_param_type,
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		id => {
		    description => 'Unique ID',
		    type => 'string',
		},
		bytes => {
		    description => "Size of raw email.",
		    type => 'integer' ,
		},
		envelope_sender => {
		    description => "SMTP envelope sender.",
		    type => 'string',
		},
		from => {
		    description => "Header 'From' field.",
		    type => 'string',
		},
		sender => {
		    description => "Header 'Sender' field.",
		    type => 'string',
		    optional => 1,
		},
		receiver => {
		    description => "Receiver email address",
		    type => 'string',
		},
		subject => {
		    description => "Header 'Subject' field.",
		    type => 'string',
		},
		time => {
		    description => "Receive time stamp",
		    type => 'integer',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;
	return $quarantine_api->($param, 'A', defined($param->{pmail}));
    }});

__PACKAGE__->register_method ({
    name => 'virusstatus',
    path => 'virusstatus',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit'] },
    description => "Get Virus Quarantine Status",
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => "object",
	properties => {
	    count => {
		description => 'Number of stored mails.',
		type => 'integer',
	    },
	    mbytes => {
		description => "Estimated disk space usage in MByte.",
		type => 'number',
	    },
	    avgbytes => {
		description => "Average size of stored mails in bytes.",
		type => 'number',
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $dbh = PMG::DBTools::open_ruledb();
	my $ref = PMG::DBTools::get_quarantine_count($dbh, 'V');

	delete $ref->{avgspam};
	
	return $ref;
    }});

my $get_and_check_mail = sub {
    my ($id, $rpcenv, $dbh) = @_;

    my ($cid, $rid, $tid) = $id =~ m/^C(\d+)R(\d+)T(\d+)$/;
    ($cid, $rid, $tid) = (int($cid), int($rid), int($tid));

    $dbh = PMG::DBTools::open_ruledb() if !$dbh;

    my $ref = PMG::DBTools::load_mail_data($dbh, $cid, $rid, $tid);

    my $authuser = $rpcenv->get_user();
    my $role = $rpcenv->get_role();

    if ($role eq 'quser') {
	my $quar_username = $ref->{pmail} . '@quarantine';
	raise_perm_exc("mail does not belong to user '$authuser' ($ref->{pmail})")
	    if $authuser ne $quar_username;
    }

    return $ref;
};

__PACKAGE__->register_method ({
    name => 'content',
    path => 'content',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    description => "Get email data. There is a special formatter called 'htmlmail' to get sanitized html view of the mail content (use the '/api2/htmlmail/quarantine/content' url).",
    parameters => {
	additionalProperties => 0,
	properties => {
	    id => {
		description => 'Unique ID',
		type => 'string',
		pattern => 'C\d+R\d+T\d+',
		maxLength => 60,
	    },
	    raw => {
		description => "Display 'raw' eml data. Deactivates size limit.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
		id => {
		    description => 'Unique ID',
		    type => 'string',
		},
		bytes => {
		    description => "Size of raw email.",
		    type => 'integer' ,
		},
		envelope_sender => {
		    description => "SMTP envelope sender.",
		    type => 'string',
		},
		from => {
		    description => "Header 'From' field.",
		    type => 'string',
		},
		sender => {
		    description => "Header 'Sender' field.",
		    type => 'string',
		    optional => 1,
		},
		receiver => {
		    description => "Receiver email address",
		    type => 'string',
		},
		subject => {
		    description => "Header 'Subject' field.",
		    type => 'string',
		},
		time => {
		    description => "Receive time stamp",
		    type => 'integer',
		},
		spamlevel => {
		    description => "Spam score.",
		    type => 'number',
		},
		spaminfo => {
		    description => "Information about matched spam tests (name, score, desc, url).",
		    type => 'array',
		},
		header => {
		    description => "Raw email header data.",
		    type => 'string',
		},
		content => {
		    description => "Raw email data (first 4096 bytes). Useful for preview. NOTE: The  'htmlmail' formatter displays the whole email.",
		    type => 'string',
		},
	},
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $format = $rpcenv->get_format();

	my $raw = $param->{raw} // 0;

	my $ref = $get_and_check_mail->($param->{id}, $rpcenv);

	my $res = $parse_header_info->($ref);

	my $filename = $ref->{file};
	my $spooldir = $PMG::MailQueue::spooldir;

	my $path = "$spooldir/$filename";

	if ($format eq 'htmlmail') {

	    my $cfg = PMG::Config->new();
	    my $viewimages = $cfg->get('spamquar', 'viewimages');
	    my $allowhref = $cfg->get('spamquar', 'allowhrefs');

	    $res->{content} = PMG::HTMLMail::email_to_html($path, $raw, $viewimages, $allowhref) // 'unable to parse mail';

	    # to make result verification happy
	    $res->{file} = '';
	    $res->{header} = '';
	    $res->{spamlevel} = 0;
	    $res->{spaminfo} = [];
	} else {
	    # include additional details

	    # we want to get the whole email in raw mode
	    my $maxbytes = (!$raw)? 4096 : undef;

	    my ($header, $content) = PMG::HTMLMail::read_raw_email($path, $maxbytes);

	    $res->{file} = $ref->{file};
	    $res->{spaminfo} = decode_spaminfo($ref->{info});
	    $res->{header} = $header;
	    $res->{content} = $content;
	}

	return $res;

    }});

my $get_attachments = sub {
    my ($mailid, $dumpdir, $with_path) = @_;

    my $rpcenv = PMG::RESTEnvironment->get();

    my $ref = $get_and_check_mail->($mailid, $rpcenv);

    my $filename = $ref->{file};
    my $spooldir = $PMG::MailQueue::spooldir;

    my $parser = PMG::MIMEUtils::new_mime_parser({
	nested => 1,
	decode_bodies => 0,
	extract_uuencode => 0,
	dumpdir => $dumpdir,
    });

    my $entity = $parser->parse_open("$spooldir/$filename");
    PMG::MIMEUtils::fixup_multipart($entity);
    PMG::MailQueue::decode_entities($parser, 'attachmentquarantine', $entity);

    my $res = [];
    my $id = 0;

    PMG::MIMEUtils::traverse_mime_parts($entity, sub {
	my ($part) = @_;
	my $name = PMG::Utils::extract_filename($part->head) || "part-$id";
	my $attachment_path = $part->{PMX_decoded_path};
	return if !$attachment_path || ! -f $attachment_path;
	my $size = -s $attachment_path // 0;
	my $entry = {
	    id => $id,
	    name => $name,
	    size => $size,
	    'content-disposition' => $part->head->mime_attr('content-disposition'),
	    'content-type' => $part->head->mime_attr('content-type'),
	};
	$entry->{path} = $attachment_path if $with_path;
	push @$res, $entry;
	$id++;
    });

    return $res;
};

__PACKAGE__->register_method ({
    name => 'listattachments',
    path => 'listattachments',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    description => "Get Attachments for E-Mail in Quarantine.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    id => {
		description => 'Unique ID',
		type => 'string',
		pattern => 'C\d+R\d+T\d+',
		maxLength => 60,
	    },
	},
    },
    returns => {
	type => "array",
	items => {
	    type => "object",
	    properties => {
		id => {
		    description => 'Attachment ID',
		    type => 'integer',
		},
		size => {
		    description => "Size of raw attachment in bytes.",
		    type => 'integer' ,
		},
		name => {
		    description => "Raw email header data.",
		    type => 'string',
		},
		'content-type' => {
		    description => "Raw email header data.",
		    type => 'string',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $dumpdir = "/run/pmgproxy/pmg-$param->{id}-$$";
	my $res = $get_attachments->($param->{id}, $dumpdir);
	rmtree $dumpdir;

	return $res;

    }});

__PACKAGE__->register_method ({
    name => 'download',
    path => 'download',
    method => 'GET',
    permissions => { check => [ 'admin', 'qmanager', 'audit', 'quser'] },
    description => "Download E-Mail or Attachment from Quarantine.",
    download => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    mailid => {
		description => 'Unique ID',
		type => 'string',
		pattern => 'C\d+R\d+T\d+',
		maxLength => 60,
	    },
	    attachmentid => {
		description => "The Attachment ID for the mail.",
		type => 'integer',
		optional => 1,
	    },
	},
    },
    returns => {
	type => "object",
    },
    code => sub {
	my ($param) = @_;

	my $mailid = $param->{mailid};
	my $attachmentid = $param->{attachmentid};

	my $dumpdir = "/run/pmgproxy/pmg-$mailid-$$/";
	my $res;

	if ($attachmentid) {
	    my $attachments = $get_attachments->($mailid, $dumpdir, 1);
	    $res = $attachments->[$attachmentid];
	    if (!$res) {
		raise_param_exc({ attachmentid => "Invalid Attachment ID for Mail."});
	    }
	} else {
	    my $rpcenv = PMG::RESTEnvironment->get();
	    my $ref = $get_and_check_mail->($mailid, $rpcenv);
	    my $spooldir = $PMG::MailQueue::spooldir;

	    $res = {
		'content-type' => 'message/rfc822',
		path => "$spooldir/$ref->{file}",
	    };
	}

	$res->{fh} = IO::File->new($res->{path}, '<') ||
	    die "unable to open file '$res->{path}' - $!\n";

	rmtree $dumpdir if -e $dumpdir;

	return $res;

    }});

PVE::APIServer::Formatter::register_page_formatter(
    'format' => 'htmlmail',
    method => 'GET',
    path => '/quarantine/content',
    code => sub {
        my ($res, $data, $param, $path, $auth, $config) = @_;

	if(!HTTP::Status::is_success($res->{status})) {
	    return ("Error $res->{status}: $res->{message}", "text/plain");
	}

	my $ct = "text/html;charset=UTF-8";

	my $raw = $data->{content};

	return (encode('UTF-8', $raw), $ct, 1);
});

__PACKAGE__->register_method ({
    name =>'action',
    path => 'content',
    method => 'POST',
    description => "Execute quarantine actions.",
    permissions => { check => [ 'admin', 'qmanager', 'quser'] },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    id => {
		description => 'Unique IDs, separate with ;',
		type => 'string',
		pattern => 'C\d+R\d+T\d+(;C\d+R\d+T\d+)*',
	    },
	    action => {
		description => 'Action - specify what you want to do with the mail.',
		type => 'string',
		enum => ['whitelist', 'blacklist', 'deliver', 'delete'],
	    },
	},
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PMG::RESTEnvironment->get();
	my $action = $param->{action};
	my @idlist = split(';', $param->{id});

	my $dbh = PMG::DBTools::open_ruledb();

	for my $id (@idlist) {

	    my $ref = $get_and_check_mail->($id, $rpcenv, $dbh);
	    my $sender = try_decode_utf8($get_real_sender->($ref));
	    my $pmail = try_decode_utf8($ref->{pmail});
	    my $receiver = try_decode_utf8($ref->{receiver} // $ref->{pmail});

	    if ($action eq 'whitelist') {
		PMG::Quarantine::add_to_blackwhite($dbh, $pmail, 'WL', [ $sender ]);
		PMG::Quarantine::deliver_quarantined_mail($dbh, $ref, $receiver);
	    } elsif ($action eq 'blacklist') {
		PMG::Quarantine::add_to_blackwhite($dbh, $pmail, 'BL', [ $sender ]);
		PMG::Quarantine::delete_quarantined_mail($dbh, $ref);
	    } elsif ($action eq 'deliver') {
		PMG::Quarantine::deliver_quarantined_mail($dbh, $ref, $receiver);
	    } elsif ($action eq 'delete') {
		PMG::Quarantine::delete_quarantined_mail($dbh, $ref);
	    } else {
		die "internal error, unknown action '$action'"; # should not be reached
	    }
	}

	return undef;
    }});

my $link_map_fn = "/run/pmgproxy/quarantinelink.map";
my $per_user_limit = 60*60; # 1 hour

my sub send_link_mail {
    my ($cfg, $receiver) = @_;

    my $hostname = PVE::INotify::nodename();
    my $fqdn = $cfg->get('spamquar', 'hostname') //
    PVE::Tools::get_fqdn($hostname);

    my $port = $cfg->get('spamquar', 'port') // 8006;

    my $protocol = $cfg->get('spamquar', 'protocol') // 'https';

    my $protocol_fqdn_port = "$protocol://$fqdn";
    if (($protocol eq 'https' && $port != 443) ||
	($protocol eq 'http' && $port != 80)) {
	$protocol_fqdn_port .= ":$port";
    }

    my $mailfrom = $cfg->get ('spamquar', 'mailfrom') //
    "Proxmox Mail Gateway <postmaster>";

    my $ticket = PMG::Ticket::assemble_quarantine_ticket($receiver);
    my $esc_ticket = uri_escape($ticket);
    my $link = "$protocol_fqdn_port/quarantine?ticket=${esc_ticket}";

    my $text = "Here is your Link for the Spam Quarantine on $fqdn:\n\n$link\n";

    my $mail = MIME::Entity->build(
	Type    => "text/plain",
	To      => $receiver,
	From    => $mailfrom,
	Subject => "Proxmox Mail Gateway - Quarantine Link",
	Data    => $text,
    );

    # we use an empty envelope sender (we don't want to receive NDRs)
    PMG::Utils::reinject_local_mail ($mail, '', [$receiver], undef, $fqdn);
}

__PACKAGE__->register_method ({
    name =>'sendlink',
    path => 'sendlink',
    method => 'POST',
    description => "Send Quarantine link to given e-mail.",
    permissions => { user => 'world' },
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {
	    mail => get_standard_option('pmg-email-address'),
	},
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	my $starttime = time();

	my $cfg = PMG::Config->new();
	my $is_enabled = $cfg->get('spamquar', 'quarantinelink');
	if (!$is_enabled) {
	    die "This feature is not enabled\n";
	}

	my $stat = File::stat::stat($link_map_fn);

	if (defined($stat) && ($stat->mtime + 5) > $starttime) {
	    sleep(3);
	    die "Too many requests. Please try again later\n";
	}

	my $domains = PVE::INotify::read_file('domains');
	my $domainregex = PMG::Utils::domain_regex([keys %$domains]);

	my $receiver = $param->{mail};

	if ($receiver !~ $domainregex) {
	    sleep(3);
	    return undef; # silently ignore invalid mails
	}

	PVE::Tools::lock_file_full("${link_map_fn}.lck", 10, 1, sub {
	    return if !-f $link_map_fn;
	    # check if user is allowed to request mail
	    my $data = PVE::Tools::file_get_contents($link_map_fn);
	    for my $line (split("\n", $data)) {
		next if $line !~ m/^\Q$receiver\E (\d+)$/;
		if (($1 + $per_user_limit) > $starttime) {
		    sleep(3);
		    die "Too many requests for '$receiver', only one request per"
		        ."hour is permitted. Please try again later\n";
		} else {
		    last;
		}
	    }
	});
	die $@ if $@;

	# we are allowed to send mail, lock and update file and send
	PVE::Tools::lock_file("${link_map_fn}.lck", 10, sub {
	    my $newdata = "$receiver $starttime\n";

	    if (-f $link_map_fn) {
		my $data = PVE::Tools::file_get_contents($link_map_fn);
		for my $line (split("\n", $data)) {
		    if ($line =~ m/^(?:.*) (\d+)$/) {
			if (($1 + $per_user_limit) > $starttime) {
			    $newdata .= $line . "\n";
			}
		    }
		}
	    }
	    PVE::Tools::file_set_contents($link_map_fn, $newdata);
	});
	die $@ if $@;

	send_link_mail($cfg, $receiver);
	sleep(1); # always delay for a bit

	return undef;
    }});

1;
