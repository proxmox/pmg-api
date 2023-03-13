package PMG::RuleDB::Spam;

use strict;
use warnings;
use DBI;
use Digest::SHA;
use Encode qw(encode);
use Time::HiRes qw (gettimeofday);

use PVE::SafeSyslog;
use Mail::SpamAssassin;

use PMG::Utils;
use PMG::RuleDB::Object;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 3000;
}

sub oclass {
    return 'what';
}

sub otype_text {
    return 'Spam Filter';
}

sub new {
    my ($type, $level, $ogroup) = @_;
    
    my $class = ref($type) || $type;

    my $self = $class->SUPER::new($class->otype(), $ogroup);

    $level = 5 if !defined ($level);

    $self->{level} = $level;
    
    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;
    
    my $class = ref($type) || $type;

    defined($value) || die "undefined value: ERROR";

    my $obj = $class->new($value, $ogroup);
    $obj->{id} = $id;
    
    $obj->{digest} = Digest::SHA::sha1_hex($id, $value, $ogroup);

    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || die "undefined ogroup: ERROR";
    defined($self->{level}) || die "undefined spam level: ERROR";

    if (defined ($self->{id})) {
	# update
	
	$ruledb->{dbh}->do(
	    "UPDATE Object SET Value = ? WHERE ID = ?", 
	    undef, $self->{level}, $self->{id});

    } else {
	# insert

	my $sth = $ruledb->{dbh}->prepare(
	    "INSERT INTO Object (Objectgroup_ID, ObjectType, Value) " .
	    "VALUES (?, ?, ?);");

	$sth->execute($self->ogroup, $self->otype, $self->{level});
    
	$self->{id} = PMG::Utils::lastid ($ruledb->{dbh}, 'object_id_seq'); 
    }
	
    return $self->{id};
}

sub parse_addrlist {
    my ($list) = @_;

    my $adlist = {};

    foreach my $addr (split ('\s*,\s*', $list)) {
	$addr = lc $addr;
	my $regex = $addr;
	# SA like checks
	$regex =~ s/[\000\\\(]/_/gs;		# is this really necessasry ?
	$regex =~ s/([^\*\?_\w])/\\$1/g;	# escape possible metachars
	$regex =~ tr/?/./;			# replace "?" with "."
	$regex =~ s/\*+/\.\*/g;			# replace "*" with  ".*"

	# we use a hash for extra fast testing
	$adlist->{$addr} = "^${regex}\$";
    }

    return $adlist;
}

sub check_addrlist {
    my ($list, $addrlst) = @_;

    foreach my $addr (@$addrlst) {

	$addr = lc $addr;

	return 1 if defined ($list->{$addr});

	study $addr;

	foreach my $r (values %{$list}) {
	    if ($addr =~ qr/$r/i) {
		return 1;
	    }
	}
    }

    return 0;
}

sub get_blackwhite {
    my ($dbh, $entity, $msginfo) = @_;

    my $target_info = {};

    my $targets = $msginfo->{targets};

    my $cond = '';
    foreach my $r (@$targets) {
	my $pmail = $msginfo->{pmail}->{$r} || lc ($r);
	my $qr = $dbh->quote (encode('UTF-8', $pmail));
	$cond .= " OR " if $cond;
	$cond .= "pmail = $qr";
    }	 

    eval {
	my $query = "SELECT * FROM UserPrefs WHERE " .
	    "($cond) AND (Name = 'BL' OR Name = 'WL')";
	my $sth = $dbh->prepare($query);

	$sth->execute();

	while (my $ref = $sth->fetchrow_hashref()) {
	    my $pmail = lc (PMG::Utils::try_decode_utf8($ref->{pmail}));
	    if ($ref->{name} eq 'WL') {
		$target_info->{$pmail}->{whitelist} = 
		    parse_addrlist(PMG::Utils::try_decode_utf8($ref->{data}));
	    } elsif ($ref->{name} eq 'BL') {
		$target_info->{$pmail}->{blacklist} = 
		    parse_addrlist(PMG::Utils::try_decode_utf8($ref->{data}));
	    }
	}

	$sth->finish;
    };
    if (my $err = $@) {
	syslog('err', $err);
    }
    
    return $target_info;
}

sub what_match_targets {
    my ($self, $queue, $entity, $msginfo, $dbh) = @_;

    my $target_info;

    if (!$queue->{spam_analyzed}) {
	$self->analyze_spam($queue, $entity, $msginfo);
	$queue->{blackwhite} = get_blackwhite($dbh, $entity, $msginfo);
	$queue->{spam_analyzed} = 1;
    }

    if ($msginfo->{testmode}) {
	$queue->{sa_score} = 100 if $queue->{sa_score} > 100;
	my $data;
	foreach my $s (@{$queue->{sa_data}}) {
	    next if $s->{rule} eq 'AWL';
	    push @$data, $s;
	}
	$queue->{sa_data} = $data;
    }
    
    if (defined($queue->{sa_score}) && $queue->{sa_score} >= $self->{level}) {

	my $info = {
	    sa_score => $queue->{sa_score},
	    sa_max => $self->{level},
	    sa_data => $queue->{sa_data},
	    sa_hits => $queue->{sa_hits}
	};

	foreach my $t (@{$msginfo->{targets}}) {
	    my $list;
	    my $pmail = $msginfo->{pmail}->{$t} || $t;
	    if ($queue->{blackwhite}->{$pmail} && 
		($list = $queue->{blackwhite}->{$pmail}->{whitelist}) &&
		check_addrlist($list, $queue->{all_from_addrs})) {
		syslog('info', "%s: sender in user (%s) welcomelist",
		       $queue->{logid}, encode('UTF-8', $pmail));
	    } else {
		$target_info->{$t}->{marks} = []; # never add additional marks here
		$target_info->{$t}->{spaminfo} = $info;
	    }
	}

    } else {

	foreach my $t (@{$msginfo->{targets}}) {
	    my $info = {
		sa_score => 100,
		sa_max => $self->{level},
		sa_data => [{
		    rule => 'USER_IN_BLOCKLIST',
		    score => 100,
		    desc => PMG::Utils::user_bl_description(),
		}],
		sa_hits => 'USER_IN_BLOCKLIST',
	    };

	    my $list;
	    my $pmail = $msginfo->{pmail}->{$t} || $t;
	    if ($queue->{blackwhite}->{$pmail} && 
		($list = $queue->{blackwhite}->{$pmail}->{blacklist}) &&
		check_addrlist($list, $queue->{all_from_addrs})) {
		$target_info->{$t}->{marks} = [];
		$target_info->{$t}->{spaminfo} = $info;
		syslog ('info', "%s: sender in user (%s) blocklist",
			$queue->{logid}, encode('UTF-8',$pmail));
	    }
	}
    }

    return $target_info;
}

sub level { 
    my ($self, $v) = @_; 

    if (defined ($v)) {
	$self->{level} = $v;
    }

    $self->{level}; 
}

sub short_desc {
    my $self = shift;
    
    return "Level $self->{level}";
}

sub __get_addr {
    my ($head, $name) = @_;

    my $result = $head->get($name);

    return '' if !$result;

    # copied from Mail::Spamassassin:PerMsgStatus _get()

    $result =~ s/^[^:]+:(.*);\s*$/$1/gs;	# 'undisclosed-recipients: ;'
    $result =~ s/\s+/ /g;			# reduce whitespace
    $result =~ s/^\s+//;			# leading whitespace
    $result =~ s/\s+$//;			# trailing whitespace

    # Get the email address out of the header
    # All of these should result in "jm@foo":
    # jm@foo
    # jm@foo (Foo Blah)
    # jm@foo, jm@bar
    # display: jm@foo (Foo Blah), jm@bar ;
    # Foo Blah <jm@foo>
    # "Foo Blah" <jm@foo>
    # "'Foo Blah'" <jm@foo>
    #
    # strip out the (comments)
    $result =~ s/\s*\(.*?\)//g;
    # strip out the "quoted text", unless it's the only thing in the string
    if ($result !~ /^".*"$/) {
        $result =~ s/(?<!<)"[^"]*"(?!@)//g;   #" emacs
    }
    # Foo Blah <jm@xxx> or <jm@xxx>
    $result =~ s/^[^"<]*?<(.*?)>.*$/$1/;
    # multiple addresses on one line? remove all but first
    $result =~ s/,.*$//;

    return $result;
}

# implement our own all_from_addrs()
# because we do not call spamassassin in canes of commtouch match
# see Mail::Spamassassin:PerMsgStatus for details
sub __all_from_addrs {
    my ($head, $spamtest) = @_;

    my @addrs;

    my $resent = $head->get('Resent-From');
    if (defined($resent) && $resent =~ /\S/) {
	@addrs = $spamtest->find_all_addrs_in_line($resent);
    } else {
	@addrs = map { tr/././s; $_ } grep { $_ ne '' }
        (__get_addr($head, 'From'),		# std
         __get_addr($head, 'Envelope-Sender'),	# qmail: new-inject(1)
         __get_addr($head, 'Resent-Sender'),	# procmailrc manpage
         __get_addr($head, 'X-Envelope-From'),	# procmailrc manpage
         __get_addr($head, 'EnvelopeFrom'));	# SMTP envelope
    }

    # Remove duplicate addresses
    my %addrs = map { $_ => 1 } @addrs;
    @addrs = keys %addrs;

    return @addrs;
}

sub analyze_spam {
    my ($self, $queue, $entity, $msginfo) = @_;

    my $maxspamsize = $msginfo->{maxspamsize};

    $maxspamsize = 200*1024 if !$maxspamsize;

    my $spamtest = $queue->{sa};

    my ($sa_score, $sa_max, $sa_scores, $sa_sumary, $list, $autolearn, $bayes, $loglist);
    $list = '';
    $loglist = '';
    $bayes = 'undefined';
    $autolearn = 'no';
    $sa_score = 0;
    $sa_max = 5;

    # do not run SA if license is not valid
    if (!$queue->{lic_valid}) {
	$queue->{sa_score} = 0;
	return 0;
    }

    my $fromhash = { $queue->{from} => 1 }; 
    foreach my $f (__all_from_addrs($entity->head(), $spamtest)) {
	$fromhash->{$f} = 1;
    }
    $queue->{all_from_addrs} = [ keys %$fromhash ];

    if (my $hit = $queue->{clamav_heuristic}) {
	my $score = $queue->{clamav_heuristic_score};
	my $descr = "ClamAV heuristic test: $hit";
	my $rule = 'ClamAVHeuristics';
	$sa_score += $score;
	$list .= $list ? ",$rule" : $rule;
	$loglist .= $loglist ? ",$rule($score)" : "$rule($score)";
	push @$sa_scores, { score => $score, rule => $rule, desc => $descr };
    }

    if (my $hit = $queue->{spam_custom}) {
	my $score += $queue->{spam_custom};
	my $descr = "Custom Check Script";
	my $rule = 'CustomCheck';
	$sa_score += $score;
	$list .= $list ? ",$rule" : $rule;
	$list .= $list ? ",$rule" : $rule;
	$loglist .= $loglist ? ",$rule($score)" : "$rule($score)";
	push @$sa_scores, { score => $score, rule => $rule, desc => $descr };
    }

    my ($csec, $usec) = gettimeofday ();

    # only run SA in testmode or when clamav_heuristic did not confirm spam (score < 5)
    if ($msginfo->{testmode} || ($sa_score < 5)) {

	# save and disable alarm (SA forgets to clear alarm in some cases) 
	my $previous_alarm = alarm (0);

	my $pid = $$;

	eval {
	    $queue->{fh}->seek(0, 0);

	    # Truncate message to $maxspamsize
	    # Note: similar code to read content is used inside
	    # Mail::SpamAssassin::Message->new()
	    my $nread;
	    my $raw_str = '';
	    while ($nread = sysread($queue->{fh}, $raw_str, 16384, length($raw_str))) {
		last if length($raw_str) >= $maxspamsize;
	    }
	    defined($nread) || die "error reading message: $!\n";

	    my $suppl_attrib = {};
	    if (length($raw_str) >= $maxspamsize &&
		length($raw_str) < $queue->{bytes}) {
		$suppl_attrib->{body_size} = $queue->{bytes};
	    }

	    my @message = split(/^/m, $raw_str, -1);
	    undef $raw_str; # free memory early

	    my $mail = $spamtest->parse(\@message, 0, $suppl_attrib);

	    # hack: pass envelope sender to spamassassin
	    $mail->header('X-Proxmox-Envelope-From', $queue->{from});

	    my $status = $spamtest->check($mail);

	    #my $fromhash = { $queue->{from} => 1 }; 
	    #foreach my $f ($status->all_from_addrs()) {
	    #$fromhash->{$f} = 1;
	    #}
	    #$queue->{all_from_addrs} = [ keys %$fromhash ];

	    $sa_score += $status->get_score();
	    $sa_max = $status->get_required_score();
	    $autolearn = $status->get_autolearn_status();

	    $bayes = defined($status->{bayes_score}) ?
		sprintf('%0.2f', $status->{bayes_score}) : "undefined";

	    my $salist = $status->get_names_of_tests_hit();

	    foreach my $rule (split (/,/, $salist)) {
		$list .= $list ? ",$rule" : $rule;
		my $score = $status->{conf}->{scores}->{$rule};
		$loglist .= $loglist ? ",$rule($score)" : "$rule($score)";
		my $desc = $status->{conf}->get_description_for_rule($rule);
		if (my $hits = $status->{uridnsbl_hits}->{$rule}) {
		    $desc .= ' [' . join(',', keys %$hits) . ']';
		}
		push @$sa_scores, { score => $score, rule => $rule, desc => $desc };
	    }

	    $status->finish();
	    $mail->finish();	

	    alarm 0; # avoid race conditions
	};
	my $err = $@;
	
	alarm ($previous_alarm);
	
	# just to be sure - exit if SA produces a child process
	if ($$ != $pid) {
	    syslog ('err', "WARNING: detected SA produced process - exiting");
	    POSIX::_exit (-1);  # exit immediately
	}
     
	if ($err) {
	    syslog('err', $err);
	    $queue->{errors} = 1;
	}
    }

    $sa_score = int ($sa_score);
    $sa_score = 0 if $sa_score < 0;

    my ($csec_end, $usec_end) = gettimeofday();
    $queue->{ptime_spam} = 
	int (($csec_end-$csec)*1000 + ($usec_end - $usec)/1000);

    syslog ('info', "%s: SA score=%s/%s time=%0.3f bayes=%s autolearn=%s hits=%s", 
	    $queue->{logid}, $sa_score, $sa_max, $queue->{ptime_spam}/1000.0, 
	    $bayes, $autolearn, $loglist);

    $queue->{sa_score} = $sa_score;
    $queue->{sa_max} = $sa_max;
    $queue->{sa_data} = $sa_scores;
    $queue->{sa_hits} = $list;

    return ($sa_score >= $sa_max);
}

sub properties {
    my ($class) = @_;

    return {
	spamlevel => {
	    description => "Spam Level",
	    type => 'integer',
	    minimum => 0,
	},
    };
}

sub get {
    my ($self) = @_;

    return { spamlevel => $self->{level} };
}

sub update {
    my ($self, $param) = @_;

    $self->{level} = $param->{spamlevel};
}

1;

__END__

=head1 PVE::RuleDB::Spam

Spam level filter
