package PMG::RuleDB::Remove;

use strict;
use warnings;
use DBI;
use Digest::SHA;
use MIME::Words;
use MIME::Entity;
use Encode;

use PVE::SafeSyslog;

use PMG::Utils;
use PMG::ModGroup;
use PMG::RuleDB::Object;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 4007;
}

sub otype_text {
    return 'Remove attachments';
}

sub oclass {
    return 'action';
}

sub oisedit {
    return 1;
}

sub final {
    return 0;
}

sub priority {
    return 40;
}

sub new {
    my ($type, $all, $text, $ogroup, $quarantine) = @_;

    my $class = ref($type) || $type;

    $all = 0 if !defined ($all);

    my $self = $class->SUPER::new($class->otype(), $ogroup);

    $self->{all} = $all;
    $self->{text} = $text;
    $self->{quarantine} = $quarantine;

    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;

    my $class = ref($type) || $type;

    defined ($value) || die "undefined value: ERROR";

    my ($obj, $text);

    if ($value =~ m/^([01])\,([01])(\:(.*))?$/s) {
	$text = PMG::Utils::try_decode_utf8($4);
	$obj = $class->new($1, $text, $ogroup, $2);
    } elsif ($value =~ m/^([01])(\:(.*))?$/s) {
	$text = PMG::Utils::try_decode_utf8($3);
	$obj = $class->new($1, $text, $ogroup);
    } else {
	$obj = $class->new(0, undef, $ogroup);
    }

    $obj->{id} = $id;

    $obj->{digest} = Digest::SHA::sha1_hex($id, $value, $ogroup);

    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || die "undefined ogroup: ERROR";

    my $value = $self->{all} ? '1' : '0';
    $value .= ','. ($self->{quarantine} ? '1' : '0');

    if ($self->{text}) {
	$value .= encode('UTF-8', ":$self->{text}");
    }

    if (defined ($self->{id})) {
	# update

	$ruledb->{dbh}->do(
	    "UPDATE Object SET Value = ? WHERE ID = ?",
	    undef, $value, $self->{id});

    } else {
	# insert

	my $sth = $ruledb->{dbh}->prepare(
	    "INSERT INTO Object (Objectgroup_ID, ObjectType, Value) " .
	    "VALUES (?, ?, ?);");

	$sth->execute($self->ogroup, $self->otype, $value);

	$self->{id} = PMG::Utils::lastid($ruledb->{dbh}, 'object_id_seq');
    }

    return $self->{id};
}

sub delete_marked_parts {
    my ($self, $queue, $entity, $html, $rtype, $marks, $rulename) = @_;

    my $nparts = [];

    my $ctype = $entity->head->mime_type;
    my $pn = $entity->parts;
    for (my $i = 0; $i < $pn; $i++) {
	my $part = $entity->parts($i);

	my ($id, $found);

	if ($id = $part->head->mime_attr('x-proxmox-tmp-aid')) {
	    chomp $id;

	    if ($self->{all}) {
		my $ctype_part = $part->head->mime_type;
		if ($self->{message_seen}) {
		    $found = 1;
		} else {
		    if ($ctype =~ m|multipart/alternative|i) {
			if ($ctype_part !~ m{text/(?:plain|html)}i) {
			    $found = 1 ;
			}

			if ($i == ($pn-1)) {
			    # we have not seen the message and it is the
			    # end of the first multipart/alternative, mark as message seen
			    $self->{message_seen} = 1;
			}
		    } else {
			if ($ctype_part =~ m{text/(?:plain|html)}i) {
			    $self->{message_seen} = 1;
			} elsif ($ctype_part !~ m|multipart/|i) {
			    $found = 1 ;
			}
		    }
		}
	    } else {
		foreach my $m (@$marks) {
		    $found = 1 if $m eq $id;
		}
	    }

	}

	if ($found) {

	    my $on = PMG::Utils::extract_filename($part->head) || '';

	    my $text = PMG::Utils::subst_values($html, { FILENAME => $on } );

	    my $fname = "REMOVED_ATTACHMENT_$id." . ($rtype eq "text/html" ? "html" : "txt");

	    my $ent = MIME::Entity->build(
		Type        => $rtype,
		Charset     => 'UTF-8',
		Encoding    => "quoted-printable",
		Filename    => $fname,
		Disposition => "attachment",
		Data        => encode('UTF-8', $text));

	    push (@$nparts, $ent);

	    syslog ('info', "%s: removed attachment $id ('%s', rule: %s)",
		    $queue->{logid}, $on, $rulename);

	} else {
	    $self->delete_marked_parts($queue, $part, $html, $rtype, $marks, $rulename);
	    push (@$nparts, $part);
	}
    }

    $entity->parts ($nparts);
}

sub execute {
    my ($self, $queue, $ruledb, $mod_group, $targets,
	$msginfo, $vars, $marks, $ldap) = @_;

    my $rulename = encode('UTF-8', $vars->{RULE} // 'unknown');

    if (!$self->{all}) {
	my $found_mark = 0;
	for my $target (keys $marks->%*) {
	    if (scalar($marks->{$target}->@*) > 0) {
		$found_mark = 1;
		last;
	    }
	}
	return if !$found_mark;
    }

    my $subgroups;
    if ($marks->{spaminfo}) {
	# when there was a spam check in the rule, we might have different marks for
	# different targets, so simply copy the mail for each target that matches
	$subgroups = $mod_group->explode($targets);
    } else {
	$subgroups = $mod_group->subgroups ($targets);
    }

    my $html = PMG::Utils::subst_values($self->{text}, $vars);

    if (!$html) {
	$html = "This attachment was removed: __FILENAME__\n";
	$html .= "It was put into the Attachment Quarantine, please contact your Administrator\n" if $self->{quarantine};
    }

    my $rtype = "text/plain";

    if ($html =~ m/\<\w+\>/s) {
	$rtype = "text/html";
    }

    foreach my $ta (@$subgroups) {
	my ($tg, $entity) = (@$ta[0], @$ta[1]);

	# copy original entity to attachment quarantine if configured
	if ($self->{quarantine}) {
	    my $original_entity = $entity->dup;
	    PMG::Utils::remove_marks($original_entity);
	    if (my $qid = $queue->quarantine_mail($ruledb, 'A', $original_entity, $tg, $msginfo, $vars, $ldap)) {
		# adapt the Message-ID header of the mail without attachment to
		# prevent 2 different mails with the same Message-ID
		my $message_id = $entity->head->get('Message-ID');
		if (defined($message_id)) {
		    $message_id =~ s/^(<?)(.+)(>?)$/$1pmg-aquar-$$-$2$3/;
		    $entity->head->replace('Message-ID', $message_id);
		}

		foreach (@$tg) {
		    syslog (
			'info',
			"$queue->{logid}: moved mail for <%s> to attachment quarantine - %s (rule: %s)",
			encode('UTF-8',$_),
			$qid,
			$rulename,
		    );
		}
	    }
	}

	# handle singlepart mails
	my $ctype = $entity->head->mime_type;
	if (!$entity->is_multipart && (!$self->{all} || $ctype !~ m|text/.*|i)) {
	    $entity->make_multipart();
	    my $first_part = $entity->parts(0);
	    $first_part->head->mime_attr('x-proxmox-tmp-aid' => $entity->head->mime_attr('x-proxmox-tmp-aid'));
	    $entity->head->delete('x-proxmox-tmp-aid');
	}

	$self->{message_seen} = 0;

	# if we only had a spam/virus check, the marks are identical
	# otherwise we get a subgroup per target anyway
	my $match_marks = $marks->{$tg->[0]};

	$self->delete_marked_parts($queue, $entity, $html, $rtype, $match_marks, $rulename);
	delete $self->{message_seen};

	if ($msginfo->{testmode}) {
	    $entity->head->mime_attr('Content-type.boundary' => '------=_TEST123456') if $entity->is_multipart;
	}
    }
}

sub short_desc {
    my $self = shift;

    if ($self->{all}) {
	return "remove all attachments";
    } else {
	return "remove matching attachments";
    }
}

sub properties {
    my ($class) = @_;

    return {
	all => {
	    description => "Remove all attachments",
	    type => 'boolean',
	    optional => 1,
	},
	quarantine => {
	    description => "Copy original mail to attachment Quarantine.",
	    type => 'boolean',
	    default => 0,
	    optional => 1,
	},
	text => {
	    description => "The replacement text.",
	    type => 'string',
	    maxLength => 2048
	}
    };
}

sub get {
    my ($self) = @_;

    return {
	text => $self->{text},
	all => $self->{all},
	quarantine => $self->{quarantine},
    };
}

sub update {
    my ($self, $param) = @_;

    $self->{text} = $param->{text};
    $self->{all} = $param->{all} ? 1 : 0;
    $self->{quarantine} = $param->{quarantine} ? 1 : 0;
}

1;
__END__

=head1 PMG::RuleDB::Remove

Remove attachments.
