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
    my ($type, $all, $text, $ogroup) = @_;

    my $class = ref($type) || $type;

    $all = 0 if !defined ($all);

    my $self = $class->SUPER::new($class->otype(), $ogroup);

    $self->{all} = $all;
    $self->{text} = $text;

    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;

    my $class = ref($type) || $type;

    defined ($value) || die "undefined value: ERROR";

    my $obj;

    if ($value =~ m/^([01])(\:(.*))?$/s) {
	$obj = $class->new($1, $3, $ogroup);
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

    if ($self->{text}) {
	$value .= ":$self->{text}";
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

    my $pn = $entity->parts;
    for (my $i = 0; $i < $pn; $i++) {
	my $part = $entity->parts($i);

	my ($id, $found);

	if ($id = $part->head->mime_attr('x-proxmox-tmp-aid')) {
	    chomp $id;

	    if ($self->{all}) {
		my $ctype_part = $part->head->mime_type;
		if (!($i == 0 && $ctype_part =~ m|text/.*|i)) {
		    $found = 1;
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
	    $self->delete_marked_parts($queue, $part, $html, $rtype, $marks);
	    push (@$nparts, $part);
	}
    }

    $entity->parts ($nparts);
}

sub execute {
    my ($self, $queue, $ruledb, $mod_group, $targets,
	$msginfo, $vars, $marks) = @_;

    my $rulename = $vars->{RULE} // 'unknown';

    if (!$self->{all} && ($#$marks == -1)) {
	# no marks
	return;
    }

    my $subgroups = $mod_group->subgroups ($targets);

    my $html = PMG::Utils::subst_values($self->{text}, $vars);

    $html = "This attachment was removed: __FILENAME__\n" if !$html;

    my $rtype = "text/plain";

    if ($html =~ m/\<\w+\>/s) {
	$rtype = "text/html";
    }

    foreach my $ta (@$subgroups) {
	my ($tg, $entity) = (@$ta[0], @$ta[1]);

	# handle singlepart mails
	my $ctype = $entity->head->mime_type;
	if (!$entity->is_multipart && (!$self->{all} || $ctype !~ m|text/.*|i)) {
	    $entity->make_multipart();
	    my $first_part = $entity->parts(0);
	    $first_part->head->mime_attr('x-proxmox-tmp-aid' => $entity->head->mime_attr('x-proxmox-tmp-aid'));
	    $entity->head->delete('x-proxmox-tmp-aid');
	}

	$self->delete_marked_parts($queue, $entity, $html, $rtype, $marks, $rulename);

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
    };
}

sub update {
    my ($self, $param) = @_;

    $self->{text} = $param->{text};
    $self->{all} = $param->{all} ? 1 : 0;
}

1;
__END__

=head1 PMG::RuleDB::Remove

Remove attachments.
