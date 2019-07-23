package PMG::RuleDB;

use strict;
use warnings;
use DBI;
use HTML::Entities;
use Data::Dumper;

use PVE::SafeSyslog;

use PMG::Utils;
use PMG::DBTools;

use PMG::RuleDB::Group;

#use Proxmox::Statistic;
use PMG::RuleDB::Object;
use PMG::RuleDB::WhoRegex;
use PMG::RuleDB::ReceiverRegex;
use PMG::RuleDB::EMail;
use PMG::RuleDB::Receiver;
use PMG::RuleDB::IPAddress;
use PMG::RuleDB::IPNet;
use PMG::RuleDB::Domain;
use PMG::RuleDB::ReceiverDomain;
use PMG::RuleDB::LDAP;
use PMG::RuleDB::LDAPUser;
use PMG::RuleDB::TimeFrame;
use PMG::RuleDB::Spam;
use PMG::RuleDB::ReportSpam;
use PMG::RuleDB::Virus;
use PMG::RuleDB::Accept;
use PMG::RuleDB::Remove;
use PMG::RuleDB::ModField;
use PMG::RuleDB::MatchField;
use PMG::RuleDB::MatchFilename;
use PMG::RuleDB::Attach;
use PMG::RuleDB::Disclaimer;
use PMG::RuleDB::BCC;
use PMG::RuleDB::Quarantine;
use PMG::RuleDB::Block;
use PMG::RuleDB::Counter;
use PMG::RuleDB::Notify;
use PMG::RuleDB::Rule;
use PMG::RuleDB::ContentTypeFilter;
use PMG::RuleDB::ArchiveFilter;

sub new {
    my ($type, $dbh) = @_;

    $dbh = PMG::DBTools::open_ruledb("Proxmox_ruledb")  if !defined ($dbh);

    my $self = bless { dbh => $dbh }, $type;

    return $self;
}

sub close {
    my ($self) = @_;

    $self->{dbh}->disconnect();
}

sub create_group_with_obj {
    my ($self, $obj, $name, $info) = @_;

    my $og;
    my $id;

    defined($obj) || die "proxmox: undefined object";

    $name //= '';
    $info //= '';

    eval {

	$self->{dbh}->begin_work;

        $self->{dbh}->do("INSERT INTO Objectgroup (Name, Info, Class) " .
			 "VALUES (?, ?, ?)", undef,
			 $name, $info, $obj->oclass());

	my $lid = PMG::Utils::lastid($self->{dbh}, 'objectgroup_id_seq');

	$og = PMG::RuleDB::Group->new($name, $info, $obj->oclass());
	$og->{id} = $lid;

	$obj->{ogroup} = $lid;
	$id = $obj->save($self, 1);
	$obj->{id} = $id; # just to be sure

        $self->{dbh}->commit;
    };
    if (my $err = $@) {
	$self->{dbh}->rollback;
	die $err;
    }
    return $og;
}

sub load_groups {
    my ($self, $rule) = @_;

    defined($rule->{id}) || die "undefined rule id: ERROR";

    my $sth = $self->{dbh}->prepare(
	"SELECT RuleGroup.Grouptype, Objectgroup.ID, " .
	"Objectgroup.Name, Objectgroup.Info " .
	"FROM Rulegroup, Objectgroup " .
	"WHERE Rulegroup.Rule_ID = ? and " .
	"Rulegroup.Objectgroup_ID = Objectgroup.ID " .
	"ORDER BY RuleGroup.Grouptype");

    my $groups = ();

    $sth->execute($rule->{id});

    my ($from, $to, $when, $what, $action) = ([], [], [], [], []);

    while (my $ref = $sth->fetchrow_hashref()) {
	my $og = PMG::RuleDB::Group->new($ref->{name}, $ref->{info});
	$og->{id} = $ref->{id};

	if ($ref->{'grouptype'} == 0) {      #from
	    push @$from, $og;
	} elsif ($ref->{'grouptype'} == 1) { # to
	    push @$to, $og;
	} elsif ($ref->{'grouptype'} == 2) { # when
	    push @$when, $og;
	} elsif ($ref->{'grouptype'} == 3) { # what
	    push @$what, $og;
	} elsif ($ref->{'grouptype'} == 4) { # action
	    my $objects = $self->load_group_objects($og->{id});
	    my $obj = @$objects[0];
	    defined($obj) || die "undefined action object: ERROR";
	    $og->{action} = $obj;
	    push @$action, $og;
	}
    }

    $sth->finish();

    return ($from, $to, $when, $what, $action);
}

sub load_groups_by_name {
    my ($self, $rule) = @_;

    my ($from, $to, $when, $what, $action) =
	$self->load_groups($rule);

    return {
	from => $from,
	to => $to,
	when => $when,
	what => $what,
	action => $action,
    };
}

sub save_group {
    my ($self, $og) = @_;

    defined($og->{name}) ||
	die "undefined group attribute - name: ERROR";
    defined($og->{info}) ||
	die "undefined group attribute - info: ERROR";
    defined($og->{class}) ||
	die "undefined group attribute - class: ERROR";

    if (defined($og->{id})) {

	$self->{dbh}->do("UPDATE Objectgroup " .
			 "SET Name = ?, Info = ? " .
			 "WHERE ID = ?", undef,
			 $og->{name}, $og->{info}, $og->{id});

	return $og->{id};

    } else {
	my $sth = $self->{dbh}->prepare(
	    "INSERT INTO Objectgroup (Name, Info, Class) " .
	    "VALUES (?, ?, ?);");

	$sth->execute($og->name, $og->info, $og->class);

	return $og->{id} = PMG::Utils::lastid($self->{dbh}, 'objectgroup_id_seq');
    }

    return undef;
}

sub delete_group {
    my ($self, $groupid) = @_;

    defined($groupid) || die "undefined group id: ERROR";

    eval {

	$self->{dbh}->begin_work;

	# test if group is used in rules
	$self->{dbh}->do("LOCK TABLE RuleGroup IN EXCLUSIVE MODE");

	my $sth = $self->{dbh}->prepare(
	    "SELECT Rule.Name as rulename, ObjectGroup.Name as groupname " .
	    "FROM RuleGroup, Rule, ObjectGroup WHERE " .
	    "ObjectGroup.ID = ? AND Objectgroup_ID = ObjectGroup.ID AND " .
	    "Rule_ID = Rule.ID");

	$sth->execute($groupid);

	if (my $ref = $sth->fetchrow_hashref()) {
	    die "Group '$ref->{groupname}' is used by rule '$ref->{rulename}' - unable to delete\n";
	}

        $sth->finish();

	$self->{dbh}->do("DELETE FROM ObjectGroup " .
			 "WHERE ID = ?", undef, $groupid);

	$self->{dbh}->do("DELETE FROM RuleGroup " .
			 "WHERE Objectgroup_ID = ?", undef, $groupid);

	$sth = $self->{dbh}->prepare("SELECT * FROM Object " .
				      "where Objectgroup_ID = ?");
	$sth->execute($groupid);

	while (my $ref = $sth->fetchrow_hashref()) {
	    $self->{dbh}->do("DELETE FROM Attribut " .
			     "WHERE Object_ID = ?", undef, $ref->{id});
	}

	$sth->finish();

	$self->{dbh}->do("DELETE FROM Object " .
			 "WHERE Objectgroup_ID = ?", undef, $groupid);

	$self->{dbh}->commit;
    };
    if (my $err = $@) {
	$self->{dbh}->rollback;
	die $err;
    }

    return undef;
}

sub load_objectgroups {
    my ($self, $class, $id) = @_;

    my $sth;

    defined($class) || die "undefined object class";

    if (!(defined($id))) {
        $sth = $self->{dbh}->prepare(
	    "SELECT * FROM Objectgroup where Class = ? ORDER BY name");
        $sth->execute($class);

    } else {
        $sth = $self->{dbh}->prepare(
	    "SELECT * FROM Objectgroup where Class like ? and id = ? " .
	    "order by name");
        $sth->execute($class,$id);
    }

    my $arr_og = ();
    while (my $ref = $sth->fetchrow_hashref()) {
    	my $og = PMG::RuleDB::Group->new($ref->{name}, $ref->{info},
					 $ref->{class});
    	$og->{id} = $ref->{id};

	if ($class eq 'action') {
	    my $objects = $self->load_group_objects($og->{id});
	    my $obj = @$objects[0];
	    defined($obj) || die "undefined action object: ERROR";
	    $og->{action} = $obj;
	}
    	push @$arr_og, $og;
    }

    $sth->finish();

    return $arr_og;
}

sub get_object {
    my ($self, $otype) = @_;

     my $obj;

    # WHO OBJECTS
    if ($otype == PMG::RuleDB::Domain::otype()) {
	$obj = PMG::RuleDB::Domain->new();
    }
    elsif ($otype == PMG::RuleDB::ReceiverDomain::otype) {
	$obj = PMG::RuleDB::ReceiverDomain->new();
    }
    elsif ($otype == PMG::RuleDB::WhoRegex::otype) {
	$obj = PMG::RuleDB::WhoRegex->new();
    }
    elsif ($otype == PMG::RuleDB::ReceiverRegex::otype) {
	$obj = PMG::RuleDB::ReceiverRegex->new();
    }
    elsif ($otype == PMG::RuleDB::EMail::otype) {
	$obj = PMG::RuleDB::EMail->new();
    }
    elsif ($otype == PMG::RuleDB::Receiver::otype) {
	$obj = PMG::RuleDB::Receiver->new();
    }
    elsif ($otype == PMG::RuleDB::IPAddress::otype) {
	$obj = PMG::RuleDB::IPAddress->new();
    }
    elsif ($otype == PMG::RuleDB::IPNet::otype) {
	$obj = PMG::RuleDB::IPNet->new();
    }
    elsif ($otype == PMG::RuleDB::LDAP::otype) {
	$obj = PMG::RuleDB::LDAP->new();
    }
    elsif ($otype == PMG::RuleDB::LDAPUser::otype) {
	$obj = PMG::RuleDB::LDAPUser->new();
    }
    # WHEN OBJECTS
    elsif ($otype == PMG::RuleDB::TimeFrame::otype) {
	$obj = PMG::RuleDB::TimeFrame->new();
    }
    # WHAT OBJECTS
    elsif ($otype == PMG::RuleDB::Spam::otype) {
        $obj = PMG::RuleDB::Spam->new();
    }
    elsif ($otype == PMG::RuleDB::Virus::otype) {
        $obj = PMG::RuleDB::Virus->new();
    }
    elsif ($otype == PMG::RuleDB::MatchField::otype) {
        $obj = PMG::RuleDB::MatchField->new();
    }
    elsif ($otype == PMG::RuleDB::MatchFilename::otype) {
        $obj = PMG::RuleDB::MatchFilename->new();
    }
    elsif ($otype == PMG::RuleDB::ContentTypeFilter::otype) {
        $obj = PMG::RuleDB::ContentTypeFilter->new();
    }
    elsif ($otype == PMG::RuleDB::ArchiveFilter::otype) {
        $obj = PMG::RuleDB::ArchiveFilter->new();
    }
    # ACTION OBJECTS
    elsif ($otype == PMG::RuleDB::ModField::otype) {
        $obj = PMG::RuleDB::ModField->new();
    }
    elsif ($otype == PMG::RuleDB::Accept::otype()) {
        $obj = PMG::RuleDB::Accept->new();
    }
    elsif ($otype == PMG::RuleDB::ReportSpam::otype()) {
        $obj = PMG::RuleDB::ReportSpam->new();
    }
    elsif ($otype == PMG::RuleDB::Attach::otype) {
        $obj = PMG::RuleDB::Attach->new();
    }
    elsif ($otype == PMG::RuleDB::Disclaimer::otype) {
        $obj = PMG::RuleDB::Disclaimer->new();
    }
    elsif ($otype == PMG::RuleDB::BCC::otype) {
        $obj = PMG::RuleDB::BCC->new();
    }
    elsif ($otype == PMG::RuleDB::Quarantine::otype) {
        $obj = PMG::RuleDB::Quarantine->new();
    }
    elsif ($otype == PMG::RuleDB::Block::otype) {
        $obj = PMG::RuleDB::Block->new();
    }
    elsif ($otype == PMG::RuleDB::Counter::otype) {
        $obj = PMG::RuleDB::Counter->new();
    }
    elsif ($otype == PMG::RuleDB::Remove::otype) {
        $obj = PMG::RuleDB::Remove->new();
    }
    elsif ($otype == PMG::RuleDB::Notify::otype) {
        $obj = PMG::RuleDB::Notify->new();
    }
    else {
	    die "proxmox: unknown object type: ERROR";
    }

    return $obj;
}

sub load_counters_data {
    my ($self) = @_;

    my $sth = $self->{dbh}->prepare(
	"SELECT Object.id, Objectgroup.name, Object.Value, Objectgroup.info " .
	"FROM Object, Objectgroup " .
	"WHERE objectgroup.id = object.objectgroup_id and ObjectType = ? " .
	"order by Objectgroup.name, Value");

    my @data;

    $sth->execute(PMG::RuleDB::Counter->otype());

    while (my $ref = $sth->fetchrow_hashref()) {
    	my $tmp = [$ref->{id},$ref->{name},$ref->{value},$ref->{info}];
    	push (@data, $tmp);
    }

    $sth->finish();

    return @data;
}

sub load_object {
    my ($self, $objid) = @_;

    my $value = '';

    defined($objid) || die "undefined object id";

    my $sth = $self->{dbh}->prepare("SELECT * FROM Object where ID = ?");
    $sth->execute($objid);

    my $ref = $sth->fetchrow_hashref();

    $sth->finish();

    if (defined($ref->{'value'})) {
        $value = $ref->{'value'};
    }

    if (!(defined($ref->{'objecttype'}) &&
	  defined($ref->{'objectgroup_id'}))) {
	return undef;
    }

    my $ogroup = $ref->{'objectgroup_id'};

    my $otype = $ref->{'objecttype'};
    my $obj = $self->get_object($otype);

    $obj->load_attr($self, $objid, $ogroup, $value);
}

sub load_object_full {
    my ($self, $id, $gid, $exp_otype) = @_;

    my $obj = $self->load_object($id);
    die "object '$id' does not exists\n" if !defined($obj);

    my $otype = $obj->otype();
    die "wrong object type ($otype != $exp_otype)\n"
	if defined($exp_otype) && $otype != $exp_otype;

    die "wrong object group ($obj->{ogroup} != $gid)\n"
	if $obj->{ogroup} != $gid;

    return $obj;
}

sub load_group_by_name {
    my ($self, $name) = @_;

    my $sth = $self->{dbh}->prepare("SELECT * FROM Objectgroup " .
				    "WHERE name = ?");

    $sth->execute($name);

    while (my $ref = $sth->fetchrow_hashref()) {
   	my $og = PMG::RuleDB::Group->new($ref->{name}, $ref->{info},
					 $ref->{class});
    	$og->{id} = $ref->{id};

	$sth->finish();

	if ($ref->{'class'} eq 'action') {
	    my $objects = $self->load_group_objects($og->{id});
	    my $obj = @$objects[0];
	    defined($obj) || die "undefined action object: ERROR";
	    $og->{action} = $obj;
	}

	return $og;
    }

    $sth->finish();

    return undef;
}

sub greylistexclusion_groupid {
    my ($self) = @_;

    my $sth = $self->{dbh}->prepare(
	"select id from objectgroup where class='greylist' limit 1;");

    $sth->execute();

    my $ref = $sth->fetchrow_hashref();

    return $ref->{id};
}

sub load_group_objects {
    my ($self, $ogid) = @_;

    defined($ogid) || die "undefined group id: ERROR";

    my $sth = $self->{dbh}->prepare(
	"SELECT * FROM Object " .
	"WHERE Objectgroup_ID = ? order by ObjectType,Value");

    my $objects = ();

    $sth->execute($ogid);

    while (my $ref = $sth->fetchrow_hashref()) {
	my $obj = $self->load_object($ref->{id});
	push @$objects, $obj;
    }

    $sth->finish();

    return $objects;
}


sub save_object {
    my ($self, $obj) = @_;

    $obj->save($self);

    return $obj->{id};
}

sub group_add_object {
    my ($self, $group, $obj) = @_;

    ($obj->oclass() eq $group->{class}) ||
	die "wrong object class: ERROR";

    $obj->{ogroup} = $group->{id};

    $self->save_object($obj);
}

sub delete_object {
    my ($self, $obj) = @_;

    defined($obj->{id}) || die "undefined object id";

    eval {

	$self->{dbh}->begin_work;

	$self->{dbh}->do("DELETE FROM Attribut " .
			  "WHERE Object_ID = ?", undef, $obj->{id});

	$self->{dbh}->do("DELETE FROM Object " .
			  "WHERE ID = ?",
			  undef, $obj->{id});

	$self->{dbh}->commit;
    };
    if (my $err = $@) {
	$self->{dbh}->rollback;
	syslog('err', $err);
	return undef;
    }

    $obj->{id} = undef;

    return 1;
}

sub save_rule {
    my ($self, $rule) = @_;

    defined($rule->{name}) ||
	die "undefined rule attribute - name: ERROR";
    defined($rule->{priority}) ||
	die "undefined rule attribute - priority: ERROR";
    defined($rule->{active}) ||
	die "undefined rule attribute - active: ERROR";
    defined($rule->{direction}) ||
	die "undefined rule attribute - direction: ERROR";

    if (defined($rule->{id})) {

	$self->{dbh}->do(
	    "UPDATE Rule " .
	    "SET Name = ?, Priority = ?, Active = ?, Direction = ? " .
	    "WHERE ID = ?", undef,
	    $rule->{name}, $rule->{priority}, $rule->{active},
	    $rule->{direction}, $rule->{id});

	return $rule->{id};

    } else {
	my $sth = $self->{dbh}->prepare(
	    "INSERT INTO Rule (Name, Priority, Active, Direction) " .
	    "VALUES (?, ?, ?, ?);");

	$sth->execute($rule->name, $rule->priority, $rule->active,
		      $rule->direction);

	return $rule->{id} = PMG::Utils::lastid($self->{dbh}, 'rule_id_seq');
    }

    return undef;
}

sub delete_rule {
    my ($self, $ruleid) = @_;

    defined($ruleid) || die "undefined rule id: ERROR";

    eval {
	$self->{dbh}->begin_work;

	$self->{dbh}->do("DELETE FROM Rule " .
			 "WHERE ID = ?", undef, $ruleid);
	$self->{dbh}->do("DELETE FROM RuleGroup " .
			 "WHERE Rule_ID = ?", undef, $ruleid);

	$self->{dbh}->commit;
    };
    if (my $err = $@) {
	$self->{dbh}->rollback;
	syslog('err', $err);
	return undef;
    }

    return 1;
}

sub delete_testrules {
    my ($self) = @_;

    eval {
	$self->{dbh}->begin_work;

	my $sth = $self->{dbh}->prepare("Select id FROM Rule " .
					"WHERE name = 'testrule'");
	$sth->execute();

	while(my $ref = $sth->fetchrow_hashref()) {
	    $self->{dbh}->do("DELETE FROM Rule " .
			     "WHERE ID = ?", undef, $ref->{id});
	    $self->{dbh}->do("DELETE FROM RuleGroup " .
			     "WHERE Rule_ID = ?", undef, $ref->{id});
	}
	$sth->finish();

	$self->{dbh}->commit;
    };
    if (my $err = $@) {
	$self->{dbh}->rollback;
	die $err;
    }

    return 1;
}

my $grouptype_hash = {
    from => 0,
    to => 1,
    when => 2,
    what => 3,
    action => 4,
};

sub rule_add_group {
    my ($self, $ruleid, $groupid, $gtype_str) = @_;

    my $gtype = $grouptype_hash->{$gtype_str} //
	die "unknown group type '$gtype_str'\n";

    defined($ruleid) || die "undefined rule id: ERROR";
    defined($groupid) || die "undefined group id: ERROR";
    defined($gtype) || die "undefined group type: ERROR";

    $self->{dbh}->do("INSERT INTO RuleGroup " .
		     "(Objectgroup_ID, Rule_ID, Grouptype) " .
		     "VALUES (?, ?, ?)", undef,
		     $groupid, $ruleid, $gtype);
    return 1;
}

sub rule_add_from_group {
    my ($self, $rule, $group) = @_;

    $self->rule_add_group($rule->{id}, $group->{id}, 'from');
}

sub rule_add_to_group {
    my ($self, $rule, $group) = @_;

    $self->rule_add_group($rule->{id}, $group->{id}, 'to');
}

sub rule_add_when_group {
    my ($self, $rule, $group) = @_;

    $self->rule_add_group($rule->{id}, $group->{id}, 'when');
}

sub rule_add_what_group {
    my ($self, $rule, $group) = @_;

    $self->rule_add_group($rule->{id}, $group->{id}, 'what');
}

sub rule_add_action {
    my ($self, $rule, $group) = @_;

    $self->rule_add_group($rule->{id}, $group->{id}, 'action');
}

sub rule_remove_group {
    my ($self, $ruleid, $groupid, $gtype_str) = @_;

    my $gtype = $grouptype_hash->{$gtype_str} //
	die "unknown group type '$gtype_str'\n";

    defined($ruleid) || die "undefined rule id: ERROR";
    defined($groupid) || die "undefined group id: ERROR";
    defined($gtype) || die "undefined group type: ERROR";

    $self->{dbh}->do("DELETE FROM RuleGroup WHERE " .
		     "Objectgroup_ID = ? and Rule_ID = ? and Grouptype = ?",
		     undef, $groupid, $ruleid, $gtype);
    return 1;
}

sub load_rule {
    my ($self, $id) = @_;

    defined($id) || die "undefined id: ERROR";

    my $sth = $self->{dbh}->prepare(
	"SELECT * FROM Rule where id = ? ORDER BY Priority DESC");

    my $rules = ();

    $sth->execute($id);

    my $ref = $sth->fetchrow_hashref();
    die "rule '$id' does not exist\n" if !defined($ref);

    my $rule = PMG::RuleDB::Rule->new($ref->{name}, $ref->{priority},
				      $ref->{active}, $ref->{direction});
    $rule->{id} = $ref->{id};

    return $rule;
}

sub load_rules {
    my ($self) = @_;

    my $sth = $self->{dbh}->prepare(
	"SELECT * FROM Rule ORDER BY Priority DESC");

    my $rules = ();

    $sth->execute();

    while (my $ref = $sth->fetchrow_hashref()) {
	my $rule = PMG::RuleDB::Rule->new($ref->{name}, $ref->{priority},
					  $ref->{active}, $ref->{direction});
	$rule->{id} = $ref->{id};
	push @$rules, $rule;
    }

    $sth->finish();

    return $rules;
}



1;

__END__

=head1 PMG::RuleDB

The RuleDB Object manages the database connection and provides an interface to manipulate the database without SQL. A typical application first create a RuleDB object:

    use PMG::RuleDB;

    $ruledb = PMG::RuleDB->new();

=head2 Database Overview

=head3 Rules

Rules contains sets of Groups, grouped by classes (FROM, TO, WHEN, WHAT and ACTION). Each rule has an associated priority and and active/inactive marker.

=head3 Groups

A Group is a set of Objects.

=head3 Objects

Objects contains the filter data.

=head3 Rule Semantics

The classes have 'and' semantics. A rule matches if the checks in FROM, TO, WHEN and WHAT classes returns TRUE.

Within a class the objects are or'ed together.

=head2 Managing Rules

=head3 $ruledb->load_rules()

    Returns an array of Rules containing all rules in the database.

=head3 $ruledb->save_rule ($rule)

One can use the following code to add a new rule to the database:

    my $rule = PMG::RuleDB::Rule->new ($name, $priority, $active);
    $ruledb->save_rule ($rule);

You can also use save_rule() to commit changes back to the database.

=head3 $ruledb->delete_rule ($ruleid)

Removes the rule from the database.

=head3  $ruledb->rule_add_group ($rule, $og, $gtype)

Add an object group to the rule.

Possible values for $gtype are:

    'from' 'to', 'when', 'what', 'action'

=head3  $ruledb->rule_remove_group ($rule, $og, $gtype)

Removes an object group from the rule.

=head2 Managing Objects and Groups

=head3 $ruledb->load_groups ($rule)

Return all object groups belonging to a rule. Data is divided into separate arrays:

    my ($from, $to, $when, $what, $action) =
	$ruledb->load_groups($rule);

=head3 $ruledb->save_group ($og)

This can be used to add or modify an Group. This code segemnt creates
a new object group:

    $og = PMG::RuleDB::Group->new ($name, $desc);
    $ruledb->save_group ($og);


=head3 $ruledb->delete_group ($groupid)

Deletes the object group, all reference to the group and all objects
belonging to this group from the Database.

=head3 $ruledb->group_add_object ($og, $obj)

Attach an object to an object group.

=head3 $ruledb->save_object ($obj)

Save or update an object. This can be used to add new objects
to the database (although group_add_object() is the prefered way):

    $obj =  PMG::RuleDB::EMail->new ('.*@mydomain.com');
    # we need to set the object group manually
    $obj->ogroup ($group->id);
    $ruledb->save_object ($obj);


=head3 $ruledb->delete_object ($obj)

Deletes the object, all references to the object  and all object
attributes from the database.
