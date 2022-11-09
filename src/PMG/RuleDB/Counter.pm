package PMG::RuleDB::Counter;

# FIXME: remove with PMG 8.0

use strict;
use warnings;
use DBI;
use Digest::SHA;

use PVE::SafeSyslog;

use PMG::Utils;
use PMG::RuleDB::Object;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 4999;
}

sub oclass {
    return 'action';
}

sub otype_text {
    return 'Counter';
}

sub new {
    my ($type, $count, $ogroup) = @_;
    
    my $class = ref($type) || $type;
 
    my $self = $class->SUPER::new($class->otype(), $ogroup);

    $count = 0 if !defined ($count); 

    $self->{count} = $count;
    
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
    
    my $adr;
    
    defined($self->{ogroup}) ||  die "undefined ogroup: ERROR";
    defined($self->{count}) ||  die "undefined count: ERROR";

    if (defined ($self->{id})) {
	# update
	
	$ruledb->{dbh}->do(
	    "UPDATE Object SET Value = ? WHERE ID = ?", 
	    undef, $self->{count}, $self->{id});

    } else {
	# insert

	my $sth = $ruledb->{dbh}->prepare(
	    "INSERT INTO Object (Objectgroup_ID, ObjectType, Value) " .
	    "VALUES (?, ?, ?);");

	$sth->execute($self->{ogroup}, $self->otype, $self->{count});
    
	$self->{id} = PMG::Utils::lastid($ruledb->{dbh}, 'object_id_seq'); 
    }
	
    return $self->{id};
}

sub execute {
    my ($self, $queue, $ruledb, $mod_group, $targets, 
	$msginfo, $vars, $marks) = @_;

    syslog('warning', "%s: deprecated action 'Counter' will be removed with PMG 8.0.",
	   $queue->{logid},);

    eval {
	$ruledb->{dbh}->begin_work;
	
	$ruledb->{dbh}->do("LOCK TABLE Object IN SHARE MODE");

	my $sth = $ruledb->{dbh}->prepare(
	    "SELECT Value FROM Object where ID = ?");
	$sth->execute($self->{id});
	
	my $ref = $sth->fetchrow_hashref();

	$sth->finish();

	defined($ref->{'value'}) || die "undefined value: ERROR";

	my $value = int($ref->{'value'}); 
	
	$ruledb->{dbh}->do(
	    "UPDATE Object SET Value = ? WHERE ID = ?", 
	    undef, $value + 1, $self->{id});

	$ruledb->{dbh}->commit;

	if ($msginfo->{testmode}) {
	    print ("counter increased\n");
	}
    };
    if (my $err = $@) {
	$ruledb->{dbh}->rollback;
   	syslog('err', $err);
    	return undef;
    }
}

sub count { 
    my ($self, $count) = @_; 

    if (defined ($count)) {
	$self->{count} = $count;
    }

    $self->{count}; 
}


sub short_desc {
    my $self = shift;

    return "Increase Counter";
}

1;

__END__

=head1 PMG::RuleDB::Counter

Counter Object

=head2 Attributes

=head3 count

Unique Name of the Counter

=head2 Examples

    $obj = PMG::RuleDB::Counter->new (0);

