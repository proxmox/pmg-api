package PMG::RuleDB::WhoRegex;

use strict;
use warnings;
use DBI;
use Digest::SHA;
use Encode qw(encode);

use PMG::Utils;
use PMG::RuleDB::Object;

use base qw(PMG::RuleDB::Object);

sub otype {
    return 1000;
}

sub oclass {
    return 'who';
}

sub otype_text {
    return 'Regular Expression';
}

sub new {
    my ($type, $address, $ogroup) = @_;
    
    my $class = ref($type) || $type;
 
    my $self = $class->SUPER::new($class->otype(), $ogroup);

    $address //= '.*@domain\.tld';
  
    $self->{address} = $address;
    
    return $self;
}

sub load_attr {
    my ($type, $ruledb, $id, $ogroup, $value) = @_;
    
    my $class = ref($type) || $type;

    defined($value) || die "undefined value: ERROR";

    my $decoded_value = PMG::Utils::try_decode_utf8($value);
    my $obj = $class->new ($decoded_value, $ogroup);
    $obj->{id} = $id;

    $obj->{digest} = Digest::SHA::sha1_hex($id, $value, $ogroup);
    
    return $obj;
}

sub save {
    my ($self, $ruledb) = @_;

    defined($self->{ogroup}) || die "undefined ogroup: ERROR";
    defined($self->{address}) || die "undefined address: ERROR";

    my $adr = $self->{address};

    PMG::Utils::test_regex("^${adr}\$");

    $adr =~ s/\\/\\\\/g;
    $adr = encode('UTF-8', $adr);

    if (defined ($self->{id})) {
	# update
	
	$ruledb->{dbh}->do (
	    "UPDATE Object SET Value = ? WHERE ID = ?", 
	    undef, $adr, $self->{id});

    } else {
	# insert

	# check if it exists first
	if (my $id = PMG::Utils::get_existing_object_id(
	    $ruledb->{dbh},
	    $self->{ogroup},
	    $self->otype(),
	    $adr
	)) {
	    return $id;
	}

	my $sth = $ruledb->{dbh}->prepare (
	    "INSERT INTO Object (Objectgroup_ID, ObjectType, Value) " .
	    "VALUES (?, ?, ?);");

	$sth->execute($self->{ogroup}, $self->otype, $adr);

	$self->{id} = PMG::Utils::lastid($ruledb->{dbh}, 'object_id_seq');
    }
       
    return $self->{id};
}

sub who_match {
    my ($self, $addr) = @_;

    my $t = $self->address;

    my $res;
    eval {
	$res = $addr =~ m/^$t$/i;
    };
    warn "invalid regex: $@\n" if $@;
    return $res;
}

sub address { 
    my ($self, $addr) = @_; 

    if (defined ($addr)) {
	$self->{address} = $addr;
    }

    $self->{address}; 
}

sub short_desc {
    my $self = shift;

    my $desc = $self->{address};
    
    return $desc;
}

sub properties {
    my ($class) = @_;

    return {
	regex => {
	    description => "Email address regular expression.",
	    type => 'string',
	    maxLength => 1024,
	},
    };
}

sub get {
    my ($self) = @_;

    return { regex => $self->{address} };
}

sub update {
    my ($self, $param) = @_;

    $self->{address} = $param->{regex};
}

1;

__END__

=head1 PMG::RuleDB::WhoRegex

A WHO object to check email addresses with regular expressions.

=head2 Attributes

=head3 address

A Perl regular expression used to compare email addresses (ignore case).

=head2 Examples

    $obj = PMG::RuleDB::WhoRegex->new ('.*@yourdomain.com');

