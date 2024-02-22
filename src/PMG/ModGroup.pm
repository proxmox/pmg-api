package PMG::ModGroup;

use strict;
use warnings;

sub new {
    my ($type, $entity, $targets) = @_;

    my $self = {
	targets => $targets,
	ea => [$entity],
	groups => [$targets],
	entity => $entity,
    };

    bless $self, $type;

    return $self;
}

# compute subgroups
# set ro (read only) to 1 if you do not plan to modify the
# entity (in actions like 'accept' od 'bcc'). This
# just return the existing groups but does not create new groups.

sub subgroups {
    my ($self, $targets, $ro) = @_;

    my $groups;
    if ($ro) {
	my @copy = @{$self->{groups}};
	$groups =  \@copy;
    } else {
	$groups =  $self->{groups};
    }

    my $ea =  $self->{ea};

    my $res;

    for my $i (0..$#$groups) {
	my $g = @$groups[$i];

	my $tcount = -1;
	my ($ma, $ua);
	foreach my $member (@$g) {
	    my $found = 0;
	    foreach my $t (@$targets) {
		if ($member eq $t) {
		    $found = 1;
		    $tcount++;
		}
	    }
	    if ($found) {
		push @$ma, $member;
	    } else {
		push @$ua, $member;
	    }
	}

	next if $tcount == -1;

	if ($tcount < $#$g) {
	    @$groups[$i] = $ma;
	    push @$groups, $ua;
	    if ($ro) {
		push @$ea, @$ea[$i];
	    } else {
		my $e = @$ea[$i];
		my $copy = $e->dup;

		# also copy proxmox attribute
		foreach (keys %$e) {$copy->{$_} = $e->{$_} if $_ =~ m/^PMX_/};

		push @$ea, $copy;
	    }
	}
	push @$res, [$ma, @$ea[$i]];
    }

    return $res;
}

# explode the groups, so we have one for each target we need
# only to be used by the rRemove action when there was a spaminfo
sub explode {
    my ($self, $targets) = @_;

    my $groups = $self->{groups};
    my $ea = $self->{ea};
    my $res;

    # TODO: implement it more directly with less overhead!
    for my $target ($targets->@*) {
	$self->subgroups([$target]);
    }

    return $self->subgroups($targets);
}

1;

__END__

=head1 PMG::RuleDB::ModGroup

The idea behind the modification group object (ModGroup) is that some
modification are target specific. For example a mail can be posted to
two receiver:

  TO: user1@domain1.com, user2@domain2.com

and we have different rules to add disclaimers for those domains:

  Rule1: .*@domain1.com --> add disclaimer one
  Rule2: .*@domain2.com --> add disclaimer two

Both Rules are matching, because there are two different receivers,
one in each domain. If we simply modify the original mail we end up
with a mail containing both disclaimers, which is not what we want.

Another example is when you have receiver specific content filters,
for example you don't want to get .exe files for a specific user, but
allow it for everyone else:

  Rule1: user1@domain1.com && .exe attachments --> remove attachments
  Rule1: .*@domain2.com && .exe attachments --> accept

So you don't want to remeove the .exe file for user2@domain.com

Instead we want to group modification by matching rule targets.

  $mod_group = PMG::RuleDB::ModGroup->new ($targets, $entity);

  $targets ... array of all receivers
  $entity  ... original mail

return a new ModGroup Object. Action Objects which do target specific
modification have to call:

  my $subgroups = $mod_group->subgroups ($rule_targets);

  foreach my $ta (@$subgroups) {
    my ($targets, $entity) = (@$ta[0], @$ta[1]);
    my_modify_entity ($entity, $targets);
  }

That way we seamlessly hide the fact that mails are delivered to more
than one recipient, without the requirement to make a copy for each
recipient (which would lead to many unnecessays notification
mail). Instead we only make a minimum number of copies for specific
target groups.
