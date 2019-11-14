package PMG::SACustom;

use strict;
use warnings;

use PVE::INotify;
use Digest::SHA;

my $shadow_path = "/var/cache/pmg-scores.cf";
my $conf_path = "/etc/mail/spamassassin/pmg-scores.cf";

sub get_shadow_path {
    return $shadow_path;
}

sub apply_changes {
    rename($shadow_path, $conf_path) if -f $shadow_path;
}

sub calc_digest {
    my ($data) = @_;

    my $raw = '';

    foreach my $rule (sort keys %$data) {
	my $score = $data->{$rule}->{score};
	my $comment = $data->{$rule}->{comment} // "";
	$raw .= "$rule$score$comment";
    }

    my $digest = Digest::SHA::sha1_hex($raw);
    return $digest;
}

PVE::INotify::register_file('pmg-scores.cf', $conf_path,
			    \&read_pmg_cf,
			    \&write_pmg_cf,
			    undef,
			    always_call_parser => 1,
			    shadow => $shadow_path,
			    );

sub read_pmg_cf {
    my ($filename, $fh) = @_;

    my $scores = {};

    my $comment = '';
    if (defined($fh)) {
	while (defined(my $line = <$fh>)) {
	    chomp $line;
	    next if $line =~ m/^\s*$/;
	    if ($line =~ m/^# ?(.*)\s*$/) {
		$comment = $1;
		next;
	    }
	    if ($line =~ m/^score\s+(\S+)\s+(\S+)\s*$/) {
		my $rule = $1;
		my $score = $2;
		$scores->{$rule} = {
		    name => $rule,
		    score => $score,
		    comment => $comment,
		};
		$comment = '';
	    } else {
		warn "parse error in '$filename': $line\n";
		$comment = '';
	    }
	}
    }

    return $scores;
}

sub write_pmg_cf {
    my ($filename, $fh, $scores) = @_;

    my $content = "";
    foreach my $rule (sort keys %$scores) {
	my $comment = $scores->{$rule}->{comment};
	my $score = sprintf("%.3f", $scores->{$rule}->{score});
	$content .= "# $comment\n" if defined($comment) && $comment !~ m/^\s*$/;
	$content .= "score $rule $score\n";
    }
    PVE::Tools::safe_print($filename, $fh, $content);
}

1;
