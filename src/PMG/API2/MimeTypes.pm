package PMG::API2::MimeTypes;

use strict;
use warnings;

use PVE::RESTHandler;

use base qw(PVE::RESTHandler);

my $load_mime_types = sub {

    my $mtypes = {
	'message/delivery-status' => undef,
	'message/disposition-notification' => undef,
	'message/external-body' => undef,
	'message/news' => undef,
	'message/partial' => undef,
	'message/rfc822' => undef,
	'multipart/alternative' => undef,
	'multipart/digest' => undef,
	'multipart/encrypted' => undef,
	'multipart/mixed' => undef,
	'multipart/related' => undef,
	'multipart/report' => undef,
	'multipart/signed' => undef,
    };

    # get mimetypes out of /usr/share/mime/globs

    open(DAT, "/usr/share/mime/globs") ||
	die ("Could not open file $!: ERROR");

    while (my $row = <DAT>) {
        next if $row =~ m/^\#/;

	if ($row =~ m/([A-Za-z0-9-_\.]*)\/([A-Za-z0-9-_\+\.]*):\*\.(\S{1,10})\s*$/) {

	    my $m = "$1/$2";
	    my $end = $3;

	    $m =~ s/\./\\\./g; # quote '.'
	    $m =~ s/\+/\\\+/g; # quote '+'

	    if (defined ($end)) {
		$mtypes->{"$m"} = $mtypes->{"$m"} ? $mtypes->{"$m"} . ",$end" : $end;
	    }
	}
    }
    close(DAT);

    # sort and add wildcard entries
    my $lasttype='';

    my $mime = [];
    foreach my $mt (sort keys %$mtypes) {
	my ($type, $subtype) = split ('/', $mt);

	if ($type ne $lasttype) {
	    push @$mime, { mimetype => "$type/.*", text => "$type/.*"};
	    $lasttype = $type;
	}

	my $text = $mtypes->{$mt} ? "$mt ($mtypes->{$mt})" : $mt;

	push @$mime, { mimetype => $mt, text => $text };
    }

    return $mime;
};

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Get Mime Types List",
    parameters => {
	additionalProperties => 0,
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		mimetype => { type => 'string'},
		text => { type => 'string' },
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $mime = $load_mime_types->();

	return $mime;
    }});

1;
